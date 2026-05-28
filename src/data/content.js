// All chapter content, descriptions, callouts, and code snippets
// Code is condensed to the most architecturally significant parts

// ─── Snippet store ────────────────────────────────────────────────────────────
const S = {}

S.gatewayMain = `// apps/api-gateway/src/main.ts
// OTel MUST be first — monkey-patches pg, ioredis, kafkajs at load time.
// If NestJS modules load first, auto-instrumentation misses them entirely.
import './telemetry/tracing.init';

import { NestFactory } from '@nestjs/core';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import helmet from 'helmet';
import * as compression from 'compression';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });

  // Pino replaces NestJS logger — 5× faster than Winston, structured JSON
  const logger = app.get(Logger);
  app.useLogger(logger);

  // Security headers: HSTS, CSP, X-Frame-Options, X-DNS-Prefetch-Control
  // Tighten CSP in prod — currently permissive for Swagger UI
  app.use(helmet());

  // Brotli/gzip — offload to NGINX/Cloudflare in prod for zero CPU overhead
  app.use(compression());

  // CORS allowlist — never use origin: '*' for a financial API
  app.enableCors({
    origin: process.env.CORS_ORIGINS?.split(',') ?? [],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Correlation-Id', 'X-Operator-Id'],
    credentials: true,
    maxAge: 600, // preflight cache 10 min
  });

  // URI versioning: /api/v1/bets — non-breaking API evolution
  app.setGlobalPrefix('api/v1', { exclude: ['/health'] });
  app.enableVersioning({ type: VersioningType.URI });

  // whitelist: strips unknown props (prevents mass-assignment attacks)
  // transform: coerces "?page=1" string to number
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));

  // SIGTERM → stop accepting → drain in-flight requests → close Kafka producer
  // k8s terminationGracePeriodSeconds must be > drain window + margin
  app.enableShutdownHooks();

  await app.listen(3000, '0.0.0.0');
}`

S.appModule = `// apps/api-gateway/src/app.module.ts
// Module composition — the DI wiring diagram of the entire gateway

@Module({
  imports: [
    // isGlobal: crash loudly at startup on missing env vars (fail-fast)
    ConfigModule.forRoot({ isGlobal: true, validate }),

    // Pino auto-logs every HTTP request/response with duration and status.
    // Redacts: Authorization header, req.body.password, req.body.cardNumber
    LoggerModule.forRootAsync({ ... }),

    // CLS = AsyncLocalStorage: propagates correlationId/userId through
    // the entire async call chain without threading params manually.
    ClsModule.forRoot({ global: true, middleware: { mount: true } }),

    // Redis-backed sliding window counter (shared across all pods)
    ThrottlerModule.forRootAsync({
      useFactory: (config) => ({
        throttlers: [
          { name: 'burst',  ttl: 1_000,  limit: 20  }, // 20 req/s
          { name: 'global', ttl: 60_000, limit: 300 }, // 300 req/min
        ],
        // Without Redis storage each pod has its own counter —
        // a user can multiply their limit by the pod count
      }),
    }),

    RedisModule.forRootAsync(),   // @betting/redis — global singleton
    KafkaModule.forRootAsync(),   // @betting/kafka — global producer
    TelemetryModule.forRoot(),    // OTel tracer + metrics registration

    AuthModule, BettingModule, WalletModule,
    MarketsModule, GamesModule, RealtimeModule,
    HealthModule, AdminModule,
  ],

  providers: [
    // Guards applied in ORDER — each receives req.user set by the previous
    { provide: APP_GUARD, useClass: JwtAuthGuard   }, // 1. JWT → req.user
    { provide: APP_GUARD, useClass: RolesGuard     }, // 2. @Roles() check
    { provide: APP_GUARD, useClass: OperatorGuard  }, // 3. B2B key check
    { provide: APP_GUARD, useClass: ThrottlerGuard }, // 4. IP rate limit

    // Interceptors wrap the handler — LoggingInterceptor captures the response
    { provide: APP_INTERCEPTOR, useClass: LoggingInterceptor   },
    { provide: APP_INTERCEPTOR, useClass: TransformInterceptor },
    { provide: APP_INTERCEPTOR, useClass: TimeoutInterceptor   },

    { provide: APP_FILTER, useClass: GlobalExceptionFilter },
  ],
})
export class AppModule implements NestModule {
  // Middleware runs BEFORE guards. Pipeline order:
  // Middleware → Guard → Interceptor(pre) → Pipe → Handler → Interceptor(post) → Filter
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(CorrelationIdMiddleware).forRoutes('*');
    consumer.apply(GeoBlockMiddleware)
      .exclude('/health/(.*)', '/metrics')
      .forRoutes('*');
  }
}`

S.correlationId = `// apps/api-gateway/src/common/middleware/correlation-id.middleware.ts
// Every request gets a UUID that threads through ALL downstream calls:
//   HTTP headers, gRPC metadata, Kafka message headers,
//   DB query comments, OpenTelemetry trace, log lines
//
// This is non-negotiable for debugging a 6-service fleet in production.
// Without it, correlating a single user action across service logs takes hours.

@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  constructor(private readonly cls: ClsService) {}

  use(req: Request, res: Response, next: NextFunction): void {
    const incomingId = req.headers['x-correlation-id'] as string | undefined;

    // Only trust incoming ID from verified proxy (Cloudflare HMAC signature)
    // Never trust raw client-supplied IDs — they can spoof tracking
    const correlationId =
      incomingId && this.isTrustedSource(req) ? incomingId : randomUUID();

    // Store in AsyncLocalStorage so it's accessible anywhere in this request
    // without passing it as a parameter through every function call
    this.cls.set('correlationId', correlationId);
    this.cls.set('requestStartTime', Date.now());

    // Echo back for client-side log correlation (support tickets)
    res.setHeader('x-correlation-id', correlationId);
    next();
  }
}`

S.geoBlock = `// apps/api-gateway/src/common/middleware/geo-block.middleware.ts
// Regulatory compliance — gambling operators MUST block unlicensed territories.
// Failure = criminal liability in most jurisdictions.
//
// Defence layers:
//   1. Cloudflare Workers (edge, zero latency) — primary
//   2. This middleware (application tier)       — secondary
//   3. Account creation DB check               — tertiary

@Injectable()
export class GeoBlockMiddleware implements NestMiddleware {
  // Hardcoded baseline: US UIGEA, DPRK, Iran, Syria, Cuba
  private readonly blockedCountries = new Set(['US', 'KP', 'IR', 'SY', 'CU']);

  async use(req: Request, res: Response, next: NextFunction): Promise<void> {
    const countryCode = this.resolveCountry(req);

    if (!countryCode && process.env.NODE_ENV === 'production') {
      // Unknown origin → fail closed in prod
      throw new ForbiddenException({ code: 'GEO_UNKNOWN' });
    }

    // Operator-specific jurisdiction config loaded from Redis cache
    // const operatorGeo = await this.redis.get(\`op:geo:\${operatorId}\`);

    if (this.blockedCountries.has(countryCode)) {
      throw new ForbiddenException({
        code: 'GEO_BLOCKED',
        // Never include the country code — tells VPN users what to spoof
        message: 'Service not available in your region',
      });
    }

    (req as any).geoCountry = countryCode; // downstream audit + compliance
    next();
  }

  private resolveCountry(req: Request): string | null {
    return (
      req.headers['cf-ipcountry'] as string ||  // Cloudflare (prod)
      req.headers['x-geoip-country'] as string  // NGINX geoip2 (fallback)
      || null
    );
  }
}`

S.jwtGuard = `// apps/api-gateway/src/common/guards/jwt-auth.guard.ts
// Token validation flow:
//   1. Extract Bearer token from Authorization header
//   2. Verify RS256 signature (JwtStrategy does this via JWKS endpoint)
//   3. Check Redis blacklist — logout / password-change tokens still in window
//   4. Check token version — detects forced re-auth (admin action, compromise)
//   5. Check self-exclusion flag — regulatory RG requirement
//   6. Populate req.user and CLS context

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
    private readonly cls: ClsService,
  ) { super(); }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Skip auth for @Public() routes (login, register, public odds, health)
    const isPublic = this.reflector.getAllAndOverride(IS_PUBLIC_KEY, [
      context.getHandler(), context.getClass(),
    ]);
    if (isPublic) return true;

    const isAuthenticated = await super.canActivate(context) as boolean;
    if (!isAuthenticated) return false;

    const { user } = context.switchToHttp().getRequest();

    // JWT blacklist — jti stored with TTL = remaining token lifetime
    // const blacklisted = await this.redis.exists(\`jwt:bl:\${user.jti}\`);
    // if (blacklisted) throw new UnauthorizedException({ code: 'TOKEN_REVOKED' });

    // Token version — incremented on password change / admin lockout
    // const storedVersion = await this.redis.get(\`u:tv:\${user.sub}\`);
    // if (storedVersion && +storedVersion !== user.tokenVersion)
    //   throw new UnauthorizedException({ code: 'TOKEN_VERSION_MISMATCH' });

    // Self-exclusion — set permanently by RG tools or admin
    // const excluded = await this.redis.exists(\`u:excl:\${user.sub}\`);
    // if (excluded) throw new ForbiddenException({ code: 'SELF_EXCLUDED' });

    // Enrich CLS → auto-populates every log line with userId
    this.cls.set('userId', user.sub);
    this.cls.set('userRoles', user.roles);
    return true;
  }

  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      const expired = info?.message === 'jwt expired';
      throw new UnauthorizedException({
        code: expired ? 'TOKEN_EXPIRED' : 'AUTH_INVALID_TOKEN',
        message: expired ? 'Token expired' : 'Invalid token',
      });
    }
    return user;
  }
}`

S.rolesGuard = `// apps/api-gateway/src/common/guards/roles.guard.ts
// RBAC via JWT-embedded roles (no DB lookup per request).
// Role changes take effect on next token refresh (≤15 min) — acceptable.
// For immediate effect (admin suspends account), use Redis suspension flag.
//
// Role hierarchy:
//   PLAYER → AFFILIATE → SUPPORT → COMPLIANCE → RISK_ANALYST
//   → OPERATOR → ADMIN → SUPER_ADMIN

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );
    if (!requiredRoles?.length) return true; // No @Roles() = any auth'd user

    const { user } = context.switchToHttp().getRequest();
    const hasRole = requiredRoles.some(r => user?.roles?.includes(r));

    if (!hasRole) throw new ForbiddenException({
      code: 'INSUFFICIENT_PERMISSIONS',
      // Never expose user's actual roles in response — information leakage
      message: \`Requires one of: [\${requiredRoles.join(', ')}]\`,
    });

    return true;
  }
}

// ── Custom decorators ────────────────────────────────────────────────────────
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
export const AuditLog = (action: string) => SetMetadata(AUDIT_ACTION_KEY, action);
export const Idempotent = () => SetMetadata(IDEMPOTENT_KEY, true);
export const Timeout = (ms: number) => SetMetadata(REQUEST_TIMEOUT_KEY, ms);

// Usage in a controller:
// @Post()
// @Roles(UserRole.PLAYER)        // RBAC
// @AuditLog('BET_PLACED')        // Compliance audit trail
// @Idempotent()                  // Require Idempotency-Key header
// @Timeout(5_000)                // Override global 10s timeout
// async placeBet(@CurrentUser() user: JwtPayload, @Body() dto: PlaceBetDto) { ... }`

S.operatorGuard = `// apps/api-gateway/src/common/guards/operator.guard.ts
// Multi-tenant white-label: each B2B operator has an API key.
// Operator context drives: jurisdiction rules, game catalogue, limits, RTP.
//
// Key rotation: SHA-256 hashed before storage, pre-provisioned alongside
// old key (24h grace period), revocation takes effect in <5s via Redis pub/sub.

@Injectable()
export class OperatorGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiresOperator = this.reflector.getAllAndOverride(
      REQUIRE_OPERATOR_KEY, [context.getHandler(), context.getClass()]
    );
    if (!requiresOperator) return true;

    const req = context.switchToHttp().getRequest();
    const { 'x-operator-id': operatorId, 'x-operator-key': operatorKey } = req.headers;

    if (!operatorId || !operatorKey)
      throw new UnauthorizedException({ code: 'OPERATOR_CREDENTIALS_MISSING' });

    // const storedHash = await this.redis.hget('operators:keys', operatorId);
    // const keyHash = sha256(operatorKey);
    // if (!storedHash || storedHash !== keyHash)
    //   throw new UnauthorizedException({ code: 'OPERATOR_KEY_INVALID' });

    // const status = await this.redis.get(\`op:status:\${operatorId}\`);
    // if (status !== 'active') throw new ForbiddenException({ code: 'OPERATOR_SUSPENDED' });

    this.cls.set('operatorId', operatorId); // downstream partitioning + audit
    return true;
  }
}`

S.interceptors = `// apps/api-gateway/src/common/interceptors/

// ── LoggingInterceptor ───────────────────────────────────────────────────────
// Audit log for every API call. Financial actions (bet, deposit, withdrawal)
// published to Kafka audit topic (append-only, 7-year retention per UKGC).
// GDPR: log userId (opaque UUID), NEVER email, IP, or name.
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const { method, url } = ctx.switchToHttp().getRequest();
    const startTime = this.cls.get('requestStartTime') ?? Date.now();

    return next.handle().pipe(
      tap((data) => {
        const res = ctx.switchToHttp().getResponse();
        this.logger.log({
          correlationId: this.cls.get('correlationId'),
          userId: this.cls.get('userId'),
          method, path: url,
          statusCode: res.statusCode,
          duration: Date.now() - startTime,
        });
      }),
    );
  }
}

// ── TransformInterceptor ─────────────────────────────────────────────────────
// Every success response wrapped in { data, meta } envelope.
// meta.requestId enables client ↔ server log correlation.
@Injectable()
export class TransformInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<ApiResponse<unknown>> {
    const correlationId = this.cls.get('correlationId') ?? '';
    return next.handle().pipe(
      map((data) => ({
        data,
        meta: { requestId: correlationId, timestamp: new Date().toISOString(), version: '1.0' },
      })),
    );
  }
}

// ── TimeoutInterceptor ───────────────────────────────────────────────────────
// Without timeouts a slow downstream service exhausts connection pools and
// cascades into a full gateway outage. 10s global, 5s for bet placement.
@Injectable()
export class TimeoutInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const ms = this.reflector.getAllAndOverride(REQUEST_TIMEOUT_KEY,
      [ctx.getHandler(), ctx.getClass()]) ?? 10_000;

    return next.handle().pipe(
      timeout(ms),
      catchError((err) => {
        if (err instanceof TimeoutError)
          return throwError(() => new RequestTimeoutException({ code: 'REQUEST_TIMEOUT' }));
        return throwError(() => err);
      }),
    );
  }
}`

S.exceptionFilter = `// apps/api-gateway/src/common/filters/global-exception.filter.ts
// Normalises ALL exceptions to: { error: { code, message, details, requestId, timestamp } }
//
// Security rules:
//   5xx → generic code only, NEVER expose stack traces, SQL errors, internal paths
//   4xx → code + message safe to expose, NOT internal details
//   422 → field-level validation details (help clients, sanitise reflected input)
//
// Error codes are stable API contracts — never rename without a deprecation window.
// Client teams parse these machine-readable codes, not the human message string.

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const correlationId = this.cls?.get('correlationId') ?? '';

    let statusCode: number, errorCode: string, message: string;

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      const body = exception.getResponse() as Record<string, any>;
      errorCode = body?.code ?? this.statusToCode(statusCode);
      message   = body?.message ?? exception.message;
    } else {
      statusCode = 500;
      errorCode  = 'INTERNAL_ERROR';
      message    = 'An unexpected error occurred';
      // Full details → Sentry (never to client)
      // Sentry.captureException(exception, { extra: { correlationId } });
    }

    res.status(statusCode).json({
      error: { code: errorCode, message, requestId: correlationId, timestamp: new Date().toISOString() },
    });
  }
}`

S.bettingController = `// apps/api-gateway/src/modules/betting/betting.controller.ts

@ApiTags('betting')
@ApiBearerAuth()
@Controller({ path: 'bets', version: '1' })
export class BettingController {
  constructor(private readonly bettingProxy: BettingProxyService) {}

  @Post()
  @HttpCode(201)
  @Roles(UserRole.PLAYER)
  @AuditLog('BET_PLACED')   // → compliance Kafka topic (7-year retention)
  @Idempotent()              // Require Idempotency-Key header — network retry safe
  @Timeout(5_000)            // Bet placement SLA: 5s hard cut-off
  @ApiOperation({
    summary: 'Place a bet',
    description: \`
      Flow: validate DTO → check JWT → rate limit → call betting-service gRPC
      → betting-service reserves funds → checks risk → writes bet + Kafka event
      (outbox, atomic with DB transaction) → returns betId to client.

      Failure codes:
        INSUFFICIENT_FUNDS    → 402  (wallet balance too low)
        MARKET_SUSPENDED      → 409  (selection locked by trading)
        ODDS_CHANGED          → 409  (odds drifted since quote)
        STAKE_LIMIT_EXCEEDED  → 422  (RG limit hit)
    \`
  })
  async placeBet(@CurrentUser() user: JwtPayload, @Body() dto: PlaceBetDto) {
    return this.bettingProxy.placeBet(user.sub, dto);
  }

  @Get()
  @Roles(UserRole.PLAYER)
  async getBets(@CurrentUser('sub') userId: string, @Query() query: GetBetsQueryDto) {
    // Open bets → Redis cache; settled bets → PostgreSQL read replica
    return this.bettingProxy.getBets(userId, query);
  }

  @Patch(':betId/cashout')
  @Roles(UserRole.PLAYER)
  @AuditLog('BET_CASHED_OUT')
  @Idempotent()
  @Timeout(8_000) // Cashout credits wallet, slightly longer SLA
  async cashout(
    @CurrentUser('sub') userId: string,
    @Param('betId', ParseUUIDPipe) betId: string,
    @Body() dto: CashoutBetDto,
  ) { return this.bettingProxy.cashout(userId, betId, dto); }

  @Post('price')
  @HttpCode(200)
  @Timeout(2_000) // Must be instant for interactive bet-builder UX
  async previewPrice(@Body() dto: PlaceBetDto) {
    // Read-only: price calculation from Redis odds cache, no DB, no fund reservation
    return this.bettingProxy.previewPrice(dto);
  }

  @Patch(':betId/void')
  @Roles(UserRole.ADMIN, UserRole.SUPER_ADMIN)
  @AuditLog('BET_VOIDED')
  async voidBet(
    @CurrentUser() admin: JwtPayload,
    @Param('betId', ParseUUIDPipe) betId: string,
    @Body('reason') reason: string,
  ) {
    // Saga: mark void → credit stake back → notify user → compliance record
    return this.bettingProxy.voidBet(betId, admin.sub, reason);
  }
}`

S.placeBetDto = `// apps/api-gateway/src/modules/betting/dto/place-bet.dto.ts
// DTOs are the first validation boundary — structural correctness only.
// Business rules (market open, odds valid, limit checks) belong in the domain.
//
// Stake as integer minor units: GBP pence, EUR cents.
// NEVER use floats for money — 0.1 + 0.2 = 0.30000000000000004 in JavaScript.

export class BetSelectionDto {
  @IsUUID(4) marketId: string;
  @IsUUID(4) outcomeId: string;

  // Decimal odds × 1000 stored as integer: 2.50 → 2500
  // Avoids float representation issues throughout the entire pipeline
  @IsNumber() @Min(1001) @Max(100_000)
  quotedOddsDecimalMillis: number;
}

export class PlaceBetDto {
  @IsEnum(BetType)
  type: BetType; // SINGLE | DOUBLE | ACCUMULATOR | TRIXIE | YANKEE ...

  @IsArray() @ArrayMinSize(1) @ArrayMaxSize(20)
  @ValidateNested({ each: true }) @Type(() => BetSelectionDto)
  selections: BetSelectionDto[];

  // Minor units (pence/cents) as positive integer
  // Hard DTO cap: 100,000 currency units. Per-user RG limits enforced downstream.
  @IsNumber({ maxDecimalPlaces: 0 }) @IsPositive() @Max(10_000_000)
  stakeMinorUnits: number;

  @IsEnum(OddsAcceptance) // ANY | BETTER_ONLY | EXACT
  oddsAcceptance: OddsAcceptance = OddsAcceptance.ANY;

  @IsOptional() @IsString()
  currency?: string; // Must match user account currency

  @IsOptional() @IsUUID(4)
  freeBetTokenId?: string; // Bonus token — regulatory tracking required

  @IsOptional() @IsBoolean()
  eachWay?: boolean; // Horse racing: splits stake win part + place part

  @IsOptional() @IsUUID(4)
  quoteId?: string; // Client-side quote reference for odds drift detection
}`

S.circuitBreaker = `// apps/api-gateway/src/modules/betting/betting-proxy.service.ts
// The circuit breaker prevents a degraded betting-service from exhausting
// all gateway threads and taking down the entire API.
//
// States:
//   CLOSED   → normal operation, calls pass through
//   OPEN     → fast-fail immediately, no calls made (saves resources)
//   HALF_OPEN → one probe call; if succeeds → CLOSED, if fails → OPEN
//
// Tuning for a gambling platform (conservative):
//   errorThresholdPercentage: 30  (trip at 30% errors — finance = fail fast)
//   timeout: 4_000                (below the controller's 5s handler timeout)
//   resetTimeout: 15_000          (probe every 15s)
//   volumeThreshold: 20           (min calls before tripping — avoid cold-start trips)

@Injectable()
export class BettingProxyService implements OnModuleInit {
  private grpcBettingService: BettingGrpcService;
  private circuitBreaker: CircuitBreaker;

  onModuleInit() {
    this.grpcBettingService = this.client.getService<BettingGrpcService>('BettingService');

    this.circuitBreaker = new CircuitBreaker(
      async (grpcCall: () => Promise<any>) => grpcCall(),
      { timeout: 4_000, errorThresholdPercentage: 30, resetTimeout: 15_000, volumeThreshold: 20 },
    );

    this.circuitBreaker.on('open',     () => this.logger.error('Circuit OPEN — betting-service unreachable'));
    this.circuitBreaker.on('halfOpen', () => this.logger.warn('Circuit HALF_OPEN — probing'));
    this.circuitBreaker.on('close',    () => this.logger.log('Circuit CLOSED — recovered'));
  }

  async placeBet(userId: string, dto: PlaceBetDto): Promise<any> {
    return this.callWithBreaker(() =>
      firstValueFrom(this.grpcBettingService.placeBet({ userId, ...dto }))
    );
  }

  private async callWithBreaker<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await this.circuitBreaker.fire(fn);
    } catch (err) {
      // Map gRPC status codes → HTTP exceptions
      // UNAVAILABLE      → 503 ServiceUnavailableException
      // FAILED_PRECONDITION → 409 ConflictException (market suspended)
      // RESOURCE_EXHAUSTED  → 429 TooManyRequestsException
      throw this.mapGrpcError(err);
    }
  }
}`

S.websocket = `// apps/api-gateway/src/modules/realtime/realtime.gateway.ts
// WebSocket gateway scaling strategy:
//   Socket.IO + @socket.io/redis-adapter
//   Any gateway pod receives a Kafka event, publishes to Redis pub/sub,
//   adapter broadcasts to ALL connected clients across ALL pods.
//   → Fully stateless, no sticky sessions needed.
//
// Connection budget (10M users, 5% concurrency = 500k simultaneous):
//   Target: 100k connections/pod → need 5+ gateway pods at peak events
//   Pre-warm via HPA on active_websocket_connections Prometheus metric

@WebSocketGateway({ namespace: '/realtime', transports: ['websocket', 'polling'] })
export class RealtimeGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer() server: Server;

  afterInit(server: Server) {
    // Redis adapter must be attached post-init (not in constructor)
    // const pubClient = this.redis.createDedicatedClient();
    // const subClient = pubClient.duplicate();
    // server.adapter(createAdapter(pubClient, subClient));
  }

  async handleConnection(socket: Socket) {
    const token = socket.handshake.auth?.token?.replace('Bearer ', '');
    if (!token) { socket.disconnect(true); return; }

    // Verify JWT (same logic as JwtAuthGuard + blacklist check)
    // const payload = await this.jwtService.verifyAsync(token);
    // socket.data.userId = payload.sub;

    // Join private user room for personal events (bet settled, wallet update)
    // await socket.join(\`user:\${socket.data.userId}\`);

    // Track for RG session timer (4h max, then force logout)
    // await this.redis.set(\`ws:sess:\${socket.id}\`, socket.data.userId, 'EX', 14400);
  }

  @SubscribeMessage('subscribe:market')
  async handleMarketSubscribe(@ConnectedSocket() socket: Socket, @MessageBody() data: { marketIds: string[] }) {
    // Enforce limit: max 100 market subscriptions per socket
    if (socket.rooms.size - 1 + data.marketIds.length > 100)
      throw new WsException({ code: 'SUBSCRIPTION_LIMIT' });

    await Promise.all(data.marketIds.map(id => socket.join(\`market:\${id}:odds\`)));

    // Push current odds snapshot immediately on subscribe
    // const snapshot = await this.redis.hgetall(\`mkt:odds:\${marketId}\`);
    // socket.emit('odds:snapshot', { marketId, odds: snapshot });
    return { subscribed: data.marketIds };
  }

  // Called by Kafka consumer when MARKET_ODDS_UPDATED event arrives
  pushOddsUpdate(marketId: string, update: any) {
    // Redis adapter ensures all pods forward to their local sockets
    this.server.to(\`market:\${marketId}:odds\`).emit('odds:update', update);
  }

  pushUserEvent(userId: string, event: string, data: any) {
    this.server.to(\`user:\${userId}\`).emit(event, data);
  }
}`

S.cqrsCommand = `// apps/betting-service/src/application/commands/place-bet.command.ts
// Commands = immutable intent to mutate state. Named in imperative.
// NOT serialised to DB (that's events). Transient, in-process only.

export class PlaceBetCommand implements ICommand {
  constructor(
    public readonly userId: string,
    public readonly operatorId: string,
    public readonly type: BetType,
    public readonly selections: BetSelectionInput[],
    public readonly stakeMinorUnits: number,
    public readonly oddsAcceptance: OddsAcceptance,
    public readonly currency: string,
    public readonly idempotencyKey: string,  // from Idempotency-Key header
    public readonly correlationId: string,
    public readonly freeBetTokenId?: string,
    public readonly eachWay?: boolean,
    public readonly quoteId?: string,
  ) {}
}

// ── CQRS Module wiring ────────────────────────────────────────────────────────
// Every handler MUST be listed in the module providers array
// for CqrsModule to discover and register it with the appropriate bus.

@Module({
  imports: [CqrsModule, DatabaseModule.forFeature([Bet, BetSelection])],
  controllers: [BettingController, BettingConsumer],
  providers: [
    // Command side (writes)
    PlaceBetHandler, SettleBetHandler, CashoutBetHandler, VoidBetHandler,
    // Query side (reads)
    GetBetHandler, GetBetsHandler, GetCashoutValueHandler,
    // Event side (async side effects)
    BetPlacedEventHandler, BetSettledEventHandler,
    // Saga orchestration
    BetSettlementSaga,
    // Domain services
    OddsService, RgLimitService, BetDomainService,
    // Infrastructure adapters
    BetRepository, BettingProducer, WalletGrpcClient, RiskGrpcClient,
  ],
})
export class BettingModule {}`

S.placeBetHandler = `// apps/betting-service/src/application/commands/handlers/place-bet.handler.ts
// The most critical write path in the system.
// Orchestrates: odds check → RG limits → risk score → wallet reserve → DB write + event
//
// ┌──────────────────────────────────────────────────────────────────────────┐
// │  DISTRIBUTED TRANSACTION (SAGA ORCHESTRATION)                           │
// │                                                                          │
// │  1. OddsService      — validate quoted vs current odds (Redis, <1ms)   │
// │  2. RgLimitService   — check deposit/stake/loss limits (Redis, <2ms)   │
// │  3. RiskGrpcClient   — fraud score from risk-service (gRPC, <5ms)      │
// │  4. DistributedLock  — acquire wallet lock (Redlock, prevents overdraft)│
// │  5. WalletGrpcClient — reserve stake funds in escrow (gRPC)            │
// │  6. DB Transaction   — INSERT bet + INSERT outbox row (ATOMIC)         │
// │  7. Outbox Processor — publishes Kafka event async (reliable delivery)  │
// └──────────────────────────────────────────────────────────────────────────┘

@CommandHandler(PlaceBetCommand)
@Injectable()
export class PlaceBetHandler implements ICommandHandler<PlaceBetCommand> {
  async execute(command: PlaceBetCommand): Promise<{ betId: string; betReference: string }> {
    const { userId, stakeMinorUnits, idempotencyKey } = command;

    // Step 1: Odds still valid?
    // const oddsCheck = await this.oddsService.validateSelectionOdds(command.selections, command.oddsAcceptance);
    // if (!oddsCheck.acceptable) throw new ConflictException({ code: 'ODDS_CHANGED', details: oddsCheck.changes });

    // Step 2: RG limits (REGULATORY — cannot skip for licensed operators)
    // const rgCheck = await this.riskClient.checkRgLimits({ userId, stakeMinorUnits, currency });
    // if (!rgCheck.allowed) throw new UnprocessableEntityException({ code: 'RG_LIMIT_EXCEEDED', ...rgCheck });

    // Step 3: Fraud / risk score (async flag if score > threshold)
    // const risk = await this.riskClient.evaluateBetRisk({ userId, selections, stakeMinorUnits });
    // if (risk.action === 'BLOCK') throw new ConflictException({ code: 'BET_NOT_ACCEPTED' });

    // Step 4-6: Distributed lock → wallet reserve → atomic DB write
    return await this.lock.withLock(\`wallet:\${userId}\`, async () => {
      // const wallet = await this.walletClient.reserveStake({ userId, stakeMinorUnits, idempotencyKey });
      // if (!wallet.success) throw new ConflictException({ code: 'INSUFFICIENT_FUNDS' });

      const queryRunner = this.dataSource.createQueryRunner();
      await queryRunner.connect();
      await queryRunner.startTransaction('SERIALIZABLE'); // Strongest isolation for finance

      try {
        const bet = this.buildBetEntity(command);
        // await queryRunner.manager.save(Bet, bet);

        // OUTBOX: Kafka event + DB row in the SAME commit (dual-write solved)
        // await this.outbox.enqueue(queryRunner.manager, {
        //   topic: KafkaTopics.BET_PLACED, key: userId,
        //   payload: new BetPlacedEvent(bet), headers: { correlationId },
        // });

        await queryRunner.commitTransaction();
        await this.eventBus.publish(new BetPlacedEvent(bet.id, userId, stakeMinorUnits, command.currency, command.correlationId));
        return { betId: bet.id, betReference: bet.betReference };
      } catch (err) {
        await queryRunner.rollbackTransaction();
        // Compensate: release wallet reservation
        // await this.walletClient.releaseReservation({ userId, reference: idempotencyKey });
        throw err;
      } finally {
        await queryRunner.release();
      }
    }, { ttlMs: 5_000, retries: 3 });
  }
}`

S.saga = `// apps/betting-service/src/application/sagas/bet-settlement.saga.ts
// Sagas = long-running reactive processes.
// They listen to the EventBus (RxJS observable) and dispatch new Commands.
// This makes them the ORCHESTRATOR for multi-step distributed workflows.
//
// NestJS @Saga decorator subscribes to ALL events published through EventBus.
// ofType(EventClass) filters to the specific events we care about.
// Returns Observable<ICommand> — each emitted item is dispatched to CommandBus.

@Injectable()
export class BetSettlementSaga {

  // ── Happy path: bet settles ────────────────────────────────────────────────
  // Triggered by BetSettledEvent (from Kafka consumer handling results feed)
  @Saga()
  betSettled = (events$: Observable<any>): Observable<ICommand> =>
    events$.pipe(
      ofType(BetSettledEvent),
      switchMap((event: BetSettledEvent) => {
        const commands: ICommand[] = [
          new UpdateBetStatusCommand(event.betId, event.outcome, event.settlementId),
        ];
        if (event.outcome === 'WON' || event.outcome === 'VOID') {
          // Credit winnings / return stake — idempotency key prevents double-credit
          commands.push(new CreditWinningsCommand(
            event.userId, event.betId, event.payoutMinorUnits, event.currency, event.settlementId
          ));
        }
        commands.push(new NotifyBetSettledCommand(event.userId, event.betId, event.outcome));
        return commands; // each dispatched individually via CommandBus
      }),
      catchError((err) => {
        this.logger.error({ action: 'saga_settlement_error', error: err.message });
        // Dead-letter to Kafka for manual review — never silently drop financial events
        return EMPTY;
      }),
    );

  // ── Compensation: wallet debit failed → rollback ───────────────────────────
  // If PlaceBetHandler rolls back AFTER a successful wallet debit,
  // this saga issues the compensating transaction to release the reservation.
  @Saga()
  walletDebitFailed = (events$: Observable<any>): Observable<ICommand> =>
    events$.pipe(
      ofType(WalletDebitFailedEvent),
      map((event: WalletDebitFailedEvent) =>
        new ReverseWalletDebitCommand(event.userId, event.idempotencyKey, event.reason)
      ),
    );
}`

S.betEntity = `// apps/betting-service/src/domain/entities/bet.entity.ts
// Aggregate Root — owns the bet state machine and all financial invariants.
//
// Financial precision rules:
//   - All monetary values: integer BIGINT minor units (pence/cents)
//   - Odds: integer millis (2.50 → 2500) — never a float in the DB
//   - Calculations: Decimal.js, NOT native JS floats (0.1+0.2 = 0.300...04 is real)
//   - potentialPayoutMinorUnits stored at placement time — audit trail integrity
//
// Partitioning strategy (PostgreSQL):
//   - LIST(status): OPEN bets on hot NVMe SSD partition, settled on cheaper tier
//   - Settled bets archived to cold storage after 90 days (S3/Glacier after 1yr)
//   - Minimum 5yr retention depending on jurisdiction (UKGC, MGA requirements)

@Entity({ name: 'bets', schema: 'betting' })
@Index('idx_bets_user_created', ['userId', 'createdAt'])
@Index('idx_bets_reference', ['betReference'], { unique: true })
@Check('\`stake_minor_units\` > 0')
@Check('\`potential_payout_minor_units\` >= \`stake_minor_units\`')
export class Bet extends BaseEntity {
  @Column({ name: 'user_id', type: 'uuid' }) userId: string;
  @Column({ name: 'operator_id', type: 'uuid' }) operatorId: string;

  // Human-readable reference shown to customer: BET-2024-XJKP9
  // Generated server-side — never user-supplied
  @Column({ name: 'bet_reference', type: 'varchar', length: 30 }) betReference: string;

  @Column({ type: 'enum', enum: BetType })   type: BetType;
  @Column({ type: 'enum', enum: BetStatus, default: BetStatus.PENDING }) status: BetStatus;
  @Column({ type: 'enum', enum: Currency })  currency: Currency;

  @Column({ name: 'stake_minor_units',             type: 'bigint' }) stakeMinorUnits: number;
  @Column({ name: 'combined_odds_millis',           type: 'bigint' }) combinedOddsMillis: number;
  @Column({ name: 'potential_payout_minor_units',   type: 'bigint' }) potentialPayoutMinorUnits: number;
  @Column({ name: 'actual_payout_minor_units', type: 'bigint', nullable: true }) actualPayoutMinorUnits: number | null;

  // Regulatory: track bonus fund usage for wagering requirement calculations
  @Column({ name: 'free_bet_token_id', type: 'uuid', nullable: true }) freeBetTokenId: string | null;

  // RG snapshot at placement time — immutable audit record even if user's profile changes
  @Column({ name: 'rg_snapshot', type: 'jsonb', nullable: true })
  rgSnapshot: { sessionDurationMinutes: number; dailyStakeAccumulated: number; selfExclusionChecked: boolean } | null;

  // Optimistic locking — TypeORM increments on every save.
  // Concurrent cashout + auto-settlement → one gets OptimisticLockVersionMismatchError
  @VersionColumn({ name: 'version', default: 0 }) version: number;

  @OneToMany(() => BetSelection, sel => sel.bet, { cascade: true, eager: false })
  selections: BetSelection[];
}`

S.betRepository = `// apps/betting-service/src/infrastructure/repositories/bet.repository.ts
// Repository pattern: keeps TypeORM details out of the domain layer.
// All queries pass through here — centralises index hints, join strategy, caching.
//
// Read / write split:
//   Writes → always PRIMARY (strong consistency, financial data)
//   Reads  → REPLICA acceptable for history/analytics, NOT for balance/status checks
//
// Keyset pagination (vs offset):
//   Offset pagination is UNSTABLE: if a new bet is inserted between page 1 and 2,
//   an item is repeated or skipped. Keyset is stable because it filters by value.
//   Cursor = base64(JSON { createdAt, betId }) — opaque to the client.

@Injectable()
export class BetRepository extends BaseRepository<Bet> {
  async findByUserIdWithCursor(filter: BetFilter): Promise<{ items: Bet[]; nextCursor: string | null }> {
    const qb = this.getRepository()
      .createQueryBuilder('bet')
      .where('bet.userId = :userId', { userId: filter.userId })
      .orderBy('bet.createdAt', 'DESC')
      .addOrderBy('bet.id', 'DESC')
      .take(filter.limit + 1); // fetch +1 to know if there's a next page

    if (filter.cursor) {
      // Keyset filter: rows strictly after the cursor position
      qb.andWhere('(bet.createdAt, bet.id) < (:createdAt, :betId)',
        { createdAt: filter.cursor.createdAt, betId: filter.cursor.betId });
    }

    if (filter.status) qb.andWhere('bet.status IN (:...statuses)', { statuses: [filter.status].flat() });

    const items = await qb.getMany();
    const hasMore = items.length > filter.limit;
    if (hasMore) items.pop();

    const nextCursor = hasMore
      ? Buffer.from(JSON.stringify({ createdAt: items.at(-1)!.createdAt, betId: items.at(-1)!.id })).toString('base64')
      : null;

    return { items, nextCursor };
  }

  async findOpenBetsByMarket(marketId: string): Promise<Bet[]> {
    // Used by settlement worker. Hits the OPEN partition only (partitioned by status).
    // In batches of 100 to avoid loading millions at once on popular markets.
    return []; // TODO: join to bet_selections WHERE marketId
  }
}`

S.kafkaConsumer = `// apps/betting-service/src/infrastructure/kafka/betting.consumer.ts
// Consumes events from other services. Pure event-driven — no sync dependency.
//
// Key topics:
//   MARKET_ODDS_UPDATED — HIGH VOLUME (1000s/sec during live events)
//     → Only Redis write, no DB touch. Sub-1ms per message.
//   EVENT_SETTLED       — Triggers settlement for all open bets on this event
//   USER_SELF_EXCLUDED  — REGULATORY: must cancel all open bets immediately
//
// Idempotency (at-least-once delivery):
//   Every handler checks Redis deduplication key BEFORE processing.
//   Offset committed manually AFTER successful processing.
//   Dead-letter topic (DLT) after 3 retries → on-call alert.

@Controller()
export class BettingConsumer {
  @MessagePattern(KafkaTopics.EVENT_SETTLED)
  async handleEventSettled(@Payload() payload: any, @Ctx() context: KafkaContext) {
    const { eventId, results } = payload;

    // Idempotency check
    // const processed = await this.redis.exists(\`settled:event:\${eventId}\`);
    // if (processed) { await commitOffset(context); return; }

    // Load open bets in BATCHES (avoid OOM on popular events with 50k bets)
    // const openBets = await this.betRepo.findOpenBetsByEvent(eventId);
    // await Promise.allSettled(
    //   openBets.map(bet => this.commandBus.execute(new SettleBetCommand(bet.id, results, eventId)))
    // );

    // Commit AFTER processing (at-least-once; consumers must be idempotent)
    // await commitOffset(context);
  }

  @EventPattern(KafkaTopics.MARKET_ODDS_UPDATED)
  async handleOddsUpdated(@Payload() payload: { marketId: string; outcomes: any[] }) {
    // Batch Redis pipeline — one network round-trip for all outcome updates
    // const pipeline = this.redis.pipeline();
    // for (const o of payload.outcomes) pipeline.hset(\`mkt:odds:\${payload.marketId}\`, o.id, o.oddsMillis);
    // pipeline.expire(\`mkt:odds:\${payload.marketId}\`, 3600);
    // await pipeline.exec();

    // Push to WebSocket subscribers via Redis pub/sub → adapter → all pods
    // await this.redis.publish('ws:odds:update', JSON.stringify(payload));
  }

  @EventPattern(KafkaTopics.USER_SELF_EXCLUDED)
  async handleSelfExclusion(@Payload() payload: { userId: string }) {
    // REGULATORY — must be implemented for licensed operators
    // 1. Cancel all PENDING/OPEN bets (void, not settle as loss)
    // 2. Return all stakes to wallet
    // 3. Write compliance audit record for every cancellation
    // 4. Set permanent Redis flag to block future bet placement
    // await this.commandBus.execute(new CancelAllOpenBetsCommand(payload.userId, 'SELF_EXCLUSION'));
    // await this.redis.set(\`u:excl:\${payload.userId}\`, '1'); // permanent
  }
}`

S.outbox = `// libs/kafka/src/outbox/outbox.processor.ts
// ─────────────────────────────────────────────────────────────────────────────
// THE OUTBOX PATTERN — solving the dual-write problem
// ─────────────────────────────────────────────────────────────────────────────
//
// Problem: a service must ATOMICALLY write to DB AND publish a Kafka event.
//   ✗ DB write succeeds, Kafka publish fails → event lost, inconsistent state
//   ✗ Kafka publish succeeds, DB write fails → phantom event, inconsistent state
//
// Solution: write a Kafka "outbox" row inside the SAME DB transaction as the
// business entity. A background worker polls this table and publishes to Kafka.
//
//   BEGIN TRANSACTION;
//     INSERT INTO bets VALUES (...);                              ← business entity
//     INSERT INTO outbox (topic, key, payload) VALUES (...);     ← deferred event
//   COMMIT;  ← both succeed or both fail — atomicity guaranteed
//
// The outbox poller (this class) runs every 500ms:
//   SELECT ... FOR UPDATE SKIP LOCKED  ← multiple pods grab different rows
//   kafka.produce(row)
//   UPDATE outbox SET published_at = NOW()
//
// PROD alternative: Debezium CDC (reads PostgreSQL WAL directly → Kafka)
//   + Sub-100ms latency vs 500ms polling
//   + Zero DB load when outbox is empty
//   - Requires Kafka Connect + Debezium connector deployment

@Injectable()
export class OutboxProcessor {
  @Cron('*/500 * * * * *') // every 500ms
  async processOutbox(): Promise<void> {
    if (this.isRunning || this.isShuttingDown) return;
    this.isRunning = true;

    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // SELECT FOR UPDATE SKIP LOCKED: each pod claims unique rows — no duplicates
      // const rows = await queryRunner.query(\`
      //   SELECT id, topic, partition_key, payload, headers
      //   FROM outbox WHERE published_at IS NULL AND retry_count < 3
      //   ORDER BY id ASC LIMIT 100
      //   FOR UPDATE SKIP LOCKED
      // \`);

      // await this.producer.sendBatch(rows.map(r => ({ topic: r.topic, key: r.partition_key, value: r.payload })));
      // await queryRunner.query('UPDATE outbox SET published_at = NOW() WHERE id = ANY($1)', [rows.map(r => r.id)]);
      await queryRunner.commitTransaction();
    } catch (err) {
      await queryRunner.rollbackTransaction();
      // Increment retry_count; after MAX_RETRIES alert on-call and stop retrying
    } finally {
      await queryRunner.release();
      this.isRunning = false;
    }
  }
}`

S.redisLock = `// libs/redis/src/distributed-lock.service.ts
// Redlock algorithm — distributed mutual exclusion across Redis nodes.
// Prevents race conditions:
//   - Two simultaneous bets from the same user overdrafting their balance
//   - Concurrent cashout + automatic settlement of the same bet
//   - Two withdrawal requests racing to drain the same wallet
//
// Why Redlock over simple SETNX?
//   Single-node SETNX loses the lock on Redis failover.
//   Redlock requires N/2+1 nodes to agree (quorum) — tolerates node failure.
//   PROD: 5 independent Redis nodes (not cluster) for correct Redlock quorum.
//
// Lock release: Lua script (compare-and-delete) — atomic.
//   Only the lock holder can release it (prevents releasing another process's lock).

const RELEASE_SCRIPT = \`
  if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
  else return 0 end
\`;

@Injectable()
export class DistributedLockService {
  async withLock<T>(lockKey: string, fn: () => Promise<T>, opts: LockOptions = {}): Promise<T> {
    const { ttlMs = 5_000, retries = 3, retryDelayMs = 200 } = opts;
    const value = randomBytes(16).toString('hex'); // unique token per acquisition
    const key = \`lock:\${lockKey}\`;

    const acquired = await this.acquire(key, value, ttlMs, retries, retryDelayMs);
    if (!acquired) throw new InternalServerErrorException({
      code: 'LOCK_CONTENTION',
      message: 'Resource temporarily unavailable, please retry',
      retryable: true,
    });

    try {
      return await fn();
    } finally {
      // Atomic: check token matches before deleting (prevents releasing another's lock)
      await this.redis.eval(RELEASE_SCRIPT, 1, key, value);
    }
  }

  private async acquire(key: string, value: string, ttlMs: number, retries: number, delayMs: number) {
    for (let i = 0; i <= retries; i++) {
      // SET key value NX PX ttlMs — atomic "set if not exists with TTL"
      const result = await this.redis.set(key, value, 'NX', 'PX', ttlMs);
      if (result === 'OK') return true;
      if (i < retries) await new Promise(r => setTimeout(r, delayMs + Math.random() * delayMs * 0.2));
    }
    return false;
  }
}`

S.rateLimiter = `// libs/redis/src/rate-limiter.service.ts
// Sliding window rate limiter — more accurate than fixed windows.
// Fixed window allows 2× the limit at the boundary (end of window 1 + start of window 2).
// Sliding window counts requests in any rolling [now - windowMs, now] interval.
//
// Algorithm (Redis sorted set):
//   ZADD key [timestamp] [requestId]       ← add current request
//   ZREMRANGEBYSCORE key -inf [windowStart] ← remove expired entries
//   ZCARD key                               ← count in-window requests
//   All in a Lua script (atomic — no race conditions)
//
// Multi-tier enforcement:
//   Tier 1: Per IP (unauthenticated)    — catches bots, scrapers, DDoS probes
//   Tier 2: Per userId (authenticated) — prevents abuse of financial endpoints
//   Tier 3: Per operatorId (B2B)       — SLA enforcement, fair capacity allocation
//
// Response headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset

const SLIDING_WINDOW_SCRIPT = \`
  local key = KEYS[1]
  local now = tonumber(ARGV[1])
  local window = tonumber(ARGV[2])
  local limit = tonumber(ARGV[3])
  local windowStart = now - window
  redis.call('zremrangebyscore', key, '-inf', windowStart)
  local count = redis.call('zcard', key)
  if count < limit then
    redis.call('zadd', key, now, ARGV[4])
    redis.call('pexpire', key, window)
    return {1, limit - count - 1, windowStart + window}
  else
    return {0, 0, windowStart + window}
  end
\`;

@Injectable()
export class RateLimiterService {
  async checkBetPlacementLimit(userId: string): Promise<RateLimitResult> {
    // 10 bets per 10 seconds — prevents scripted/bot betting
    return this.checkLimit(userId, 'bet:place', { windowMs: 10_000, maxRequests: 10 });
  }

  async checkLoginLimit(ipAddress: string): Promise<RateLimitResult> {
    // 10 attempts per 5 minutes — prevents credential stuffing
    // Combined with CAPTCHA at 3 failures, account lockout at 10
    return this.checkLimit(ipAddress, 'auth:login', { windowMs: 300_000, maxRequests: 10 });
  }
}`

S.sessionService = `// libs/redis/src/session.service.ts
// Refresh token lifecycle — single-use rotation with theft detection.
//
// Flow:
//   Login → issue (accessToken 15min, refreshToken 30d)
//   → Store hash(refreshToken) → { userId, deviceInfo } in Redis (TTL 30d)
//   → Client stores refreshToken in HttpOnly cookie (NOT localStorage — XSS risk)
//
//   On access token expiry:
//   → Client sends refreshToken to POST /auth/refresh
//   → Server: verify signature → check Redis exists → DELETE old → SET new
//   → Issue new pair (rotation: single-use)
//
//   Logout: DELETE refreshToken from Redis → immediately invalid
//   Password change: increment tokenVersion in Redis → all access tokens invalid within 15min
//
// Theft detection:
//   If a refreshToken is used that no longer exists in Redis (already rotated):
//   → Either benign double-submit OR the token was stolen and used by attacker first
//   → Conservative response: revoke ALL sessions for this user + security alert

@Injectable()
export class SessionService {
  async validateAndRotateRefreshToken(incomingHash: string, newHash: string, ttlSeconds: number) {
    // Atomic Lua: check → delete old → set new (prevents TOCTOU race)
    const session = await this.redis.get<{ userId: string }>(RedisKeys.refreshToken(incomingHash));

    if (!session) {
      // Token not found — may indicate theft (same refresh token used twice)
      // TODO: Trigger security event → lock all user sessions + alert
      return null;
    }

    await this.redis.del(RedisKeys.refreshToken(incomingHash));
    await this.redis.set(RedisKeys.refreshToken(newHash), session, ttlSeconds);
    return { userId: session.userId };
  }

  async blacklistAccessToken(jti: string, expiresInMs: number): Promise<void> {
    // JWT ID stored with TTL = remaining token lifetime.
    // JwtAuthGuard checks this on EVERY request — must be O(1) → Redis GET.
    await this.redis.set(RedisKeys.jwtBlacklist(jti), '1', Math.ceil(expiresInMs / 1000));
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.redis.incr(RedisKeys.userTokenVersion(userId));
    // Scan + DELETE all refresh tokens for this user
    // (requires reverse index: SADD \`u:sessions:\${userId}\` tokenHash)
  }
}`

S.kafkaTopics = `// libs/common/src/constants/kafka-topics.constant.ts
// Centralised topic registry — NEVER use raw strings in producers/consumers.
// A typo silently creates a new topic and events disappear with no error.
//
// Naming: {domain}.{entity}.{past-tense-verb}  (domain event, not command)
// Schema Registry: every topic has a registered Avro/Protobuf schema.
// Compatibility: BACKWARD_TRANSITIVE — new schema must read old messages.
//
// Retention by category:
//   Financial events:   7 years   (UKGC, MGA regulatory requirement)
//   Operational:        30 days
//   Analytics feed:     90 days   (warehouse ingests within hours)
//   Odds updates:       compacted  (current state only, no history needed)

export const KafkaTopics = {
  // ── Betting ─────────────────────────────────────────────────────────────
  BET_PLACED:              'betting.bet.placed',       // 48 partitions (by userId)
  BET_SETTLED:             'betting.bet.settled',      // 24 partitions (by eventId)
  BET_VOIDED:              'betting.bet.voided',
  BET_CASHED_OUT:          'betting.bet.cashed-out',

  // ── Trading / Markets ────────────────────────────────────────────────────
  MARKET_ODDS_UPDATED:     'trading.market.odds-updated',  // log compacted
  MARKET_SUSPENDED:        'trading.market.suspended',
  EVENT_SETTLED:           'trading.event.settled',

  // ── Wallet (7-year retention) ────────────────────────────────────────────
  WALLET_DEPOSITED:        'wallet.transaction.deposited',
  WALLET_WITHDRAWN:        'wallet.transaction.withdrawn',
  WALLET_STAKE_RESERVED:   'wallet.transaction.stake-reserved',
  WALLET_WINNINGS_CREDITED:'wallet.transaction.winnings-credited',
  WALLET_DEBIT_FAILED:     'wallet.transaction.debit-failed',

  // ── Auth / Compliance ────────────────────────────────────────────────────
  USER_SELF_EXCLUDED:      'auth.user.self-excluded',
  USER_LIMITS_UPDATED:     'auth.user.limits-updated',
  AUDIT_FINANCIAL_ACTION:  'compliance.audit.financial-action', // 7yr retention

  // ── Analytics (feeds data warehouse via Kafka Connect) ───────────────────
  ANALYTICS_BET_EVENT:     'analytics.bet.event',
  ANALYTICS_USER_ACTIVITY: 'analytics.user.activity',
} as const;`

S.redisKeys = `// libs/common/src/constants/redis-keys.constant.ts
// Typed key factory functions — centralised schema for all Redis keys.
// Naming: {domain}:{entity}:{id}:{attribute}
// Always call redis.set with explicit TTL — no immortal keys.
//
// Memory sizing (10M users):
//   JWT blacklist:  10M × 64 bytes  = 640MB  (15min TTL rolling)
//   Sessions:       1M active × 1KB = 1GB
//   RG counters:    10M × 200 bytes = 2GB
//   Market odds:    100K × 500 bytes= 50MB
//   Rate limits:    1M req/min × 30B = 30MB
//   ────────────────────────────────────────
//   Total: ~4GB → ElastiCache r6g.xlarge (13GB) with room for growth

export const RedisKeys = {
  jwtBlacklist:          (jti: string)        => \`jwt:bl:\${jti}\`,        // TTL = token remaining life
  refreshToken:          (hash: string)        => \`rt:\${hash}\`,          // TTL = 30 days
  userTokenVersion:      (userId: string)      => \`u:tv:\${userId}\`,      // permanent
  userSelfExcluded:      (userId: string)      => \`u:excl:\${userId}\`,    // permanent
  userSuspended:         (userId: string)      => \`u:sus:\${userId}\`,     // permanent
  wsSession:             (socketId: string)    => \`ws:sess:\${socketId}\`, // TTL = 4h
  marketOdds:            (marketId: string)    => \`mkt:odds:\${marketId}\`,// TTL = 1h (refreshed on update)
  marketSuspended:       (marketId: string)    => \`mkt:sus:\${marketId}\`, // TTL = until unsuspended
  walletLock:            (userId: string)      => \`lock:wallet:\${userId}\`,// TTL = 5s
  walletBalanceCache:    (userId: string, ccy) => \`w:bal:\${userId}:\${ccy}\`,// TTL = 30s
  rateLimitKey:          (id: string, ep: str) => \`rl:\${ep}:\${id}\`,     // TTL = window size
  idempotencyKey:        (key: string)         => \`idem:\${key}\`,         // TTL = 24h
  operatorConfig:        (operatorId: string)  => \`op:cfg:\${operatorId}\`,// TTL = 5min
  userRgStakeCounters:   (userId: string)      => \`rg:stake:\${userId}\`,  // TTL = rolling window
}`

S.infrastructure = `# docker-compose.yml — key architecture decisions annotated

services:
  postgres-primary:
    image: postgres:16-alpine
    command: >
      postgres
        -c wal_level=logical           # Required for Debezium CDC
        -c max_replication_slots=10    # CDC slots
        -c max_connections=500         # Beyond 200 active, use PgBouncer
        -c shared_buffers=256MB
    # PROD: AWS RDS Multi-AZ / Aurora Serverless v2
    #       PgBouncer in transaction mode for connection pooling

  redis-primary:
    image: redis:7.4-alpine
    command: >
      redis-server
        --maxmemory 512mb
        --maxmemory-policy allkeys-lru  # Evict LRU keys when full
        --appendonly yes                # AOF persistence
        --appendfsync everysec          # Balance durability vs perf
    # PROD: ElastiCache Redis 7 cluster mode (6 nodes across 3 AZs)
    #       Global Datastore for cross-region replication

  kafka-broker-1:
    image: confluentinc/cp-kafka:7.7.0
    environment:
      KAFKA_MIN_INSYNC_REPLICAS: 2       # Require 2 of 3 replicas to ack
      KAFKA_DEFAULT_REPLICATION_FACTOR: 2
      KAFKA_PRODUCER_ENABLE_IDEMPOTENCE: "true"
    # PROD: MSK (Amazon Managed Streaming for Kafka)
    #       3+ brokers across AZs, tiered storage for infinite retention

  schema-registry:
    image: confluentinc/cp-schema-registry:7.7.0
    environment:
      SCHEMA_REGISTRY_SCHEMA_COMPATIBILITY_LEVEL: BACKWARD_TRANSITIVE
    # Enforces Avro/Protobuf contracts across all services.
    # Prevents a breaking schema change from silently corrupting consumers.

  debezium:
    image: debezium/connect:2.7
    # CDC: streams PostgreSQL WAL changes directly to Kafka.
    # Used for: wallet mutations → audit pipeline,
    #           user changes → risk-service cache invalidation
    # Zero-latency alternative to the outbox polling approach.

  jaeger:
    image: jaegertracing/all-in-one:1.61
    # PROD: OTel Collector → Tempo (Grafana stack) or Datadog APM
    # Distributed tracing non-negotiable in a 6-service fleet.
    # Without it, debugging a slow bet placement takes hours.`

// ─── Additional snippets ──────────────────────────────────────────────────────

S.nestDecorators = `// NestJS Decorator Reference — what each decorator does under the hood
//
// Every decorator is a TypeScript factory function that calls
// Reflect.defineMetadata() to attach configuration to the class/method.
// NestJS reads this metadata at startup when it scans the DI container.

// ── @Module ──────────────────────────────────────────────────────────────────
// Root metadata: describes what this module imports, provides, and exports.
//   imports:     other modules whose exported providers this module can use
//   providers:   services/guards registered with DI (singleton by default)
//   controllers: route handlers; NestJS registers @Get/@Post with the HTTP adapter
//   exports:     subset of providers visible to other modules that import this one

@Module({
  imports: [TypeOrmModule.forFeature([Bet, BetSelection])],
  providers: [BetRepository, BetDomainService, PlaceBetHandler],
  controllers: [BettingController],
  exports: [BetRepository],  // only BetRepository is visible outside this module
})
export class BettingModule {}

// ── @Injectable ──────────────────────────────────────────────────────────────
// Marks a class as a DI provider. NestJS reads constructor param types
// via TypeScript's reflect-metadata to automatically resolve dependencies.
// Without @Injectable() the metadata is never emitted — injection silently fails.

@Injectable()
export class OddsService {
  constructor(
    private readonly redis: RedisService,          // injected by type
    @Inject(CONFIG_TOKEN) private readonly cfg: AppConfig, // injected by token
  ) {}
}

// ── @Controller ──────────────────────────────────────────────────────────────
// Registers HTTP route handlers. The path prefix applies to all methods inside.
// version: '1' → /api/v1/bets (requires enableVersioning in main.ts)
@Controller({ path: 'bets', version: '1' })
export class BettingController {}

// ── @Get / @Post / @Patch / @Delete ─────────────────────────────────────────
// Method decorators that register routes with the HTTP adapter (Express/Fastify).
// @HttpCode(201): overrides the default 200 response status for POST handlers.
@Get(':id')               // GET /bets/:id
@Post()                   // POST /bets
@Patch(':id/cashout')     // PATCH /bets/:id/cashout
@HttpCode(201)            // respond 201 on POST
async handler() {}

// ── Parameter decorators ─────────────────────────────────────────────────────
// Each decorator extracts one piece of the incoming request.
async example(
  @Param('id', ParseUUIDPipe) id: string,           // route param, UUID-validated
  @Body() dto: PlaceBetDto,                          // request body → through pipes
  @Query('limit', ParseIntPipe) limit: number,       // ?limit=20 → number
  @Headers('x-correlation-id') corrId: string,       // single header value
  @Req() req: Request,                               // raw Express request (avoid — use specific decorators)
  @CurrentUser() user: JwtPayload,                   // custom decorator (createParamDecorator)
) {}

// ── @UseGuards / @UseInterceptors / @UsePipes / @UseFilters ─────────────────
// Method-level scope: applied to this handler only (vs global APP_GUARD).
// Evaluated AFTER global providers, in left-to-right order.
@Get('admin')
@UseGuards(JwtAuthGuard, RolesGuard)
@UseInterceptors(AuditInterceptor)
@UsePipes(new ValidationPipe({ whitelist: true }))
async adminRoute() {}

// ── createParamDecorator ──────────────────────────────────────────────────────
// Build custom parameter decorators. 'data' is what you pass in the decorator call.
// @CurrentUser() → full JwtPayload
// @CurrentUser('sub') → just the userId string
export const CurrentUser = createParamDecorator(
  (field: keyof JwtPayload | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return field ? request.user?.[field] : request.user;
  },
);

// ── SetMetadata + Reflector ───────────────────────────────────────────────────
// The pattern behind every custom decorator that modifies guard/interceptor behaviour.
// SetMetadata attaches a value to the handler; Reflector reads it.
export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
export const Timeout = (ms: number) => SetMetadata(REQUEST_TIMEOUT_KEY, ms);

// In a guard: read the metadata attached to the current handler
canActivate(ctx: ExecutionContext): boolean {
  const roles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
    ctx.getHandler(), // method-level decorator wins over class-level
    ctx.getClass(),
  ]);
  return roles?.some(r => user.roles.includes(r)) ?? true;
}`

S.diProviders = `// Provider patterns — four ways to register a provider in NestJS DI
// All patterns resolve to the same Reflect.defineMetadata mechanism under the hood.

// ── 1. useClass (most common) ─────────────────────────────────────────────────
// NestJS instantiates the class and resolves its constructor dependencies.
{ provide: OddsService, useClass: OddsService }
// Shorthand (identical):
// providers: [OddsService]

// Swap implementations without changing injection sites:
{
  provide: BetRepository,
  useClass: process.env.NODE_ENV === 'test' ? InMemoryBetRepository : PostgresBetRepository,
}

// ── 2. useFactory ─────────────────────────────────────────────────────────────
// Runs at module init. Supports async — NestJS awaits it before marking the module ready.
// inject[] lists the dependencies passed to the factory as positional arguments.
{
  provide: REDIS_CLIENT,
  useFactory: async (config: ConfigService): Promise<IORedis> => {
    const client = new IORedis({
      host:      config.getOrThrow('REDIS_HOST'),
      port:      config.get<number>('REDIS_PORT', 6379),
      password:  config.get('REDIS_PASSWORD'),
      tls:       config.get('NODE_ENV') === 'production' ? {} : undefined,
      retryStrategy: (times) => Math.min(times * 100, 3000), // exponential backoff cap 3s
      keyPrefix: config.get('REDIS_KEY_PREFIX', 'bp:'),      // namespace isolation
    });
    // Wait for connection before NestJS marks module ready.
    // Without this, the first Redis call may race against connection setup.
    await new Promise<void>((res, rej) => {
      client.once('ready', res);
      client.once('error', rej);
    });
    return client;
  },
  inject: [ConfigService],
}

// ── 3. useValue ───────────────────────────────────────────────────────────────
// Injects a static value. Useful for constants, compiled config, and test mocks.
{ provide: 'MAX_RETRY_ATTEMPTS', useValue: 3 }
{ provide: APP_CONFIG, useValue: { maxBetSizeMinorUnits: 10_000_000 } }

// ── 4. useExisting (alias) ────────────────────────────────────────────────────
// Both tokens resolve to the SAME singleton instance — no second instantiation.
// Use when renaming a service but keeping backward-compatible injection.
{ provide: 'LegacyBetService', useExisting: BettingService }

// ── Injection Scopes ───────────────────────────────────────────────────────────
// DEFAULT (singleton): one instance per DI container lifetime. 99% of services.
// REQUEST: new instance per HTTP request. Required for per-request state.
//   ⚠️  Scope bubble: every provider that injects a REQUEST-scoped service also
//   becomes REQUEST-scoped. This cascades upward and accidentally degrades
//   performance — singleton services turn into per-request allocations.
// TRANSIENT: new instance at every injection point. Almost never needed.

@Injectable({ scope: Scope.REQUEST })
export class RequestContextService {
  // Safe to read request here — a new instance exists for each incoming request
  constructor(@Inject(REQUEST) private readonly req: Request) {}
  getCorrelationId(): string { return this.req.headers['x-correlation-id'] as string; }
}

// ── @Global() ─────────────────────────────────────────────────────────────────
// Exports providers to ALL modules automatically — no import needed.
// Use sparingly: only for true cross-cutting infrastructure (Redis, Kafka, Telemetry).
// Over-using @Global() creates invisible coupling and makes module boundaries meaningless.

@Global()
@Module({ providers: [RedisService], exports: [RedisService] })
export class RedisModule {}`

S.grpcProto = `// libs/proto/betting.proto
// Protocol Buffers: the strongly typed contract between microservices.
// All services share this single source of truth. Generated TypeScript types
// via: npx ts-proto --ts_proto_out=./libs/proto betting.proto

syntax = "proto3";
package betting.v1;

// ── Service definition ────────────────────────────────────────────────────────
// Each rpc maps to exactly one @GrpcMethod() handler in NestJS.
// stream return → Observable<T> in NestJS (server-side streaming).
service BettingService {
  rpc PlaceBet             (PlaceBetRequest)       returns (PlaceBetResponse);
  rpc GetBet               (GetBetRequest)         returns (BetResponse);
  rpc CashoutBet           (CashoutRequest)        returns (CashoutResponse);
  rpc VoidBet              (VoidBetRequest)        returns (VoidBetResponse);
  // Server streaming: continuously pushes updated cashout values to the client
  rpc StreamCashoutValues  (CashoutStreamRequest)  returns (stream CashoutValueUpdate);
}

// ── Messages ──────────────────────────────────────────────────────────────────
// int64 for all monetary values — no floats in protobuf for money.
// optional: field is explicitly absent (proto3 otherwise defaults to 0 / "")
message PlaceBetRequest {
  string   user_id            = 1;
  string   operator_id        = 2;
  string   bet_type           = 3;
  repeated SelectionInput selections = 4;
  int64    stake_minor_units  = 5;  // pence/cents, never float
  string   odds_acceptance    = 6;  // ANY | BETTER_ONLY | EXACT
  string   currency           = 7;
  string   idempotency_key    = 8;  // from Idempotency-Key header
  string   correlation_id     = 9;
  optional string free_bet_token_id = 10;
}

message PlaceBetResponse {
  string bet_id          = 1;
  string bet_reference   = 2;  // human-readable: BET-2024-XJKP9
  int64  potential_payout_minor_units = 3;
}

message SelectionInput {
  string market_id   = 1;
  string outcome_id  = 2;
  int64  quoted_odds_decimal_millis = 3;  // 2.50 → 2500
}

message CashoutStreamRequest { string bet_id = 1; }
message CashoutValueUpdate {
  string bet_id = 1;
  int64  current_value_minor_units = 2;
  bool   available = 3;  // false = stream complete, cashout no longer offered
}

// ── Wallet service proto ──────────────────────────────────────────────────────
service WalletService {
  rpc ReserveStake       (ReserveStakeRequest)   returns (ReserveStakeResponse);
  rpc ReleaseReservation (ReleaseRequest)        returns (ReleaseResponse);
  rpc CreditWinnings     (CreditRequest)         returns (CreditResponse);
  rpc GetBalance         (GetBalanceRequest)     returns (BalanceResponse);
}

message ReserveStakeRequest {
  string user_id            = 1;
  int64  amount_minor_units = 2;
  string currency           = 3;
  string idempotency_key    = 4;  // prevents double-debit on retry
}
message ReserveStakeResponse { bool success = 1; int64 available_after_minor_units = 2; }`

S.grpcService = `// apps/betting-service/src/modules/betting/betting.grpc.controller.ts
// gRPC transport layer — translates protobuf messages to domain Commands.
// No business logic here. The controller is thin: deserialise → command → result.

@Controller()
export class BettingGrpcController {
  constructor(
    private readonly commandBus: CommandBus,
    private readonly queryBus: QueryBus,
  ) {}

  // ── Unary RPC ────────────────────────────────────────────────────────────
  // @GrpcMethod(protoServiceName, rpcMethodName)
  // protoServiceName MUST exactly match the service {} block in the .proto file.
  // Returns a plain object — NestJS serialises it to a protobuf response frame.
  @GrpcMethod('BettingService', 'PlaceBet')
  async placeBet(data: PlaceBetRequest, metadata: Metadata): Promise<PlaceBetResponse> {
    // Extract correlation ID propagated by the API Gateway in gRPC metadata
    const correlationId = metadata.get('x-correlation-id')[0]?.toString() ?? randomUUID();

    // Build the domain command from the protobuf message fields
    const command = new PlaceBetCommand(
      data.userId, data.operatorId, data.betType as BetType,
      data.selections, data.stakeMinorUnits, data.oddsAcceptance as OddsAcceptance,
      data.currency, data.idempotencyKey, correlationId, data.freeBetTokenId,
    );

    const result = await this.commandBus.execute(command);
    return { betId: result.betId, betReference: result.betReference, potentialPayoutMinorUnits: 0 };
  }

  // ── Server-streaming RPC ─────────────────────────────────────────────────
  // Returns Observable<T>. NestJS emits each item as a separate protobuf frame.
  // The stream closes when the Observable completes.
  // Client sets a deadline on the call — NestJS respects gRPC deadlines automatically.
  @GrpcStreamMethod('BettingService', 'StreamCashoutValues')
  streamCashoutValues(data: CashoutStreamRequest, metadata: Metadata): Observable<CashoutValueUpdate> {
    return new Observable(observer => {
      const timer = setInterval(async () => {
        // const value = await this.cashoutCalc.calculate(data.betId);
        // if (!value.available) { observer.complete(); clearInterval(timer); return; }
        // observer.next({ betId: data.betId, currentValueMinorUnits: value.amount, available: true });
      }, 2_000); // recalculate and push every 2 seconds

      // Cleanup on client disconnect or stream error
      return () => clearInterval(timer);
    });
  }
}

// ── apps/betting-service/src/main.ts — Hybrid app (HTTP + gRPC + Kafka) ──────
// connectMicroservice() registers additional transport layers.
// startAllMicroservices() must be called BEFORE app.listen().
async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Transport 1: gRPC — sync service-to-service RPCs
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.GRPC,
    options: {
      package:   'betting.v1',
      protoPath: join(__dirname, '../../../libs/proto/betting.proto'),
      url: '0.0.0.0:5001',
      // Keepalive prevents load balancers from closing idle gRPC connections
      // keepalive: { keepaliveTimeMs: 10_000, keepalivePermitWithoutCalls: 1 }
      // mTLS in prod: credentials.createSsl(rootCert, privateKey, certChain)
    },
  });

  // Transport 2: Kafka — async event consumption
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.KAFKA,
    options: {
      client: { brokers: process.env.KAFKA_BROKERS?.split(',') ?? ['localhost:9092'] },
      consumer: {
        groupId: 'betting-service-v1',  // versioned: new version = new group = replay from head
        allowAutoTopicCreation: false,  // never silently create a topic on typo
      },
      run: { autoCommit: false },  // manual offset commit: at-least-once delivery
    },
  });

  await app.startAllMicroservices();
  await app.listen(3001);  // HTTP health/metrics on 3001, gRPC on 5001
}`

S.jwtStrategy = `// apps/auth-service/src/modules/auth/strategies/jwt.strategy.ts
// Passport strategy invoked by AuthGuard('jwt') on every non-public request.
// It handles: token extraction → signature verification → payload decoding.
// The guard then runs additional checks (blacklist, version, self-exclusion).

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(private readonly config: ConfigService) {
    super({
      // ── Key source ────────────────────────────────────────────────────────
      // Development: simple HS256 shared secret
      // Production:  RS256 asymmetric. Private key only in auth-service.
      //              All other services fetch the public key via JWKS endpoint.
      //              A compromised downstream service cannot forge tokens.
      secretOrKeyProvider: config.get('NODE_ENV') === 'production'
        ? passportJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            // JWKS endpoint served by auth-service: /api/v1/auth/.well-known/jwks.json
            // Contains public key(s). Multiple keys support zero-downtime key rotation.
            jwksUri: config.getOrThrow('JWKS_URI'),
          })
        : (_req: Request, _rawJwt: string, done: (err: null, secret: string) => void) => {
            done(null, config.getOrThrow('JWT_SECRET'));
          },

      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,    // NEVER set true — would accept expired tokens
      algorithms: config.get('NODE_ENV') === 'production' ? ['RS256'] : ['HS256'],
      audience: config.get('JWT_AUDIENCE', 'betting-platform-api'),
      issuer:   config.get('JWT_ISSUER',   'betting-platform-auth'),
    });
  }

  // Return value becomes req.user — available in all downstream guards and handlers.
  // Minimal validation here; business checks (blacklist, version) live in JwtAuthGuard.
  async validate(payload: JwtPayload): Promise<JwtPayload> {
    if (!payload.sub || !payload.roles)
      throw new UnauthorizedException({ code: 'INVALID_TOKEN_PAYLOAD' });
    return payload;
  }
}

// ── JWT Payload shape ─────────────────────────────────────────────────────────
// Embedded in every request — keep it small.
// Do NOT embed fine-grained permissions (too large); embed roles only.
// Add jti for blacklisting and tokenVersion for forced re-auth.
export interface JwtPayload {
  sub:          string;      // userId (UUID) — the primary identity
  email:        string;      // display only; NEVER use for business logic (mutable)
  roles:        UserRole[];  // coarse-grained RBAC
  operatorId?:  string;      // white-label operator context
  kycStatus:    KycStatus;   // drives deposit/withdrawal limits inline (avoids DB lookup)
  jti:          string;      // JWT ID — used to blacklist this specific token
  tokenVersion: number;      // increment to invalidate all tokens for this user
  iat: number;
  exp: number;
}

// ── Auth Controller: login / refresh / logout ─────────────────────────────────
@Controller({ path: 'auth', version: '1' })
export class AuthController {
  // POST /api/v1/auth/login
  // Returns: accessToken in body (15min), refreshToken in HttpOnly cookie (30d)
  @Post('login')
  @Public()
  @HttpCode(200)
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response) {
    // const result = await this.authService.login(dto.email, dto.password);
    // Set refresh token as HttpOnly cookie — inaccessible to JavaScript (XSS-safe)
    // res.cookie('refresh_token', result.refreshToken, {
    //   httpOnly: true, secure: true, sameSite: 'strict',
    //   maxAge: 30 * 24 * 60 * 60 * 1000,
    //   path: '/api/v1/auth/refresh', // scoped: not sent on every request
    // });
    // return { accessToken: result.accessToken, expiresIn: 900 };
  }

  // POST /api/v1/auth/refresh
  // Single-use rotation: old token deleted, new token issued atomically
  @Post('refresh')
  @Public()
  @HttpCode(200)
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    // const refreshToken = req.cookies['refresh_token'];
    // const result = await this.sessionService.validateAndRotateRefreshToken(...);
    // if (!result) throw new UnauthorizedException({ code: 'REFRESH_TOKEN_INVALID' });
    // return { accessToken: result.newAccessToken };
  }

  // POST /api/v1/auth/logout
  @Post('logout')
  @HttpCode(204)
  async logout(@CurrentUser() user: JwtPayload) {
    // Blacklist the current access token with TTL = remaining lifetime
    // await this.sessionService.blacklistAccessToken(user.jti, remainingMs);
    // Delete the refresh token from Redis
    // res.clearCookie('refresh_token');
  }
}`

S.typeormModule = `// libs/database/src/database.module.ts
// TypeORM module: connection pooling, read replicas, schema-per-service isolation,
// migration runner, and fail-fast validation at startup.

@Global()
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService): TypeOrmModuleOptions => ({
        type: 'postgres',
        host:     config.getOrThrow('DB_HOST'),
        port:     config.get<number>('DB_PORT', 5432),
        username: config.getOrThrow('DB_USERNAME'),
        password: config.getOrThrow('DB_PASSWORD'),
        database: config.getOrThrow('DB_NAME'),

        // ── Schema-per-service isolation ──────────────────────────────────
        // Each service owns its schema: betting, wallet, auth, risk.
        // This prevents cross-service table joins at the DB level.
        // schema: config.get('DB_SCHEMA', 'betting'),

        // ── Connection pool ────────────────────────────────────────────────
        // Rule of thumb for Postgres: (num_cores × 2) + effective_spindle_count
        // 4-core container → pool of ~10.
        // Beyond 200 active connections → use PgBouncer in transaction mode.
        extra: {
          max: config.get<number>('DB_POOL_MAX', 10),
          min: config.get<number>('DB_POOL_MIN', 2),
          idleTimeoutMillis:    30_000,
          connectionTimeoutMillis: 5_000,
          // Per-statement guardrails (enforced by PostgreSQL itself)
          statement_timeout: '30s',  // kill runaway queries
          lock_timeout:      '5s',   // fast-fail on contention vs hang forever
        },

        entities:   [__dirname + '/../../**/*.entity{.ts,.js}'],
        migrations: [__dirname + '/../../migrations/*{.ts,.js}'],

        // NEVER true in production — TypeORM drops columns to match entities.
        // One accidental column rename = irreversible data loss.
        synchronize: false,

        // Run pending migrations at startup. Idempotent IF your migrations use
        // IF NOT EXISTS / IF EXISTS — safe in blue/green deployments.
        migrationsRun: config.get('NODE_ENV') !== 'test',

        logging:              config.get('NODE_ENV') === 'development' ? ['query', 'error'] : ['error'],
        maxQueryExecutionTime: 5_000, // log slow queries > 5s (not kill — statement_timeout does that)
      }),
    }),
  ],
  exports: [TypeOrmModule],
})
export class DatabaseModule {
  static forFeature(entities: EntityClassOrSchema[]) {
    return TypeOrmModule.forFeature(entities);
  }
}`

S.baseEntity = `// libs/database/src/base.entity.ts
// All entities extend BaseEntity — centralises audit columns and optimistic locking.

@Entity()
export abstract class BaseEntity {
  // UUID v4: globally unique, no sequential guessing, safe in public URLs.
  // (BIGSERIAL would expose row count and insertion rate to competitors.)
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;

  // Optimistic locking — TypeORM auto-increments on every UPDATE.
  // Two processes read version=5 → both try UPDATE WHERE version=5
  // → one succeeds, the other gets OptimisticLockVersionMismatchError.
  // Prevents: concurrent cashout + auto-settlement updating the same bet row.
  @VersionColumn({ name: 'version', default: 0 })
  version: number;
}

// ── TypeORM Migration example ─────────────────────────────────────────────────
// Migrations are an immutable changelog — never edit existing migrations.
// Create a new one: npx typeorm migration:create src/migrations/AddRgSnapshotToBets
// Naming convention: {timestamp}_{description}

export class AddRgSnapshotToBets1710000000000 implements MigrationInterface {
  async up(queryRunner: QueryRunner): Promise<void> {
    // ADD COLUMN is fast on PG (no table rewrite for nullable columns)
    await queryRunner.query(\`
      ALTER TABLE betting.bets
        ADD COLUMN IF NOT EXISTS rg_snapshot JSONB,
        ADD COLUMN IF NOT EXISTS operator_id UUID;
    \`);

    // CONCURRENTLY: builds index without holding an ACCESS EXCLUSIVE lock.
    // Safe in production — reads and writes continue while the index builds.
    // Cannot run inside a transaction — must be its own query.
    await queryRunner.query(\`
      CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_bets_user_operator
        ON betting.bets (user_id, operator_id, created_at DESC);
    \`);
  }

  async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(\`DROP INDEX IF EXISTS betting.idx_bets_user_operator\`);
    await queryRunner.query(\`
      ALTER TABLE betting.bets
        DROP COLUMN IF EXISTS rg_snapshot,
        DROP COLUMN IF EXISTS operator_id;
    \`);
  }
}`

S.walletEntity = `// apps/wallet-service/src/domain/entities/wallet.entity.ts
// Financial ledger — the most consistency-critical entity in the system.
// All values: BIGINT minor units. No nullable balances — default to 0.
// @Check constraints are enforced by PostgreSQL even if the ORM is bypassed.

@Entity({ name: 'wallets', schema: 'wallet' })
@Index('idx_wallets_user', ['userId'], { unique: true })
@Check(\`"real_balance_minor_units" >= 0\`)
@Check(\`"in_play_stake_minor_units" >= 0\`)
export class Wallet extends BaseEntity {
  @Column({ name: 'user_id', type: 'uuid', unique: true }) userId: string;
  @Column({ name: 'operator_id', type: 'uuid' }) operatorId: string;
  @Column({ type: 'enum', enum: Currency }) currency: Currency;

  // Real money deposited by the user
  @Column({ name: 'real_balance_minor_units', type: 'bigint', default: 0 })
  realBalanceMinorUnits: number;

  // Bonus: wagering requirements apply, cannot withdraw directly
  @Column({ name: 'bonus_balance_minor_units', type: 'bigint', default: 0 })
  bonusBalanceMinorUnits: number;

  // Funds escrowed for open bets: realBalance - inPlayStake = withdrawable balance
  @Column({ name: 'in_play_stake_minor_units', type: 'bigint', default: 0 })
  inPlayStakeMinorUnits: number;

  // AML: frozen wallets can deposit but cannot withdraw (suspicious activity)
  @Column({ name: 'is_frozen', type: 'boolean', default: false }) isFrozen: boolean;

  // Computed (not persisted) — only ever read from this getter, never calculated inline
  get availableBalanceMinorUnits(): number {
    return this.realBalanceMinorUnits - this.inPlayStakeMinorUnits;
  }
}

// ── WalletTransaction entity — immutable ledger ───────────────────────────────
// Never UPDATE or DELETE transaction rows.
// Every balance change produces one append-only transaction record.
// The idempotency_key prevents duplicate credits if the bet settlement retries.

@Entity({ name: 'wallet_transactions', schema: 'wallet' })
@Index('idx_wallet_txns_wallet_date', ['walletId', 'createdAt'])
export class WalletTransaction extends BaseEntity {
  @Column({ name: 'wallet_id', type: 'uuid' }) walletId: string;

  @Column({ type: 'enum', enum: TransactionType })
  type: TransactionType;  // DEPOSIT | WITHDRAWAL | STAKE_RESERVE | WINNINGS_CREDIT

  // Always positive — direction is implied by the type enum
  @Column({ name: 'amount_minor_units', type: 'bigint' }) amountMinorUnits: number;

  // betId, depositId, withdrawalId — what triggered this transaction
  @Column({ name: 'reference_id', type: 'uuid' }) referenceId: string;

  // Prevents duplicate credits on retry: INSERT ... ON CONFLICT (idempotency_key) DO NOTHING
  @Column({ name: 'idempotency_key', type: 'varchar', length: 64, unique: true })
  idempotencyKey: string;

  // Snapshot for audit: "balance was 5000, this credit of 500 made it 5500"
  @Column({ name: 'balance_before_minor_units', type: 'bigint' }) balanceBeforeMinorUnits: number;
  @Column({ name: 'balance_after_minor_units',  type: 'bigint' }) balanceAfterMinorUnits: number;
}`

S.rgService = `// apps/risk-service/src/modules/risk/rg-limit.service.ts
// Responsible Gambling (RG) — mandatory for every licensed gambling operator.
// UKGC, MGA, and most European jurisdictions require:
//   • Deposit / loss / stake limits (daily, weekly, monthly)
//   • Session time limits (e.g. max 4h continuous play)
//   • Mandatory cooling-off periods (cannot reduce self-exclusion early)
//   • Self-exclusion (permanent or time-limited account ban)
//   • Reality checks (pop-up after 1h: "You've been playing for X hours")
//
// Architecture: limits stored in DB (source of truth) + Redis (hot cache for bet path).
// Limit checks on every bet: O(1) Redis lookup, never a DB query on the hot path.

@Injectable()
export class RgLimitService {
  // ── Check limits before allowing a bet ───────────────────────────────────
  async checkBetLimits(params: {
    userId: string;
    stakeMinorUnits: number;
    currency: string;
  }): Promise<{ allowed: boolean; reason?: string; limitType?: string }> {
    const [dailyUsed, weeklyUsed, limits] = await Promise.all([
      this.redis.get<number>(\`rg:stake:daily:\${params.userId}\`),
      this.redis.get<number>(\`rg:stake:weekly:\${params.userId}\`),
      this.getUserLimitsFromCache(params.userId),
    ]);

    if (limits?.maxStakePerBet && params.stakeMinorUnits > limits.maxStakePerBet)
      return { allowed: false, reason: 'Stake exceeds per-bet limit', limitType: 'STAKE_PER_BET' };

    if (limits?.dailyStakeLimit && ((dailyUsed ?? 0) + params.stakeMinorUnits) > limits.dailyStakeLimit)
      return { allowed: false, reason: 'Daily stake limit reached', limitType: 'DAILY_STAKE' };

    if (limits?.weeklyStakeLimit && ((weeklyUsed ?? 0) + params.stakeMinorUnits) > limits.weeklyStakeLimit)
      return { allowed: false, reason: 'Weekly stake limit reached', limitType: 'WEEKLY_STAKE' };

    // Session time check: RG timer started on login, checked on each bet
    // const sessionMins = await this.redis.get<number>(\`rg:session:\${userId}\`);
    // if (limits?.sessionTimeLimitMins && (sessionMins ?? 0) > limits.sessionTimeLimitMins)
    //   return { allowed: false, reason: 'Session time limit reached', limitType: 'SESSION_TIME' };

    return { allowed: true };
  }

  // ── Self-exclusion: set a permanent or time-limited account ban ───────────
  // CANNOT be reversed before the cooling-off period (UKGC: minimum 6 months).
  // This is enforced at: JwtAuthGuard, bet placement, deposit, and game launch.
  async setSelfExclusion(userId: string, durationDays: number | 'permanent'): Promise<void> {
    const key = \`u:excl:\${userId}\`;
    if (durationDays === 'permanent') {
      await this.redis.set(key, 'permanent');   // no TTL — permanent
    } else {
      await this.redis.set(key, 'excluded', durationDays * 86_400);
    }
    // Saga: cancel all open bets (void, refund stake), freeze deposits, send email
    await this.eventBus.publish(new UserSelfExcludedEvent(userId, durationDays));
  }

  // ── Deposit limit change with cooling-off ─────────────────────────────────
  // Reducing limits → effective IMMEDIATELY (protective: user wants less risk)
  // Increasing limits → 24h cooling-off period (prevents impulsive reversal)
  async updateDepositLimit(userId: string, newLimitMinorUnits: number): Promise<void> {
    // const current = await this.getUserDepositLimit(userId);
    // if (newLimitMinorUnits > current) {
    //   await this.db.save(PendingLimitChange, { userId, newLimit, effectiveAt: addHours(now(), 24) });
    //   return; // scheduled job applies it after 24h
    // }
    // await this.applyLimitImmediately(userId, newLimitMinorUnits);
  }
}`

S.otelTracing = `// libs/telemetry/src/tracing.init.ts
// ⚡ MUST be the very first import in main.ts
// OpenTelemetry SDK monkey-patches modules at load time.
// If pg / ioredis / kafkajs load before the SDK, they cannot be instrumented
// and you get no database/cache/queue spans in your traces.

import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { SEMRESATTRS_SERVICE_NAME, SEMRESATTRS_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';
import { IORedisInstrumentation } from '@opentelemetry/instrumentation-ioredis';
import { KafkaJsInstrumentation } from '@opentelemetry/instrumentation-kafkajs';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { GrpcInstrumentation } from '@opentelemetry/instrumentation-grpc';

const sdk = new NodeSDK({
  resource: new Resource({
    [SEMRESATTRS_SERVICE_NAME]:    process.env.SERVICE_NAME    ?? 'api-gateway',
    [SEMRESATTRS_SERVICE_VERSION]: process.env.npm_package_version ?? '0.0.0',
    'deployment.environment':      process.env.NODE_ENV        ?? 'development',
  }),

  traceExporter: new OTLPTraceExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? 'http://localhost:4318/v1/traces',
  }),

  // ── Auto-instrumentation ────────────────────────────────────────────────────
  // Each plugin wraps the library to emit spans automatically.
  // pg → span per SQL query (includes table name, row count)
  // ioredis → span per Redis command
  // kafkajs → span per produce/consume
  // http / grpc → span per incoming and outgoing request
  instrumentations: [
    new HttpInstrumentation({
      // Ignore health check probes — they generate noise without insight
      ignoreIncomingRequestHook: (req) => req.url?.includes('/health') ?? false,
    }),
    new GrpcInstrumentation(),
    new PgInstrumentation({ enhancedDatabaseReporting: false }), // false = no SQL params in spans (PII)
    new IORedisInstrumentation(),
    new KafkaJsInstrumentation(),
  ],
});

sdk.start();
// Flush pending spans before process exits (k8s SIGTERM / graceful shutdown)
process.on('SIGTERM', () => sdk.shutdown());

// ── TracingInterceptor ─────────────────────────────────────────────────────────
// Creates a named span for every NestJS controller handler.
// Auto-instrumentation handles DB/Redis/Kafka child spans inside.
// The interceptor provides the application-level root span with business context.

@Injectable()
export class TracingInterceptor implements NestInterceptor {
  intercept(ctx: ExecutionContext, next: CallHandler): Observable<any> {
    const tracer = trace.getTracer('nestjs-handler');
    const handlerName = \`\${ctx.getClass().name}.\${ctx.getHandler().name}\`;

    // startActiveSpan: makes this span the parent for all child spans created within
    return new Observable(subscriber => {
      tracer.startActiveSpan(handlerName, { kind: SpanKind.INTERNAL }, (span) => {
        const req = ctx.switchToHttp().getRequest();
        span.setAttributes({
          'http.method':       req.method,
          'http.route':        req.route?.path ?? req.url,
          'user.id':           req.user?.sub   ?? 'anonymous',
          'correlation.id':    req.headers['x-correlation-id'] ?? '',
        });

        next.handle().pipe(
          tap(() => { span.setStatus({ code: SpanStatusCode.OK }); span.end(); }),
          catchError((err) => {
            span.recordException(err);
            span.setStatus({ code: SpanStatusCode.ERROR, message: err.message });
            span.end();
            return throwError(() => err);
          }),
        ).subscribe(subscriber);
      });
    });
  }
}`

S.pinoConfig = `// Pino structured logging — configured in AppModule's LoggerModule.forRootAsync()
// Pino is 5× faster than Winston for high-throughput JSON output.
// Every log line is a valid JSON object, ingested directly by Datadog/Loki/CloudWatch.

LoggerModule.forRootAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    pinoHttp: {
      level: config.get('NODE_ENV') === 'production' ? 'info' : 'trace',

      // ── PII Redaction ───────────────────────────────────────────────────
      // GDPR Article 25: privacy by design. These paths are scrubbed
      // from every log entry before it is written to any transport.
      redact: {
        paths: [
          'req.headers.authorization',    // Bearer token
          'req.headers.cookie',           // session cookie
          'req.body.password',
          'req.body.cardNumber',
          'req.body.iban',
          'req.body.cvv',
          'res.headers["set-cookie"]',
        ],
        censor: '[REDACTED]',
      },

      // ── Request/response serialisers ─────────────────────────────────────
      // Define EXACTLY what gets logged. Default serialisers include too much.
      serializers: {
        req: (req) => ({
          method:        req.method,
          url:           req.url,
          correlationId: req.headers['x-correlation-id'],
          userAgent:     req.headers['user-agent'],
          // NEVER: IP address (PII), full headers, full body
        }),
        res: (res) => ({ statusCode: res.statusCode }),
      },

      // Dev: pretty-print for human readability.
      // In production: remove entirely (perf overhead, breaks JSON ingestion)
      transport: config.get('NODE_ENV') !== 'production'
        ? { target: 'pino-pretty', options: { colorize: true, translateTime: 'SYS:standard' } }
        : undefined,

      // Auto-logged fields on every HTTP request/response:
      //   req.method, req.url, res.statusCode, responseTime (ms), correlationId
      customSuccessMessage: () => 'request completed',
      customErrorMessage:   (_req, res) => \`request failed with status \${res.statusCode}\`,
    },
  }),
})

// ── Structured log output (example JSON line) ─────────────────────────────────
// {
//   "level":         30,
//   "time":          1710000000000,
//   "pid":           1,
//   "correlationId": "7f3c2a1b-...",
//   "userId":        "a9b8c7d6-...",
//   "method":        "POST",
//   "url":           "/api/v1/bets",
//   "statusCode":    201,
//   "responseTime":  23,
//   "msg":           "request completed"
// }
//
// Every field is queryable in Datadog/Grafana Loki with zero parsing configuration.`

S.bullmqQueues = `// apps/notification-service/src/app.module.ts
// BullMQ priority queues: critical notifications never wait behind marketing emails.
// Three separate queues with different retry policies and priority levels.

@Module({
  imports: [
    BullModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: {
          host:     config.getOrThrow('REDIS_HOST'),
          port:     config.get<number>('REDIS_PORT', 6379),
          password: config.get('REDIS_PASSWORD'),
          // ⚠ Use a dedicated Redis DB for queues (db: 1).
          // Cache uses allkeys-lru eviction policy — which would silently delete queued jobs.
          db: 1,
        },
        defaultJobOptions: {
          attempts: 3,
          backoff: { type: 'exponential', delay: 5_000 }, // 5s, 10s, 20s
          removeOnComplete: { count: 1_000 },  // keep for debugging
          removeOnFail:     { count: 5_000 },  // keep failed jobs for inspection
        },
      }),
    }),

    // Three queues, lowest number = highest priority
    BullModule.registerQueue(
      { name: 'notification:critical',      defaultJobOptions: { priority: 1, attempts: 5 } },
      { name: 'notification:transactional', defaultJobOptions: { priority: 2, attempts: 3 } },
      { name: 'notification:marketing',     defaultJobOptions: { priority: 3, attempts: 2 } },
    ),
  ],
  providers: [NotificationProducer, NotificationProcessor, EmailService, SmsService, PushService],
})
export class NotificationModule {}

// ── Notification Processor ─────────────────────────────────────────────────────
@Processor('notification:transactional')
export class NotificationProcessor extends WorkerHost {
  // process() is called by BullMQ worker for each dequeued job.
  // If it throws, BullMQ will retry according to the backoff policy.
  async process(job: Job<NotificationJob>): Promise<void> {
    const { userId, type, data, channels } = job.data;

    // Fan-out: same event → multiple channels based on user preferences
    const deliveries = channels.map(channel => {
      switch (channel) {
        case 'email': return this.emailService.send({ userId, template: type, data });
        case 'sms':   return this.smsService.send({ userId, message: data.shortMessage });
        case 'push':  return this.pushService.send({ userId, title: data.title, body: data.body });
        default:      return Promise.resolve();
      }
    });

    // Promise.allSettled: if email fails, push/SMS still deliver.
    // Never use Promise.all here — one channel failure would block the others.
    const results = await Promise.allSettled(deliveries);
    const failures = results.filter(r => r.status === 'rejected');
    if (failures.length > 0) {
      // Partial failure: log but do NOT rethrow (avoids re-sending to channels that succeeded)
      this.logger.warn({ jobId: job.id, failedChannels: failures.length }, 'Partial delivery failure');
    }
  }

  // ── Worker event hooks ─────────────────────────────────────────────────────
  @OnWorkerEvent('failed')
  onFailed(job: Job, err: Error) {
    // Exhausted all retries — alert on-call. NEVER silently drop transactional notifications.
    if (job.attemptsMade >= (job.opts.attempts ?? 1)) {
      this.logger.error({ jobId: job.id, type: job.data.type, err: err.message }, 'Job dead-lettered');
      // this.alertingService.page('notification-dlq', { jobId: job.id });
    }
  }

  @OnWorkerEvent('stalled')
  onStalled(jobId: string) {
    // Stalled = worker died mid-processing. BullMQ auto-retries but log it.
    this.logger.warn({ jobId }, 'Job stalled — worker likely crashed');
  }
}`

S.pipes = `// Pipes: transform and validate data BEFORE it reaches the handler.
// Applied in this order: Global → Controller-level → Route-level → Parameter-level.
// NestJS built-in pipes: ValidationPipe, ParseIntPipe, ParseUUIDPipe,
//   ParseBoolPipe, ParseArrayPipe, DefaultValuePipe.

// ── Global ValidationPipe (configured in main.ts) ──────────────────────────
app.useGlobalPipes(new ValidationPipe({
  // Strip properties not defined on the DTO class.
  // Prevents mass-assignment attacks where attacker sends unexpected fields.
  whitelist: true,

  // Throw 400 instead of silently stripping (loud failure > silent permissiveness)
  forbidNonWhitelisted: true,

  // Coerce types: "?page=1" (string) → 1 (number) when @Type(() => Number) is set.
  // Eliminates manual parseInt() in every query handler.
  transform: true,
  transformOptions: { enableImplicitConversion: true },

  // Structured error response instead of NestJS default:
  //   { "statusCode": 400, "message": ["stakeMinorUnits must be positive"] }
  exceptionFactory: (errors: ValidationError[]) => new BadRequestException({
    code: 'VALIDATION_ERROR',
    fields: errors.map(e => ({
      field: e.property,
      constraints: Object.values(e.constraints ?? {}),
      children: e.children?.map(c => c.property) ?? [],
    })),
  }),
}));

// ── class-validator decorators on a real DTO ─────────────────────────────────
export class GetBetsQueryDto {
  @IsOptional()
  @IsString()
  cursor?: string;  // opaque base64 pagination cursor

  @IsOptional()
  @Type(() => Number)     // transform "20" → 20 (needs transform: true in ValidationPipe)
  @IsInt()
  @Min(1) @Max(100)
  limit: number = 20;     // DefaultValuePipe alternative: @DefaultValuePipe(20)

  @IsOptional()
  @IsEnum(BetStatus)
  status?: BetStatus;

  @IsOptional()
  @IsDateString()         // validates ISO 8601: "2024-03-15T10:00:00Z"
  fromDate?: string;

  @IsOptional()
  @IsEnum(Currency)
  currency?: Currency;
}

// ── Custom pipe: decode and validate an opaque pagination cursor ─────────────
@Injectable()
export class ParseCursorPipe implements PipeTransform {
  transform(value: string | undefined): { createdAt: string; betId: string } | null {
    if (!value) return null;
    try {
      const decoded = Buffer.from(value, 'base64').toString('utf-8');
      const cursor = JSON.parse(decoded);
      if (!cursor.createdAt || !cursor.betId) throw new Error('missing fields');
      return cursor;
    } catch {
      throw new BadRequestException({
        code: 'INVALID_CURSOR',
        message: 'Pagination cursor is malformed or tampered',
      });
    }
  }
}

// Usage: @Query('cursor', ParseCursorPipe) cursor: CursorToken | null

// ── @ValidateNested + @Type: nested DTO validation ───────────────────────────
// Without @Type(), class-transformer doesn't know to deserialise the nested object.
// Without @ValidateNested(), class-validator skips nested validation entirely.
export class PlaceBetDto {
  @IsArray()
  @ValidateNested({ each: true })   // validate each element in the array
  @Type(() => BetSelectionDto)      // deserialise each element as BetSelectionDto
  @ArrayMinSize(1)
  @ArrayMaxSize(20)
  selections: BetSelectionDto[];
}`

S.lifecycleHooks = `// NestJS Module Lifecycle & Health Checks
//
// ── STARTUP execution order ────────────────────────────────────────────────────
// 1. All provider constructors run (DI graph resolved)
// 2. onModuleInit()          — per provider, in dependency order
// 3. onApplicationBootstrap() — after ALL modules have initialised
// 4. HTTP server / gRPC transport starts accepting connections
//
// ── SHUTDOWN execution order (triggered by app.enableShutdownHooks() + SIGTERM) ─
// 1. onModuleDestroy()            — per provider (clean up resources)
// 2. beforeApplicationShutdown()  — last chance before connections close
// 3. HTTP server stops accepting new connections
// 4. In-flight requests drain (k8s terminationGracePeriodSeconds window)
// 5. Process exits

@Injectable()
export class KafkaProducerService implements OnModuleInit, OnModuleDestroy {
  private producer: Producer;

  // onModuleInit: called once all DI providers are constructed.
  // Use for: opening connections, loading config caches, warming up pools.
  async onModuleInit(): Promise<void> {
    this.producer = this.kafka.producer({
      idempotent: true,            // exactly-once within Kafka producer session
      maxInFlightRequests: 5,
    });
    await this.producer.connect();
    this.logger.log('Kafka producer connected');
  }

  // onModuleDestroy: called when app receives SIGTERM (k8s rolling deploy).
  // flush() waits for any pending messages before disconnecting.
  // app.enableShutdownHooks() in main.ts MUST be called or this hook never fires.
  async onModuleDestroy(): Promise<void> {
    this.logger.log('Flushing Kafka producer...');
    await this.producer.flush({ timeout: 5_000 });
    await this.producer.disconnect();
  }
}

// ── Health checks with @nestjs/terminus ──────────────────────────────────────
// Kubernetes liveness probe: is the process alive? (restart if not)
// Kubernetes readiness probe: is it ready to serve? (remove from load balancer if not)
// A readiness probe that returns 503 during DB reconnection prevents request loss.

@Controller('health')
export class HealthController {
  constructor(
    private health: HealthCheckService,
    private db: TypeOrmHealthIndicator,
  ) {}

  // Readiness: all critical dependencies must be healthy
  @Get('ready')
  @HealthCheck()
  ready() {
    return this.health.check([
      () => this.db.pingCheck('database', { timeout: 2_000 }),
      // () => this.redis.isHealthy('redis'),
      // () => this.kafka.isConnected('kafka'),
    ]);
    // Returns HTTP 200 { status: 'ok', ... } or 503 { status: 'error', ... }
  }

  // Liveness: just the process — a 503 triggers a pod restart
  @Get('live')
  live() {
    return { status: 'ok', uptime: process.uptime() };
  }
}`

// ─── Additional snippets (batch 2) ───────────────────────────────────────────

S.executionContext = `// ExecutionContext — the single object passed to every guard and interceptor.
// It wraps the current request regardless of transport (HTTP, gRPC, WebSocket).
// The most important skill for writing reusable NestJS infrastructure code.

// ── getType() — which transport delivered this request? ──────────────────────
canActivate(ctx: ExecutionContext): boolean {
  const type = ctx.getType<'http' | 'rpc' | 'ws' | 'graphql'>();
  // 'http'    → Express/Fastify: @Get, @Post …
  // 'rpc'     → gRPC (@GrpcMethod) or Kafka (@MessagePattern, @EventPattern)
  // 'ws'      → Socket.IO gateway (@SubscribeMessage)
  // 'graphql' → Apollo GraphQL resolver
}

// ── switchToHttp() — access the Express Request/Response ────────────────────
const httpCtx = ctx.switchToHttp();
const req  = httpCtx.getRequest<Request>();
const res  = httpCtx.getResponse<Response>();

// ── switchToRpc() — access gRPC or Kafka message context ────────────────────
const rpcCtx = ctx.switchToRpc();
const data     = rpcCtx.getData();      // deserialized payload
const metadata = rpcCtx.getContext();   // gRPC Metadata or KafkaContext

// ── switchToWs() — access Socket.IO client and payload ──────────────────────
const wsCtx = ctx.switchToWs();
const socket = wsCtx.getClient<Socket>();
const data   = wsCtx.getData();

// ── Writing a transport-agnostic guard ────────────────────────────────────────
// One guard class — works on HTTP endpoints, gRPC methods, AND WebSocket handlers.
// No duplicate JwtAuthGuard per transport.

@Injectable()
export class UniversalAuthGuard implements CanActivate {
  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const token = this.extractToken(ctx);
    if (!token) throw new UnauthorizedException({ code: 'TOKEN_MISSING' });

    const user = await this.jwtService.verifyAsync<JwtPayload>(token);
    this.attachUser(ctx, user);
    return true;
  }

  private extractToken(ctx: ExecutionContext): string | null {
    switch (ctx.getType()) {
      case 'http': {
        const req = ctx.switchToHttp().getRequest();
        return req.headers.authorization?.replace('Bearer ', '') ?? null;
      }
      case 'rpc': {
        // gRPC: token passed in Metadata by the API gateway
        const meta = ctx.switchToRpc().getContext<Metadata>();
        return meta.get('authorization')[0]?.toString()?.replace('Bearer ', '') ?? null;
      }
      case 'ws': {
        // WebSocket: token in socket.handshake.auth (sent at connection time)
        const socket = ctx.switchToWs().getClient<Socket>();
        return socket.handshake.auth?.token?.replace('Bearer ', '') ?? null;
      }
      default: return null;
    }
  }

  private attachUser(ctx: ExecutionContext, user: JwtPayload): void {
    switch (ctx.getType()) {
      case 'http':  ctx.switchToHttp().getRequest().user = user;                       break;
      case 'rpc':   ctx.switchToRpc().getContext<Metadata>().set('user', JSON.stringify(user)); break;
      case 'ws':    ctx.switchToWs().getClient<Socket>().data.user = user;             break;
    }
  }
}

// ── getHandler() and getClass() — reading metadata in guards/interceptors ────
// getHandler() → the CONTROLLER METHOD being called right now.
// getClass()   → the CONTROLLER CLASS containing that method.
// getAllAndOverride: method-level metadata wins; falls back to class-level.

const roles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
  ctx.getHandler(),  // @Roles() placed on the handler method
  ctx.getClass(),    // @Roles() placed on the controller class
]);
// If both are set, the method-level value takes precedence.`

S.dynamicModules = `// Dynamic Modules — the pattern behind every forRoot() / forRootAsync() / forFeature().
// A dynamic module is just a module factory method that returns a DynamicModule object.
// It lets the caller pass configuration INTO the module at import time.
//
// Use static .forRoot() for: eager sync config (options object known at compile time).
// Use static .forRootAsync() for: async config that needs ConfigService or other providers.
// Use static .forFeature() for: scoped, non-global registrations (TypeORM entities, queues).

@Module({})  // empty — all providers are added dynamically inside the factory methods
export class RedisModule {

  // forRoot: synchronous; caller passes a plain options object
  static forRoot(options: RedisOptions): DynamicModule {
    return {
      module:   RedisModule,
      global:   true,   // same as @Global() but set programmatically
      providers: [
        { provide: REDIS_OPTIONS, useValue: options },
        RedisService,
      ],
      exports:  [RedisService],
    };
  }

  // forRootAsync: most common pattern; inject ConfigService into the factory
  static forRootAsync(opts?: {
    imports?:    any[];
    useFactory?: (...args: any[]) => RedisOptions | Promise<RedisOptions>;
    inject?:     any[];
  }): DynamicModule {
    return {
      module:  RedisModule,
      global:  true,
      imports: opts?.imports ?? [],  // caller imports ConfigModule here
      providers: [
        {
          provide:    REDIS_OPTIONS,
          useFactory: opts?.useFactory ?? (() => ({})),
          inject:     opts?.inject     ?? [],
        },
        {
          provide: REDIS_CLIENT,
          useFactory: async (options: RedisOptions): Promise<IORedis> => {
            const client = new IORedis(options);
            // Wait for connection BEFORE NestJS marks the module as ready.
            // Without this, the first Redis call races against the connection setup.
            await new Promise<void>((res, rej) => {
              client.once('ready', res);
              client.once('error', rej);
            });
            return client;
          },
          inject: [REDIS_OPTIONS],
        },
        RedisService,
      ],
      exports: [RedisService, REDIS_CLIENT],
    };
  }

  // forFeature: non-global, scoped to the importing module only
  // e.g. RedisModule.forFeature(['user-events', 'bet-events']) registers two queues
  static forFeature(queues: string[]): DynamicModule {
    const providers = queues.map(name => ({
      provide:    \`QUEUE_\${name.toUpperCase().replace(/-/g, '_')}\`,
      useFactory: (client: IORedis) => new Queue(name, { connection: client }),
      inject:     [REDIS_CLIENT],
    }));
    return {
      module:    RedisModule,
      providers,
      exports:   providers.map(p => p.provide),
    };
  }
}

// ── Consuming a dynamic module ────────────────────────────────────────────────
@Module({
  imports: [
    RedisModule.forRootAsync({
      imports:    [ConfigModule],
      useFactory: (config: ConfigService) => ({
        host:     config.getOrThrow('REDIS_HOST'),
        port:     config.get<number>('REDIS_PORT', 6379),
        password: config.get('REDIS_PASSWORD'),
        tls:      config.get('NODE_ENV') === 'production' ? {} : undefined,
      }),
      inject: [ConfigService],
    }),
    RedisModule.forFeature(['notification:critical', 'notification:transactional']),
  ],
})
export class AppModule {}`

S.serialization = `// ClassSerializerInterceptor — transforms response objects using class-transformer.
// Applied globally: { provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor }
// Lets you define WHAT fields are in the API response at the class level, not in each handler.

// ── @Exclude — strip a field from every response ─────────────────────────────
export class UserResponseDto {
  @Expose() id: string;
  @Expose() email: string;
  @Expose() roles: UserRole[];
  @Expose() kycStatus: KycStatus;
  @Expose() createdAt: Date;

  @Exclude()  // never serialised to the response
  passwordHash: string;

  @Exclude()
  twoFactorSecret: string;

  // Only included when caller serialises with { groups: ['admin'] }
  @Expose({ groups: ['admin'] })
  internalRiskScore: number;
}

// ── @Transform — reshape a value before it leaves the service ────────────────
export class BetResponseDto {
  @Expose() id: string;
  @Expose() betReference: string;
  @Expose() status: BetStatus;
  @Expose() type: BetType;

  // Internal representation: BIGINT integer minor units (10050)
  // External representation: formatted decimal string ("100.50")
  // The client never sees pence — it sees currency amounts.
  @Expose()
  @Transform(({ value }) => (value / 100).toFixed(2))
  stakeAmount: number;        // 10050 → "100.50"

  @Expose()
  @Transform(({ value }) => (value / 100).toFixed(2))
  potentialPayout: number;

  @Expose()
  @Transform(({ value }) => value?.toISOString() ?? null)
  createdAt: Date;

  @Exclude() rgSnapshot: unknown;  // never expose internal RG data to players
  @Exclude() version: number;      // ORM internals: irrelevant to API consumers
}

// ── @Type — nested object transformation ─────────────────────────────────────
// Without @Type, class-transformer does not know what class to instantiate for nested objects.
// @Expose/@Exclude on the nested class will be silently ignored.
export class PlaceBetResponseDto {
  @Expose() betId: string;
  @Expose() betReference: string;

  @Expose()
  @Type(() => SelectionResponseDto)     // tell class-transformer the nested type
  selections: SelectionResponseDto[];
}

// ── Controller: return DTO, interceptor handles the rest ─────────────────────
@Get(':id')
async getBet(@Param('id', ParseUUIDPipe) id: string): Promise<BetResponseDto> {
  const bet = await this.queryBus.execute(new GetBetQuery(id));
  // ClassSerializerInterceptor reads @Exclude/@Expose from BetResponseDto and applies them.
  // Alternatively: return plainToInstance(BetResponseDto, bet) for explicit control.
  return plainToInstance(BetResponseDto, bet, { excludeExtraneousValues: true });
}

// ── @SerializeOptions — per-route override ───────────────────────────────────
// excludeExtraneousValues: true → ONLY @Expose() fields are included (strict whitelist)
// groups → enables @Expose({ groups: ['admin'] }) fields for this route only
@Get('admin/:id')
@SerializeOptions({ groups: ['admin'], excludeExtraneousValues: true })
async adminGetUser(@Param('id', ParseUUIDPipe) id: string) {
  return this.usersService.findById(id);
}`

S.configModule = `// @nestjs/config deep-dive
// ConfigModule.forRoot() + validate option = fail-fast env validation at startup.
// Crash with a clear message if JWT_SECRET is missing — not a cryptic error on first request.

// ── Step 1: define and validate env shape with class-validator ───────────────
export class EnvironmentVariables {
  @IsEnum(['development', 'production', 'test'])
  NODE_ENV: string;

  @IsNumber() @Min(1) @Max(65535) @Type(() => Number)
  PORT: number = 3000;

  @IsString() @IsNotEmpty()
  DB_HOST: string;

  @IsNumber() @Type(() => Number)
  DB_PORT: number = 5432;

  @IsString() @MinLength(32)       // enforce minimum entropy
  JWT_SECRET: string;

  @IsUrl()
  JWKS_URI: string;

  @IsString() @IsNotEmpty()
  REDIS_HOST: string;

  @IsString() @IsNotEmpty()
  KAFKA_BROKERS: string;
}

export function validate(config: Record<string, unknown>) {
  const validated = plainToInstance(EnvironmentVariables, config, { enableImplicitConversion: true });
  const errors = validateSync(validated, { skipMissingProperties: false });
  if (errors.length > 0) {
    // Crash at startup: "DB_HOST is missing" > cryptic runtime failure minutes later
    throw new Error('Config validation failed:\\n' + errors.map(e => e.toString()).join('\\n'));
  }
  return validated;
}

// ── Step 2: namespaced configuration ─────────────────────────────────────────
// registerAs() creates a typed namespace. Use config.get<DbConfig>('db') instead of
// config.get<string>('DB_HOST') — refactor-safe, auto-complete, grouped by concern.

export const databaseConfig = registerAs('db', () => ({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT ?? '5432', 10),
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  poolMax:  parseInt(process.env.DB_POOL_MAX ?? '10', 10),
  schema:   process.env.DB_SCHEMA ?? 'public',
}));
export type DbConfig = ReturnType<typeof databaseConfig>;

export const jwtConfig = registerAs('jwt', () => ({
  secret:           process.env.JWT_SECRET,
  expiresIn:        process.env.JWT_EXPIRES_IN        ?? '15m',
  refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '30d',
  jwksUri:          process.env.JWKS_URI,
  audience:         process.env.JWT_AUDIENCE ?? 'betting-platform-api',
  issuer:           process.env.JWT_ISSUER   ?? 'betting-platform-auth',
}));

// ── Step 3: module setup ──────────────────────────────────────────────────────
ConfigModule.forRoot({
  isGlobal:        true,          // import once in AppModule → available everywhere
  validate,                       // crash on invalid env (fail-fast)
  load:            [databaseConfig, jwtConfig],  // register namespaces
  envFilePath:     ['.env.local', '.env'],        // local overrides win
  expandVariables: true,           // support \${OTHER_VAR} references in .env
})

// ── Step 4: two injection patterns ───────────────────────────────────────────
@Injectable()
export class JwtService {
  constructor(
    // Pattern A: ConfigService (flat key lookup, untyped string)
    private readonly config: ConfigService,

    // Pattern B: typed namespace injection (preferred for complex config)
    @Inject(jwtConfig.KEY)
    private readonly jwtCfg: ConfigType<typeof jwtConfig>,
  ) {
    // Pattern A — untyped, prone to typos:
    const secret = this.config.getOrThrow<string>('JWT_SECRET');

    // Pattern B — typed, refactor-safe, auto-complete:
    const audience = this.jwtCfg.audience;
    const issuer   = this.jwtCfg.issuer;
  }
}`

S.testing = `// NestJS Testing — Test.createTestingModule builds a real DI container in isolation.
// overrideProvider() swaps any provider with a mock without changing production code.

// ── Unit test: service in isolation ──────────────────────────────────────────
describe('PlaceBetHandler', () => {
  let handler:      PlaceBetHandler;
  let oddsService:  jest.Mocked<OddsService>;
  let lockService:  jest.Mocked<DistributedLockService>;
  let dataSource:   jest.Mocked<DataSource>;

  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        PlaceBetHandler,
        { provide: OddsService,            useValue: { validateSelectionOdds: jest.fn() } },
        { provide: DistributedLockService, useValue: { withLock: jest.fn() } },
        { provide: DataSource,             useValue: { createQueryRunner: jest.fn() } },
        { provide: EventBus,               useValue: { publish: jest.fn() } },
      ],
    }).compile();

    handler     = module.get(PlaceBetHandler);
    oddsService = module.get(OddsService);
    lockService = module.get(DistributedLockService);
    dataSource  = module.get(DataSource);
  });

  it('rejects with ODDS_CHANGED when odds drift beyond tolerance', async () => {
    oddsService.validateSelectionOdds.mockResolvedValue({
      acceptable: false,
      changes: [{ marketId: 'mkt-1', from: 2500, to: 2300 }],
    });

    const cmd = new PlaceBetCommand('user-1', 'op-1', BetType.SINGLE,
      [{ marketId: 'mkt-1', outcomeId: 'out-1', quotedOddsDecimalMillis: 2500 }],
      1000, OddsAcceptance.EXACT, 'GBP', 'idem-1', 'corr-1');

    await expect(handler.execute(cmd)).rejects.toMatchObject({
      response: { code: 'ODDS_CHANGED' },
    });
  });

  it('releases wallet reservation when DB commit fails', async () => {
    oddsService.validateSelectionOdds.mockResolvedValue({ acceptable: true, changes: [] });
    lockService.withLock.mockImplementation((_key, fn) => fn());
    dataSource.createQueryRunner.mockReturnValue({
      connect:            jest.fn(),
      startTransaction:   jest.fn(),
      commitTransaction:  jest.fn().mockRejectedValue(new Error('DB unavailable')),
      rollbackTransaction: jest.fn(),
      release:            jest.fn(),
      manager:            { save: jest.fn() },
    } as any);

    const cmd = new PlaceBetCommand('user-1', 'op-1', BetType.SINGLE, [], 1000,
      OddsAcceptance.ANY, 'GBP', 'idem-2', 'corr-2');

    await expect(handler.execute(cmd)).rejects.toThrow('DB unavailable');
    // Verify compensating transaction was triggered
    // expect(walletClient.releaseReservation).toHaveBeenCalledWith({ idempotencyKey: 'idem-2' });
  });
});

// ── Integration test: real module wiring, mocked external deps ───────────────
describe('BettingModule (integration)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const module = await Test.createTestingModule({
      imports: [BettingModule, DatabaseModule],
    })
    // overrideProvider: swap specific providers while keeping the real DI graph
    .overrideProvider(WalletGrpcClient)
    .useValue({ reserveStake: jest.fn().mockResolvedValue({ success: true }) })
    .overrideProvider(RiskGrpcClient)
    .useValue({ evaluateBetRisk: jest.fn().mockResolvedValue({ action: 'ACCEPT' }) })
    .compile();

    app = module.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
    await app.init();
  });

  afterAll(() => app.close());
});

// ── E2E test: full HTTP stack with supertest ──────────────────────────────────
describe('POST /api/v1/bets (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const module = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(BettingProxyService)
      .useValue({ placeBet: jest.fn().mockResolvedValue({ betId: 'test-bet-id' }) })
      .compile();

    app = module.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
    await app.init();
  });

  afterAll(() => app.close());

  it('returns 401 without Authorization header', () =>
    request(app.getHttpServer())
      .post('/api/v1/bets')
      .send({ type: 'SINGLE', selections: [], stakeMinorUnits: 1000, oddsAcceptance: 'ANY' })
      .expect(401)
      .expect(({ body }) => expect(body.error.code).toBe('AUTH_INVALID_TOKEN'))
  );

  it('returns 400 when stakeMinorUnits is negative', () =>
    request(app.getHttpServer())
      .post('/api/v1/bets')
      .set('Authorization', 'Bearer ' + validTestJwt)
      .send({ type: 'SINGLE', selections: [validSelection], stakeMinorUnits: -100, oddsAcceptance: 'ANY' })
      .expect(400)
      .expect(({ body }) => {
        expect(body.error.code).toBe('VALIDATION_ERROR');
        expect(body.error.fields).toEqual(expect.arrayContaining([
          expect.objectContaining({ field: 'stakeMinorUnits' }),
        ]));
      })
  );
});`

S.scheduler = `// @nestjs/schedule — declarative task scheduling
// ScheduleModule.forRoot() must be imported in AppModule.
// Methods in any @Injectable() service can use @Cron, @Interval, @Timeout.

// ── @Cron — standard cron expression or CronExpression enum ──────────────────
// If the previous execution is still running when the next fire time arrives,
// the new execution is SKIPPED (non-overlapping by default).
// For multi-pod deployments: use a distributed lock inside the handler.

@Injectable()
export class ScheduledTasksService implements OnModuleDestroy {
  private readonly dynamicJobs = new Map<string, CronJob>();

  constructor(private readonly schedulerRegistry: SchedulerRegistry) {}

  // Every 30 seconds — process outbox rows that weren't delivered yet
  @Cron(CronExpression.EVERY_30_SECONDS, { name: 'outbox-processor' })
  async processOutbox(): Promise<void> {
    // In a multi-pod deployment: acquire a distributed lock first.
    // Without it, every pod races to publish the same outbox rows.
    // await this.lock.withLock('outbox:processor', () => this.outboxService.process(), { ttlMs: 25_000 });
  }

  // Daily at midnight UTC — reset RG daily stake counters for all users
  @Cron('0 0 * * *', { timeZone: 'UTC', name: 'rg-daily-reset' })
  async resetDailyRgCounters(): Promise<void> {
    // SCAN + DEL rg:stake:daily:* — Redis pattern delete, no individual key knowledge needed
    this.logger.log('Resetting RG daily stake counters');
    // await this.redis.deletePattern('rg:stake:daily:*');
  }

  // Every 2s — recalculate cashout values for all open bets
  // In production: event-driven (trigger on odds change), not fixed interval
  @Interval('cashout-refresh', 2_000)
  async refreshCashoutValues(): Promise<void> { /* ... */ }

  // Run ONCE, 5s after module init — warm Redis odds cache from DB
  @Timeout('startup-warm', 5_000)
  async warmOddsCache(): Promise<void> {
    // Give Kafka consumer 5s to connect before we try to read from it
    this.logger.log('Warming market odds cache...');
  }

  // ── SchedulerRegistry: add/remove/modify jobs at runtime ─────────────────
  // Use for: per-operator schedules, user-specific reminders, data-driven timing.
  addOperatorDailyJob(operatorId: string, cronExpression: string): void {
    if (this.schedulerRegistry.doesExist('cron', \`op:\${operatorId}\`)) return;

    const job = new CronJob(cronExpression, async () => {
      this.logger.log({ operatorId }, 'Running operator daily settlement');
      // await this.settlementService.runForOperator(operatorId);
    });

    this.schedulerRegistry.addCronJob(\`op:\${operatorId}\`, job);
    job.start();
    this.dynamicJobs.set(operatorId, job);
  }

  removeOperatorJob(operatorId: string): void {
    const job = this.dynamicJobs.get(operatorId);
    if (job) {
      job.stop();
      this.schedulerRegistry.deleteCronJob(\`op:\${operatorId}\`);
      this.dynamicJobs.delete(operatorId);
    }
  }

  // Stop all dynamic jobs on graceful shutdown — prevents mid-drain execution
  onModuleDestroy(): void {
    this.dynamicJobs.forEach((job, id) => {
      job.stop();
      try { this.schedulerRegistry.deleteCronJob(id); } catch {}
    });
  }
}`

S.exceptionHierarchy = `// NestJS Exception Hierarchy
// All HTTP exceptions extend HttpException(response, statusCode).
// The response can be a string or an object { code, message, ... }.
// @Catch() filters intercept the exact exception type you specify.

// ── Built-in HTTP exceptions (most commonly used) ────────────────────────────
new BadRequestException({ code: 'VALIDATION_ERROR', fields: [...] });         // 400
new UnauthorizedException({ code: 'TOKEN_EXPIRED' });                         // 401
new ForbiddenException({ code: 'INSUFFICIENT_PERMISSIONS' });                 // 403
new NotFoundException({ code: 'BET_NOT_FOUND', betId });                     // 404
new ConflictException({ code: 'MARKET_SUSPENDED' });                         // 409
new GoneException({ code: 'CASHOUT_EXPIRED' });                              // 410
new UnprocessableEntityException({ code: 'RG_LIMIT_EXCEEDED', ...limits });  // 422
new TooManyRequestsException({ code: 'RATE_LIMIT_EXCEEDED', retryAfterMs }); // 429
new InternalServerErrorException({ code: 'INTERNAL_ERROR' });                // 500
new ServiceUnavailableException({ code: 'CIRCUIT_OPEN' });                   // 503
new GatewayTimeoutException({ code: 'UPSTREAM_TIMEOUT' });                   // 504

// ── Custom domain exceptions — keep domain code free of HTTP concepts ────────
// The handler throws InsufficientFundsException — it doesn't know about HTTP 409.
// The exception filter decides the HTTP status code.
// This makes PlaceBetHandler testable without an HTTP context.

export class InsufficientFundsException extends ConflictException {
  constructor(
    public readonly userId: string,
    public readonly requiredMinorUnits: number,
    public readonly availableMinorUnits: number,
  ) {
    super({ code: 'INSUFFICIENT_FUNDS', message: 'Wallet balance too low to place bet' });
    // Never expose exact balance in the response — information for attackers.
    // Log it server-side with full context for fraud monitoring.
  }
}

export class OddsChangedException extends ConflictException {
  constructor(public readonly changes: OddsChange[]) {
    super({ code: 'ODDS_CHANGED', changedSelections: changes.length });
  }
}

export class RgLimitExceededException extends UnprocessableEntityException {
  constructor(public readonly limitType: string, public readonly cooldownUntil?: Date) {
    super({ code: 'RG_LIMIT_EXCEEDED', limitType,
      cooldownUntil: cooldownUntil?.toISOString() });
  }
}

// ── Non-HTTP transport exceptions ─────────────────────────────────────────────
// When a Kafka consumer or gRPC handler needs to signal an error:
throw new RpcException({ code: 'ODDS_CHANGED', message: 'Odds have drifted' });
// The Kafka/gRPC framework translates this into the appropriate transport error.

// WebSocket handlers:
throw new WsException({ code: 'SUBSCRIPTION_LIMIT', message: 'Max 100 subscriptions' });

// ── @Catch(SpecificType) — typed exception filter ────────────────────────────
// Catches ONLY InsufficientFundsException — other exceptions fall through.
@Catch(InsufficientFundsException)
export class InsufficientFundsFilter implements ExceptionFilter {
  catch(ex: InsufficientFundsException, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    // Full context for fraud/risk monitoring (server-side only)
    this.logger.warn({
      userId:    ex.userId,
      required:  ex.requiredMinorUnits,
      available: ex.availableMinorUnits,
    }, 'Bet rejected: insufficient funds');
    // Lean response to client — never expose internal balance state
    res.status(409).json({ error: { code: 'INSUFFICIENT_FUNDS', message: ex.message } });
  }
}

// ── WebSocket exception filter ────────────────────────────────────────────────
@Catch(WsException)
export class WsExceptionFilter extends BaseWsExceptionFilter {
  catch(exception: WsException, host: ArgumentsHost): void {
    const client = host.switchToWs().getClient<Socket>();
    client.emit('error', { code: exception.getError() });
    // Do NOT disconnect on every error — only disconnect on auth failures.
  }
}`

S.microservicePatterns = `// NestJS Microservice Patterns
// @MessagePattern → Request-Response (caller awaits a reply)
// @EventPattern   → Fire-and-Forget (no reply expected, at-least-once delivery)
//
// Transport choice:
//   Synchronous queries:   gRPC (typed, streaming, low-latency, deadline propagation)
//   Domain events:         Kafka (durable, replayable, auditable, 7yr retention)
//   @MessagePattern+Kafka: useful for request-response over Kafka when gRPC isn't available

// ── Receiving side: Kafka consumer ────────────────────────────────────────────
@Controller()
export class BettingMicroserviceController {

  // @MessagePattern: MUST return a value — the framework sends it back as the reply.
  // Only useful on Kafka if the client subscribes to the reply topic (see ClientProxy below).
  @MessagePattern(KafkaTopics.GET_BET_BY_ID)
  async getBet(
    @Payload() data: { betId: string; userId: string },
    @Ctx() context: KafkaContext,
  ): Promise<BetDto | null> {
    // Correlation header is in the Kafka message headers
    const headers = context.getMessage().headers;
    this.logger.debug({ betId: data.betId, correlationId: headers?.['x-correlation-id'] });
    return this.queryBus.execute(new GetBetQuery(data.betId, data.userId));
  }

  // @EventPattern: no return value; fire-and-forget from the producer's perspective.
  // At-least-once delivery: this handler MUST be idempotent.
  @EventPattern(KafkaTopics.MARKET_ODDS_UPDATED)
  async onOddsUpdated(
    @Payload() data: { marketId: string; outcomes: OddsUpdate[] },
    @Ctx() context: KafkaContext,
  ): Promise<void> {
    const msgId = context.getMessage().key?.toString();
    // const alreadyProcessed = await this.redis.exists(\`dedup:odds:\${msgId}\`);
    // if (alreadyProcessed) return; // idempotency guard

    await this.oddsCache.bulkUpdate(data.marketId, data.outcomes);
    // Manual offset commit after successful processing
    // const { offset } = context.getMessage();
    // await context.getConsumer().commitOffsets([{ topic, partition, offset: (BigInt(offset) + 1n).toString() }]);
  }
}

// ── Sending side: ClientProxy ─────────────────────────────────────────────────
// ClientProxy is transport-agnostic — same API for Kafka, Redis, TCP, NATS.
// Injected via @Inject(SERVICE_TOKEN) where the token maps to ClientsModule registration.

@Injectable()
export class BettingProducer implements OnModuleInit {
  constructor(
    @Inject(KAFKA_SERVICE_TOKEN)
    private readonly client: ClientKafka,
  ) {}

  async onModuleInit(): Promise<void> {
    // For request-response over Kafka, subscribe to the reply topic BEFORE connecting.
    // NestJS generates a reply topic: originalTopic + '.reply'
    this.client.subscribeToResponseOf(KafkaTopics.GET_BET_BY_ID);
    await this.client.connect();
  }

  // send() → returns Observable<T>; wraps request-response pattern.
  // Always pipe timeout() — never await an Observable that might never emit.
  async getBetById(betId: string, userId: string): Promise<BetDto> {
    return firstValueFrom(
      this.client.send<BetDto, { betId: string; userId: string }>(
        KafkaTopics.GET_BET_BY_ID,
        { betId, userId },
      ).pipe(timeout(3_000)),  // 3s deadline — don't wait forever for a reply
    );
  }

  // emit() → fire-and-forget. Returns Observable<void>; resolves on broker ack.
  // With idempotent producer + acks: 'all', this is durably accepted by Kafka.
  async publishBetPlaced(event: BetPlacedEvent): Promise<void> {
    await firstValueFrom(
      this.client.emit(KafkaTopics.BET_PLACED, {
        key:     event.userId,         // partition by userId: ordering within a user's bets
        value:   event,
        headers: { 'x-correlation-id': event.correlationId },
      }),
    );
  }
}

// ── ClientsModule registration ────────────────────────────────────────────────
// In AppModule (or the feature module that needs to produce):
ClientsModule.registerAsync([{
  name: KAFKA_SERVICE_TOKEN,
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    transport: Transport.KAFKA,
    options: {
      client: { brokers: config.getOrThrow<string>('KAFKA_BROKERS').split(',') },
      producer: { idempotent: true, allowAutoTopicCreation: false },
    },
  }),
}])`

// ─── Chapter definitions ──────────────────────────────────────────────────────
export const chapters = [
  {
    id: 'nestjs-concepts',
    title: 'NestJS Core Concepts',
    subtitle: 'Module, Provider, Controller, Service, Guard — explained by a staff engineer',
    tag: { label: 'Legend', color: '#a371f7', bg: '#1f1535' },
    description: 'Before any architecture diagram makes sense, you need to understand the vocabulary. These are the nine building blocks NestJS is made of. Not the official docs version — the mental model you actually need to read production code and make good decisions.',
    sections: [
      {
        title: 'The DI Container — the engine everything runs on',
        description: 'NestJS is not an HTTP framework with dependency injection bolted on — it is an IoC container that manages object creation and wiring, with HTTP, gRPC, and WebSocket support sitting on top of it.',
        callouts: [
          {
            type: 'insight', icon: '⚙️', title: 'NestJS is fundamentally a dependency injection framework with HTTP on top',
            body: 'Everything else — modules, providers, guards, interceptors — is a structured way to tell the DI container what to create, in what order, and who gets access to what. When you understand that NestJS is an IoC container first and an HTTP framework second, every decorator and pattern makes immediate sense.',
          },
          {
            type: 'pattern', icon: '🔄', title: 'The container lifecycle: create → wire → use → destroy',
            body: 'On startup, NestJS reads the module tree, figures out the dependency graph, instantiates every provider in the correct order (leaf dependencies first), and wires them into whoever needs them. After that, the same singleton instances serve every request for the lifetime of the app. On shutdown (SIGTERM), onModuleDestroy() hooks run in reverse order — close DB pools, flush Kafka producers, drain queues.',
          },
        ],
      },
      {
        title: 'Module',
        description: 'A module is the unit of encapsulation in NestJS — it declares what it owns, what it exposes, and what it depends on, making it impossible for providers to leak across domain boundaries by accident.',
        callouts: [
          {
            type: 'pattern', icon: '📦', title: 'Module = encapsulation boundary, not a file boundary',
            body: 'A module is not just a barrel file. It is a contract: "these providers exist, these are public, these are private." BettingModule can expose BettingService but keep PlaceBetHandler, BetRepository, and OddsValidator private. Nothing outside BettingModule can inject those. This forces you to think about the public API of each domain slice — the same discipline as designing a library.',
          },
          {
            type: 'insight', icon: '🌍', title: '@Global() — use sparingly, for true infrastructure',
            body: '@Global() makes all of a module\'s exports available everywhere without importing it. Correct uses: RedisModule, LoggerModule, ConfigModule, TracingModule — things every module legitimately needs. Wrong uses: anything domain-specific. @Global() on a domain module destroys the dependency graph — you can no longer tell from a module\'s imports list what it actually depends on.',
          },
          {
            type: 'tip', icon: '🔧', title: 'Dynamic modules — forRoot / forRootAsync / forFeature',
            body: 'A static @Module() has the same providers every time. A dynamic module (forRoot returns a DynamicModule object) lets the caller pass configuration that changes what providers are created. forRoot() = sync config. forRootAsync() = config comes from another provider (ConfigService). forFeature() = register a subset (e.g. TypeOrmModule.forFeature([UserEntity]) registers only the User repository for that module).',
          },
        ],
        files: [{
          filename: 'module anatomy',
          lang: 'typescript',
          code: `@Module({
  imports: [
    // Other modules whose EXPORTED providers this module can inject.
    // Importing a module does NOT give you its private providers — only its exports.
    TypeOrmModule.forFeature([Bet, BetLeg]),
    KafkaModule,           // @Global(), so not strictly needed — but makes the dep explicit
  ],
  controllers: [
    // HTTP/gRPC/WebSocket entry points. Controllers are never injected into other things —
    // they are leaves in the dependency graph.
    BettingController,
    BettingGrpcController,
  ],
  providers: [
    // Everything the DI container should create and manage for this module.
    // Private by default — not accessible outside this module.
    PlaceBetHandler,
    CashoutHandler,
    BetRepository,
    OddsValidator,
  ],
  exports: [
    // Subset of providers made available to modules that import this one.
    // Exporting a provider does not make it @Global() — the importer still has
    // to explicitly import BettingModule to get access.
    BetRepository,
  ],
})
export class BettingModule {}`,
        }],
      },
      {
        title: 'Provider',
        description: 'A provider is anything the DI container creates and manages — the token is its name, the scope controls its lifetime, and the injection mechanism is how it ends up in whatever needs it.',
        callouts: [
          {
            type: 'pattern', icon: '💉', title: 'Four ways to provide a value',
            body: 'useClass: NestJS instantiates the class and injects its constructor dependencies. useFactory: a function (can be async) that returns the value — factory dependencies are listed in inject[]. useValue: a plain object or primitive, no class needed — useful for config objects and tokens. useExisting: alias one token to another already-registered provider.',
          },
          {
            type: 'insight', icon: '🔑', title: 'Injection tokens — strings, Symbols, or class references',
            body: 'When you write constructor(private userService: UserService), NestJS uses the TypeScript type UserService as the injection token. For non-class values (config objects, primitives, interfaces) you need an explicit token: @Inject("REDIS_CLIENT") or @Inject(REDIS_TOKEN). Symbols are better than strings for tokens — they are unique by identity and cannot clash across libraries.',
          },
          {
            type: 'warning', icon: '⚠️', title: 'Scope.REQUEST creates a new instance per request — and it bubbles',
            body: 'Default scope is Singleton — one instance for the entire app lifetime. Scope.REQUEST creates a fresh instance per request, injecting a reference to the current request object. The catch: if a singleton depends on a request-scoped provider, NestJS must make that singleton request-scoped too — the scope bubbles up the entire dependency chain. This can unintentionally make critical services like DB connections request-scoped. Only use Scope.REQUEST when you genuinely need per-request isolation.',
          },
        ],
        files: [{
          filename: 'provider registration patterns',
          lang: 'typescript',
          code: `// The four provider forms — all valid in the providers array

// 1. useClass (shorthand: just the class name)
providers: [UserService]
// expands to: { provide: UserService, useClass: UserService }

// 2. useFactory — for async setup, external resources, conditional logic
{
  provide: 'REDIS_CLIENT',
  useFactory: async (config: ConfigService) => {
    const client = new Redis(config.get('REDIS_URL'));
    await client.ping();    // async setup — NestJS awaits this before proceeding
    return client;
  },
  inject: [ConfigService],  // factory dependencies — resolved by DI before factory runs
},

// 3. useValue — plain value, no class required
{
  provide: 'APP_VERSION',
  useValue: process.env.APP_VERSION ?? 'local',
},

// 4. useExisting — alias: LEGACY_TOKEN resolves to the same instance as NewService
{
  provide: 'LEGACY_TOKEN',
  useExisting: NewService,
},

// Injecting non-class tokens:
@Injectable()
export class SomeService {
  constructor(
    @Inject('REDIS_CLIENT') private redis: Redis,
    @Inject('APP_VERSION') private version: string,
  ) {}
}`,
        }],
      },
      {
        title: 'Controller',
        description: 'A controller is the translation layer between a transport protocol and your domain — its only job is to extract inputs from the request and hand them to a service, never to hold business logic itself.',
        callouts: [
          {
            type: 'pattern', icon: '🎯', title: 'Controllers should be thin — extraction and delegation only',
            body: 'A controller method should do three things: extract inputs from the request (@Param, @Body, @Query, @CurrentUser), call a service or command bus, return the result. If a controller method is longer than 10 lines it is doing too much. Business logic, validation beyond basic type-checking, and data assembly belong in services or handlers — not in controllers.',
          },
          {
            type: 'insight', icon: '🔌', title: 'One controller class can handle multiple transports',
            body: 'You can have a BettingController (@Controller) for HTTP and a BettingGrpcController (@Controller() with @GrpcMethod) for gRPC in the same module. They share the same injected services. @MessagePattern and @EventPattern turn a class into a microservice consumer handler for Kafka, Redis, TCP, etc. The controller type determines how NestJS routes the incoming message — the handler body is just TypeScript.',
          },
        ],
        files: [{
          filename: 'controller anatomy',
          lang: 'typescript',
          code: `@Controller('bets')               // route prefix: /bets
export class BettingController {
  constructor(
    // Controllers can inject services, but never inject other controllers
    private commandBus: CommandBus,
    private queryBus: QueryBus,
  ) {}

  @Post()                          // maps POST /bets
  @HttpCode(201)
  @UseGuards(JwtAuthGuard)         // route-level guard — overrides global if needed
  async placeBet(
    @Body() dto: PlaceBetDto,      // parsed + validated by ValidationPipe
    @CurrentUser() user: User,     // custom param decorator — reads from request
  ) {
    // Thin: extract inputs, fire command, return result — nothing else
    return this.commandBus.execute(new PlaceBetCommand(user.id, dto));
  }

  @Get(':id')                      // maps GET /bets/:id
  async getBet(@Param('id', ParseUUIDPipe) id: string) {
    return this.queryBus.execute(new GetBetQuery(id));
  }
}

// Microservice controller — same class shape, different decorators
@Controller()
export class BettingMicroserviceController {
  @MessagePattern('bet.place')     // request-response via Kafka/TCP
  async handlePlaceBet(@Payload() data: PlaceBetMessage) { ... }

  @EventPattern('bet.settled')     // fire-and-forget event listener
  async handleBetSettled(@Payload() event: BetSettledEvent) { ... }
}`,
        }],
      },
      {
        title: 'Service',
        description: '"Service" is not a NestJS concept at all — it is a team convention for an @Injectable() class that owns reusable business logic, distinguishing it from repositories, handlers, and factories that are also just providers under the hood.',
        callouts: [
          {
            type: 'insight', icon: '🏗️', title: 'Service is a convention, @Injectable() is the mechanism',
            body: 'What makes a class a "service" is that it is marked @Injectable() and registered in a module\'s providers array. That is it. The name "Service" signals: this class holds logic that is used by multiple consumers and should be injected. Compare with a "Repository" (data access), "Handler" (single command/event), "Factory" (creates instances), "Guard" (authorisation). These are all @Injectable() — the naming tells your team what role the class plays.',
          },
          {
            type: 'pattern', icon: '🔗', title: 'Services should have one clear responsibility',
            body: 'UserService that handles registration, login, profile update, password reset, avatar upload, and email verification is not one service — it is six services duct-taped together. When a service grows, split it by the reason it would change: AuthService changes when auth logic changes, UserProfileService changes when profile features change. The single responsibility principle is how you keep services testable and maintainable.',
          },
        ],
      },
      {
        title: 'Guard',
        description: 'A guard is a synchronous gate that runs before the handler and answers exactly one boolean question: is this identity allowed to perform this action — and if not, reject it before any business logic runs.',
        callouts: [
          {
            type: 'pattern', icon: '🛡️', title: 'Guards are for authorization, not authentication details',
            body: 'Authentication (verifying a token is valid) is often done in middleware or a guard. Authorization (does this user have the right to do this thing?) is always a guard. The distinction matters for testing: an auth guard can be overridden with a mock in tests, while middleware runs below the NestJS testing layer. Use @UseGuards() at the controller or method level for specific permissions; use APP_GUARD for rules that apply everywhere (like rate limiting).',
          },
          {
            type: 'insight', icon: '📋', title: 'Guards can read route metadata via Reflector',
            body: 'SetMetadata(\'roles\', [\'admin\']) on a route handler stores metadata. In a guard, Reflector.getAllAndOverride(\'roles\', [context.getHandler(), context.getClass()]) reads it. This is how @Roles(\'admin\') decorator-driven RBAC works: the decorator stores the required roles, the guard reads them and checks the current user. getAllAndOverride means method-level metadata wins over class-level.',
          },
          {
            type: 'tip', icon: '🔗', title: 'Guards run in order — later guards trust earlier ones',
            body: 'In @UseGuards(AuthGuard, RolesGuard, FeatureGuard), AuthGuard sets request.user. RolesGuard reads request.user — it trusts AuthGuard already ran. FeatureGuard reads request.user.companyId — it trusts both. If you remove AuthGuard, the others break silently. Document these dependencies with explicit error messages: throw new Error("Did you forget AuthGuard?") when the expected request property is missing.',
          },
        ],
      },
      {
        title: 'Interceptor',
        description: 'An interceptor wraps the entire handler execution as an Observable, making it the only primitive in NestJS that can observe and transform both the incoming request and the outgoing response in a single class.',
        callouts: [
          {
            type: 'pattern', icon: '🔁', title: 'Interceptors use RxJS — handle() returns an Observable',
            body: 'next.handle() returns an Observable that emits the handler\'s return value. You can pipe() RxJS operators onto it: map() to transform responses, tap() to log without changing the value, catchError() to handle errors, timeout() to add per-route time limits. If you never used RxJS before, the mental model is: it\'s a Promise that you can transform before the caller sees it.',
          },
          {
            type: 'insight', icon: '⏱️', title: 'Interceptors are how you add cross-cutting post-handler logic',
            body: 'Middleware cannot see the response. Guards reject requests but cannot modify responses. Interceptors can do both — they run code before next.handle() (pre-handler) and pipe operators after it (post-handler). This makes them the right place for: response transformation (wrap all responses in { data: ..., meta: ... }), request timing (Date.now() before, subtract after), and response caching (return cached value without calling next.handle() at all).',
          },
        ],
        files: [{
          filename: 'interceptor patterns',
          lang: 'typescript',
          code: `@Injectable()
export class TransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const start = Date.now();

    return next.handle().pipe(
      // map() transforms every emitted value — wraps the response
      map(data => ({
        data,
        meta: { duration: Date.now() - start, timestamp: new Date().toISOString() },
      })),

      // tap() runs a side effect without changing the value — good for logging
      tap(() => {
        const req = context.switchToHttp().getRequest();
        logger.log(\`\${req.method} \${req.url} — \${Date.now() - start}ms\`);
      }),

      // catchError() lets the interceptor handle or re-throw errors
      catchError(err => {
        logger.error('handler threw', err);
        return throwError(() => err);  // re-throw — let the exception filter handle it
      }),

      // timeout() rejects if the handler takes too long
      timeout(5000),  // 5 second per-route timeout
    );
  }
}

// Caching interceptor — short-circuits the handler entirely
@Injectable()
export class CacheInterceptor implements NestInterceptor {
  async intercept(context: ExecutionContext, next: CallHandler) {
    const key = context.switchToHttp().getRequest().url;
    const cached = await this.cache.get(key);

    if (cached) return of(cached);  // of() creates an Observable that emits immediately

    return next.handle().pipe(
      tap(response => this.cache.set(key, response, 60)),
    );
  }
}`,
        }],
      },
      {
        title: 'Pipe',
        description: 'A pipe is the last checkpoint before your handler sees a value — it coerces types, validates shapes, and throws immediately if the data is wrong, so your business logic never receives garbage input.',
        callouts: [
          {
            type: 'pattern', icon: '🔍', title: 'Two distinct jobs: transformation and validation',
            body: 'Transformation: ParseIntPipe turns the string "42" into the number 42. ParseUUIDPipe validates and passes through. ParseEnumPipe(StatusEnum) ensures the value is a valid enum member. Validation: ValidationPipe with class-validator decorators checks that a DTO has all required fields in the right shapes. You can compose both — ParseUUIDPipe ensures it\'s a valid UUID format, then the handler receives a string it can safely use as a DB key.',
          },
          {
            type: 'insight', icon: '🎯', title: 'Pipes can be scoped to a single parameter',
            body: '@Param("id", ParseUUIDPipe) applies the pipe only to the id parameter. @Body(new ValidationPipe({ whitelist: true })) applies a specific ValidationPipe config to just the body. This is more precise than a global pipe — useful when one route needs stricter validation than the global default, or when you need a different transform for a specific parameter.',
          },
        ],
      },
      {
        title: 'Exception Filter',
        description: 'An exception filter is the final safety net of the entire request pipeline — it intercepts any unhandled throw from any stage and decides what the client sees versus what gets logged, keeping internal state invisible to the outside world.',
        callouts: [
          {
            type: 'pattern', icon: '🎣', title: '@Catch() targets specific exception types',
            body: '@Catch() with no arguments catches everything. @Catch(HttpException) catches only HttpException and subclasses. @Catch(InsufficientFundsException) catches only that specific domain exception. Typed filters run before the global catch-all, so you can handle specific exceptions with richer logic (extra logging, side effects like fraud alerts) while the global filter handles the rest.',
          },
          {
            type: 'critical', icon: '🔒', title: 'Never leak internal state in exception responses',
            body: 'The filter is where you decide what the client sees vs what goes in the logs. Log everything: userId, requestId, full stack trace, internal error context. Send to the client: a stable error code, a safe message, an HTTP status. If the handler throws an exception with the DB query that failed, the filter must strip that before responding. An attacker who sees "column balance_minor_units does not exist" learns your schema.',
          },
          {
            type: 'insight', icon: '🏛️', title: 'extends BaseExceptionFilter to delegate response writing',
            body: 'If you implement ExceptionFilter from scratch you must write the raw HTTP response yourself. If you extend BaseExceptionFilter you can intercept, reformat the exception as a new HttpException with a different body, and then call super.catch() to let NestJS write the response. This is the deskbird DeskbirdExceptionFilter approach — it normalises all exceptions to { statusCode, errorCode, message } without reimplementing response serialisation.',
          },
        ],
      },
      {
        title: 'Middleware',
        description: 'Middleware runs below the NestJS abstraction layer on the raw request object, before the framework has any awareness of routes or decorators — making it the right place for concerns that must run unconditionally on every request regardless of what NestJS does next.',
        callouts: [
          {
            type: 'pattern', icon: '🔌', title: 'Right for raw request concerns: context setup, headers, logging',
            body: 'Middleware is the right place for: setting up AsyncLocalStorage context (correlation IDs, tracing), reading and normalising raw headers, applying security headers (helmet), compression, and basic request logging before any parsing happens. If you need to read route metadata or the parsed body, use an interceptor instead — middleware runs too early.',
          },
          {
            type: 'tip', icon: '📍', title: 'Registered via configure(), not providers array',
            body: 'Middleware is not registered in the @Module() providers array. It is registered by implementing the NestModule interface and its configure(consumer: MiddlewareConsumer) method. consumer.apply(TracingMiddleware).forRoutes("*") applies it to all routes. consumer.apply(AuthMiddleware).forRoutes({ path: "admin/*", method: RequestMethod.ALL }) scopes it to specific paths.',
          },
        ],
      },
      {
        title: 'Decorator',
        description: 'A NestJS decorator is either configuring the DI container, binding a transport route, or storing metadata for a guard or interceptor to read later — and most of them do nothing at all without a corresponding guard or interceptor that actually enforces them.',
        callouts: [
          {
            type: 'insight', icon: '🏷️', title: 'Most NestJS decorators just attach metadata — they do nothing by themselves',
            body: '@Roles("admin") on a method does absolutely nothing on its own. It calls SetMetadata("roles", ["admin"]) which stores the value in a Reflect metadata key on the method. A guard later reads that value via Reflector. Remove the guard and @Roles() is completely inert. This is important: decorators like @Public() or @Timeout(3000) only work because some guard or interceptor is reading their metadata.',
          },
          {
            type: 'pattern', icon: '🛠️', title: 'createParamDecorator — extract anything from the request',
            body: 'createParamDecorator((data, ctx) => ...) creates a parameter decorator like @CurrentUser() or @CurrentPublicApiUser(). The data argument is whatever you pass in the decorator call — @CurrentUser("id") passes "id" as data. The ctx is the full ExecutionContext. This is how you encapsulate request-reading logic: instead of @Req() req: Request and then req.user in every method, you write @CurrentUser() user: User once and use it everywhere.',
          },
          {
            type: 'pattern', icon: '🔗', title: 'applyDecorators — compose multiple decorators into one',
            body: 'applyDecorators(UseGuards(JwtAuthGuard), Roles("admin"), ApiBearerAuth()) creates a single @AdminOnly() decorator that applies all three. This is how you build opinionated abstractions: a new engineer calls @AdminOnly() and gets auth + role check + Swagger annotation for free without knowing how any of them work. Used in deskbird for reusable Swagger response decorators like @ForbiddenResponse and @UnauthorizedResponse.',
          },
        ],
        files: [{
          filename: 'decorator patterns',
          lang: 'typescript',
          code: `// 1. Simple metadata decorator
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);
export const Public = () => SetMetadata('isPublic', true);

// Guard reads it back:
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext): boolean {
    // getAllAndOverride: method-level wins over class-level
    const roles = this.reflector.getAllAndOverride<string[]>('roles', [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (!roles) return true;  // no @Roles() = no restriction
    return roles.includes(ctx.switchToHttp().getRequest().user?.role);
  }
}

// 2. Custom parameter decorator
export const CurrentUser = createParamDecorator(
  (field: keyof User | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    return field ? user?.[field] : user;  // @CurrentUser('id') returns just the id
  },
);

// 3. Composite decorator with applyDecorators
export const Auth = (...roles: string[]) =>
  applyDecorators(
    SetMetadata('roles', roles),
    UseGuards(JwtAuthGuard, RolesGuard),
    ApiBearerAuth(),          // Swagger: marks endpoint as requiring Bearer auth
    ApiUnauthorizedResponse({ description: 'Unauthorized' }),
  );

// Usage — one decorator does all of the above
@Auth('admin')
@Delete(':id')
async deleteUser(@Param('id') id: string) { ... }`,
        }],
      },
      {
        title: 'The Execution Order — putting it all together',
        description: 'The execution order in NestJS is fixed and non-negotiable — Middleware → Guards → Interceptors → Pipes → Handler → Interceptors → Exception Filter — and understanding it is the single most important thing for debugging why something is undefined or a security check is not running.',
        callouts: [
          {
            type: 'pattern', icon: '➡️', title: 'Inbound: Middleware → Guards → Interceptors (pre) → Pipes → Handler',
            body: 'Middleware runs first on the raw request — no NestJS context. Guards run next and can reject the request. Interceptors run after guards and wrap the handler — their pre-handler code runs here. Pipes run just before the handler, on individual parameters. Then the handler executes. On the way out: Interceptors (post) transform the response. Exception Filters catch any throw from any of these stages.',
          },
          {
            type: 'critical', icon: '⚠️', title: 'The order is fixed — you cannot swap guards and interceptors',
            body: 'Guards always run before interceptors. Interceptors always run before pipes. Pipes always run before the handler. This is not configurable. Consequences: a guard cannot use data transformed by an interceptor (interceptors run after guards). A pipe cannot see what a guard put on the request (pipes run after guards, so actually it can read request.user). An interceptor can see what a guard set on the request (interceptors run after guards). Get this mental model right and you will never have mysterious "why is this undefined" bugs.',
          },
          {
            type: 'insight', icon: '🔍', title: 'Exceptions flow backwards through the same chain',
            body: 'If the handler throws, the exception travels back out: interceptors\' catchError() operators see it first, then exception filters. If a guard throws, the exception skips the handler and interceptors entirely and goes straight to the exception filter. This means your exception filter catches throws from guards, pipes, interceptors, and handlers — it is the single catch-all for the entire request pipeline.',
          },
        ],
        files: [{
          filename: 'full execution order',
          lang: 'typescript',
          code: `// Inbound request lifecycle (in order):
//
// 1. Middleware          — raw req/res, no NestJS context
//    TracingMiddleware   → sets AsyncLocalStorage correlation-id
//    helmet()            → security headers
//
// 2. Guards (left to right in @UseGuards)
//    JwtAuthGuard        → verifies token, sets request.user
//    RolesGuard          → reads @Roles() metadata, checks user.role
//    ThrottlerGuard      → checks rate limit counter in Redis
//
// 3. Interceptors (pre-handler, top to bottom)
//    LoggingInterceptor  → records start time
//    TransformInterceptor→ (nothing to do yet on the way in)
//
// 4. Pipes (per parameter, left to right in handler signature)
//    ParseUUIDPipe       → validates @Param('id') is a UUID
//    ValidationPipe      → validates @Body() against DTO class
//
// 5. Handler executes
//    controller method   → calls service → returns result
//
// Outbound response lifecycle (in reverse order):
//
// 6. Interceptors (post-handler, piped operators)
//    TransformInterceptor→ wraps result in { data, meta }
//    LoggingInterceptor  → logs duration
//
// 7. Exception Filter (if anything above threw)
//    DeskbirdExceptionFilter → formats { statusCode, errorCode, message }
//
// Key: if a Guard throws → skips straight to step 7
//      if a Pipe throws  → skips straight to step 7
//      if a Handler throws → goes through Interceptors' catchError first, then step 7`,
        }],
      },
    ],
  },

  {
    id: 'overview',
    title: 'Architecture Overview',
    subtitle: 'The full picture before we dive in',
    tag: { label: 'Start here', color: '#3fb950', bg: '#0f2d18' },
    description: 'A high-scale betting platform for 10M+ concurrent users, built as a NestJS 11 monorepo. Six domain microservices communicate via gRPC (synchronous) and Kafka (asynchronous). Every architectural decision is explained from a staff-engineer perspective — trade-offs, failure modes, and scale targets included.',
    type: 'overview',
    sections: [],
  },
  {
    id: 'pipeline',
    title: 'Request Pipeline',
    subtitle: 'From browser to database and back',
    tag: { label: 'Foundation', color: '#4493f8', bg: '#121d2f' },
    description: 'Every HTTP request passes through a predictable, ordered pipeline. Understanding this order is essential — a guard cannot use data set by an interceptor, and middleware runs before guards. Get this wrong and security breaks silently.',
    type: 'pipeline',
    sections: [],
  },
  {
    id: 'bootstrap',
    title: 'API Gateway Bootstrap',
    subtitle: 'main.ts & AppModule — the wiring diagram',
    tag: { label: 'API Gateway', color: '#f0883e', bg: '#271b0e' },
    description: 'The gateway is the single external entry point (BFF pattern). It bootstraps security headers, compression, validation pipes, and registers global guards/interceptors as APP_GUARD / APP_INTERCEPTOR providers. The module composition order here is the security contract for the entire platform.',
    sections: [
      {
        title: 'Bootstrap — main.ts',
        description: 'NestJS app initialization with security hardening, structured logging, and graceful shutdown. OpenTelemetry MUST be the very first import — it monkey-patches modules at load time.',
        callouts: [
          { type: 'critical', icon: '⚡', title: 'OTel first', body: 'Import tracing.init before ALL other imports. If NestJS modules load first, the SDK misses pg, ioredis, and kafkajs — you get no DB/cache/queue spans in your traces.' },
          { type: 'insight', icon: '🔒', title: 'Never use origin: \'*\'', body: 'CORS allowlist is a financial security requirement. A CSRF attack against a gambling wallet is a direct financial attack.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/main.ts', lang: 'typescript', code: S.gatewayMain }],
      },
      {
        title: 'Module Composition — AppModule',
        description: 'Global guards are applied in order. JwtAuthGuard must run before RolesGuard (needs req.user). APP_GUARD providers are evaluated top-to-bottom on every request.',
        callouts: [
          { type: 'pattern', icon: '🏗️', title: 'DI Scope awareness', body: 'Default (singleton): all stateless services. REQUEST scope: CLS / CurrentUser. Avoid REQUEST scope creep — it cascades up and accidentally makes singleton services request-scoped.' },
          { type: 'warning', icon: '⚠️', title: 'Redis-backed ThrottlerStorage', body: 'Without Redis storage for ThrottlerModule, each pod has its own counter. A user can multiply their effective rate limit by the pod count.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/app.module.ts', lang: 'typescript', code: S.appModule }],
      },
    ],
  },
  {
    id: 'middleware',
    title: 'Middleware Layer',
    subtitle: 'Correlation IDs & Geo-blocking',
    tag: { label: 'Middleware', color: '#d29922', bg: '#2a1f0a' },
    description: 'Middleware runs before guards and interceptors — it\'s the first thing that touches every request. Here we establish the correlation ID (threads through all downstream logs) and enforce geo-blocking for regulatory compliance.',
    sections: [
      {
        title: 'Correlation ID Middleware',
        description: 'Assigns a UUID to every request. This ID propagates through HTTP headers, gRPC metadata, Kafka message headers, DB query comments, and OpenTelemetry traces. Without it, debugging a user issue across 6 services takes hours.',
        callouts: [
          { type: 'insight', icon: '🔍', title: 'CLS (AsyncLocalStorage)', body: 'nestjs-cls stores the correlationId in Node.js AsyncLocalStorage. It flows through all async operations (awaits, callbacks, Promises) without passing it as a parameter — like a thread-local variable in Java.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/middleware/correlation-id.middleware.ts', lang: 'typescript', code: S.correlationId }],
      },
      {
        title: 'Geo-block Middleware',
        description: 'Blocking unlicensed jurisdictions is a criminal law requirement for gambling operators. We implement defence-in-depth: edge (Cloudflare Workers), application (this middleware), and database (account creation check).',
        callouts: [
          { type: 'critical', icon: '⚖️', title: 'Regulatory requirement', body: 'Serving users in jurisdictions where you are not licensed is a criminal offence in most countries. This is not optional — it must be enforced at multiple layers.' },
          { type: 'tip', icon: '💡', title: 'VPN detection', body: 'Layer additional VPN/proxy detection: Cloudflare Fraud Score header, MaxMind minFraud API, or IPQualityScore. Don\'t block on it — flag for manual risk review.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/middleware/geo-block.middleware.ts', lang: 'typescript', code: S.geoBlock }],
      },
    ],
  },
  {
    id: 'security',
    title: 'Security: Guards',
    subtitle: 'JWT auth, RBAC, and B2B operator validation',
    tag: { label: 'Security', color: '#f85149', bg: '#2d1318' },
    description: 'Three guards run in sequence on every authenticated request. JwtAuthGuard validates the token and populates req.user. RolesGuard checks the @Roles() decorator. OperatorGuard validates the B2B operator API key for white-label routes.',
    sections: [
      {
        title: 'JWT Auth Guard',
        description: 'Uses RS256 (asymmetric) rather than HS256. Only the auth-service holds the private key. All other services verify using the public key from the JWKS endpoint — a compromised downstream service cannot forge tokens.',
        callouts: [
          { type: 'insight', icon: '🔑', title: 'RS256 vs HS256', body: 'With HS256, any service that can verify tokens can also forge them (same secret). With RS256, the private key never leaves the auth-service — all other services just have the public key from the JWKS endpoint.' },
          { type: 'insight', icon: '📋', title: 'JWT blacklist strategy', body: 'Store jti in Redis with TTL = remaining token lifetime. O(1) lookup. Without this, logout doesn\'t actually log out — the token stays valid until expiry.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/guards/jwt-auth.guard.ts', lang: 'typescript', code: S.jwtGuard }],
      },
      {
        title: 'Roles Guard & Custom Decorators',
        description: 'Coarse-grained RBAC via roles embedded in the JWT. For fine-grained permissions (a support agent can only see accounts in their region), use ABAC with Casbin or OPA evaluated server-side.',
        callouts: [
          { type: 'warning', icon: '⚠️', title: 'Role change latency', body: 'Roles are embedded in the JWT. A role change takes effect on the next token refresh (max 15 min). For immediate effect (admin suspends account), use the Redis suspension flag checked in JwtAuthGuard.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/guards/', lang: 'typescript', code: S.rolesGuard }],
      },
      {
        title: 'Operator Guard — B2B Multi-tenancy',
        description: 'Multiple white-label operators run their brands on our infrastructure. Each has a separate API key, jurisdiction config, game catalogue, and rate limits. The operator context from this guard drives downstream partitioning.',
        callouts: [
          { type: 'tip', icon: '🏷️', title: 'Key rotation without downtime', body: 'Pre-provision the new key alongside the old one. Both are valid during the 24h grace period. The old key expires automatically — zero-downtime rotation.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/guards/operator.guard.ts', lang: 'typescript', code: S.operatorGuard }],
      },
    ],
  },
  {
    id: 'interceptors',
    title: 'Interceptors & Exception Filter',
    subtitle: 'Logging, response envelope, timeout, and error normalisation',
    tag: { label: 'Response pipeline', color: '#bc8cff', bg: '#1f1535' },
    description: 'Interceptors wrap the handler execution — they can observe both the request and the response. The exception filter is the last line of defence, normalising all errors to a consistent shape so clients can rely on a stable error contract.',
    sections: [
      {
        title: 'Logging, Transform & Timeout Interceptors',
        description: 'Three interceptors applied globally. LoggingInterceptor produces the audit trail. TransformInterceptor wraps all responses in a consistent envelope. TimeoutInterceptor prevents slow downstream services from exhausting the event loop.',
        callouts: [
          { type: 'critical', icon: '⏱️', title: 'Always set timeouts', body: 'Without TimeoutInterceptor, a slow betting-service causes requests to queue indefinitely, exhausting all connection pools and taking down the gateway. This is one of the most common sources of cascading microservice failures.' },
          { type: 'insight', icon: '📊', title: 'Audit log requirements', body: 'For licensed gambling operators, all financial actions must be logged with full context and stored for 5-7 years. Logs must be tamper-evident (append-only, WORM storage). Never include PII — log userId (opaque UUID), not email or name.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/interceptors/', lang: 'typescript', code: S.interceptors }],
      },
      {
        title: 'Global Exception Filter',
        description: 'Normalises all exceptions — including unexpected runtime errors — into { error: { code, message, requestId, timestamp } }. The machine-readable code is a stable contract; the human message can change.',
        callouts: [
          { type: 'critical', icon: '🔒', title: 'Never leak internals on 5xx', body: 'Stack traces, SQL error messages, and internal file paths in 500 responses are a security vulnerability. Log them server-side to Sentry; return only a generic code+message to clients.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/common/filters/global-exception.filter.ts', lang: 'typescript', code: S.exceptionFilter }],
      },
    ],
  },
  {
    id: 'betting-api',
    title: 'Betting REST API',
    subtitle: 'Controller, DTO validation, and Circuit Breaker proxy',
    tag: { label: 'Betting domain', color: '#3fb950', bg: '#0f2d18' },
    description: 'The betting controller is thin — no business logic. It validates, decorates, and delegates. The BettingProxyService translates HTTP to gRPC and wraps every call in a circuit breaker to prevent cascade failures.',
    sections: [
      {
        title: 'Betting Controller',
        description: 'All bet endpoints with full decorator composition. Note how each financial endpoint has @AuditLog + @Idempotent + a custom @Timeout override — a consistent pattern for all write operations.',
        files: [{ filename: 'apps/api-gateway/src/modules/betting/betting.controller.ts', lang: 'typescript', code: S.bettingController }],
      },
      {
        title: 'PlaceBet DTO — Validation',
        description: 'All monetary values are integers (minor units). Odds as integer millis. Never floats — floating-point arithmetic on financial values causes real money errors. class-validator enforces this at the boundary.',
        callouts: [
          { type: 'critical', icon: '💰', title: 'Never use floats for money', body: 'Store as integer minor units (pence/cents). 2.50 odds → 2500. All arithmetic with Decimal.js, never native JS number. This is non-negotiable for a financial system.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/modules/betting/dto/place-bet.dto.ts', lang: 'typescript', code: S.placeBetDto }],
      },
      {
        title: 'BFF Proxy — gRPC + Circuit Breaker',
        description: 'The gateway translates HTTP to gRPC and wraps every call with opossum circuit breaker. When the betting-service is degraded, the circuit opens and the gateway fast-fails instead of queueing indefinitely.',
        callouts: [
          { type: 'pattern', icon: '⚡', title: 'Why gRPC internally?', body: 'Protobuf is 5-10× more compact than JSON. gRPC deadlines propagate automatically (parent timeout → child deadline). HTTP/2 multiplexing eliminates per-request TCP overhead. Strongly typed contracts enforced at compile time.' },
        ],
        files: [{ filename: 'apps/api-gateway/src/modules/betting/betting-proxy.service.ts', lang: 'typescript', code: S.circuitBreaker }],
      },
    ],
  },
  {
    id: 'realtime',
    title: 'Real-time: WebSocket Gateway',
    subtitle: 'Socket.IO scaled horizontally via Redis adapter',
    tag: { label: 'Real-time', color: '#4493f8', bg: '#121d2f' },
    description: 'The platform pushes live odds updates, bet settlements, cashout values, and wallet changes to clients in real-time. Socket.IO with the Redis adapter makes the WebSocket layer fully stateless — any pod can handle any client.',
    sections: [
      {
        title: 'Realtime Gateway',
        description: 'Socket.IO with Redis pub/sub adapter. A Kafka consumer on any pod receives an ODDS_UPDATED event, publishes to Redis, and the adapter broadcasts to all subscribed clients across the entire pod fleet.',
        callouts: [
          { type: 'insight', icon: '📡', title: 'Horizontal scaling without sticky sessions', body: 'Socket.IO Redis adapter uses Redis pub/sub to relay messages between pods. Client A connects to pod 1, client B connects to pod 2 — both receive the same odds update pushed from pod 3. No sticky routing needed.' },
          { type: 'warning', icon: '⚠️', title: 'Peak event traffic', body: 'A Champions League final can push 500k+ simultaneous connections. Pre-warm pods via HPA on active_websocket_connections Prometheus metric before big events. Target 100k connections/pod (Socket.IO + uWS adapter).' },
        ],
        files: [{ filename: 'apps/api-gateway/src/modules/realtime/realtime.gateway.ts', lang: 'typescript', code: S.websocket }],
      },
    ],
  },
  {
    id: 'cqrs',
    title: 'CQRS: Command Side',
    subtitle: 'PlaceBetCommand → Handler → Saga orchestration',
    tag: { label: 'CQRS', color: '#bc8cff', bg: '#1f1535' },
    description: 'The betting-service uses CQRS to separate the write side (commands with strict consistency) from the read side (queries with eventual consistency and caching). The PlaceBetHandler is the most complex write path — a distributed transaction orchestrating 6 external calls.',
    sections: [
      {
        title: 'Command & Module Wiring',
        description: 'Commands are immutable value objects representing intent. The BettingModule explicitly lists every CQRS handler in its providers array — NestJS CqrsModule discovers them via decorators but needs them to be DI-registered.',
        callouts: [
          { type: 'insight', icon: '🏛️', title: 'Why CQRS here?', body: 'Bet placement needs strict consistency (SERIALIZABLE transaction). Bet history reads can be eventually consistent (read replicas, Redis cache). CQRS lets us scale and optimise each side independently without coupling them.' },
        ],
        files: [{ filename: 'apps/betting-service/src/application/commands/', lang: 'typescript', code: S.cqrsCommand }],
      },
      {
        title: 'PlaceBet Handler — Distributed Orchestration',
        description: 'The handler orchestrates 6 steps, each of which can fail independently. The Outbox pattern ensures that the Kafka event and the DB write are atomic — both succeed or both fail. The distributed lock prevents two concurrent bets from overdrafting the same wallet.',
        callouts: [
          { type: 'pattern', icon: '🔄', title: 'Outbox over direct Kafka publish', body: 'Direct kafka.produce() inside a DB transaction risks: DB commits but Kafka fails → event lost. With the outbox: the event row IS the DB transaction. If the DB commits, the event will be published. If the DB rolls back, no event is published. Dual-write solved.' },
          { type: 'critical', icon: '🔒', title: 'SERIALIZABLE isolation', body: 'Financial writes use PostgreSQL SERIALIZABLE isolation. This prevents phantom reads where two concurrent bet placements both see the same "available balance" and both succeed, causing an overdraft.' },
        ],
        files: [{ filename: 'apps/betting-service/src/application/commands/handlers/place-bet.handler.ts', lang: 'typescript', code: S.placeBetHandler }],
      },
      {
        title: 'Settlement Saga — Event-driven Orchestration',
        description: 'The BetSettlementSaga reacts to BetSettledEvent (from the results Kafka consumer) and coordinates: update DB status → credit winnings to wallet → send notification. Each step dispatches a separate Command, keeping concerns isolated.',
        callouts: [
          { type: 'insight', icon: '⚙️', title: 'Saga = Choreography + catchError safety net', body: 'NestJS @Saga provides a reactive orchestration pattern. The saga subscribes to the EventBus RxJS stream, filters to specific events, and maps them to Commands. Crucially, catchError prevents one bad event from killing the entire saga subscription.' },
        ],
        files: [{ filename: 'apps/betting-service/src/application/sagas/bet-settlement.saga.ts', lang: 'typescript', code: S.saga }],
      },
    ],
  },
  {
    id: 'domain',
    title: 'Domain & Persistence',
    subtitle: 'Aggregate root, TypeORM entity, and keyset pagination',
    tag: { label: 'Domain', color: '#f0883e', bg: '#271b0e' },
    description: 'The Bet entity is the aggregate root — it owns the state machine, all invariants, and the financial data. The repository abstracts storage so the domain layer never imports TypeORM directly.',
    sections: [
      {
        title: 'Bet Entity — Aggregate Root',
        description: 'All monetary values are stored as BIGINT minor units, odds as integer millis. A @VersionColumn prevents lost-update races. Regulatory data (free bet tokens, RG snapshot) is captured at placement time — immutable audit record.',
        callouts: [
          { type: 'critical', icon: '🔒', title: 'Never use synchronize: true in production', body: 'TypeORM\'s synchronize option drops columns to match entities. One accidental column rename in prod = data loss. Use migrations only, run automatically at service startup.' },
          { type: 'insight', icon: '📦', title: 'Partitioning strategy', body: 'OPEN bets → hot NVMe SSD partition (fast reads for in-play UI). SETTLED bets → cold partition. Archive to S3/Glacier after 1 year. PostgreSQL LIST partitioning on status column makes this transparent to queries.' },
        ],
        files: [{ filename: 'apps/betting-service/src/domain/entities/bet.entity.ts', lang: 'typescript', code: S.betEntity }],
      },
      {
        title: 'Bet Repository — Keyset Pagination',
        description: 'Offset pagination is unstable (a new bet inserted between page 1 and 2 causes items to be skipped or repeated). Keyset pagination uses a stable cursor position — the user always sees a consistent ordered list.',
        callouts: [
          { type: 'pattern', icon: '📄', title: 'Cursor-based pagination', body: 'Cursor = base64(JSON { createdAt, betId }). The betId tiebreaker handles cases where multiple bets have the same createdAt timestamp. Expose as an opaque string — clients treat it as a black box, implementation can change.' },
        ],
        files: [{ filename: 'apps/betting-service/src/infrastructure/repositories/bet.repository.ts', lang: 'typescript', code: S.betRepository }],
      },
    ],
  },
  {
    id: 'kafka',
    title: 'Kafka & The Outbox Pattern',
    subtitle: 'Event streaming, reliable delivery, and CDC',
    tag: { label: 'Event streaming', color: '#d29922', bg: '#2a1f0a' },
    description: 'Kafka decouples services: the betting-service doesn\'t know or care that a risk-service, notification-service, and analytics pipeline also care about every bet placed. The Outbox pattern guarantees that events are delivered exactly once, even if the pod crashes mid-transaction.',
    sections: [
      {
        title: 'Kafka Consumer — Event-driven Integration',
        description: 'The betting-service consumes events from other services. At-least-once delivery guarantees mean every handler must be idempotent. Offsets are committed manually after successful processing.',
        callouts: [
          { type: 'insight', icon: '📬', title: 'Partition by userId, not random', body: 'Partitioning BET_PLACED by userId guarantees that all bets from the same user land in the same partition, in order. This makes per-user RG limit tracking and fraud detection simpler — no out-of-order events to reconcile.' },
          { type: 'critical', icon: '⚖️', title: 'Self-exclusion is regulatory', body: 'The USER_SELF_EXCLUDED handler MUST cancel all open bets. This is a legal requirement in UKGC, MGA, and most other jurisdictions. Failing to implement this correctly = license suspension risk.' },
        ],
        files: [{ filename: 'apps/betting-service/src/infrastructure/kafka/betting.consumer.ts', lang: 'typescript', code: S.kafkaConsumer }],
      },
      {
        title: 'Outbox Processor — Reliable Event Delivery',
        description: 'The Outbox pattern solves the dual-write problem: Kafka event and DB write in the same transaction. The processor polls unpublished rows and forwards them to Kafka. For production at scale, replace polling with Debezium CDC (reads WAL directly, sub-100ms latency).',
        callouts: [
          { type: 'pattern', icon: '📤', title: 'Outbox vs direct produce()', body: 'Direct Kafka.produce() after a DB commit risks: DB commits successfully, then the pod crashes before Kafka receives the message. Event lost, state inconsistent. With outbox: the event IS the DB row — commit = guaranteed eventual delivery.' },
          { type: 'tip', icon: '🚀', title: 'Scale with Debezium CDC', body: 'For high-throughput services (1M+ events/day), replace the 500ms polling with Debezium CDC. It reads PostgreSQL WAL directly and publishes to Kafka. Sub-100ms latency, zero DB polling load, exactly-once semantics with WAL offset tracking.' },
        ],
        files: [{ filename: 'libs/kafka/src/outbox/outbox.processor.ts', lang: 'typescript', code: S.outbox }],
      },
    ],
  },
  {
    id: 'redis',
    title: 'Redis Infrastructure',
    subtitle: 'Distributed locks, rate limiting, and session management',
    tag: { label: 'Redis', color: '#f85149', bg: '#2d1318' },
    description: 'Redis is the shared nervous system of the platform: distributed locks prevent concurrent wallet overdrafts, sliding-window rate limiters prevent abuse, and session management implements secure JWT rotation with theft detection.',
    sections: [
      {
        title: 'Distributed Lock — Redlock Algorithm',
        description: 'Single SETNX is not safe across a Redis cluster failover. Redlock requires quorum from N/2+1 independent nodes — a node failure can\'t silently drop the lock. In production: 5 independent Redis nodes (not cluster) for correct quorum.',
        callouts: [
          { type: 'critical', icon: '🔐', title: 'Always use compare-and-delete', body: 'Never del(lockKey) directly on release — you might delete another process\'s lock. The Lua script checks the value matches your unique token before deleting. This prevents releasing a lock you don\'t own after a TTL timeout.' },
        ],
        files: [{ filename: 'libs/redis/src/distributed-lock.service.ts', lang: 'typescript', code: S.redisLock }],
      },
      {
        title: 'Rate Limiter — Sliding Window',
        description: 'Fixed-window rate limiting has a boundary problem (allows 2× the limit at window edges). The sliding window counts requests in any rolling [now - window, now] interval for accurate enforcement.',
        files: [{ filename: 'libs/redis/src/rate-limiter.service.ts', lang: 'typescript', code: S.rateLimiter }],
      },
      {
        title: 'Session Service — Refresh Token Rotation',
        description: 'Single-use refresh tokens with automatic rotation. If a refresh token is used that no longer exists in Redis (already rotated), it indicates potential theft — the server revokes ALL sessions for that user.',
        callouts: [
          { type: 'insight', icon: '🔄', title: 'Token theft detection', body: 'Refresh token rotation makes theft detectable: a stolen token will eventually be used by the attacker. When the legitimate user tries to refresh, they get "token not found" (already consumed by attacker). Server detects double-use and locks all sessions.' },
          { type: 'critical', icon: '🍪', title: 'Store refresh tokens in HttpOnly cookies', body: 'Never localStorage — XSS attacks can read localStorage and steal the token. HttpOnly cookies are inaccessible to JavaScript. Combine with SameSite=Strict + Secure + CSRF tokens.' },
        ],
        files: [{ filename: 'libs/redis/src/session.service.ts', lang: 'typescript', code: S.sessionService }],
      },
    ],
  },
  {
    id: 'shared-libs',
    title: 'Shared Libraries & Infrastructure',
    subtitle: 'Common types, Kafka topics, Redis keys, docker-compose',
    tag: { label: 'Libs', color: '#3fb950', bg: '#0f2d18' },
    description: 'The @betting/common library holds only the types and constants that multiple services genuinely share. Over-sharing creates coupling — the golden rule: share contracts (types, topic names), never share business logic.',
    sections: [
      {
        title: 'Kafka Topics Registry',
        description: 'All topic names defined as typed constants. A typo in a producer creates a new topic silently. Schema Registry enforces Avro/Protobuf contracts and BACKWARD_TRANSITIVE compatibility — breaking schema changes are caught at publish time, not at consumer runtime.',
        files: [{ filename: 'libs/common/src/constants/kafka-topics.constant.ts', lang: 'typescript', code: S.kafkaTopics }],
      },
      {
        title: 'Redis Key Schema',
        description: 'Typed factory functions for all Redis keys. Short prefixes save memory at scale (10M users × 100 keys = meaningful bytes). Always explicit TTL — immortal keys are a production incident waiting to happen.',
        files: [{ filename: 'libs/common/src/constants/redis-keys.constant.ts', lang: 'typescript', code: S.redisKeys }],
      },
      {
        title: 'Infrastructure: docker-compose',
        description: 'Local development infrastructure with annotated configuration explaining why each setting exists and what its production equivalent is. The comments are the architecture decision record for the infrastructure layer.',
        callouts: [
          { type: 'tip', icon: '🐳', title: 'Running locally', body: 'docker-compose up -d starts PostgreSQL, Redis, Kafka (2 brokers), Schema Registry, Debezium, Prometheus, Grafana, and Jaeger. Then run each service with: npm run start:{service-name}' },
        ],
        files: [{ filename: 'docker-compose.yml', lang: 'yaml', code: S.infrastructure }],
      },
    ],
  },

  // ── NEW CHAPTERS ────────────────────────────────────────────────────────────

  {
    id: 'di-decorators',
    title: 'NestJS Core: Decorators & DI',
    subtitle: 'How @Module, @Injectable, providers, and scopes actually work',
    tag: { label: 'NestJS Core', color: '#58a6ff', bg: '#121d2f' },
    description: 'Every NestJS feature — guards, interceptors, services — is built on two primitives: decorators (which attach metadata via Reflect.defineMetadata) and the DI container (which reads that metadata to wire up the object graph). Understanding these makes everything else click.',
    sections: [
      {
        title: 'Core Decorators Reference',
        description: '@Module describes the DI wiring. @Injectable marks a class as a provider. @Controller registers route handlers. Parameter decorators extract pieces of the request. SetMetadata + Reflector power all custom decorator patterns.',
        callouts: [
          { type: 'insight', icon: '🏗️', title: 'Decorators are just metadata', body: 'A decorator like @Injectable() calls Reflect.defineMetadata(\'injectable\', true, MyClass). At startup, NestJS scans every class in registered modules, reads this metadata, and builds the dependency graph. There is no magic — just metadata and a DI container.' },
          { type: 'warning', icon: '⚠️', title: 'emitDecoratorMetadata must be true', body: 'Without "emitDecoratorMetadata": true in tsconfig.json, TypeScript does not emit constructor parameter type information. Injection silently fails — NestJS cannot resolve constructor dependencies.' },
          { type: 'tip', icon: '💡', title: 'getAllAndOverride vs getAllAndMerge', body: 'getAllAndOverride: method-level decorator wins over class-level (use for @Roles, @Timeout). getAllAndMerge: combines both arrays (use when you want to accumulate values from both class and method). Wrong choice leads to subtle permission bypass bugs.' },
        ],
        files: [{ filename: 'NestJS Decorator Reference', lang: 'typescript', code: S.nestDecorators }],
      },
      {
        title: 'Provider Patterns: useClass, useFactory, useValue, useExisting',
        description: 'The DI container supports four provider shapes. useFactory with inject[] is the most powerful — it lets you run async setup code (connect to Redis, fetch remote config) before NestJS marks the module ready.',
        callouts: [
          { type: 'insight', icon: '🔄', title: 'useFactory is async-aware', body: 'NestJS awaits async factory functions before the module is ready to serve requests. This means you can open a Redis connection, wait for "ready" event, and the HTTP server will not start until it succeeds. Build-time dependency validation for free.' },
          { type: 'critical', icon: '⚡', title: 'REQUEST scope bubble', body: 'Injecting a REQUEST-scoped service into a singleton makes that singleton REQUEST-scoped too — silently. The "scope bubble" cascades upward through the entire dependency chain. Profile with NestJS DevTools before adding REQUEST scope to shared services.' },
          { type: 'pattern', icon: '🌍', title: '@Global() sparingly', body: 'Good candidates for @Global(): RedisModule, KafkaModule, TelemetryModule — true infrastructure that every module genuinely needs. Never @Global() a domain service (OddsService, BetService) — it destroys module boundaries and makes testing harder.' },
        ],
        files: [{ filename: 'Provider Patterns', lang: 'typescript', code: S.diProviders }],
      },
    ],
  },

  {
    id: 'grpc',
    title: 'gRPC: Service-to-Service Communication',
    subtitle: 'Protocol Buffers, hybrid app setup, and streaming RPCs',
    tag: { label: 'gRPC', color: '#f0883e', bg: '#271b0e' },
    description: 'All synchronous inter-service calls use gRPC. Protobuf is 5-10× more compact than JSON, HTTP/2 multiplexing eliminates TCP overhead, and deadlines propagate automatically from parent to child calls. The betting-service exposes both a unary PlaceBet RPC and a server-streaming cashout values feed.',
    sections: [
      {
        title: 'Protocol Buffer Contract',
        description: 'The .proto file is the single source of truth for service communication. It is version-controlled, shared across services, and generates TypeScript types. Any change that breaks an existing consumer fails at compile time, not at runtime.',
        callouts: [
          { type: 'insight', icon: '⚡', title: 'Why gRPC over REST internally?', body: 'Protobuf encoding is 5-10× smaller than JSON. HTTP/2 multiplexing means dozens of concurrent RPCs over one TCP connection. gRPC deadlines propagate: if the API Gateway sets a 5s deadline, the betting-service gRPC call to wallet-service inherits a proportional sub-deadline automatically.' },
          { type: 'critical', icon: '🔒', title: 'mTLS in production', body: 'Internal gRPC without mTLS means any process on the same network can call your financial services. Use mutual TLS: each service has a certificate, both sides verify identity. Istio service mesh can handle this automatically with SPIFFE/SPIRE.' },
          { type: 'pattern', icon: '📦', title: 'int64 for all monetary fields', body: 'Protobuf float and double have the same IEEE 754 precision issues as JavaScript number. Use int64 (minor units) for all monetary fields. The payer\'s balance must not differ between the sender\'s encoding and the receiver\'s decoding.' },
        ],
        files: [{ filename: 'libs/proto/betting.proto', lang: 'protobuf', code: S.grpcProto }],
      },
      {
        title: 'Hybrid App: gRPC + Kafka + HTTP',
        description: 'NestJS hybrid apps attach multiple transports to a single NestJS application instance. The betting-service listens on three transports simultaneously: HTTP (health/metrics), gRPC (sync RPCs), and Kafka (async events). One DI container, three entry points.',
        callouts: [
          { type: 'warning', icon: '⚠️', title: 'startAllMicroservices before listen()', body: 'Always call startAllMicroservices() before app.listen(). If HTTP starts first, the Kubernetes readiness probe may succeed before gRPC is ready — the gateway will try to call a service that isn\'t listening yet.' },
          { type: 'insight', icon: '🔁', title: 'Versioned Kafka consumer group', body: 'Using groupId: \'betting-service-v1\' means a new deployment creates a new consumer group. The old version finishes draining its partitions, then the new version picks up from the head. Zero-downtime redeployment without stopping Kafka consumption.' },
        ],
        files: [{ filename: 'Hybrid App + gRPC Controller', lang: 'typescript', code: S.grpcService }],
      },
    ],
  },

  {
    id: 'auth-service',
    title: 'Auth Service: JWT & Token Lifecycle',
    subtitle: 'RS256 JWKS strategy, Passport, refresh rotation, and logout',
    tag: { label: 'Auth', color: '#a371f7', bg: '#1f1535' },
    description: 'The auth-service is the only issuer of JWTs. It uses RS256 asymmetric signing — all other services verify tokens using the public key from the JWKS endpoint without ever seeing the private key. This means a compromised downstream service cannot forge tokens.',
    sections: [
      {
        title: 'JWT Strategy & Token Shape',
        description: 'PassportStrategy extends the validate() method which runs after signature verification. Keep the JWT payload small — it travels in every request header. Embed roles and kycStatus to avoid DB lookups on every request, but not permissions (too granular and too large).',
        callouts: [
          { type: 'insight', icon: '🔑', title: 'RS256 vs HS256 — why it matters', body: 'HS256: any service with the secret can both verify AND forge tokens. One compromised service = all tokens forgeable. RS256: private key only in auth-service. All other services have only the public key (from JWKS). A compromised service can verify but not forge.' },
          { type: 'insight', icon: '🔄', title: 'JWKS: zero-downtime key rotation', body: 'The JWKS endpoint returns multiple public keys. When rotating: publish the new key alongside the old one → wait for all active tokens (15min max) to expire → remove the old key. Services using jwks-rsa automatically fetch the new key — no redeployment needed.' },
          { type: 'critical', icon: '🍪', title: 'Never store refresh tokens in localStorage', body: 'localStorage is readable by any JavaScript on the page — including injected XSS scripts. Store refresh tokens in HttpOnly cookies: inaccessible to JavaScript, automatically sent by the browser on matching requests. Combine with SameSite=Strict to prevent CSRF.' },
        ],
        files: [{ filename: 'Auth Strategy, Controller & Refresh Flow', lang: 'typescript', code: S.jwtStrategy }],
      },
    ],
  },

  {
    id: 'database',
    title: 'Database Layer: TypeORM Deep-dive',
    subtitle: 'Connection pooling, migrations, BaseEntity, and the ledger pattern',
    tag: { label: 'Database', color: '#d29922', bg: '#2a1f0a' },
    description: 'TypeORM is configured with schema-per-service isolation, fail-fast connection validation, and a strict no-synchronize policy. Migrations are an immutable changelog. The BaseEntity provides UUID primary keys and optimistic locking on every entity for free.',
    sections: [
      {
        title: 'Database Module & Connection Pooling',
        description: 'The TypeORM module is @Global() — every feature module imports it without re-configuring. Connection pool sizing, statement timeouts, and schema isolation are set once here and apply to the entire service.',
        callouts: [
          { type: 'critical', icon: '🚫', title: 'synchronize: false is non-negotiable', body: 'TypeORM\'s synchronize: true drops columns to match entities. Rename a column in development, deploy to production, and the old column (with data) is silently dropped. Use migrations only. Run them automatically at startup with migrationsRun: true and idempotent IF EXISTS / IF NOT EXISTS guards.' },
          { type: 'insight', icon: '🔌', title: 'PgBouncer for 200+ connections', body: 'PostgreSQL forks a process per connection. Beyond 200 active connections, latency degrades. PgBouncer in transaction-mode multiplexes many app connections into a smaller number of real PG connections. target: 1 PgBouncer instance per service with a pool of 20-50.' },
          { type: 'tip', icon: '📊', title: 'statement_timeout vs maxQueryExecutionTime', body: 'statement_timeout (PostgreSQL): kills the query at the DB level, preventing runaway queries from consuming resources. maxQueryExecutionTime (TypeORM): only logs slow queries — does NOT kill them. You need both: log at 1s, kill at 30s.' },
        ],
        files: [{ filename: 'libs/database/src/database.module.ts', lang: 'typescript', code: S.typeormModule }],
      },
      {
        title: 'BaseEntity, Optimistic Locking & Migrations',
        description: 'Every entity inherits UUID primary key, audit timestamps, and a @VersionColumn for optimistic locking. Migrations are append-only — never edit a migration that has run in production.',
        callouts: [
          { type: 'pattern', icon: '🔒', title: 'Optimistic vs pessimistic locking', body: 'Optimistic (VersionColumn): read, modify, save — fail if someone else saved first. Best for: bet status updates, settlement (rare conflicts). Pessimistic (SELECT FOR UPDATE): hold a row lock. Best for: wallet debit (always contended). Use both: Redlock for distributed wallets, VersionColumn for bet state machine.' },
          { type: 'insight', icon: '🔑', title: 'UUID vs BIGSERIAL primary keys', body: 'BIGSERIAL exposes your row count to any user who can create a record (e.g. betId=12345 → you have ~12k bets). UUID v4 reveals nothing. Also, UUIDs are safe to generate client-side or in microservices without coordination. Performance: use BRIN index on createdAt instead of relying on primary key ordering.' },
          { type: 'tip', icon: '🐘', title: 'CREATE INDEX CONCURRENTLY', body: 'Regular CREATE INDEX takes an ACCESS EXCLUSIVE lock — all reads and writes on the table block until it completes. On a large table in production, this is an outage. CONCURRENTLY builds the index without blocking, takes longer, but the table stays fully accessible. Always use CONCURRENTLY in migration up() methods.' },
        ],
        files: [{ filename: 'Base Entity & Migration Example', lang: 'typescript', code: S.baseEntity }],
      },
    ],
  },

  {
    id: 'wallet',
    title: 'Wallet Service: Financial Ledger',
    subtitle: 'Immutable ledger, balance components, and responsible gambling enforcement',
    tag: { label: 'Wallet', color: '#3fb950', bg: '#0f2d18' },
    description: 'The wallet-service is the most consistency-critical service in the platform. Every balance change is an immutable ledger entry. The wallet entity tracks four balance components — real, bonus, in-play escrow, and pending withdrawal — with PostgreSQL CHECK constraints enforcing non-negative values.',
    sections: [
      {
        title: 'Wallet Entity & Transaction Ledger',
        description: 'The Wallet entity stores running balance totals. WalletTransaction is an immutable append-only ledger — it is never updated or deleted, only inserted. The idempotency key prevents double-credits on network retries.',
        callouts: [
          { type: 'critical', icon: '💰', title: 'Never update ledger rows', body: 'WalletTransaction rows are immutable. If an error occurs, insert a correcting/reversing transaction — never UPDATE the original. An immutable ledger means any balance at any point in time can be reconstructed by replaying transactions. This is an audit and reconciliation requirement.' },
          { type: 'insight', icon: '🔢', title: 'Four balance components', body: 'Real = deposited cash. Bonus = promotional funds (wagering requirements apply). In-play = escrowed for open bets (cannot withdraw). Pending withdrawal = requested but not yet PSP-processed. The withdrawable balance = real - inPlay - pendingWithdrawal. Each tracked separately for regulatory reporting.' },
          { type: 'pattern', icon: '🛡️', title: 'DB CHECK constraints as last resort', body: 'The application code should never allow a negative balance — that\'s the Redlock + SERIALIZABLE transaction\'s job. But CHECK constraints are the ultimate safety net: they enforce invariants even if code has a bug, a migration runs directly on the DB, or someone uses psql manually.' },
        ],
        files: [{ filename: 'Wallet Entity & Ledger', lang: 'typescript', code: S.walletEntity }],
      },
      {
        title: 'Responsible Gambling: Limit Enforcement',
        description: 'RG is a legal requirement — not a feature. Limit checks run on every bet placement. Limits are cached in Redis for O(1) lookups. Self-exclusion is permanent by default and triggers immediate cancellation of all open bets.',
        callouts: [
          { type: 'critical', icon: '⚖️', title: 'Cooling-off is not optional', body: 'UKGC requires that limit reductions take effect immediately, while limit increases must wait 24+ hours (preventing impulsive reversal). Self-exclusion minimum is 6 months and cannot be reversed by the user. Failing to implement this correctly = license suspension.' },
          { type: 'warning', icon: '⚠️', title: 'Limits in Redis, not in JWT', body: 'RG limits change frequently (user updates daily limit mid-session). Never cache them in the JWT (15min stale window too long for regulatory compliance). Store in Redis with a 30s TTL — fresh enough for real-time enforcement, fast enough for the bet-placement hot path.' },
        ],
        files: [{ filename: 'apps/risk-service/src/modules/risk/rg-limit.service.ts', lang: 'typescript', code: S.rgService }],
      },
    ],
  },

  {
    id: 'observability',
    title: 'Observability: OTel + Pino',
    subtitle: 'Distributed tracing, structured logging, and PII redaction',
    tag: { label: 'Observability', color: '#79c0ff', bg: '#121d2f' },
    description: 'In a 6-service fleet, a single user action touches multiple services. Without distributed tracing, debugging a slow bet placement means grepping logs across 6 log streams and correlating timestamps manually. OpenTelemetry and structured JSON logging make this a 10-second query.',
    sections: [
      {
        title: 'OpenTelemetry SDK & TracingInterceptor',
        description: 'The OTel SDK auto-instruments PostgreSQL, Redis, Kafka, HTTP, and gRPC. The TracingInterceptor adds an application-level root span per handler with business context (userId, correlationId). Every child span (DB query, Redis command, downstream gRPC call) is automatically nested beneath it.',
        callouts: [
          { type: 'critical', icon: '⚡', title: 'OTel import order is critical', body: 'Import tracing.init as the first line of main.ts — before NestJS, TypeORM, ioredis, or kafkajs. The SDK patches modules at load time via require() hooks. If any instrumented library loads first, its operations will produce no spans. This is the most common OTel setup mistake.' },
          { type: 'insight', icon: '📡', title: 'Tail-based sampling for cost control', body: 'At 10M users × 5 requests each = 50M traces/day. At $0.10/100k traces, that\'s $50/day without sampling. Use 100% sampling for errors (always valuable), 10% for success (statistically representative). An OTel Collector with tail-based sampling makes this decision after seeing the full trace.' },
          { type: 'pattern', icon: '🔗', title: 'W3C TraceContext propagation', body: 'The OTel SDK propagates trace context via the W3C traceparent header. The API Gateway starts a trace; the header flows through HTTP → gRPC metadata → Kafka message headers. Every service in the chain attaches its spans to the same root trace — the full distributed call tree in one query.' },
        ],
        files: [{ filename: 'OTel Init & Tracing Interceptor', lang: 'typescript', code: S.otelTracing }],
      },
      {
        title: 'Pino Structured Logging & PII Redaction',
        description: 'Every log line is a JSON object queryable in Datadog/Grafana/CloudWatch without a parser. PII redaction is configured once at the logger level — no risk of a developer accidentally logging an email or card number in a new handler.',
        callouts: [
          { type: 'critical', icon: '🔒', title: 'Never log PII — even in dev', body: 'Developers copying a log line to Slack, a ticket, or a pastebin is a real GDPR incident. Configure redaction in the logger itself (not per-handler). Redact: Authorization header, cookies, passwords, card numbers, IBANs. Log userId (opaque UUID), never email or name.' },
          { type: 'tip', icon: '🌊', title: 'Log level discipline', body: 'error: system broken, needs immediate attention. warn: something unexpected but handled. info: normal business events (bet placed, settlement started). debug: useful in dev only. trace: verbose internals. In production: info+. Never log at trace in prod — the volume alone can consume significant I/O budget.' },
        ],
        files: [{ filename: 'Pino LoggerModule Config', lang: 'typescript', code: S.pinoConfig }],
      },
    ],
  },

  {
    id: 'queues',
    title: 'BullMQ: Background Queues',
    subtitle: 'Priority queues, processors, retry policies, and dead-letter handling',
    tag: { label: 'Queues', color: '#f0883e', bg: '#271b0e' },
    description: 'Notifications are delivered asynchronously via BullMQ priority queues backed by Redis. Critical notifications (2FA codes, security alerts) occupy their own queue with higher priority and more retries than marketing emails. If a worker pod crashes mid-processing, BullMQ auto-requeues the job.',
    sections: [
      {
        title: 'Queue Configuration & Processor',
        description: 'Three queues, one processor class per queue. @Processor(queueName) registers the class with BullMQ. WorkerHost.process() is called for each dequeued job. Promise.allSettled ensures partial delivery failure on one channel does not block others.',
        callouts: [
          { type: 'critical', icon: '💾', title: 'Queues need a dedicated Redis instance', body: 'Never use the same Redis for queues and cache. Cache uses allkeys-lru eviction policy — it silently evicts the oldest keys when memory is full. A queued notification job IS a Redis key. In a memory spike, Redis would evict queued jobs, silently dropping notifications. Use db: 1 or a dedicated Redis instance.' },
          { type: 'insight', icon: '🔄', title: 'Stalled job detection', body: 'If a worker crashes mid-job (OOM, SIGKILL), BullMQ marks it stalled and re-queues it after a timeout. This means process() can be called twice for the same job — it MUST be idempotent. Check a "delivered" flag in Redis before sending, or use idempotent PSP/email APIs.' },
          { type: 'pattern', icon: '📬', title: 'Promise.allSettled over Promise.all for fan-out', body: 'When delivering to email + SMS + push simultaneously, Promise.all fails fast if any channel throws. Promise.allSettled collects all results regardless — a failed email delivery does not block push. Log partial failures but do not retry the whole job (email was already sent).' },
        ],
        files: [{ filename: 'BullMQ Config & Processor', lang: 'typescript', code: S.bullmqQueues }],
      },
    ],
  },

  {
    id: 'pipes-lifecycle',
    title: 'Pipes, Lifecycle & Health Checks',
    subtitle: 'Validation pipeline, module hooks, and Kubernetes probes',
    tag: { label: 'Pipes & Lifecycle', color: '#3fb950', bg: '#0f2d18' },
    description: 'Pipes are the validation and transformation stage — they run between the incoming request and the handler. Lifecycle hooks let services manage resource connections cleanly across deployments. Health checks tell Kubernetes whether a pod should receive traffic.',
    sections: [
      {
        title: 'ValidationPipe Deep-dive & Custom Pipes',
        description: 'ValidationPipe with whitelist + forbidNonWhitelisted + transform is the correct configuration for a financial API. The custom ParseCursorPipe shows how to implement a type-safe pagination cursor decoder as a reusable pipe.',
        callouts: [
          { type: 'insight', icon: '🔍', title: 'whitelist + forbidNonWhitelisted together', body: 'whitelist alone silently drops unexpected fields. forbidNonWhitelisted throws 400 if any unexpected field arrives. For a financial API, use both: unknown fields are an error, not a silent no-op. They may indicate a client sending wrong version DTOs or an attacker probing fields.' },
          { type: 'pattern', icon: '✅', title: '@ValidateNested requires @Type', body: 'class-validator\'s @ValidateNested({ each: true }) only recurses if class-transformer knows the target type. Without @Type(() => BetSelectionDto), each element stays as a plain object and validation silently passes — even if required fields are missing. Always pair them.' },
          { type: 'tip', icon: '🔢', title: 'implicit vs explicit type coercion', body: 'transformOptions: { enableImplicitConversion: true } coerces "?limit=20" to number without needing @Type(() => Number) everywhere. Useful for simple query strings. Disable for body DTOs — implicit coercion can silently convert things you don\'t expect.' },
        ],
        files: [{ filename: 'Pipes & ValidationPipe Config', lang: 'typescript', code: S.pipes }],
      },
      {
        title: 'Module Lifecycle Hooks & Health Checks',
        description: 'onModuleInit() and onModuleDestroy() bracket the service lifetime. The health controller uses @nestjs/terminus to expose readiness and liveness probes that Kubernetes uses to route traffic and restart unhealthy pods.',
        callouts: [
          { type: 'critical', icon: '🔌', title: 'enableShutdownHooks() is required', body: 'Without app.enableShutdownHooks() in main.ts, SIGTERM never triggers onModuleDestroy(). The pod is killed mid-Kafka-produce and messages are lost. This is especially critical for: Kafka producers (flush pending), DB connections (drain transactions), gRPC server (drain active streams).' },
          { type: 'insight', icon: '🏥', title: 'Liveness vs readiness', body: 'Liveness: is the Node.js event loop still running? A 503 here means the pod is stuck (deadlock, OOM) — restart it. Readiness: can the pod serve requests right now? A 503 here means the DB is temporarily unreachable — remove from load balancer, but do not restart. They are different signals, not the same check.' },
          { type: 'pattern', icon: '⏱️', title: 'terminationGracePeriodSeconds', body: 'In Kubernetes, set terminationGracePeriodSeconds = Kafka flush timeout + DB drain timeout + 10s margin. Default is 30s. If your Kafka producer can buffer for up to 5s and DB transactions drain in 10s, set terminationGracePeriodSeconds to 25+. If k8s kills the pod before onModuleDestroy() finishes, you lose data.' },
        ],
        files: [{ filename: 'Lifecycle Hooks & Health Controller', lang: 'typescript', code: S.lifecycleHooks }],
      },
    ],
  },

  {
    id: 'execution-context',
    title: 'ExecutionContext Deep-dive',
    subtitle: 'Writing guards & interceptors that work across HTTP, gRPC, and WebSocket',
    tag: { label: 'Core concept', color: '#58a6ff', bg: '#121d2f' },
    description: 'ExecutionContext is the most important object in NestJS infrastructure code. Every guard and interceptor receives one. It is transport-agnostic — the same object whether the request came from an HTTP client, a gRPC caller, or a WebSocket message. Understanding it lets you write one guard class that works everywhere.',
    sections: [
      {
        title: 'ExecutionContext, getType(), switchTo*(), and Reflector',
        description: 'The context exposes the current transport type, the handler method being called, and the controller class. switchToHttp/Rpc/Ws returns a transport-specific object. getHandler() + getClass() are how Reflector reads your custom decorator metadata.',
        callouts: [
          { type: 'insight', icon: '🔀', title: 'One guard for all transports', body: 'JwtAuthGuard can extend AuthGuard(\'jwt\') for HTTP or implement CanActivate directly for multi-transport use. The UniversalAuthGuard pattern here handles HTTP Bearer tokens, gRPC Metadata headers, and WebSocket handshake auth in the same canActivate() method — no code duplication.' },
          { type: 'warning', icon: '⚠️', title: 'switchToHttp() throws on other transports', body: 'Calling ctx.switchToHttp() inside a guard attached to a gRPC handler throws a runtime error. Always check ctx.getType() first, or use try/catch. This is the most common cause of "guard works on HTTP but crashes on Kafka consumer" bugs.' },
          { type: 'tip', icon: '💡', title: 'getAllAndOverride vs getAllAndMerge', body: 'getAllAndOverride: the more specific decorator wins (method > class). Use for @Roles, @Timeout — you want the method\'s value to override the class default. getAllAndMerge: combines both arrays into one. Use when accumulating multiple values, e.g. collecting required capabilities from both class and method.' },
        ],
        files: [{ filename: 'ExecutionContext Reference', lang: 'typescript', code: S.executionContext }],
      },
    ],
  },

  {
    id: 'dynamic-modules',
    title: 'Dynamic Modules',
    subtitle: 'Building forRoot(), forRootAsync(), and forFeature() yourself',
    tag: { label: 'Module system', color: '#a371f7', bg: '#1f1535' },
    description: 'Dynamic modules are how NestJS allows library modules to be configured by the application — ConfigModule, TypeOrmModule, BullModule, and every @Global module uses this pattern. Building one teaches you exactly how the NestJS DI container wires up async providers and how forFeature() achieves scoped registrations.',
    sections: [
      {
        title: 'forRoot, forRootAsync, and forFeature',
        description: 'forRoot() is synchronous config. forRootAsync() is the async equivalent — it accepts useFactory + inject so the module can receive ConfigService. forFeature() returns a non-global DynamicModule that adds scoped providers only to the importing module.',
        callouts: [
          { type: 'insight', icon: '🏭', title: 'forRootAsync is a DynamicModule factory', body: 'The method returns a plain JavaScript object { module, providers, exports, imports, global }. There is no magic — NestJS reads this object exactly as it would read a @Module() decorator. Understanding this means you can debug any third-party module by logging its returned DynamicModule.' },
          { type: 'pattern', icon: '🔗', title: 'forFeature for scoped registrations', body: 'TypeOrmModule.forFeature([Bet]) creates TypeORM repositories only for the BettingModule. BullModule.registerQueue creates queue clients only for the importing module. This prevents every module from polluting the global DI container with hundreds of entity repositories.' },
          { type: 'warning', icon: '⚠️', title: 'Await async providers before module ready', body: 'If useFactory is async, NestJS awaits it before marking the module as initialized. If your Redis factory does NOT await the connection ready event, the first Redis call after startup races against the connecting state. Always await the connection inside the factory.' },
        ],
        files: [{ filename: 'Dynamic Module Implementation', lang: 'typescript', code: S.dynamicModules }],
      },
    ],
  },

  {
    id: 'serialization',
    title: 'Response Serialization',
    subtitle: 'ClassSerializerInterceptor, @Exclude, @Expose, and @Transform',
    tag: { label: 'Interceptor', color: '#79c0ff', bg: '#121d2f' },
    description: 'ClassSerializerInterceptor runs class-transformer on every response object. Combined with @Exclude and @Expose decorators on your DTO classes, it provides a declarative, class-level API for controlling what data leaves the service — no manual property deletion in handlers.',
    sections: [
      {
        title: '@Exclude, @Expose, @Transform, @Type, and @SerializeOptions',
        description: 'Annotate your response DTO with which fields are visible. @Transform reshapes values — use it to convert internal integer minor units to formatted decimal strings for clients. @Type is required for nested objects to receive their own @Exclude/@Expose treatment.',
        callouts: [
          { type: 'critical', icon: '🔒', title: 'excludeExtraneousValues: true is the safe default', body: 'Without it, ClassSerializerInterceptor includes ALL properties unless @Exclude is applied — a new property added to the entity silently appears in the API response. With excludeExtraneousValues: true, ONLY @Expose() fields are included. This is a whitelist, not a blacklist.' },
          { type: 'insight', icon: '🔄', title: 'Convert BIGINT minor units at the serialisation layer', body: 'Internal representation: 10050 (integer pence). External: "100.50" (formatted string). The @Transform decorator on the DTO is the single place this conversion lives — not scattered across handlers. Clients always see formatted values; the domain always works in integers.' },
          { type: 'warning', icon: '⚠️', title: '@Type is required for nested object serialisation', body: 'Without @Type(() => SelectionResponseDto), class-transformer treats nested objects as plain Record<string, unknown>. The @Exclude/@Expose decorators on SelectionResponseDto are silently ignored. Always pair @ValidateNested + @Type for input, @Expose + @Type for output.' },
        ],
        files: [{ filename: 'Response Serialisation with class-transformer', lang: 'typescript', code: S.serialization }],
      },
    ],
  },

  {
    id: 'config-module',
    title: 'Configuration Module',
    subtitle: '@nestjs/config, namespaced config, and fail-fast validation',
    tag: { label: 'Config', color: '#d29922', bg: '#2a1f0a' },
    description: 'The validate option in ConfigModule.forRoot() is the most important configuration decision. Crash immediately at startup if JWT_SECRET is missing — not with a cryptic error on the first authenticated request. Namespaced config with registerAs() provides typed, auto-complete access to grouped settings.',
    sections: [
      {
        title: 'Env Validation, Namespaced Config, and Injection Patterns',
        description: 'class-validator validates every environment variable at startup. registerAs() groups related config into typed namespaces. The typed @Inject(configToken.KEY) pattern is refactor-safe and provides full TypeScript auto-complete — no more string key lookups scattered across services.',
        callouts: [
          { type: 'critical', icon: '💥', title: 'validate fails fast at startup', body: 'Without validate, a missing JWT_SECRET surfaces as a cryptic RS256 error on the first authenticated request in production — possibly minutes after deploy. With validate, the pod refuses to start and the Kubernetes readiness probe fails immediately. Fail fast, fail loudly.' },
          { type: 'insight', icon: '📦', title: 'registerAs creates a typed namespace', body: 'config.get<string>(\'DB_HOST\') is a string lookup that can drift from the actual env var name. databaseConfig.host is TypeScript-typed and refactor-safe — rename the env var in registerAs, the TypeScript compiler finds all usages. Use namespaced config for any service with more than 5 env vars.' },
          { type: 'tip', icon: '🔍', title: 'expandVariables for .env composition', body: 'With expandVariables: true, you can write DB_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/db in your .env file. Good for composing connection strings from individual parts while still validating each component separately with class-validator.' },
        ],
        files: [{ filename: '@nestjs/config Deep-dive', lang: 'typescript', code: S.configModule }],
      },
    ],
  },

  {
    id: 'testing',
    title: 'Testing in NestJS',
    subtitle: 'createTestingModule, overrideProvider, integration & E2E tests',
    tag: { label: 'Testing', color: '#3fb950', bg: '#0f2d18' },
    description: 'NestJS testing builds a real DI container in isolation. overrideProvider() swaps any provider with a mock without touching production code. The same module hierarchy used in production is used in tests — you get real DI wiring validation for free alongside your functional tests.',
    sections: [
      {
        title: 'Unit Tests, Integration Tests, and E2E with supertest',
        description: 'Unit tests isolate one class with mocked dependencies. Integration tests wire real modules but mock external calls (gRPC, Kafka). E2E tests spin up the full HTTP stack with supertest — test the API contract including validation, guards, and the response envelope.',
        callouts: [
          { type: 'insight', icon: '🏗️', title: 'overrideProvider: mock at the boundary', body: 'Mock the providers that represent external systems (WalletGrpcClient, RiskGrpcClient, KafkaProducer). Keep the real DI wiring for everything internal (CommandBus, BetRepository, OddsService). This tests the actual orchestration logic while isolating network calls.' },
          { type: 'pattern', icon: '🧪', title: 'Test the contract, not the implementation', body: 'E2E tests should assert: status code, error.code structure, response envelope shape — not that a specific internal method was called. This lets you refactor the implementation freely without rewriting tests. Integration tests assert observable DB state, not internal service calls.' },
          { type: 'tip', icon: '💡', title: 'Use a real test database, not mocks', body: 'TypeORM repository mocks pass tests even when the query is wrong (WHERE clause typo, missing index). Use a real PostgreSQL test database (Docker Compose in CI). Integration tests that hit real DB catch: missing migrations, constraint violations, wrong isolation levels.' },
        ],
        files: [{ filename: 'Unit, Integration & E2E Tests', lang: 'typescript', code: S.testing }],
      },
    ],
  },

  {
    id: 'scheduling',
    title: 'Task Scheduling',
    subtitle: '@Cron, @Interval, SchedulerRegistry, and dynamic jobs',
    tag: { label: 'Scheduler', color: '#f0883e', bg: '#271b0e' },
    description: 'The platform uses scheduled tasks for: outbox polling (every 30s), RG counter resets (nightly), expired session cleanup, and market data aggregation. @nestjs/schedule wraps node-cron and provides declarative method-level scheduling with a SchedulerRegistry for runtime job management.',
    sections: [
      {
        title: '@Cron, @Interval, @Timeout, and Dynamic Job Management',
        description: 'Decorators register jobs at module init. SchedulerRegistry lets you add, remove, and query jobs at runtime — essential when job timing comes from database configuration (per-operator settlement schedules, user-specific reminders).',
        callouts: [
          { type: 'warning', icon: '⚠️', title: '@Cron skips if previous execution is still running', body: 'This is the default (non-overlapping) behaviour — good for idempotent tasks. But if the outbox processor takes longer than 30s, you silently fall behind. Add a distributed lock with a TTL slightly shorter than the interval, and monitor lag via a "outbox_unpublished_count" metric.' },
          { type: 'insight', icon: '🌍', title: 'timeZone option for multi-jurisdiction platforms', body: 'A nightly RG reset at midnight UTC is wrong for UK users (BST = UTC+1 in summer). Use { timeZone: \'Europe/London\' }. For per-operator timezones stored in the DB, use SchedulerRegistry.addCronJob() at startup with each operator\'s preferred timezone.' },
          { type: 'critical', icon: '🔒', title: 'Use distributed locks in multi-pod deployments', body: 'Every pod runs the same @Cron handlers. Without a distributed lock, 3 pods × 1 outbox processor = 3× publishes for each outbox row. Use DistributedLockService.withLock() inside every @Cron handler that produces side effects (DB writes, Kafka publishes, external API calls).' },
        ],
        files: [{ filename: 'Scheduled Tasks Service', lang: 'typescript', code: S.scheduler }],
      },
    ],
  },

  {
    id: 'exceptions',
    title: 'Exception Hierarchy & Custom Exceptions',
    subtitle: 'Built-in exceptions, domain exceptions, WsException, RpcException',
    tag: { label: 'Exceptions', color: '#f85149', bg: '#2d1318' },
    description: 'NestJS provides a full hierarchy of HTTP exceptions, but the real power is in custom domain exceptions. Throwing InsufficientFundsException instead of ConflictException keeps business logic free of HTTP concerns, enables typed @Catch() filters with context-rich logging, and makes test assertions readable.',
    sections: [
      {
        title: 'Exception Types, Custom Domain Exceptions, and Typed Filters',
        description: 'All 14 built-in HTTP exceptions, non-HTTP exceptions (RpcException, WsException), and how to build custom domain exceptions that carry rich context for logging while returning safe minimal responses to clients.',
        callouts: [
          { type: 'insight', icon: '🏛️', title: 'Domain exceptions decouple from HTTP', body: 'PlaceBetHandler throws InsufficientFundsException — it has no knowledge of HTTP 409. The exception filter decides the HTTP status. This makes the handler fully testable with jest.fn() without starting an HTTP server, and makes the intent explicit: "funds were insufficient" is clearer than "conflict".' },
          { type: 'critical', icon: '🔒', title: 'Never expose internal state in exception responses', body: 'InsufficientFundsException logs userId + required + available server-side. The client response says only "Insufficient funds" with no amounts. An attacker who can observe the exact balance gap can probe the wallet state. Log everything; expose nothing sensitive.' },
          { type: 'pattern', icon: '🎯', title: '@Catch(SpecificType) for domain exception routing', body: 'The global @Catch() filter handles everything. Typed filters @Catch(InsufficientFundsException) intercept before the global filter — use them when a specific exception needs richer logging, a different response shape, or side effects (alerting, fraud flagging). Both can coexist.' },
        ],
        files: [{ filename: 'Exception Hierarchy Reference', lang: 'typescript', code: S.exceptionHierarchy }],
      },
    ],
  },

  {
    id: 'microservice-patterns',
    title: 'Microservice Patterns',
    subtitle: '@MessagePattern, @EventPattern, ClientProxy, send() vs emit()',
    tag: { label: 'Microservices', color: '#79c0ff', bg: '#121d2f' },
    description: 'NestJS microservice decorators abstract the transport — the same @MessagePattern works over Kafka, Redis, TCP, or NATS. ClientProxy.send() provides request-response; .emit() is fire-and-forget. The critical difference: only use Kafka @MessagePattern for queries that truly need a reply; prefer gRPC for low-latency synchronous calls.',
    sections: [
      {
        title: '@MessagePattern vs @EventPattern, ClientProxy, and ClientsModule',
        description: 'The receiving side uses @MessagePattern for queries that need a typed reply and @EventPattern for domain events that need no reply. The sending side uses ClientProxy — the transport-agnostic client that maps send() to request-response and emit() to fire-and-forget.',
        callouts: [
          { type: 'insight', icon: '📨', title: 'send() vs emit() — the key difference', body: 'ClientProxy.send() waits for a reply — use for queries (get bet, check balance). ClientProxy.emit() is fire-and-forget — use for domain events (bet placed, user registered). emit() resolves when the broker acknowledges receipt, not when a consumer has processed it. Always pipe timeout() onto send() — a missing consumer means it never resolves.' },
          { type: 'warning', icon: '⚠️', title: 'subscribeToResponseOf() before connect()', body: 'For Kafka request-response, call subscribeToResponseOf(topic) in onModuleInit() BEFORE connect(). NestJS generates a reply topic and needs to subscribe to it before the connection is established. Missing this = send() never receives a reply, timeout after N seconds.' },
          { type: 'pattern', icon: '🔑', title: 'Partition by userId for event ordering', body: 'When emitting BET_PLACED with key: event.userId, all bets from the same user land in the same Kafka partition. Consumers processing that partition see events in order. This makes per-user RG limit tracking and fraud detection reliable — no out-of-order bet events to reconcile.' },
        ],
        files: [{ filename: 'Microservice Patterns Reference', lang: 'typescript', code: S.microservicePatterns }],
      },
    ],
  },
]

// ─────────────────────────────────────────────────────────────────────────────
// deskbird example app
// ─────────────────────────────────────────────────────────────────────────────

const D = {}

D.appBootstrap = `// src/app/app.ts  — entry point
// NestFastifyApplication = Fastify adapter instead of Express.
// Fastify is 2× faster at raw HTTP throughput; required for HTTP/2 push on GCP.

export async function createApp() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    // HTTP/2 only on Cloud (GCP Cloud Run), plain HTTP/1.1 locally
    new FastifyAdapter(isCloudExecution() ? { http2: true } : undefined),
    { bufferLogs: true },   // buffer until custom logger is wired
  );

  await configureApp(app);           // helmet + CORS (from @deskbird/rest-nestjs)
  app.useLogger(app.get(DeskbirdLoggerService));
  app.enableShutdownHooks();         // graceful SIGTERM drain

  // Swagger: generate OpenAPI spec and write it to disk at startup.
  // The CI pipeline diffs openapi-spec.json to catch unintended breaking changes.
  const config = new DocumentBuilder()
    .setTitle('Deskbird Public Api')
    .setVersion('1.0')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, 'firebase-jwt')
    .build();

  const document = SwaggerModule.createDocument(app, config);

  // Strip legacy /v1 path prefix from the public spec (internal routes are hidden)
  const filteredPaths = Object.entries(document.paths).reduce(
    (acc, [path, pathItem]) => {
      if (!path.startsWith(LEGACY_PATH_PREFIX)) acc[path] = pathItem;
      return acc;
    },
    {} as Record<string, PathItemObject>,
  );
  document.paths = filteredPaths;

  fs.writeFileSync('./openapi-spec.json', JSON.stringify(document, null, 2));
  SwaggerModule.setup('docs', app, document);

  return app;
}

// src/app/app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot(),            // Zod-validated env at startup
    SharedModule,                      // service clients + shared guards
    DeskbirdAuthModule.forRootAsync({ useClass: DeskbirdAuthOptionsFactory }),
    DeskbirdLoggingModule.forRootAsync({ useClass: DeskbirdLoggingOptionsFactory }),
    TracingModule.forRoot(),           // GCP Cloud Trace propagation
    DeskbirdErrorModule.forRoot(),     // global exception filter
    ServiceAccountTokenProviderModule.forRootAsync({ useClass: ServiceAccountTokenProviderModuleFactory }),
    JwtModule.register({ global: true }),
    // Feature modules (one per domain entity)
    UsersModule, BookingsModule, OfficesModule, KeysModule,
    GroupsModule, ResourcesModule, ImportModule, SchedulingModule,
    RoomsModule, FloorsModule, ZonesModule,
  ],
  providers: [
    // Global ValidationPipe: transform: true coerces query strings to typed objects
    { provide: APP_PIPE, useFactory: () => new ValidationPipe({ transform: true }) },
  ],
})
export class AppModule {}`

D.configureApp = `// libs/rest-nestjs/src/configureApp.ts
// Shared bootstrap helper — every NestJS service in the monorepo calls this.
// Centralises security headers so they cannot be forgotten per-service.

export const configureApp = async (app: NestFastifyApplication) => {
  // fastify-helmet: sets Content-Security-Policy, HSTS, X-Frame-Options,
  // X-Content-Type-Options, Referrer-Policy, X-DNS-Prefetch-Control
  await app.register(fastifyHelmet);

  // noindex/nofollow on every response — API responses must never appear in search results
  app.getHttpAdapter().getInstance().addHook('onRequest', (_req, reply, done) => {
    reply.header('X-Robots-Tag', 'noindex, nofollow');
    done();
  });

  // CORS: allowlist driven by CUSTOM_DOMAINS env var (set per-environment in Cloud Run)
  app.enableCors(corsOptions(customDomains()));
};

// cors.ts
export const corsOptions = (customDomains: string[]): CorsOptions => ({
  origin: [
    /\\.deskbird\\.app$/,        // all deskbird subdomains
    /\\.deskbird\\.com$/,
    ...customDomains,            // per-company white-label domains
    ...(isDev() ? [/localhost/] : []),
  ],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'correlation-id', 'traceparent'],
  credentials: true,
})`

D.authModule = `// libs/auth-nestjs/src/auth.module-definition.ts
// ConfigurableModuleBuilder generates forRoot / forRootAsync / forFeature
// with full async factory support (useClass / useFactory / useExisting).
// This is the idiomatic NestJS pattern for publishable library modules.

export type ModuleOptions = {
  gcpProjectId: string;
  numericProjectId: number;
};

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
  new ConfigurableModuleBuilder<MinimalModuleOptions>()
    .setClassMethodName('forRoot')   // generates forRoot() and forRootAsync()
    .build();

// libs/auth-nestjs/src/auth.module.ts
@Global()          // exported providers available everywhere without re-importing
@Module({
  imports: [
    ScheduleModule.forRoot(),   // for certificate renewal cron
    JwtModule.register({}),
  ],
  providers: [
    CertificateProvider,
    CertificateRenewalService,
    AuthVerifier,
    DeskbirdAuthModuleOptionsWithDefaultsFactory,
    {
      provide: MODULE_OPTIONS_WITH_DEFAULTS_TOKEN,
      // async factory: fetches numericProjectId from GCP metadata endpoint
      // if not provided explicitly — this means the module self-configures on GCP
      useFactory: (factory: DeskbirdAuthModuleOptionsWithDefaultsFactory) => factory.create(),
      inject: [DeskbirdAuthModuleOptionsWithDefaultsFactory],
    },
  ],
  exports: [AuthVerifier, MODULE_OPTIONS_WITH_DEFAULTS_TOKEN],
})
export class DeskbirdAuthModule extends ConfigurableModuleClass {}

// Usage in consuming app (app.module.ts):
// DeskbirdAuthModule.forRootAsync({ useClass: DeskbirdAuthOptionsFactory })
// where DeskbirdAuthOptionsFactory implements ModuleOptionsFactory<MinimalModuleOptions>`

D.certificateProvider = `// libs/auth-nestjs/src/auth.certificateProvider.ts
// Firebase issues JWT tokens signed with rotating X.509 certificates.
// The certificates are fetched from Google APIs and cached in-memory.
// CertificateRenewalService runs a @Cron job to refresh them before expiry.

@Injectable()
export class CertificateProvider {
  // Two issuers supported:
  //   securetoken.google.com/<project> → Firebase Auth (mobile/web users)
  //   accounts.google.com              → Google SA tokens (service-to-service)
  private readonly cache: Map<string, CertificateConfig>;

  constructor(@Inject(MODULE_OPTIONS_WITH_DEFAULTS_TOKEN) options: ModuleOptions) {
    this.cache = new Map([
      [
        \`https://securetoken.google.com/\${options.gcpProjectId}\`,
        { url: 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com', certificates: {} },
      ],
      [
        'https://accounts.google.com',
        { url: 'https://www.googleapis.com/oauth2/v1/certs', certificates: {} },
      ],
    ]);
  }

  getCachedCertificateOrThrow({ iss, kid }: { iss: string; kid: string }): string {
    const cert = this.cache.get(iss)?.certificates[kid];
    if (!cert) throw new Error('iss or kid not found');
    return cert;
  }

  async renewCertificates(iss: string, maxRetries = 3): Promise<{ maxAgeInSeconds: number }> {
    const config = this.cache.get(iss);
    // retry with 1s delay — Google APIs have transient 5xx
    const { data, headers } = await retry({ times: maxRetries, delay: 1000 }, () => axios.get(config!.url));

    // Respect Cache-Control: max-age from Google — re-fetch only when certs actually rotate
    const maxAgeInSeconds = extractMaxAgeFromHeaders(headers['cache-control']) ?? 60;
    this.cache.set(iss, { ...config!, certificates: data });
    return { maxAgeInSeconds };
  }
}

// libs/auth-nestjs/src/auth.verifier.ts
@Injectable()
export class AuthVerifier {
  constructor(
    private jwtService: JwtService,
    private certificateProvider: CertificateProvider,
  ) {}

  verify(token: string): object {
    // Decode without verifying first — need kid/iss to look up the right certificate
    const decoded = this.jwtService.decode(token, { complete: true });
    const kid = decoded?.header?.kid;
    const iss = decoded?.payload?.iss;

    if (!kid || !iss)
      throw new DeskbirdHttpException(HttpStatus.UNAUTHORIZED, 'tokenIncompatible', 'Token format not compatible');

    const certificate = this.certificateProvider.getCachedCertificateOrThrow({ kid, iss });

    // Now verify signature — throws TokenExpiredError if expired
    return this.jwtService.verify(token, { publicKey: certificate });
  }
}`

D.guards = `// libs/guards-nestjs/src/requireFirebaseToken.ts
// Three-layer guard chain (applied via @UseGuards in that order):
//   1. RequireFirebaseToken  — verifies JWT, attaches tokenData to request
//   2. RequireUser           — fetches full user from Users service, attaches user
//   3. RequireUserRole       — checks user.role against allowed roles
//
// Why separate guards instead of one?
//   Each layer is independently reusable.
//   Some routes need token only (stats endpoints), some need role check.
//   Guards run sequentially; later guards trust earlier ones already ran.

@Injectable()
export class RequireFirebaseToken implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const [type, token] = request.headers.authorization?.split(' ') ?? [];

    if (type !== 'Bearer' || !token)
      throw new DeskbirdHttpException(401, 'tokenRequired', 'Resource access requires bearer token');

    try {
      const payload = this.authVerifier.verify(token);

      // aud must match GCP project ID — prevents tokens from other projects being used
      if (payload.aud !== this.authModuleOptions.gcpProjectId)
        throw new DeskbirdHttpException(401, 'tokenIncompatible', 'Token audience mismatch');

      // Zod parse: validates shape AND transforms snake_case → camelCase
      // e.g. email_verified → emailVerified, sub → firebaseId
      const result = UserTokenDataSchema.safeParse(payload);
      if (!result.success)
        throw new DeskbirdHttpException(401, 'tokenIncompatible', 'Token payload format not compatible');

      // Attach to request — downstream guards and @CurrentUserTokenData() read this
      (request as RequestWithUserTokenData).userTokenData = result.data;
      return true;
    } catch (error) {
      if (error instanceof DeskbirdHttpException) throw error;
      if (error instanceof TokenExpiredError)
        throw new DeskbirdHttpException(401, 'tokenExpired', 'Bearer token is expired');
      throw new DeskbirdHttpException(401, 'unauthorized', 'Token invalid or expired');
    }
  }
}

// RequireUser — fetches user from Users service and attaches to request
@Injectable()
export class RequireUser implements CanActivate {
  constructor(private usersClient: UsersClient) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    // Relies on RequireFirebaseToken having run first
    if (!isRequestWithUserTokenData(request))
      throw new Error('Did you forget to call RequireFirebaseToken before?');

    const user = await this.usersClient.findOne({ id: request.userTokenData.firebaseId }).then(unwrapOrThrow);
    if (!user) throw new DeskbirdHttpException(404, 'user_not_found', 'User not found');

    (request as RequestWithUser).user = user;
    return true;
  }
}

// RequireUserRole — uses mixin() for parameterised guard instances
// mixin() creates a new class with the config baked in,
// making each instance a distinct injectable for NestJS's DI container.
export const RequireUserRole = ({ oneOf, allowDeskbirdAdmins }: {
  oneOf: DeskbirdUser['role'][];
  allowDeskbirdAdmins?: boolean;
}) => {
  class RequireUserRoleGuardMixin implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
      const request = context.switchToHttp().getRequest<FastifyRequest>();

      // Super-admin bypass: deskbird internal staff can access any company
      if (allowDeskbirdAdmins && request.userTokenData?.isDeskbirdAdmin) return true;

      if (!isRequestWithUser(request))
        throw new Error('Did you forget to call RequireUser before?');

      if (!oneOf.includes(request.user.role))
        throw new DeskbirdHttpException(403, 'forbidden', 'You are not allowed to access this resource');

      return true;
    }
  }
  return mixin(RequireUserRoleGuardMixin);
};

// Usage on a controller:
// @UseGuards(RequireFirebaseToken, RequireUser, RequireUserRole({ oneOf: ['admin'] }))

// RequireFeatures — feature-flag guard that calls FeatureManager service
// The featureAccessContextProvider is injected at the call site so the guard
// knows which company/user context to check features for.
export const RequireFeatures =
  (contextProvider: FeatureAccessContextProvider) =>
  (conditionType: 'all' | 'any', ...features: string[]) => {
    @Injectable()
    class RequireFeaturesMixin implements CanActivate {
      constructor(@Inject(FeatureManagerClient) private client: FeatureManagerClient) {}

      async canActivate(ctx: ExecutionContext): Promise<boolean> {
        const context = await contextProvider(ctx);
        if (!context) return true;  // no context = no company to check against

        const result = await this.client.getFeatureAccess(context);
        if (!result.success)
          throw new DeskbirdHttpException(500, 'internal_error', 'Failed to get feature access');

        const enabled = result.data.features;
        const allowed = conditionType === 'all'
          ? features.every(f => enabled.includes(f))
          : features.some(f => enabled.includes(f));

        if (!allowed) throw new DeskbirdHttpException(403, 'forbidden', 'Feature disabled');
        return true;
      }
    }
    return mixin(RequireFeaturesMixin);
  };

// @CurrentUserTokenData — custom param decorator to extract token data
export const CurrentUserTokenData = createParamDecorator((_, ctx: ExecutionContext): UserTokenData => {
  const request = ctx.switchToHttp().getRequest<FastifyRequest>();
  if (!isRequestWithUserTokenData(request))
    throw new Error('Missing token payload. Did you forget RequireFirebaseToken?');
  return request.userTokenData;
});`

D.serviceClient = `// libs/service-clients/src/serviceClient.class.ts
// Base class for all inter-service HTTP clients.
// Every internal service (bookings, users, offices, etc.) has a concrete client
// that extends this class and adds typed methods (findOne, findMany, create...).

export abstract class ServiceClient {
  protected readonly api: AxiosInstance;

  constructor(options: ServiceClientOptions) {
    const axiosClient = axios.create({
      baseURL: options.baseUrl.replace(/\\/$/, ''),
      timeout: options.timeout ?? 10000,
      headers: { 'User-Agent': \`@deskbird/service-clients/\${version}\` },
    });

    // Automatic retry on network errors and idempotent requests (GET/HEAD/OPTIONS)
    // exponentialDelay: 1s, 2s, 4s — avoids thundering herd on downstream blip
    if (options.retryConfig) {
      axiosRetry(axiosClient, {
        retries: options.retryConfig.retries ?? 2,
        retryDelay: exponentialDelay,
        shouldResetTimeout: true,
        retryCondition: (err) => isNetworkOrIdempotentRequestError(err) || isIdempotentTimeoutError(err),
      });
    }

    // Response interceptor: transform axios errors into typed ServiceError
    // so callers can switch on errorCode rather than parsing arbitrary HTTP bodies
    axiosClient.interceptors.response.use(
      response => response,
      error => {
        if (isAxiosError(error) && error.response?.data?.errorCode) {
          throw new ServiceError(
            error.response.status,
            error.response.data.errorCode,
            error.response.data,
            \`\${error.config?.method?.toUpperCase()} \${error.config?.baseURL}\${error.config?.url}\`,
          );
        }
        throw error;
      },
    );

    // Request interceptor: inject auth + tracing headers on every outgoing request
    // headerFactories are provided by the consuming app:
    //   authorization: () => serviceAccountTokenProvider.getToken(audience)
    //   correlation-id: () => tracingService.getCorrelationId()
    //   traceparent:    () => tracingService.getTraceparent()
    axiosClient.interceptors.request.use(async config => {
      for (const [header, factory] of Object.entries(options.headerFactories)) {
        const value = await factory();
        if (value) config.headers[header] = value;
      }
      return config;
    });

    this.api = axiosClient;
  }

  // Zod validation of responses — enabled in non-prod environments.
  // In prod it falls back to the raw data (avoids breaking on minor schema drift).
  // Parsing errors are reported via onParsingError (Sentry/logging) but not thrown.
  protected parseData<T extends z.ZodTypeAny>(schema: T, data: unknown): z.infer<T> {
    const result = schema.safeParse(data);
    if (!result.success) {
      this.serviceOptions.onParsingError?.(result.error);
      if (this.validateResponses) throw result.error;
      return data as z.infer<T>;  // graceful degradation in prod
    }
    return result.data;
  }
}

// ServiceResult<T, ErrorCode> — typed success/error discriminated union
export type ServiceResult<T, ErrorCode extends string | undefined> =
  | { success: true; data: T }
  | { success: false; error: Error; errorCode?: ErrorCode };

// Example concrete client (BookingsClient):
export class BookingsClient extends ServiceClient {
  async findOne(params: { id: string; companyId: string }): ServiceResultPromise<Booking, 'not_found'> {
    try {
      const { data } = await this.api.get(\`/bookings/\${params.id}\`, { params: { companyId: params.companyId } });
      return { success: true, data: this.parseData(BookingSchema, data) };
    } catch (err) {
      if (err instanceof ServiceError && err.statusCode === 404)
        return { success: false, error: err, errorCode: 'not_found' };
      throw err;
    }
  }
}`

D.errorHandling = `// libs/errors-nestjs/src/deskbirdError.classes.ts
// DeskbirdHttpException is a plain Error subclass — NOT HttpException.
// This keeps domain logic free of HTTP: services throw it, the filter maps to HTTP.
// The errorCode string is a stable contract for API clients
// (they switch on errorCode, not on HTTP status, for localisation).

export class DeskbirdHttpException extends Error {
  constructor(
    readonly status: number,      // HTTP status code
    readonly errorCode: string,   // stable machine-readable code: 'tokenExpired', 'user_not_found'
    message: string,              // human-readable, may be shown to developer
    readonly cause?: unknown,     // original error for server-side logging only
    readonly details?: unknown,   // extra context (validation errors, field names)
  ) {
    super(message);
  }
}

// libs/errors-nestjs/src/deskbirdError.exceptionfilter.ts
// Extends BaseExceptionFilter (not implements ExceptionFilter).
// BaseExceptionFilter handles the actual HTTP response writing;
// we intercept, reformat, then delegate to super.catch().
export class DeskbirdExceptionFilter extends BaseExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    // Our own exceptions: use errorCode + status directly
    if (exception instanceof DeskbirdHttpException) {
      return this.formatException(
        { statusCode: exception.status, errorCode: exception.errorCode,
          message: exception.message, details: exception.details },
        host,
      );
    }

    // NestJS built-in exceptions: normalize to our error shape
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      if (status === 400) {
        // ValidationPipe throws BadRequestException with array of messages in body.message
        const response = exception.getResponse();
        return this.formatException({
          statusCode: 400, errorCode: 'badRequest', message: 'Bad Request',
          details: typeof response === 'object' && 'message' in response ? response.message : response,
        }, host);
      }
      if (status === 404) return this.formatException({ statusCode: 404, errorCode: 'notFound', message: 'Resource not found' }, host);
      if (status === 429) return this.formatException({ statusCode: 429, errorCode: 'tooManyRequests', message: 'Too many requests' }, host);
    }

    // Unhandled: log server-side, return generic 500 — never leak internals
    this.logger.error('unhandled error', exception);
    return this.formatException({ statusCode: 500, errorCode: 'internalServerError', message: 'Sorry, an unexpected error occurred.' }, host);
  }

  // Wire it up globally in main.ts:
  // app.useGlobalFilters(new DeskbirdExceptionFilter(app.get(HttpAdapterHost).httpAdapter));
  // Or via DeskbirdErrorModule.forRoot() which registers it as APP_FILTER
}`

D.bookingsController = `// src/features/bookings/apis/rest/controllers/bookings.controller.ts
// Public API controller for desk bookings.
// Auth flow: RequirePublicApiToken verifies the API key (not Firebase JWT),
// then RequireFeatures checks the company has PUBLIC_API enabled.
// The feature gate prevents upselling bypass — customers must subscribe to get API access.

@ApiTags('Bookings')
@ApiKeyAuthorizationHeader          // Swagger: shows API key auth header in docs
@Controller([
  \`\${LEGACY_PATH_PREFIX}/bookings\`, // /v1/bookings  (kept for backwards compat)
  '/bookings',                       // /bookings     (new path)
])
@UseGuards(
  RequirePublicApiToken,
  RequireFeatures('PUBLIC_API', 'RESOURCE_BOOKING_PUBLIC_API'), // both flags required
)
export class BookingsController {
  @Get()
  public async getBookings(
    @Query() { startDate, endDate, ids, officeIds, statuses, limit, offset }: GetBookingsQuery,
    @CurrentPublicApiUser() { companyUuid }: PublicApiUser,  // extracted from verified token
  ): Promise<PaginatedBookingResponse> {
    return this.getBookingsService.getBookings({
      companyId: companyUuid,
      startDate, endDate,
      ids: ids?.split(','),
      officeIds: officeIds?.split(','),
      statuses: statuses?.split(',') as BookingStatus[],
      limit, offset,
    });
  }

  @Post()
  @HttpCode(200)
  public async createBooking(
    @Body() dto: CreateBookingDto,
    @CurrentApiTokenCreatedById() createdBy: string,  // creator from token claims
    @CurrentPublicApiUser() { companyId }: PublicApiUser,
  ): Promise<BookingResponse> {
    const bookingModel = createBookingMapper(dto);
    const [result] = await this.bookingActions.createBookings({
      bookings: [bookingModel], creatorId: createdBy, companyId,
    });

    // createBookings returns a discriminated union per booking
    if (!result.success)
      throw new DeskbirdHttpException(result.error.statusCode, result.error.errorCode, result.error.message);

    return result.booking;
  }

  @Patch('/:bookingId/cancel')
  @HttpCode(204)  // 204 No Content: successful mutation with no response body
  public async cancel(
    @Param(ValidationPipe) { bookingId }: GetSingleBookingQuery,
    @CurrentApiTokenCreatedById() createdBy: string,
  ): Promise<void> {
    await this.bookingActions.cancelBooking(bookingId, createdBy);
  }

  @Patch('/:bookingId/checkIn')
  @HttpCode(204)
  public async checkIn(
    @Param(ValidationPipe) { bookingId }: GetSingleBookingQuery,
    @Body() { resourceId }: CheckInDto,
    @CurrentApiTokenCreatedById() createdBy: string,
  ): Promise<void> {
    await this.bookingActions.checkIn(bookingId, resourceId, createdBy);
  }
}

// BookingActionsService — orchestrates multiple service clients
// It fan-outs to Bookings, Users, Guests, Resources, Offices clients in parallel
// after creating bookings, to assemble the full response object.
@Injectable()
export class BookingActionsService {
  constructor(
    private bookingsClient: BookingsClient,
    private guestsClient: GuestsClient,
    private usersClient: UsersClient,
    private resourcesClient: ResourcesClient,
    private officesClient: OfficesClient,
  ) {}

  async createBookings({ bookings, creatorId, companyId }) {
    const results = await this.bookingsClient.createBookings(bookings, { userUuid: creatorId })
      .then(result => unwrapOrThrowMapped(result, (code) => {
        // Map domain error codes to HTTP exceptions
        switch (code) {
          case 'anonymousBookingNotAllowed': throw new DeskbirdHttpException(403, 'forbidden', 'Anonymous booking not allowed');
          case 'deskAlreadyOccupied':        throw new DeskbirdHttpException(400, 'badRequest', 'Desk already occupied');
          case 'officeClosed':               throw new DeskbirdHttpException(403, 'forbidden', 'Office closed');
        }
      }));

    // Parallel fan-out to enrich booking with related entities
    const createdBookings = results.filter(b => b.success).map(b => b.booking);
    const [guests, users, resources, offices] = await Promise.all([
      this.getGuests(uniq(compact(createdBookings.map(b => b.guestId)))),
      this.getUsers(uniq(compact(createdBookings.map(b => b.userId)))),
      this.getResources(uniq(compact(createdBookings.map(b => b.resourceId)))),
      this.getOffices(companyId, createdBookings.map(b => b.officeId)),
    ]);

    const mapper = bookingMapper(
      new Map(guests.map(g => [g.id, g])),
      new Map(users.map(u => [u.id, u])),
      new Map(resources.map(r => [r.id, r])),
      new Map(offices.map(o => [o.id, o])),
    );

    return results.map(r => r.success
      ? { success: true, booking: mapper(r.booking) }
      : { success: false, error: mapBookingError(r.error) }
    );
  }
}`

D.tracing = `// libs/tracing-nestjs/src/tracing.middleware.ts
// Two tracing primitives — middleware for HTTP, interceptor for Pub/Sub.
//
// TracingMiddleware runs on every HTTP request.
// It sets correlation-id and traceparent in AsyncLocalStorage (via TracingService).
// All downstream service clients read these via tracingService.getCorrelationId()
// and inject them into outgoing request headers — enabling cross-service trace linkage.

@Injectable()
export class TracingMiddleware implements NestMiddleware {
  constructor(private tracingService: TracingService) {}

  use(req: FastifyRequest['raw'], _res: FastifyReply['raw'], next: () => void) {
    return this.tracingService.runWithTracingInformation(
      {
        // Accept correlation-id from the caller (frontend/CDN) or generate a new one
        correlationId: () => getHeader(req, 'correlation-id') || getHeader(req, 'x-transaction-id'),
        // W3C traceparent: 00-<trace-id>-<parent-id>-<flags>
        traceparent: () => getHeader(req, 'traceparent'),
        requestRoute: () => \`\${req.method} \${req.url}\`,
      },
      () => next(),  // executes the rest of the request within the tracing context
    );
  }
}

// TracingInterceptor — for Pub/Sub message handlers (NestJS controllers receiving POST)
// When GCP Pub/Sub delivers a message to an HTTP endpoint, the original traceparent
// is in the message attributes, not in HTTP headers.
// This interceptor reads from req.body.message.attributes for Pub/Sub payloads.
@Injectable()
export class TracingInterceptor implements NestInterceptor {
  constructor(private tracingService: TracingService) {}

  intercept(context: ExecutionContext, next: CallHandler) {
    const req = context.switchToHttp().getRequest<FastifyRequest>();

    if (isPubSubMessageWithAttributes(req.body)) {
      // Override the HTTP-header-based tracing set by middleware
      // with the tracing context from inside the Pub/Sub message
      this.tracingService.setTracing({
        correlationId: req.body.message.attributes['correlation-id'],
        traceparent: req.body.message.attributes.traceparent,
      });
    }

    return next.handle();
  }
}

// Wire up in AppModule:
// export class AppModule implements NestModule {
//   configure(consumer: MiddlewareConsumer) {
//     consumer.apply(TracingMiddleware).forRoutes('*');
//   }
// }
// And in the controller for Pub/Sub endpoints:
// @UseInterceptors(TracingInterceptor)`

D.rateLimiting = `// src/shared/guards/tokenRateLimiter.guard.ts
// Token-based rate limiting (not IP-based).
// IP-based limits fail on shared NAT (office building: 500 users, same IP).
// Token-based: each API key gets its own rate limit bucket.

@Injectable()
export class TokenRateLimiterGuard extends RateLimiterGuard {
  constructor(
    @Inject('RATE_LIMITER_OPTIONS') options: RateLimiterOptions,
    reflector: Reflector,
    private jwtService: JwtService,
  ) {
    super(options, reflector);
  }

  // Override getIpFromRequest() — the base class calls this to get the bucket key
  protected getIpFromRequest(request: FastifyRequest): string {
    const identifier = this.extractRequestIdentifier(request);
    if (!identifier) throw DeskbirdInvalidApiKeyTokenError;
    // SHA-256 hash: stable, unique per token, doesn't store the raw token in Redis
    return createHash('sha256').update(identifier).digest('hex');
  }

  private extractRequestIdentifier(request: FastifyRequest): string | undefined {
    const authorization = request.headers['authorization'];
    if (!authorization) return undefined;
    const token = authorization.trim().replace(/^(Bearer|ApiKey)\\s+/i, '');
    const decoded = this.jwtService.decode(token);
    // sub = IAM service account UUID; keyId = legacy API key identifier
    return decoded?.sub || decoded?.keyId;
  }
}

// Config (from config.schema.ts, validated with Zod at startup):
// RATE_LIMIT_DURATION_SECONDS: 1       // 1-second sliding window
// RATE_LIMIT_POINTS: 10                // 10 requests per second per token
// EXEC_EVENLY_MIN_DELAY_MS: 50         // smooth bursty traffic over the window
// REDIS_HOST/PORT/PASSWORD: string     // rate limit state stored in Redis
//
// Applied as a global guard in SharedModule, wrapping all public API routes.`

D.configSchema = `// src/config/config.schema.ts — Zod schema for environment validation
// Zod's .transform() on the main object lets you derive computed values
// (DESKBIRD_AUDIENCE) from validated fields at startup, not at use time.

export const appEnvSchema = z
  .object({
    GCP_PROJECT_ID:                 z.string(),
    DESKBIRD_API_BASE_URL:          z.string(),
    FEATURE_MANAGER_BASE_URL:       z.string(),
    GENERIC_BOOKINGS_SERVICE_URL:   z.string(),
    PUBLIC_API_KEY_GENERATION_SECRET: z.string(),
    PORT:                           z.coerce.number().default(3000),
    LOG_LEVEL:                      z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    NUMERIC_PROJECT_ID:             z.coerce.number().optional(),
    FAKE_SERVICE_ACCOUNT_TOKENS:    z.enum(['true', 'false']).transform(v => v === 'true').default('false'),
    IAM_SERVICE_URL:                z.string(),
    IAM_SIGNING_KEY_PUBLIC_KEY:     z.string(),
    RATE_LIMIT_DURATION_SECONDS:    z.coerce.number().int().min(1).default(1),
    RATE_LIMIT_POINTS:              z.coerce.number().int().min(1).default(10),
    REDIS_HOST:                     z.string(),
    REDIS_PORT:                     z.coerce.number().default(6378),
    REDIS_PASSWORD:                 z.string().optional(),
  })
  // Derived value: computed once from validated fields, used everywhere
  .transform(data => ({ ...data, DESKBIRD_AUDIENCE: \`deskbird-api.\${data.GCP_PROJECT_ID}\` }));

// Config module wraps this in NestJS ConfigModule:
// src/config/config.module.ts
@Module({
  imports: [
    NestConfigModule.forRoot({
      validate: (config) => {
        const result = appEnvSchema.safeParse(config);
        if (!result.success) {
          // Crash at startup with a clear error listing all missing/invalid env vars.
          // "Missing REDIS_HOST" is 10× easier to debug than a connection error at 3am.
          console.error('Invalid environment config:', result.error.format());
          process.exit(1);
        }
        return result.data;
      },
      isGlobal: true,
    }),
  ],
  providers: [ConfigService],
  exports: [ConfigService],
})
export class ConfigModule {
  static forRoot() { return { module: ConfigModule }; }
}`

export const deskbirdChapters = [
  {
    id: 'deskbird-intro',
    title: 'Architecture Overview',
    subtitle: 'How the system is structured and why it was built that way',
    tag: { label: 'Intro', color: '#58a6ff', bg: '#0d1f33' },
    description: 'deskbird is a B2B SaaS desk booking platform used by enterprise companies to manage hybrid work. Employees book desks, parking spots, and meeting rooms. The backend is a set of NestJS microservices running on GCP Cloud Run, backed by a shared internal library monorepo that standardises auth, error handling, tracing, and inter-service communication across every service.',
    sections: [
      {
        title: 'System Architecture',
        callouts: [
          {
            type: 'insight', icon: '🏗️', title: 'Many small NestJS services, one shared library monorepo',
            body: 'Each domain (bookings, users, offices, resources, rooms, floors, IAM, feature-manager, notifications...) is a separate NestJS service deployed independently on GCP Cloud Run. They share behaviour through @deskbird/* npm packages published from a separate monorepo (deskbird-libs). This means auth logic, error shapes, tracing, and service client patterns are written once and versioned — not copy-pasted across 15 repos.',
          },
          {
            type: 'pattern', icon: '🌐', title: 'public-api is the external gateway',
            body: 'The public-api service is the only entry point for external API consumers (enterprise customers integrating via REST). It authenticates API keys, enforces feature flags, and delegates to internal services via HTTP. It never owns any data — it is purely an orchestration layer. Internal services are not publicly reachable.',
          },
          {
            type: 'pattern', icon: '🔀', title: 'Two separate auth systems: Firebase JWT for users, Service Account tokens for services',
            body: 'End users (employees, admins) authenticate with Firebase Auth — the client gets a Firebase JWT and sends it as a Bearer token. Internal service-to-service calls use GCP Service Account tokens (short-lived JWTs signed by Google). The ServiceAccountTokenProvider fetches and caches these tokens. The two flows never mix: user-facing endpoints use RequireFirebaseToken, internal endpoints use RequireGcpServiceAccountToken.',
          },
        ],
      },
      {
        title: 'Key Architectural Decisions',
        callouts: [
          {
            type: 'insight', icon: '📡', title: 'HTTP (Axios) for all inter-service communication — no gRPC',
            body: 'All sync calls between services go over plain HTTP using the ServiceClient base class. This was chosen for operational simplicity: no protobuf schemas to maintain, no gRPC server setup per service, easier local development and debugging with curl/Postman. The trade-off is slightly higher latency and larger payloads compared to gRPC, acceptable for a desk-booking workload that is not latency-critical.',
          },
          {
            type: 'pattern', icon: '📨', title: 'GCP Pub/Sub for async events — not Kafka',
            body: 'Async domain events (booking created, user updated, office changed) are published via GCP Pub/Sub. Since the entire stack runs on GCP, Pub/Sub is the natural choice — no separate Kafka cluster to operate. Pub/Sub messages are delivered to NestJS HTTP endpoints (push subscriptions) rather than a consumer loop, which fits Cloud Run\'s request-driven scaling model.',
          },
          {
            type: 'tip', icon: '⚡', title: 'Fastify over Express — HTTP/2 on Cloud Run',
            body: 'Every NestJS service uses the Fastify adapter instead of Express. Fastify is roughly 2× faster at raw HTTP throughput, which reduces Cloud Run CPU time and therefore cost at scale. On Cloud Run, HTTP/2 is enabled in production (isCloudExecution() check) for header compression and request multiplexing — relevant when a single user action triggers several internal service calls.',
          },
          {
            type: 'insight', icon: '🚦', title: 'Feature flags as business gates, not just kill-switches',
            body: 'The FeatureManagerClient is called on nearly every public endpoint via RequireFeatures guards. Flags like PUBLIC_API, SCIM, RESOURCE_BOOKING_PUBLIC_API are not deployment toggles — they are the upselling mechanism. A company on the basic plan hits a 403 on API endpoints until they upgrade. This means the feature flag system is part of the billing model, not just an ops tool.',
          },
          {
            type: 'pattern', icon: '✅', title: 'Zod everywhere — config validation, response validation, token parsing',
            body: 'Zod is used in three distinct places: (1) config.schema.ts validates all env vars at startup and crashes the process if anything is wrong; (2) ServiceClient.parseData() validates responses from downstream services to catch schema drift early; (3) UserTokenDataSchema in RequireFirebaseToken parses and transforms the JWT payload, converting snake_case fields and validating email format. class-validator is only used for incoming request DTOs via ValidationPipe.',
          },
          {
            type: 'critical', icon: '🔒', title: 'Stable errorCode strings are the real API contract',
            body: 'Every error response has a machine-readable errorCode string: "tokenExpired", "user_not_found", "forbidden". Enterprise API consumers switch on errorCode in their integration code. HTTP status codes are secondary and can be adjusted; errorCode strings are frozen once released. This was a deliberate design decision to make the API resilient to HTTP semantics debates (is "booking not found" a 404 or 422?).',
          },
        ],
      },
      {
        title: 'How a Request Flows Through the System',
        callouts: [
          {
            type: 'pattern', icon: '➡️', title: 'Typical public API request lifecycle',
            body: '1. Client sends Bearer token (API key JWT) to public-api\n2. TokenRateLimiterGuard checks the per-token rate limit bucket in Redis\n3. RequirePublicApiToken verifies the JWT and calls IAM service to confirm the service account is active\n4. RequireFeatures calls FeatureManager to check the company has the required feature flags\n5. Controller handler runs — calls one or more internal services via ServiceClient (HTTP + SA token)\n6. ServiceClient injects correlation-id and traceparent headers on every outgoing call\n7. Response is assembled (possibly with Promise.all fan-out to multiple services) and returned\n8. DeskbirdExceptionFilter catches any DeskbirdHttpException and formats { statusCode, errorCode, message }',
          },
          {
            type: 'insight', icon: '🔍', title: 'Tracing connects the whole chain',
            body: 'Every inbound HTTP request passes through TracingMiddleware, which reads (or generates) a correlation-id and W3C traceparent and stores them in AsyncLocalStorage via TracingService. Every outgoing ServiceClient call reads from that AsyncLocalStorage and injects the same headers. This means a single user action produces a linked trace across public-api → bookings-service → users-service → offices-service, all correlated by the same correlation-id in GCP Cloud Trace.',
          },
        ],
      },
      {
        title: 'The Shared Library Monorepo (deskbird-libs)',
        description: 'deskbird-libs is an npm workspaces monorepo that publishes @deskbird/* packages consumed by every NestJS service. The idea is simple: any code that would otherwise be copy-pasted across services lives in a lib instead. Each lib is a focused NestJS module — it exports providers, guards, or utilities and nothing else.',
        callouts: [
          {
            type: 'pattern', icon: '📦', title: 'What lives in libs vs what lives in each service',
            body: 'libs owns: how to verify a Firebase token, what an error response looks like, how to propagate a trace, how to call another service. Each service owns: its own domain logic, its own controllers and DTOs, its own config schema. The boundary is deliberate — libs never imports from a specific service, services always import from libs.',
          },
          {
            type: 'insight', icon: '🔄', title: 'Versioned and published — not a symlink or path alias',
            body: 'Each lib is a proper npm package with its own package.json and version number. Services depend on @deskbird/auth-nestjs@1.2.3 in their package.json. When a lib changes, it gets a new version, and each service opts in by bumping the version. This means a breaking change in a lib does not silently affect all services — services upgrade on their own schedule.',
          },
        ],
      },
      {
        title: '@deskbird/auth-nestjs',
        description: 'Handles Firebase JWT verification. Consuming a service calls DeskbirdAuthModule.forRootAsync() once in AppModule and gets AuthVerifier injected anywhere it is needed.',
        callouts: [
          {
            type: 'pattern', icon: '🔑', title: 'What it provides',
            body: 'AuthVerifier — the @Injectable() service that verifies a token string and returns the decoded payload. CertificateProvider — fetches and caches Google\'s public X.509 certificates (two issuers: Firebase Auth and Google SA). CertificateRenewalService — a @Cron job that refreshes certs before they expire based on the Cache-Control max-age from Google\'s API. The module is @Global() so AuthVerifier is available everywhere after one import.',
          },
          {
            type: 'insight', icon: '⚙️', title: 'How a service wires it in',
            body: 'AppModule imports DeskbirdAuthModule.forRootAsync({ useClass: DeskbirdAuthOptionsFactory }). The factory class gets ConfigService injected and returns { gcpProjectId }. The module uses ConfigurableModuleBuilder so the forRootAsync pattern is generated automatically — the lib author does not write boilerplate async factory handling by hand.',
          },
          {
            type: 'tip', icon: '🌐', title: 'GCP Metadata endpoint for numeric project ID',
            body: 'Firebase requires the numeric GCP project ID to validate token audience. If not set as NUMERIC_PROJECT_ID env var, the module fetches it at startup from the GCP metadata server (http://metadata.google.internal) — only reachable on GCP. Locally, the env var must be set. This self-configuration pattern means Cloud Run services need zero Firebase-specific env vars.',
          },
        ],
      },
      {
        title: '@deskbird/guards-nestjs',
        description: 'Provides the four guard classes and two param decorators used across all NestJS services. Guards are applied via @UseGuards() on controllers or routes.',
        callouts: [
          {
            type: 'pattern', icon: '🛡️', title: 'RequireFirebaseToken',
            body: 'Reads the Authorization header, calls AuthVerifier.verify(), then parses the payload with UserTokenDataSchema (Zod). Zod transforms the raw JWT payload: renames email_verified→emailVerified, sub→firebaseId, validates email format, checks isDeskbirdAdmin from the group claim. The parsed data is attached to request.userTokenData. Exports CurrentUserTokenData param decorator that reads it back in controller methods.',
          },
          {
            type: 'pattern', icon: '👤', title: 'RequireUser',
            body: 'Reads request.userTokenData (set by RequireFirebaseToken), calls UsersClient.findOne({ id: firebaseId }) to fetch the full user record from the Users service, and attaches it as request.user. Must run after RequireFirebaseToken. Exports CurrentUser param decorator. The separation exists because many endpoints only need the token (no DB hit) while others need the full user object.',
          },
          {
            type: 'pattern', icon: '🔐', title: 'RequireUserRole and RequireFeatures',
            body: 'Both use the mixin() pattern to create parameterised guard classes. RequireUserRole({ oneOf: ["admin"] }) creates a distinct injectable class with the role list baked in. RequireFeatures is a higher-order function: RequireFeatures(contextProvider)("all", "PUBLIC_API") — the contextProvider is passed at the call site so the guard knows which company/user to check features for. mixin() is required because NestJS DI treats each class as a unique injectable; without it, two calls with different params would resolve to the same instance.',
          },
          {
            type: 'tip', icon: '🔗', title: 'How guards compose in practice',
            body: '@UseGuards(RequireFirebaseToken, RequireUser, RequireUserRole({ oneOf: ["admin"] })) — they run left to right. Each guard trusts that the previous one already ran. RequireUserRole does not re-verify the token; it just reads request.user.role. If you apply RequireUserRole without RequireUser, it throws a developer error at runtime ("Did you forget RequireUser?") rather than silently passing.',
          },
        ],
      },
      {
        title: '@deskbird/errors-nestjs',
        description: 'Defines the error class and exception filter used by every service. Consuming a service imports DeskbirdErrorModule.forRoot() which registers DeskbirdExceptionFilter as a global APP_FILTER.',
        callouts: [
          {
            type: 'pattern', icon: '🏛️', title: 'DeskbirdHttpException — plain Error, not HttpException',
            body: 'Extends Error directly, not NestJS HttpException. It carries status (number), errorCode (string), message, optional cause, and optional details. Domain code throws it without knowing about HTTP — the filter decides the response shape. This keeps services transport-agnostic: the same exception can be thrown in an HTTP handler or a Pub/Sub handler.',
          },
          {
            type: 'insight', icon: '🔧', title: 'DeskbirdExceptionFilter extends BaseExceptionFilter',
            body: 'Extends BaseExceptionFilter instead of implementing ExceptionFilter from scratch. This lets the filter intercept, reformat the exception as a new HttpException with the deskbird shape { statusCode, errorCode, message, details }, and then call super.catch() to delegate the actual HTTP response writing to NestJS. It also handles NestJS built-ins: 400 BadRequest extracts the validation error array from body.message; 404 and 429 are normalized to deskbird error codes.',
          },
        ],
      },
      {
        title: '@deskbird/service-clients',
        description: 'The largest lib — contains the abstract ServiceClient base class and one concrete client class per internal service (BookingsClient, UsersClient, OfficesClient, ResourcesClient, IamClient, FeatureManagerClient, and ~15 more).',
        callouts: [
          {
            type: 'pattern', icon: '🔌', title: 'ServiceClient base class',
            body: 'Abstract class that creates and configures an AxiosInstance. Subclasses call super(options) in their constructor and get: automatic auth header injection (via headerFactories.authorization factory), correlation-id and traceparent propagation (via headerFactories), axios-retry with exponential backoff, and response error normalization into typed ServiceError. Subclasses only implement typed methods like findOne(), findMany(), create() on top of this.api.',
          },
          {
            type: 'insight', icon: '📋', title: 'ServiceResult<T, ErrorCode> return type',
            body: 'Client methods return ServiceResult<T, ErrorCode> = { success: true, data: T } | { success: false, error, errorCode }. The ErrorCode generic is a string literal union of expected error codes for that operation ("not_found" | "forbidden" | ...). Callers can use unwrapOrThrow() to throw on failure, or unwrapOrThrowMapped() to map specific error codes to different DeskbirdHttpExceptions before bubbling up.',
          },
          {
            type: 'tip', icon: '✅', title: 'Zod response validation — strict in dev, lenient in prod',
            body: 'Every client method calls this.parseData(SomeZodSchema, responseData). In non-production environments validation throws on schema mismatch — catches drift between services early in CI. In production it falls back to the raw data and reports the error via onParsingError (Sentry) without crashing. This gives strong guarantees in dev without risking a prod incident over an added field.',
          },
          {
            type: 'pattern', icon: '💉', title: 'How services register clients',
            body: 'SharedModule in public-api registers all client instances as providers, injecting ConfigService and TracingService. Each client provider uses useFactory: (cfg, tracing) => new BookingsClient({ baseUrl: cfg.get("DESKBIRD_API_BASE_URL"), headerFactories: { authorization: () => tokenProvider.getToken(audience), "correlation-id": () => tracing.getCorrelationId() } }). SharedModule exports them all so any feature module can inject BookingsClient directly.',
          },
        ],
      },
      {
        title: '@deskbird/tracing-nestjs',
        description: 'Two classes: TracingMiddleware for HTTP requests and TracingInterceptor for Pub/Sub message handlers. Both read tracing context from different places and store it in AsyncLocalStorage via TracingService.',
        callouts: [
          {
            type: 'pattern', icon: '🔍', title: 'Middleware vs Interceptor — why both are needed',
            body: 'HTTP requests carry traceparent in headers — middleware reads them before the request hits any guard or handler. Pub/Sub messages arrive via HTTP POST but their tracing context is inside req.body.message.attributes, not in HTTP headers. The interceptor detects the Pub/Sub shape (isPubSubMessageWithAttributes check) and overrides the tracing context from the message body. Without the interceptor, Pub/Sub handlers would create orphaned traces with no parent.',
          },
          {
            type: 'insight', icon: '📡', title: 'AsyncLocalStorage — zero-overhead context propagation',
            body: 'TracingService wraps Node.js AsyncLocalStorage. runWithTracingInformation() sets correlationId and traceparent for the current async chain. Any code downstream — guards, services, ServiceClient request interceptors — can call tracingService.getCorrelationId() with no parameter threading. This is how a correlation ID set by TracingMiddleware on the inbound request ends up in the headers of every outgoing Axios call made during that request.',
          },
        ],
      },
      {
        title: '@deskbird/pubsub-nestjs and @deskbird/rest-nestjs',
        callouts: [
          {
            type: 'pattern', icon: '📨', title: '@deskbird/pubsub-nestjs — DeskbirdPubSubModule',
            body: 'A thin wrapper around DeskbirdPubSubClient (from the non-NestJS @deskbird/pubsub package). DeskbirdPubSubModule.forRoot() registers the client as a global provider, injecting TracingService optionally — if tracing is wired up, the client automatically attaches correlation-id and traceparent as Pub/Sub message attributes. PubSubMessagePipe is a NestJS pipe that validates incoming Pub/Sub push webhook payloads with Zod before they reach the controller.',
          },
          {
            type: 'pattern', icon: '🔒', title: '@deskbird/rest-nestjs — configureApp() and CORS',
            body: 'Exports one function: configureApp(app). It registers fastify-helmet (security headers), adds an onRequest hook for X-Robots-Tag: noindex, and enables CORS with a regex allowlist for *.deskbird.app and *.deskbird.com plus any custom domains from the CUSTOM_DOMAINS env var. Every service calls this in its bootstrap function — guaranteeing the same security baseline without per-service configuration.',
          },
        ],
      },
    ],
  },

  {
    id: 'deskbird-public-api-deep-dive',
    title: 'Public API — Deep Dive',
    subtitle: 'Module structure, auth, SharedModule, controllers, service layer, API key management',
    tag: { label: 'Public API', color: '#3fb950', bg: '#0d1f14' },
    description: 'The public-api service is the external gateway for enterprise customers. It exposes a REST API secured by API keys, enforces feature flags, and orchestrates calls to 10+ internal services. This chapter walks through every layer — from how the app is composed in AppModule down to how individual service methods fan out to multiple downstream clients.',
    sections: [
      {
        title: 'Module Composition',
        description: 'AppModule wires together lib modules (auth, logging, tracing, errors) and feature modules (one per domain entity). SharedModule is the backbone — it instantiates all service client providers and registers the global rate-limiting guard.',
        callouts: [
          {
            type: 'pattern', icon: '🧩', title: 'AppModule: lib modules imported once, feature modules per domain',
            body: 'DeskbirdAuthModule, DeskbirdLoggingModule, TracingModule, DeskbirdErrorModule, ServiceAccountTokenProviderModule are all imported once with forRootAsync — each reads config from ConfigService via a small local factory class. Feature modules (BookingsModule, KeysModule, UsersModule, etc.) are pure domain slices: they import SharedModule to get service clients, declare their own controllers and providers, and export nothing. The boundary is clean: SharedModule provides infrastructure, feature modules provide domain logic.',
          },
          {
            type: 'insight', icon: '💉', title: 'Global ValidationPipe registered as APP_PIPE',
            body: 'Instead of calling app.useGlobalPipes() in main.ts, ValidationPipe is registered as { provide: APP_PIPE, useFactory: () => new ValidationPipe({ transform: true }) } in AppModule.providers. The transform: true option makes NestJS coerce query string values ("?limit=10") to their declared TypeScript types (number) automatically. APP_PIPE guarantees it applies to all routes including those in lazy-loaded modules.',
          },
        ],
        files: [{
          filename: 'app.module.ts (annotated)',
          lang: 'typescript',
          code: `// app.module.ts — full wiring diagram
@Module({
  imports: [
    ConfigModule.forRoot(),   // Zod schema, crashes on bad env at startup

    SharedModule,             // ALL service clients + global rate limit guard (see below)

    // Each lib module uses a local factory class to read its config from ConfigService.
    // This avoids hardcoding config keys in AppModule — each factory knows its own needs.
    DeskbirdAuthModule.forRootAsync({ useClass: DeskbirdAuthOptionsFactory }),
    DeskbirdLoggingModule.forRootAsync({ useClass: DeskbirdLoggingOptionsFactory }),
    TracingModule.forRoot(),
    DeskbirdErrorModule.forRoot(),      // registers DeskbirdExceptionFilter as APP_FILTER
    ServiceAccountTokenProviderModule.forRootAsync({ useClass: ServiceAccountTokenProviderModuleFactory }),

    JwtModule.register({ global: true }),  // used by PublicApiTokenVerifier + TokenRateLimiterGuard

    // Feature modules — each is an isolated domain slice
    UsersModule, BookingsModule, OfficesModule, KeysModule,
    GroupsModule, ResourcesModule, ImportModule, SchedulingModule,
    RoomsModule, FloorsModule, ZonesModule,
  ],
  providers: [
    { provide: APP_PIPE, useFactory: () => new ValidationPipe({ transform: true }) },
  ],
})
export class AppModule {}

// Local factory classes — each is @Injectable() and gets ConfigService from DI
@Injectable()
class DeskbirdAuthOptionsFactory {
  constructor(private configService: ConfigService) {}
  create(): MinimalDeskbirdAuthModuleOptions {
    return { gcpProjectId: this.configService.get('GCP_PROJECT_ID') };
  }
}

@Injectable()
class ServiceAccountTokenProviderModuleFactory {
  constructor(private configService: ConfigService) {}
  create() {
    return {
      // All audiences this service ever calls — SA token provider pre-fetches tokens for these
      audiences: [
        this.configService.get('DESKBIRD_API_BASE_URL'),
        \`internal.\${this.configService.get('GCP_PROJECT_ID')}\`,
        this.configService.get('FEATURE_MANAGER_BASE_URL'),
        this.configService.get('IAM_SERVICE_URL'),
        this.configService.get('GENERIC_BOOKINGS_SERVICE_URL'),
      ],
      fakeSaTokens: this.configService.get('FAKE_SERVICE_ACCOUNT_TOKENS'), // true in local dev
    };
  }
}`,
        }],
      },
      {
        title: 'SharedModule — Service Client Factory Pattern',
        description: 'SharedModule is the most complex module in the app. It registers every service client as a provider using a factory pattern that avoids duplicating the auth/tracing header setup for each client.',
        callouts: [
          {
            type: 'pattern', icon: '🏭', title: 'SERVICE_CLIENT_OPTIONS_FACTORY_TOKEN — shared factory',
            body: 'Instead of repeating the headerFactories config for each of the 12 clients, SharedModule registers one factory provider under a Symbol token. This factory is a closure: (audience: string) => ServiceClientOptions. Each client provider then calls serviceClientOptionsFactory(audience) to get its options, passing only the specific audience URL it needs. The auth header, tracing headers, and onParsingError callback are shared — defined once.',
          },
          {
            type: 'insight', icon: '🔑', title: 'Service account token per audience',
            body: 'serviceAccountTokenProvider.getToken(audience) fetches a GCP Service Account token scoped to a specific audience (the target service URL). Each internal service validates that the token audience matches its own URL — this prevents a token issued to call the bookings service from being used to call the IAM service. The token provider caches tokens and refreshes them before expiry.',
          },
          {
            type: 'critical', icon: '⚠️', title: 'Global rate limit guard registered in SharedModule',
            body: 'SharedModule registers { provide: APP_GUARD, useClass: TokenRateLimiterGuard } — making it a global guard that runs on every request without needing @UseGuards() on each controller. This is intentional: rate limiting must be impossible to forget on new controllers. TokenRateLimiterGuard uses Redis (via the RedisModule also imported in SharedModule) with per-token buckets.',
          },
        ],
        files: [{
          filename: 'shared.module.ts (annotated)',
          lang: 'typescript',
          code: `// shared.module.ts — central service client wiring
const SERVICE_CLIENT_OPTIONS_FACTORY_TOKEN = Symbol.for('ServiceClientOptions');

// One provider that builds the reusable options factory closure
{
  provide: SERVICE_CLIENT_OPTIONS_FACTORY_TOKEN,
  useFactory: (tracingService, serviceAccountTokenProvider, logger) => {
    // Returns a FUNCTION — not an object — so each client calls it with its own audience
    return (audience: string) => ({
      headerFactories: {
        authorization: async () =>
          \`Bearer \${await serviceAccountTokenProvider.getToken(audience)}\`,
        [TRACEPARENT_KEY]:   () => tracingService.getTraceparent(),
        [CORRELATION_ID_KEY]: () => tracingService.getCorrelationId(),
      },
      onParsingError: (error) => logger.warn('failure in response parsing', { error }),
    });
  },
  inject: [TracingService, ServiceAccountTokenProvider, DeskbirdLoggerService],
},

// Each client provider calls the factory with its own audience URL
{
  provide: BookingsClient,
  useFactory: (factory, config) => new BookingsClient({
    deskbirdApiBaseUrl: config.get('DESKBIRD_API_BASE_URL'),
    ...factory(config.get('DESKBIRD_AUDIENCE')),  // audience = deskbird-api.<projectId>
  }),
  inject: [SERVICE_CLIENT_OPTIONS_FACTORY_TOKEN, ConfigService],
},
{
  provide: IamClient,
  useFactory: (factory, config) => new IamClient({
    iamServiceBaseUrl: config.get('IAM_SERVICE_URL'),
    ...factory(config.get('IAM_SERVICE_URL')),  // audience = IAM service URL itself
  }),
  inject: [SERVICE_CLIENT_OPTIONS_FACTORY_TOKEN, ConfigService],
},
// ... 10 more client providers, all following the same pattern

// Global guard — applied to EVERY route, no @UseGuards() needed
{ provide: APP_GUARD, useClass: TokenRateLimiterGuard },

@Module({
  imports: [ConfigModule, RedisModule, RateLimiterModule.registerAsync({ useClass: DeskbirdRateLimitingOptionsFactory })],
  providers: [...providers, { provide: APP_GUARD, useClass: TokenRateLimiterGuard }],
  exports: providers,  // all clients exported so feature modules can inject them
})
export class SharedModule {}`,
        }],
      },
      {
        title: 'API Key Authentication',
        description: 'Public API consumers authenticate with API keys, not Firebase JWTs. The auth flow involves two token formats (legacy and IAM), Zod schema union parsing, and an IAM service call to verify the service account is still active.',
        callouts: [
          {
            type: 'insight', icon: '🔑', title: 'Two token formats — legacy and IAM — parsed with Zod union',
            body: 'The public API went through a migration: older integrations use legacy tokens (HMAC-signed, payload has keyId), newer ones use IAM service tokens (RSA-signed, payload has sub + iss: "deskbird-iam"). PublicApiTokenSchema is a Zod union: legacyTokenPayloadSchema.or(iamServiceTokenPayloadSchema). Zod tries the first schema, falls through to the second on failure. Both schemas add a payloadType discriminant via .transform() so downstream code can switch on it.',
          },
          {
            type: 'pattern', icon: '🛡️', title: 'RequirePublicApiToken — three steps in canActivate',
            body: '1) PublicApiTokenVerifier.verifyToken() extracts the token from Authorization header, decodes the payload without verifying (to read payloadType), then verifies the signature with the correct key (HMAC secret for legacy, RSA public key for IAM). 2) IamClient.serviceAccounts.verify() checks the service account is active and of type "publicApi" — prevents deleted/suspended keys from working even if the JWT is still valid. 3) Attaches { id, companyId, companyUuid, createdBy } as request.publicApiUser.',
          },
          {
            type: 'tip', icon: '🏗️', title: 'PublicApiTokenVerifier is a plain @Injectable() — not a guard itself',
            body: 'Verification logic lives in PublicApiTokenVerifier so it can be tested independently and reused in multiple guards. The actual guard (RequirePublicApiToken) injects it and calls verifyToken(). This separation follows the single responsibility principle: the verifier knows how to verify a token, the guard knows what to do after verification (attach user to request, call IAM).',
          },
        ],
        files: [{
          filename: 'token auth flow',
          lang: 'typescript',
          code: `// shared/guards/types.ts — two token schemas unified with Zod
const legacyTokenPayloadSchema = z.object({
  companyId: z.string(),
  keyId:     z.string().uuid(),  // service account ID in the old system
  iat:       z.number().int().positive(),
}).transform(data => ({ ...data, payloadType: 'legacy' as const }));

const iamServiceTokenPayloadSchema = z.object({
  type:        z.literal('service_account_key'),
  sub:         z.string().uuid(),  // service account ID in the IAM system
  iss:         z.literal('deskbird-iam'),
  iat:         z.number().int().positive(),
  companyUuid: z.string().uuid(),
}).transform(data => ({ ...data, payloadType: 'iam' as const }));

// Zod tries legacyTokenPayloadSchema first; if it fails, tries iamServiceTokenPayloadSchema
export const PublicApiTokenSchema = legacyTokenPayloadSchema.or(iamServiceTokenPayloadSchema);
export type PublicApiTokenPayload = z.infer<typeof PublicApiTokenSchema>;

// shared/guards/publicApiTokenVerifier.ts
@Injectable()
export class PublicApiTokenVerifier {
  constructor(
    private jwtService: JwtService,
    configService: ConfigService,
  ) {
    this.jwtSecret = configService.get('PUBLIC_API_KEY_GENERATION_SECRET');  // for legacy
    this.iamSigningKeyPublicKey = configService.get('IAM_SIGNING_KEY_PUBLIC_KEY');  // for IAM
  }

  async verifyToken(context: ExecutionContext): Promise<PublicApiTokenPayload> {
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    const token = extractTokenFromRequest(request);  // throws DeskbirdTokenRequiredError if missing

    // Decode WITHOUT verifying first — need payloadType to know which key to use
    const payload = parseTokenPayload(token);  // Zod union parse, throws on invalid shape

    const verificationOptions = payload.payloadType === 'legacy'
      ? { secret: this.jwtSecret }            // HMAC
      : { publicKey: this.iamSigningKeyPublicKey };  // RSA

    const validation = await safeAwait(this.jwtService.verifyAsync(token, verificationOptions));
    if (validation.isError) throw DeskbirdInvalidApiKeyTokenError;

    return payload;
  }
}

// shared/guards/requirePublicApiToken.guard.ts
@Injectable()
export class RequirePublicApiToken implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const token = await this.tokenVerifier.verifyToken(context);

    // Step 2: verify the service account is still active in IAM
    const result = await this.iamClient.serviceAccounts.verify(
      token.payloadType === 'iam' ? token.sub : token.keyId,
      'publicApi',
    );
    if (!result.success || !result.data.verified) throw DeskbirdInvalidApiKeyTokenError;

    const serviceAccount = result.data.serviceAccount;

    // Step 3: attach public API user to request
    const request = context.switchToHttp().getRequest<FastifyRequest>();
    (request as PublicApiRequest).publicApiUser = {
      id:         serviceAccount.id,
      companyId:  serviceAccount.companyId,
      companyUuid: token.payloadType === 'iam'
        ? token.companyUuid                          // already in IAM token payload
        : serviceAccount.claims?.companyUuid,        // legacy: read from SA claims
      createdBy: serviceAccount.createdBy,
    };
    return true;
  }
}`,
        }],
      },
      {
        title: 'Feature Flag Wiring',
        description: 'The public-api wraps the generic RequireFeatures from @deskbird/guards-nestjs with a local context provider that knows how to extract companyUuid from either a public API token or a Firebase JWT.',
        callouts: [
          {
            type: 'pattern', icon: '🚦', title: 'featureAccessContextProvider — the glue between guard and request',
            body: 'RequireFeatures from the guards lib needs a context provider function to know which company to check features for. The public-api provides featureAccessContextProvider which reads companyUuid from request.publicApiUser (public API routes) or request.userTokenData (Firebase JWT routes). This dual-source lookup means the same RequireFeatures wrapper works for both auth flows — the guard does not know or care which auth mechanism was used.',
          },
          {
            type: 'insight', icon: '🔠', title: 'Feature type safety with a local Feature union',
            body: 'The public-api defines type Feature = "PUBLIC_API" | "RESOURCE_BOOKING_PUBLIC_API" | "SCIM" | "WORKFORCE_PUBLIC_API". The local RequireFeatures wrapper accepts ...features: Feature[] — so passing an unknown feature string is a compile-time error. The base lib uses string[], which is more flexible but less safe. The public-api tightens the type to its own known feature set.',
          },
        ],
        files: [{
          filename: 'shared/guards/requireFeatures.guard.ts',
          lang: 'typescript',
          code: `// shared/guards/requireFeatures.guard.ts
// Typed feature enum — only features relevant to the public-api
type Feature = 'PUBLIC_API' | 'RESOURCE_BOOKING_PUBLIC_API' | 'SCIM' | 'WORKFORCE_PUBLIC_API';

// Context provider: reads companyUuid from whichever auth mechanism was used
export const featureAccessContextProvider = async (context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest();

  // publicApiUser is set by RequirePublicApiToken
  // userTokenData is set by RequireFirebaseToken
  // This guard works after either one
  const companyUuid = (request.publicApiUser ?? request.userTokenData)?.companyUuid;

  if (!companyUuid)
    throw new DeskbirdHttpException(401, 'tokenRequired', 'Resource access requires bearer token');

  return { companyUuid };
};

// Local wrappers — pre-bind the context provider and enforce the Feature type
export const RequireFeatures = (...features: Feature[]) =>
  _RequireFeatures(featureAccessContextProvider)('all', ...features);

export const RequireAnyFeatures = (...features: Feature[]) =>
  _RequireFeatures(featureAccessContextProvider)('any', ...features);

// Usage on a controller:
@UseGuards(RequirePublicApiToken, RequireFeatures('PUBLIC_API', 'RESOURCE_BOOKING_PUBLIC_API'))
export class BookingsController { ... }

// RequireAnyFeatures on the keys controller (either PUBLIC_API or SCIM is enough):
@UseGuards(RequireFirebaseToken, RequireUser, RequireUserRole({ oneOf: ['admin'] }), RequireAnyFeatures('PUBLIC_API', 'SCIM'))
export class ApiKeyController { ... }`,
        }],
      },
      {
        title: 'Controller Patterns',
        description: 'Controllers in the public-api follow a consistent pattern: Swagger decorators, guard chain, typed param decorators, and thin handler methods that delegate immediately to a service.',
        callouts: [
          {
            type: 'pattern', icon: '📄', title: 'Swagger decorators as reusable composites',
            body: '@ListBookingsResponse, @ForbiddenResponse, @UnauthorizedResponse are custom decorators defined in swagger/bookings.responses.ts. Each applies a bundle of @ApiResponse() decorators. Reusing these composites across endpoints ensures consistent Swagger docs and avoids repeating the same @ApiResponse(status: 401, ...) on every method. The @ApiOperation({ summary, description }) is unique per endpoint and lives directly on the method.',
          },
          {
            type: 'insight', icon: '🔀', title: 'Dual path prefix — backward compatibility without duplication',
            body: '@Controller([LEGACY_PATH_PREFIX + "/bookings", "/bookings"]) maps two paths to one controller. New clients use /bookings, old integrations keep working via /v1/bookings. The Swagger spec filters out LEGACY_PATH_PREFIX paths at startup so new customers only see the canonical routes in the docs. There is no code duplication — both paths hit the same handler methods.',
          },
          {
            type: 'tip', icon: '🧩', title: 'createParamDecorator for CurrentApiTokenCreatedById',
            body: 'CurrentApiTokenCreatedById is defined inline in bookings.controller.ts with createParamDecorator. It reads the createdBy field from request.publicApiUser (which is the Firebase UID of the user who generated the API key). This is used as the actor when creating/cancelling bookings — so the audit trail records who made the change, not just which company. If createdBy is missing, it throws 401 immediately.',
          },
          {
            type: 'pattern', icon: '📦', title: 'Feature module structure: controller → service, imports SharedModule',
            body: 'BookingsModule imports SharedModule (to get BookingsClient, UsersClient, etc.), declares BookingsController, and provides GetBookingsService + BookingActionsService. The two services are split by read vs write: GetBookingsService handles all read queries, BookingActionsService handles mutations. This keeps each class focused and makes testing easier — GetBookingsService tests never need to mock write operations.',
          },
        ],
        files: [{
          filename: 'controller structure (annotated)',
          lang: 'typescript',
          code: `// features/bookings/bookings.module.ts
@Module({
  imports: [SharedModule],  // gets BookingsClient, UsersClient, GuestsClient, ResourcesClient, OfficesClient
  controllers: [BookingsController],
  providers: [GetBookingsService, BookingActionsService],
  // No exports — this module is a leaf, nothing needs its providers
})
export class BookingsModule {}

// features/bookings/apis/rest/controllers/bookings.controller.ts
@ApiTags('Bookings')                    // groups all endpoints under "Bookings" in Swagger UI
@ApiKeyAuthorizationHeader              // custom composite: adds auth header to every endpoint in Swagger
@Controller([LEGACY_PATH_PREFIX + '/bookings', '/bookings'])
@UseGuards(
  RequirePublicApiToken,               // verifies API key JWT + calls IAM to confirm active SA
  RequireFeatures('PUBLIC_API', 'RESOURCE_BOOKING_PUBLIC_API'),  // both flags required
)
export class BookingsController {
  // Inline param decorator — reads from request.publicApiUser.createdBy
  // Defined in the controller file, not exported, because it is only used here
  private readonly CurrentApiTokenCreatedById = createParamDecorator((_, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest<FastifyRequest>();
    const userData = getPublicApiUserData(request);
    if (!userData.createdBy)
      throw new DeskbirdHttpException(401, 'UNAUTHORIZED', 'Invalid Token');
    return userData.createdBy;
  });

  @ApiOperation({ summary: 'Lists company bookings', description: '...' })
  @ForbiddenResponse     // @ApiResponse(403)
  @UnauthorizedResponse  // @ApiResponse(401)
  @ListBookingsResponse  // @ApiResponse(200, schema: PaginatedBookingResponse)
  @Get()
  async getBookings(
    @Query() query: GetBookingsQuery,              // class-validator + transform: coerces types
    @CurrentPublicApiUser() { companyUuid }: PublicApiUser,  // from request.publicApiUser
  ): Promise<PaginatedBookingResponse> {
    // Controller is a thin delegation layer — no business logic here
    return this.getBookingsService.getBookings({ companyId: companyUuid, ...query });
  }

  @Post()
  @HttpCode(200)  // explicit: POST that creates returns 200, not 201 (API design choice)
  async createBooking(
    @Body() dto: CreateBookingDto,
    @CurrentApiTokenCreatedById() createdBy: string,
    @CurrentPublicApiUser() { companyId }: PublicApiUser,
  ): Promise<BookingResponse> {
    const [result] = await this.bookingActions.createBookings({ ... });
    // Handle per-booking failure: createBookings returns discriminated union array
    if (!result.success)
      throw new DeskbirdHttpException(result.error.statusCode, result.error.errorCode, result.error.message);
    return result.booking;
  }

  @Patch('/:bookingId/cancel')
  @HttpCode(204)  // 204 No Content — mutation succeeded, nothing to return
  async cancel(
    @Param(ValidationPipe) { bookingId }: GetSingleBookingQuery,
    @CurrentApiTokenCreatedById() createdBy: string,
  ): Promise<void> {
    await this.bookingActions.cancelBooking(bookingId, createdBy);
  }
}`,
        }],
      },
      {
        title: 'Service Layer — Fan-out and Data Assembly',
        description: 'The service layer does the heavy lifting: parallel fan-out to multiple internal services, chunked requests for large ID sets, and company membership assertions before returning data.',
        callouts: [
          {
            type: 'pattern', icon: '🔀', title: 'Promise.all fan-out — one bulk fetch per service',
            body: 'After fetching bookings, GetBookingsService collects all unique guestIds, userIds, resourceIds, officeIds from the result set, then calls four services in parallel via Promise.all(). The results are assembled into Maps keyed by ID, then a mapper function creates the final response objects. This pattern avoids N+1 calls (one per booking) while keeping the code readable — all fetching is declarative and parallel.',
          },
          {
            type: 'insight', icon: '📦', title: 'chunk() for large resource ID sets',
            body: 'getResources() uses lodash chunk() to split resource IDs into batches of 500 before calling the resources service. This handles the case where a company has hundreds of bookings in a single page — without chunking, the resources service URL query string would exceed the maximum URL length. The chunks are fetched in parallel via Promise.all(), then flatMapped into one array.',
          },
          {
            type: 'critical', icon: '🔐', title: 'assertCompanyMembership — cross-tenant data isolation',
            body: 'getBooking() (single booking by ID) calls assertCompanyMembership(companyId, booking) after fetching the booking. This checks that booking.companyId matches the authenticated API token\'s companyId. Without this check, a company with a valid API key could fetch any other company\'s bookings by guessing booking IDs. The assertion is a dedicated util function so it can be reused across services.',
          },
          {
            type: 'pattern', icon: '📝', title: 'GetBookingsService vs BookingActionsService — read/write split',
            body: 'Reads live in GetBookingsService, mutations in BookingActionsService. Both inject the same set of service clients from SharedModule. The split makes each class smaller and more focused — GetBookingsService only needs to understand how to assemble read responses, BookingActionsService only needs to understand how to map mutation errors to HTTP exceptions. Tests for each class are independently scoped.',
          },
        ],
        files: [{
          filename: 'service layer patterns',
          lang: 'typescript',
          code: `// GetBookingsService — read side
@Injectable()
export class GetBookingsService {
  async getBookings({ companyId, ...query }): Promise<PaginatedResponse<BookingModel>> {
    const response = await this.bookingsClient.findMany({ companyId, ...query });
    const { data: bookings, ...pagination } = unwrapOrThrow(response);

    // Collect all unique IDs from the result set — one bulk fetch per service
    const guestIds    = uniq(compact(bookings.map(b => b.guestId)));
    const userIds     = uniq(compact(bookings.map(b => b.userId)));
    const resourceIds = uniq(compact(bookings.map(b => b.resourceId)));
    const officeIds   = uniq(compact(bookings.map(b => b.officeId)));

    // All four fetches run in parallel
    const [guests, users, resources, offices] = await Promise.all([
      this.getGuests(guestIds),
      this.getUsers(userIds),
      this.getResources(resourceIds),  // chunked internally for large sets
      this.getOffices(companyId, officeIds),
    ]);

    // Maps for O(1) lookup during mapping
    const guestsMap    = new Map(guests.map(g    => [g.id, g]));
    const usersMap     = new Map(users.map(u     => [u.id, u]));
    const resourcesMap = new Map(resources.map(r => [r.id, r]));
    const officesMap   = new Map(offices.map(o   => [o.id, o]));

    return { ...pagination, data: bookings.map(bookingMapper(guestsMap, usersMap, resourcesMap, officesMap)) };
  }

  async getBooking({ bookingId, companyId }) {
    const booking = unwrapOrThrowMapped(
      await this.bookingsClient.findOne({ id: bookingId }),
      () => DeskbirdNotFoundException,
    );
    if (!booking) throw DeskbirdNotFoundException;

    // Cross-tenant isolation check — must run before returning any data
    assertCompanyMembership(companyId, booking);

    const [user, [guest], [resource], [office]] = await Promise.all([...]);
    return mapBooking(booking, user, guest, resource!, office!);
  }

  private async getResources(resourceIds: string[]): Promise<Resource[]> {
    if (!resourceIds.length) return [];
    // Split into 500-ID chunks to avoid URL length limits
    const chunks = chunk(uniq(resourceIds), 500);
    const results = await Promise.all(
      chunks.map(ids => this.resourcesClient.findMany({ ids }).then(unwrapOrThrow))
    );
    return results.flatMap(({ data }) => data);
  }
}`,
        }],
      },
      {
        title: 'API Key Management',
        description: 'The /keys endpoint lets company admins create and manage API keys. Under the hood, each API key is backed by a GCP Service Account in the IAM service — creating a key creates a service account, deleting a key deletes the service account.',
        callouts: [
          {
            type: 'pattern', icon: '🔑', title: 'API key = IAM Service Account + key',
            body: 'ApiKeyService.createNewApiKey() calls iamClient.serviceAccounts.create() to create a service account with claims: { companyUuid } (and provider for SCIM keys). Then calls iamClient.serviceAccounts.createKey() to get the actual JWT token string. There is a 1:1 relationship between service account and API key — deleting a key deletes the service account. This means all validation (is the key active? what company is it for?) is delegated to the IAM service.',
          },
          {
            type: 'insight', icon: '⏰', title: 'API key expiration — 1 year default for publicApi type',
            body: 'publicApi keys get a 1-year expiration by default (configurable via expirationInYears). SCIM keys do not expire. The expiresAt is passed to iamClient.serviceAccounts.createKey() — the IAM service enforces it when verifying. The public-api does not track expiration itself; it relies entirely on IAM\'s verify() call in RequirePublicApiToken.',
          },
          {
            type: 'tip', icon: '🧹', title: 'Rollback on partial failure',
            body: 'If serviceAccounts.create() succeeds but serviceAccounts.createKey() fails, ApiKeyService deletes the just-created service account before throwing. Without this cleanup, orphaned service accounts would accumulate in IAM. This manual rollback is necessary because there is no distributed transaction across two service calls.',
          },
          {
            type: 'pattern', icon: '🔐', title: 'ApiKeyController guard chain',
            body: '@UseGuards(RequireFirebaseToken, RequireUser, RequireUserRole({ oneOf: ["admin"], allowDeskbirdAdmins: true }), RequireAnyFeatures("PUBLIC_API", "SCIM")) — four guards in order. Firebase JWT must be valid, user must exist in the DB, user must be an admin (or a deskbird internal employee), and the company must have at least one of the API features enabled. Only admins can create/delete API keys — employees cannot.',
          },
        ],
        files: [{
          filename: 'apiKey.service.ts + apiKey.controller.ts',
          lang: 'typescript',
          code: `// features/keys/domain/services/apiKey.service.ts
@Injectable()
export class ApiKeyService {
  async createNewApiKey(inputModel: CreateApiKeyModel, { userId, userUuid, companyId, companyUuid }) {
    const { serviceAccountId, apiKey, expiresAt } = await this.createServiceAccountWithKey({
      ...inputModel, companyUuid, userUuid,
    });
    return { ...inputModel, id: serviceAccountId, apiKey, companyId, companyUuid, status: 'active', expiresAt, createdAt: new Date(), createdBy: userId };
  }

  private async createServiceAccountWithKey(input) {
    const expiresAt = input.type === 'publicApi'
      ? new Date(Date.now() + ONE_YEAR_MS * Math.max(1, input.expirationInYears ?? 1))
      : undefined;  // SCIM keys do not expire

    const claims = input.type === 'scim'
      ? { companyUuid: input.companyUuid, provider: input.provider }
      : { companyUuid: input.companyUuid };

    // Step 1: create the service account in IAM
    const { id: serviceAccountId } = unwrapOrThrowMapped(
      await this.iamClient.serviceAccounts.create({ type: input.type, companyUuid: input.companyUuid, claims, createdByUserUuid: input.userUuid }),
      error => DeskbirdPreconditionFailedError(error, 'Service account creation failed.'),
    );

    // Step 2: generate the JWT key for this service account
    const keyResult = await this.iamClient.serviceAccounts.createKey({ serviceAccountId, expiresAt: expiresAt ?? null });

    if (!keyResult.success) {
      // Rollback: delete the orphaned service account before throwing
      await this.iamClient.serviceAccounts.delete(serviceAccountId);
      throw DeskbirdPreconditionFailedError(keyResult.errorCode ?? 'unknown', 'Service account key creation failed.');
    }

    return { serviceAccountId, apiKey: keyResult.data.key, expiresAt };
  }

  async deleteApiKey(serviceAccountId: string): Promise<void> {
    // Deleting the service account invalidates the key — IAM verify() will fail
    await this.iamClient.serviceAccounts.delete(serviceAccountId);
  }
}

// features/keys/apis/rest/controllers/apiKey.controller.ts
@Controller([LEGACY_PATH_PREFIX + '/keys', '/keys'])
@UseGuards(
  RequireFirebaseToken,
  RequireUser,
  RequireUserRole({ oneOf: ['admin'], allowDeskbirdAdmins: true }),
  RequireAnyFeatures('PUBLIC_API', 'SCIM'),
)
export class ApiKeyController {
  @Post()
  @HttpCode(201)
  async newApiKey(
    @Body() body: CreateApiKeyInputModel,
    @CurrentUserTokenData() { companyId, companyUuid, userId, userUuid }: UserTokenData,
  ) {
    // Check the specific feature flag for this key type before creating
    const feature = body.type === 'publicApi' ? 'PUBLIC_API' : 'SCIM';
    const access = await this.featureManagerClient.getFeatureAccess({ companyUuid });
    if (!access.success || !access.data.features.includes(feature))
      throw new DeskbirdHttpException(403, 'featureNotAllowed', 'Feature not allowed');

    return this.apiKeyService.createNewApiKey(
      CreateApiKeyInputModel.toCreateApiKeyModel(body),
      { companyId, companyUuid, userId, userUuid },
    );
  }

  @Delete(':id')
  @HttpCode(204)
  async deleteApiKey(@Param('id', new ParseUUIDPipe()) id: string) {
    return this.apiKeyService.deleteApiKey(id);
  }
}`,
        }],
      },
    ],
  },

  {
    id: 'deskbird-overview',
    title: 'deskbird — Real-World NestJS',
    subtitle: 'Desk booking SaaS: architecture, tech stack, and design decisions',
    tag: { label: 'deskbird', color: '#58a6ff', bg: '#0d1f33' },
    description: 'deskbird is a desk booking SaaS used by hundreds of enterprise companies. The public-api service is a NestJS 10 application using Fastify, Firebase Auth, GCP Pub/Sub, Redis, and a suite of shared internal libraries. This walkthrough covers exactly how NestJS is used in a real production codebase — from bootstrap to guards to inter-service communication.',
    sections: [
      {
        title: 'What is deskbird?',
        description: 'deskbird lets employees book desks, parking spots, and meeting rooms. It exposes a Public API (OAuth2-style API keys) used by enterprise customers to integrate with their HR/IT systems — think creating bookings from Slack, syncing with Microsoft Teams, or bulk-importing users from SCIM.',
        callouts: [
          { type: 'insight', icon: '🏢', title: 'Architecture: many small NestJS services', body: 'deskbird uses a microservices architecture on GCP Cloud Run. The public-api service is the external gateway — it validates API keys, enforces feature flags, and proxies to internal services (bookings, users, offices, resources) via HTTP. Internal services communicate via service account JWT tokens, not user tokens.' },
          { type: 'pattern', icon: '📦', title: 'Shared library monorepo', body: 'deskbird-libs is an npm workspaces monorepo of internal libraries: @deskbird/auth-nestjs, @deskbird/guards-nestjs, @deskbird/errors-nestjs, @deskbird/service-clients, @deskbird/tracing-nestjs, @deskbird/pubsub-nestjs. Every NestJS service installs these instead of duplicating auth/tracing/error code. Changes to a lib are published and bumped across all services.' },
          { type: 'tip', icon: '⚡', title: 'Why Fastify instead of Express?', body: 'Fastify is 2× faster at raw HTTP throughput. On GCP Cloud Run (pay-per-CPU-second), it directly reduces costs at scale. Fastify also supports HTTP/2 natively — the public-api enables HTTP/2 on Cloud Run (isCloudExecution() check in bootstrap) to get multiplexed streams and header compression for free.' },
        ],
      },
      {
        title: 'Tech Stack',
        callouts: [
          { type: 'pattern', icon: '🛠️', title: 'Stack overview', body: 'NestJS 10 + Fastify adapter · Firebase Authentication (RS256 JWT) · GCP Pub/Sub (async events) · Redis (rate limiting, session cache) · Zod (schema validation) · @nestjs/swagger (auto OpenAPI spec) · nestjs-rate-limiter · axios-retry · OpenTelemetry / GCP Cloud Trace' },
        ],
        files: [{ filename: 'app.ts + app.module.ts', lang: 'typescript', code: D.appBootstrap }],
      },
    ],
  },

  {
    id: 'deskbird-config',
    title: 'Config & Bootstrap',
    subtitle: 'Zod env validation, Fastify adapter, Helmet, Swagger, graceful shutdown',
    tag: { label: 'Config', color: '#3fb950', bg: '#0d1f14' },
    description: 'Configuration is validated with Zod at startup — if any required env var is missing or the wrong type, the process exits immediately with a human-readable error. The app uses NestFastifyApplication for HTTP/2 support on GCP Cloud Run and registers Helmet security headers via the shared configureApp() helper.',
    sections: [
      {
        title: 'Zod Config Validation',
        description: 'Unlike class-validator, Zod can coerce types (string → number), derive computed fields via .transform(), and produce detailed error messages listing every invalid field at once — not just the first failure.',
        callouts: [
          { type: 'insight', icon: '✅', title: 'Fail-fast at startup, not at runtime', body: 'Without config validation, missing REDIS_HOST causes a connection failure at the first request, not at startup. Zod validation means the pod crashes immediately on deploy with a clear error — catchable in your CI/CD pipeline before traffic reaches it.' },
          { type: 'pattern', icon: '🔄', title: 'FAKE_SERVICE_ACCOUNT_TOKENS for local dev', body: 'In local development there is no GCP metadata server, so real service account tokens cannot be fetched. FAKE_SERVICE_ACCOUNT_TOKENS=true makes the ServiceAccountTokenProvider return a dummy token instead of calling GCP. This flag is validated as a boolean (Zod transforms "true"→true) and is never true in production.' },
        ],
        files: [{ filename: 'config.schema.ts', lang: 'typescript', code: D.configSchema }],
      },
      {
        title: 'App Bootstrap & Security Middleware',
        callouts: [
          { type: 'tip', icon: '🔒', title: 'configureApp() is a shared library function', body: 'Every NestJS service in the deskbird monorepo calls configureApp() from @deskbird/rest-nestjs. This guarantees helmet headers and CORS are applied uniformly — a new service cannot accidentally forget them. Shared bootstrap helpers are a key advantage of a monorepo library architecture.' },
          { type: 'insight', icon: '📄', title: 'OpenAPI spec written to disk at startup', body: 'SwaggerModule.createDocument() runs at startup and writes openapi-spec.json. The CI pipeline checks this file into git and diffs it on every PR. If an endpoint signature changes without a spec update, the diff makes it visible — preventing silent breaking changes to API consumers.' },
        ],
        files: [{ filename: 'configureApp.ts', lang: 'typescript', code: D.configureApp }],
      },
    ],
  },

  {
    id: 'deskbird-auth',
    title: 'Firebase Auth Module',
    subtitle: 'ConfigurableModuleBuilder, certificate caching, JWT verification',
    tag: { label: 'Auth', color: '#a371f7', bg: '#1f1535' },
    description: 'The @deskbird/auth-nestjs library wraps Firebase JWT verification. Firebase uses rotating X.509 certificates (not a static secret), so the library must fetch and cache Google\'s public certificates, respecting the Cache-Control max-age header. The module is built with ConfigurableModuleBuilder — the idiomatic NestJS pattern for publishable library modules that support both sync and async configuration.',
    sections: [
      {
        title: 'ConfigurableModuleBuilder and Certificate Caching',
        callouts: [
          { type: 'pattern', icon: '🏗️', title: 'ConfigurableModuleBuilder generates forRoot/forRootAsync', body: 'setClassMethodName("forRoot").build() generates four exports: ConfigurableModuleClass (to extend), MODULE_OPTIONS_TOKEN (injection token for options), OPTIONS_TYPE and ASYNC_OPTIONS_TYPE (TypeScript types). The consuming module just extends ConfigurableModuleClass and gets forRoot() and forRootAsync() for free — no manual async factory boilerplate.' },
          { type: 'insight', icon: '🔑', title: 'Two Firebase issuers supported', body: 'securetoken.google.com/<projectId> → tokens issued to end users (Firebase Auth SDK). accounts.google.com → Google service account tokens used for machine-to-machine calls. Each issuer has its own certificate URL at Google APIs. The CertificateProvider maintains a cache keyed by issuer, fetching both on startup.' },
          { type: 'warning', icon: '⚠️', title: 'Numeric project ID from GCP metadata endpoint', body: 'Firebase requires the numeric GCP project ID (not the string project ID) to validate token audience. On GCP Cloud Run, if not set as env var, DeskbirdAuthModuleOptionsWithDefaultsFactory fetches it from the GCP metadata endpoint (http://metadata.google.internal) — this only works when running on GCP, hence the env var fallback for local dev.' },
        ],
        files: [
          { filename: 'auth.module.ts + module-definition.ts', lang: 'typescript', code: D.authModule },
          { filename: 'certificateProvider.ts + authVerifier.ts', lang: 'typescript', code: D.certificateProvider },
        ],
      },
    ],
  },

  {
    id: 'deskbird-guards',
    title: 'Guard Chain',
    subtitle: 'RequireFirebaseToken → RequireUser → RequireUserRole → RequireFeatures',
    tag: { label: 'Guards', color: '#f0883e', bg: '#271b0e' },
    description: 'Authentication and authorization in deskbird use a four-layer guard chain applied via @UseGuards(). Each guard does one thing: verify the token, fetch the user, check the role, check the feature flag. The mixin() pattern enables parameterised guard instances — RequireUserRole({ oneOf: [\'admin\'] }) creates a new injectable class with the config baked in.',
    sections: [
      {
        title: 'Guard Chain and the mixin() Pattern',
        callouts: [
          { type: 'pattern', icon: '🔗', title: 'Guards are a pipeline, not a single monolith', body: 'RequireFirebaseToken attaches tokenData to the request. RequireUser reads that tokenData, fetches the full user from Users service, and attaches it. RequireUserRole reads the user. This chain enables fine-grained reuse: some routes verify token only (no DB hit), some fetch the user, some also check features — apply only what\'s needed.' },
          { type: 'insight', icon: '🧱', title: 'mixin() vs @SetMetadata() for parameterised guards', body: 'mixin() creates a new class per call — RequireUserRole({ oneOf: [\'admin\'] }) returns a distinct class from RequireUserRole({ oneOf: [\'employee\'] }). NestJS\'s DI treats them as separate injectables. This is cleaner than SetMetadata+Reflector because the config is type-checked at the call site, not at runtime.' },
          { type: 'tip', icon: '👤', title: 'isDeskbirdAdmin bypass', body: 'Deskbird internal staff have isDeskbirdAdmin: true in their token (from a Firebase custom claim). RequireUserRole({ allowDeskbirdAdmins: true }) lets them bypass company role checks — enabling customer support to access any company\'s data. This flag is validated by Zod during token parsing, not trusted from raw JWT.' },
        ],
        files: [{ filename: 'guards chain', lang: 'typescript', code: D.guards }],
      },
    ],
  },

  {
    id: 'deskbird-service-clients',
    title: 'Service Clients',
    subtitle: 'Abstract ServiceClient, Axios interceptors, Zod validation, ServiceResult<T>',
    tag: { label: 'Clients', color: '#79c0ff', bg: '#0d1f33' },
    description: 'All inter-service HTTP calls in deskbird go through the @deskbird/service-clients library. An abstract ServiceClient base class provides: automatic auth header injection (service account tokens), correlation ID + traceparent propagation, Axios retry with exponential backoff, and Zod response validation. Each downstream service gets a concrete client class with typed methods.',
    sections: [
      {
        title: 'Abstract ServiceClient Base Class',
        callouts: [
          { type: 'pattern', icon: '🔌', title: 'headerFactories: lazy async header injection', body: 'The authorization factory calls ServiceAccountTokenProvider.getToken(audience) on every request. The token provider caches the token and refreshes it before expiry — callers never manage token lifecycle. Similarly, correlationId and traceparent factories read from AsyncLocalStorage (TracingService) so they always reflect the current request\'s tracing context.' },
          { type: 'insight', icon: '📋', title: 'ServiceResult<T, ErrorCode> — typed error handling', body: 'Instead of try/catch on every call, clients return { success: true, data } | { success: false, error, errorCode }. The errorCode is a string literal union (\'not_found\' | \'forbidden\' | ...) so callers can switch on it with type narrowing. unwrapOrThrow() throws if success is false; unwrapOrThrowMapped() lets you map specific error codes to different exceptions.' },
          { type: 'tip', icon: '✅', title: 'Zod response validation off in prod', body: 'validateResponses is enabled in non-prod environments (GCP_PROJECT_ID !== "deskbird-bbe72" — the prod project). In prod, if a downstream service returns an unexpected field, it\'s ignored instead of throwing. Parsing errors are reported to Sentry via onParsingError for monitoring without causing prod incidents.' },
        ],
        files: [{ filename: 'serviceClient.class.ts', lang: 'typescript', code: D.serviceClient }],
      },
    ],
  },

  {
    id: 'deskbird-error-handling',
    title: 'Error Handling',
    subtitle: 'DeskbirdHttpException, BaseExceptionFilter, stable errorCode contract',
    tag: { label: 'Errors', color: '#ff7b72', bg: '#2d1318' },
    description: 'deskbird uses DeskbirdHttpException — a plain Error subclass, not NestJS HttpException — as its domain exception class. The DeskbirdExceptionFilter extends BaseExceptionFilter and normalises all exceptions into a consistent { statusCode, errorCode, message, details } shape. The errorCode string is the stable API contract; HTTP status codes can change, error codes cannot.',
    sections: [
      {
        title: 'DeskbirdHttpException and DeskbirdExceptionFilter',
        callouts: [
          { type: 'insight', icon: '🏛️', title: 'Why not extend HttpException?', body: 'If domain code throws HttpException(409), it couples to HTTP. If it throws InsufficientFundsException (which extends Error, not HttpException), the domain stays transport-agnostic. The filter decides the HTTP status. The same exception class could be thrown in a Pub/Sub handler with no HTTP context.' },
          { type: 'pattern', icon: '🔍', title: 'BaseExceptionFilter for response delegation', body: 'extends BaseExceptionFilter instead of implements ExceptionFilter lets us intercept, reformat the exception body, then call super.catch(new HttpException(newBody, status)) to delegate actual response writing to NestJS. This avoids re-implementing all the content negotiation logic.' },
          { type: 'critical', icon: '⚠️', title: 'errorCode is a stable public contract', body: 'API clients switch on errorCode: "tokenExpired", "user_not_found", "forbidden". These strings are in their integration code and cannot change without a breaking change + migration period. HTTP status codes are secondary. Always add new error codes; never rename existing ones.' },
        ],
        files: [{ filename: 'error classes + filter', lang: 'typescript', code: D.errorHandling }],
      },
    ],
  },

  {
    id: 'deskbird-bookings',
    title: 'Bookings API',
    subtitle: 'Controller, service orchestration, feature gates, parallel fan-out',
    tag: { label: 'Bookings', color: '#3fb950', bg: '#0d1f14' },
    description: 'The BookingsController is the core of the public API — it handles CRUD operations on desk/parking/resource bookings. After creating bookings, BookingActionsService does a parallel fan-out to enrich the response: it fetches users, guests, resources, and offices from four different internal services concurrently via Promise.all().',
    sections: [
      {
        title: 'Controller and Service Orchestration',
        callouts: [
          { type: 'pattern', icon: '🔀', title: 'Promise.all() fan-out for response enrichment', body: 'createBookings() first creates all bookings in one batch call, then fans out to 4 services in parallel: getGuests, getUsers, getResources, getOffices. The results are combined via Maps keyed by ID. This is the standard pattern for N+1 prevention in a microservices architecture — one bulk fetch per service, not one fetch per booking.' },
          { type: 'insight', icon: '🔒', title: 'Feature flags as business gates, not kill-switches', body: 'RequireFeatures("PUBLIC_API", "RESOURCE_BOOKING_PUBLIC_API") means a company must have both flags enabled in FeatureManager to call this endpoint. This is not just a technical toggle — it is the upselling mechanism. Companies on the basic plan do not have PUBLIC_API, so they get 403 until they upgrade. No separate auth check needed.' },
          { type: 'tip', icon: '📝', title: 'Dual path prefix for backwards compatibility', body: '@Controller([legacy_prefix + "/bookings", "/bookings"]) maps two URL paths to the same controller. The legacy path is kept for existing integrations that cannot migrate immediately. LEGACY_PATH_PREFIX routes are filtered out of the public Swagger spec so new customers see only the canonical path.' },
        ],
        files: [{ filename: 'bookings.controller.ts + bookingActions.service.ts', lang: 'typescript', code: D.bookingsController }],
      },
    ],
  },

  {
    id: 'deskbird-tracing',
    title: 'Tracing & Rate Limiting',
    subtitle: 'TracingMiddleware, TracingInterceptor, token-based rate limiting with Redis',
    tag: { label: 'Observability', color: '#79c0ff', bg: '#0d1f33' },
    description: 'Distributed tracing in deskbird uses W3C traceparent headers propagated via AsyncLocalStorage. TracingMiddleware handles HTTP requests; TracingInterceptor handles Pub/Sub message payloads (where the tracing context is in message attributes, not HTTP headers). Rate limiting uses a custom guard that rate-limits per API token (not per IP) with SHA-256 hashed bucket keys in Redis.',
    sections: [
      {
        title: 'Tracing Middleware + Interceptor',
        callouts: [
          { type: 'pattern', icon: '🔍', title: 'Middleware for HTTP, Interceptor for Pub/Sub', body: 'HTTP requests carry tracing context in headers — TracingMiddleware reads them before the request reaches any guard or handler. Pub/Sub messages are delivered via HTTP POST, but the traceparent lives in message.attributes, not HTTP headers. TracingInterceptor detects this and overrides the tracing context from the message attributes.' },
          { type: 'insight', icon: '📡', title: 'AsyncLocalStorage for zero-overhead propagation', body: 'TracingService wraps Node.js AsyncLocalStorage. Once runWithTracingInformation() sets the context, any code in the same async chain (guards, interceptors, service clients, Pub/Sub handlers) can call getCorrelationId() and getTraceparent() without any parameter threading. This is how correlation IDs flow from the HTTP handler all the way into outgoing service client requests.' },
        ],
        files: [{ filename: 'tracing.middleware.ts + interceptor', lang: 'typescript', code: D.tracing }],
      },
      {
        title: 'Token-Based Rate Limiting',
        callouts: [
          { type: 'critical', icon: '🔴', title: 'IP-based rate limiting fails at enterprise scale', body: 'When 500 employees at a company share a corporate NAT, they all appear as one IP. IP-based limiting would block the entire company after 10 requests/second. Token-based limiting gives each API key its own bucket — the API key is the unit of rate limiting, not the network location.' },
          { type: 'pattern', icon: '🔑', title: 'SHA-256 hash of token as bucket key', body: 'The rate limiter stores buckets in Redis keyed by a hash of the API token. SHA-256(token) is deterministic, fixed-length, and does not store the raw token in Redis (where it would be a security exposure). If the token is compromised, rotating it immediately changes the bucket key, invalidating the old rate limit history.' },
        ],
        files: [{ filename: 'tokenRateLimiter.guard.ts', lang: 'typescript', code: D.rateLimiting }],
      },
    ],
  },
]
