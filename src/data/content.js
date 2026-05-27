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

// ─── Chapter definitions ──────────────────────────────────────────────────────
export const chapters = [
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
]
