import React, { useState, useCallback } from 'react'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import { chapters } from './data/content'

/* ─── Sidebar ──────────────────────────────────────────────────────────── */
function Sidebar({ current, onSelect }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-logo">
          <span className="sidebar-logo-icon">♠</span>
          <div>
            <div className="sidebar-logo-title">BetPlatform</div>
            <div className="sidebar-logo-sub">Architecture Guide</div>
          </div>
        </div>
      </div>
      <nav className="sidebar-nav">
        {chapters.map((ch, i) => (
          <button
            key={ch.id}
            className={`sidebar-item ${i === current ? 'active' : ''} ${i < current ? 'completed' : ''}`}
            onClick={() => onSelect(i)}
          >
            <span className={`step-dot ${i === current ? 'active' : ''} ${i < current ? 'completed' : ''}`}>
              {i < current ? '✓' : i + 1}
            </span>
            <div className="sidebar-item-text">
              <div className="sidebar-item-title">{ch.title}</div>
              <div className="sidebar-item-sub">{ch.subtitle}</div>
            </div>
          </button>
        ))}
      </nav>
    </aside>
  )
}

/* ─── Callout ──────────────────────────────────────────────────────────── */
function Callout({ type, icon, title, body }) {
  return (
    <div className={`callout callout-${type}`}>
      <div className="callout-header">
        <span className="callout-icon">{icon}</span>
        <span className="callout-title">{title}</span>
      </div>
      <div className="callout-body">{body}</div>
    </div>
  )
}

/* ─── CodeBlock ────────────────────────────────────────────────────────── */
function CodeBlock({ files }) {
  const [activeTab, setActiveTab] = useState(0)
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(files[activeTab].code).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [activeTab, files])

  if (!files || files.length === 0) return null

  return (
    <div className="code-block">
      {files.length > 1 && (
        <div className="code-tabs">
          {files.map((f, i) => (
            <button
              key={f.filename}
              className={`code-tab ${i === activeTab ? 'active' : ''}`}
              onClick={() => setActiveTab(i)}
            >
              {f.filename}
            </button>
          ))}
        </div>
      )}
      {files.length === 1 && (
        <div className="code-tabs">
          <span className="code-tab active">{files[0].filename}</span>
        </div>
      )}
      <div className="code-copy-row">
        <button className="copy-btn" onClick={handleCopy}>
          {copied ? '✓ Copied' : '⎘ Copy'}
        </button>
      </div>
      <SyntaxHighlighter
        language={files[activeTab].lang || 'typescript'}
        style={vscDarkPlus}
        customStyle={{
          margin: 0,
          borderRadius: '0 0 8px 8px',
          fontSize: '13px',
          lineHeight: '1.6',
          background: '#0d1117',
          padding: '20px 24px',
        }}
        showLineNumbers
        lineNumberStyle={{ color: '#3d4450', minWidth: '2.5em' }}
      >
        {files[activeTab].code}
      </SyntaxHighlighter>
    </div>
  )
}

/* ─── Overview Chapter ─────────────────────────────────────────────────── */
function OverviewChapter({ chapter }) {
  const services = [
    { name: 'API Gateway', role: 'BFF / Edge', color: '#58a6ff', icon: '⬡' },
    { name: 'Betting Service', role: 'Core domain + CQRS', color: '#3fb950', icon: '♠' },
    { name: 'Wallet Service', role: 'Financial ledger', color: '#f0883e', icon: '⬡' },
    { name: 'Auth Service', role: 'JWT + JWKS + Sessions', color: '#a371f7', icon: '⬡' },
    { name: 'Risk Service', role: 'Fraud + RG limits', color: '#ff7b72', icon: '⬡' },
    { name: 'Notification Service', role: 'BullMQ multi-channel', color: '#79c0ff', icon: '⬡' },
  ]
  const tech = [
    ['NestJS 11', 'Framework'],
    ['PostgreSQL 16', 'Primary DB'],
    ['Redis 7', 'Cache / Lock / Rate-limit'],
    ['Kafka 3.7', 'Event backbone'],
    ['gRPC / protobuf', 'Sync RPC'],
    ['Socket.IO', 'WebSockets'],
    ['BullMQ', 'Priority queues'],
    ['OpenTelemetry', 'Distributed tracing'],
    ['TypeORM', 'ORM + migrations'],
    ['Debezium', 'CDC / WAL capture'],
    ['Opossum', 'Circuit breaker'],
    ['Pino', 'Structured logging'],
  ]
  const stats = [
    { val: '10M+', label: 'Concurrent users' },
    { val: '6', label: 'Microservices' },
    { val: '5', label: 'Shared libraries' },
    { val: '<50ms', label: 'P99 bet placement' },
  ]

  return (
    <div className="chapter-body">
      <div className="overview-hero">
        <div className="overview-hero-tag">{chapter.tag}</div>
        <h1 className="overview-hero-title">{chapter.title}</h1>
        <p className="overview-hero-desc">{chapter.description}</p>
        <div className="stat-row">
          {stats.map(s => (
            <div className="stat-card" key={s.label}>
              <div className="stat-value">{s.val}</div>
              <div className="stat-label">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      <h2 className="section-title">Microservices</h2>
      <div className="services-grid">
        {services.map(s => (
          <div className="service-card" key={s.name} style={{ borderTopColor: s.color }}>
            <div className="service-card-icon" style={{ color: s.color }}>{s.icon}</div>
            <div className="service-card-name">{s.name}</div>
            <div className="service-card-role">{s.role}</div>
          </div>
        ))}
      </div>

      <h2 className="section-title" style={{ marginTop: '40px' }}>Technology Stack</h2>
      <div className="tech-grid">
        {tech.map(([name, role]) => (
          <div className="tech-card" key={name}>
            <div className="tech-name">{name}</div>
            <div className="tech-role">{role}</div>
          </div>
        ))}
      </div>

      {chapter.sections && chapter.sections.map((sec, i) => (
        <div key={i}>
          {sec.callouts && sec.callouts.map((c, j) => (
            <Callout key={j} {...c} />
          ))}
          {sec.files && <CodeBlock files={sec.files} />}
        </div>
      ))}
    </div>
  )
}

/* ─── Pipeline Chapter ─────────────────────────────────────────────────── */
function PipelineChapter({ chapter }) {
  const steps = [
    { label: 'Cloudflare Edge', sub: 'DDoS + WAF + TLS termination', color: '#f0883e' },
    { label: 'Correlation ID Middleware', sub: 'X-Correlation-Id → CLS store', color: '#58a6ff' },
    { label: 'Geo-Block Middleware', sub: 'Jurisdiction check (fail-closed)', color: '#ff7b72' },
    { label: 'JWT Auth Guard', sub: 'RS256 verify + blacklist + token version', color: '#a371f7' },
    { label: 'Roles Guard', sub: 'RBAC via @Roles() decorator', color: '#a371f7' },
    { label: 'Operator Guard', sub: 'B2B SHA-256 key validation', color: '#a371f7' },
    { label: 'Throttler Guard', sub: 'Redis sliding-window rate limit', color: '#3fb950' },
    { label: 'Logging Interceptor', sub: 'Pre-handler: start timer', color: '#79c0ff' },
    { label: 'Transform Interceptor', sub: 'Post-handler: wrap { data, meta }', color: '#79c0ff' },
    { label: 'Timeout Interceptor', sub: 'RxJS timeout() per-route', color: '#79c0ff' },
    { label: 'Controller / Handler', sub: 'Route logic + CommandBus.execute()', color: '#58a6ff' },
    { label: 'gRPC Service', sub: 'Circuit-broken call → Betting Service', color: '#f0883e' },
    { label: 'Exception Filter', sub: '@Catch() — sanitize 5xx, stable 4xx codes', color: '#ff7b72' },
  ]

  return (
    <div className="chapter-body">
      <div className="section-header">
        <span className="tag">{chapter.tag}</span>
        <h2 className="section-title" style={{ marginTop: 8 }}>{chapter.title}</h2>
        <p className="section-desc">{chapter.description}</p>
      </div>

      <div className="pipeline-diagram">
        {steps.map((s, i) => (
          <React.Fragment key={i}>
            <div className="pipeline-step" style={{ borderLeftColor: s.color }}>
              <div className="pipeline-step-label" style={{ color: s.color }}>{s.label}</div>
              <div className="pipeline-step-sub">{s.sub}</div>
            </div>
            {i < steps.length - 1 && <div className="pipeline-arrow">↓</div>}
          </React.Fragment>
        ))}
      </div>

      {chapter.sections && chapter.sections.map((sec, i) => (
        <div key={i}>
          {sec.callouts && sec.callouts.map((c, j) => <Callout key={j} {...c} />)}
          {sec.files && <CodeBlock files={sec.files} />}
        </div>
      ))}
    </div>
  )
}

/* ─── Generic Chapter ──────────────────────────────────────────────────── */
function GenericChapter({ chapter }) {
  return (
    <div className="chapter-body">
      <div className="section-header">
        <span className="tag">{chapter.tag}</span>
        <h1 className="chapter-title">{chapter.title}</h1>
        {chapter.subtitle && <div className="chapter-subtitle">{chapter.subtitle}</div>}
        {chapter.description && <p className="chapter-desc">{chapter.description}</p>}
      </div>

      {chapter.sections && chapter.sections.map((sec, si) => (
        <section className="chapter-section" key={si}>
          {sec.title && <h2 className="section-title">{sec.title}</h2>}
          {sec.description && <p className="section-desc">{sec.description}</p>}
          {sec.callouts && sec.callouts.map((c, ci) => <Callout key={ci} {...c} />)}
          {sec.files && sec.files.length > 0 && <CodeBlock files={sec.files} />}
        </section>
      ))}
    </div>
  )
}

/* ─── Chapter Router ───────────────────────────────────────────────────── */
function ChapterView({ chapter }) {
  if (chapter.type === 'overview') return <OverviewChapter chapter={chapter} />
  if (chapter.type === 'pipeline') return <PipelineChapter chapter={chapter} />
  return <GenericChapter chapter={chapter} />
}

/* ─── App ──────────────────────────────────────────────────────────────── */
export default function App() {
  const [current, setCurrent] = useState(0)
  const total = chapters.length
  const progress = Math.round(((current + 1) / total) * 100)

  const goTo = useCallback((i) => {
    setCurrent(i)
    document.querySelector('.main-content')?.scrollTo({ top: 0, behavior: 'smooth' })
  }, [])

  const prev = useCallback(() => { if (current > 0) goTo(current - 1) }, [current, goTo])
  const next = useCallback(() => { if (current < total - 1) goTo(current + 1) }, [current, total, goTo])

  const chapter = chapters[current]

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-left">
          <span className="header-logo">♠</span>
          <span className="header-title">Betting Platform — Architecture Guide</span>
        </div>
        <div className="header-center">
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>
          <span className="progress-label">{current + 1} / {total}</span>
        </div>
        <div className="header-right">
          <span className="header-tag">{chapter.tag}</span>
        </div>
      </header>

      <div className="layout">
        <Sidebar current={current} onSelect={goTo} />

        <main className="main-content">
          <ChapterView chapter={chapter} />

          {/* Navigation */}
          <div className="nav-row">
            <button className="nav-btn nav-btn-prev" onClick={prev} disabled={current === 0}>
              ← Previous
            </button>

            <div className="nav-dots">
              {chapters.map((_, i) => (
                <button
                  key={i}
                  className={`nav-dot ${i === current ? 'active' : ''} ${i < current ? 'completed' : ''}`}
                  onClick={() => goTo(i)}
                  title={chapters[i].title}
                />
              ))}
            </div>

            <button className="nav-btn nav-btn-next" onClick={next} disabled={current === total - 1}>
              Next →
            </button>
          </div>
        </main>
      </div>
    </div>
  )
}
