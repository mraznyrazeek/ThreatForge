
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import './App.css'

type Page = 'overview' | 'indicators' | 'analytics' | 'settings'
type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

type Indicator = {
  id: string
  value: string
  type: string
  source: string
  family: string
  severity: Severity
  detected: string
}

type IconName =
  | 'shield'
  | 'grid'
  | 'activity'
  | 'database'
  | 'settings'
  | 'search'
  | 'bell'
  | 'chevron'
  | 'arrow'
  | 'filter'
  | 'terminal'
  | 'globe'
  | 'lock'
  | 'menu'
  | 'close'
  | 'check'

const indicators: Indicator[] = [
  {
    id: 'IOC-001',
    value: '203.0.113.42:443',
    type: 'IP:Port',
    source: 'ThreatFox',
    family: 'Cobalt Strike',
    severity: 'Critical',
    detected: '12 Nov 2026',
  },
  {
    id: 'IOC-002',
    value: 'update-node.example.com',
    type: 'Domain',
    source: 'URLhaus',
    family: 'ClearFake',
    severity: 'High',
    detected: '12 Nov 2026',
  },
  {
    id: 'IOC-003',
    value: '198.51.100.27:8080',
    type: 'IP:Port',
    source: 'ThreatFox',
    family: 'Mirai',
    severity: 'High',
    detected: '11 Nov 2026',
  },
  {
    id: 'IOC-004',
    value: 'b6d81c2e4a7f09d3...',
    type: 'SHA256',
    source: 'ThreatFox',
    family: 'AMOS',
    severity: 'Medium',
    detected: '11 Nov 2026',
  },
  {
    id: 'IOC-005',
    value: 'cdn-check.example.org',
    type: 'Domain',
    source: 'URLhaus',
    family: 'Unknown Loader',
    severity: 'Medium',
    detected: '10 Nov 2026',
  },
  {
    id: 'IOC-006',
    value: '192.0.2.84:8443',
    type: 'IP:Port',
    source: 'ThreatFox',
    family: 'Vidar',
    severity: 'Low',
    detected: '10 Nov 2026',
  },
]

const activity = [
  { day: 'Mon', threatfox: 44, urlhaus: 24 },
  { day: 'Tue', threatfox: 60, urlhaus: 31 },
  { day: 'Wed', threatfox: 49, urlhaus: 37 },
  { day: 'Thu', threatfox: 74, urlhaus: 42 },
  { day: 'Fri', threatfox: 62, urlhaus: 32 },
  { day: 'Sat', threatfox: 86, urlhaus: 51 },
  { day: 'Sun', threatfox: 70, urlhaus: 39 },
]

const severityData: {
  name: Severity
  count: number
  percentage: number
}[] = [
  { name: 'Critical', count: 84, percentage: 7 },
  { name: 'High', count: 312, percentage: 24 },
  { name: 'Medium', count: 556, percentage: 43 },
  { name: 'Low', count: 332, percentage: 26 },
]

const navigation: {
  label: string
  page: Page
  icon: IconName
}[] = [
  { label: 'Overview', page: 'overview', icon: 'grid' },
  { label: 'Threat Indicators', page: 'indicators', icon: 'shield' },
  { label: 'Analytics', page: 'analytics', icon: 'activity' },
  { label: 'Settings', page: 'settings', icon: 'settings' },
]

function Icon({
  name,
  size = 18,
}: {
  name: IconName
  size?: number
}) {
  const paths: Record<IconName, ReactNode> = {
    shield: (
      <>
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        <path d="m9 12 2 2 4-4" />
      </>
    ),
    grid: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </>
    ),
    activity: (
      <path d="M3 12h4l3-8 4 16 3-8h4" />
    ),
    database: (
      <>
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5" />
        <path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.07.07-2.86 2.86-.07-.07A1.7 1.7 0 0 0 15 19.4l-1 .42V22h-4v-2.18l-1-.42a1.7 1.7 0 0 0-1.88.34l-.07.07-2.86-2.86.07-.07A1.7 1.7 0 0 0 4.6 15l-.42-1H2v-4h2.18l.42-1a1.7 1.7 0 0 0-.34-1.88l-.07-.07 2.86-2.86.07.07A1.7 1.7 0 0 0 9 4.6l1-.42V2h4v2.18l1 .42a1.7 1.7 0 0 0 1.88-.34l.07-.07 2.86 2.86-.07.07A1.7 1.7 0 0 0 19.4 9l.42 1H22v4h-2.18Z" />
      </>
    ),
    search: (
      <>
        <circle cx="10.8" cy="10.8" r="7.3" />
        <path d="m16.2 16.2 4.3 4.3" />
      </>
    ),
    bell: (
      <>
        <path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9" />
        <path d="M10 21h4" />
      </>
    ),
    chevron: <path d="m9 18 6-6-6-6" />,
    arrow: (
      <>
        <path d="M7 17 17 7" />
        <path d="M8 7h9v9" />
      </>
    ),
    filter: (
      <>
        <path d="M4 7h16M7 12h10M10 17h4" />
      </>
    ),
    terminal: (
      <>
        <rect x="2.5" y="3.5" width="19" height="17" rx="2" />
        <path d="m6 9 3 3-3 3M12 15h5" />
      </>
    ),
    globe: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18" />
      </>
    ),
    lock: (
      <>
        <rect x="5" y="10" width="14" height="11" rx="2" />
        <path d="M8 10V7a4 4 0 0 1 8 0v3" />
      </>
    ),
    menu: <path d="M4 6h16M4 12h16M4 18h16" />,
    close: <path d="M5 5 19 19M19 5 5 19" />,
    check: <path d="m5 12 5 5L20 7" />,
  }

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.65"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  )
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity severity--${severity.toLowerCase()}`}>
      <span className="severity-dot" />
      {severity}
    </span>
  )
}

function SectionHeading({
  eyebrow,
  title,
  detail,
}: {
  eyebrow: string
  title: string
  detail?: string
}) {
  return (
    <div className="section-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h2>{title}</h2>
      </div>
      {detail && <span className="section-detail">{detail}</span>}
    </div>
  )
}

function IndicatorTable({
  rows,
  emptyMessage,
}: {
  rows: Indicator[]
  emptyMessage?: string
}) {
  return (
    <div className="table-scroll">
      <table className="indicator-table">
        <thead>
          <tr>
            <th>Indicator</th>
            <th>Type</th>
            <th>Malware family</th>
            <th>Source</th>
            <th>Severity</th>
            <th>Detected</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((indicator) => (
            <tr key={indicator.id}>
              <td>
                <span className="indicator-value">
                  {indicator.value}
                </span>
                <span className="indicator-id">{indicator.id}</span>
              </td>
              <td>{indicator.type}</td>
              <td>{indicator.family}</td>
              <td>
                <span className="source-label">
                  <span className="source-dot" />
                  {indicator.source}
                </span>
              </td>
              <td>
                <SeverityBadge severity={indicator.severity} />
              </td>
              <td className="date-cell">{indicator.detected}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={6} className="empty-table">
                {emptyMessage ?? 'No matching indicators found.'}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function Overview({
  onExplore,
}: {
  onExplore: () => void
}) {
  const stats = [
    {
      label: 'TOTAL INDICATORS',
      value: '11,370',
      note: 'Sample intelligence volume',
      accent: 'cyan',
      icon: 'shield' as IconName,
    },
    {
      label: 'SOURCE OBSERVATIONS',
      value: '11,376',
      note: 'Across intelligence feeds',
      accent: 'blue',
      icon: 'database' as IconName,
    },
    {
      label: 'CRITICAL SIGNALS',
      value: '84',
      note: 'Synthetic severity breakdown',
      accent: 'red',
      icon: 'activity' as IconName,
    },
    {
      label: 'ACTIVE DATA SOURCES',
      value: '02',
      note: 'ThreatFox + URLhaus',
      accent: 'green',
      icon: 'globe' as IconName,
    },
  ]

  return (
    <>
      <section className="welcome-panel">
        <div className="welcome-content">
          <div className="welcome-kicker">
            <span className="pulse-dot" />
            THREAT INTELLIGENCE PLATFORM
          </div>
          <h2>Intelligence at a glance.</h2>
          <p>
            A unified workspace to analyze indicators,
            identify emerging threats, and understand
            activity across intelligence sources.
          </p>
          <button
            type="button"
            className="primary-button"
            onClick={onExplore}
          >
            Explore indicators <Icon name="arrow" size={16} />
          </button>
        </div>
        <div className="radar-visual" aria-hidden="true">
          <div className="radar-ring radar-ring--outer" />
          <div className="radar-ring radar-ring--middle" />
          <div className="radar-ring radar-ring--inner" />
          <div className="radar-crosshair radar-crosshair--h" />
          <div className="radar-crosshair radar-crosshair--v" />
          <span className="radar-point radar-point--one" />
          <span className="radar-point radar-point--two" />
          <span className="radar-point radar-point--three" />
          <div className="radar-core">
            <Icon name="shield" size={29} />
          </div>
        </div>
      </section>

      <div className="stats-grid">
        {stats.map((stat) => (
          <article
            className={`stat-card stat-card--${stat.accent}`}
            key={stat.label}
          >
            <div className="stat-top">
              <span>{stat.label}</span>
              <div className="stat-icon">
                <Icon name={stat.icon} size={19} />
              </div>
            </div>
            <div className="stat-value">{stat.value}</div>
            <div className="stat-note">{stat.note}</div>
          </article>
        ))}
      </div>

      <div className="analytics-grid">
        <section className="panel activity-panel">
          <SectionHeading
            eyebrow="INTELLIGENCE TRENDS"
            title="Threat activity"
            detail="Illustrative weekly activity"
          />
          <div className="chart-legend">
            <span>
              <i className="legend-dot legend-dot--cyan" />
              ThreatFox
            </span>
            <span>
              <i className="legend-dot legend-dot--blue" />
              URLhaus
            </span>
          </div>
          <div
            className="activity-chart"
            role="img"
            aria-label="Illustrative grouped bar chart of ThreatFox and URLhaus activity for seven days"
          >
            <div className="chart-grid">
              <span>150</span>
              <span>100</span>
              <span>50</span>
              <span>0</span>
            </div>
            <div className="chart-bars">
              {activity.map((item) => (
                <div className="chart-column" key={item.day}>
                  <div className="bar-group">
                    <div
                      className="chart-bar chart-bar--cyan"
                      style={{ height: `${item.threatfox}%` }}
                    />
                    <div
                      className="chart-bar chart-bar--blue"
                      style={{ height: `${item.urlhaus}%` }}
                    />
                  </div>
                  <span className="chart-day">{item.day}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="panel severity-panel">
          <SectionHeading
            eyebrow="RISK OVERVIEW"
            title="Severity distribution"
            detail="Sample data"
          />
          <div className="risk-total">
            <strong>1,284</strong>
            <span>classified indicators</span>
          </div>
          <div className="severity-stack" aria-hidden="true">
            {severityData.map((item) => (
              <span
                key={item.name}
                className={`stack-segment stack-segment--${item.name.toLowerCase()}`}
                style={{ width: `${item.percentage}%` }}
              />
            ))}
          </div>
          <div className="severity-list">
            {severityData.map((item) => (
              <div className="severity-row" key={item.name}>
                <span className="severity-name">
                  <i
                    className={`risk-dot risk-dot--${item.name.toLowerCase()}`}
                  />
                  {item.name}
                </span>
                <span className="severity-count">
                  {item.count.toLocaleString()}
                </span>
                <span className="severity-percent">
                  {item.percentage}%
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="panel recent-panel">
        <div className="panel-header">
          <SectionHeading
            eyebrow="LATEST INTELLIGENCE"
            title="Recent threat indicators"
            detail="Synthetic examples"
          />
          <button
            type="button"
            className="text-button"
            onClick={onExplore}
          >
            View all <Icon name="chevron" size={16} />
          </button>
        </div>
        <IndicatorTable rows={indicators.slice(0, 5)} />
      </section>
    </>
  )
}

function IndicatorExplorer() {
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] =
    useState<'All' | Severity>('All')

  const filteredIndicators = useMemo(() => {
    const query = search.trim().toLowerCase()

    return indicators.filter((item) => {
      const matchesQuery =
        !query ||
        [
          item.value,
          item.type,
          item.source,
          item.family,
          item.id,
        ].some((value) => value.toLowerCase().includes(query))

      const matchesSeverity =
        severityFilter === 'All' ||
        item.severity === severityFilter

      return matchesQuery && matchesSeverity
    })
  }, [search, severityFilter])

  return (
    <section className="panel explorer-panel">
      <SectionHeading
        eyebrow="INDICATOR EXPLORER"
        title="Investigate threat signals"
        detail="Demo dataset"
      />
      <div className="explorer-toolbar">
        <label className="search-field">
          <Icon name="search" size={17} />
          <span className="sr-only">Search indicators</span>
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search indicator, malware, source..."
          />
        </label>
        <label className="select-field">
          <Icon name="filter" size={16} />
          <span className="sr-only">Filter by severity</span>
          <select
            value={severityFilter}
            onChange={(event) =>
              setSeverityFilter(
                event.target.value as 'All' | Severity
              )
            }
          >
            <option value="All">All severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </label>
      </div>
      <div className="result-count">
        Showing {filteredIndicators.length} of {indicators.length} sample
        indicators
      </div>
      <IndicatorTable rows={filteredIndicators} />
    </section>
  )
}

function AnalyticsPage() {
  return (
    <div className="placeholder-grid">
      <section className="panel feature-panel">
        <div className="feature-icon">
          <Icon name="activity" size={25} />
        </div>
        <div className="eyebrow">ANALYTICS WORKSPACE</div>
        <h2>Turn threat data into intelligence.</h2>
        <p>
          Threat activity, malware family rankings, indicator
          distribution, and source correlation will be connected
          to the existing analytics API in M8.3.
        </p>
        <span className="feature-status">API INTEGRATION PLANNED</span>
      </section>
      <section className="panel integration-panel">
        <SectionHeading
          eyebrow="AVAILABLE BACKEND CAPABILITIES"
          title="Analytics modules"
        />
        {[
          'Indicator distribution',
          'Malware family rankings',
          'Daily threat activity',
          'Cross-source correlation',
        ].map((name) => (
          <div className="integration-row" key={name}>
            <Icon name="check" size={15} />
            {name}
            <span>API ready</span>
          </div>
        ))}
      </section>
    </div>
  )
}

function SettingsPage() {
  return (
    <section className="panel feature-panel settings-panel">
      <div className="feature-icon">
        <Icon name="lock" size={25} />
      </div>
      <div className="eyebrow">SECURITY CONFIGURATION</div>
      <h2>Secure by design.</h2>
      <p>
        Keycloak authentication with Authorization Code + PKCE
        S256 will be integrated into the frontend in M8.2.
        This preview does not authenticate users or access
        protected API resources.
      </p>
      <div className="settings-facts">
        <div>
          <span>Identity provider</span>
          <strong>Keycloak</strong>
        </div>
        <div>
          <span>Login method</span>
          <strong>OIDC + PKCE S256</strong>
        </div>
        <div>
          <span>Frontend authentication</span>
          <strong>Not yet connected</strong>
        </div>
      </div>
    </section>
  )
}

function App() {
  const [activePage, setActivePage] = useState<Page>('overview')
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const currentLabel =
    navigation.find((item) => item.page === activePage)?.label ??
    'Overview'

  const navigate = (page: Page) => {
    setActivePage(page)
    setMobileMenuOpen(false)
  }

  return (
    <div className="app-shell">
      {mobileMenuOpen && (
        <button
          type="button"
          className="sidebar-backdrop"
          aria-label="Close navigation"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      <aside
        className={`sidebar ${mobileMenuOpen ? 'sidebar--open' : ''}`}
      >
        <div className="brand">
          <div className="brand-mark">
            <Icon name="shield" size={23} />
          </div>
          <div className="brand-text">
            <strong>
              THREAT<span>FORGE</span>
            </strong>
            <small>INTELLIGENCE PLATFORM</small>
          </div>
          <button
            type="button"
            className="mobile-close icon-button"
            aria-label="Close navigation"
            onClick={() => setMobileMenuOpen(false)}
          >
            <Icon name="close" />
          </button>
        </div>

        <div className="workspace-label">WORKSPACE</div>

        <nav className="sidebar-nav" aria-label="Main navigation">
          {navigation.map((item) => (
            <button
              key={item.page}
              type="button"
              className={`nav-item ${
                activePage === item.page ? 'nav-item--active' : ''
              }`}
              aria-current={
                activePage === item.page ? 'page' : undefined
              }
              onClick={() => navigate(item.page)}
            >
              <Icon name={item.icon} size={18} />
              <span>{item.label}</span>
              {activePage === item.page && (
                <Icon name="chevron" size={14} />
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="connection-card">
            <div className="connection-title">
              <span className="connection-indicator" />
              DEVELOPMENT MODE
            </div>
            <p>
              Interface preview using synthetic data.
              Live API integration is upcoming.
            </p>
            <div className="connection-footer">
              <Icon name="terminal" size={15} />
              M8.1 / FOUNDATION
            </div>
          </div>
          <div className="sidebar-version">
            <span>THREATFORGE</span>
            <span>v0.1.0</span>
          </div>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              type="button"
              className="mobile-toggle icon-button"
              aria-label="Open navigation"
              onClick={() => setMobileMenuOpen(true)}
            >
              <Icon name="menu" />
            </button>
            <span className="breadcrumb-muted">Workspace</span>
            <Icon name="chevron" size={14} />
            <span className="breadcrumb-current">{currentLabel}</span>
          </div>

          <div className="topbar-right">
            <span className="demo-pill">
              <span className="demo-pill-dot" />
              DEMO DATA
            </span>
            <div className="topbar-divider" />
            <div className="avatar" title="Frontend preview profile">
              TF
            </div>
          </div>
        </header>

        <main className="content">
          <div className="page-heading">
            <div>
              <div className="page-overline">
                SECURITY OPERATIONS / THREATFORGE
              </div>
              <h1>
                {activePage === 'overview'
                  ? 'Intelligence Overview'
                  : currentLabel}
              </h1>
              <p>
                {activePage === 'overview'
                  ? 'Monitor threats, analyze signals, and stay ahead of emerging risks.'
                  : activePage === 'indicators'
                    ? 'Explore and filter threat indicators in your intelligence workspace.'
                    : activePage === 'analytics'
                      ? 'Analyze activity and identify patterns across threat sources.'
                      : 'Manage identity and platform configuration.'}
              </p>
            </div>
            <div className="environment-tag">
              <Icon name="globe" size={15} />
              LOCAL ENVIRONMENT
            </div>
          </div>

          <div className="demo-notice">
            <Icon name="activity" size={16} />
            <span>
              <strong>Frontend preview.</strong> Metrics and
              indicator rows are illustrative. Live authenticated
              intelligence will be connected in M8.2–M8.3.
            </span>
          </div>

          {activePage === 'overview' && (
            <Overview onExplore={() => navigate('indicators')} />
          )}
          {activePage === 'indicators' && <IndicatorExplorer />}
          {activePage === 'analytics' && <AnalyticsPage />}
          {activePage === 'settings' && <SettingsPage />}

          <footer className="content-footer">
            <span>© 2026 ThreatForge · Intelligence Platform</span>
            <span>
              <span className="footer-dot" />
              DEVELOPMENT BUILD
            </span>
          </footer>
        </main>
      </div>
    </div>
  )
}

export default App
