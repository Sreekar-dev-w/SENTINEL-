import { AlertTriangle, CheckCircle2, FileText, Globe2, Info, Network, Search, Server, Shield, Sparkles, XCircle } from 'lucide-react'
import { useMemo, useState } from 'react'
import { EmptyState } from './EmptyState'
import { Badge } from './Badge'
import { statusLabel } from '../lib/scan-utils'
import type { IntelligenceObservation, IntelligenceResource, ScanStatusResponse } from '../types'

type SectionKey = 'domain' | 'http' | 'redirects' | 'dns' | 'infrastructure' | 'technologies' | 'resources' | 'forms'

const sectionLabels: Record<SectionKey, string> = {
  domain: 'Domain',
  http: 'HTTP',
  redirects: 'Redirects',
  dns: 'DNS',
  infrastructure: 'Infrastructure',
  technologies: 'Technologies',
  resources: 'Resources',
  forms: 'Forms',
}

function safeText(value: unknown, fallback = '—'): string {
  if (typeof value === 'string' && value.trim()) return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return fallback
}

function valueMap(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

function sectionForObservation(item: IntelligenceObservation): SectionKey {
  if (item.kind.startsWith('domain.')) return 'domain'
  if (item.kind.startsWith('http.redirect')) return 'redirects'
  if (item.kind.startsWith('http.')) return 'http'
  if (item.kind.startsWith('dns.')) return 'dns'
  if (item.kind.startsWith('infrastructure.')) return 'infrastructure'
  if (item.kind.startsWith('technology.')) return 'technologies'
  return 'http'
}

function Evidence({ item }: { item: IntelligenceObservation | IntelligenceResource }) {
  if (!item.evidence) return null
  return <div className="intelligence-evidence"><FileText size={12} /><span>{item.evidence.status_code ?? '—'} · {Object.keys(item.evidence.headers).join(', ') || 'safe metadata'}</span></div>
}

function Provenance({ item }: { item: IntelligenceObservation | IntelligenceResource }) {
  const inferred = item.mode.toLowerCase() === 'inferred'
  return <div className="intelligence-provenance"><span className={`intelligence-origin ${inferred ? 'inferred' : ''}`}>{inferred ? <Sparkles size={12} /> : <CheckCircle2 size={12} />}{statusLabel(item.mode)} · {statusLabel(item.confidence)}</span><Badge tone={item.status === 'error' ? 'danger' : item.status === 'limited' || item.status === 'inconclusive' ? 'warning' : 'neutral'}>{statusLabel(item.status)}</Badge></div>
}

function ObservationCard({ item }: { item: IntelligenceObservation }) {
  const values = valueMap(item.value)
  const Icon = item.kind.startsWith('dns.') ? Network : item.kind.startsWith('technology.') ? Shield : item.kind.startsWith('infrastructure.') ? Server : Globe2
  return <article className="intelligence-card"><div className="intelligence-card-title"><Icon size={16} /><h3>{statusLabel(item.kind.replace('.', ' · '))}</h3></div><dl className="intelligence-values">{Object.entries(values).map(([key, value]) => <div className="intelligence-value" key={key}><dt>{statusLabel(key)}</dt><dd className="break-text">{Array.isArray(value) ? value.join(', ') : safeText(value)}</dd></div>)}{!Object.keys(values).length && <div className="intelligence-value"><dt>Status</dt><dd>{statusLabel(item.status)}</dd></div>}</dl><Provenance item={item} /><Evidence item={item} /></article>
}

function ResourceCard({ item }: { item: IntelligenceResource }) {
  return <article className="intelligence-card"><div className="intelligence-card-title"><FileText size={16} /><h3>{statusLabel(item.kind)}</h3></div><dl className="intelligence-values"><div className="intelligence-value"><dt>URL</dt><dd className="break-text">{item.url}</dd></div><div className="intelligence-value"><dt>Depth</dt><dd>{item.depth}</dd></div>{item.method && <div className="intelligence-value"><dt>Method</dt><dd>{item.method}</dd></div>}{item.fields.length > 0 && <div className="intelligence-value"><dt>Fields</dt><dd>{item.fields.join(', ')}</dd></div>}{item.source_url && <div className="intelligence-value"><dt>Source</dt><dd className="break-text">{item.source_url}</dd></div>}</dl><Provenance item={item} /><Evidence item={item} /></article>
}

function sectionMatches(section: SectionKey, query: string, observations: IntelligenceObservation[], resources: IntelligenceResource[]): boolean {
  if (!query) return true
  const needle = query.toLowerCase()
  const items = section === 'resources' || section === 'forms' ? resources.filter((item) => section === 'forms' ? item.kind === 'form' : item.kind !== 'form') : observations.filter((item) => sectionForObservation(item) === section)
  return items.some((item) => JSON.stringify(item).toLowerCase().includes(needle))
}

function Banner({ intelligence }: { intelligence: NonNullable<ScanStatusResponse['intelligence']> }) {
  const partial = intelligence.status === 'inconclusive' || intelligence.summary.partial
  const failed = intelligence.status === 'error'
  const Icon = failed ? XCircle : partial ? AlertTriangle : intelligence.status === 'observed' ? CheckCircle2 : Info
  const tone = failed ? 'danger' : partial ? 'warning' : intelligence.status === 'observed' ? 'success' : 'running'
  return <div className={`intelligence-banner ${tone}`} role={failed ? 'alert' : 'status'}><Icon size={17} /><div><strong>{statusLabel(intelligence.status)}</strong><span>{failed ? (intelligence.error ?? 'The optional collector failed without changing the v0.1 scan result.') : partial ? 'Some bounded discovery work was limited or inconclusive.' : 'Values below are API-reported observations; inferred values are labeled.'}</span></div></div>
}

export function IntelligenceView({ scan }: { scan: ScanStatusResponse | null }) {
  const [query, setQuery] = useState('')
  const [section, setSection] = useState<'all' | SectionKey>('all')
  const intelligence = scan?.intelligence
  const observations = intelligence?.observations ?? []
  const resources = intelligence?.resources ?? []
  const sections = useMemo(() => Object.keys(sectionLabels) as SectionKey[], [])

  if (!scan) return <EmptyState title="No scan selected" description="Create an assessment to inspect its intelligence profile." />
  if (!intelligence) return <><div className="page-header"><div><p className="eyebrow">Surface intelligence</p><h1>Intelligence profile</h1><p className="page-description">Optional v0.2 observations for {scan.target_url}</p></div></div><EmptyState title="Intelligence is not available" description="This older v0.1 scan has no intelligence profile. The dashboard only displays data returned by the API." /></>

  const visible = sections.filter((key) => (section === 'all' || key === section) && sectionMatches(key, query, observations, resources))
  const hasData = observations.length > 0 || resources.length > 0
  return <><div className="page-header"><div><p className="eyebrow">Surface intelligence</p><h1>Intelligence profile</h1><p className="page-description">Bounded observations returned for {scan.target_url}</p></div><span className="intelligence-version"><Sparkles size={14} /> v0.2 profile</span></div><Banner intelligence={intelligence} /><div className="intelligence-summary"><div className="intelligence-summary-item"><strong>{intelligence.summary.pages_scanned}</strong><span>Pages scanned</span></div><div className="intelligence-summary-item"><strong>{intelligence.summary.resources_discovered}</strong><span>Resources found</span></div><div className="intelligence-summary-item"><strong>{intelligence.summary.cross_origin_blocked}</strong><span>Cross-origin blocked</span></div><div className="intelligence-summary-item"><strong>{intelligence.summary.observations_total}</strong><span>Observations</span></div></div><div className="filter-bar intelligence-filter"><div className="search-field"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search intelligence…" aria-label="Search intelligence" /></div><select value={section} onChange={(event) => setSection(event.target.value as 'all' | SectionKey)} aria-label="Filter intelligence sections"><option value="all">All sections</option>{sections.map((key) => <option value={key} key={key}>{sectionLabels[key]}</option>)}</select><span className="filter-count">{hasData ? `${visible.length} sections · no bodies retained` : 'No observations'}</span></div>{!hasData ? <EmptyState title="No intelligence observations" description="The collector completed without returning safe observations." /> : !visible.length ? <EmptyState title="No matching intelligence" description="Try a different search or section filter." /> : <div className="intelligence-sections">{visible.map((key) => { const items = key === 'resources' || key === 'forms' ? resources.filter((item) => key === 'forms' ? item.kind === 'form' : item.kind !== 'form') : observations.filter((item) => sectionForObservation(item) === key); return <section className="intelligence-section" key={key}><div className="intelligence-section-heading"><div><p className="eyebrow">API-reported surface</p><h2>{sectionLabels[key]}</h2></div><span className="muted small-text">{items.length} item{items.length === 1 ? '' : 's'}</span></div><div className="intelligence-cards">{items.map((item) => 'kind' in item && 'url' in item ? <ResourceCard item={item} key={`${item.kind}-${item.url}-${item.depth}`} /> : <ObservationCard item={item} key={`${item.kind}-${JSON.stringify(item.value)}`} />)}</div></section>})}</div>}</>
}
