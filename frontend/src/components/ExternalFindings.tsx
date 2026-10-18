import { ArrowRight, ChevronRight, Search, ShieldCheck, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Badge } from './Badge'
import { EmptyState } from './EmptyState'
import { formatDate, severityTone, statusLabel } from '../lib/scan-utils'
import type { ExternalNormalizedFinding, FindingResponse, ScanStatusResponse } from '../types'
import type { View } from './Sidebar'

type ExplorerFinding = FindingResponse | ExternalNormalizedFinding
const isExternal = (finding: ExplorerFinding): finding is ExternalNormalizedFinding => 'rule_id' in finding

function FindingRow({ finding, checkName, onClick }: { finding: ExplorerFinding; checkName?: string; onClick: () => void }) {
  const external = isExternal(finding)
  const metadata = external
    ? <><span className="finding-source">External · {finding.source}</span><span className="finding-code">Rule: {finding.rule_id}</span></>
    : <><span className="finding-code">{finding.code}</span>{checkName && <span className="finding-check">{statusLabel(checkName)}</span>}</>
  return <button className="finding-row finding-button" onClick={onClick}><span className={`severity-bar severity-${severityTone(finding.severity)}`} /><div className="finding-copy"><div><Badge tone={`severity-${severityTone(finding.severity)}`}>{finding.severity}</Badge>{metadata}</div><strong>{finding.title}</strong><p>{finding.description}</p></div><ChevronRight size={16} className="muted" /></button>
}

function FindingDetail({ finding, checkName, onClose }: { finding: ExplorerFinding; checkName?: string; onClose: () => void }) {
  const external = isExternal(finding)
  const details = external
    ? <dl className="detail-list"><div><dt>Source</dt><dd>{finding.source}</dd></div><div><dt>Tool</dt><dd>{finding.provenance.tool}</dd></div><div><dt>Rule</dt><dd>{finding.rule_id}</dd></div><div><dt>Adapter</dt><dd>{finding.provenance.adapter}</dd></div><div><dt>Confidence</dt><dd>{statusLabel(finding.confidence)}</dd></div>{finding.target && <div><dt>Target</dt><dd className="break-text">{finding.target}</dd></div>}{finding.provenance.tool_version && <div><dt>Tool version</dt><dd>{finding.provenance.tool_version}</dd></div>}{finding.provenance.api_version && <div><dt>API version</dt><dd>{finding.provenance.api_version}</dd></div>}{finding.provenance.source_alert_id && <div><dt>Source alert ID</dt><dd>{finding.provenance.source_alert_id}</dd></div>}{finding.provenance.observed_at && <div><dt>Observed</dt><dd>{formatDate(finding.provenance.observed_at)}</dd></div>}</dl>
    : <dl className="detail-list"><div><dt>Check</dt><dd>{checkName ? statusLabel(checkName) : 'API finding'}</dd></div><div><dt>Confidence</dt><dd>{statusLabel(finding.confidence)}</dd></div>{finding.target && <div><dt>Target</dt><dd className="break-text">{finding.target}</dd></div>}</dl>
  return <div className="finding-detail"><div className="detail-close-row"><p className="eyebrow">Finding detail</p><button className="icon-button" onClick={onClose} aria-label="Close finding details"><X size={16} /></button></div><Badge tone={`severity-${severityTone(finding.severity)}`}>{finding.severity} · {external ? 'External normalized finding' : statusLabel(finding.status)}</Badge><h2>{finding.title}</h2><p>{finding.description}</p>{details}{finding.remediation && <div className="remediation"><strong>Remediation</strong><p>{finding.remediation}</p></div>}{!external && finding.evidence && <div className="evidence"><strong>Safe evidence</strong><span>HTTP {finding.evidence.status_code ?? '—'} · {Object.keys(finding.evidence.headers).length} selected headers</span></div>}{external && <div className="evidence"><strong>Safe provenance</strong><span>Normalized metadata from the API; raw external-tool output is not shown.</span></div>}</div>
}

export function ExternalFindings({ scan, onNavigate }: { scan: ScanStatusResponse | null; onNavigate: (view: View) => void }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [status, setStatus] = useState('all')
  const [selected, setSelected] = useState<ExplorerFinding | null>(null)
  const findingCheck = useMemo(() => new Map((scan?.checks ?? []).flatMap((check) => check.findings.map((finding) => [`${finding.code}:${finding.title}`, check.name] as const))), [scan?.checks])
  const returned = useMemo(() => {
    if (!scan) return []
    const native = scan.findings
    const external = [...(scan.external_tools ?? []).flatMap((tool) => tool.findings ?? []), ...(scan.external_findings ?? [])]
    const seen = new Set<string>()
    return [...native, ...external].filter((finding) => {
      if (!isExternal(finding)) return true
      const key = `${finding.source}\u0000${finding.rule_id}\u0000${finding.target}\u0000${finding.title}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
  }, [scan])
  const findings = useMemo(() => returned.filter((finding) => {
    const needle = query.toLowerCase()
    const searchable = isExternal(finding) ? [finding.title, finding.description, finding.rule_id, finding.source, finding.target, finding.provenance.tool, finding.provenance.adapter] : [finding.title, finding.description, finding.code, finding.target ?? '', findingCheck.get(`${finding.code}:${finding.title}`) ?? '']
    return (!needle || searchable.some((value) => value.toLowerCase().includes(needle))) && (severity === 'all' || finding.severity.toLowerCase() === severity) && (status === 'all' || (isExternal(finding) ? status === 'open' : finding.status.toLowerCase() === status))
  }), [findingCheck, query, returned, severity, status])
  if (!scan) return <EmptyState title="No scan selected" description="Create an assessment to inspect findings." action={<button className="button button-primary" onClick={() => onNavigate('new-scan')}>Start a scan <ArrowRight size={15} /></button>} />
  const context = selected ? <FindingDetail finding={selected} checkName={isExternal(selected) ? undefined : findingCheck.get(`${selected.code}:${selected.title}`)} onClose={() => setSelected(null)} /> : <div className="finding-context"><p className="eyebrow">Review context</p><h2>Select a finding</h2><div className="legend-row"><span className="legend-dot" style={{ background: 'var(--red)' }} /><strong>Critical</strong><span>Immediate attention</span></div><div className="legend-row"><span className="legend-dot" style={{ background: 'var(--orange)' }} /><strong>High</strong><span>Prioritize soon</span></div><div className="legend-row"><span className="legend-dot" style={{ background: 'var(--yellow)' }} /><strong>Medium</strong><span>Review in context</span></div><div className="legend-row"><span className="legend-dot" style={{ background: 'var(--cyan)' }} /><strong>Low</strong><span>Track and improve</span></div><div className="legend-note"><ShieldCheck size={14} /> Findings are API-returned signals. External-tool entries show normalized source, rule, and provenance.</div></div>
  return <div className="findings-page"><div className="page-header"><div><p className="eyebrow">Signal review</p><h1>Findings explorer</h1><p className="page-description">Results returned for {scan.target_url}</p></div></div><div className="filter-bar"><div className="search-field"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings…" aria-label="Search findings" /></div><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by finding status"><option value="all">All statuses</option><option value="open">Open</option><option value="resolved">Resolved</option><option value="accepted">Accepted</option><option value="false_positive">False positive</option></select><span className="filter-count">{findings.length} shown · {returned.length} total</span></div><div className="findings-layout"><section className="panel findings-panel">{findings.length ? findings.map((finding) => <FindingRow key={`${isExternal(finding) ? finding.rule_id : finding.code}-${finding.title}`} finding={finding} checkName={isExternal(finding) ? undefined : findingCheck.get(`${finding.code}:${finding.title}`)} onClick={() => setSelected(finding)} />) : <EmptyState title="No matching findings" description={returned.length ? 'Try a different search or filter.' : 'The API has not returned any findings for this scan.'} />}</section><aside className="panel finding-legend">{context}</aside></div></div>
}
