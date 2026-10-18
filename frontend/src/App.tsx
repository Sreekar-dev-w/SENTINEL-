import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Activity, AlertTriangle, ArrowRight, Check, ChevronRight, CircleHelp, ClipboardCheck, Clock3, Download, ExternalLink, FileCheck2, Globe2, KeyRound, LockKeyhole, RefreshCw, Search, Server, ShieldCheck, Sparkles, Square, Target, X } from 'lucide-react'
import { cancelScan, createScan, getScan, getScanReportJson, getScanReportMarkdown } from './api'
import { Badge } from './components/Badge'
import { AssessmentView } from './components/AssessmentView'
import { EmptyState } from './components/EmptyState'
import { IntelligenceView } from './components/IntelligenceView'
import { ScanStatus } from './components/ScanStatus'
import { Sidebar, type View } from './components/Sidebar'
import { StatCard } from './components/StatCard'
import { Topbar } from './components/Topbar'
import { checkTone, formatDate, formatRelative, isTerminal, progressForScan, severityTone, statusLabel } from './lib/scan-utils'
import type { ApiError, CheckResponse, FindingResponse, ScanReport, ScanStatusResponse } from './types'
import './styles.css'

function errorMessage(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'message' in error) return String((error as ApiError).message)
  return 'Something went wrong. Please try again.'
}

function downloadReport(scanId: string, format: 'json' | 'markdown', content: string): void {
  const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `scan-${scanId}.${format === 'json' ? 'json' : 'md'}`
  link.click()
  URL.revokeObjectURL(url)
}

function reportJsonContent(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`
}

function useScanPolling(scan: ScanStatusResponse | null, onUpdate: (scan: ScanStatusResponse) => void, onError: (message: string) => void) {
  useEffect(() => {
    if (!scan || isTerminal(scan.status)) return
    let disposed = false
    const controller = new AbortController()
    const poll = async () => {
      try {
        const latest = await getScan(scan.id, controller.signal)
        if (!disposed) onUpdate(latest)
      } catch (error) {
        if (!disposed && !(error instanceof DOMException && error.name === 'AbortError')) onError(errorMessage(error))
      }
    }
    const timer = window.setInterval(() => void poll(), 2500)
    void poll()
    return () => { disposed = true; controller.abort(); window.clearInterval(timer) }
  }, [scan?.id, scan?.status, onError, onUpdate])
}

export default function App() {
  const [view, setView] = useState<View>('overview')
  const [scan, setScan] = useState<ScanStatusResponse | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [pollError, setPollError] = useState('')
  const [globalError, setGlobalError] = useState('')

  const onUpdate = useCallback((latest: ScanStatusResponse) => { setScan(latest); setPollError('') }, [])
  const onPollError = useCallback((message: string) => setPollError(message), [])
  useScanPolling(scan, onUpdate, onPollError)

  const handleCreated = (created: ScanStatusResponse) => {
    setScan(created); setGlobalError(''); setPollError(''); setView('detail')
  }

  return <div className="app-shell">
    <Sidebar view={view} onNavigate={setView} open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />
    <main className="main-content">
      <Topbar view={view} onNavigate={setView} />
      {globalError && <div className="alert alert-danger" role="alert"><AlertTriangle size={17} /><span>{globalError}</span><button onClick={() => setGlobalError('')} aria-label="Dismiss error"><X size={16} /></button></div>}
      {pollError && <div className="alert alert-warning" role="status"><RefreshCw size={17} /><span>Live refresh paused: {pollError}</span><button onClick={() => setPollError('')} aria-label="Dismiss polling warning"><X size={16} /></button></div>}
      <div className="page-wrap">
        {view === 'overview' && <Overview scan={scan} onNavigate={setView} />}
        {view === 'new-scan' && <NewScan onCreated={handleCreated} onError={setGlobalError} />}
        {view === 'history' && <History scan={scan} onNavigate={setView} />}
        {view === 'detail' && (scan ? <ScanDetail scan={scan} onUpdate={setScan} onNavigate={setView} onError={setGlobalError} /> : <NoScan onNavigate={setView} />)}
        {view === 'findings' && <Findings scan={scan} onNavigate={setView} />}
        {view === 'assessment' && <AssessmentView scan={scan} />}
        {view === 'intelligence' && <IntelligenceView scan={scan} />}
        {view === 'settings' && <Settings />}
        {view === 'about' && <About />}
      </div>
    </main>
  </div>
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-header"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="page-description">{description}</p></div>{action}</div>
}

function Overview({ scan, onNavigate }: { scan: ScanStatusResponse | null; onNavigate: (view: View) => void }) {
  const summary = scan?.summary
  const severityCount = summary?.findings_by_severity ?? {}
  return <>
    <PageHeader eyebrow="Security posture" title="Good morning, operator." description="A calm view of your authorized assessment workspace." action={<button className="button button-primary" onClick={() => onNavigate('new-scan')}><Target size={16} /> New scan <ArrowRight size={15} /></button>} />
    <section className="hero-card"><div className="hero-grid"><div><div className="hero-kicker"><span className="live-dot" /> LOCAL ASSESSMENT CONSOLE</div><h2>Know what your surface is saying.</h2><p>SENTINEL runs bounded, non-destructive checks against targets you are authorized to assess. Results stay focused, safe, and explainable.</p><button className="button button-secondary" onClick={() => onNavigate('about')}>How it works <ChevronRight size={15} /></button></div><div className="hero-orbit" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="orbit-core"><ShieldCheck size={28} /></div><span className="orbit-label orbit-label-one">SAFE</span><span className="orbit-label orbit-label-two">SCOPED</span></div></div></section>
    <div className="section-heading"><div><p className="eyebrow">Workspace pulse</p><h2>Assessment overview</h2></div>{scan && <button className="text-button" onClick={() => onNavigate('detail')}>Open latest scan <ArrowRight size={14} /></button>}</div>
    <div className="stats-grid">
      <StatCard label="Latest status" value={scan ? statusLabel(scan.status) : 'No scan'} detail={scan ? formatRelative(scan.created_at) : 'Ready for your first assessment'} icon={Activity} tone="cyan" />
      <StatCard label="Checks completed" value={summary ? `${summary.checks_completed}/${summary.checks_total}` : '—'} detail={summary ? 'Reported by the API' : 'No assessment data yet'} icon={FileCheck2} tone="violet" />
      <StatCard label="Findings" value={summary?.findings_total ?? '—'} detail={summary ? `${severityCount.high ?? 0} high · ${severityCount.critical ?? 0} critical` : 'Appears after a scan'} icon={AlertTriangle} tone="amber" />
      <StatCard label="Target scope" value={scan ? '1 URL' : '—'} detail={scan ? 'Single authorized origin' : 'No target selected'} icon={Globe2} tone="rose" />
    </div>
    <section className="dashboard-grid"><div className="panel panel-large"><div className="panel-heading"><div><p className="eyebrow">Latest activity</p><h2>{scan ? 'Current assessment' : 'No assessments yet'}</h2></div>{scan && <ScanStatus status={scan.status} />}</div>{scan ? <LatestScan scan={scan} onClick={() => onNavigate('detail')} /> : <EmptyState title="Start with an authorized target" description="Create a scan to see live progress, checks, and safe evidence here." action={<button className="button button-secondary" onClick={() => onNavigate('new-scan')}>Create first scan <ArrowRight size={15} /></button>} />}</div><div className="panel"><div className="panel-heading"><div><p className="eyebrow">Signal mix</p><h2>Findings by severity</h2></div><CircleHelp size={17} className="muted" /></div>{scan ? <SeverityBreakdown summary={summary} /> : <div className="muted-block">Severity data will appear after the API returns findings.</div>}</div></section>
  </>
}

function LatestScan({ scan, onClick }: { scan: ScanStatusResponse; onClick: () => void }) {
  return <button className="latest-scan" onClick={onClick}><div className="target-icon"><Globe2 size={19} /></div><div className="latest-main"><strong>{scan.target_url}</strong><span>Created {formatDate(scan.created_at)} · ID {scan.id.slice(0, 8)}…</span></div><div className="latest-result"><strong>{scan.summary.findings_total} finding{scan.summary.findings_total === 1 ? '' : 's'}</strong><span>{scan.summary.checks_completed}/{scan.summary.checks_total} checks</span></div><ChevronRight size={18} className="muted" /></button>
}

function SeverityBreakdown({ summary }: { summary?: ScanStatusResponse['summary'] }) {
  const values = [{ key: 'critical', label: 'Critical', color: 'var(--red)' }, { key: 'high', label: 'High', color: 'var(--orange)' }, { key: 'medium', label: 'Medium', color: 'var(--yellow)' }, { key: 'low', label: 'Low', color: 'var(--cyan)' }]
  const total = summary?.findings_total ?? 0
  return <div className="severity-list">{values.map((item) => { const value = summary?.findings_by_severity[item.key] ?? 0; return <div className="severity-row" key={item.key}><span className="severity-name"><i style={{ background: item.color }} />{item.label}</span><div className="severity-track"><span style={{ width: `${total ? (value / total) * 100 : 0}%`, background: item.color }} /></div><strong>{value}</strong></div> })}<div className="severity-total"><span>Total findings</span><strong>{total}</strong></div></div>
}

function NewScan({ onCreated, onError }: { onCreated: (scan: ScanStatusResponse) => void; onError: (message: string) => void }) {
  const [targetUrl, setTargetUrl] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('')
    if (!authorized) { setError('Confirm that you are authorized to assess this target.'); return }
    if (!targetUrl.trim()) { setError('Enter an HTTP or HTTPS target URL.'); return }
    setBusy(true)
    try { onCreated(await createScan({ target_url: targetUrl.trim(), authorization_confirmed: true })) }
    catch (requestError) { const message = errorMessage(requestError); setError(message); onError('Scan could not be created: ' + message) }
    finally { setBusy(false) }
  }
  return <><PageHeader eyebrow="Authorized assessment" title="Start a new scan" description="Define one target. SENTINEL will run bounded metadata checks and show progress as it happens." /><div className="form-layout"><form className="panel scan-form" onSubmit={submit}><div className="form-section"><div className="form-section-icon"><Target size={18} /></div><div><h2>Target scope</h2><p>Only one HTTP(S) origin is accepted per scan.</p></div></div><label className="field-label" htmlFor="target-url">Target URL</label><div className="input-wrap"><Globe2 size={17} /><input id="target-url" type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="https://authorized-target.example" autoComplete="url" /></div><p className="field-help">The API normalizes and validates the URL before any scan work begins.</p><label className={`confirm-box ${authorized ? 'checked' : ''}`}><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span className="checkmark"><Check size={13} /></span><span><strong>I confirm I am authorized to assess this target.</strong><small>Scanning systems without permission may be unlawful. This confirmation is sent with the request.</small></span></label>{error && <div className="form-error" role="alert"><AlertTriangle size={16} />{error}</div>}<button className="button button-primary button-wide" type="submit" disabled={busy || !authorized}>{busy ? <><RefreshCw size={16} className="spin" /> Creating scan…</> : <><ShieldCheck size={16} /> Create authorized scan</>}</button></form><aside className="panel guidance"><p className="eyebrow">What happens next</p><h2>Small, observable steps.</h2><div className="guidance-item"><span>01</span><div><strong>Validate</strong><p>Target URL and authorization are checked at the API boundary.</p></div></div><div className="guidance-item"><span>02</span><div><strong>Assess</strong><p>A bounded GET and metadata-only security checks run in the worker.</p></div></div><div className="guidance-item"><span>03</span><div><strong>Explain</strong><p>Safe evidence and remediation guidance are returned with findings.</p></div></div></aside></div></>
}

function NoScan({ onNavigate }: { onNavigate: (view: View) => void }) { return <EmptyState title="No scan selected" description="Create an assessment to inspect its live status and findings." action={<button className="button button-primary" onClick={() => onNavigate('new-scan')}>Start a scan <ArrowRight size={15} /></button>} /> }

function History({ scan, onNavigate }: { scan: ScanStatusResponse | null; onNavigate: (view: View) => void }) {
  return <>
    <PageHeader eyebrow="Session archive" title="Scan history" description="The current API exposes one scan at a time; persistent history is not implemented in v0.1." />
    <section className="panel history-panel">
      {scan ? <LatestScan scan={scan} onClick={() => onNavigate('detail')} /> : <EmptyState title="No scans in this session" description="Start an authorized scan to create the first in-memory record." action={<button className="button button-secondary" onClick={() => onNavigate('new-scan')}>Create first scan <ArrowRight size={15} /></button>} />}
      <div className="history-note"><Clock3 size={15} /><span>Scan records live in backend memory and disappear when the API process restarts. This view does not invent historical data.</span></div>
    </section>
  </>
}

function ScanDetail({ scan, onUpdate, onNavigate, onError }: { scan: ScanStatusResponse; onUpdate: (scan: ScanStatusResponse) => void; onNavigate: (view: View) => void; onError: (message: string) => void }) {
  const [cancelling, setCancelling] = useState(false)
  const [exporting, setExporting] = useState<'json' | 'markdown' | null>(null)
  const canCancel = !isTerminal(scan.status)
  const canExport = scan.status.toLowerCase() === 'completed'
  const handleCancel = async () => {
    if (!window.confirm('Cancel this scan? The API will mark it cancelled when the request is accepted.')) return
    setCancelling(true)
    try { onUpdate(await cancelScan(scan.id)) } catch (error) { onError('Unable to cancel scan: ' + errorMessage(error)) } finally { setCancelling(false) }
  }
  const handleExport = async (format: 'json' | 'markdown') => {
    if (!canExport) return
    setExporting(format)
    try {
      if (format === 'json') {
        const report = await getScanReportJson(scan.id)
        downloadReport(scan.id, format, reportJsonContent(report))
      } else {
        const report = await getScanReportMarkdown(scan.id)
        downloadReport(scan.id, format, report)
      }
    } catch (error) {
      onError(`Unable to export ${format === 'json' ? 'JSON' : 'Markdown'} report: ${errorMessage(error)}`)
    } finally {
      setExporting(null)
    }
  }
  const progress = progressForScan(scan)
  return <>
    <PageHeader eyebrow="Live assessment" title="Scan detail" description={scan.target_url} action={<div className="header-actions">{canCancel && <button className="button button-danger-ghost" onClick={() => void handleCancel()} disabled={cancelling}>{cancelling ? <RefreshCw size={15} className="spin" /> : <Square size={14} fill="currentColor" />} {cancelling ? 'Cancelling…' : 'Cancel scan'}</button>}<button className="button button-secondary" onClick={() => onNavigate('findings')}><FileCheck2 size={15} /> View findings</button><button className="button button-secondary" onClick={() => onNavigate('assessment')}><ClipboardCheck size={15} /> Assessment</button><button className="button button-secondary" onClick={() => onNavigate('intelligence')}><Sparkles size={15} /> Intelligence</button><button className="button button-secondary export-button" onClick={() => void handleExport('json')} disabled={!canExport || exporting !== null}><Download size={15} /> {exporting === 'json' ? 'Exporting…' : 'Export JSON'}</button><button className="button button-secondary export-button" onClick={() => void handleExport('markdown')} disabled={!canExport || exporting !== null}><Download size={15} /> {exporting === 'markdown' ? 'Exporting…' : 'Export Markdown'}</button></div>} />
    <section className="detail-hero panel"><div className="detail-summary"><div className="detail-target-icon"><Globe2 size={25} /></div><div><p className="eyebrow">Authorized target</p><h2>{scan.target_url}</h2><span className="mono">{scan.id}</span></div><ScanStatus status={scan.status} /></div><div className="progress-line"><div className="progress-meta"><span>{isTerminal(scan.status) ? 'Assessment complete' : 'Assessment in progress'}</span><strong>{progress}%</strong></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div><div className="detail-meta"><span><Clock3 size={14} /> Created {formatDate(scan.created_at)}</span><span><LockKeyhole size={14} /> Authorization confirmed</span><span><Server size={14} /> API-reported state</span></div></section>
    <div className="detail-grid">
      <section className="panel"><div className="panel-heading"><div><p className="eyebrow">Execution timeline</p><h2>Security checks</h2></div><span className="muted small-text">{scan.summary.checks_completed} of {scan.summary.checks_total}</span></div>{scan.checks.length ? <div className="checks-list">{scan.checks.map((check) => <CheckRow key={check.name} check={check} />)}</div> : <EmptyState title="Waiting for checks" description="The API has accepted this scan. Check results will appear as the worker reports them." />}</section>
      <section className="panel"><div className="panel-heading"><div><p className="eyebrow">Safe output</p><h2>Findings</h2></div><button className="text-button" onClick={() => onNavigate('findings')}>Explore <ArrowRight size={14} /></button></div>{scan.findings.length ? <div className="finding-preview">{scan.findings.slice(0, 4).map((finding) => <FindingRow finding={finding} key={`${finding.code}-${finding.title}`} />)}</div> : <EmptyState title={isTerminal(scan.status) ? 'No findings returned' : 'No findings yet'} description={isTerminal(scan.status) ? 'The API reported no findings for this assessment.' : 'Findings will appear as checks complete.'} />}</section>
    </div>
    {scan.error && <div className="alert alert-danger detail-error"><AlertTriangle size={17} /><span>{scan.error}</span></div>}
  </>
}

function CheckRow({ check }: { check: CheckResponse }) { const tone = checkTone(check); const Icon = tone === 'done' ? Check : tone === 'failed' ? X : tone === 'running' ? RefreshCw : Clock3; return <div className="check-row"><span className={`check-icon check-${tone}`}><Icon size={15} className={tone === 'running' ? 'spin' : ''} /></span><div><strong>{check.name}</strong><span>{check.error ?? (check.findings.length ? `${check.findings.length} finding${check.findings.length === 1 ? '' : 's'}` : statusLabel(check.status))}</span></div><span className="check-status">{statusLabel(check.status)}</span></div> }

function FindingRow({ finding, onClick, checkName }: { finding: FindingResponse; onClick?: () => void; checkName?: string }) { const Tag = onClick ? 'button' : 'div'; return <Tag className={`finding-row ${onClick ? 'finding-button' : ''}`} onClick={onClick}><span className={`severity-bar severity-${severityTone(finding.severity)}`} /><div className="finding-copy"><div><Badge tone={`severity-${severityTone(finding.severity)}`}>{finding.severity}</Badge><span className="finding-code">{finding.code}</span>{checkName && <span className="finding-check">{statusLabel(checkName)}</span>}</div><strong>{finding.title}</strong><p>{finding.description}</p></div>{onClick && <ChevronRight size={16} className="muted" />}</Tag> }

function Findings({ scan, onNavigate }: { scan: ScanStatusResponse | null; onNavigate: (view: View) => void }) {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [check, setCheck] = useState('all')
  const [status, setStatus] = useState('all')
  const [selected, setSelected] = useState<FindingResponse | null>(null)
  const findingCheck = useMemo(() => new Map((scan?.checks ?? []).flatMap((item) => item.findings.map((finding) => [`${finding.code}:${finding.title}`, item.name] as const))), [scan?.checks])
  const checkOptions = useMemo(() => [...new Set((scan?.checks ?? []).filter((item) => item.findings.length).map((item) => item.name))], [scan?.checks])
  const findings = useMemo(() => (scan?.findings ?? []).filter((finding) => {
    const needle = query.toLowerCase()
    const checkName = findingCheck.get(`${finding.code}:${finding.title}`) ?? ''
    const matchesQuery = !needle || [finding.title, finding.description, finding.code, finding.target ?? '', checkName].some((value) => value.toLowerCase().includes(needle))
    const matchesSeverity = severity === 'all' || finding.severity.toLowerCase() === severity
    const matchesCheck = check === 'all' || checkName === check
    const matchesStatus = status === 'all' || finding.status.toLowerCase() === status
    return matchesQuery && matchesSeverity && matchesCheck && matchesStatus
  }), [query, scan?.findings, findingCheck, severity, check, status])
  return <><PageHeader eyebrow="Signal review" title="Findings explorer" description={scan ? `Results returned for ${scan.target_url}` : 'Findings are scoped to the latest scan returned by the API.'} action={scan ? <ScanStatus status={scan.status} /> : undefined} />{scan ? <><div className="filter-bar"><div className="search-field"><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings…" aria-label="Search findings" /></div><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select value={check} onChange={(event) => setCheck(event.target.value)} aria-label="Filter by check"><option value="all">All checks</option>{checkOptions.map((option) => <option value={option} key={option}>{statusLabel(option)}</option>)}</select><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by finding status"><option value="all">All statuses</option><option value="open">Open</option><option value="resolved">Resolved</option><option value="accepted">Accepted</option><option value="false_positive">False positive</option></select><span className="filter-count">{findings.length} shown · {scan.findings.length} total</span></div><div className="findings-layout"><section className="panel findings-panel">{findings.length ? findings.map((finding) => <FindingRow finding={finding} checkName={findingCheck.get(`${finding.code}:${finding.title}`)} key={`${finding.code}-${finding.title}`} onClick={() => setSelected(finding)} />) : <EmptyState title="No matching findings" description={scan.findings.length ? 'Try a different search or filter.' : 'The API has not returned any findings for this scan.'} />}</section><aside className="panel finding-legend">{selected ? <FindingDetail finding={selected} checkName={findingCheck.get(`${selected.code}:${selected.title}`)} onClose={() => setSelected(null)} /> : <><p className="eyebrow">Severity guide</p><h2>Prioritize clearly.</h2>{[['critical', 'Immediate attention'], ['high', 'Address soon'], ['medium', 'Review and plan'], ['low', 'Informational']].map(([key, label]) => <div className="legend-row" key={key}><span className={`legend-dot severity-${severityTone(key)}`} /><strong>{key}</strong><span>{label}</span></div>)}<div className="legend-note"><LockKeyhole size={15} /> Evidence is limited to safe response metadata.</div></>}</aside></div></> : <NoScan onNavigate={onNavigate} />}</>
}

function FindingDetail({ finding, checkName, onClose }: { finding: FindingResponse; checkName?: string; onClose: () => void }) {
  return <div className="finding-detail"><div className="detail-close-row"><p className="eyebrow">Finding detail</p><button className="icon-button" onClick={onClose} aria-label="Close finding details"><X size={16} /></button></div><Badge tone={`severity-${severityTone(finding.severity)}`}>{finding.severity} · {statusLabel(finding.status)}</Badge><h2>{finding.title}</h2><p>{finding.description}</p><dl className="detail-list"><div><dt>Check</dt><dd>{checkName ? statusLabel(checkName) : 'API finding'}</dd></div><div><dt>Confidence</dt><dd>{statusLabel(finding.confidence)}</dd></div>{finding.target && <div><dt>Target</dt><dd className="break-text">{finding.target}</dd></div>}</dl>{finding.remediation && <div className="remediation"><strong>Remediation</strong><p>{finding.remediation}</p></div>}{finding.evidence && <div className="evidence"><strong>Safe evidence</strong><span>HTTP {finding.evidence.status_code ?? '—'} · {Object.keys(finding.evidence.headers).length} selected headers</span></div>}</div>
}

function Settings() { return <><PageHeader eyebrow="Workspace configuration" title="Settings" description="A transparent view of how this local frontend connects to SENTINEL." /><div className="settings-grid"><section className="panel"><div className="setting-heading"><div className="setting-icon"><Globe2 size={18} /></div><div><p className="eyebrow">Connection</p><h2>API endpoint</h2></div></div><div className="setting-value"><span>{import.meta.env.VITE_API_BASE_URL?.trim() || 'Same origin'}</span><Badge tone="success" dot>Configured</Badge></div><p className="setting-description">Set <code>VITE_API_BASE_URL</code> at build time to point at a different FastAPI origin. The default uses the browser's current origin.</p></section><section className="panel"><div className="setting-heading"><div className="setting-icon violet"><RefreshCw size={18} /></div><div><p className="eyebrow">Live updates</p><h2>Polling behavior</h2></div></div><div className="setting-value"><span>Every 2.5 seconds</span><Badge tone="neutral">GET /scans/:id</Badge></div><p className="setting-description">Polling stops when a scan reaches completed, failed, or cancelled, and when the detail view unmounts.</p></section><section className="panel"><div className="setting-heading"><div className="setting-icon amber"><KeyRound size={18} /></div><div><p className="eyebrow">Data boundary</p><h2>Authorization</h2></div></div><div className="setting-value"><span>Explicit confirmation</span><Badge tone="warning">Required</Badge></div><p className="setting-description">Every create request includes <code>authorization_confirmed: true</code> only after you check the confirmation box.</p></section><section className="panel"><div className="setting-heading"><div className="setting-icon rose"><ShieldCheck size={18} /></div><div><p className="eyebrow">Scope</p><h2>Safe by design</h2></div></div><div className="setting-value"><span>Metadata-only results</span><Badge tone="success">v0.1 API</Badge></div><p className="setting-description">This interface renders the API's safe evidence fields and never receives or displays response bodies, cookies, or authorization headers.</p></section></div></> }

function About() { return <><PageHeader eyebrow="Product notes" title="About SENTINEL" description="A focused console for authorized, non-destructive web vulnerability assessment." /><div className="about-layout"><section className="panel about-main"><div className="about-logo"><div className="brand-mark"><ShieldCheck size={26} /></div><div><strong>SENTINEL</strong><span>SECURITY OPERATIONS</span></div></div><h2>Clarity over noise.</h2><p>SENTINEL gives operators a restrained, explainable view of a target's security signals. It keeps the scope explicit, the lifecycle visible, and the evidence safe.</p><div className="principles"><div><span>01</span><strong>Authorized</strong><p>Every assessment starts with an explicit confirmation of permission.</p></div><div><span>02</span><strong>Bounded</strong><p>The backend owns request limits, scope enforcement, and scan deadlines.</p></div><div><span>03</span><strong>Truthful</strong><p>This dashboard only shows data returned by the existing API routes.</p></div></div></section><aside className="panel about-side"><p className="eyebrow">API surface</p><h2>Three focused routes.</h2>{['POST /scans', 'GET /scans/{scan_id}', 'POST /scans/{scan_id}/cancel'].map((route) => <div className="route-row" key={route}><span className="route-dot" /><code>{route}</code></div>)}<div className="about-note"><ExternalLink size={15} /> Built to pair with the SENTINEL FastAPI service.</div></aside></div></> }
