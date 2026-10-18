import { AlertTriangle, CheckCircle2, Circle, FileText, Gauge, ListChecks, ShieldCheck, XCircle } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Badge } from './Badge'
import { EmptyState } from './EmptyState'
import { severityTone, statusLabel } from '../lib/scan-utils'
import type { AssessmentFinding, AssessmentModule, AssessmentResponse, ScanStatusResponse } from '../types'

type FindingFilter = 'all' | 'severity' | 'verification' | 'module' | 'owasp'

function text(value: string | null | undefined): string {
  return value && value.trim() ? value : ''
}

function moduleKey(module: AssessmentModule): string {
  return text(module.module) || text(module.id) || text(module.key) || text(module.name) || text(module.label)
}

function moduleLabel(module: AssessmentModule): string {
  return text(module.label) || text(module.name) || text(module.module) || text(module.key) || text(module.id) || 'Unnamed module'
}

function findingModule(finding: AssessmentFinding): string {
  return text(finding.module_name) || text(finding.module) || text(finding.module_id)
}

function findingVerification(finding: AssessmentFinding): string {
  return text(finding.verification_state) || text(finding.verification)
}

function findingOwasp(finding: AssessmentFinding): string {
  return text(finding.owasp_category) || text(finding.owasp) || text(finding.owasp_id)
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'running' | 'neutral' {
  const value = status.toLowerCase()
  if (['failed', 'error'].includes(value)) return 'danger'
  if (['partial', 'cancelled', 'canceled', 'skipped', 'not_run', 'not-run', 'unavailable'].includes(value)) return 'warning'
  if (['running', 'pending', 'queued', 'in_progress', 'in-progress'].includes(value)) return 'running'
  if (['completed', 'complete', 'passed', 'done'].includes(value)) return 'success'
  return 'neutral'
}

function assessmentState(scan: ScanStatusResponse, assessment: AssessmentResponse): string {
  return scan.status.toLowerCase() === 'completed' ? (text(assessment.status) || scan.status) : scan.status
}

function StateBanner({ scan, assessment }: { scan: ScanStatusResponse; assessment: AssessmentResponse }) {
  const state = assessmentState(scan, assessment)
  const normalized = state.toLowerCase()
  const failed = normalized === 'failed' || normalized === 'error'
  const cancelled = normalized === 'cancelled' || normalized === 'canceled'
  const partial = normalized === 'partial' || assessment.partial === true
  const running = ['running', 'pending', 'queued', 'in_progress', 'in-progress'].includes(normalized)
  const unavailable = normalized === 'unavailable' || normalized === 'skipped'
  const Icon = failed ? XCircle : cancelled ? Circle : partial ? AlertTriangle : running ? Gauge : CheckCircle2
  const message = failed
    ? assessment.error || scan.error || 'The API reported that the assessment failed.'
    : cancelled
      ? assessment.error || scan.error || 'The API reported that the assessment was cancelled before completion.'
      : partial
        ? 'The API returned a partial assessment. Skipped and not-run work is shown below when explained by the API.'
        : running
          ? 'The API is still running this assessment. Results may be incomplete until it reaches a terminal state.'
          : unavailable
            ? 'The API reported that assessment coverage is unavailable or skipped; no results are inferred.'
            : 'Values below are assessment data returned by the API.'
  return <div className={`assessment-banner ${statusTone(state)}`} role={failed ? 'alert' : 'status'}><Icon size={17} /><div><strong>{statusLabel(state)}</strong><span>{message}</span></div></div>
}

function Profile({ assessment }: { assessment: AssessmentResponse }) {
  const profile = assessment.profile
  const profileFields = typeof profile === 'string'
    ? [{ label: 'Profile', value: profile }]
      : profile
        ? [{ label: 'Profile', value: profile.name }, { label: 'Version', value: profile.version }, { label: 'Identifier', value: profile.id }, { label: 'Description', value: profile.description }]
          .filter((item) => Boolean(text(item.value)))
        : []
  const fields = profileFields.length > 0 ? profileFields : [
    { label: 'Profile', value: assessment.profile_id },
    { label: 'Version', value: assessment.profile_version },
  ].filter((item) => Boolean(text(item.value)))
  const enabled = assessment.enabled_modules ?? (typeof profile === 'object' && profile ? profile.enabled_modules ?? [] : [])
  if (!fields.length && !enabled.length) return null
  return <section className="panel assessment-profile"><div className="panel-heading"><div><p className="eyebrow">Assessment profile</p><h2>Scope and enabled modules</h2></div><ShieldCheck size={17} className="muted" /></div><div className="assessment-profile-grid">{fields.map((field) => <div key={field.label}><span>{field.label}</span><strong className="break-text">{field.value}</strong></div>)}{enabled.length > 0 && <div className="assessment-enabled"><span>Enabled modules</span><div>{enabled.map((item, index) => { const value = typeof item === 'string' ? item : moduleLabel(item); return <Badge tone="neutral" key={`${value}-${index}`}>{value}</Badge> })}</div></div>}</div></section>
}

function ModuleCard({ module }: { module: AssessmentModule }) {
  const label = moduleLabel(module)
  const state = text(module.status)
  const hasProgress = typeof module.progress === 'number' || typeof module.progress_percent === 'number'
  const hasChecks = typeof module.checks_completed === 'number' || typeof module.checks_total === 'number'
  const progressValue = module.progress ?? module.progress_percent
  const progress = hasProgress ? Math.max(0, Math.min(100, progressValue as number)) : null
  const reason = text(module.skip_reason) || text(module.not_run_reason) || text(module.status_reason) || text(module.error)
  return <article className="assessment-module"><div className="assessment-module-heading"><div><h3>{label}</h3>{(module.test_id || module.id) && <span className="mono break-text">{module.test_id || module.id}</span>}</div>{state && <Badge tone={statusTone(state)}>{statusLabel(state)}</Badge>}</div>{(module.test_version || module.impact || module.execution_mode) && <div className="assessment-module-meta"><span>{module.test_version ? `Test ${module.test_version}` : module.impact || module.execution_mode}</span><strong>{module.impact || module.execution_mode || ''}</strong></div>}{hasProgress && <div className="assessment-progress"><div><span>Progress</span><strong>{progress}%</strong></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div>}{hasChecks && <div className="assessment-module-meta"><span>Checks</span><strong>{module.checks_completed ?? 0}/{module.checks_total ?? 0}</strong></div>}{typeof module.findings_total === 'number' && <div className="assessment-module-meta"><span>Findings</span><strong>{module.findings_total}</strong></div>}{reason && <p className="assessment-reason">{reason}</p>}</article>
}

function Modules({ assessment }: { assessment: AssessmentResponse }) {
  const modules = assessment.modules ?? []
  if (!modules.length) return null
  return <section className="panel assessment-modules"><div className="panel-heading"><div><p className="eyebrow">Module execution</p><h2>Assessment modules</h2></div><ListChecks size={17} className="muted" /></div><div className="assessment-module-grid">{modules.map((module, index) => <ModuleCard key={`${moduleKey(module) || 'module'}-${index}`} module={module} />)}</div></section>
}

function Coverage({ assessment, scan }: { assessment: AssessmentResponse; scan: ScanStatusResponse }) {
  const coverage = assessment.coverage ?? scan.coverage
  const moduleExplanations = (assessment.modules ?? [])
    .filter((module) => module.status && !['completed', 'complete', 'passed', 'done'].includes(module.status.toLowerCase()))
    .map((module) => {
      const reason = text(module.skip_reason) || text(module.not_run_reason) || text(module.status_reason) || text(module.error)
      return reason ? `${moduleLabel(module)}: ${reason}` : ''
    })
    .filter(Boolean)
  const explanations = [...(coverage?.skipped_reasons ?? []), ...(coverage?.not_run_reasons ?? []), ...(assessment.skipped ?? []), ...(assessment.not_run ?? []), ...moduleExplanations]
    .map((item) => typeof item === 'string' ? item : [item.module, item.reason].filter(Boolean).join(': '))
    .filter(Boolean)
  if (!coverage && !explanations.length) return null
  const values = [
    ['Applicable tests', coverage?.applicable_tests],
    ['Passed tests', coverage?.passed_tests],
    ['Total modules', coverage?.total ?? coverage?.total_modules],
    ['Completed', coverage?.covered ?? coverage?.completed ?? coverage?.completed_modules],
    ['Total checks', coverage?.total_checks],
    ['Covered checks', coverage?.covered_checks],
    ['Skipped', coverage?.skipped ?? coverage?.skipped_modules ?? coverage?.skipped_checks],
    ['Not run', coverage?.not_run ?? coverage?.not_run_checks],
    ['Unavailable', coverage?.unavailable_modules],
    ['Errors', coverage?.error_modules],
    ['Execution failures', coverage?.execution_failures],
    ['Confirmed findings', coverage?.confirmed_findings],
    ['Potential findings', coverage?.potential_findings],
    ['Informational observations', coverage?.informational_observations],
    ['Findings', coverage?.findings_total],
    ['Observations', coverage?.observations_total],
  ].filter((item) => typeof item[1] === 'number')
  return <section className="panel assessment-coverage"><div className="panel-heading"><div><p className="eyebrow">Coverage</p><h2>What the API reported</h2></div><Gauge size={17} className="muted" /></div>{values.length > 0 && <div className="coverage-grid">{values.map(([label, value]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}</div>}{explanations.length > 0 && <div className="coverage-explanations"><strong>Skipped or not run</strong><ul>{explanations.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul></div>}</section>
}

function Evidence({ finding }: { finding: AssessmentFinding }) {
  if (!finding.evidence) return null
  const headers = Object.keys(finding.evidence.headers)
  return <div className="assessment-evidence"><strong><FileText size={13} /> Safe evidence</strong><span>{finding.evidence.url}</span><span>HTTP {finding.evidence.status_code ?? '—'} · {headers.length ? `${headers.length} selected header${headers.length === 1 ? '' : 's'}` : 'selected metadata only'}</span></div>
}

function FindingCard({ finding }: { finding: AssessmentFinding }) {
  const module = findingModule(finding)
  const verification = findingVerification(finding)
  const owasp = findingOwasp(finding)
  return <article className="assessment-finding"><div className="assessment-finding-top"><Badge tone={`severity-${severityTone(finding.severity)}`}>{finding.severity}</Badge><span className="finding-code">{finding.code}</span>{verification && <Badge tone="neutral">{statusLabel(verification)}</Badge>}</div><h3>{finding.title}</h3><p>{finding.description}</p><div className="assessment-finding-tags">{module && <span>Module: {module}</span>}{owasp && <span>OWASP: {owasp}</span>}{finding.target && <span className="break-text">Target: {finding.target}</span>}</div>{finding.remediation && <div className="assessment-remediation"><strong>Remediation</strong><p>{finding.remediation}</p></div>}<Evidence finding={finding} /></article>
}

function Findings({ assessment }: { assessment: AssessmentResponse }) {
  const findings = assessment.findings ?? []
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [verification, setVerification] = useState('all')
  const [module, setModule] = useState('all')
  const [owasp, setOwasp] = useState('all')
  const [groupBy, setGroupBy] = useState<FindingFilter>('module')
  const options = useMemo(() => ({
    severity: [...new Set(findings.map((item) => item.severity).filter(Boolean))],
    verification: [...new Set(findings.map(findingVerification).filter(Boolean))],
    module: [...new Set(findings.map(findingModule).filter(Boolean))],
    owasp: [...new Set(findings.map(findingOwasp).filter(Boolean))],
  }), [findings])
  const visible = useMemo(() => findings.filter((finding) => {
    const needle = query.toLowerCase()
    const searchable = [finding.code, finding.title, finding.description, finding.target ?? '', findingModule(finding), findingVerification(finding), findingOwasp(finding)]
    return (!needle || searchable.some((value) => value.toLowerCase().includes(needle)))
      && (severity === 'all' || finding.severity === severity)
      && (verification === 'all' || findingVerification(finding) === verification)
      && (module === 'all' || findingModule(finding) === module)
      && (owasp === 'all' || findingOwasp(finding) === owasp)
  }), [findings, module, owasp, query, severity, verification])
  const grouped = useMemo(() => {
    const groups = new Map<string, AssessmentFinding[]>()
    visible.forEach((finding) => {
      const label = groupBy === 'severity' ? finding.severity : groupBy === 'verification' ? findingVerification(finding) : groupBy === 'owasp' ? findingOwasp(finding) : findingModule(finding)
      const key = label || 'Unspecified'
      groups.set(key, [...(groups.get(key) ?? []), finding])
    })
    return [...groups.entries()]
  }, [groupBy, visible])
  return <section className="assessment-findings"><div className="section-heading"><div><p className="eyebrow">Assessment findings</p><h2>Observed signals</h2></div><span className="filter-count">{visible.length} shown · {findings.length} returned</span></div><div className="filter-bar assessment-filter"><div className="search-field"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search assessment findings…" aria-label="Search assessment findings" /></div><select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter assessment findings by severity"><option value="all">All severities</option>{options.severity.map((item) => <option value={item} key={item}>{statusLabel(item)}</option>)}</select><select value={verification} onChange={(event) => setVerification(event.target.value)} aria-label="Filter assessment findings by verification state"><option value="all">All verification states</option>{options.verification.map((item) => <option value={item} key={item}>{statusLabel(item)}</option>)}</select><select value={module} onChange={(event) => setModule(event.target.value)} aria-label="Filter assessment findings by module"><option value="all">All modules</option>{options.module.map((item) => <option value={item} key={item}>{item}</option>)}</select><select value={owasp} onChange={(event) => setOwasp(event.target.value)} aria-label="Filter assessment findings by OWASP category"><option value="all">All OWASP categories</option>{options.owasp.map((item) => <option value={item} key={item}>{item}</option>)}</select><select value={groupBy} onChange={(event) => setGroupBy(event.target.value as FindingFilter)} aria-label="Group assessment findings by"><option value="module">Group by module</option><option value="severity">Group by severity</option><option value="verification">Group by verification</option><option value="owasp">Group by OWASP category</option></select></div>{!findings.length ? <EmptyState title="No assessment findings returned" description="The API did not include assessment findings for this response." /> : !visible.length ? <EmptyState title="No matching assessment findings" description="Try a different search or filter." /> : <div className="assessment-finding-groups">{grouped.map(([label, items]) => <section key={label} className="assessment-finding-group"><div className="assessment-group-heading"><h3>{label}</h3><span>{items.length} finding{items.length === 1 ? '' : 's'}</span></div>{items.map((finding, index) => <FindingCard key={`${finding.id ?? finding.code}-${index}`} finding={finding} />)}</section>)}</div>}</section>
}

export function AssessmentView({ scan }: { scan: ScanStatusResponse | null }) {
  if (!scan) return <EmptyState title="No scan selected" description="Create an assessment to inspect its API-reported assessment data." />
  const assessment = scan.assessment
  if (!assessment) {
    const lifecycle = ['running', 'pending', 'queued', 'failed', 'cancelled', 'canceled'].includes(scan.status.toLowerCase())
    return <><div className="page-header"><div><p className="eyebrow">Assessment workspace</p><h1>Assessment</h1><p className="page-description">No v0.3 assessment data was returned for {scan.target_url}.</p></div></div>{lifecycle && <StateBanner scan={scan} assessment={{ status: scan.status, error: scan.error }} />}<EmptyState title="Assessment data is not available" description={lifecycle ? 'The API did not return an assessment result for this scan state. The dashboard does not invent modules, coverage, or findings.' : 'This scan response is from an older API version or did not include an assessment. The dashboard does not invent modules, coverage, or findings.'} /></>
  }
  return <><div className="page-header"><div><p className="eyebrow">Assessment workspace</p><h1>Assessment</h1><p className="page-description">API-reported assessment data for {scan.target_url}</p></div>{assessment.progress !== null && typeof assessment.progress === 'number' && <Badge tone="running">{Math.max(0, Math.min(100, assessment.progress))}% reported</Badge>}</div><StateBanner scan={scan} assessment={assessment} /><div className="assessment-grid"><Profile assessment={assessment} /><Modules assessment={assessment} /><Coverage assessment={assessment} scan={scan} /></div><Findings assessment={assessment} /></>
}
