import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { cancelScan, createScan, getScan } from './api'
import type { AssessmentResponse, IntelligenceResponse, ScanStatusResponse } from './types'

vi.mock('./api', () => ({
  cancelScan: vi.fn(),
  createScan: vi.fn(),
  getScan: vi.fn(),
}))

const mockedCreateScan = vi.mocked(createScan)
const mockedGetScan = vi.mocked(getScan)
const mockedCancelScan = vi.mocked(cancelScan)

function scan(status: string = 'completed', overrides: Partial<ScanStatusResponse> = {}): ScanStatusResponse {
  const finding = {
    code: 'csp-missing',
    severity: 'low',
    confidence: 'high',
    target: 'https://controlled.fixture/',
    title: 'Content-Security-Policy is missing',
    description: 'The response does not advertise a Content-Security-Policy.',
    status: 'open',
    remediation: 'Define a restrictive Content-Security-Policy.',
    evidence: { url: 'https://controlled.fixture/', status_code: 200, headers: {} },
  }
  return {
    id: 'scan-1',
    target_url: 'https://controlled.fixture/',
    status,
    created_at: '2026-01-01T00:00:00Z',
    started_at: '2026-01-01T00:00:01Z',
    completed_at: status === 'completed' ? '2026-01-01T00:00:02Z' : null,
    error: null,
    summary: { checks_total: 4, checks_completed: status === 'queued' ? 0 : 4, findings_total: 1, findings_by_severity: { low: 1 } },
    checks: [{ name: 'content_security_policy', status: 'failed', findings: [finding], evidence: null, observation: null, started_at: null, completed_at: null, error: null }],
    findings: [finding],
    ...overrides,
  }
}

const assessment: AssessmentResponse = {
  status: 'completed',
  profile: { id: 'baseline', name: 'Baseline assessment', version: '0.3' },
  enabled_modules: ['headers'],
  modules: [{ module: 'headers', label: 'Security headers', status: 'completed', progress: 100, checks_total: 1, checks_completed: 1, findings_total: 1 }],
  progress: 100,
  coverage: { total_modules: 1, completed_modules: 1, skipped_modules: 0, unavailable_modules: 0 },
  findings: [{
    code: 'assessment-csp', severity: 'high', confidence: 'high', target: 'https://findings.fixture/',
    title: 'Assessment finding returned by API', description: 'The assessment returned this finding.', status: 'open',
    verification_state: 'verified', module: 'headers', owasp_category: 'A05 Security Misconfiguration', remediation: 'Apply the returned remediation.', evidence: null,
  }],
}

const intelligence: IntelligenceResponse = {
  initial_url: 'https://findings.fixture/', final_url: 'https://findings.fixture/', mode: 'observed', confidence: 'high', status: 'observed', error: null,
  summary: { pages_scanned: 1, resources_discovered: 1, resources_scanned: 1, cross_origin_blocked: 0, observations_total: 1, partial: false },
  observations: [{ kind: 'technology.web_server', value: { name: 'Fixture server' }, mode: 'observed', confidence: 'high', status: 'observed', evidence: null }],
  resources: [{ url: 'https://findings.fixture/form', kind: 'form', depth: 1, mode: 'observed', confidence: 'high', status: 'observed', method: 'POST', fields: ['email'], source_url: 'https://findings.fixture/', evidence: null }],
}

function openNewScan() {
  fireEvent.click(within(screen.getByRole('navigation')).getByRole('button', { name: /new scan/i }))
}

function navigateTo(label: string | RegExp) {
  fireEvent.click(within(screen.getByRole('navigation')).getByRole('button', { name: label }))
}

describe('SENTINEL dashboard flows', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockedGetScan.mockResolvedValue(scan())
  })

  it('requires explicit authorization before enabling submission', () => {
    render(<App />)
    openNewScan()
    const submit = screen.getByRole('button', { name: /create authorized scan/i })
    expect(submit).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://controlled.fixture/' } })
    expect(submit).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox'))
    expect(submit).toBeEnabled()
  })

  it('submits through the API and renders terminal findings with remediation', async () => {
    mockedCreateScan.mockResolvedValue(scan('queued'))
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://controlled.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))

    await waitFor(() => expect(mockedCreateScan).toHaveBeenCalledWith({ target_url: 'https://controlled.fixture/', authorization_confirmed: true }))
    await waitFor(() => expect(screen.getByText(/content-security-policy is missing/i)).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /view findings/i }))
    fireEvent.click(screen.getByRole('button', { name: /content-security-policy is missing/i }))
    expect(screen.getByText(/define a restrictive content-security-policy/i)).toBeInTheDocument()
  })

  it('shows API validation errors without exposing raw response objects', async () => {
    mockedCreateScan.mockRejectedValue({ message: 'Only http and https URLs are supported', status: 422 })
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'ftp://controlled.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))

    const alerts = await screen.findAllByRole('alert')
    expect(alerts[alerts.length - 1]).toHaveTextContent('Only http and https URLs are supported')
  })

  it('filters findings and supports cancellation only for active scans', async () => {
    mockedCreateScan.mockResolvedValue(scan('running'))
    mockedGetScan.mockResolvedValue(scan('running'))
    mockedCancelScan.mockResolvedValue(scan('cancelled'))
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://controlled.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))
    await waitFor(() => expect(screen.getByRole('button', { name: /cancel scan/i })).toBeInTheDocument())
    fireEvent.click(screen.getByRole('button', { name: /cancel scan/i }))
    await waitFor(() => expect(mockedCancelScan).toHaveBeenCalledWith('scan-1'))
    fireEvent.click(screen.getByRole('button', { name: /view findings/i }))
    fireEvent.change(screen.getByLabelText(/filter by severity/i), { target: { value: 'high' } })
    expect(screen.getByText(/no matching findings/i)).toBeInTheDocument()
  })

  it.each([
    {
      name: 'a target with API-returned findings',
      target: 'https://findings.fixture/',
      findings: true,
    },
    {
      name: 'a target with no API-returned findings',
      target: 'https://clean.fixture/',
      findings: false,
    },
  ])('shows the $name consistently across scan detail and findings', async ({ target, findings }) => {
    const returnedFinding = scan().findings[0]
    const response = scan('completed', {
      target_url: target,
      checks: [],
      findings: findings ? [{ ...returnedFinding, target }] : [],
      summary: { checks_total: 1, checks_completed: 1, findings_total: findings ? 1 : 0, findings_by_severity: findings ? { low: 1 } : {} },
    })
    mockedCreateScan.mockResolvedValue(response)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: target } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))

    await waitFor(() => expect(screen.getByRole('heading', { name: target })).toBeInTheDocument())
    if (!findings) expect(screen.getByText('No findings returned')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /view findings/i }))
    if (findings) {
      expect(screen.getByText('Content-Security-Policy is missing')).toBeInTheDocument()
      expect(screen.queryByText('Finding invented by the frontend')).not.toBeInTheDocument()
    } else {
      expect(screen.getByText('No matching findings')).toBeInTheDocument()
      expect(screen.queryByText('Content-Security-Policy is missing')).not.toBeInTheDocument()
    }
  })

  it('passes one successful API response through detail, findings, assessment, and intelligence views', async () => {
    const response = scan('completed', {
      target_url: 'https://findings.fixture/',
      assessment,
      intelligence,
      findings: [{ ...scan().findings[0], target: 'https://findings.fixture/' }],
      summary: { checks_total: 1, checks_completed: 1, findings_total: 1, findings_by_severity: { low: 1 } },
      checks: [],
    })
    mockedCreateScan.mockResolvedValue(response)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://findings.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))
    await waitFor(() => expect(screen.getByRole('heading', { name: 'https://findings.fixture/' })).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /view findings/i }))
    expect(screen.getByText('Content-Security-Policy is missing')).toBeInTheDocument()
    navigateTo('Assessment')
    expect(screen.getByText('Baseline assessment')).toBeInTheDocument()
    expect(screen.getByText('Assessment finding returned by API')).toBeInTheDocument()
    expect(screen.queryByText('Assessment finding invented by the frontend')).not.toBeInTheDocument()
    navigateTo('Intelligence')
    expect(screen.getByText('Fixture server')).toBeInTheDocument()
    expect(screen.getByText('https://findings.fixture/form')).toBeInTheDocument()
    expect(screen.queryByText('Invented technology')).not.toBeInTheDocument()
  })

  it('shows partial intelligence and assessment failures without inventing data', async () => {
    const partialAssessment: AssessmentResponse = { ...assessment, status: 'partial', partial: true, findings: [], error: null }
    const failedIntelligence: IntelligenceResponse = { ...intelligence, status: 'error', error: 'collector failure', observations: [], resources: [], summary: { ...intelligence.summary, observations_total: 0, partial: true } }
    const response = scan('completed', { assessment: partialAssessment, intelligence: failedIntelligence, findings: [], summary: { checks_total: 1, checks_completed: 1, findings_total: 0, findings_by_severity: {} }, checks: [] })
    mockedCreateScan.mockResolvedValue(response)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://controlled.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))
    await waitFor(() => expect(screen.getByText(/no findings returned/i)).toBeInTheDocument())

    navigateTo('Assessment')
    expect(screen.getByRole('status')).toHaveTextContent(/partial assessment/i)
    expect(screen.getByText(/no assessment findings returned/i)).toBeInTheDocument()
    navigateTo('Intelligence')
    expect(screen.getByRole('alert')).toHaveTextContent('collector failure')
    expect(screen.getByText(/no intelligence observations/i)).toBeInTheDocument()
    expect(screen.queryByText('Fixture server')).not.toBeInTheDocument()
  })

  it.each([
    ['cancelled', 'The operator cancelled this scan.'],
    ['failed', 'The API worker failed this scan.'],
  ])('renders %s lifecycle responses and their API error without findings', async (status, error) => {
    const response = scan(status, { error, findings: [], checks: [], summary: { checks_total: 1, checks_completed: 0, findings_total: 0, findings_by_severity: {} } })
    mockedCreateScan.mockResolvedValue(response)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://controlled.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))
    await waitFor(() => expect(screen.getByText(error)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /cancel scan/i })).not.toBeInTheDocument()
    expect(screen.getByText(/no findings returned/i)).toBeInTheDocument()
    navigateTo(/^Findings/)
    expect(screen.getByText('No matching findings')).toBeInTheDocument()
    navigateTo('Assessment')
    expect(screen.getByText(/assessment data is not available/i)).toBeInTheDocument()
    navigateTo('Intelligence')
    expect(screen.getByText(/intelligence is not available/i)).toBeInTheDocument()
  })

  it('keeps older responses without optional v0.3 fields valid and empty', async () => {
    const response = scan('completed', { target_url: 'https://legacy.fixture/', findings: [], checks: [], summary: { checks_total: 0, checks_completed: 0, findings_total: 0, findings_by_severity: {} } })
    mockedCreateScan.mockResolvedValue(response)
    render(<App />)
    openNewScan()
    fireEvent.change(screen.getByLabelText(/target url/i), { target: { value: 'https://legacy.fixture/' } })
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /create authorized scan/i }))
    await waitFor(() => expect(mockedCreateScan).toHaveBeenCalledWith({ target_url: 'https://legacy.fixture/', authorization_confirmed: true }))
    await waitFor(() => expect(screen.getByText('No findings returned')).toBeInTheDocument())
    expect(screen.getAllByText('https://legacy.fixture/').length).toBeGreaterThan(0)
    navigateTo('Assessment')
    expect(screen.getByText(/older api version/i)).toBeInTheDocument()
    expect(screen.queryByText(/Baseline assessment/i)).not.toBeInTheDocument()
    navigateTo('Intelligence')
    expect(screen.getByText(/older v0.1 scan/i)).toBeInTheDocument()
    expect(screen.queryByText('Fixture server')).not.toBeInTheDocument()
  })
})
