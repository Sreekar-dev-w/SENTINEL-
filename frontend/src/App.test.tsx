import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { cancelScan, createScan, getScan } from './api'
import type { ScanStatusResponse } from './types'

vi.mock('./api', () => ({
  cancelScan: vi.fn(),
  createScan: vi.fn(),
  getScan: vi.fn(),
}))

const mockedCreateScan = vi.mocked(createScan)
const mockedGetScan = vi.mocked(getScan)
const mockedCancelScan = vi.mocked(cancelScan)

function scan(status: string = 'completed'): ScanStatusResponse {
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
  }
}

function openNewScan() {
  fireEvent.click(within(screen.getByRole('navigation')).getByRole('button', { name: /new scan/i }))
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
})
