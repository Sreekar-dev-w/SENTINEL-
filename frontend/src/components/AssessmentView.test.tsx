import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { AssessmentView } from './AssessmentView'
import type { AssessmentResponse, ScanStatusResponse } from '../types'

function scan(assessment?: AssessmentResponse | null, status = 'completed'): ScanStatusResponse {
  return {
    id: 'scan-assessment', target_url: 'https://controlled.fixture/', status,
    created_at: '2026-01-01T00:00:00Z', started_at: null, completed_at: null, error: null,
    summary: { checks_total: 0, checks_completed: 0, findings_total: 0, findings_by_severity: {} }, checks: [], findings: [], assessment,
  }
}

const profile: AssessmentResponse = {
  status: 'completed',
  profile: { id: 'baseline', name: 'Baseline web assessment', version: '0.3' },
  enabled_modules: ['headers', 'injection'],
  modules: [
    { module: 'headers', label: 'Security headers', status: 'completed', progress: 100, checks_total: 4, checks_completed: 4, findings_total: 1 },
    { module: 'injection', label: 'Injection checks', status: 'skipped', progress: 0, checks_total: 3, checks_completed: 0, skipped: true, not_run_reason: 'Module requires an API-provided opt-in.' },
  ],
  progress: 67,
  coverage: { total_modules: 7, completed_modules: 4, skipped_modules: 1, unavailable_modules: 2, skipped_reasons: ['Injection module: API policy skipped active probes.'] },
  findings: [
    { id: 'f-1', code: 'header-csp', severity: 'high', confidence: 'high', target: 'https://controlled.fixture/', title: 'Content-Security-Policy is missing', description: 'The response did not include a CSP.', status: 'open', verification_state: 'verified', module: 'headers', owasp_category: 'A05 Security Misconfiguration', remediation: 'Define a restrictive policy.', evidence: { url: 'https://controlled.fixture/', status_code: 200, headers: { server: 'fixture' } } },
    { id: 'f-2', code: 'header-xcto', severity: 'low', confidence: 'medium', target: null, title: 'X-Content-Type-Options is missing', description: 'The response omitted the header.', status: 'open', verification_state: 'needs_review', module: 'headers', owasp_category: 'A05 Security Misconfiguration', remediation: null, evidence: null },
    { id: 'f-3', code: 'input-reflection', severity: 'medium', confidence: 'low', target: '/search', title: '<script>unsafe</script>', description: 'A returned value needs review.', status: 'open', verification_state: 'unverified', module: 'injection', owasp_category: 'A03 Injection', remediation: 'Encode output.', evidence: null },
  ],
}

describe('AssessmentView', () => {
  it('handles missing assessment data for old v0.1/v0.2 responses without inventing results', () => {
    render(<AssessmentView scan={scan()} />)
    expect(screen.getByText(/assessment data is not available/i)).toBeInTheDocument()
    expect(screen.getByText(/older api version/i)).toBeInTheDocument()
    expect(screen.queryByText(/security headers/i)).not.toBeInTheDocument()
  })

  it('renders profile, modules, coverage explanations, and safely escaped findings', () => {
    render(<AssessmentView scan={scan(profile)} />)
    expect(screen.getByText('Baseline web assessment')).toBeInTheDocument()
    expect(screen.getByText('Security headers')).toBeInTheDocument()
    expect(screen.getByText('Injection module: API policy skipped active probes.')).toBeInTheDocument()
    expect(screen.getAllByText('Skipped').length).toBeGreaterThan(0)
    expect(screen.getByText('<script>unsafe</script>')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
    expect(screen.getByText('Define a restrictive policy.')).toBeInTheDocument()
    expect(screen.getByText(/HTTP 200/)).toBeInTheDocument()
  })

  it('filters findings by severity, verification, module, and OWASP category and groups them', () => {
    render(<AssessmentView scan={scan(profile)} />)
    expect(screen.getByText('A03 Injection')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/filter assessment findings by severity/i), { target: { value: 'high' } })
    expect(screen.getByText('Content-Security-Policy is missing')).toBeInTheDocument()
    expect(screen.queryByText('X-Content-Type-Options is missing')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/filter assessment findings by severity/i), { target: { value: 'all' } })
    fireEvent.change(screen.getByLabelText(/filter assessment findings by verification state/i), { target: { value: 'needs_review' } })
    expect(screen.getByText('X-Content-Type-Options is missing')).toBeInTheDocument()
    expect(screen.queryByText('Content-Security-Policy is missing')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/filter assessment findings by verification state/i), { target: { value: 'all' } })
    fireEvent.change(screen.getByLabelText(/filter assessment findings by module/i), { target: { value: 'injection' } })
    expect(screen.queryByText('X-Content-Type-Options is missing')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/filter assessment findings by OWASP category/i), { target: { value: 'A03 Injection' } })
    expect(screen.getByText('<script>unsafe</script>')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/group assessment findings by/i), { target: { value: 'owasp' } })
    expect(screen.getAllByText('A03 Injection').length).toBeGreaterThan(1)
  })

  it.each([
    ['running', /still running/i],
    ['partial', /partial assessment/i],
    ['cancelled', /cancelled before completion/i],
    ['failed', /assessment failed/i],
  ])('explains %s state without claiming completion', (status, message) => {
    const response = { ...profile, status, findings: [] }
    render(<AssessmentView scan={scan(response, status)} />)
    expect(screen.getByRole(status === 'failed' ? 'alert' : 'status')).toHaveTextContent(message)
  })
})
