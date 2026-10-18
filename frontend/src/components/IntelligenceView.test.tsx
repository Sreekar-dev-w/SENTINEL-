import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { IntelligenceView } from './IntelligenceView'
import type { IntelligenceResponse, ScanStatusResponse } from '../types'

function scan(intelligence?: IntelligenceResponse | null): ScanStatusResponse {
  return {
    id: 'scan-intelligence', target_url: 'https://controlled.fixture/', status: 'completed',
    created_at: '2026-01-01T00:00:00Z', started_at: null, completed_at: '2026-01-01T00:00:02Z', error: null,
    summary: { checks_total: 0, checks_completed: 0, findings_total: 0, findings_by_severity: {} }, checks: [], findings: [], intelligence,
  }
}

const profile: IntelligenceResponse = {
  initial_url: 'https://controlled.fixture/', final_url: 'https://controlled.fixture/', mode: 'observed', confidence: 'high', status: 'observed', error: null,
  summary: { pages_scanned: 2, resources_discovered: 3, resources_scanned: 2, cross_origin_blocked: 1, observations_total: 3, partial: false },
  observations: [
    { kind: 'domain.target', value: { hostname: 'controlled.fixture' }, mode: 'observed', confidence: 'high', status: 'observed', evidence: null },
    { kind: 'technology.web_server', value: { name: '<script>alert(1)</script>', source: 'server' }, mode: 'observed', confidence: 'medium', status: 'observed', evidence: null },
    { kind: 'infrastructure.edge_indicators', value: { headers: ['x-cache'] }, mode: 'inferred', confidence: 'low', status: 'inferred', evidence: null },
  ],
  resources: [{ url: 'https://controlled.fixture/form', kind: 'form', depth: 1, mode: 'observed', confidence: 'high', status: 'limited', method: 'POST', fields: ['email'], source_url: 'https://controlled.fixture/', evidence: null }],
}

describe('IntelligenceView', () => {
  it('shows observed and inferred sections and safely renders untrusted text', () => {
    render(<IntelligenceView scan={scan(profile)} />)
    expect(screen.getByRole('heading', { name: 'Intelligence profile' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Domain' })).toBeInTheDocument()
    expect(screen.getByText('Technology · Web Server')).toBeInTheDocument()
    expect(screen.getAllByText(/observed · high/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/inferred · low/i)).toBeInTheDocument()
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })

  it('filters sections and searches API-reported text', () => {
    render(<IntelligenceView scan={scan(profile)} />)
    fireEvent.change(screen.getByLabelText(/filter intelligence sections/i), { target: { value: 'technologies' } })
    expect(screen.getByText('Technology · Web Server')).toBeInTheDocument()
    expect(screen.queryByText('Domain · Target')).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText(/search intelligence/i), { target: { value: 'does-not-exist' } })
    expect(screen.getByText(/no matching intelligence/i)).toBeInTheDocument()
  })

  it('explains that old v0.1 scans do not have intelligence', () => {
    render(<IntelligenceView scan={scan()} />)
    expect(screen.getByText(/intelligence is not available/i)).toBeInTheDocument()
    expect(screen.getByText(/older v0.1 scan/i)).toBeInTheDocument()
  })

  it('reports partial and failed collection states without inventing observations', () => {
    const partial: IntelligenceResponse = { ...profile, status: 'inconclusive', error: null, summary: { ...profile.summary, partial: true }, observations: [], resources: [] }
    const { rerender } = render(<IntelligenceView scan={scan(partial)} />)
    expect(screen.getByRole('status')).toHaveTextContent(/inconclusive/i)
    expect(screen.getByText(/no intelligence observations/i)).toBeInTheDocument()
    rerender(<IntelligenceView scan={scan({ ...partial, status: 'error', error: 'collector failure' })} />)
    expect(screen.getByRole('alert')).toHaveTextContent(/collector failure/i)
  })
})
