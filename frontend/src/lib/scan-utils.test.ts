import { describe, expect, it } from 'vitest'
import { isTerminal, progressForScan, severityTone, statusLabel } from './scan-utils'
import type { ScanStatusResponse } from '../types'

const scan: ScanStatusResponse = {
  id: 'scan-1', target_url: 'https://example.test/', status: 'running', created_at: '2026-01-01T00:00:00Z', started_at: null, completed_at: null, error: null,
  summary: { checks_total: 4, checks_completed: 2, findings_total: 0, findings_by_severity: {} }, checks: [], findings: [],
}

describe('scan utilities', () => {
  it('recognizes terminal lifecycle states', () => {
    expect(isTerminal('completed')).toBe(true)
    expect(isTerminal('running')).toBe(false)
  })

  it('calculates bounded progress from API summary values', () => {
    expect(progressForScan(scan)).toBe(50)
    expect(progressForScan({ ...scan, status: 'completed', summary: { ...scan.summary, checks_total: 0 } })).toBe(100)
  })

  it('normalizes display labels and severity tones', () => {
    expect(statusLabel('in_progress')).toBe('In Progress')
    expect(severityTone('moderate')).toBe('medium')
    expect(severityTone('unknown')).toBe('info')
  })
})
