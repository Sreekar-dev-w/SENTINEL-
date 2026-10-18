import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cancelEngagement, createEngagement, createScan, getEngagement } from './api'
import type { CreateEngagementRequest, EngagementResponse } from './types'

const request: CreateEngagementRequest = {
  target_domains: ['example.com'], target_ips: [], target_cidrs: [], excluded_hosts: [], excluded_addresses: [], excluded_routes: [],
  permitted_ports: [443], permitted_service_types: ['https'], allowed_assessment_profiles: ['legacy-passive'], allowed_capabilities: [],
  authorization_reference: 'AUTH-1', expires_at: null, budgets: { maximum_requests_per_scan: 10 },
}

const response: EngagementResponse = {
  id: 'engagement-1', target_domains: ['example.com'], target_ips: [], target_cidrs: [], excluded_hosts: [], excluded_addresses: [], excluded_routes: [],
  permitted_ports: [443], permitted_service_types: ['https'], allowed_assessment_profiles: ['legacy-passive'], allowed_capabilities: [],
  authorization_reference: 'AUTH-1', created_at: '2026-01-01T00:00:00Z', expires_at: null, status: 'active', budgets: {},
  cancelled_at: null, cancelled_by: null, cancellation_reason: null, audit_metadata: [],
}

describe('engagement API helpers', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('posts the typed engagement request to the supported route', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify(response), { status: 201, headers: { 'content-type': 'application/json' } }))
    await expect(createEngagement(request)).resolves.toEqual(response)
    expect(fetchMock).toHaveBeenCalledWith('/engagements', expect.objectContaining({ method: 'POST', body: JSON.stringify(request) }))
  })

  it('retrieves and cancels only through the existing engagement routes', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(JSON.stringify(response), { status: 200, headers: { 'content-type': 'application/json' } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ...response, status: 'cancelled' }), { status: 200, headers: { 'content-type': 'application/json' } }))
    await expect(getEngagement('engagement-1')).resolves.toEqual(response)
    await expect(cancelEngagement('engagement-1')).resolves.toMatchObject({ id: 'engagement-1', status: 'cancelled' })
    expect(fetchMock.mock.calls[0][0]).toBe('/engagements/engagement-1')
    expect(fetchMock.mock.calls[1][0]).toBe('/engagements/engagement-1/cancel')
    expect(fetchMock.mock.calls[1][1]).toEqual(expect.objectContaining({ method: 'POST' }))
  })
})

describe('scan API helpers', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('serializes explicitly selected external tools without changing native defaults', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'scan-1' }), { status: 202, headers: { 'content-type': 'application/json' } }))
    const input = { target_url: 'https://example.com/', authorization_confirmed: true as const, engagement_id: 'engagement-1', external_tools: ['owasp-zap', 'nmap'] }
    await createScan(input)
    expect(fetchMock).toHaveBeenCalledWith('/scans', expect.objectContaining({ method: 'POST', body: JSON.stringify(input) }))
  })
})
