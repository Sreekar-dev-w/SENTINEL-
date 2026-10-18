export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string

export interface CreateScanRequest {
  target_url: string
  authorization_confirmed: true
}

export interface EvidenceResponse {
  url: string
  status_code: number | null
  headers: Record<string, string>
}

export interface FindingResponse {
  code: string
  severity: string
  confidence: string
  target: string | null
  title: string
  description: string
  status: string
  evidence: EvidenceResponse | null
  remediation: string | null
}

export interface CheckResponse {
  name: string
  status: string
  findings: FindingResponse[]
  evidence: EvidenceResponse | null
  observation: Record<string, string | boolean> | null
  started_at: string | null
  completed_at: string | null
  error: string | null
}

export interface SummaryResponse {
  checks_total: number
  checks_completed: number
  findings_total: number
  findings_by_severity: Record<string, number>
}

export interface ScanStatusResponse {
  id: string
  target_url: string
  status: ScanStatus
  created_at: string
  started_at: string | null
  completed_at: string | null
  summary: SummaryResponse
  checks: CheckResponse[]
  findings: FindingResponse[]
  error: string | null
  /**
   * Optional v0.2 intelligence contract. v0.1 responses omit this property;
   * the UI must continue to treat that as a valid response.
   *
    * The frontend does not issue a second request or manufacture local data;
    * it renders this property only when the backend includes it.
   */
  intelligence?: IntelligenceResponse | null
}

export interface ApiError {
  detail?: string
  message: string
  status?: number
}

export type IntelligenceMode = 'observed' | 'inferred' | string
export type IntelligenceConfidence = 'low' | 'medium' | 'high' | string
export type IntelligenceStatus = 'observed' | 'inferred' | 'unavailable' | 'inconclusive' | 'limited' | 'error' | string

export interface IntelligenceObservation {
  kind: string
  value: unknown
  mode: IntelligenceMode
  confidence: IntelligenceConfidence
  status: IntelligenceStatus
  evidence: EvidenceResponse | null
}

export interface IntelligenceResource {
  url: string
  kind: string
  depth: number
  mode: IntelligenceMode
  confidence: IntelligenceConfidence
  status: IntelligenceStatus
  method: string | null
  fields: string[]
  source_url: string | null
  evidence: EvidenceResponse | null
}

export interface IntelligenceSummary {
  pages_scanned: number
  resources_discovered: number
  resources_scanned: number
  cross_origin_blocked: number
  observations_total: number
  partial: boolean
}

export interface IntelligenceResponse {
  initial_url: string
  final_url: string | null
  mode: IntelligenceMode
  confidence: IntelligenceConfidence
  status: IntelligenceStatus
  observations: IntelligenceObservation[]
  resources: IntelligenceResource[]
  summary: IntelligenceSummary
  error: string | null
}
