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
}

export interface ApiError {
  detail?: string
  message: string
  status?: number
}
