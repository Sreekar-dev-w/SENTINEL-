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
  verification?: string | null
  module?: string | null
  test_id?: string | null
  test_version?: string | null
  reference?: string | null
  references?: string[]
  timestamp?: string | null
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
  engagement_id?: string | null
  assessment_profile?: string | null
  active_testing_authorized?: boolean | null
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
  /** Optional v0.3 assessment contract. Older v0.1/v0.2 responses omit it. */
  assessment?: AssessmentResponse | null
  /** v0.3 coverage may also be exposed beside the assessment for clients that read aggregates directly. */
  coverage?: AssessmentCoverage | null
}

/** Canonical JSON returned by the completed-scan report endpoint. */
export type ScanReport = Record<string, unknown>

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

export interface AssessmentProfile {
  id?: string | null
  name?: string | null
  version?: string | null
  description?: string | null
  enabled_modules?: Array<string | AssessmentModule>
}

export interface AssessmentModule {
  module?: string | null
  test_id?: string | null
  test_version?: string | null
  id?: string | null
  key?: string | null
  name?: string | null
  label?: string | null
  enabled?: boolean | null
  status?: string | null
  progress?: number | null
  progress_percent?: number | null
  checks_total?: number | null
  checks_completed?: number | null
  findings_total?: number | null
  skipped?: boolean | null
  skip_reason?: string | null
  not_run_reason?: string | null
  error?: string | null
  status_reason?: string | null
  observations?: AssessmentObservation[]
  reference?: string | null
  references?: string[]
  impact?: string | null
  execution_mode?: string | null
  timestamp?: string | null
}

export interface AssessmentCoverage {
  applicable_tests?: number | null
  passed_tests?: number | null
  skipped_tests?: number | null
  not_run_tests?: number | null
  execution_failures?: number | null
  confirmed_findings?: number | null
  potential_findings?: number | null
  informational_observations?: number | null
  total?: number | null
  covered?: number | null
  completed?: number | null
  skipped?: number | null
  not_run?: number | null
  total_modules?: number | null
  total_checks?: number | null
  covered_checks?: number | null
  skipped_checks?: number | null
  not_run_checks?: number | null
  completed_modules?: number | null
  skipped_modules?: number | null
  unavailable_modules?: number | null
  error_modules?: number | null
  findings_total?: number | null
  observations_total?: number | null
  partial?: boolean | null
  skipped_reasons?: Array<string | AssessmentExplanation>
  not_run_reasons?: Array<string | AssessmentExplanation>
}

export interface AssessmentObservation {
  kind?: string
  value?: unknown
  status?: string
  module?: string | null
  reference?: string | null
}

export interface AssessmentExplanation {
  module?: string | null
  reason?: string | null
}

export interface AssessmentFinding extends FindingResponse {
  id?: string | null
  module?: string | null
  module_id?: string | null
  module_name?: string | null
  verification_state?: string | null
  verification?: string | null
  owasp_category?: string | null
  owasp?: string | null
  owasp_id?: string | null
}

export interface AssessmentResponse {
  status?: string | null
  profile_id?: string | null
  profile_version?: string | null
  profile?: AssessmentProfile | string | null
  enabled_modules?: Array<string | AssessmentModule>
  modules?: AssessmentModule[]
  progress?: number | null
  coverage?: AssessmentCoverage | null
  findings?: AssessmentFinding[]
  skipped?: AssessmentExplanation[]
  not_run?: AssessmentExplanation[]
  partial?: boolean | null
  error?: string | null
  observations?: AssessmentObservation[]
  timestamp?: string | null
}
