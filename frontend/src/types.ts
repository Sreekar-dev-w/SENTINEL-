export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string

export interface CreateScanRequest {
  target_url: string
  authorization_confirmed: true
  assessment_profile?: string
  engagement_id?: string
  active_testing_authorized?: true
}

export interface EngagementBudgets {
  maximum_requests_per_scan?: number | null
  maximum_requests_per_host?: number | null
  maximum_concurrency?: number | null
  scan_timeout_seconds?: number | null
  maximum_response_bytes?: number | null
  maximum_redirects?: number | null
  maximum_findings?: number | null
}

export interface CreateEngagementRequest {
  target_domains: string[]
  target_ips: string[]
  target_cidrs: string[]
  excluded_hosts: string[]
  excluded_addresses: string[]
  excluded_routes: string[]
  permitted_ports: number[]
  permitted_service_types: string[]
  allowed_assessment_profiles: string[]
  allowed_capabilities: string[]
  authorization_reference: string
  expires_at?: string | null
  budgets?: EngagementBudgets
}

export type EngagementStatus = 'active' | 'cancelled' | 'expired' | string

export interface EngagementAuditEntry {
  action: string
  actor?: string | null
  reason?: string | null
  timestamp: string
}

export interface EngagementResponse {
  id: string
  target_domains: string[]
  target_ips: string[]
  target_cidrs: string[]
  excluded_hosts: string[]
  excluded_addresses: string[]
  excluded_routes: string[]
  permitted_ports: number[]
  permitted_service_types: string[]
  allowed_assessment_profiles: string[]
  allowed_capabilities: string[]
  authorization_reference: string
  created_at: string
  expires_at: string | null
  status: EngagementStatus
  budgets: EngagementBudgets
  cancelled_at: string | null
  cancelled_by: string | null
  cancellation_reason: string | null
  audit_metadata: EngagementAuditEntry[]
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

/** Availability returned by the read-only GET /external-tools endpoint. */
export type ExternalToolAvailabilityStatus = 'unknown' | 'available' | 'unavailable' | 'error' | string

export type ExternalToolCapability = 'passive_scan' | 'active_scan' | string

export interface ExternalToolIdentity {
  name: string
  vendor: string
  adapter_version: string
  tool_version?: string | null
  api_version?: string | null
}

export interface ExternalToolDiagnostic {
  code: string
  message: string
  phase: string
  retryable?: boolean
}

export interface ExternalToolAvailability {
  status: ExternalToolAvailabilityStatus
  identity: ExternalToolIdentity
  capabilities?: ExternalToolCapability[]
  diagnostics?: ExternalToolDiagnostic[]
  checked_at?: string
}

export interface ExternalFindingProvenance {
  adapter: string
  tool: string
  tool_version?: string | null
  api_version?: string | null
  source_alert_id?: string | null
  observed_at?: string
}

/** Normalized external finding; raw tool alerts are never expected here. */
export interface ExternalNormalizedFinding {
  source: string
  rule_id: string
  /** Some API/report versions also expose the compatibility alias `rule`. */
  rule?: string
  title: string
  description: string
  severity: string
  confidence: string
  target: string
  remediation?: string | null
  references?: string[]
  provenance: ExternalFindingProvenance
}

export interface ExternalToolExecutionResult {
  state: string
  tool: ExternalToolIdentity
  observations?: unknown[]
  findings?: ExternalNormalizedFinding[]
  diagnostics?: ExternalToolDiagnostic[]
  partial?: boolean
  requests_made?: number
  started_at?: string
  completed_at?: string
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
  /** Optional external-tool results. Older/native-only responses omit this. */
  external_tool_names?: string[]
  external_tools?: ExternalToolExecutionResult[]
  /** Optional flattened form used by report-oriented API versions. */
  external_findings?: ExternalNormalizedFinding[]
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
