/**
 * M47 — Response Comparator Core (DB-free)
 *
 * Contract version: fixguard-response-comparator/v0
 *
 * Defines pure TypeScript contracts for comparing sanitized HTTP response
 * snapshots and producing sanitized comparison results.
 *
 * M47 does NOT:
 *   - execute network requests or tools
 *   - import M45 types or build EvidenceRecord / FindingCandidateRecord
 *   - persist any data
 *   - create findings
 *   - confirm vulnerabilities
 *   - make severity/risk/impact claims
 *   - echo raw responses, headers, bodies, or secrets
 *
 * Intended future flow:
 *   Tool/adapter output -> safe snapshots -> M47 comparison
 *   -> future mapper -> M45 EvidenceRecord -> M45 promotion
 */

// ---------------------------------------------------------------------------
// Contract Version
// ---------------------------------------------------------------------------

export type ResponseComparatorContractVersion = 'fixguard-response-comparator/v0';

export const RESPONSE_COMPARATOR_CONTRACT_VERSION: ResponseComparatorContractVersion =
  'fixguard-response-comparator/v0';

// ---------------------------------------------------------------------------
// Classification Flags
// ---------------------------------------------------------------------------

export interface ResponseComparatorClassificationFlags {
  createsRealFindings: false;
  createsPersistedEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
  persistsData: false;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface ValidationResult {
  isValid: boolean;
  errorCode?: string;
  message?: string;
}

// ---------------------------------------------------------------------------
// HTTP Methods (closed enum)
// ---------------------------------------------------------------------------

export const ALLOWED_HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;
export type HttpMethod = (typeof ALLOWED_HTTP_METHODS)[number];

// ---------------------------------------------------------------------------
// Snapshot role
// ---------------------------------------------------------------------------

export const ALLOWED_SNAPSHOT_ROLES = ['baseline', 'validation'] as const;
export type SnapshotRole = (typeof ALLOWED_SNAPSHOT_ROLES)[number];

// ---------------------------------------------------------------------------
// Body shape kind
// ---------------------------------------------------------------------------

export const ALLOWED_SHAPE_KINDS = [
  'json_object', 'json_array', 'html', 'text', 'empty', 'unknown'
] as const;
export type ShapeKind = (typeof ALLOWED_SHAPE_KINDS)[number];

// ---------------------------------------------------------------------------
// Auth state signal
// ---------------------------------------------------------------------------

export const ALLOWED_AUTH_STATE_SIGNALS = [
  'unknown', 'appears_authenticated', 'appears_unauthenticated'
] as const;
export type AuthStateSignal = (typeof ALLOWED_AUTH_STATE_SIGNALS)[number];

// ---------------------------------------------------------------------------
// Error signal names (closed enum)
// ---------------------------------------------------------------------------

export const ALLOWED_ERROR_SIGNAL_NAMES = [
  'sql_error_like',
  'stack_trace_like',
  'auth_error_like',
  'server_error_like',
  'rate_limit_like',
  'validation_error_like'
] as const;
export type ErrorSignalName = (typeof ALLOWED_ERROR_SIGNAL_NAMES)[number];

// ---------------------------------------------------------------------------
// Safe excerpt source
// ---------------------------------------------------------------------------

export const ALLOWED_EXCERPT_SOURCES = [
  'sanitized_body_excerpt', 'sanitized_header_name', 'manual_note'
] as const;
export type ExcerptSource = (typeof ALLOWED_EXCERPT_SOURCES)[number];

// ---------------------------------------------------------------------------
// Subject
// ---------------------------------------------------------------------------

export interface SnapshotSubject {
  normalizedOrigin?: string;
  method?: HttpMethod;
  pathTemplate?: string;
  routeId?: string;
}

// ---------------------------------------------------------------------------
// Normalized body shape
// ---------------------------------------------------------------------------

export interface NormalizedBodyShape {
  shapeKind: ShapeKind;
  topLevelJsonKeys?: string[];
  normalizedSchemaHash?: string;
}

// ---------------------------------------------------------------------------
// Redirect
// ---------------------------------------------------------------------------

export interface RedirectInfo {
  redirected: boolean;
  locationOriginHash?: string;
  locationPathTemplate?: string;
}

// ---------------------------------------------------------------------------
// Auth state
// ---------------------------------------------------------------------------

export interface AuthStateInfo {
  authenticatedSignal: AuthStateSignal;
  authStateHash?: string;
}

// ---------------------------------------------------------------------------
// Error signals
// ---------------------------------------------------------------------------

export interface ErrorSignalsInfo {
  hasSqlErrorSignal: boolean;
  hasStackTraceSignal: boolean;
  hasAuthErrorSignal: boolean;
  hasServerErrorSignal: boolean;
  signalNames: ErrorSignalName[];
}

// ---------------------------------------------------------------------------
// Safe excerpt
// ---------------------------------------------------------------------------

export interface SafeExcerpt {
  text: string;
  source: ExcerptSource;
  redacted: true;
}

// ---------------------------------------------------------------------------
// SafeResponseSnapshot
// ---------------------------------------------------------------------------

export interface SafeResponseSnapshot {
  contractVersion: ResponseComparatorContractVersion;
  kind: 'safe_response_snapshot';
  snapshotId: string;
  scanId: string;
  capturedAt: string;
  role: SnapshotRole;
  subject: SnapshotSubject;
  statusCode: number;
  contentLength: number;
  responseTimeMs: number;
  headerNames: string[];
  bodyHash: string;
  normalizedBodyShape?: NormalizedBodyShape;
  redirect?: RedirectInfo;
  authState?: AuthStateInfo;
  errorSignals?: ErrorSignalsInfo;
  safeExcerpt?: SafeExcerpt;
  classification: ResponseComparatorClassificationFlags;
}

// ---------------------------------------------------------------------------
// Comparison mode
// ---------------------------------------------------------------------------

export const ALLOWED_COMPARISON_MODES = [
  'http_difference',
  'authorization_difference',
  'time_based_difference',
  'generic_signal_comparison'
] as const;
export type ComparisonMode = (typeof ALLOWED_COMPARISON_MODES)[number];

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

export interface ComparisonThresholds {
  contentLengthDeltaPercentSignificant: number;
  responseTimeDeltaMsSignificant: number;
}

// ---------------------------------------------------------------------------
// ResponseComparisonRequest
// ---------------------------------------------------------------------------

export interface ResponseComparisonRequest {
  contractVersion: ResponseComparatorContractVersion;
  kind: 'response_comparison_request';
  comparisonId: string;
  scanId: string;
  requestedAt: string;
  baseline: SafeResponseSnapshot;
  validation: SafeResponseSnapshot;
  comparisonMode: ComparisonMode;
  thresholds: ComparisonThresholds;
  classification: ResponseComparatorClassificationFlags;
}

// ---------------------------------------------------------------------------
// Signal summary items (closed enum)
// ---------------------------------------------------------------------------

export const ALLOWED_SIGNAL_SUMMARY_ITEMS = [
  'status_code_changed',
  'content_length_changed',
  'response_time_changed',
  'body_hash_changed',
  'headers_changed',
  'json_shape_changed',
  'redirect_changed',
  'auth_state_changed',
  'error_signal_observed'
] as const;
export type SignalSummaryItem = (typeof ALLOWED_SIGNAL_SUMMARY_ITEMS)[number];

// ---------------------------------------------------------------------------
// Response difference
// ---------------------------------------------------------------------------

export interface ResponseDifference {
  statusCodeChanged: boolean;
  baselineStatusCode?: number;
  validationStatusCode?: number;

  contentLengthChanged: boolean;
  contentLengthDelta: number;
  contentLengthDeltaPercent: number;
  contentLengthSignificant: boolean;

  responseTimeChanged: boolean;
  responseTimeDeltaMs: number;
  responseTimeSignificant: boolean;

  bodyHashChanged: boolean;

  headerNamesAdded: string[];
  headerNamesRemoved: string[];

  jsonKeysAdded: string[];
  jsonKeysRemoved: string[];

  redirectChanged: boolean;
  authStateChanged: boolean;
  errorSignalObserved: boolean;

  signalSummary: SignalSummaryItem[];
}

// ---------------------------------------------------------------------------
// Comparison significance (NOT severity/risk/impact)
// ---------------------------------------------------------------------------

export const ALLOWED_STRONGEST_SIGNALS = [
  'none', 'status_code', 'content_length', 'response_time',
  'body_hash', 'headers', 'json_shape', 'redirect', 'auth_state', 'error_signal'
] as const;
export type StrongestSignal = (typeof ALLOWED_STRONGEST_SIGNALS)[number];

export const ALLOWED_SIGNAL_STRENGTHS = ['none', 'weak', 'moderate', 'strong'] as const;
export type ComparisonSignalStrength = (typeof ALLOWED_SIGNAL_STRENGTHS)[number];

export interface ComparisonSignificance {
  hasAnyDifference: boolean;
  hasSignificantDifference: boolean;
  strongestSignal: StrongestSignal;
  comparisonSignalStrength: ComparisonSignalStrength;
  rationale: string;
}

// ---------------------------------------------------------------------------
// Evidence mapping hint (not a real EvidenceRecord)
// ---------------------------------------------------------------------------

export const ALLOWED_SUGGESTED_EVIDENCE_TYPES = [
  'http_difference',
  'authorization_difference',
  'time_based_difference',
  'manual_review_note'
] as const;
export type SuggestedEvidenceType = (typeof ALLOWED_SUGGESTED_EVIDENCE_TYPES)[number];

export const ALLOWED_SUGGESTED_SIGNAL_STRENGTHS = ['weak', 'moderate', 'strong'] as const;
export type SuggestedSignalStrength = (typeof ALLOWED_SUGGESTED_SIGNAL_STRENGTHS)[number];

export interface EvidenceMappingHint {
  suggestedEvidenceType: SuggestedEvidenceType;
  suggestedSignalStrength: SuggestedSignalStrength;
  requiresHumanReview: true;
  notPersistedEvidence: true;
}

// ---------------------------------------------------------------------------
// Explicit non-claims
// ---------------------------------------------------------------------------

export interface ExplicitNonClaims {
  noConfirmedVulnerability: true;
  noFindingCreated: true;
  noPersistedEvidenceCreated: true;
  noSeverityRiskOrImpactClaim: true;
  noRawSensitiveDataIncluded: true;
}

// ---------------------------------------------------------------------------
// Failed result error
// ---------------------------------------------------------------------------

export const ALLOWED_COMPARATOR_ERROR_CODES = [
  'invalid_comparison_request',
  'invalid_baseline_snapshot',
  'invalid_validation_snapshot',
  'invalid_comparison_metadata',
  'scan_mismatch',
  'snapshot_role_mismatch',
  'subject_mismatch',
  'unsafe_content_rejected',
  'unexpected_comparator_failure'
] as const;
export type ComparatorErrorCode = (typeof ALLOWED_COMPARATOR_ERROR_CODES)[number];

export interface ComparatorError {
  code: ComparatorErrorCode;
  safeMessage: string;
}

// ---------------------------------------------------------------------------
// ResponseComparisonResult
// ---------------------------------------------------------------------------

export interface ResponseComparisonResult {
  contractVersion: ResponseComparatorContractVersion;
  kind: 'response_comparison_result';
  comparisonId: string;
  scanId: string;
  comparedAt: string;
  status: 'completed' | 'failed';
  baselineSnapshotId: string;
  validationSnapshotId: string;
  difference: ResponseDifference | null;
  significance: ComparisonSignificance | null;
  evidenceMappingHint: EvidenceMappingHint | null;
  explicitNonClaims: ExplicitNonClaims;
  classification: ResponseComparatorClassificationFlags;
  error?: ComparatorError;
}
