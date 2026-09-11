export type EvidenceBoundaryContractVersion = "fixguard-evidence-boundary/v0";

export type EvidenceBoundaryClassificationFlags = {
  createsRealFindings: false;
  createsPersistedEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
};

export const ALLOWED_OBSERVATION_SOURCE_KINDS = [
  "crawler", "passive_recon", "active_recon", "tool_adapter", "response_comparator", "oob_engine", "manual"
] as const;
export type ObservationSourceKind = typeof ALLOWED_OBSERVATION_SOURCE_KINDS[number];

export const ALLOWED_OBSERVATION_TYPES = [
  "endpoint_discovered", "header_observed", "technology_detected", "asset_discovered", 
  "form_discovered", "api_operation_discovered", "raw_tool_output_observed", 
  "response_anomaly_observed", "oob_callback_observed"
] as const;
export type ObservationType = typeof ALLOWED_OBSERVATION_TYPES[number];

export const ALLOWED_SAFE_EXCERPT_SOURCES = [
  "sanitized_header_name", "sanitized_body_excerpt", "manual_note"
] as const;
export type SafeExcerpt = {
  text: string;
  source: typeof ALLOWED_SAFE_EXCERPT_SOURCES[number];
  redacted: true;
};

export const ALLOWED_HTTP_METHODS = [
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
] as const;
export type SafeSubject = {
  normalizedOrigin?: string;
  method?: typeof ALLOWED_HTTP_METHODS[number];
  pathTemplate?: string;
  routeId?: string;
  assetUrlHash?: string;
};

export type ObservationSafeData = {
  statusCode?: number;
  contentLength?: number;
  headerNames?: string[];
  bodyHash?: string;
  rawOutputHash?: string;
  safeExcerpt?: SafeExcerpt;
};

export type ObservationRecord = {
  contractVersion: EvidenceBoundaryContractVersion;
  kind: "observation_record";
  observationId: string;
  scanId: string;
  observedAt: string;
  sourceKind: ObservationSourceKind;
  observationType: ObservationType;
  subject: SafeSubject;
  provenance: {
    originId?: string;
    description: string;
  };
  safeData: ObservationSafeData;
  classification: EvidenceBoundaryClassificationFlags;
};

export const ALLOWED_INDICATOR_TYPES = [
  "potential_sqli", "potential_xss", "potential_ssrf", "potential_xxe", 
  "idor_candidate", "bola_candidate", "mass_assignment_candidate", 
  "auth_weakness_candidate", "secret_exposure_candidate", "cors_candidate", 
  "misconfiguration_candidate", "version_exposure_candidate", "oob_validation_candidate"
] as const;
export type IndicatorType = typeof ALLOWED_INDICATOR_TYPES[number];

export const ALLOWED_APPROVAL_LEVELS = [
  "none", "active_validation", "authenticated_testing", "aggressive_validation", "oob_testing"
] as const;
export type ApprovalLevelRequired = typeof ALLOWED_APPROVAL_LEVELS[number];

export type IndicatorRecord = {
  contractVersion: EvidenceBoundaryContractVersion;
  kind: "indicator_record";
  indicatorId: string;
  scanId: string;
  derivedFromObservationIds: string[];
  indicatorType: IndicatorType;
  target: SafeSubject;
  confidence: number;
  rationale: string;
  suggestedValidation: string;
  requiresHumanApproval: boolean;
  approvalLevelRequired: ApprovalLevelRequired;
  classification: EvidenceBoundaryClassificationFlags;
};

export const ALLOWED_COLLECTED_BY = [
  "response_comparator", "oob_engine", "tool_adapter", "manual_review"
] as const;
export type CollectedBy = typeof ALLOWED_COLLECTED_BY[number];

export const ALLOWED_EVIDENCE_TYPES = [
  "http_difference", "oob_callback", "authorization_difference", "time_based_difference", 
  "configuration_exposure", "secret_indicator_validated", "manual_review_note"
] as const;
export type EvidenceType = typeof ALLOWED_EVIDENCE_TYPES[number];

export type EvidenceSnapshot = {
  method?: string;
  normalizedUrlHash?: string;
  pathTemplate?: string;
  statusCode?: number;
  contentLength?: number;
  responseTimeMs?: number;
  headerNames?: string[];
  bodyHash?: string;
  safeExcerpt?: SafeExcerpt;
  payloadDescription?: string;
  payloadHash?: string;
};

export type EvidenceDifference = {
  statusCodeChanged?: boolean;
  contentLengthDeltaPercent?: number;
  responseTimeDeltaMs?: number;
  newJsonKeys?: string[];
  missingJsonKeys?: string[];
  redirectChanged?: boolean;
  authStateChanged?: boolean;
  errorSignalObserved?: boolean;
};

export const ALLOWED_OOB_PROTOCOLS = [
  "http", "dns", "ldap", "ftp", "smb"
] as const;

export type EvidenceOobCallback = {
  correlationId: string;
  receivedAt: string;
  protocol: typeof ALLOWED_OOB_PROTOCOLS[number];
  sourceIpHash: string;
  rawCallbackHash: string;
};

export const ALLOWED_EVIDENCE_STRENGTHS = ["weak", "moderate", "strong"] as const;
export type EvidenceStrength = typeof ALLOWED_EVIDENCE_STRENGTHS[number];

/**
 * M58: Mandatory authorization lineage attached to substantive evidence records.
 */
export type ExecutionLineage = {
  assessmentId: string;
  scanId: string;
  authorizationGrantId: string;
  authorizationDecisionId: string;
  actorId: string;
  validationId: string;
};

export type EvidenceRecord = {
  contractVersion: EvidenceBoundaryContractVersion;
  kind: "evidence_record";
  evidenceId: string;
  scanId: string;
  indicatorId: string;
  collectedAt: string;
  collectedBy: CollectedBy;
  evidenceType: EvidenceType;
  baseline?: EvidenceSnapshot;
  attackOrValidation?: EvidenceSnapshot;
  difference?: EvidenceDifference;
  oobCallback?: EvidenceOobCallback;
  lineage?: ExecutionLineage;
  redaction: {
    isRedacted: true;
    redactionMethod: string;
  };
  strength: EvidenceStrength;
  classification: EvidenceBoundaryClassificationFlags;
};

// ---------------------------------------------------------------------------
// M58: Discriminated Unions for Substantive Evidence Payloads
// ---------------------------------------------------------------------------

export type HttpDifferenceSubstancePayload = {
  evidenceType: "http_difference" | "authorization_difference";
  baseline: EvidenceSnapshot;
  attackOrValidation: EvidenceSnapshot;
  difference: EvidenceDifference;
};

export type TimeBasedDifferenceSubstancePayload = {
  evidenceType: "time_based_difference";
  baseline: EvidenceSnapshot;
  attackOrValidation: EvidenceSnapshot;
  difference: EvidenceDifference & { responseTimeDeltaMs: number };
};

export type OobCallbackSubstancePayload = {
  evidenceType: "oob_callback";
  oobCallback: EvidenceOobCallback;
};

export type ConfigurationExposureSubstancePayload = {
  evidenceType: "configuration_exposure" | "secret_indicator_validated";
  attackOrValidation: EvidenceSnapshot;
};

export type ManualReviewNoteSubstancePayload = {
  evidenceType: "manual_review_note";
  attackOrValidation: EvidenceSnapshot & {
    safeExcerpt: SafeExcerpt & { source: "manual_note" };
  };
};

export type EvidenceSubstancePayload =
  | HttpDifferenceSubstancePayload
  | TimeBasedDifferenceSubstancePayload
  | OobCallbackSubstancePayload
  | ConfigurationExposureSubstancePayload
  | ManualReviewNoteSubstancePayload;

export type SubstantiveEvidenceRecord = EvidenceRecord & {
  lineage: ExecutionLineage;
} & (
  | ({ evidenceType: "http_difference" | "authorization_difference" } & HttpDifferenceSubstancePayload)
  | ({ evidenceType: "time_based_difference" } & TimeBasedDifferenceSubstancePayload)
  | ({ evidenceType: "oob_callback" } & OobCallbackSubstancePayload)
  | ({ evidenceType: "configuration_exposure" | "secret_indicator_validated" } & ConfigurationExposureSubstancePayload)
  | ({ evidenceType: "manual_review_note" } & ManualReviewNoteSubstancePayload)
);

export const ALLOWED_CANDIDATE_TYPES = [
  "sqli_candidate", "xss_candidate", "ssrf_candidate", "xxe_candidate", 
  "idor_candidate", "bola_candidate", "mass_assignment_candidate", 
  "auth_weakness_candidate", "secret_exposure_candidate", "cors_candidate", 
  "misconfiguration_candidate", "version_exposure_candidate"
] as const;
export type FindingCandidateType = typeof ALLOWED_CANDIDATE_TYPES[number];

export const ALLOWED_CANDIDATE_STATUSES = ["candidate", "needs_review", "rejected"] as const;
export type FindingCandidateStatus = typeof ALLOWED_CANDIDATE_STATUSES[number];

export const ALLOWED_SEVERITY_GATE_STATUSES = ["not_assessed", "requires_human_review", "blocked_until_impact_review"] as const;
export type SeverityGate = {
  status: typeof ALLOWED_SEVERITY_GATE_STATUSES[number];
  reason: string;
};

/**
 * @deprecated Use ReviewedEvidenceFormalFindingCandidate from finding-candidate-promotion instead.
 * FindingCandidateRecord is an early M45 experimental boundary model.
 * In FixGuard V2 (M54+), ReviewedEvidenceFormalFindingCandidate is the canonical candidate.
 */
export type FindingCandidateRecord = {
  contractVersion: EvidenceBoundaryContractVersion;
  kind: "finding_candidate_record";
  candidateId: string;
  scanId: string;
  derivedFromIndicatorIds: string[];
  evidenceIds: string[];
  candidateType: FindingCandidateType;
  status: FindingCandidateStatus;
  confidence: number;
  severityGate: SeverityGate;
  rationale: string;
  classification: EvidenceBoundaryClassificationFlags;
  isRealFinding: false;
  requiresHumanReview: true;
  notForExternalDelivery: true;
};

export type ReportReadiness = {
  externalDeliveryReady: false;
  requiresHumanReview: true;
  notAFinalVulnerabilityReport: true;
};

export type ExplicitNonClaims = {
  noConfirmedVulnerability: true;
  noRealFindingCreated: true;
  noPersistedEvidenceCreated: true;
  noRiskSeverityOrImpactClaim: true;
  noRawSensitiveDataIncluded: true;
};

export type SafeReportItemSnapshot = {
  contractVersion: EvidenceBoundaryContractVersion;
  kind: "safe_report_item_snapshot";
  candidateId: string;
  title: string;
  summary: string;
  affectedSubject: SafeSubject;
  evidenceSummary: string;
  recommendationSummary: string;
  reportReadiness: ReportReadiness;
  explicitNonClaims: ExplicitNonClaims;
  classification: EvidenceBoundaryClassificationFlags;
};

export type EvidenceBoundaryErrorCode = 
  | "invalid_observation"
  | "invalid_indicator"
  | "invalid_evidence"
  | "invalid_finding_candidate"
  | "invalid_report_item"
  | "promotion_not_eligible"
  | "insufficient_evidence"
  | "insufficient_evidence_substance"
  | "invalid_lineage"
  | "cross_scan_evidence_rejected"
  | "unsafe_content_rejected"
  | "manual_review_required"
  | "not_external_report_ready"
  | "unexpected_evidence_boundary_failure";

export type ValidationResult = 
  | { isValid: true; error?: undefined }
  | { isValid: false; errorCode: EvidenceBoundaryErrorCode; message: string };

export type FindingPromotionDecisionStatus = 
  | "eligible_for_candidate"
  | "needs_more_evidence"
  | "rejected"
  | "invalid_input";

export type FindingPromotionDecision = {
  status: FindingPromotionDecisionStatus;
  errorCode?: EvidenceBoundaryErrorCode;
  reason: string;
};

export type BuildFindingCandidateResult = 
  | {
      status: "completed";
      candidate: FindingCandidateRecord;
      error?: undefined;
      classification: EvidenceBoundaryClassificationFlags;
    }
  | {
      status: "failed";
      candidate?: undefined;
      error: { code: EvidenceBoundaryErrorCode; message: string };
      classification: EvidenceBoundaryClassificationFlags;
    };

export type BuildSafeReportItemSnapshotResult = 
  | {
      status: "completed";
      reportItem: SafeReportItemSnapshot;
      error?: undefined;
      classification: EvidenceBoundaryClassificationFlags;
    }
  | {
      status: "failed";
      reportItem?: undefined;
      error: { code: EvidenceBoundaryErrorCode; message: string };
      classification: EvidenceBoundaryClassificationFlags;
    };
