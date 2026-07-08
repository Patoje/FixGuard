import type {
  ResponseComparisonResult,
  SignalSummaryItem
} from "../comparison/ResponseComparatorContracts.js";

import type {
  EvidenceType,
  EvidenceStrength
} from "../evidence/EvidenceBoundaryContracts.js";

export const COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION = "fixguard-comparison-evidence-mapping/v0";

export type SourceComparisonMode =
  | "http_difference"
  | "authorization_difference"
  | "time_based_difference"
  | "generic_signal_comparison";

export type MappingMode =
  | "http_difference_to_evidence"
  | "authorization_difference_to_evidence"
  | "time_based_signal_to_evidence"
  | "manual_review_note";

export interface ReviewerPolicy {
  requireHumanReview: true;
  allowAutoEvidenceRecord: false;
  allowFindingCandidateCreation: false;
  allowPersistence: false;
  allowExternalDelivery: false;
}

export interface ComparisonEvidenceMappingRequestClassification {
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

export interface ComparisonEvidenceMappingRequest {
  contractVersion: "fixguard-comparison-evidence-mapping/v0";
  kind: "comparison_evidence_mapping_request";
  mappingId: string;
  scanId: string;
  requestedAt: string;
  sourceComparison: ResponseComparisonResult;
  sourceComparisonMode: SourceComparisonMode;
  mappingMode: MappingMode;
  reviewerPolicy: ReviewerPolicy;
  classification: ComparisonEvidenceMappingRequestClassification;
}

export interface ExplicitNonClaims {
  noConfirmedVulnerability: true;
  noFindingCreated: true;
  noFindingCandidateCreated: true;
  noPersistedEvidenceCreated: true;
  noSeverityRiskOrImpactClaim: true;
  noExternalReportCreated: true;
  noRawSensitiveDataIncluded: true;
}

export interface EvidenceDraftEnvelope {
  draftKind: "non_persisted_comparison_evidence_draft";
  draftId: string;
  suggestedEvidenceType: EvidenceType;
  suggestedStrength: EvidenceStrength;
  sourceComparisonId: string;
  sourceSnapshotIds: {
    baselineSnapshotId: string;
    validationSnapshotId: string;
  };
  requiresHumanReview: true;
  notPersisted: true;
  notARealFinding: true;
  notConfirmedEvidence: true;
  notForExternalDelivery: true;
  notM45EvidenceRecord: true;
  safeRationale: string;
}

export interface SourceSummary {
  comparisonStatus: "completed" | "failed";
  sourceComparisonMode: SourceComparisonMode;
  strongestSignal:
    | "none"
    | "status_code"
    | "content_length"
    | "response_time"
    | "body_hash"
    | "headers"
    | "json_shape"
    | "redirect"
    | "auth_state"
    | "error_signal";
  comparisonSignalStrength: "none" | "weak" | "moderate" | "strong";
  signalSummary: SignalSummaryItem[];
}

export type MappingStatus =
  | "draft_ready"
  | "blocked"
  | "needs_more_review"
  | "failed";

export type MappingReasonCode =
  | "draft_ready_http_difference"
  | "draft_ready_authorization_difference"
  | "draft_ready_time_based_signal"
  | "needs_more_review_no_significant_difference"
  | "needs_more_review_weak_signal"
  | "blocked_failed_source_comparison"
  | "blocked_source_nonclaims_missing"
  | "blocked_source_metadata_unsafe"
  | "blocked_mode_mismatch"
  | "blocked_policy_not_review_safe"
  | "invalid_mapping_request"
  | "invalid_mapping_metadata"
  | "unsafe_content_rejected"
  | "unexpected_mapping_failure";

export interface EvidenceMappingDecision {
  contractVersion: "fixguard-comparison-evidence-mapping/v0";
  kind: "evidence_mapping_decision";
  mappingId: string;
  scanId: string;
  comparisonId: string;
  mappedAt: string;
  status: MappingStatus;
  reasonCode: MappingReasonCode;
  sourceSummary?: SourceSummary;
  mappedEvidenceType?: EvidenceType;
  mappedSignalStrength?: EvidenceStrength;
  evidenceDraft?: EvidenceDraftEnvelope;
  reviewerPolicy: ReviewerPolicy;
  explicitNonClaims: ExplicitNonClaims;
  classification: ComparisonEvidenceMappingRequestClassification;
  error?: { safeMessage: string; code: MappingReasonCode };
}
