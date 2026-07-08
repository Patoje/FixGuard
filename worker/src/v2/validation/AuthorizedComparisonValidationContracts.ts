export const AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION = "fixguard-authorized-comparison-validation/v0";

import type { AuthorizedScopeGrant, ScopeActionRequest, ReasonCode as ScopeReasonCode, RequiredPermission } from "../scope/AuthorizedScopeContracts.js";
import type { SafeResponseSnapshot, ComparisonMode, ComparisonThresholds } from "../comparison/ResponseComparatorContracts.js";
import type { ReviewerPolicy, MappingMode, EvidenceDraftEnvelope, SourceComparisonMode } from "../evidence-mapping/ComparisonEvidenceMappingContracts.js";
import type { EvidenceType } from "../evidence/EvidenceBoundaryContracts.js";

export type AuthorizedComparisonValidationReasonCode = 
  | "completed_with_evidence_draft"
  | "needs_more_review_from_mapping"
  | "blocked_scope_denied"
  | "blocked_scope_invalid"
  | "blocked_comparison_failed"
  | "blocked_mapping_blocked"
  | "failed_mapping_failed"
  | "blocked_policy_not_review_safe"
  | "invalid_validation_request"
  | "invalid_validation_metadata"
  | "unsafe_content_rejected"
  | "unexpected_validation_failure";

export interface ExplicitNonClaims {
  noConfirmedVulnerability: true;
  noFindingCreated: true;
  noFindingCandidateCreated: true;
  noPersistedEvidenceCreated: true;
  noSeverityRiskOrImpactClaim: true;
  noExternalReportCreated: true;
  noRawSensitiveDataIncluded: true;
  noNetworkExecution: true;
  noToolExecution: true;
}

export interface AuthorizedComparisonValidationClassification {
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

export interface AuthorizedComparisonValidationRequest {
  contractVersion: "fixguard-authorized-comparison-validation/v0";
  kind: "authorized_comparison_validation_request";
  validationId: string;
  scanId: string;
  requestedAt: string;

  scopeGrant: AuthorizedScopeGrant;
  scopeActionRequest: ScopeActionRequest;

  baselineSnapshot: SafeResponseSnapshot;
  validationSnapshot: SafeResponseSnapshot;

  comparisonMode: ComparisonMode;
  comparisonThresholds: ComparisonThresholds;

  mappingMode: MappingMode;
  reviewerPolicy: ReviewerPolicy;

  classification: AuthorizedComparisonValidationClassification;
}

export interface ScopeDecisionSummary {
  decision: "allowed" | "denied";
  reasonCode: ScopeReasonCode | string;
  matchedPermission?: RequiredPermission | string;
}

export interface ComparisonSummary {
  status: "completed" | "failed";
  comparisonId: string;
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
  comparisonSignalStrength:
    | "none"
    | "weak"
    | "moderate"
    | "strong";
  suggestedEvidenceType: EvidenceType;
}

export interface MappingSummary {
  status:
    | "draft_ready"
    | "blocked"
    | "needs_more_review"
    | "failed";
  reasonCode: string;
  mappedEvidenceType?: EvidenceType;
  mappedSignalStrength?: "weak" | "moderate" | "strong";
}

export interface AuthorizedComparisonValidationResult {
  contractVersion: "fixguard-authorized-comparison-validation/v0";
  kind: "authorized_comparison_validation_result";
  validationId: string;
  scanId: string;
  evaluatedAt: string;

  status: "completed" | "blocked" | "needs_more_review" | "failed";
  reasonCode: AuthorizedComparisonValidationReasonCode;

  scopeDecisionSummary?: ScopeDecisionSummary;
  comparisonSummary?: ComparisonSummary;
  mappingSummary?: MappingSummary;
  evidenceDraft?: EvidenceDraftEnvelope;

  explicitNonClaims: ExplicitNonClaims;
  classification: AuthorizedComparisonValidationClassification;
  error?: {
    code: AuthorizedComparisonValidationReasonCode;
    safeMessage: string;
  };
}
