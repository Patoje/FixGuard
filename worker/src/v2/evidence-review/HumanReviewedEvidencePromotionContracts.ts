export type HumanReviewedEvidencePromotionReasonCode =
  | "promoted_to_non_persisted_evidence_record"
  | "rejected_by_human_review"
  | "human_review_requested_more_review"
  | "source_validation_not_completed"
  | "source_validation_not_evidence_ready"
  | "source_evidence_draft_missing"
  | "source_evidence_draft_invalid"
  | "source_indicator_ref_missing"
  | "source_scan_mismatch"
  | "evidence_record_validation_failed"
  | "human_review_required"
  | "invalid_promotion_request"
  | "invalid_promotion_metadata"
  | "blocked_policy_not_review_safe"
  | "unsafe_content_rejected"
  | "unexpected_promotion_failure";

export type HumanReviewedEvidencePromotionRequestClassification = {
  createsNonPersistedEvidenceRecord: false;
  createsPersistedEvidence: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
  persistsData: false;
};

import type { AuthorizedComparisonValidationResult } from "../validation/AuthorizedComparisonValidationContracts.js";
import type { EvidenceRecord } from "../evidence/EvidenceBoundaryContracts.js";

export type HumanReviewedEvidencePromotionRequest = {
  contractVersion: "fixguard-human-reviewed-evidence-promotion/v0";
  kind: "human_reviewed_evidence_promotion_request";

  promotionId: string;
  scanId: string;
  requestedAt: string;

  validationResult: AuthorizedComparisonValidationResult;

  sourceIndicatorRef: {
    kind: "reviewed_indicator_reference";
    indicatorId: string;
    scanId: string;
  };

  reviewDecision: {
    decision: "approve_evidence" | "reject" | "needs_more_review";
    reviewerId: string;
    reviewedAt: string;
  };

  classification: HumanReviewedEvidencePromotionRequestClassification;
};

export type HumanReviewedEvidencePromotionResultClassification = {
  createsNonPersistedEvidenceRecord: boolean;
  createsPersistedEvidence: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
  persistsData: false;
};

export type HumanReviewedEvidencePromotionResult = {
  contractVersion: "fixguard-human-reviewed-evidence-promotion/v0";
  kind: "human_reviewed_evidence_promotion_result";

  promotionId: string;
  scanId: string;
  evaluatedAt: string;

  status: "promoted" | "rejected" | "needs_more_review" | "blocked" | "failed";
  reasonCode: HumanReviewedEvidencePromotionReasonCode;

  sourceValidationSummary?: {
    validationId: string;
    status: string;
    reasonCode: string;
    evidenceDraftPresent: boolean;
  };

  reviewSummary?: {
    decision: "approve_evidence" | "reject" | "needs_more_review";
    reviewerId: string;
    reviewedAt: string;
  };

  nonPersistedEvidenceRecord?: EvidenceRecord;

  explicitNonClaims: {
    noConfirmedVulnerability: true;
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noSeverityRiskOrImpactClaim: true;
    noExternalReportCreated: true;
    noPersistence: true;
    noNetworkExecution: true;
    noToolExecution: true;
  };

  classification: HumanReviewedEvidencePromotionResultClassification;

  error?: {
    code: HumanReviewedEvidencePromotionReasonCode;
    safeMessage: string;
  };
};
