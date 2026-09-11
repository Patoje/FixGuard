export type ReviewedEvidenceFindingCandidateTriageDecision = {
  decisionId: string;
  reviewerId: string;
  reviewedAt: string;

  decision:
    | "approve_finding_candidate_promotion"
    | "reject_finding_candidate_promotion"
    | "needs_more_evidence";

  attestations: {
    reviewedDraft: true;
    reviewedEvidenceRefs: true;
    understandsCandidateIsNotConfirmedFinding: true;
    understandsNoVulnerabilityConfirmed: true;
    understandsNoExploitabilityClaim: true;
    understandsNoSeverityRiskImpactAssigned: true;
    understandsNoRemediationAdvice: true;
    authorizedPromotionToFormalCandidate: boolean;
  };

  explicitNonClaims: {
    noConfirmedFinding: true;
    noConfirmedVulnerability: true;
    noExploitabilityClaim: true;
    noSeverityRiskOrImpactClaim: true;
    noRemediationAdvice: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };
};

export type ReviewedEvidenceFormalFindingCandidateClassification = {
  createsFormalFindingCandidate: true;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsCandidate: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

import type { ExecutionLineage } from "../evidence/EvidenceBoundaryContracts.js";

export type ReviewedEvidenceFormalFindingCandidate = {
  contractVersion: "fixguard-reviewed-evidence-formal-finding-candidate/v0";
  kind: "reviewed_evidence_formal_finding_candidate";

  candidateId: string;
  scanId: string;
  createdAt: string;

  lineage?: ExecutionLineage;

  sourceDraft: {
    draftId: string;
    sourceSelectionId: string;
    selectedCount: number;
    candidateKind: "reviewed_evidence_group";
    triageState: "requires_human_triage";
    confidenceState: "evidence_grouped_not_confirmed";
  };

  humanTriage: {
    decisionId: string;
    reviewerId: string;
    reviewedAt: string;
    decision: "approve_finding_candidate_promotion";
    humanApprovedPromotion: true;
  };

  evidenceRefs: {
    selectedRefs: Array<{
      storeRecordId: string;
      evidenceId: string;
      scanId: string;
      indicatorId: string;
    }>;
    selectedCount: number;
  };

  observedEvidenceSummary: {
    evidenceTypeCounts: Record<string, number>;
    strengthCounts: Record<string, number>;
    indicatorIds: string[];
    collectedAtRange: {
      earliest: string;
      latest: string;
    };
    savedAtRange: {
      earliest: string;
      latest: string;
    };
  };

  candidateState: {
    lifecycleState: "formal_candidate_created";
    confirmationState: "not_confirmed";
    reportState: "not_reported";
    persistenceState: "not_persisted";
    requiresFurtherHumanReview: true;
  };

  storage: {
    persisted: false;
    persistedToDatabase: false;
    externalized: false;
  };

  explicitNonClaims: {
    noConfirmedFinding: true;
    noConfirmedVulnerability: true;
    noExploitabilityClaim: true;
    noSeverityRiskOrImpactClaim: true;
    noRemediationAdvice: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceFormalFindingCandidateClassification;
};

import type {
  ReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js";

export type ReviewedEvidenceFindingCandidatePromotionRequestClassification = {
  createsFormalFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsCandidate: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type PromoteReviewedEvidenceFindingCandidateDraftRequest = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0";
  kind: "promote_reviewed_evidence_finding_candidate_draft_request";

  candidateId: string;
  scanId: string;
  requestedAt: string;

  draft: ReviewedEvidenceFindingCandidateDraft;
  triageDecision: ReviewedEvidenceFindingCandidateTriageDecision;

  lineage?: ExecutionLineage;

  classification: ReviewedEvidenceFindingCandidatePromotionRequestClassification;
};

export type ReviewedEvidenceFindingCandidatePromotionReasonCode =
  | "formal_finding_candidate_created"
  | "formal_finding_candidate_summary_created"
  | "triage_decision_rejected"
  | "triage_needs_more_evidence"
  | "triage_authorization_missing"
  | "draft_invalid"
  | "source_scan_mismatch"
  | "blocked_lineage_mismatch"
  | "invalid_promotion_request"
  | "invalid_promotion_metadata"
  | "invalid_triage_decision"
  | "invalid_candidate_summary_request"
  | "invalid_candidate_summary_metadata"
  | "candidate_validation_failed"
  | "unexpected_promotion_failure";

export type ReviewedEvidenceFindingCandidatePromotionResultClassification = {
  createsFormalFindingCandidate: boolean; // true only when status === "candidate_created"
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsCandidate: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type PromoteReviewedEvidenceFindingCandidateDraftResult = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0";
  kind: "promote_reviewed_evidence_finding_candidate_draft_result";

  candidateId: string;
  scanId: string;
  evaluatedAt: string;

  status:
    | "candidate_created"
    | "blocked"
    | "failed";

  reasonCode: ReviewedEvidenceFindingCandidatePromotionReasonCode;

  candidate?: ReviewedEvidenceFormalFindingCandidate;

  explicitNonClaims: {
    noConfirmedFinding: true;
    noConfirmedVulnerability: true;
    noExploitabilityClaim: true;
    noSeverityRiskOrImpactClaim: true;
    noRemediationAdvice: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceFindingCandidatePromotionResultClassification;

  error?: {
    code: ReviewedEvidenceFindingCandidatePromotionReasonCode;
    safeMessage: string;
  };
};

export type ReviewedEvidenceFormalFindingCandidateSummaryRequestClassification = {
  createsFormalFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsCandidate: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceFormalFindingCandidateRequest = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0";
  kind: "summarize_reviewed_evidence_formal_finding_candidate_request";

  summaryId: string;
  scanId: string;
  requestedAt: string;

  candidate: ReviewedEvidenceFormalFindingCandidate;

  classification: ReviewedEvidenceFormalFindingCandidateSummaryRequestClassification;
};

export type ReviewedEvidenceFormalFindingCandidateSummary = {
  candidateId: string;
  scanId: string;
  sourceDraftId: string;
  sourceSelectionId: string;
  selectedCount: number;
  lifecycleState: "formal_candidate_created";
  confirmationState: "not_confirmed";
  reportState: "not_reported";
  persistenceState: "not_persisted";
  evidenceTypeCounts: Record<string, number>;
  strengthCounts: Record<string, number>;
  indicatorIds: string[];
  createdAt: string;
};

export type ReviewedEvidenceFormalFindingCandidateSummaryResultClassification = {
  createsFormalFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsCandidate: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceFormalFindingCandidateResult = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0";
  kind: "summarize_reviewed_evidence_formal_finding_candidate_result";

  summaryId: string;
  scanId: string;
  evaluatedAt: string;

  status: "summarized" | "failed";

  reasonCode: ReviewedEvidenceFindingCandidatePromotionReasonCode;

  summary?: ReviewedEvidenceFormalFindingCandidateSummary;

  explicitNonClaims: {
    noConfirmedFinding: true;
    noConfirmedVulnerability: true;
    noExploitabilityClaim: true;
    noSeverityRiskOrImpactClaim: true;
    noRemediationAdvice: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceFormalFindingCandidateSummaryResultClassification;

  error?: {
    code: ReviewedEvidenceFindingCandidatePromotionReasonCode;
    safeMessage: string;
  };
};

/**
 * M58: Canonical Candidate Definition
 * In FixGuard V2, ReviewedEvidenceFormalFindingCandidate is the single canonical candidate model.
 * Historical FindingCandidateRecord (M45) is deprecated.
 */
export type CanonicalFindingCandidate = ReviewedEvidenceFormalFindingCandidate;

export function projectCanonicalCandidate(
  candidate: ReviewedEvidenceFormalFindingCandidate
): CanonicalFindingCandidate {
  return candidate;
}

