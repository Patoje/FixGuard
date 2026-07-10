import type {
  ReviewedEvidenceSelectionSet,
  ReviewedEvidenceSelectionRef
} from "../evidence-selection/ReviewedEvidenceSelectionContracts.js";

export type ReviewedEvidenceFindingCandidateDraftClassification = {
  createsFindingCandidateDraft: true;
  createsFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsDraft: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type ReviewedEvidenceFindingCandidateDraft = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0";
  kind: "reviewed_evidence_finding_candidate_draft";

  draftId: string;
  scanId: string;
  createdAt: string;

  sourceSelection: {
    selectionId: string;
    selectionMode:
      | "explicit_store_record_ids"
      | "explicit_evidence_ids"
      | "criteria_query";
    selectedCount: number;
    selectedRefs: ReviewedEvidenceSelectionRef[];
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

  draftTriage: {
    triageState: "requires_human_triage";
    confidenceState: "evidence_grouped_not_confirmed";
    humanReviewRequired: true;
  };

  draftLabels: {
    candidateKind: "reviewed_evidence_group";
    labelSource: "closed_boundary_generated";
  };

  storage: {
    persisted: false;
    persistedToDatabase: false;
    externalized: false;
  };

  explicitNonClaims: {
    noFindingCandidateCreated: true;
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

  classification: ReviewedEvidenceFindingCandidateDraftClassification;
};

export type ReviewedEvidenceFindingCandidateDraftRequestClassification = {
  createsFindingCandidateDraft: false;
  createsFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsDraft: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type CreateReviewedEvidenceFindingCandidateDraftRequest = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0";
  kind: "create_reviewed_evidence_finding_candidate_draft_request";

  draftId: string;
  scanId: string;
  requestedAt: string;

  selectionSet: ReviewedEvidenceSelectionSet;

  classification: ReviewedEvidenceFindingCandidateDraftRequestClassification;
};

export type ReviewedEvidenceFindingCandidateDraftReasonCode =
  | "finding_candidate_draft_created"
  | "finding_candidate_draft_summary_created"
  | "selection_set_empty"
  | "selection_set_invalid"
  | "source_scan_mismatch"
  | "invalid_draft_request"
  | "invalid_draft_metadata"
  | "invalid_draft_summary_request"
  | "invalid_draft_summary_metadata"
  | "draft_validation_failed"
  | "unexpected_draft_failure";

export type ReviewedEvidenceFindingCandidateDraftResultClassification = {
  createsFindingCandidateDraft: boolean; // true only when status === "draft_created"
  createsFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsDraft: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type CreateReviewedEvidenceFindingCandidateDraftResult = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0";
  kind: "create_reviewed_evidence_finding_candidate_draft_result";

  draftId: string;
  scanId: string;
  evaluatedAt: string;

  status: "draft_created" | "blocked" | "failed";

  reasonCode: ReviewedEvidenceFindingCandidateDraftReasonCode;

  draft?: ReviewedEvidenceFindingCandidateDraft;

  explicitNonClaims: {
    noFindingCandidateCreated: true;
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

  classification: ReviewedEvidenceFindingCandidateDraftResultClassification;

  error?: {
    code: ReviewedEvidenceFindingCandidateDraftReasonCode;
    safeMessage: string;
  };
};

export type ReviewedEvidenceFindingCandidateDraftSummaryRequestClassification = {
  createsFindingCandidateDraft: false;
  createsFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsDraft: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceFindingCandidateDraftRequest = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0";
  kind: "summarize_reviewed_evidence_finding_candidate_draft_request";

  summaryId: string;
  scanId: string;
  requestedAt: string;

  draft: ReviewedEvidenceFindingCandidateDraft;

  classification: ReviewedEvidenceFindingCandidateDraftSummaryRequestClassification;
};

export type ReviewedEvidenceFindingCandidateDraftSummary = {
  draftId: string;
  scanId: string;
  sourceSelectionId: string;
  selectedCount: number;
  candidateKind: "reviewed_evidence_group";
  triageState: "requires_human_triage";
  confidenceState: "evidence_grouped_not_confirmed";
  evidenceTypeCounts: Record<string, number>;
  strengthCounts: Record<string, number>;
  indicatorIds: string[];
  createdAt: string;
};

export type ReviewedEvidenceFindingCandidateDraftSummaryResultClassification = {
  createsFindingCandidateDraft: false;
  createsFindingCandidate: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsDraft: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceFindingCandidateDraftResult = {
  contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0";
  kind: "summarize_reviewed_evidence_finding_candidate_draft_result";

  summaryId: string;
  scanId: string;
  evaluatedAt: string;

  status: "summarized" | "failed";
  reasonCode: ReviewedEvidenceFindingCandidateDraftReasonCode;

  summary?: ReviewedEvidenceFindingCandidateDraftSummary;

  explicitNonClaims: {
    noFindingCandidateCreated: true;
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

  classification: ReviewedEvidenceFindingCandidateDraftSummaryResultClassification;

  error?: {
    code: ReviewedEvidenceFindingCandidateDraftReasonCode;
    safeMessage: string;
  };
};
