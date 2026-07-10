import type { ReviewedEvidenceStoreSummary } from "../evidence-store/ReviewedEvidenceStoreContracts.js";

export type ReviewedEvidenceSelectionRef = {
  storeRecordId: string;
  evidenceId: string;
  scanId: string;
  indicatorId: string;
};

export type ReviewedEvidenceSelectionClassification = {
  createsReviewedEvidenceSelectionSet: true;
  persistsSelectionSet: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsFinding: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type ReviewedEvidenceSelectionSet = {
  contractVersion: "fixguard-reviewed-evidence-selection/v0";
  kind: "reviewed_evidence_selection_set";

  selectionId: string;
  scanId: string;
  createdAt: string;

  selectionMode:
    | "explicit_store_record_ids"
    | "explicit_evidence_ids"
    | "criteria_query";

  selectedRefs: ReviewedEvidenceSelectionRef[];
  selectedSummaries: ReviewedEvidenceStoreSummary[];

  selectionStats: {
    selectedCount: number;
    candidateInputCount: number;
    rejectedInputCount: number;
    duplicateInputCount: number;
  };

  storage: {
    persisted: false;
    persistedToDatabase: false;
    externalized: false;
  };

  explicitNonClaims: {
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noConfirmedVulnerability: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceSelectionClassification;
};

export type ReviewedEvidenceSelectionCriteria = {
  evidenceTypes?: string[];
  strengths?: string[];
  indicatorIds?: string[];
  savedAtFrom?: string;
  savedAtTo?: string;
  collectedAtFrom?: string;
  collectedAtTo?: string;
};

export type ReviewedEvidenceSelectionOptions = {
  limit?: number;
};

export type ReviewedEvidenceSelectionRequestClassification = {
  createsReviewedEvidenceSelectionSet: false;
  persistsSelectionSet: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsFinding: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SelectReviewedEvidenceRequest = {
  contractVersion: "fixguard-reviewed-evidence-selection/v0";
  kind: "select_reviewed_evidence_request";

  selectionId: string;
  scanId: string;
  requestedAt: string;

  source:
    | {
        mode: "explicit_store_record_ids";
        storeRecordIds: string[];
      }
    | {
        mode: "explicit_evidence_ids";
        evidenceIds: string[];
      }
    | {
        mode: "criteria_query";
        criteria: ReviewedEvidenceSelectionCriteria;
      };

  options?: ReviewedEvidenceSelectionOptions;

  classification: ReviewedEvidenceSelectionRequestClassification;
};

export type ReviewedEvidenceSelectionReasonCode =
  | "reviewed_evidence_selected"
  | "selection_summary_created"
  | "selection_empty"
  | "selected_evidence_not_found"
  | "source_reviewed_evidence_invalid"
  | "source_scan_mismatch"
  | "invalid_selection_request"
  | "invalid_selection_metadata"
  | "invalid_selection_criteria"
  | "invalid_selection_options"
  | "invalid_selection_summary_request"
  | "invalid_selection_summary_metadata"
  | "repository_read_failed"
  | "selection_set_validation_failed"
  | "unexpected_selection_failure";

export type ReviewedEvidenceSelectionResultClassification = {
  createsReviewedEvidenceSelectionSet: boolean;
  persistsSelectionSet: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsFinding: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SelectReviewedEvidenceResult = {
  contractVersion: "fixguard-reviewed-evidence-selection/v0";
  kind: "select_reviewed_evidence_result";

  selectionId: string;
  scanId: string;
  evaluatedAt: string;

  status: "selected" | "blocked" | "failed";

  reasonCode: ReviewedEvidenceSelectionReasonCode;

  selectionSet?: ReviewedEvidenceSelectionSet;

  explicitNonClaims: {
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noConfirmedVulnerability: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceSelectionResultClassification;

  error?: {
    code: ReviewedEvidenceSelectionReasonCode;
    safeMessage: string;
  };
};

export type ReviewedEvidenceSelectionSummaryRequestClassification = {
  createsReviewedEvidenceSelectionSet: false;
  persistsSelectionSet: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsFinding: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceSelectionRequest = {
  contractVersion: "fixguard-reviewed-evidence-selection/v0";
  kind: "summarize_reviewed_evidence_selection_request";

  summaryId: string;
  scanId: string;
  requestedAt: string;

  selectionSet: ReviewedEvidenceSelectionSet;

  classification: ReviewedEvidenceSelectionSummaryRequestClassification;
};

export type ReviewedEvidenceSelectionSummary = {
  selectionId: string;
  scanId: string;
  selectionMode:
    | "explicit_store_record_ids"
    | "explicit_evidence_ids"
    | "criteria_query";
  selectedCount: number;
  candidateInputCount: number;
  rejectedInputCount: number;
  duplicateInputCount: number;
  selectedRefs: ReviewedEvidenceSelectionRef[];
  createdAt: string;
};

export type ReviewedEvidenceSelectionSummaryResultClassification = {
  createsReviewedEvidenceSelectionSet: false;
  persistsSelectionSet: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsFinding: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SummarizeReviewedEvidenceSelectionResult = {
  contractVersion: "fixguard-reviewed-evidence-selection/v0";
  kind: "summarize_reviewed_evidence_selection_result";

  summaryId: string;
  scanId: string;
  evaluatedAt: string;

  status: "summarized" | "failed";
  reasonCode: ReviewedEvidenceSelectionReasonCode;

  summary?: ReviewedEvidenceSelectionSummary;

  explicitNonClaims: {
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noConfirmedVulnerability: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
    noPersistence: true;
  };

  classification: ReviewedEvidenceSelectionSummaryResultClassification;

  error?: {
    code: ReviewedEvidenceSelectionReasonCode;
    safeMessage: string;
  };
};
