import type { ReviewedEvidenceStoreRecord } from "../evidence-store/ReviewedEvidenceStoreContracts.js";
import type { HumanReviewedEvidencePromotionResult } from "../evidence-review/HumanReviewedEvidencePromotionContracts.js";

export type CoreCandidatePipelineRealityCheckFailureStage =
  | "input_fixture"
  | "reviewed_evidence_store"
  | "reviewed_evidence_selection"
  | "candidate_draft"
  | "human_triage_gate"
  | "formal_candidate_promotion"
  | "formal_candidate_summary"
  | "continuity_validation"
  | "boundary_validation"
  | "unexpected_failure";

export type CoreCandidatePipelineContinuityCheck =
  | "same_scan_id"
  | "refs_preserved"
  | "counts_preserved"
  | "indicator_ids_preserved"
  | "timestamp_ranges_preserved"
  | "human_approval_required"
  | "nonclaims_preserved";

export type CoreCandidatePipelineRealityCheckReasonCode =
  | "core_candidate_pipeline_reality_check_passed"
  | "invalid_reality_check_input"
  | "reviewed_evidence_store_failed"
  | "reviewed_evidence_selection_failed"
  | "candidate_draft_failed"
  | "human_triage_gate_failed"
  | "formal_candidate_promotion_failed"
  | "formal_candidate_summary_failed"
  | "continuity_check_failed"
  | "boundary_check_failed"
  | "unexpected_reality_check_failure";

export type CoreCandidatePipelineRealityCheckNonClaims = {
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

export type CoreCandidatePipelineRealityCheckClassification = {
  createsNewDomainFeature: false;
  createsConfirmedFinding: false;
  createsSafeReportItem: false;
  createsExternalReport: false;
  confirmsVulnerabilities: false;
  makesExploitabilityClaims: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  providesRemediationAdvice: false;
  persistsToDatabase: false;
  executesNetwork: false;
  executesTools: false;
};

export type RunCoreCandidatePipelineRealityCheckRequest = {
  contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0";
  kind: "run_core_candidate_pipeline_reality_check_request";

  scanId: string;
  evaluatedAt: string;

  fixture: {
    promotedEvidenceResults: HumanReviewedEvidencePromotionResult[];
  };

  debugMutation?: 
    | "mutate_scan_id_after_selection"
    | "mutate_selected_count_after_selection"
    | "mutate_candidate_refs_before_summary";

  classification: CoreCandidatePipelineRealityCheckClassification;
};

export type CoreCandidatePipelineRealityCheckResult =
  | CoreCandidatePipelineRealityCheckPassedResult
  | CoreCandidatePipelineRealityCheckFailedResult;

export type CoreCandidatePipelineRealityCheckPassedResult = {
  contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0";
  kind: "core_candidate_pipeline_reality_check_result";

  status: "passed";
  scanId: string;
  evaluatedAt: string;

  stages: {
    reviewedEvidenceStored: {
      completed: true;
      count: number;
    };
    reviewedEvidenceSelected: {
      completed: true;
      selectionId: string;
      selectedCount: number;
    };
    draftCreated: {
      completed: true;
      draftId: string;
      selectedCount: number;
    };
    formalCandidatePromoted: {
      completed: true;
      candidateId: string;
      selectedCount: number;
      humanApprovedPromotion: true;
    };
    formalCandidateSummarized: {
      completed: true;
      summaryId: string;
      selectedCount: number;
    };
  };

  continuity: {
    sameScanId: true;
    refsPreserved: true;
    countsPreserved: true;
    indicatorIdsPreserved: true;
    timestampRangesPreserved: true;
    humanApprovalRequired: true;
    nonClaimsPreserved: true;
  };

  finalState: {
    lifecycleState: "formal_candidate_created";
    confirmationState: "not_confirmed";
    reportState: "not_reported";
    persistenceState: "not_persisted";
    requiresFurtherHumanReview: true;
  };

  explicitNonClaims: CoreCandidatePipelineRealityCheckNonClaims;
  classification: CoreCandidatePipelineRealityCheckClassification;
};

export type CoreCandidatePipelineRealityCheckFailedResult = {
  contractVersion: "fixguard-core-candidate-pipeline-reality-check/v0";
  kind: "core_candidate_pipeline_reality_check_result";

  status: "failed";
  scanId: string;
  evaluatedAt: string;

  failureStage: CoreCandidatePipelineRealityCheckFailureStage;
  failedContinuityChecks: CoreCandidatePipelineContinuityCheck[];

  stages: {
    reviewedEvidenceStored: {
      completed: boolean;
      count?: number;
    };
    reviewedEvidenceSelected: {
      completed: boolean;
      selectionId?: string;
      selectedCount?: number;
    };
    draftCreated: {
      completed: boolean;
      draftId?: string;
      selectedCount?: number;
    };
    formalCandidatePromoted: {
      completed: boolean;
      candidateId?: string;
      selectedCount?: number;
      humanApprovedPromotion?: boolean;
    };
    formalCandidateSummarized: {
      completed: boolean;
      summaryId?: string;
      selectedCount?: number;
    };
  };

  continuity: {
    sameScanId: boolean;
    refsPreserved: boolean;
    countsPreserved: boolean;
    indicatorIdsPreserved: boolean;
    timestampRangesPreserved: boolean;
    humanApprovalRequired: boolean;
    nonClaimsPreserved: boolean;
  };

  explicitNonClaims: CoreCandidatePipelineRealityCheckNonClaims;
  classification: CoreCandidatePipelineRealityCheckClassification;

  error: {
    code: CoreCandidatePipelineRealityCheckReasonCode;
    safeMessage: string;
  };
};
