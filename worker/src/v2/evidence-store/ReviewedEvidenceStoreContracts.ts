import type { HumanReviewedEvidencePromotionResult } from "../evidence-review/HumanReviewedEvidencePromotionContracts.js";
import type { EvidenceRecord } from "../evidence/EvidenceBoundaryContracts.js";

export type ReviewedEvidenceStoreReasonCode =
  | "saved_reviewed_evidence_record"
  | "duplicate_reviewed_evidence_record"
  | "read_reviewed_evidence_record_found"
  | "list_reviewed_evidence_records_completed"
  | "source_promotion_not_promoted"
  | "source_promotion_not_evidence_ready"
  | "source_evidence_record_missing"
  | "source_scan_mismatch"
  | "source_promotion_policy_unsafe"
  | "source_evidence_record_invalid"
  | "store_record_validation_failed"
  | "repository_save_failed"
  | "repository_read_failed"
  | "invalid_store_request"
  | "invalid_store_metadata"
  | "invalid_read_request"
  | "invalid_read_metadata"
  | "invalid_list_request"
  | "invalid_list_metadata"
  | "unsafe_content_rejected"
  | "not_found"
  | "unexpected_store_failure";

export type SaveReviewedEvidenceRequestClassification = {
  storesReviewedEvidenceRecord: false;
  storesInMemoryOnly: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SaveReviewedEvidenceRequest = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "save_reviewed_evidence_request";

  saveId: string;
  scanId: string;
  requestedAt: string;

  promotionResult: HumanReviewedEvidencePromotionResult;

  classification: SaveReviewedEvidenceRequestClassification;
};

export type ReviewedEvidenceStoreRecordClassification = {
  storesReviewedEvidenceRecord: true;
  storesInMemoryOnly: true;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type ReviewedEvidenceStoreRecord = {
  recordVersion: "fixguard-reviewed-evidence-store-record/v0";
  recordKind: "reviewed_evidence_store_record";

  storeRecordId: string;
  savedAt: string;

  evidenceRecord: EvidenceRecord;

  source: {
    sourceBoundary: "M50";
    sourceContractVersion: "fixguard-human-reviewed-evidence-promotion/v0";
    sourcePromotionId: string;
    sourceScanId: string;
    sourceReasonCode: "promoted_to_non_persisted_evidence_record";
  };

  storage: {
    storageKind: "in_memory_db_free";
    persistedToDatabase: false;
    externalized: false;
  };

  explicitNonClaims: {
    noConfirmedVulnerability: true;
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
  };

  classification: ReviewedEvidenceStoreRecordClassification;
};

export type ReviewedEvidenceStoreSummary = {
  storeRecordId: string;
  evidenceId: string;
  scanId: string;
  indicatorId: string;
  evidenceType: string;
  strength: string;
  collectedAt: string;
  savedAt: string;
  sourceBoundary: "M50";
};

export type SaveReviewedEvidenceResultClassification = {
  storesReviewedEvidenceRecord: boolean;
  storesInMemoryOnly: boolean;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type SaveReviewedEvidenceResult = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "save_reviewed_evidence_result";

  saveId: string;
  scanId: string;
  evaluatedAt: string;

  status: "saved" | "blocked" | "failed" | "duplicate";

  reasonCode: ReviewedEvidenceStoreReasonCode;

  record?: ReviewedEvidenceStoreRecord;
  summary?: ReviewedEvidenceStoreSummary;

  explicitNonClaims: {
    noConfirmedVulnerability: true;
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
  };

  classification: SaveReviewedEvidenceResultClassification;

  error?: {
    code: ReviewedEvidenceStoreReasonCode;
    safeMessage: string;
  };
};

export type ReviewedEvidenceReadRequestClassification = {
  storesReviewedEvidenceRecord: false;
  storesInMemoryOnly: false;
  persistsToDatabase: false;
  createsFindingCandidate: false;
  createsSafeReportItem: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
};

export type ReviewedEvidenceReadResultClassification = ReviewedEvidenceReadRequestClassification;

export type GetReviewedEvidenceRequest = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "get_reviewed_evidence_request";

  readId: string;
  scanId: string;
  requestedAt: string;

  lookup:
    | { by: "storeRecordId"; storeRecordId: string }
    | { by: "evidenceId"; evidenceId: string };

  classification: ReviewedEvidenceReadRequestClassification;
};

export type GetReviewedEvidenceResult = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "get_reviewed_evidence_result";

  readId: string;
  scanId: string;
  evaluatedAt: string;

  status: "found" | "not_found" | "failed";
  reasonCode: ReviewedEvidenceStoreReasonCode;

  record?: ReviewedEvidenceStoreRecord;
  summary?: ReviewedEvidenceStoreSummary;

  explicitNonClaims: {
    noConfirmedVulnerability: true;
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
  };
  classification: ReviewedEvidenceReadResultClassification;

  error?: {
    code: ReviewedEvidenceStoreReasonCode;
    safeMessage: string;
  };
};

export type ReviewedEvidenceListOptions = {
  limit?: number;
};

export type ListReviewedEvidenceRequest = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "list_reviewed_evidence_request";

  listId: string;
  scanId: string;
  requestedAt: string;

  options?: ReviewedEvidenceListOptions;

  classification: ReviewedEvidenceReadRequestClassification;
};

export type ListReviewedEvidenceResult = {
  contractVersion: "fixguard-reviewed-evidence-store/v0";
  kind: "list_reviewed_evidence_result";

  listId: string;
  scanId: string;
  evaluatedAt: string;

  status: "listed" | "failed";
  reasonCode: ReviewedEvidenceStoreReasonCode;

  summaries: ReviewedEvidenceStoreSummary[];

  explicitNonClaims: {
    noConfirmedVulnerability: true;
    noFindingCreated: true;
    noFindingCandidateCreated: true;
    noSafeReportItemCreated: true;
    noExternalReportCreated: true;
    noSeverityRiskOrImpactClaim: true;
    noNetworkExecution: true;
    noToolExecution: true;
  };
  classification: ReviewedEvidenceReadResultClassification;

  error?: {
    code: ReviewedEvidenceStoreReasonCode;
    safeMessage: string;
  };
};

export interface ReviewedEvidenceStoreRepository {
  save(record: ReviewedEvidenceStoreRecord): Promise<ReviewedEvidenceStoreRecord>;
  getByStoreRecordId(storeRecordId: string): Promise<ReviewedEvidenceStoreRecord | null>;
  getByEvidenceId(evidenceId: string): Promise<ReviewedEvidenceStoreRecord | null>;
  listByScanId(
    scanId: string,
    options?: ReviewedEvidenceListOptions
  ): Promise<ReviewedEvidenceStoreRecord[]>;
}
