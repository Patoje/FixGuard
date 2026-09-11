import type {
  SaveReviewedEvidenceRequest,
  SaveReviewedEvidenceResult,
  ReviewedEvidenceStoreRecord,
  ReviewedEvidenceStoreSummary,
  ReviewedEvidenceStoreRepository
} from "./ReviewedEvidenceStoreContracts.js";
import { validateEvidenceRecord } from "../evidence/EvidenceBoundaryService.js";
import type { EvidenceRecord } from "../evidence/EvidenceBoundaryContracts.js";
import { PersistenceConflictError } from "../storage/StorageErrors.js";

const UNSAFE_TERMS = [
  "authorization", "bearer", "cookie", "set-cookie", "password", "secret",
  "token", "api_key", "apikey", "access_token", "refresh_token",
  "raw_request", "raw response", "raw_body", "raw body", "raw_headers", "raw headers",
  "sqli", "idor", "bola", "auth bypass", "vulnerable", "exploit", "critical severity", "target is vulnerable"
];

function isSafeString(val: any): boolean {
  if (typeof val !== "string") return false;
  const lower = val.toLowerCase();
  return !UNSAFE_TERMS.some(term => lower.includes(term));
}

function isStrictSafeId(val: any): boolean {
  if (typeof val !== "string") return false;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(val)) return false;
  return isSafeString(val);
}

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

const ALLOWED_SAVE_REQUEST_KEYS = new Set([
  "contractVersion", "kind", "saveId", "scanId", "requestedAt", "promotionResult", "classification"
]);

function validatePromotionResultForStore(promo: any, requestScanId: string): boolean {
  if (!promo || typeof promo !== "object") return false;
  
  const keys = Object.keys(promo);
  const allowedKeys = new Set([
    "contractVersion", "kind", "promotionId", "scanId", "evaluatedAt", "status", "reasonCode",
    "nonPersistedEvidenceRecord", "reviewSummary", "sourceValidationSummary", "explicitNonClaims", "classification"
  ]);
  
  for (const k of keys) {
    if (!allowedKeys.has(k)) return false;
  }
  
  if (promo.contractVersion !== "fixguard-human-reviewed-evidence-promotion/v0") return false;
  if (promo.kind !== "human_reviewed_evidence_promotion_result") return false;
  
  if (!isStrictSafeId(promo.promotionId)) return false;
  if (!isStrictSafeId(promo.scanId)) return false;
  if (!isStrictIsoTimestamp(promo.evaluatedAt)) return false;
  
  const nc = promo.explicitNonClaims;
  if (!nc || typeof nc !== "object") return false;
  const ncKeys = Object.keys(nc);
  if (ncKeys.length !== 9) return false;
  if (
    nc.noConfirmedVulnerability !== true ||
    nc.noFindingCreated !== true ||
    nc.noFindingCandidateCreated !== true ||
    nc.noSafeReportItemCreated !== true ||
    nc.noSeverityRiskOrImpactClaim !== true ||
    nc.noExternalReportCreated !== true ||
    nc.noNetworkExecution !== true ||
    nc.noToolExecution !== true ||
    nc.noPersistence !== true
  ) return false;

  const cl = promo.classification;
  if (!cl || typeof cl !== "object") return false;
  const clKeys = Object.keys(cl);
  if (clKeys.length !== 11) return false;
  if (
    cl.createsNonPersistedEvidenceRecord !== true ||
    cl.createsPersistedEvidence !== false ||
    cl.createsFindingCandidate !== false ||
    cl.createsSafeReportItem !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false ||
    cl.persistsData !== false
  ) return false;

  return true;
}

export function validateReviewedEvidenceStoreRecord(record: any, expectedScanId?: string): boolean {
  if (!record || typeof record !== "object" || Array.isArray(record)) return false;

  const recordKeys = Object.keys(record);
  if (recordKeys.length !== 9) return false;
  const allowedRecordKeys = new Set(["recordVersion", "recordKind", "storeRecordId", "savedAt", "evidenceRecord", "source", "storage", "explicitNonClaims", "classification"]);
  for (const k of recordKeys) {
    if (!allowedRecordKeys.has(k)) return false;
  }

  if (record.recordVersion !== "fixguard-reviewed-evidence-store-record/v0") return false;
  if (record.recordKind !== "reviewed_evidence_store_record") return false;

  if (!isStrictSafeId(record.storeRecordId)) return false;
  if (!isStrictIsoTimestamp(record.savedAt)) return false;

  if (!record.source || typeof record.source !== "object") return false;
  const sourceKeys = Object.keys(record.source);
  if (sourceKeys.length !== 5) return false;
  const allowedSourceKeys = new Set(["sourceBoundary", "sourceContractVersion", "sourcePromotionId", "sourceScanId", "sourceReasonCode"]);
  for (const k of sourceKeys) {
    if (!allowedSourceKeys.has(k)) return false;
  }
  if (record.source.sourceBoundary !== "M50") return false;
  if (record.source.sourceContractVersion !== "fixguard-human-reviewed-evidence-promotion/v0") return false;
  if (record.source.sourceReasonCode !== "promoted_to_non_persisted_evidence_record") return false;
  if (!isStrictSafeId(record.source.sourcePromotionId)) return false;
  if (!isStrictSafeId(record.source.sourceScanId)) return false;

  if (!record.storage || typeof record.storage !== "object") return false;
  const storageKeys = Object.keys(record.storage);
  if (storageKeys.length !== 3) return false;
  const allowedStorageKeys = new Set(["storageKind", "persistedToDatabase", "externalized"]);
  for (const k of storageKeys) {
    if (!allowedStorageKeys.has(k)) return false;
  }
  if (record.storage.storageKind !== "in_memory_db_free") return false;
  if (record.storage.persistedToDatabase !== false) return false;
  if (record.storage.externalized !== false) return false;

  const nc = record.explicitNonClaims;
  if (!nc || typeof nc !== "object") return false;
  const ncKeys = Object.keys(nc);
  if (ncKeys.length !== 8) return false;
  const allowedNcKeys = new Set(["noConfirmedVulnerability", "noFindingCreated", "noFindingCandidateCreated", "noSafeReportItemCreated", "noExternalReportCreated", "noSeverityRiskOrImpactClaim", "noNetworkExecution", "noToolExecution"]);
  for (const k of ncKeys) {
    if (!allowedNcKeys.has(k)) return false;
  }
  if (nc.noConfirmedVulnerability !== true || nc.noFindingCreated !== true || nc.noFindingCandidateCreated !== true || nc.noSafeReportItemCreated !== true || nc.noExternalReportCreated !== true || nc.noSeverityRiskOrImpactClaim !== true || nc.noNetworkExecution !== true || nc.noToolExecution !== true) return false;

  const cl = record.classification;
  if (!cl || typeof cl !== "object") return false;
  const clKeys = Object.keys(cl);
  if (clKeys.length !== 11) return false;
  const allowedClKeys = new Set(["storesReviewedEvidenceRecord", "storesInMemoryOnly", "persistsToDatabase", "createsFindingCandidate", "createsSafeReportItem", "confirmsVulnerabilities", "makesRiskClaims", "makesSeverityClaims", "makesImpactClaims", "executesNetwork", "executesTools"]);
  for (const k of clKeys) {
    if (!allowedClKeys.has(k)) return false;
  }
  if (cl.storesReviewedEvidenceRecord !== true || cl.storesInMemoryOnly !== true || cl.persistsToDatabase !== false || cl.createsFindingCandidate !== false || cl.createsSafeReportItem !== false || cl.confirmsVulnerabilities !== false || cl.makesRiskClaims !== false || cl.makesSeverityClaims !== false || cl.makesImpactClaims !== false || cl.executesNetwork !== false || cl.executesTools !== false) return false;

  const evVal = validateEvidenceRecord(record.evidenceRecord);
  if (!evVal.isValid) return false;

  if (!isStrictSafeId(record.evidenceRecord.evidenceId)) return false;
  if (!isStrictSafeId(record.evidenceRecord.scanId)) return false;
  if (!isStrictSafeId(record.evidenceRecord.indicatorId)) return false;
  if (!isStrictIsoTimestamp(record.evidenceRecord.collectedAt)) return false;
  
  if (record.evidenceRecord.scanId !== record.source.sourceScanId) return false;

  if (expectedScanId !== undefined) {
    if (record.evidenceRecord.scanId !== expectedScanId) return false;
    if (record.source.sourceScanId !== expectedScanId) return false;
  }

  return true;
}

export async function saveReviewedEvidence(
  request: any,
  evaluatedAt: string,
  repository: ReviewedEvidenceStoreRepository
): Promise<SaveReviewedEvidenceResult> {
  const safeEvaluatedAt = isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "1970-01-01T00:00:00.000Z";
  const safeSaveId = isStrictSafeId(request?.saveId) ? request.saveId : "SAVE_ID_REDACTED";
  const safeScanId = isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED";

  const baseResult: SaveReviewedEvidenceResult = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "save_reviewed_evidence_result",
    saveId: safeSaveId,
    scanId: safeScanId,
    evaluatedAt: safeEvaluatedAt,
    status: "failed",
    reasonCode: "invalid_store_request",
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true,
    },
    classification: {
      storesReviewedEvidenceRecord: false,
      storesInMemoryOnly: false,
      persistsToDatabase: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
    },
  };

  if (!isStrictIsoTimestamp(evaluatedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_store_metadata" };
  }

  if (!request || request.contractVersion !== "fixguard-reviewed-evidence-store/v0" || request.kind !== "save_reviewed_evidence_request") {
    return { ...baseResult, status: "failed", reasonCode: "invalid_store_request" };
  }

  for (const key of Object.keys(request)) {
    if (!ALLOWED_SAVE_REQUEST_KEYS.has(key)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_store_request" };
    }
  }

  if (!isStrictSafeId(request.saveId) || !isStrictSafeId(request.scanId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_store_metadata" };
  }

  if (!isStrictIsoTimestamp(request.requestedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_store_metadata" };
  }

  const reqClass = request.classification;
  if (!reqClass ||
      reqClass.storesReviewedEvidenceRecord !== false ||
      reqClass.storesInMemoryOnly !== false ||
      reqClass.persistsToDatabase !== false ||
      reqClass.createsFindingCandidate !== false ||
      reqClass.createsSafeReportItem !== false ||
      reqClass.confirmsVulnerabilities !== false ||
      reqClass.makesRiskClaims !== false ||
      reqClass.makesSeverityClaims !== false ||
      reqClass.makesImpactClaims !== false ||
      reqClass.executesNetwork !== false ||
      reqClass.executesTools !== false ||
      Object.keys(reqClass).length !== 11) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_store_request" };
  }

  const promo = request.promotionResult;
  if (!validatePromotionResultForStore(promo, request.scanId)) {
    return { ...baseResult, status: "blocked", reasonCode: "source_promotion_policy_unsafe" };
  }

  if (promo.status !== "promoted") {
    return { ...baseResult, status: "blocked", reasonCode: "source_promotion_not_promoted" };
  }

  if (promo.reasonCode !== "promoted_to_non_persisted_evidence_record") {
    return { ...baseResult, status: "blocked", reasonCode: "source_promotion_not_evidence_ready" };
  }

  if (!promo.nonPersistedEvidenceRecord) {
    return { ...baseResult, status: "blocked", reasonCode: "source_evidence_record_missing" };
  }

  if (promo.scanId !== request.scanId) {
    return { ...baseResult, status: "blocked", reasonCode: "source_scan_mismatch" };
  }

  const evidenceRecord = promo.nonPersistedEvidenceRecord as EvidenceRecord;
  const validationRes = validateEvidenceRecord(evidenceRecord);
  if (!validationRes.isValid) {
    return { ...baseResult, status: "blocked", reasonCode: "source_evidence_record_invalid" };
  }

  if (evidenceRecord.scanId !== request.scanId) {
    return { ...baseResult, status: "blocked", reasonCode: "source_scan_mismatch" };
  }

  const storeRecord: ReviewedEvidenceStoreRecord = {
    recordVersion: "fixguard-reviewed-evidence-store-record/v0",
    recordKind: "reviewed_evidence_store_record",
    storeRecordId: request.saveId,
    savedAt: safeEvaluatedAt,
    evidenceRecord,
    source: {
      sourceBoundary: "M50",
      sourceContractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
      sourcePromotionId: promo.promotionId,
      sourceScanId: promo.scanId,
      sourceReasonCode: "promoted_to_non_persisted_evidence_record"
    },
    storage: {
      storageKind: "in_memory_db_free",
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true
    },
    classification: {
      storesReviewedEvidenceRecord: true,
      storesInMemoryOnly: true,
      persistsToDatabase: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false
    }
  };

  if (!validateReviewedEvidenceStoreRecord(storeRecord)) {
    return { ...baseResult, status: "failed", reasonCode: "store_record_validation_failed" };
  }

  try {
    const savedRecord = await repository.save(storeRecord);
    
    const summary: ReviewedEvidenceStoreSummary = {
      storeRecordId: savedRecord.storeRecordId,
      evidenceId: savedRecord.evidenceRecord.evidenceId,
      scanId: savedRecord.evidenceRecord.scanId,
      indicatorId: savedRecord.evidenceRecord.indicatorId,
      evidenceType: savedRecord.evidenceRecord.evidenceType,
      strength: savedRecord.evidenceRecord.strength,
      collectedAt: savedRecord.evidenceRecord.collectedAt,
      savedAt: savedRecord.savedAt,
      sourceBoundary: "M50"
    };

    return {
      ...baseResult,
      status: "saved",
      reasonCode: "saved_reviewed_evidence_record",
      record: savedRecord,
      summary,
      classification: {
        ...baseResult.classification,
        storesReviewedEvidenceRecord: true,
        storesInMemoryOnly: true
      }
    };
  } catch (e: any) {
    if (e instanceof PersistenceConflictError || (e.message && e.message.includes("Duplicate"))) {
      return { ...baseResult, status: "duplicate", reasonCode: "duplicate_reviewed_evidence_record" };
    }
    return { ...baseResult, status: "failed", reasonCode: "repository_save_failed" };
  }
}
