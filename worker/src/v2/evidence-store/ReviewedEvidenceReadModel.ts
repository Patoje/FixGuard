import type {
  GetReviewedEvidenceRequest,
  GetReviewedEvidenceResult,
  ListReviewedEvidenceRequest,
  ListReviewedEvidenceResult,
  ReviewedEvidenceStoreRepository,
  ReviewedEvidenceStoreSummary
} from "./ReviewedEvidenceStoreContracts.js";
import { validateEvidenceRecord } from "../evidence/EvidenceBoundaryService.js";
import { validateReviewedEvidenceStoreRecord } from "./ReviewedEvidenceStoreService.js";

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

const ALLOWED_GET_REQUEST_KEYS = new Set([
  "contractVersion", "kind", "readId", "scanId", "requestedAt", "lookup", "classification"
]);

const ALLOWED_LIST_REQUEST_KEYS = new Set([
  "contractVersion", "kind", "listId", "scanId", "requestedAt", "options", "classification"
]);

export async function getReviewedEvidence(
  request: any,
  evaluatedAt: string,
  repository: ReviewedEvidenceStoreRepository
): Promise<GetReviewedEvidenceResult> {
  const safeEvaluatedAt = isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "1970-01-01T00:00:00.000Z";
  const safeReadId = isStrictSafeId(request?.readId) ? request.readId : "READ_ID_REDACTED";
  const safeScanId = isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED";

  const baseResult: GetReviewedEvidenceResult = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "get_reviewed_evidence_result",
    readId: safeReadId,
    scanId: safeScanId,
    evaluatedAt: safeEvaluatedAt,
    status: "failed",
    reasonCode: "invalid_read_request",
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
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_metadata" };
  }

  if (!request || request.contractVersion !== "fixguard-reviewed-evidence-store/v0" || request.kind !== "get_reviewed_evidence_request") {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
  }

  for (const key of Object.keys(request)) {
    if (!ALLOWED_GET_REQUEST_KEYS.has(key)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
    }
  }

  if (!isStrictSafeId(request.readId) || !isStrictSafeId(request.scanId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_metadata" };
  }

  if (!isStrictIsoTimestamp(request.requestedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_metadata" };
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
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
  }

  const lookup = request.lookup;
  if (!lookup || typeof lookup !== "object" || Array.isArray(lookup)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
  }
  const lookupKeys = Object.keys(lookup);
  if (lookupKeys.length !== 2) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
  }
  
  const hasStoreRecordId = lookup.by === "storeRecordId" && "storeRecordId" in lookup;
  const hasEvidenceId = lookup.by === "evidenceId" && "evidenceId" in lookup;
  
  if (hasStoreRecordId) {
    if (!isStrictSafeId(lookup.storeRecordId)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_read_metadata" };
    }
  } else if (hasEvidenceId) {
    if (!isStrictSafeId(lookup.evidenceId)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_read_metadata" };
    }
  } else {
    return { ...baseResult, status: "failed", reasonCode: "invalid_read_request" };
  }

  try {
    let record = null;
    if (hasStoreRecordId && lookup.by === "storeRecordId") {
      record = await repository.getByStoreRecordId(lookup.storeRecordId);
    } else if (hasEvidenceId && lookup.by === "evidenceId") {
      record = await repository.getByEvidenceId(lookup.evidenceId);
    }

    if (!record) {
      return { ...baseResult, status: "not_found", reasonCode: "not_found" };
    }

    if (!validateReviewedEvidenceStoreRecord(record, request.scanId)) {
      return { ...baseResult, status: "failed", reasonCode: "store_record_validation_failed" };
    }

    const summary: ReviewedEvidenceStoreSummary = {
      storeRecordId: record.storeRecordId,
      evidenceId: record.evidenceRecord.evidenceId,
      scanId: record.evidenceRecord.scanId,
      indicatorId: record.evidenceRecord.indicatorId,
      evidenceType: record.evidenceRecord.evidenceType,
      strength: record.evidenceRecord.strength,
      collectedAt: record.evidenceRecord.collectedAt,
      savedAt: record.savedAt,
      sourceBoundary: "M50"
    };

    return {
      ...baseResult,
      status: "found",
      reasonCode: "read_reviewed_evidence_record_found",
      record,
      summary
    };
  } catch (e) {
    return { ...baseResult, status: "failed", reasonCode: "repository_read_failed" };
  }
}

export async function listReviewedEvidence(
  request: any,
  evaluatedAt: string,
  repository: ReviewedEvidenceStoreRepository
): Promise<ListReviewedEvidenceResult> {
  const safeEvaluatedAt = isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "1970-01-01T00:00:00.000Z";
  const safeListId = isStrictSafeId(request?.listId) ? request.listId : "LIST_ID_REDACTED";
  const safeScanId = isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED";

  const baseResult: ListReviewedEvidenceResult = {
    contractVersion: "fixguard-reviewed-evidence-store/v0",
    kind: "list_reviewed_evidence_result",
    listId: safeListId,
    scanId: safeScanId,
    evaluatedAt: safeEvaluatedAt,
    status: "failed",
    reasonCode: "invalid_list_request",
    summaries: [],
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
    return { ...baseResult, status: "failed", reasonCode: "invalid_list_metadata" };
  }

  if (!request || request.contractVersion !== "fixguard-reviewed-evidence-store/v0" || request.kind !== "list_reviewed_evidence_request") {
    return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
  }

  for (const key of Object.keys(request)) {
    if (!ALLOWED_LIST_REQUEST_KEYS.has(key)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
    }
  }

  if (!isStrictSafeId(request.listId) || !isStrictSafeId(request.scanId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_list_metadata" };
  }

  if (!isStrictIsoTimestamp(request.requestedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_list_metadata" };
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
    return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
  }

  let options = request.options;
  if (options !== undefined) {
    if (!options || typeof options !== "object" || Array.isArray(options)) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
    }
    const optKeys = Object.keys(options);
    if (optKeys.length > 1 || (optKeys.length === 1 && optKeys[0] !== "limit")) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
    }
    if ("limit" in options) {
      if (typeof options.limit !== "number" || !Number.isInteger(options.limit) || options.limit <= 0) {
        return { ...baseResult, status: "failed", reasonCode: "invalid_list_metadata" };
      }
      if (options.limit > 100) {
        options = { ...options, limit: 100 };
      }
    }
  } else {
    options = {};
  }

  try {
    const records = await repository.listByScanId(request.scanId, options);
    
    const summaries: ReviewedEvidenceStoreSummary[] = [];
    for (const record of records) {
      if (!validateReviewedEvidenceStoreRecord(record, request.scanId)) {
        return { ...baseResult, status: "failed", reasonCode: "store_record_validation_failed" };
      }
      summaries.push({
        storeRecordId: record.storeRecordId,
        evidenceId: record.evidenceRecord.evidenceId,
        scanId: record.evidenceRecord.scanId,
        indicatorId: record.evidenceRecord.indicatorId,
        evidenceType: record.evidenceRecord.evidenceType,
        strength: record.evidenceRecord.strength,
        collectedAt: record.evidenceRecord.collectedAt,
        savedAt: record.savedAt,
        sourceBoundary: "M50"
      });
    }

    return {
      ...baseResult,
      status: "listed",
      reasonCode: "list_reviewed_evidence_records_completed",
      summaries
    };
  } catch (e: any) {
    if (e.message && e.message.includes("Invalid limit")) {
      return { ...baseResult, status: "failed", reasonCode: "invalid_list_request" };
    }
    return { ...baseResult, status: "failed", reasonCode: "repository_read_failed" };
  }
}
