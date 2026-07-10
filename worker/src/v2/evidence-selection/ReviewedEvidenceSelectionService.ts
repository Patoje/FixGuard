import type {
  SelectReviewedEvidenceRequest,
  SelectReviewedEvidenceResult,
  ReviewedEvidenceSelectionSet,
  ReviewedEvidenceSelectionOptions,
  ReviewedEvidenceSelectionCriteria
} from "./ReviewedEvidenceSelectionContracts.js";
import type {
  ReviewedEvidenceStoreRepository,
  ReviewedEvidenceStoreSummary
} from "../evidence-store/ReviewedEvidenceStoreContracts.js";
import {
  getReviewedEvidence,
  listReviewedEvidence
} from "../evidence-store/ReviewedEvidenceReadModel.js";
import {
  ALLOWED_EVIDENCE_TYPES,
  ALLOWED_EVIDENCE_STRENGTHS
} from "../evidence/EvidenceBoundaryContracts.js";
import { validateReviewedEvidenceStoreRecord } from "../evidence-store/ReviewedEvidenceStoreService.js";

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

function isValidOptions(options: any): boolean {
  if (options === undefined) return true;
  if (!options || typeof options !== "object" || Array.isArray(options)) return false;
  const keys = Object.keys(options);
  if (keys.length === 0) return true;
  if (keys.length > 1 || keys[0] !== "limit") return false;
  const limit = options.limit;
  if (limit !== undefined) {
    if (typeof limit !== "number" || !Number.isInteger(limit) || limit <= 0) return false;
  }
  return true;
}

function isValidCriteria(criteria: any): boolean {
  if (!criteria || typeof criteria !== "object" || Array.isArray(criteria)) return false;
  const keys = Object.keys(criteria);
  const allowedKeys = new Set(["evidenceTypes", "strengths", "indicatorIds", "savedAtFrom", "savedAtTo", "collectedAtFrom", "collectedAtTo"]);
  for (const k of keys) {
    if (!allowedKeys.has(k)) return false;
  }

  if (criteria.evidenceTypes !== undefined) {
    if (!Array.isArray(criteria.evidenceTypes) || criteria.evidenceTypes.length === 0 || criteria.evidenceTypes.length > 50) return false;
    for (const t of criteria.evidenceTypes) {
      if (!ALLOWED_EVIDENCE_TYPES.includes(t as any)) return false;
    }
  }

  if (criteria.strengths !== undefined) {
    if (!Array.isArray(criteria.strengths) || criteria.strengths.length === 0 || criteria.strengths.length > 50) return false;
    for (const s of criteria.strengths) {
      if (!ALLOWED_EVIDENCE_STRENGTHS.includes(s as any)) return false;
    }
  }

  if (criteria.indicatorIds !== undefined) {
    if (!Array.isArray(criteria.indicatorIds) || criteria.indicatorIds.length === 0 || criteria.indicatorIds.length > 50) return false;
    for (const id of criteria.indicatorIds) {
      if (!isStrictSafeId(id)) return false;
    }
  }

  if (criteria.savedAtFrom !== undefined && !isStrictIsoTimestamp(criteria.savedAtFrom)) return false;
  if (criteria.savedAtTo !== undefined && !isStrictIsoTimestamp(criteria.savedAtTo)) return false;
  if (criteria.savedAtFrom !== undefined && criteria.savedAtTo !== undefined && criteria.savedAtFrom > criteria.savedAtTo) return false;

  if (criteria.collectedAtFrom !== undefined && !isStrictIsoTimestamp(criteria.collectedAtFrom)) return false;
  if (criteria.collectedAtTo !== undefined && !isStrictIsoTimestamp(criteria.collectedAtTo)) return false;
  if (criteria.collectedAtFrom !== undefined && criteria.collectedAtTo !== undefined && criteria.collectedAtFrom > criteria.collectedAtTo) return false;

  return true;
}

function isSafeSummary(s: any): boolean {
  if (!s || typeof s !== "object") return false;
  if (Object.keys(s).length !== 9) return false;
  if (!isStrictSafeId(s.storeRecordId)) return false;
  if (!isStrictSafeId(s.evidenceId)) return false;
  if (!isStrictSafeId(s.scanId)) return false;
  if (!isStrictSafeId(s.indicatorId)) return false;
  if (!isStrictIsoTimestamp(s.collectedAt)) return false;
  if (!isStrictIsoTimestamp(s.savedAt)) return false;
  if (!ALLOWED_EVIDENCE_TYPES.includes(s.evidenceType as any)) return false;
  if (!ALLOWED_EVIDENCE_STRENGTHS.includes(s.strength as any)) return false;
  if (s.sourceBoundary !== "M50") return false;
  return true;
}

export function validateReviewedEvidenceSelectionSet(selectionSet: any): boolean {
  if (!selectionSet || typeof selectionSet !== "object" || Array.isArray(selectionSet)) return false;
  
  const keys = Object.keys(selectionSet);
  const allowedKeys = new Set(["contractVersion", "kind", "selectionId", "scanId", "createdAt", "selectionMode", "selectedRefs", "selectedSummaries", "selectionStats", "storage", "explicitNonClaims", "classification"]);
  
  if (keys.length !== 12) return false;
  for (const k of keys) {
    if (!allowedKeys.has(k)) return false;
  }

  if (selectionSet.contractVersion !== "fixguard-reviewed-evidence-selection/v0") return false;
  if (selectionSet.kind !== "reviewed_evidence_selection_set") return false;
  
  if (!isStrictSafeId(selectionSet.selectionId)) return false;
  if (!isStrictSafeId(selectionSet.scanId)) return false;
  if (!isStrictIsoTimestamp(selectionSet.createdAt)) return false;

  const validModes = new Set(["explicit_store_record_ids", "explicit_evidence_ids", "criteria_query"]);
  if (!validModes.has(selectionSet.selectionMode)) return false;

  if (!Array.isArray(selectionSet.selectedRefs) || selectionSet.selectedRefs.length > 100) return false;
  if (!Array.isArray(selectionSet.selectedSummaries) || selectionSet.selectedSummaries.length > 100) return false;
  if (selectionSet.selectedRefs.length !== selectionSet.selectedSummaries.length) return false;

  const seenStoreRecordIds = new Set<string>();
  const seenEvidenceIds = new Set<string>();

  for (let i = 0; i < selectionSet.selectedRefs.length; i++) {
    const ref = selectionSet.selectedRefs[i];
    const sum = selectionSet.selectedSummaries[i];

    if (!ref || typeof ref !== "object") return false;
    if (Object.keys(ref).length !== 4) return false;
    if (!isStrictSafeId(ref.storeRecordId) || !isStrictSafeId(ref.evidenceId) || !isStrictSafeId(ref.scanId) || !isStrictSafeId(ref.indicatorId)) return false;
    
    if (!isSafeSummary(sum)) return false;

    if (ref.storeRecordId !== sum.storeRecordId) return false;
    if (ref.evidenceId !== sum.evidenceId) return false;
    if (ref.scanId !== sum.scanId) return false;
    if (ref.indicatorId !== sum.indicatorId) return false;

    if (ref.scanId !== selectionSet.scanId) return false;

    if (seenStoreRecordIds.has(ref.storeRecordId)) return false;
    seenStoreRecordIds.add(ref.storeRecordId);

    if (seenEvidenceIds.has(ref.evidenceId)) return false;
    seenEvidenceIds.add(ref.evidenceId);
  }

  const stats = selectionSet.selectionStats;
  if (!stats || typeof stats !== "object") return false;
  const statKeys = Object.keys(stats);
  if (statKeys.length !== 4) return false;
  if (
    typeof stats.selectedCount !== "number" || !Number.isInteger(stats.selectedCount) || stats.selectedCount < 0 ||
    typeof stats.candidateInputCount !== "number" || !Number.isInteger(stats.candidateInputCount) || stats.candidateInputCount < 0 ||
    typeof stats.rejectedInputCount !== "number" || !Number.isInteger(stats.rejectedInputCount) || stats.rejectedInputCount < 0 ||
    typeof stats.duplicateInputCount !== "number" || !Number.isInteger(stats.duplicateInputCount) || stats.duplicateInputCount < 0
  ) return false;
  if (stats.selectedCount !== selectionSet.selectedRefs.length) return false;

  const storage = selectionSet.storage;
  if (!storage || typeof storage !== "object") return false;
  if (Object.keys(storage).length !== 3) return false;
  if (storage.persisted !== false || storage.persistedToDatabase !== false || storage.externalized !== false) return false;

  const nc = selectionSet.explicitNonClaims;
  if (!nc || typeof nc !== "object") return false;
  if (Object.keys(nc).length !== 9) return false;
  if (
    nc.noFindingCreated !== true ||
    nc.noFindingCandidateCreated !== true ||
    nc.noSafeReportItemCreated !== true ||
    nc.noExternalReportCreated !== true ||
    nc.noConfirmedVulnerability !== true ||
    nc.noSeverityRiskOrImpactClaim !== true ||
    nc.noNetworkExecution !== true ||
    nc.noToolExecution !== true ||
    nc.noPersistence !== true
  ) return false;

  const cl = selectionSet.classification;
  if (!cl || typeof cl !== "object") return false;
  if (Object.keys(cl).length !== 12) return false;
  if (
    cl.createsReviewedEvidenceSelectionSet !== true ||
    cl.persistsSelectionSet !== false ||
    cl.persistsToDatabase !== false ||
    cl.createsFindingCandidate !== false ||
    cl.createsFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return false;

  return true;
}

export async function selectReviewedEvidence(
  request: any,
  evaluatedAt: string,
  repository: ReviewedEvidenceStoreRepository
): Promise<SelectReviewedEvidenceResult> {
  const baseResult: Omit<SelectReviewedEvidenceResult, "status" | "reasonCode" | "selectionSet" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "select_reviewed_evidence_result",
    selectionId: isStrictSafeId(request?.selectionId) ? request.selectionId : "SELECTION_ID_REDACTED",
    scanId: isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED",
    evaluatedAt: isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "TIMESTAMP_REDACTED",
    explicitNonClaims: {
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noConfirmedVulnerability: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    }
  };

  const failedClassification = {
    createsReviewedEvidenceSelectionSet: false,
    persistsSelectionSet: false,
    persistsToDatabase: false,
    createsFindingCandidate: false,
    createsFinding: false,
    createsSafeReportItem: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetwork: false,
    executesTools: false
  } as const;

  const failedReturn = (code: SelectReviewedEvidenceResult["reasonCode"]) => ({
    ...baseResult,
    status: "failed" as const,
    reasonCode: code,
    classification: failedClassification
  });

  const blockedReturn = (code: SelectReviewedEvidenceResult["reasonCode"]) => ({
    ...baseResult,
    status: "blocked" as const,
    reasonCode: code,
    classification: failedClassification
  });

  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return failedReturn("invalid_selection_request");
  }

  const reqKeys = Object.keys(request);
  const allowedReqKeys = new Set(["contractVersion", "kind", "selectionId", "scanId", "requestedAt", "source", "options", "classification"]);
  for (const k of reqKeys) {
    if (!allowedReqKeys.has(k)) return failedReturn("invalid_selection_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-selection/v0") return failedReturn("invalid_selection_metadata");
  if (request.kind !== "select_reviewed_evidence_request") return failedReturn("invalid_selection_metadata");
  if (!isStrictSafeId(request.selectionId)) return failedReturn("invalid_selection_metadata");
  if (!isStrictSafeId(request.scanId)) return failedReturn("invalid_selection_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt)) return failedReturn("invalid_selection_metadata");
  if (!isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_selection_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object") return failedReturn("invalid_selection_metadata");
  if (Object.keys(cl).length !== 12) return failedReturn("invalid_selection_metadata");
  if (
    cl.createsReviewedEvidenceSelectionSet !== false ||
    cl.persistsSelectionSet !== false ||
    cl.persistsToDatabase !== false ||
    cl.createsFindingCandidate !== false ||
    cl.createsFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return failedReturn("invalid_selection_metadata");

  if (!isValidOptions(request.options)) return failedReturn("invalid_selection_options");
  const limitValue = request.options?.limit !== undefined ? Math.min(request.options.limit, 100) : 100;

  const src = request.source;
  if (!src || typeof src !== "object" || Array.isArray(src)) return failedReturn("invalid_selection_metadata");

  let candidateInputCount = 0;
  let duplicateInputCount = 0;
  let rejectedInputCount = 0;
  let summaries: ReviewedEvidenceStoreSummary[] = [];

  try {
    if (src.mode === "explicit_store_record_ids" || src.mode === "explicit_evidence_ids") {
      const ids = src.mode === "explicit_store_record_ids" ? src.storeRecordIds : src.evidenceIds;
      if (!Array.isArray(ids) || ids.length === 0 || ids.length > 100) return failedReturn("invalid_selection_metadata");
      const srcKeys = Object.keys(src);
      if (srcKeys.length !== 2) return failedReturn("invalid_selection_metadata");
      
      candidateInputCount = ids.length;
      const uniqueIds = new Set<string>();
      const dedupedIds: string[] = [];
      
      for (const id of ids) {
        if (!isStrictSafeId(id)) return failedReturn("invalid_selection_metadata");
        if (uniqueIds.has(id)) {
          duplicateInputCount++;
        } else {
          uniqueIds.add(id);
          dedupedIds.push(id);
        }
      }

      let explicitIndex = 0;
      for (const id of dedupedIds) {
        const getReq = {
          contractVersion: "fixguard-reviewed-evidence-store/v0" as const,
          kind: "get_reviewed_evidence_request" as const,
          readId: `m52_read_${explicitIndex++}`,
          scanId: request.scanId,
          requestedAt: request.requestedAt,
          lookup: src.mode === "explicit_store_record_ids" ? { by: "storeRecordId" as const, storeRecordId: id } : { by: "evidenceId" as const, evidenceId: id },
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
            executesTools: false
          } as const
        };

        const res = await getReviewedEvidence(getReq, evaluatedAt, repository);
        if (res.status === "failed") {
          return failedReturn(res.reasonCode === "repository_read_failed" ? "repository_read_failed" : "source_reviewed_evidence_invalid");
        }
        if (res.status === "not_found") {
          return blockedReturn("selected_evidence_not_found");
        }
        if (!res.summary || res.summary.scanId !== request.scanId) {
          return blockedReturn("source_scan_mismatch");
        }
        summaries.push(res.summary);
      }
    } else if (src.mode === "criteria_query") {
      const srcKeys = Object.keys(src);
      if (srcKeys.length !== 2) return failedReturn("invalid_selection_metadata");
      if (!isValidCriteria(src.criteria)) return failedReturn("invalid_selection_criteria");

      const listReq = {
        contractVersion: "fixguard-reviewed-evidence-store/v0" as const,
        kind: "list_reviewed_evidence_request" as const,
        listId: "m52_list_0",
        scanId: request.scanId,
        requestedAt: request.requestedAt,
        options: { limit: 100 }, // safe broad cap to fetch candidates, user limit applied post-filter
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
          executesTools: false
        } as const
      };

      const resList = await listReviewedEvidence(listReq, evaluatedAt, repository);
      if (resList.status === "failed") {
        return failedReturn(resList.reasonCode === "repository_read_failed" ? "repository_read_failed" : "source_reviewed_evidence_invalid");
      }
      
      const allSummaries = resList.summaries || [];
      candidateInputCount = allSummaries.length;
      duplicateInputCount = 0;
      
      const cr = src.criteria;
      const filtered = allSummaries.filter(s => {
        if (cr.evidenceTypes && !cr.evidenceTypes.includes(s.evidenceType)) return false;
        if (cr.strengths && !cr.strengths.includes(s.strength)) return false;
        if (cr.indicatorIds && !cr.indicatorIds.includes(s.indicatorId)) return false;
        if (cr.savedAtFrom && s.savedAt < cr.savedAtFrom) return false;
        if (cr.savedAtTo && s.savedAt > cr.savedAtTo) return false;
        if (cr.collectedAtFrom && s.collectedAt < cr.collectedAtFrom) return false;
        if (cr.collectedAtTo && s.collectedAt > cr.collectedAtTo) return false;
        return true;
      });

      // Sort: savedAt DESC, storeRecordId ASC tie-break
      filtered.sort((a, b) => {
        if (a.savedAt !== b.savedAt) {
          return a.savedAt > b.savedAt ? -1 : 1;
        }
        return a.storeRecordId.localeCompare(b.storeRecordId);
      });

      summaries = filtered.slice(0, limitValue);
      rejectedInputCount = candidateInputCount - summaries.length;
    } else {
      return failedReturn("invalid_selection_metadata");
    }

  } catch (e) {
    return failedReturn("unexpected_selection_failure");
  }

  if (summaries.length === 0) {
    return blockedReturn("selection_empty");
  }

  // Double check duplicates in selection (especially for explicit modes if multiple ids mapped to same underlying record conceptually? But here explicit maps by storeRecordId or evidenceId and deduplication already handled input duplicates)
  const finalStoreRecordIds = new Set<string>();
  const finalEvidenceIds = new Set<string>();
  const finalRefs = [];
  
  for (const s of summaries) {
    if (finalStoreRecordIds.has(s.storeRecordId) || finalEvidenceIds.has(s.evidenceId)) {
      return failedReturn("source_reviewed_evidence_invalid");
    }
    finalStoreRecordIds.add(s.storeRecordId);
    finalEvidenceIds.add(s.evidenceId);
    finalRefs.push({
      storeRecordId: s.storeRecordId,
      evidenceId: s.evidenceId,
      scanId: s.scanId,
      indicatorId: s.indicatorId
    });
  }

  const selectionSet: ReviewedEvidenceSelectionSet = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "reviewed_evidence_selection_set",
    selectionId: request.selectionId,
    scanId: request.scanId,
    createdAt: evaluatedAt,
    selectionMode: request.source.mode,
    selectedRefs: finalRefs,
    selectedSummaries: summaries,
    selectionStats: {
      selectedCount: summaries.length,
      candidateInputCount,
      duplicateInputCount,
      rejectedInputCount
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noConfirmedVulnerability: true,
      noSeverityRiskOrImpactClaim: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsReviewedEvidenceSelectionSet: true,
      persistsSelectionSet: false,
      persistsToDatabase: false,
      createsFindingCandidate: false,
      createsFinding: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false
    }
  };

  if (!validateReviewedEvidenceSelectionSet(selectionSet)) {
    return failedReturn("selection_set_validation_failed");
  }

  return {
    ...baseResult,
    status: "selected",
    reasonCode: "reviewed_evidence_selected",
    selectionSet,
    classification: selectionSet.classification
  };
}
