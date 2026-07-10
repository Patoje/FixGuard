import type {
  CreateReviewedEvidenceFindingCandidateDraftRequest,
  CreateReviewedEvidenceFindingCandidateDraftResult,
  ReviewedEvidenceFindingCandidateDraft
} from "./ReviewedEvidenceFindingCandidateDraftContracts.js";
import {
  validateReviewedEvidenceSelectionSet
} from "../evidence-selection/ReviewedEvidenceSelectionService.js";
import {
  ALLOWED_EVIDENCE_TYPES,
  ALLOWED_EVIDENCE_STRENGTHS
} from "../evidence/EvidenceBoundaryContracts.js";
import type {
  ReviewedEvidenceStoreSummary
} from "../evidence-store/ReviewedEvidenceStoreContracts.js";

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

export function validateReviewedEvidenceFindingCandidateDraft(draft: any): boolean {
  if (!draft || typeof draft !== "object" || Array.isArray(draft)) return false;
  
  const keys = Object.keys(draft);
  const allowedKeys = new Set([
    "contractVersion", "kind", "draftId", "scanId", "createdAt",
    "sourceSelection", "observedEvidenceSummary", "draftTriage",
    "draftLabels", "storage", "explicitNonClaims", "classification"
  ]);
  
  if (keys.length !== 12) return false;
  for (const k of keys) {
    if (!allowedKeys.has(k)) return false;
  }

  if (draft.contractVersion !== "fixguard-reviewed-evidence-finding-candidate-draft/v0") return false;
  if (draft.kind !== "reviewed_evidence_finding_candidate_draft") return false;

  if (!isStrictSafeId(draft.draftId)) return false;
  if (!isStrictSafeId(draft.scanId)) return false;
  if (!isStrictIsoTimestamp(draft.createdAt)) return false;

  const src = draft.sourceSelection;
  if (!src || typeof src !== "object") return false;
  if (Object.keys(src).length !== 4) return false;
  if (!isStrictSafeId(src.selectionId)) return false;
  if (src.selectionMode !== "explicit_store_record_ids" && src.selectionMode !== "explicit_evidence_ids" && src.selectionMode !== "criteria_query") return false;
  if (typeof src.selectedCount !== "number" || !Number.isInteger(src.selectedCount) || src.selectedCount <= 0) return false;
  if (!Array.isArray(src.selectedRefs) || src.selectedRefs.length !== src.selectedCount || src.selectedRefs.length > 100) return false;

  const seenStoreRecordIds = new Set<string>();
  const seenEvidenceIds = new Set<string>();
  const refIndicatorIds = new Set<string>();

  for (const ref of src.selectedRefs) {
    if (!ref || typeof ref !== "object") return false;
    if (Object.keys(ref).length !== 4) return false;
    if (!isStrictSafeId(ref.storeRecordId) || !isStrictSafeId(ref.evidenceId) || !isStrictSafeId(ref.scanId) || !isStrictSafeId(ref.indicatorId)) return false;
    if (ref.scanId !== draft.scanId) return false;
    
    if (seenStoreRecordIds.has(ref.storeRecordId)) return false;
    seenStoreRecordIds.add(ref.storeRecordId);

    if (seenEvidenceIds.has(ref.evidenceId)) return false;
    seenEvidenceIds.add(ref.evidenceId);

    refIndicatorIds.add(ref.indicatorId);
  }

  const obs = draft.observedEvidenceSummary;
  if (!obs || typeof obs !== "object") return false;
  if (Object.keys(obs).length !== 5) return false;

  const etc = obs.evidenceTypeCounts;
  if (!etc || typeof etc !== "object") return false;
  let typeSum = 0;
  for (const [k, v] of Object.entries(etc)) {
    if (!ALLOWED_EVIDENCE_TYPES.includes(k as any)) return false;
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) return false;
    typeSum += v;
  }
  if (typeSum !== src.selectedCount) return false;

  const sc = obs.strengthCounts;
  if (!sc || typeof sc !== "object") return false;
  let strengthSum = 0;
  for (const [k, v] of Object.entries(sc)) {
    if (!ALLOWED_EVIDENCE_STRENGTHS.includes(k as any)) return false;
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) return false;
    strengthSum += v;
  }
  if (strengthSum !== src.selectedCount) return false;

  const ind = obs.indicatorIds;
  if (!Array.isArray(ind) || ind.length === 0 || ind.length > 100) return false;
  if (ind.length !== refIndicatorIds.size) return false;
  const uniqueInd = new Set(ind);
  if (uniqueInd.size !== ind.length) return false;
  
  for (let i = 0; i < ind.length; i++) {
    if (!isStrictSafeId(ind[i])) return false;
    if (!refIndicatorIds.has(ind[i])) return false;
    if (i > 0 && ind[i] <= ind[i-1]) return false; // sorted ASC
  }

  const collected = obs.collectedAtRange;
  if (!collected || typeof collected !== "object") return false;
  if (Object.keys(collected).length !== 2) return false;
  if (!isStrictIsoTimestamp(collected.earliest) || !isStrictIsoTimestamp(collected.latest)) return false;
  if (collected.earliest > collected.latest) return false;

  const saved = obs.savedAtRange;
  if (!saved || typeof saved !== "object") return false;
  if (Object.keys(saved).length !== 2) return false;
  if (!isStrictIsoTimestamp(saved.earliest) || !isStrictIsoTimestamp(saved.latest)) return false;
  if (saved.earliest > saved.latest) return false;

  const triage = draft.draftTriage;
  if (!triage || typeof triage !== "object") return false;
  if (Object.keys(triage).length !== 3) return false;
  if (triage.triageState !== "requires_human_triage") return false;
  if (triage.confidenceState !== "evidence_grouped_not_confirmed") return false;
  if (triage.humanReviewRequired !== true) return false;

  const labels = draft.draftLabels;
  if (!labels || typeof labels !== "object") return false;
  if (Object.keys(labels).length !== 2) return false;
  if (labels.candidateKind !== "reviewed_evidence_group") return false;
  if (labels.labelSource !== "closed_boundary_generated") return false;

  const storage = draft.storage;
  if (!storage || typeof storage !== "object") return false;
  if (Object.keys(storage).length !== 3) return false;
  if (storage.persisted !== false || storage.persistedToDatabase !== false || storage.externalized !== false) return false;

  const nc = draft.explicitNonClaims;
  if (!nc || typeof nc !== "object") return false;
  if (Object.keys(nc).length !== 11) return false;
  if (
    nc.noFindingCandidateCreated !== true ||
    nc.noConfirmedFinding !== true ||
    nc.noConfirmedVulnerability !== true ||
    nc.noExploitabilityClaim !== true ||
    nc.noSeverityRiskOrImpactClaim !== true ||
    nc.noRemediationAdvice !== true ||
    nc.noSafeReportItemCreated !== true ||
    nc.noExternalReportCreated !== true ||
    nc.noNetworkExecution !== true ||
    nc.noToolExecution !== true ||
    nc.noPersistence !== true
  ) return false;

  const cl = draft.classification;
  if (!cl || typeof cl !== "object") return false;
  if (Object.keys(cl).length !== 15) return false;
  if (
    cl.createsFindingCandidateDraft !== true ||
    cl.createsFindingCandidate !== false ||
    cl.createsConfirmedFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.createsExternalReport !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesExploitabilityClaims !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.providesRemediationAdvice !== false ||
    cl.persistsDraft !== false ||
    cl.persistsToDatabase !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return false;

  return true;
}

export async function createReviewedEvidenceFindingCandidateDraft(
  request: any,
  evaluatedAt: string
): Promise<CreateReviewedEvidenceFindingCandidateDraftResult> {
  const baseResult: Omit<CreateReviewedEvidenceFindingCandidateDraftResult, "status" | "reasonCode" | "draft" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "create_reviewed_evidence_finding_candidate_draft_result",
    draftId: isStrictSafeId(request?.draftId) ? request.draftId : "DRAFT_ID_REDACTED",
    scanId: isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED",
    evaluatedAt: isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "TIMESTAMP_REDACTED",
    explicitNonClaims: {
      noFindingCandidateCreated: true,
      noConfirmedFinding: true,
      noConfirmedVulnerability: true,
      noExploitabilityClaim: true,
      noSeverityRiskOrImpactClaim: true,
      noRemediationAdvice: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    }
  };

  const failedClassification = {
    createsFindingCandidateDraft: false,
    createsFindingCandidate: false,
    createsConfirmedFinding: false,
    createsSafeReportItem: false,
    createsExternalReport: false,
    confirmsVulnerabilities: false,
    makesExploitabilityClaims: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    providesRemediationAdvice: false,
    persistsDraft: false,
    persistsToDatabase: false,
    executesNetwork: false,
    executesTools: false
  } as const;

  const failedReturn = (code: CreateReviewedEvidenceFindingCandidateDraftResult["reasonCode"]) => ({
    ...baseResult,
    status: "failed" as const,
    reasonCode: code,
    classification: failedClassification
  });

  const blockedReturn = (code: CreateReviewedEvidenceFindingCandidateDraftResult["reasonCode"]) => ({
    ...baseResult,
    status: "blocked" as const,
    reasonCode: code,
    classification: failedClassification
  });

  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return failedReturn("invalid_draft_request");
  }

  const reqKeys = Object.keys(request);
  const allowedReqKeys = new Set(["contractVersion", "kind", "draftId", "scanId", "requestedAt", "selectionSet", "classification"]);
  if (reqKeys.length !== allowedReqKeys.size) return failedReturn("invalid_draft_request");
  for (const k of reqKeys) {
    if (!allowedReqKeys.has(k)) return failedReturn("invalid_draft_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-finding-candidate-draft/v0") return failedReturn("invalid_draft_metadata");
  if (request.kind !== "create_reviewed_evidence_finding_candidate_draft_request") return failedReturn("invalid_draft_metadata");
  if (!isStrictSafeId(request.draftId)) return failedReturn("invalid_draft_metadata");
  if (!isStrictSafeId(request.scanId)) return failedReturn("invalid_draft_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt)) return failedReturn("invalid_draft_metadata");
  if (!isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_draft_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object") return failedReturn("invalid_draft_metadata");
  if (Object.keys(cl).length !== 15) return failedReturn("invalid_draft_metadata");
  if (
    cl.createsFindingCandidateDraft !== false ||
    cl.createsFindingCandidate !== false ||
    cl.createsConfirmedFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.createsExternalReport !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesExploitabilityClaims !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.providesRemediationAdvice !== false ||
    cl.persistsDraft !== false ||
    cl.persistsToDatabase !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return failedReturn("invalid_draft_metadata");

  const selectionSet = request.selectionSet;
  if (!validateReviewedEvidenceSelectionSet(selectionSet)) {
    return failedReturn("selection_set_invalid");
  }

  if (selectionSet.scanId !== request.scanId) {
    return failedReturn("source_scan_mismatch");
  }

  if (selectionSet.selectionStats.selectedCount <= 0) {
    return blockedReturn("selection_set_empty");
  }

  const summaries = selectionSet.selectedSummaries as ReviewedEvidenceStoreSummary[];
  
  const etc: Record<string, number> = {};
  const sc: Record<string, number> = {};
  
  let earC: string | null = null;
  let latC: string | null = null;
  let earS: string | null = null;
  let latS: string | null = null;

  for (const s of summaries) {
    etc[s.evidenceType] = (etc[s.evidenceType] || 0) + 1;
    sc[s.strength] = (sc[s.strength] || 0) + 1;

    if (earC === null || s.collectedAt < earC) earC = s.collectedAt;
    if (latC === null || s.collectedAt > latC) latC = s.collectedAt;

    if (earS === null || s.savedAt < earS) earS = s.savedAt;
    if (latS === null || s.savedAt > latS) latS = s.savedAt;
  }

  const indicatorIds = Array.from(new Set(selectionSet.selectedRefs.map((ref: any) => ref.indicatorId))).sort() as string[];

  const draft: ReviewedEvidenceFindingCandidateDraft = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "reviewed_evidence_finding_candidate_draft",
    draftId: request.draftId,
    scanId: request.scanId,
    createdAt: evaluatedAt,
    sourceSelection: {
      selectionId: selectionSet.selectionId,
      selectionMode: selectionSet.selectionMode,
      selectedCount: selectionSet.selectionStats.selectedCount,
      selectedRefs: selectionSet.selectedRefs
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: etc,
      strengthCounts: sc,
      indicatorIds,
      collectedAtRange: {
        earliest: earC!,
        latest: latC!
      },
      savedAtRange: {
        earliest: earS!,
        latest: latS!
      }
    },
    draftTriage: {
      triageState: "requires_human_triage",
      confidenceState: "evidence_grouped_not_confirmed",
      humanReviewRequired: true
    },
    draftLabels: {
      candidateKind: "reviewed_evidence_group",
      labelSource: "closed_boundary_generated"
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
      noFindingCandidateCreated: true,
      noConfirmedFinding: true,
      noConfirmedVulnerability: true,
      noExploitabilityClaim: true,
      noSeverityRiskOrImpactClaim: true,
      noRemediationAdvice: true,
      noSafeReportItemCreated: true,
      noExternalReportCreated: true,
      noNetworkExecution: true,
      noToolExecution: true,
      noPersistence: true
    },
    classification: {
      createsFindingCandidateDraft: true,
      createsFindingCandidate: false,
      createsConfirmedFinding: false,
      createsSafeReportItem: false,
      createsExternalReport: false,
      confirmsVulnerabilities: false,
      makesExploitabilityClaims: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      providesRemediationAdvice: false,
      persistsDraft: false,
      persistsToDatabase: false,
      executesNetwork: false,
      executesTools: false
    }
  };

  if (!validateReviewedEvidenceFindingCandidateDraft(draft)) {
    return failedReturn("draft_validation_failed");
  }

  return {
    ...baseResult,
    status: "draft_created",
    reasonCode: "finding_candidate_draft_created",
    draft,
    classification: draft.classification
  };
}
