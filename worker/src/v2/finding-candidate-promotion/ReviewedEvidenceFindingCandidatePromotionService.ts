import type {
  PromoteReviewedEvidenceFindingCandidateDraftRequest,
  PromoteReviewedEvidenceFindingCandidateDraftResult,
  ReviewedEvidenceFormalFindingCandidate,
  ReviewedEvidenceFindingCandidatePromotionReasonCode
} from "./ReviewedEvidenceFindingCandidatePromotionContracts.js";
import {
  validateReviewedEvidenceFindingCandidateDraft
} from "../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftService.js";
import {
  ALLOWED_EVIDENCE_TYPES,
  ALLOWED_EVIDENCE_STRENGTHS
} from "../evidence/EvidenceBoundaryContracts.js";

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

export function validateReviewedEvidenceFormalFindingCandidate(candidate: any): boolean {
  if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) return false;

  const keys = Object.keys(candidate);
  const allowedKeys = new Set([
    "contractVersion", "kind", "candidateId", "scanId", "createdAt",
    "sourceDraft", "humanTriage", "evidenceRefs", "observedEvidenceSummary",
    "candidateState", "storage", "explicitNonClaims", "classification"
  ]);

  if (keys.length !== 13) return false;
  for (const k of keys) {
    if (!allowedKeys.has(k)) return false;
  }

  if (candidate.contractVersion !== "fixguard-reviewed-evidence-formal-finding-candidate/v0") return false;
  if (candidate.kind !== "reviewed_evidence_formal_finding_candidate") return false;

  if (!isStrictSafeId(candidate.candidateId)) return false;
  if (!isStrictSafeId(candidate.scanId)) return false;
  if (!isStrictIsoTimestamp(candidate.createdAt)) return false;

  const src = candidate.sourceDraft;
  if (!src || typeof src !== "object") return false;
  if (Object.keys(src).length !== 6) return false;
  if (!isStrictSafeId(src.draftId)) return false;
  if (!isStrictSafeId(src.sourceSelectionId)) return false;
  if (typeof src.selectedCount !== "number" || !Number.isInteger(src.selectedCount) || src.selectedCount <= 0) return false;
  if (src.candidateKind !== "reviewed_evidence_group") return false;
  if (src.triageState !== "requires_human_triage") return false;
  if (src.confidenceState !== "evidence_grouped_not_confirmed") return false;

  const ht = candidate.humanTriage;
  if (!ht || typeof ht !== "object") return false;
  if (Object.keys(ht).length !== 5) return false;
  if (!isStrictSafeId(ht.decisionId)) return false;
  if (!isStrictSafeId(ht.reviewerId)) return false;
  if (!isStrictIsoTimestamp(ht.reviewedAt)) return false;
  if (ht.decision !== "approve_finding_candidate_promotion") return false;
  if (ht.humanApprovedPromotion !== true) return false;

  const refs = candidate.evidenceRefs;
  if (!refs || typeof refs !== "object") return false;
  if (Object.keys(refs).length !== 2) return false;
  if (!Array.isArray(refs.selectedRefs) || refs.selectedRefs.length === 0 || refs.selectedRefs.length > 100) return false;
  if (refs.selectedCount !== refs.selectedRefs.length) return false;
  if (refs.selectedCount !== src.selectedCount) return false;

  const seenStoreRecordIds = new Set<string>();
  const seenEvidenceIds = new Set<string>();
  const refIndicatorIds = new Set<string>();

  for (const ref of refs.selectedRefs) {
    if (!ref || typeof ref !== "object") return false;
    if (Object.keys(ref).length !== 4) return false;
    if (!isStrictSafeId(ref.storeRecordId) || !isStrictSafeId(ref.evidenceId) || !isStrictSafeId(ref.scanId) || !isStrictSafeId(ref.indicatorId)) return false;
    if (ref.scanId !== candidate.scanId) return false;

    if (seenStoreRecordIds.has(ref.storeRecordId)) return false;
    seenStoreRecordIds.add(ref.storeRecordId);

    if (seenEvidenceIds.has(ref.evidenceId)) return false;
    seenEvidenceIds.add(ref.evidenceId);

    refIndicatorIds.add(ref.indicatorId);
  }

  const obs = candidate.observedEvidenceSummary;
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
  if (typeSum !== refs.selectedCount) return false;

  const sc = obs.strengthCounts;
  if (!sc || typeof sc !== "object") return false;
  let strengthSum = 0;
  for (const [k, v] of Object.entries(sc)) {
    if (!ALLOWED_EVIDENCE_STRENGTHS.includes(k as any)) return false;
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) return false;
    strengthSum += v;
  }
  if (strengthSum !== refs.selectedCount) return false;

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

  const state = candidate.candidateState;
  if (!state || typeof state !== "object") return false;
  if (Object.keys(state).length !== 5) return false;
  if (state.lifecycleState !== "formal_candidate_created") return false;
  if (state.confirmationState !== "not_confirmed") return false;
  if (state.reportState !== "not_reported") return false;
  if (state.persistenceState !== "not_persisted") return false;
  if (state.requiresFurtherHumanReview !== true) return false;

  const storage = candidate.storage;
  if (!storage || typeof storage !== "object") return false;
  if (Object.keys(storage).length !== 3) return false;
  if (storage.persisted !== false || storage.persistedToDatabase !== false || storage.externalized !== false) return false;

  const nc = candidate.explicitNonClaims;
  if (!nc || typeof nc !== "object") return false;
  if (Object.keys(nc).length !== 10) return false;
  if (
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

  const cl = candidate.classification;
  if (!cl || typeof cl !== "object") return false;
  if (Object.keys(cl).length !== 14) return false;
  if (
    cl.createsFormalFindingCandidate !== true ||
    cl.createsConfirmedFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.createsExternalReport !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesExploitabilityClaims !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.providesRemediationAdvice !== false ||
    cl.persistsCandidate !== false ||
    cl.persistsToDatabase !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return false;

  return true;
}

export async function promoteReviewedEvidenceFindingCandidateDraft(
  request: any,
  evaluatedAt: string
): Promise<PromoteReviewedEvidenceFindingCandidateDraftResult> {
  const baseResult: Omit<PromoteReviewedEvidenceFindingCandidateDraftResult, "status" | "reasonCode" | "candidate" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
    kind: "promote_reviewed_evidence_finding_candidate_draft_result",
    candidateId: isStrictSafeId(request?.candidateId) ? request.candidateId : "CANDIDATE_ID_REDACTED",
    scanId: isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED",
    evaluatedAt: isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "TIMESTAMP_REDACTED",
    explicitNonClaims: {
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
    createsFormalFindingCandidate: false,
    createsConfirmedFinding: false,
    createsSafeReportItem: false,
    createsExternalReport: false,
    confirmsVulnerabilities: false,
    makesExploitabilityClaims: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    providesRemediationAdvice: false,
    persistsCandidate: false,
    persistsToDatabase: false,
    executesNetwork: false,
    executesTools: false
  } as const;

  const failedReturn = (code: ReviewedEvidenceFindingCandidatePromotionReasonCode) => ({
    ...baseResult,
    status: "failed" as const,
    reasonCode: code,
    classification: failedClassification
  });

  const blockedReturn = (code: ReviewedEvidenceFindingCandidatePromotionReasonCode) => ({
    ...baseResult,
    status: "blocked" as const,
    reasonCode: code,
    classification: failedClassification
  });

  if (!request || typeof request !== "object" || Array.isArray(request)) return failedReturn("invalid_promotion_request");
  
  const keys = Object.keys(request);
  const allowedKeys = new Set(["contractVersion", "kind", "candidateId", "scanId", "requestedAt", "draft", "triageDecision", "classification"]);
  if (keys.length !== 8) return failedReturn("invalid_promotion_request");
  for (const k of keys) {
    if (!allowedKeys.has(k)) return failedReturn("invalid_promotion_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-finding-candidate-promotion/v0") return failedReturn("invalid_promotion_request");
  if (request.kind !== "promote_reviewed_evidence_finding_candidate_draft_request") return failedReturn("invalid_promotion_request");

  if (!isStrictSafeId(request.candidateId) || !isStrictSafeId(request.scanId)) return failedReturn("invalid_promotion_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt) || !isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_promotion_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object" || Object.keys(cl).length !== 14) return failedReturn("invalid_promotion_metadata");
  if (
    cl.createsFormalFindingCandidate !== false ||
    cl.createsConfirmedFinding !== false ||
    cl.createsSafeReportItem !== false ||
    cl.createsExternalReport !== false ||
    cl.confirmsVulnerabilities !== false ||
    cl.makesExploitabilityClaims !== false ||
    cl.makesRiskClaims !== false ||
    cl.makesSeverityClaims !== false ||
    cl.makesImpactClaims !== false ||
    cl.providesRemediationAdvice !== false ||
    cl.persistsCandidate !== false ||
    cl.persistsToDatabase !== false ||
    cl.executesNetwork !== false ||
    cl.executesTools !== false
  ) return failedReturn("invalid_promotion_metadata");

  const draft = request.draft;
  if (!validateReviewedEvidenceFindingCandidateDraft(draft)) return failedReturn("draft_invalid");
  if (draft.scanId !== request.scanId) return failedReturn("source_scan_mismatch");

  const td = request.triageDecision;
  if (!td || typeof td !== "object" || Array.isArray(td)) return failedReturn("invalid_triage_decision");
  const tdKeys = Object.keys(td);
  const tdAllowedKeys = new Set(["decisionId", "reviewerId", "reviewedAt", "decision", "attestations", "explicitNonClaims"]);
  if (tdKeys.length !== 6) return failedReturn("invalid_triage_decision");
  for (const k of tdKeys) {
    if (!tdAllowedKeys.has(k)) return failedReturn("invalid_triage_decision");
  }

  if (!isStrictSafeId(td.decisionId) || !isStrictSafeId(td.reviewerId) || !isStrictIsoTimestamp(td.reviewedAt)) return failedReturn("invalid_triage_decision");

  const nc = td.explicitNonClaims;
  if (!nc || typeof nc !== "object" || Object.keys(nc).length !== 10) return failedReturn("invalid_triage_decision");
  if (
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
  ) return failedReturn("invalid_triage_decision");

  const att = td.attestations;
  if (!att || typeof att !== "object" || Object.keys(att).length !== 8) return failedReturn("invalid_triage_decision");
  if (
    att.reviewedDraft !== true ||
    att.reviewedEvidenceRefs !== true ||
    att.understandsCandidateIsNotConfirmedFinding !== true ||
    att.understandsNoVulnerabilityConfirmed !== true ||
    att.understandsNoExploitabilityClaim !== true ||
    att.understandsNoSeverityRiskImpactAssigned !== true ||
    att.understandsNoRemediationAdvice !== true ||
    typeof att.authorizedPromotionToFormalCandidate !== "boolean"
  ) return failedReturn("invalid_triage_decision");

  if (td.decision === "reject_finding_candidate_promotion") return blockedReturn("triage_decision_rejected");
  if (td.decision === "needs_more_evidence") return blockedReturn("triage_needs_more_evidence");
  if (td.decision !== "approve_finding_candidate_promotion") return failedReturn("invalid_triage_decision");
  
  if (att.authorizedPromotionToFormalCandidate !== true) return blockedReturn("triage_authorization_missing");

  const candidate: ReviewedEvidenceFormalFindingCandidate = {
    contractVersion: "fixguard-reviewed-evidence-formal-finding-candidate/v0",
    kind: "reviewed_evidence_formal_finding_candidate",
    candidateId: request.candidateId,
    scanId: request.scanId,
    createdAt: evaluatedAt,
    sourceDraft: {
      draftId: draft.draftId,
      sourceSelectionId: draft.sourceSelection.selectionId,
      selectedCount: draft.sourceSelection.selectedCount,
      candidateKind: "reviewed_evidence_group",
      triageState: "requires_human_triage",
      confidenceState: "evidence_grouped_not_confirmed"
    },
    humanTriage: {
      decisionId: td.decisionId,
      reviewerId: td.reviewerId,
      reviewedAt: td.reviewedAt,
      decision: "approve_finding_candidate_promotion",
      humanApprovedPromotion: true
    },
    evidenceRefs: {
      selectedRefs: draft.sourceSelection.selectedRefs.map((r: any) => ({
        storeRecordId: r.storeRecordId,
        evidenceId: r.evidenceId,
        scanId: r.scanId,
        indicatorId: r.indicatorId
      })),
      selectedCount: draft.sourceSelection.selectedCount
    },
    observedEvidenceSummary: {
      evidenceTypeCounts: { ...draft.observedEvidenceSummary.evidenceTypeCounts },
      strengthCounts: { ...draft.observedEvidenceSummary.strengthCounts },
      indicatorIds: [...draft.observedEvidenceSummary.indicatorIds],
      collectedAtRange: { ...draft.observedEvidenceSummary.collectedAtRange },
      savedAtRange: { ...draft.observedEvidenceSummary.savedAtRange }
    },
    candidateState: {
      lifecycleState: "formal_candidate_created",
      confirmationState: "not_confirmed",
      reportState: "not_reported",
      persistenceState: "not_persisted",
      requiresFurtherHumanReview: true
    },
    storage: {
      persisted: false,
      persistedToDatabase: false,
      externalized: false
    },
    explicitNonClaims: {
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
      createsFormalFindingCandidate: true,
      createsConfirmedFinding: false,
      createsSafeReportItem: false,
      createsExternalReport: false,
      confirmsVulnerabilities: false,
      makesExploitabilityClaims: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      providesRemediationAdvice: false,
      persistsCandidate: false,
      persistsToDatabase: false,
      executesNetwork: false,
      executesTools: false
    }
  };

  if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) {
    return failedReturn("candidate_validation_failed");
  }

  return {
    ...baseResult,
    status: "candidate_created",
    reasonCode: "formal_finding_candidate_created",
    candidate,
    classification: {
      ...failedClassification,
      createsFormalFindingCandidate: true
    }
  };
}
