import type {
  SummarizeReviewedEvidenceFindingCandidateDraftRequest,
  SummarizeReviewedEvidenceFindingCandidateDraftResult
} from "./ReviewedEvidenceFindingCandidateDraftContracts.js";
import {
  validateReviewedEvidenceFindingCandidateDraft
} from "./ReviewedEvidenceFindingCandidateDraftService.js";

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

export async function summarizeReviewedEvidenceFindingCandidateDraft(
  request: any,
  evaluatedAt: string
): Promise<SummarizeReviewedEvidenceFindingCandidateDraftResult> {
  const baseResult: Omit<SummarizeReviewedEvidenceFindingCandidateDraftResult, "status" | "reasonCode" | "summary" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-draft/v0",
    kind: "summarize_reviewed_evidence_finding_candidate_draft_result",
    summaryId: isStrictSafeId(request?.summaryId) ? request.summaryId : "SUMMARY_ID_REDACTED",
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

  const failedReturn = (code: SummarizeReviewedEvidenceFindingCandidateDraftResult["reasonCode"]) => ({
    ...baseResult,
    status: "failed" as const,
    reasonCode: code,
    classification: failedClassification
  });

  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return failedReturn("invalid_draft_summary_request");
  }

  const reqKeys = Object.keys(request);
  const allowedReqKeys = new Set(["contractVersion", "kind", "summaryId", "scanId", "requestedAt", "draft", "classification"]);
  if (reqKeys.length !== allowedReqKeys.size) return failedReturn("invalid_draft_summary_request");
  for (const k of reqKeys) {
    if (!allowedReqKeys.has(k)) return failedReturn("invalid_draft_summary_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-finding-candidate-draft/v0") return failedReturn("invalid_draft_summary_metadata");
  if (request.kind !== "summarize_reviewed_evidence_finding_candidate_draft_request") return failedReturn("invalid_draft_summary_metadata");
  if (!isStrictSafeId(request.summaryId)) return failedReturn("invalid_draft_summary_metadata");
  if (!isStrictSafeId(request.scanId)) return failedReturn("invalid_draft_summary_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt)) return failedReturn("invalid_draft_summary_metadata");
  if (!isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_draft_summary_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object") return failedReturn("invalid_draft_summary_metadata");
  if (Object.keys(cl).length !== 15) return failedReturn("invalid_draft_summary_metadata");
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
  ) return failedReturn("invalid_draft_summary_metadata");

  const draft = request.draft;
  if (!validateReviewedEvidenceFindingCandidateDraft(draft)) {
    return failedReturn("draft_validation_failed");
  }

  if (draft.scanId !== request.scanId) {
    return failedReturn("source_scan_mismatch");
  }

  const summary = {
    draftId: draft.draftId,
    scanId: draft.scanId,
    sourceSelectionId: draft.sourceSelection.selectionId,
    selectedCount: draft.sourceSelection.selectedCount,
    candidateKind: draft.draftLabels.candidateKind,
    triageState: draft.draftTriage.triageState,
    confidenceState: draft.draftTriage.confidenceState,
    evidenceTypeCounts: draft.observedEvidenceSummary.evidenceTypeCounts,
    strengthCounts: draft.observedEvidenceSummary.strengthCounts,
    indicatorIds: draft.observedEvidenceSummary.indicatorIds,
    createdAt: draft.createdAt
  };

  return {
    ...baseResult,
    status: "summarized",
    reasonCode: "finding_candidate_draft_summary_created",
    summary,
    classification: failedClassification
  };
}
