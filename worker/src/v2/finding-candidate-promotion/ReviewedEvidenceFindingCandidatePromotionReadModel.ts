import type {
  SummarizeReviewedEvidenceFormalFindingCandidateRequest,
  SummarizeReviewedEvidenceFormalFindingCandidateResult,
  ReviewedEvidenceFindingCandidatePromotionReasonCode
} from "./ReviewedEvidenceFindingCandidatePromotionContracts.js";
import {
  validateReviewedEvidenceFormalFindingCandidate
} from "./ReviewedEvidenceFindingCandidatePromotionService.js";

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

export async function summarizeReviewedEvidenceFormalFindingCandidate(
  request: any,
  evaluatedAt: string
): Promise<SummarizeReviewedEvidenceFormalFindingCandidateResult> {
  const baseResult: Omit<SummarizeReviewedEvidenceFormalFindingCandidateResult, "status" | "reasonCode" | "summary" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-finding-candidate-promotion/v0",
    kind: "summarize_reviewed_evidence_formal_finding_candidate_result",
    summaryId: isStrictSafeId(request?.summaryId) ? request.summaryId : "SUMMARY_ID_REDACTED",
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

  if (!request || typeof request !== "object" || Array.isArray(request)) return failedReturn("invalid_candidate_summary_request");
  
  const keys = Object.keys(request);
  const allowedKeys = new Set(["contractVersion", "kind", "summaryId", "scanId", "requestedAt", "candidate", "classification"]);
  if (keys.length !== 7) return failedReturn("invalid_candidate_summary_request");
  for (const k of keys) {
    if (!allowedKeys.has(k)) return failedReturn("invalid_candidate_summary_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-finding-candidate-promotion/v0") return failedReturn("invalid_candidate_summary_request");
  if (request.kind !== "summarize_reviewed_evidence_formal_finding_candidate_request") return failedReturn("invalid_candidate_summary_request");

  if (!isStrictSafeId(request.summaryId) || !isStrictSafeId(request.scanId)) return failedReturn("invalid_candidate_summary_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt) || !isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_candidate_summary_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object" || Object.keys(cl).length !== 14) return failedReturn("invalid_candidate_summary_metadata");
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
  ) return failedReturn("invalid_candidate_summary_metadata");

  const candidate = request.candidate;
  if (!validateReviewedEvidenceFormalFindingCandidate(candidate)) return failedReturn("candidate_validation_failed");
  if (candidate.scanId !== request.scanId) return failedReturn("source_scan_mismatch");

  return {
    ...baseResult,
    status: "summarized",
    reasonCode: "formal_finding_candidate_summary_created",
    summary: {
      candidateId: candidate.candidateId,
      scanId: candidate.scanId,
      sourceDraftId: candidate.sourceDraft.draftId,
      sourceSelectionId: candidate.sourceDraft.sourceSelectionId,
      selectedCount: candidate.sourceDraft.selectedCount,
      lifecycleState: "formal_candidate_created",
      confirmationState: "not_confirmed",
      reportState: "not_reported",
      persistenceState: "not_persisted",
      evidenceTypeCounts: { ...candidate.observedEvidenceSummary.evidenceTypeCounts },
      strengthCounts: { ...candidate.observedEvidenceSummary.strengthCounts },
      indicatorIds: [...candidate.observedEvidenceSummary.indicatorIds],
      createdAt: candidate.createdAt
    },
    classification: failedClassification
  };
}
