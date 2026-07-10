import type {
  SummarizeReviewedEvidenceSelectionRequest,
  SummarizeReviewedEvidenceSelectionResult
} from "./ReviewedEvidenceSelectionContracts.js";
import { validateReviewedEvidenceSelectionSet } from "./ReviewedEvidenceSelectionService.js";

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

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

export async function summarizeReviewedEvidenceSelection(
  request: any,
  evaluatedAt: string
): Promise<SummarizeReviewedEvidenceSelectionResult> {
  const baseResult: Omit<SummarizeReviewedEvidenceSelectionResult, "status" | "reasonCode" | "summary" | "error" | "classification"> = {
    contractVersion: "fixguard-reviewed-evidence-selection/v0",
    kind: "summarize_reviewed_evidence_selection_result",
    summaryId: isStrictSafeId(request?.summaryId) ? request.summaryId : "SUMMARY_ID_REDACTED",
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

  const failedReturn = (code: SummarizeReviewedEvidenceSelectionResult["reasonCode"]) => ({
    ...baseResult,
    status: "failed" as const,
    reasonCode: code,
    classification: failedClassification
  });

  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return failedReturn("invalid_selection_summary_request");
  }

  const reqKeys = Object.keys(request);
  const allowedReqKeys = new Set(["contractVersion", "kind", "summaryId", "scanId", "requestedAt", "selectionSet", "classification"]);
  for (const k of reqKeys) {
    if (!allowedReqKeys.has(k)) return failedReturn("invalid_selection_summary_request");
  }

  if (request.contractVersion !== "fixguard-reviewed-evidence-selection/v0") return failedReturn("invalid_selection_summary_metadata");
  if (request.kind !== "summarize_reviewed_evidence_selection_request") return failedReturn("invalid_selection_summary_metadata");
  if (!isStrictSafeId(request.summaryId)) return failedReturn("invalid_selection_summary_metadata");
  if (!isStrictSafeId(request.scanId)) return failedReturn("invalid_selection_summary_metadata");
  if (!isStrictIsoTimestamp(request.requestedAt)) return failedReturn("invalid_selection_summary_metadata");
  if (!isStrictIsoTimestamp(evaluatedAt)) return failedReturn("invalid_selection_summary_metadata");

  const cl = request.classification;
  if (!cl || typeof cl !== "object") return failedReturn("invalid_selection_summary_metadata");
  if (Object.keys(cl).length !== 12) return failedReturn("invalid_selection_summary_metadata");
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
  ) return failedReturn("invalid_selection_summary_metadata");

  if (!request.selectionSet) return failedReturn("invalid_selection_summary_metadata");
  if (!validateReviewedEvidenceSelectionSet(request.selectionSet)) {
    return failedReturn("selection_set_validation_failed");
  }
  
  if (request.selectionSet.scanId !== request.scanId) {
    return failedReturn("source_scan_mismatch");
  }

  return {
    ...baseResult,
    status: "summarized",
    reasonCode: "selection_summary_created",
    summary: {
      selectionId: request.selectionSet.selectionId,
      scanId: request.selectionSet.scanId,
      selectionMode: request.selectionSet.selectionMode,
      selectedCount: request.selectionSet.selectionStats.selectedCount,
      candidateInputCount: request.selectionSet.selectionStats.candidateInputCount,
      rejectedInputCount: request.selectionSet.selectionStats.rejectedInputCount,
      duplicateInputCount: request.selectionSet.selectionStats.duplicateInputCount,
      selectedRefs: request.selectionSet.selectedRefs,
      createdAt: request.selectionSet.createdAt
    },
    classification: failedClassification
  };
}
