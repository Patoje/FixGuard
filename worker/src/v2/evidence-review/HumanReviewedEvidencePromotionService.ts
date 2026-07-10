import type {
  HumanReviewedEvidencePromotionRequest,
  HumanReviewedEvidencePromotionResult,
  HumanReviewedEvidencePromotionReasonCode,
  HumanReviewedEvidencePromotionRequestClassification
} from "./HumanReviewedEvidencePromotionContracts.js";
import { validateEvidenceRecord } from "../evidence/EvidenceBoundaryService.js";
import type { EvidenceRecord } from "../evidence/EvidenceBoundaryContracts.js";
import { validateEvidenceDraftEnvelopeForValidationResult } from "../validation/AuthorizedComparisonValidationService.js";

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

const ALLOWED_M49_STATUSES = new Set([
  "completed", "blocked", "needs_more_review", "failed"
]);

const ALLOWED_M49_REASONS = new Set([
  "completed_with_evidence_draft", "needs_more_review_from_mapping",
  "blocked_scope_denied", "blocked_scope_invalid", "blocked_comparison_failed",
  "blocked_mapping_blocked", "failed_mapping_failed", "blocked_policy_not_review_safe",
  "invalid_validation_request", "invalid_validation_metadata", "unsafe_content_rejected",
  "unexpected_validation_failure"
]);

const ALLOWED_REQUEST_KEYS = new Set([
  "contractVersion", "kind", "promotionId", "scanId", "requestedAt",
  "validationResult", "sourceIndicatorRef", "reviewDecision", "classification"
]);

export function evaluateHumanReviewedEvidencePromotion(
  request: any,
  evaluatedAt: string
): HumanReviewedEvidencePromotionResult {
  const safeEvaluatedAt = isStrictIsoTimestamp(evaluatedAt) ? evaluatedAt : "1970-01-01T00:00:00.000Z";
  const safePromotionId = isStrictSafeId(request?.promotionId) ? request.promotionId : "PROMOTION_ID_REDACTED";
  const safeScanId = isStrictSafeId(request?.scanId) ? request.scanId : "SCAN_ID_REDACTED";

  const baseResult: HumanReviewedEvidencePromotionResult = {
    contractVersion: "fixguard-human-reviewed-evidence-promotion/v0",
    kind: "human_reviewed_evidence_promotion_result",
    promotionId: safePromotionId,
    scanId: safeScanId,
    evaluatedAt: safeEvaluatedAt,
    status: "failed",
    reasonCode: "invalid_promotion_request",
    explicitNonClaims: {
      noConfirmedVulnerability: true,
      noFindingCreated: true,
      noFindingCandidateCreated: true,
      noSafeReportItemCreated: true,
      noSeverityRiskOrImpactClaim: true,
      noExternalReportCreated: true,
      noPersistence: true,
      noNetworkExecution: true,
      noToolExecution: true,
    },
    classification: {
      createsNonPersistedEvidenceRecord: false,
      createsPersistedEvidence: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  if (!isStrictIsoTimestamp(evaluatedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_metadata" };
  }

  if (!request || request.contractVersion !== "fixguard-human-reviewed-evidence-promotion/v0" || request.kind !== "human_reviewed_evidence_promotion_request") {
    return { ...baseResult, reasonCode: "invalid_promotion_request" };
  }

  // Blocking issue 1: Top-level keys
  for (const key of Object.keys(request)) {
    if (!ALLOWED_REQUEST_KEYS.has(key)) {
      return { ...baseResult, reasonCode: "invalid_promotion_request" };
    }
  }

  if (!isStrictSafeId(request.promotionId) || !isStrictSafeId(request.scanId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_metadata" };
  }

  if (!isStrictIsoTimestamp(request.requestedAt)) {
    return { ...baseResult, reasonCode: "invalid_promotion_metadata" };
  }

  // Validate request classification
  const reqClass = request.classification;
  if (!reqClass ||
      reqClass.createsNonPersistedEvidenceRecord !== false ||
      reqClass.createsPersistedEvidence !== false ||
      reqClass.createsFindingCandidate !== false ||
      reqClass.createsSafeReportItem !== false ||
      reqClass.confirmsVulnerabilities !== false ||
      reqClass.makesRiskClaims !== false ||
      reqClass.makesSeverityClaims !== false ||
      reqClass.makesImpactClaims !== false ||
      reqClass.executesNetwork !== false ||
      reqClass.executesTools !== false ||
      reqClass.persistsData !== false) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_request" };
  }
  
  if (Object.keys(reqClass).length !== 11) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_request" };
  }

  const reviewDecision = request.reviewDecision;
  if (!reviewDecision) {
    return { ...baseResult, status: "failed", reasonCode: "human_review_required" };
  }

  if (!["approve_evidence", "reject", "needs_more_review"].includes(reviewDecision.decision)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_request" };
  }

  if (!isStrictSafeId(reviewDecision.reviewerId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_metadata" };
  }

  if (!isStrictIsoTimestamp(reviewDecision.reviewedAt)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_metadata" };
  }

  baseResult.reviewSummary = {
    decision: reviewDecision.decision as any,
    reviewerId: reviewDecision.reviewerId,
    reviewedAt: reviewDecision.reviewedAt
  };

  if (reviewDecision.decision === "reject") {
    return { ...baseResult, status: "rejected", reasonCode: "rejected_by_human_review" };
  }

  if (reviewDecision.decision === "needs_more_review") {
    return { ...baseResult, status: "needs_more_review", reasonCode: "human_review_requested_more_review" };
  }

  // Validate Source Indicator Ref
  const sourceIndicatorRef = request.sourceIndicatorRef;
  if (!sourceIndicatorRef) {
    return { ...baseResult, status: "blocked", reasonCode: "source_indicator_ref_missing" };
  }
  if (sourceIndicatorRef.kind !== "reviewed_indicator_reference" || !isStrictSafeId(sourceIndicatorRef.indicatorId)) {
    return { ...baseResult, status: "failed", reasonCode: "invalid_promotion_metadata" };
  }
  if (sourceIndicatorRef.scanId !== request.scanId) {
    return { ...baseResult, status: "blocked", reasonCode: "source_scan_mismatch" };
  }

  // Validate M49 Result
  const valResult = request.validationResult;
  if (!valResult || valResult.contractVersion !== "fixguard-authorized-comparison-validation/v0" || valResult.kind !== "authorized_comparison_validation_result") {
    return { ...baseResult, status: "blocked", reasonCode: "source_validation_not_completed" };
  }
  
  // Blocking issue 4: sanitize sourceValidationSummary
  let safeValidationId = "VALIDATION_ID_REDACTED";
  if (isStrictSafeId(valResult.validationId)) {
    safeValidationId = valResult.validationId;
  }
  const safeStatus = ALLOWED_M49_STATUSES.has(valResult.status) ? valResult.status : "UNKNOWN";
  const safeReason = ALLOWED_M49_REASONS.has(valResult.reasonCode) ? valResult.reasonCode : "UNKNOWN";

  baseResult.sourceValidationSummary = {
    validationId: safeValidationId,
    status: safeStatus,
    reasonCode: safeReason,
    evidenceDraftPresent: !!valResult.evidenceDraft
  };

  if (!ALLOWED_M49_STATUSES.has(valResult.status) || !ALLOWED_M49_REASONS.has(valResult.reasonCode)) {
    return { ...baseResult, status: "blocked", reasonCode: "source_validation_not_completed" };
  }

  if (valResult.scanId !== request.scanId) {
    return { ...baseResult, status: "blocked", reasonCode: "source_scan_mismatch" };
  }

  if (valResult.status !== "completed") {
    return { ...baseResult, status: "blocked", reasonCode: "source_validation_not_completed" };
  }
  
  if (valResult.reasonCode !== "completed_with_evidence_draft") {
    return { ...baseResult, status: "blocked", reasonCode: "source_validation_not_evidence_ready" };
  }
  
  if (!valResult.evidenceDraft) {
    return { ...baseResult, status: "blocked", reasonCode: "source_evidence_draft_missing" };
  }

  const isDraftValid = validateEvidenceDraftEnvelopeForValidationResult(valResult.evidenceDraft);
  if (!isDraftValid) {
    return { ...baseResult, status: "blocked", reasonCode: "source_evidence_draft_invalid" };
  }
  
  if (valResult.evidenceDraft.suggestedStrength !== "weak" && valResult.evidenceDraft.suggestedStrength !== "moderate" && valResult.evidenceDraft.suggestedStrength !== "strong") {
    return { ...baseResult, status: "blocked", reasonCode: "source_evidence_draft_invalid" };
  }

  // Blocking issue 2: M49 classification and explicit non claims
  const vClass = valResult.classification;
  if (!vClass ||
      vClass.createsRealFindings !== false ||
      vClass.createsPersistedEvidence !== false ||
      vClass.confirmsVulnerabilities !== false ||
      vClass.makesRiskClaims !== false ||
      vClass.makesSeverityClaims !== false ||
      vClass.makesImpactClaims !== false ||
      vClass.executesNetwork !== false ||
      vClass.executesTools !== false ||
      vClass.persistsData !== false ||
      Object.keys(vClass).length !== 9) {
    return { ...baseResult, status: "blocked", reasonCode: "blocked_policy_not_review_safe" };
  }

  const vNonClaims = valResult.explicitNonClaims;
  if (!vNonClaims ||
      vNonClaims.noConfirmedVulnerability !== true ||
      vNonClaims.noFindingCreated !== true ||
      vNonClaims.noFindingCandidateCreated !== true ||
      vNonClaims.noPersistedEvidenceCreated !== true ||
      vNonClaims.noSeverityRiskOrImpactClaim !== true ||
      vNonClaims.noExternalReportCreated !== true ||
      vNonClaims.noRawSensitiveDataIncluded !== true ||
      vNonClaims.noNetworkExecution !== true ||
      vNonClaims.noToolExecution !== true ||
      Object.keys(vNonClaims).length !== 9) {
    return { ...baseResult, status: "blocked", reasonCode: "blocked_policy_not_review_safe" };
  }

  // Construct EvidenceRecord
  const evidenceRecord: any = {
    contractVersion: "fixguard-evidence-boundary/v0",
    kind: "evidence_record",
    evidenceId: `evd_${safePromotionId.substring(0, 16)}`,
    scanId: safeScanId,
    indicatorId: sourceIndicatorRef.indicatorId,
    collectedAt: safeEvaluatedAt,
    collectedBy: "response_comparator",
    evidenceType: valResult.evidenceDraft.suggestedEvidenceType,
    strength: valResult.evidenceDraft.suggestedStrength,
    redaction: { isRedacted: true, redactionMethod: "m48_safe_comparison_draft" },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false
    }
  };

  const validationCode = validateEvidenceRecord(evidenceRecord);
  if (!validationCode.isValid) {
    console.error("DEBUG: validateEvidenceRecord failed:", validationCode.message);
    return { ...baseResult, status: "blocked", reasonCode: "evidence_record_validation_failed" };
  }

  return {
    ...baseResult,
    status: "promoted",
    reasonCode: "promoted_to_non_persisted_evidence_record",
    nonPersistedEvidenceRecord: evidenceRecord as EvidenceRecord,
    classification: {
      ...baseResult.classification,
      createsNonPersistedEvidenceRecord: true
    }
  };
}
