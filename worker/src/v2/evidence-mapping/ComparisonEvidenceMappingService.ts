import {
  COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION
} from "./ComparisonEvidenceMappingContracts.js";

import type {
  ComparisonEvidenceMappingRequest,
  EvidenceMappingDecision,
  ExplicitNonClaims,
  ComparisonEvidenceMappingRequestClassification,
  MappingMode,
  SourceComparisonMode,
  MappingStatus,
  MappingReasonCode,
  SourceSummary
} from "./ComparisonEvidenceMappingContracts.js";

import type { ResponseComparisonResult } from "../comparison/ResponseComparatorContracts.js";

type ValidationResult = { isValid: true } | { isValid: false, errorCode: MappingReasonCode, message: string };

const FORBIDDEN_WORDS = [
  'authorization', 'bearer', 'cookie', 'set-cookie', 'password', 'secret',
  'token', 'api_key', 'apikey', 'access_token', 'refresh_token',
  'raw_request', 'raw request', 'raw_response', 'raw response',
  'raw_body', 'raw body', 'raw_headers', 'raw headers', 'raw payload',
  'raw command', 'raw output', 'raw tool output', 'stack trace', 'error:',
  'confirmed vulnerability', 'critical severity', 'target is vulnerable',
  'exploitable', 'sqli', 'idor', 'bola', 'auth bypass'
];

function forbiddenContentScan(str: string): boolean {
  if (!str) return false;
  const lower = str.toLowerCase();
  for (const word of FORBIDDEN_WORDS) {
    if (lower.includes(word)) return true;
  }
  return false;
}

function validateSafeId(id: any): ValidationResult {
  if (!id || typeof id !== 'string' || id.length === 0 || id.length > 128)
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'ID invalid' };
  if (!/^[a-zA-Z0-9_\-=]+$/.test(id))
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'ID invalid shape' };
  if (forbiddenContentScan(id))
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'ID has forbidden content' };
  return { isValid: true };
}

function validateIsoTimestamp(ts: any): ValidationResult {
  if (typeof ts !== 'string')
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Timestamp missing or invalid type' };

  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(ts)) {
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Timestamp is not strict ISO 8601' };
  }

  const parsed = new Date(ts);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== ts) {
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Invalid ISO timestamp' };
  }
  return { isValid: true };
}

export function validateComparisonEvidenceMappingRequest(request: any): ValidationResult {
  if (!request || typeof request !== 'object')
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Request must be object' };
  if (request.contractVersion !== COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION)
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Invalid contractVersion' };
  if (request.kind !== "comparison_evidence_mapping_request")
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Invalid kind' };

  if (!validateSafeId(request.mappingId).isValid)
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Invalid mappingId' };
  if (!validateSafeId(request.scanId).isValid)
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Invalid scanId' };
  if (!validateIsoTimestamp(request.requestedAt).isValid)
    return { isValid: false, errorCode: 'invalid_mapping_metadata', message: 'Invalid requestedAt' };

  if (!request.sourceComparison || typeof request.sourceComparison !== 'object')
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'sourceComparison must be an object' };

  const validModes: SourceComparisonMode[] = [
    "http_difference", "authorization_difference", "time_based_difference", "generic_signal_comparison"
  ];
  if (!validModes.includes(request.sourceComparisonMode))
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Invalid sourceComparisonMode' };

  const validMapModes: MappingMode[] = [
    "http_difference_to_evidence", "authorization_difference_to_evidence", 
    "time_based_signal_to_evidence", "manual_review_note"
  ];
  if (!validMapModes.includes(request.mappingMode))
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Invalid mappingMode' };

  if (!request.reviewerPolicy || typeof request.reviewerPolicy !== 'object' || 
      request.reviewerPolicy.requireHumanReview !== true ||
      request.reviewerPolicy.allowAutoEvidenceRecord !== false ||
      request.reviewerPolicy.allowFindingCandidateCreation !== false ||
      request.reviewerPolicy.allowPersistence !== false ||
      request.reviewerPolicy.allowExternalDelivery !== false) {
    return { isValid: false, errorCode: 'blocked_policy_not_review_safe', message: 'Reviewer policy unsafe' };
  }

  // reviewerPolicy keys
  const policyKeys = new Set([
    "requireHumanReview", "allowAutoEvidenceRecord", "allowFindingCandidateCreation", "allowPersistence", "allowExternalDelivery"
  ]);
  for (const k of Object.keys(request.reviewerPolicy)) {
    if (!policyKeys.has(k)) {
      return { isValid: false, errorCode: 'invalid_mapping_request', message: `Unknown field in reviewerPolicy: ${k}` };
    }
  }

  if (!request.classification || typeof request.classification !== 'object' ||
      request.classification.createsRealFindings !== false ||
      request.classification.createsPersistedEvidence !== false ||
      request.classification.confirmsVulnerabilities !== false ||
      request.classification.makesRiskClaims !== false ||
      request.classification.makesSeverityClaims !== false ||
      request.classification.makesImpactClaims !== false ||
      request.classification.executesNetwork !== false ||
      request.classification.executesTools !== false ||
      request.classification.persistsData !== false) {
    return { isValid: false, errorCode: 'invalid_mapping_request', message: 'Classification flags must be false' };
  }

  // classification keys
  const classKeys = new Set([
    "createsRealFindings", "createsPersistedEvidence", "confirmsVulnerabilities", "makesRiskClaims", "makesSeverityClaims", 
    "makesImpactClaims", "executesNetwork", "executesTools", "persistsData"
  ]);
  for (const k of Object.keys(request.classification)) {
    if (!classKeys.has(k)) {
      return { isValid: false, errorCode: 'invalid_mapping_request', message: `Unknown field in classification: ${k}` };
    }
  }

  // Allowed keys top-level
  const allowed = new Set([
    "contractVersion", "kind", "mappingId", "scanId", "requestedAt",
    "sourceComparison", "sourceComparisonMode", "mappingMode", "reviewerPolicy", "classification"
  ]);
  for (const k of Object.keys(request)) {
    if (!allowed.has(k)) {
      return { isValid: false, errorCode: 'invalid_mapping_request', message: `Unknown field ${k}` };
    }
  }

  return { isValid: true };
}

function getSafeClassification(): ComparisonEvidenceMappingRequestClassification {
  return {
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetwork: false,
    executesTools: false,
    persistsData: false
  };
}

function getSafeNonClaims(): ExplicitNonClaims {
  return {
    noConfirmedVulnerability: true,
    noFindingCreated: true,
    noFindingCandidateCreated: true,
    noPersistedEvidenceCreated: true,
    noSeverityRiskOrImpactClaim: true,
    noExternalReportCreated: true,
    noRawSensitiveDataIncluded: true
  };
}

function buildSafeFailure(mappingId: string, scanId: string, comparisonId: string, mappedAt: string, code: MappingReasonCode, msg: string): EvidenceMappingDecision {
  const safeMappingId = validateSafeId(mappingId).isValid ? mappingId : 'invalid_mapping_id';
  const safeScanId = validateSafeId(scanId).isValid ? scanId : 'invalid_scan_id';
  const safeComparisonId = validateSafeId(comparisonId).isValid ? comparisonId : 'invalid_comparison_id';
  const safeMappedAt = validateIsoTimestamp(mappedAt).isValid ? mappedAt : '1970-01-01T00:00:00.000Z';

  return {
    contractVersion: COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION,
    kind: "evidence_mapping_decision",
    mappingId: safeMappingId,
    scanId: safeScanId,
    comparisonId: safeComparisonId,
    mappedAt: safeMappedAt,
    status: "failed",
    reasonCode: code,
    reviewerPolicy: {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false
    },
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification(),
    error: { safeMessage: msg, code }
  };
}

export function mapComparisonToEvidence(request: any, mappedAt: any): EvidenceMappingDecision {
  try {
    const reqVal = validateComparisonEvidenceMappingRequest(request);
    if (!reqVal.isValid) {
      return buildSafeFailure(
        request?.mappingId || 'invalid_mapping_id',
        request?.scanId || 'invalid_scan_id',
        request?.sourceComparison?.comparisonId || 'invalid_comparison_id',
        mappedAt,
        reqVal.errorCode,
        reqVal.message
      );
    }

    const req = request as ComparisonEvidenceMappingRequest;
    const source = req.sourceComparison;

    if (source.contractVersion !== "fixguard-response-comparator/v0" || source.kind !== "response_comparison_result") {
      return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId || 'invalid_comparison_id', mappedAt, 'invalid_mapping_request', 'Invalid source comparison contract');
    }

    // validate source top level keys
    const sourceTopKeys = new Set([
      "contractVersion", "kind", "comparisonId", "scanId", "comparedAt", "status",
      "baselineSnapshotId", "validationSnapshotId", "significance", "difference",
      "evidenceMappingHint", "explicitNonClaims", "classification"
    ]);
    for (const k of Object.keys(source)) {
      if (!sourceTopKeys.has(k)) {
        return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId, mappedAt, 'invalid_mapping_request', `Unknown field in sourceComparison: ${k}`);
      }
    }

    if (!validateIsoTimestamp(mappedAt).isValid) {
      return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId, mappedAt, 'invalid_mapping_metadata', 'Invalid mappedAt');
    }
    
    if (!validateSafeId(source.comparisonId).isValid || !validateSafeId(source.baselineSnapshotId).isValid || !validateSafeId(source.validationSnapshotId).isValid) {
      return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId, mappedAt, 'blocked_source_metadata_unsafe', 'Source metadata IDs unsafe');
    }
    
    if (source.comparisonId === 'invalid_comparison_id' || source.scanId === 'invalid_scan_id' || 
        source.baselineSnapshotId === 'invalid_snapshot_id' || source.validationSnapshotId === 'invalid_snapshot_id' ||
        source.comparedAt === '1970-01-01T00:00:00.000Z') {
      return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId, mappedAt, 'blocked_source_metadata_unsafe', 'Source metadata contains sentinels');
    }
    
    if (source.scanId !== req.scanId) {
      return buildSafeFailure(req.mappingId, req.scanId, source.comparisonId, mappedAt, 'invalid_mapping_request', 'Scan ID mismatch');
    }

    if (source.status === 'failed') {
      return buildBlockedDecision(req, mappedAt, 'blocked_failed_source_comparison');
    }

    if (source.status !== 'completed') {
      return buildBlockedDecision(req, mappedAt, 'blocked_failed_source_comparison');
    }

    if (!source.explicitNonClaims || typeof source.explicitNonClaims !== 'object' ||
        source.explicitNonClaims.noConfirmedVulnerability !== true ||
        source.explicitNonClaims.noFindingCreated !== true ||
        source.explicitNonClaims.noPersistedEvidenceCreated !== true ||
        source.explicitNonClaims.noSeverityRiskOrImpactClaim !== true ||
        source.explicitNonClaims.noRawSensitiveDataIncluded !== true) {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_nonclaims_missing');
    }

    const nonClaimsKeys = new Set([
      "noConfirmedVulnerability", "noFindingCreated", "noFindingCandidateCreated", 
      "noPersistedEvidenceCreated", "noSeverityRiskOrImpactClaim", "noExternalReportCreated", "noRawSensitiveDataIncluded"
    ]);
    for (const k of Object.keys(source.explicitNonClaims)) {
      if (!nonClaimsKeys.has(k)) {
        return buildBlockedDecision(req, mappedAt, 'blocked_source_nonclaims_missing');
      }
    }

    if (!source.classification || typeof source.classification !== 'object' ||
        source.classification.createsRealFindings !== false || 
        source.classification.createsPersistedEvidence !== false ||
        source.classification.confirmsVulnerabilities !== false ||
        source.classification.makesRiskClaims !== false ||
        source.classification.makesSeverityClaims !== false ||
        source.classification.makesImpactClaims !== false ||
        source.classification.executesNetwork !== false ||
        source.classification.executesTools !== false ||
        source.classification.persistsData !== false) {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
    }

    const classKeys = new Set([
      "createsRealFindings", "createsPersistedEvidence", "confirmsVulnerabilities", "makesRiskClaims", "makesSeverityClaims", 
      "makesImpactClaims", "executesNetwork", "executesTools", "persistsData"
    ]);
    for (const k of Object.keys(source.classification)) {
      if (!classKeys.has(k)) {
        return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
      }
    }

    if (!source.evidenceMappingHint || typeof source.evidenceMappingHint !== 'object' ||
        source.evidenceMappingHint.requiresHumanReview !== true ||
        source.evidenceMappingHint.notPersistedEvidence !== true) {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
    }

    const validEvidenceTypes = new Set(["http_difference", "authorization_difference", "time_based_difference", "manual_review_note"]);
    const validStrengths = new Set(["weak", "moderate", "strong"]);

    if (!validEvidenceTypes.has(source.evidenceMappingHint.suggestedEvidenceType) ||
        !validStrengths.has(source.evidenceMappingHint.suggestedSignalStrength)) {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
    }

    const hintKeys = new Set(["suggestedEvidenceType", "suggestedSignalStrength", "requiresHumanReview", "notPersistedEvidence"]);
    for (const k of Object.keys(source.evidenceMappingHint)) {
      if (!hintKeys.has(k)) {
        return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
      }
    }

    const sig = source.significance;
    if (!sig || typeof sig !== 'object' || typeof sig.hasAnyDifference !== 'boolean' || typeof sig.hasSignificantDifference !== 'boolean') {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
    }

    const validStrongestSignals = new Set([
      "none", "status_code", "content_length", "response_time", "body_hash", "headers", "json_shape", "redirect", "auth_state", "error_signal"
    ]);
    const validSignalStrengths = new Set(["none", "weak", "moderate", "strong"]);

    if (!validStrongestSignals.has(sig.strongestSignal) || !validSignalStrengths.has(sig.comparisonSignalStrength)) {
      return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
    }

    const sigKeys = new Set(["comparisonSignalStrength", "strongestSignal", "hasAnyDifference", "hasSignificantDifference", "rationale"]);
    for (const k of Object.keys(sig)) {
      if (!sigKeys.has(k)) {
        return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
      }
    }

    if (sig.hasAnyDifference === false || sig.comparisonSignalStrength === "none") {
      return buildNeedsMoreReviewDecision(req, mappedAt, 'needs_more_review_no_significant_difference');
    }
    if (sig.comparisonSignalStrength === "weak") {
      return buildNeedsMoreReviewDecision(req, mappedAt, 'needs_more_review_weak_signal');
    }

    if (source.difference) {
      if (typeof source.difference !== 'object') {
        return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
      }
      const diffKeys = new Set([
        "statusCodeChanged",
        "baselineStatusCode",
        "validationStatusCode",
        "contentLengthChanged",
        "contentLengthDelta",
        "contentLengthDeltaPercent",
        "contentLengthSignificant",
        "responseTimeChanged",
        "responseTimeDeltaMs",
        "responseTimeSignificant",
        "bodyHashChanged",
        "headerNamesAdded",
        "headerNamesRemoved",
        "jsonKeysAdded",
        "jsonKeysRemoved",
        "redirectChanged",
        "authStateChanged",
        "errorSignalObserved",
        "signalSummary"
      ]);
      for (const k of Object.keys(source.difference)) {
        if (!diffKeys.has(k)) {
          return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
        }
      }

      if (source.difference.signalSummary) {
        if (!Array.isArray(source.difference.signalSummary) || source.difference.signalSummary.length > 20) {
          return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
        }
        const validSummaryItems = new Set([
          "status_code_changed", "content_length_changed", "response_time_changed", "body_hash_changed", "headers_changed",
          "json_shape_changed", "redirect_changed", "auth_state_changed", "error_signal_observed"
        ]);
        for (const item of source.difference.signalSummary) {
          if (!validSummaryItems.has(item)) {
            return buildBlockedDecision(req, mappedAt, 'blocked_source_metadata_unsafe');
          }
        }
      }
    }

    // Match modes
    let mappedType: any = undefined;
    let reason: MappingReasonCode | undefined = undefined;

    if (req.mappingMode === "http_difference_to_evidence") {
      if (source.evidenceMappingHint.suggestedEvidenceType !== "http_difference") {
        return buildBlockedDecision(req, mappedAt, 'blocked_mode_mismatch');
      }
      mappedType = "http_difference";
      reason = "draft_ready_http_difference";
    } else if (req.mappingMode === "authorization_difference_to_evidence") {
      if (req.sourceComparisonMode !== "authorization_difference" || 
          source.evidenceMappingHint.suggestedEvidenceType !== "authorization_difference") {
        return buildBlockedDecision(req, mappedAt, 'blocked_mode_mismatch');
      }
      mappedType = "authorization_difference";
      reason = "draft_ready_authorization_difference";
    } else if (req.mappingMode === "time_based_signal_to_evidence") {
      if (req.sourceComparisonMode !== "time_based_difference" || 
          source.evidenceMappingHint.suggestedEvidenceType !== "time_based_difference" ||
          source.significance?.strongestSignal !== "response_time" ||
          source.difference?.responseTimeSignificant !== true) {
        return buildBlockedDecision(req, mappedAt, 'blocked_mode_mismatch');
      }
      mappedType = "time_based_difference";
      reason = "draft_ready_time_based_signal";
    } else if (req.mappingMode === "manual_review_note") {
      return buildNeedsMoreReviewDecision(req, mappedAt, 'needs_more_review_weak_signal');
    } else {
      return buildBlockedDecision(req, mappedAt, 'blocked_mode_mismatch');
    }

    return buildDraftDecision(req, mappedAt, reason!, mappedType, source.evidenceMappingHint.suggestedSignalStrength);
  } catch (err) {
    return buildSafeFailure(
      request?.mappingId || 'invalid_mapping_id',
      request?.scanId || 'invalid_scan_id',
      request?.sourceComparison?.comparisonId || 'invalid_comparison_id',
      mappedAt,
      'unexpected_mapping_failure',
      'Unexpected error occurred during evidence mapping'
    );
  }
}

function buildSourceSummary(source: ResponseComparisonResult, reqMode: SourceComparisonMode): SourceSummary {
  // sanitize signalSummary
  let signals: any[] = [];
  if (Array.isArray(source.difference?.signalSummary)) {
    const validSummaryItems = new Set([
      "status_code_changed", "content_length_changed", "response_time_changed", "body_hash_changed", "headers_changed",
      "json_shape_changed", "redirect_changed", "auth_state_changed", "error_signal_observed"
    ]);
    for (const s of source.difference!.signalSummary) {
      if (typeof s === 'string' && validSummaryItems.has(s as any) && !forbiddenContentScan(s)) {
        signals.push(s);
      }
    }
    signals = signals.slice(0, 20);
  }

  const validStrongestSignals = new Set([
    "none", "status_code", "content_length", "response_time", "body_hash", "headers", "json_shape", "redirect", "auth_state", "error_signal"
  ]);
  const validSignalStrengths = new Set(["none", "weak", "moderate", "strong"]);

  const strongestSignal = validStrongestSignals.has(source.significance?.strongestSignal as any) ? source.significance?.strongestSignal : "none";
  const comparisonSignalStrength = validSignalStrengths.has(source.significance?.comparisonSignalStrength as any) ? source.significance?.comparisonSignalStrength : "none";

  return {
    comparisonStatus: source.status === 'completed' ? 'completed' : 'failed',
    sourceComparisonMode: reqMode,
    strongestSignal: strongestSignal as any,
    comparisonSignalStrength: comparisonSignalStrength as any,
    signalSummary: signals
  };
}

function buildBlockedDecision(req: ComparisonEvidenceMappingRequest, mappedAt: string, code: MappingReasonCode): EvidenceMappingDecision {
  return {
    contractVersion: COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION,
    kind: "evidence_mapping_decision",
    mappingId: req.mappingId,
    scanId: req.scanId,
    comparisonId: req.sourceComparison.comparisonId,
    mappedAt: mappedAt,
    status: "blocked",
    reasonCode: code,
    sourceSummary: buildSourceSummary(req.sourceComparison, req.sourceComparisonMode),
    reviewerPolicy: req.reviewerPolicy,
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification()
  };
}

function buildNeedsMoreReviewDecision(req: ComparisonEvidenceMappingRequest, mappedAt: string, code: MappingReasonCode): EvidenceMappingDecision {
  return {
    contractVersion: COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION,
    kind: "evidence_mapping_decision",
    mappingId: req.mappingId,
    scanId: req.scanId,
    comparisonId: req.sourceComparison.comparisonId,
    mappedAt: mappedAt,
    status: "needs_more_review",
    reasonCode: code,
    sourceSummary: buildSourceSummary(req.sourceComparison, req.sourceComparisonMode),
    reviewerPolicy: req.reviewerPolicy,
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification()
  };
}

function buildDraftDecision(req: ComparisonEvidenceMappingRequest, mappedAt: string, code: MappingReasonCode, evType: any, evStrength: any): EvidenceMappingDecision {
  const safeRationale = "Safe response comparison produced a non-persisted draft for human review.";

  return {
    contractVersion: COMPARISON_EVIDENCE_MAPPING_CONTRACT_VERSION,
    kind: "evidence_mapping_decision",
    mappingId: req.mappingId,
    scanId: req.scanId,
    comparisonId: req.sourceComparison.comparisonId,
    mappedAt: mappedAt,
    status: "draft_ready",
    reasonCode: code,
    sourceSummary: buildSourceSummary(req.sourceComparison, req.sourceComparisonMode),
    mappedEvidenceType: evType,
    mappedSignalStrength: evStrength,
    evidenceDraft: {
      draftKind: "non_persisted_comparison_evidence_draft",
      draftId: `draft_${req.mappingId}`,
      suggestedEvidenceType: evType,
      suggestedStrength: evStrength,
      sourceComparisonId: req.sourceComparison.comparisonId,
      sourceSnapshotIds: {
        baselineSnapshotId: req.sourceComparison.baselineSnapshotId!,
        validationSnapshotId: req.sourceComparison.validationSnapshotId!
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: safeRationale
    },
    reviewerPolicy: req.reviewerPolicy,
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification()
  };
}
