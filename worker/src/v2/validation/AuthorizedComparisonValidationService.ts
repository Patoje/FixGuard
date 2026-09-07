import { AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION } from "./AuthorizedComparisonValidationContracts.js";
import type {
  AuthorizedComparisonValidationRequest,
  AuthorizedComparisonValidationResult,
  AuthorizedComparisonValidationReasonCode,
  ExplicitNonClaims,
  AuthorizedComparisonValidationClassification,
  ScopeDecisionSummary,
  ComparisonSummary,
  MappingSummary,
  AuthorizedComparisonValidationProvenance
} from "./AuthorizedComparisonValidationContracts.js";
import { evaluateScopePolicy } from "../scope/AuthorizedScopePolicyService.js";
import { compareResponses } from "../comparison/ResponseComparatorService.js";
import { mapComparisonToEvidence } from "../evidence-mapping/ComparisonEvidenceMappingService.js";
import type { ResponseComparisonRequest } from "../comparison/ResponseComparatorContracts.js";
import type { ComparisonEvidenceMappingRequest } from "../evidence-mapping/ComparisonEvidenceMappingContracts.js";
import {
  isRuntimeEstablishedVerifiedAuthorizationDecision,
  deriveAuthorizationLineageRef
} from "../authorization/VerifiedAuthorizationDecisionService.js";

function getSafeClassification(): AuthorizedComparisonValidationClassification {
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
    noRawSensitiveDataIncluded: true,
    noNetworkExecution: true,
    noToolExecution: true
  };
}

function buildSafeFailure(
  validationId: string,
  scanId: string,
  evaluatedAt: string,
  code: AuthorizedComparisonValidationReasonCode,
  msg: string
): AuthorizedComparisonValidationResult {
  return {
    contractVersion: AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION,
    kind: "authorized_comparison_validation_result",
    validationId,
    scanId,
    evaluatedAt,
    status: "failed",
    reasonCode: code,
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification(),
    error: { code, safeMessage: msg }
  };
}

function buildBlockedResult(
  validationId: string,
  scanId: string,
  evaluatedAt: string,
  code: AuthorizedComparisonValidationReasonCode,
  scopeDecisionSummary?: ScopeDecisionSummary,
  comparisonSummary?: ComparisonSummary,
  mappingSummary?: MappingSummary,
  provenance?: AuthorizedComparisonValidationProvenance
): AuthorizedComparisonValidationResult {
  return {
    contractVersion: AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION,
    kind: "authorized_comparison_validation_result",
    validationId,
    scanId,
    evaluatedAt,
    status: "blocked",
    reasonCode: code,
    scopeDecisionSummary,
    comparisonSummary,
    mappingSummary,
    ...(provenance ? { provenance } : {}),
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification()
  };
}

function hasForbiddenContent(text: string): boolean {
  if (!text) return false;
  const t = text.toLowerCase();
  const forbidden = [
    'authorization', 'bearer', 'cookie', 'set-cookie', 'password', 'secret',
    'token', 'api_key', 'apikey', 'access_token', 'refresh_token',
    'raw_request', 'raw request', 'raw_response', 'raw response',
    'raw_body', 'raw body', 'raw_headers', 'raw headers', 'raw payload',
    'raw command', 'raw output', 'raw tool output', 'stack trace', 'error:',
    'confirmed vulnerability', 'critical severity', 'target is vulnerable',
    'exploitable', 'vulnerable', 'exploit', 'sqli', 'idor', 'bola', 'auth bypass'
  ];
  for (const f of forbidden) {
    if (t.includes(f)) {
      return true;
    }
  }
  return false;
}

function validateSafeId(id: any, maxLen = 128): { isValid: boolean, errorCode: AuthorizedComparisonValidationReasonCode, message: string } {
  if (!id || typeof id !== 'string' || id.length === 0 || id.length > maxLen) {
    return { isValid: false, errorCode: 'invalid_validation_metadata', message: 'ID invalid length or missing' };
  }
  if (!/^[a-zA-Z0-9_\-=]+$/.test(id)) {
    return { isValid: false, errorCode: 'invalid_validation_metadata', message: 'ID invalid shape' };
  }
  if (hasForbiddenContent(id)) {
    return { isValid: false, errorCode: 'invalid_validation_metadata', message: 'ID contains forbidden words' };
  }
  return { isValid: true, errorCode: 'invalid_validation_metadata', message: '' };
}

function validateIsoTimestamp(ts: any): { isValid: boolean } {
  if (!ts || typeof ts !== 'string') return { isValid: false };
  const r = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
  if (!r.test(ts)) return { isValid: false };
  if (isNaN(Date.parse(ts))) return { isValid: false };
  return { isValid: true };
}

function validateValidationRequest(req: any): { isValid: boolean, errorCode: AuthorizedComparisonValidationReasonCode, message: string } {
  if (!req || typeof req !== 'object') {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Request must be an object' };
  }
  if (req.contractVersion !== AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION) {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Invalid contractVersion' };
  }
  if (req.kind !== "authorized_comparison_validation_request") {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Invalid kind' };
  }
  
  if (!validateIsoTimestamp(req.requestedAt).isValid) {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Invalid requestedAt' };
  }

  const allowedTopKeys = new Set([
    "contractVersion", "kind", "validationId", "scanId", "requestedAt", "scopeGrant", "scopeActionRequest",
    "baselineSnapshot", "validationSnapshot", "comparisonMode", "comparisonThresholds", "mappingMode", "reviewerPolicy", "classification",
    "verifiedAuthorizationDecision", "lineageRef"
  ]);
  for (const k of Object.keys(req)) {
    if (!allowedTopKeys.has(k)) {
      return { isValid: false, errorCode: 'invalid_validation_request', message: 'Unknown request field' };
    }
  }

  if (!req.classification || typeof req.classification !== 'object') {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Missing classification' };
  }
  
  const classKeys = new Set(["createsRealFindings", "createsPersistedEvidence", "confirmsVulnerabilities", "makesRiskClaims", "makesSeverityClaims", "makesImpactClaims", "executesNetwork", "executesTools", "persistsData"]);
  for (const k of Object.keys(req.classification)) {
    if (!classKeys.has(k)) {
      return { isValid: false, errorCode: 'invalid_validation_request', message: 'Unknown classification field' };
    }
  }
  
  for (const k of classKeys) {
    if (req.classification[k] !== false) {
      return { isValid: false, errorCode: 'invalid_validation_request', message: 'Classification flags must be false' };
    }
  }

  if (!req.reviewerPolicy || typeof req.reviewerPolicy !== 'object') {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Missing reviewerPolicy' };
  }
  
  const policyKeys = new Set(["requireHumanReview", "allowAutoEvidenceRecord", "allowFindingCandidateCreation", "allowPersistence", "allowExternalDelivery"]);
  for (const k of Object.keys(req.reviewerPolicy)) {
    if (!policyKeys.has(k)) {
      return { isValid: false, errorCode: 'invalid_validation_request', message: 'Unknown nested field' };
    }
  }
  
  if (req.reviewerPolicy.requireHumanReview !== true ||
      req.reviewerPolicy.allowAutoEvidenceRecord !== false ||
      req.reviewerPolicy.allowFindingCandidateCreation !== false ||
      req.reviewerPolicy.allowPersistence !== false ||
      req.reviewerPolicy.allowExternalDelivery !== false) {
    return { isValid: false, errorCode: 'blocked_policy_not_review_safe', message: 'Unsafe reviewerPolicy' };
  }

  const validComparisonModes = new Set(["http_difference", "authorization_difference", "time_based_difference", "generic_signal_comparison"]);
  if (!validComparisonModes.has(req.comparisonMode)) {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Invalid comparisonMode' };
  }

  const validMappingModes = new Set(["http_difference_to_evidence", "authorization_difference_to_evidence", "time_based_signal_to_evidence", "manual_review_note"]);
  if (!validMappingModes.has(req.mappingMode)) {
    return { isValid: false, errorCode: 'invalid_validation_request', message: 'Invalid mappingMode' };
  }

  return { isValid: true, errorCode: 'invalid_validation_metadata', message: '' };
}

export function validateEvidenceDraftEnvelopeForValidationResult(draft: any): boolean {
  if (!draft || typeof draft !== 'object') return false;

  const validDraftKinds = new Set(["non_persisted_comparison_evidence_draft"]);
  const validEvTypes = new Set(["http_difference", "authorization_difference", "time_based_difference", "manual_review_note"]);
  const validStr = new Set(["weak", "moderate", "strong"]);

  const allowedDraftKeys = new Set([
    "draftKind", "draftId", "suggestedEvidenceType", "suggestedStrength", "sourceComparisonId", "sourceSnapshotIds",
    "requiresHumanReview", "notPersisted", "notARealFinding", "notConfirmedEvidence", "notForExternalDelivery", "notM45EvidenceRecord", "safeRationale"
  ]);

  for (const k of Object.keys(draft)) {
    if (!allowedDraftKeys.has(k)) return false;
  }

  if (
    !validDraftKinds.has(draft.draftKind) ||
    !validateSafeId(draft.draftId).isValid ||
    !validEvTypes.has(draft.suggestedEvidenceType) ||
    !validStr.has(draft.suggestedStrength) ||
    !validateSafeId(draft.sourceComparisonId).isValid ||
    draft.requiresHumanReview !== true ||
    draft.notPersisted !== true ||
    draft.notARealFinding !== true ||
    draft.notConfirmedEvidence !== true ||
    draft.notForExternalDelivery !== true ||
    draft.notM45EvidenceRecord !== true ||
    hasForbiddenContent(draft.safeRationale)
  ) {
    return false;
  }

  if (!draft.sourceSnapshotIds || typeof draft.sourceSnapshotIds !== 'object') return false;
  
  const snapKeys = Object.keys(draft.sourceSnapshotIds);
  if (snapKeys.length !== 2 || !snapKeys.includes('baselineSnapshotId') || !snapKeys.includes('validationSnapshotId')) {
    return false;
  }
  
  if (!validateSafeId(draft.sourceSnapshotIds.baselineSnapshotId).isValid ||
      !validateSafeId(draft.sourceSnapshotIds.validationSnapshotId).isValid) {
    return false;
  }

  return true;
}

export function runAuthorizedComparisonValidation(request: any, evaluatedAt: any): AuthorizedComparisonValidationResult {
  try {
    const val = validateValidationRequest(request);
    if (!val.isValid) {
      if (val.errorCode === 'blocked_policy_not_review_safe') {
        // Safe metadata sentinels for early block
        return buildBlockedResult(
          validateSafeId(request?.validationId, 100).isValid ? request.validationId : 'invalid_validation_id',
          validateSafeId(request?.scanId).isValid ? request.scanId : 'invalid_scan_id',
          validateIsoTimestamp(evaluatedAt).isValid ? evaluatedAt : '1970-01-01T00:00:00.000Z',
          'blocked_policy_not_review_safe'
        );
      }
      return buildSafeFailure(
        validateSafeId(request?.validationId, 100).isValid ? request.validationId : 'invalid_validation_id',
        validateSafeId(request?.scanId).isValid ? request.scanId : 'invalid_scan_id',
        validateIsoTimestamp(evaluatedAt).isValid ? evaluatedAt : '1970-01-01T00:00:00.000Z',
        val.errorCode,
        val.message
      );
    }
    
    let safeValidationId = request.validationId;
    let safeScanId = request.scanId;
    let safeEval = evaluatedAt;

    if (!validateSafeId(request.validationId, 100).isValid) { safeValidationId = 'invalid_validation_id'; }
    if (!validateSafeId(request.scanId).isValid) { safeScanId = 'invalid_scan_id'; }
    if (!validateIsoTimestamp(evaluatedAt).isValid) { safeEval = '1970-01-01T00:00:00.000Z'; }

    if (safeValidationId === 'invalid_validation_id' || safeScanId === 'invalid_scan_id' || safeEval === '1970-01-01T00:00:00.000Z') {
      return buildSafeFailure(safeValidationId, safeScanId, safeEval, 'invalid_validation_metadata', 'Invalid metadata IDs or timestamp');
    }

    const derivedScopeDecisionId = `${safeValidationId}_scope`;
    const derivedComparisonId = `${safeValidationId}_comparison`;
    const derivedMappingId = `${safeValidationId}_mapping`;

    if (!validateSafeId(derivedScopeDecisionId).isValid || !validateSafeId(derivedComparisonId).isValid || !validateSafeId(derivedMappingId).isValid) {
      return buildSafeFailure(safeValidationId, safeScanId, safeEval, 'invalid_validation_metadata', 'Derived IDs exceed safe limits or are invalid');
    }

    const req = request as AuthorizedComparisonValidationRequest;

    let provenance: AuthorizedComparisonValidationProvenance | undefined = undefined;

    if (req.verifiedAuthorizationDecision !== undefined) {
      if (!isRuntimeEstablishedVerifiedAuthorizationDecision(req.verifiedAuthorizationDecision) ||
          req.verifiedAuthorizationDecision.decision !== 'authorized') {
        return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_authorization_invalid');
      }

      if (req.verifiedAuthorizationDecision.scanId !== safeScanId ||
          req.verifiedAuthorizationDecision.scopeGrant?.grantId !== req.scopeGrant?.grantId) {
        return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_lineage_mismatch');
      }

      if (req.lineageRef !== undefined) {
        if (req.lineageRef.scanId !== safeScanId ||
            req.lineageRef.authorizationDecisionId !== req.verifiedAuthorizationDecision.authorizationDecisionId ||
            req.lineageRef.authorizationGrantId !== req.verifiedAuthorizationDecision.authorizationGrantId) {
          return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_lineage_mismatch');
        }
      }

      const authLineage = deriveAuthorizationLineageRef(req.verifiedAuthorizationDecision);
      provenance = {
        authorizationDecisionId: authLineage.authorizationDecisionId,
        authorizationGrantId: authLineage.authorizationGrantId,
        assessmentId: authLineage.assessmentId,
        scanId: authLineage.scanId,
        actorId: authLineage.actorId,
      };
    } else if (req.lineageRef !== undefined) {
      return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_lineage_mismatch');
    }

    const allowedActionKinds = new Set(["light_validation", "active_validation", "authenticated_probe"]);
    if (!req.scopeActionRequest || !allowedActionKinds.has(req.scopeActionRequest.actionKind)) {
      return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_scope_invalid', undefined, undefined, undefined, provenance);
    }

    // Call M46
    const scopeRes = evaluateScopePolicy({
      grant: req.scopeGrant,
      request: req.scopeActionRequest,
      decisionId: derivedScopeDecisionId,
      evaluatedAt: safeEval
    });

    const scopeSummary: ScopeDecisionSummary = {
      decision: scopeRes.decision,
      reasonCode: hasForbiddenContent(scopeRes.reasonCode) ? 'invalid' : scopeRes.reasonCode,
      matchedPermission: scopeRes.matchedPermission && !hasForbiddenContent(scopeRes.matchedPermission) ? scopeRes.matchedPermission : undefined
    };
    
    if (scopeRes.decision !== 'allowed') {
      return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_scope_denied', scopeSummary, undefined, undefined, provenance);
    }

    // Call M47
    const m47Req: ResponseComparisonRequest = {
      contractVersion: "fixguard-response-comparator/v0",
      kind: "response_comparison_request",
      comparisonId: derivedComparisonId,
      scanId: safeScanId,
      requestedAt: req.requestedAt,
      baseline: req.baselineSnapshot,
      validation: req.validationSnapshot,
      comparisonMode: req.comparisonMode,
      thresholds: req.comparisonThresholds,
      classification: getSafeClassification()
    };
    const compRes = compareResponses(m47Req, safeEval);

    if (compRes.status === 'failed') {
      return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_comparison_failed', scopeSummary, undefined, undefined, provenance);
    }

    const compSummary: ComparisonSummary = {
      status: compRes.status,
      comparisonId: compRes.comparisonId,
      strongestSignal: compRes.significance?.strongestSignal || "none",
      comparisonSignalStrength: compRes.significance?.comparisonSignalStrength || "none",
      suggestedEvidenceType: compRes.evidenceMappingHint?.suggestedEvidenceType || "manual_review_note"
    };

    // Call M48
    const m48Req: ComparisonEvidenceMappingRequest = {
      contractVersion: "fixguard-comparison-evidence-mapping/v0",
      kind: "comparison_evidence_mapping_request",
      mappingId: derivedMappingId,
      scanId: safeScanId,
      requestedAt: req.requestedAt,
      sourceComparisonMode: req.comparisonMode,
      mappingMode: req.mappingMode,
      sourceComparison: compRes,
      reviewerPolicy: req.reviewerPolicy,
      classification: getSafeClassification()
    };

    const mapRes = mapComparisonToEvidence(m48Req, safeEval);

    const mapSummary: MappingSummary = {
      status: mapRes.status,
      reasonCode: hasForbiddenContent(mapRes.reasonCode) ? 'invalid' : mapRes.reasonCode,
      mappedEvidenceType: mapRes.mappedEvidenceType,
      mappedSignalStrength: mapRes.mappedSignalStrength
    };

    if (mapRes.status === 'blocked') {
      return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_mapping_blocked', scopeSummary, compSummary, mapSummary, provenance);
    }
    if (mapRes.status === 'failed') {
      return buildSafeFailure(safeValidationId, safeScanId, safeEval, 'failed_mapping_failed', 'Mapping failed');
    }
    if (mapRes.status === 'needs_more_review') {
      return {
        contractVersion: AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION,
        kind: "authorized_comparison_validation_result",
        validationId: safeValidationId,
        scanId: safeScanId,
        evaluatedAt: safeEval,
        status: "needs_more_review",
        reasonCode: "needs_more_review_from_mapping",
        scopeDecisionSummary: scopeSummary,
        comparisonSummary: compSummary,
        mappingSummary: mapSummary,
        ...(provenance ? { provenance } : {}),
        explicitNonClaims: getSafeNonClaims(),
        classification: getSafeClassification()
      };
    }

    if (mapRes.status === 'draft_ready') {
      const draft = mapRes.evidenceDraft;
      if (!draft || typeof draft !== 'object') {
        return buildSafeFailure(safeValidationId, safeScanId, safeEval, 'failed_mapping_failed', 'Invalid draft envelope');
      }

      if (!validateEvidenceDraftEnvelopeForValidationResult(draft)) {
        return buildBlockedResult(safeValidationId, safeScanId, safeEval, 'blocked_mapping_blocked', scopeSummary, compSummary, mapSummary, provenance);
      }

      return {
        contractVersion: AUTHORIZED_COMPARISON_VALIDATION_CONTRACT_VERSION,
        kind: "authorized_comparison_validation_result",
        validationId: safeValidationId,
        scanId: safeScanId,
        evaluatedAt: safeEval,
        status: "completed",
        reasonCode: "completed_with_evidence_draft",
        scopeDecisionSummary: scopeSummary,
        comparisonSummary: compSummary,
        mappingSummary: mapSummary,
        evidenceDraft: draft,
        ...(provenance ? { provenance } : {}),
        explicitNonClaims: getSafeNonClaims(),
        classification: getSafeClassification()
      };
    }

    return buildSafeFailure(safeValidationId, safeScanId, safeEval, 'unexpected_validation_failure', 'Unexpected status');
  } catch (err) {
    return buildSafeFailure('invalid_validation_id', 'invalid_scan_id', '1970-01-01T00:00:00.000Z', 'unexpected_validation_failure', 'Unexpected error');
  }
}
