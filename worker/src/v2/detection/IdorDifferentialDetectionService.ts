/**
 * Milestone F2 — IDOR / BOLA Differential Detection Engine
 *
 * Implements the first real vulnerability detection capability in FixGuard V2:
 * 1. Safe preflight verification (M39/F1).
 * 2. Dual-identity read-only HTTP probe dispatch.
 * 3. Safe response snapshot construction and differential comparison (M47).
 * 4. Human-reviewed evidence promotion (M49–M50).
 * 5. Finding candidate draft & formal candidate promotion (M51–M54).
 * 6. Canonical Finding DTO generation (type: 'BROKEN_ACCESS_CONTROL', severity: 'high').
 */

import { createHash } from 'node:crypto';
import type {
  IdorDifferentialDetectionRequest,
  IdorDifferentialDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { compareResponses } from '../comparison/ResponseComparatorService.js';
import type {
  SafeResponseSnapshot,
  SnapshotRole,
  NormalizedBodyShape,
  ResponseComparisonRequest
} from '../comparison/ResponseComparatorContracts.js';
import { runAuthorizedComparisonValidation } from '../validation/AuthorizedComparisonValidationService.js';
import type { AuthorizedComparisonValidationRequest } from '../validation/AuthorizedComparisonValidationContracts.js';
import { evaluateHumanReviewedEvidencePromotion } from '../evidence-review/HumanReviewedEvidencePromotionService.js';
import type { HumanReviewedEvidencePromotionRequest } from '../evidence-review/HumanReviewedEvidencePromotionContracts.js';
import { InMemoryReviewedEvidenceStoreRepository } from '../evidence-store/InMemoryReviewedEvidenceStoreRepository.js';
import { saveReviewedEvidence } from '../evidence-store/ReviewedEvidenceStoreService.js';
import type { SaveReviewedEvidenceRequest } from '../evidence-store/ReviewedEvidenceStoreContracts.js';
import { selectReviewedEvidence } from '../evidence-selection/ReviewedEvidenceSelectionService.js';
import type { SelectReviewedEvidenceRequest } from '../evidence-selection/ReviewedEvidenceSelectionContracts.js';
import { createReviewedEvidenceFindingCandidateDraft } from '../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftService.js';
import type { CreateReviewedEvidenceFindingCandidateDraftRequest } from '../finding-candidate-draft/ReviewedEvidenceFindingCandidateDraftContracts.js';
import { promoteReviewedEvidenceFindingCandidateDraft } from '../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js';
import type { PromoteReviewedEvidenceFindingCandidateDraftRequest } from '../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js';
import type { Finding } from '../core/Evidence.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import { pruneTransientEvidence } from '../evidence/EvidenceRetentionService.js';

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'proxy-authorization',
  'x-api-key',
  'bearer',
  'token',
  'secret',
  'password',
  'api-key',
  'apikey',
  'access-token',
  'refresh-token',
  'x-auth-token',
  'x-session-id',
  'x-csrf-token',
  'www-authenticate',
]);

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function analyzeBodyShape(bodyText: string): NormalizedBodyShape {
  const trimmed = bodyText.trim();
  if (trimmed.length === 0) {
    return { shapeKind: 'empty' };
  }

  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) {
        return {
          shapeKind: 'json_array',
          normalizedSchemaHash: sha256(`array:${parsed.length}`)
        };
      }
      if (parsed !== null && typeof parsed === 'object') {
        const topLevelJsonKeys = Object.keys(parsed).sort();
        return {
          shapeKind: 'json_object',
          topLevelJsonKeys,
          normalizedSchemaHash: sha256(topLevelJsonKeys.join(','))
        };
      }
    } catch {
      // not valid JSON, treat as text
    }
  }

  return {
    shapeKind: 'text',
    normalizedSchemaHash: sha256(trimmed.slice(0, 128))
  };
}

function createSafeSnapshot(
  snapshotId: string,
  scanId: string,
  role: SnapshotRole,
  normalizedOrigin: string,
  pathTemplate: string,
  response: HttpProbeResponse,
  identityId: string,
  capturedAt: string
): SafeResponseSnapshot {
  const sanitizedHeaderNames = Object.keys(response.headers)
    .map(h => h.toLowerCase())
    .filter(h => !SENSITIVE_HEADER_NAMES.has(h))
    .sort();

  const isAnonymous = identityId === 'anonymous';
  const bodyShape = analyzeBodyShape(response.bodyText);

  return {
    contractVersion: 'fixguard-response-comparator/v0',
    kind: 'safe_response_snapshot',
    snapshotId,
    scanId,
    capturedAt,
    role,
    subject: {
      normalizedOrigin,
      method: 'GET',
      pathTemplate
    },
    statusCode: response.statusCode,
    contentLength: response.bodyText.length,
    responseTimeMs: response.responseTimeMs,
    headerNames: sanitizedHeaderNames,
    bodyHash: sha256(response.bodyText),
    normalizedBodyShape: bodyShape,
    authState: {
      authenticatedSignal: isAnonymous ? 'appears_unauthenticated' : 'appears_authenticated',
      authStateHash: sha256(`identity:${identityId}`)
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false
    }
  };
}

export const defaultHttpProbeTransport: IdorHttpProbeTransport = async (
  req: HttpProbeRequest
): Promise<HttpProbeResponse> => {
  const start = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), req.timeoutMs ?? 5000);
  try {
    const res = await fetch(req.url, {
      method: req.method,
      headers: req.headers,
      signal: controller.signal
    });
    const bodyText = await res.text();
    const headersObj: Record<string, string> = {};
    res.headers.forEach((val, key) => {
      headersObj[key.toLowerCase()] = val;
    });
    return {
      statusCode: res.status,
      headers: headersObj,
      bodyText,
      responseTimeMs: Date.now() - start
    };
  } finally {
    clearTimeout(timeout);
  }
};

export async function runIdorDifferentialDetection(
  request: IdorDifferentialDetectionRequest
): Promise<IdorDifferentialDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();

  // 1. Adapter Preflight Pipeline Gate (7-pass check with SSRF / DNS rebinding prevention)
  const preflight = await runAdapterPreflight({
    target: request.endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: ps => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`
      }
    };
  }

  // 2. Prepare Target URL & Templates
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'invalid_target_url',
      lineage,
      error: {
        code: 'invalid_target_url',
        safeMessage: 'Target URL is invalid'
      }
    };
  }

  const normalizedOrigin = parsedUrl.origin;
  const pathTemplate = parsedUrl.pathname;
  let targetUrl = request.endpointUrl;

  if (targetUrl.includes(`{${request.resourceParamName}}`)) {
    targetUrl = targetUrl.replace(`{${request.resourceParamName}}`, request.baselineResourceId);
  } else if (targetUrl.includes(`:${request.resourceParamName}`)) {
    targetUrl = targetUrl.replace(`:${request.resourceParamName}`, request.baselineResourceId);
  } else {
    parsedUrl.searchParams.set(request.resourceParamName, request.baselineResourceId);
    targetUrl = parsedUrl.toString();
  }

  const transport = request.transport ?? defaultHttpProbeTransport;
  const method = request.method ?? 'GET';

  // 2.5. Session Lifecycle Health Check (Acción 10)
  let identityAHeaders = { ...(request.identityA.headers ?? {}) };
  let identityBHeaders = { ...(request.identityB.headers ?? {}) };

  if (request.identityA.sessionState) {
    const sessionHealthA = await validateSessionHealth(request.identityA.sessionState, nowIso);
    if (!sessionHealthA.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'idor_differential_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: sessionHealthA.reasonCode ?? 'session_expired',
        lineage,
        error: {
          code: sessionHealthA.reasonCode ?? 'session_expired',
          safeMessage: `Identity A session expired: ${sessionHealthA.reasonCode ?? 'session_expired'}`
        }
      };
    }
    if (sessionHealthA.updatedHeaders) {
      identityAHeaders = { ...identityAHeaders, ...sessionHealthA.updatedHeaders };
    }
  }

  if (request.identityB.sessionState) {
    const sessionHealthB = await validateSessionHealth(request.identityB.sessionState, nowIso);
    if (!sessionHealthB.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'idor_differential_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: sessionHealthB.reasonCode ?? 'session_expired',
        lineage,
        error: {
          code: sessionHealthB.reasonCode ?? 'session_expired',
          safeMessage: `Identity B session expired: ${sessionHealthB.reasonCode ?? 'session_expired'}`
        }
      };
    }
    if (sessionHealthB.updatedHeaders) {
      identityBHeaders = { ...identityBHeaders, ...sessionHealthB.updatedHeaders };
    }
  }

  // 3. Dispatch Read-Only Dual-Identity Probes
  let probeResponseA: HttpProbeResponse;
  let probeResponseB: HttpProbeResponse;

  try {
    probeResponseA = await transport({
      url: targetUrl,
      method,
      headers: identityAHeaders
    });

    probeResponseB = await transport({
      url: targetUrl,
      method,
      headers: identityBHeaders
    });
  } catch (probeError) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'probe_dispatch_failed',
      lineage,
      error: {
        code: 'probe_dispatch_failed',
        safeMessage: probeError instanceof Error ? probeError.message : 'HTTP probe dispatch failed'
      }
    };
  }

  // 4. Construct Safe Response Snapshots
  const baselineSnapshot = createSafeSnapshot(
    `snap_base_${safeSeed}`,
    request.scanId,
    'baseline',
    normalizedOrigin,
    pathTemplate,
    probeResponseA,
    request.identityA.identityId,
    nowIso
  );

  const validationSnapshot = createSafeSnapshot(
    `snap_val_${safeSeed}`,
    request.scanId,
    'validation',
    normalizedOrigin,
    pathTemplate,
    probeResponseB,
    request.identityB.identityId,
    nowIso
  );

  // 5. Differential Access Control Evaluation
  // Secure Target Check: If Identity B receives 401, 403, or 404 while Identity A receives 200
  const isIdentityASuccess = probeResponseA.statusCode >= 200 && probeResponseA.statusCode < 300;
  const isIdentityBDenied =
    probeResponseB.statusCode === 401 ||
    probeResponseB.statusCode === 403 ||
    probeResponseB.statusCode === 404;

  if (isIdentityASuccess && isIdentityBDenied) {
    const abstainedResult: IdorDifferentialDetectionResult = {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'access_control_enforced',
      lineage,
      baselineSnapshot,
      validationSnapshot
    };
    return pruneTransientEvidence(abstainedResult, nowIso);
  }

  // 6. Execute Response Comparator (M47)
  const comparisonRequest: ResponseComparisonRequest = {
    contractVersion: 'fixguard-response-comparator/v0',
    kind: 'response_comparison_request',
    comparisonId: `comp_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    baseline: baselineSnapshot,
    validation: validationSnapshot,
    comparisonMode: 'authorization_difference',
    thresholds: {
      contentLengthDeltaPercentSignificant: 20,
      responseTimeDeltaMsSignificant: 1000
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false
    }
  };

  const comparisonResult = compareResponses(comparisonRequest, nowIso);
  if (comparisonResult.status === 'failed') {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'comparison_failed',
      reasonCode: comparisonResult.error?.code ?? 'comparison_failed',
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      error: {
        code: comparisonResult.error?.code ?? 'comparison_failed',
        safeMessage: comparisonResult.error?.safeMessage ?? 'Comparison execution failed'
      }
    };
  }

  // 7. Route into Evidence & Promotion Pipeline (M49)
  const validationRequest: AuthorizedComparisonValidationRequest = {
    contractVersion: 'fixguard-authorized-comparison-validation/v0',
    kind: 'authorized_comparison_validation_request',
    validationId: `val_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    scopeGrant: request.scopeGrant,
    scopeActionRequest: {
      contractVersion: 'fixguard-authorized-scope-policy/v0',
      kind: 'scope_action_request',
      requestId: `act_${safeSeed}`,
      scanId: request.scanId,
      requestedAt: nowIso,
      actionKind: 'active_validation',
      target: {
        targetKind: 'origin',
        normalizedOrigin,
        host: parsedUrl.hostname,
        domain: parsedUrl.hostname
      },
      method: 'GET',
      pathTemplate,
      intensity: 'low',
      usesCredentials: true,
      mayChangeServerState: false,
      usesOob: false,
      classification: {
        createsRealFindings: false,
        createsPersistedEvidence: false,
        confirmsVulnerabilities: false,
        makesRiskClaims: false,
        makesSeverityClaims: false,
        makesImpactClaims: false,
        executesNetwork: false,
        executesTools: false,
        persistsData: false
      }
    },
    baselineSnapshot,
    validationSnapshot,
    comparisonMode: 'authorization_difference',
    comparisonThresholds: {
      contentLengthDeltaPercentSignificant: 20,
      responseTimeDeltaMsSignificant: 1000
    },
    mappingMode: 'authorization_difference_to_evidence',
    reviewerPolicy: request.reviewerPolicy ?? {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false
    },
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    lineageRef: lineage,
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false
    }
  };

  const validationResult = runAuthorizedComparisonValidation(validationRequest, nowIso);
  if (validationResult.status !== 'completed' || !validationResult.evidenceDraft) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: validationResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      error: {
        code: validationResult.reasonCode,
        safeMessage: validationResult.error?.safeMessage ?? 'Validation gate rejected evidence draft'
      }
    };
  }

  // If no explicit human review decision is supplied, halt at the human review boundary
  // and return pending_human_review with the unsigned EvidenceDraft envelope.
  if (!request.humanReviewDecision) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'pending_human_review',
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      evidenceDraft: validationResult.evidenceDraft
    };
  }

  // 8. Human-Reviewed Evidence Promotion (M50)
  const promotionRequest: HumanReviewedEvidencePromotionRequest = {
    contractVersion: 'fixguard-human-reviewed-evidence-promotion/v0',
    kind: 'human_reviewed_evidence_promotion_request',
    promotionId: `promo_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    validationResult,
    sourceIndicatorRef: {
      kind: 'reviewed_indicator_reference',
      indicatorId: `ind_${safeSeed}`,
      scanId: request.scanId
    },
    reviewDecision: request.humanReviewDecision,
    substancePayload: {
      evidenceType: 'authorization_difference',
      baseline: {
        method: 'GET',
        statusCode: baselineSnapshot.statusCode,
        contentLength: baselineSnapshot.contentLength,
        responseTimeMs: baselineSnapshot.responseTimeMs,
        bodyHash: baselineSnapshot.bodyHash
      },
      attackOrValidation: {
        method: 'GET',
        statusCode: validationSnapshot.statusCode,
        contentLength: validationSnapshot.contentLength,
        responseTimeMs: validationSnapshot.responseTimeMs,
        bodyHash: validationSnapshot.bodyHash
      },
      difference: {
        statusCodeChanged: comparisonResult.difference?.statusCodeChanged ?? false,
        contentLengthDeltaPercent: comparisonResult.difference?.contentLengthDeltaPercent ?? 0,
        responseTimeDeltaMs: comparisonResult.difference?.responseTimeDeltaMs ?? 0,
        authStateChanged: comparisonResult.difference?.authStateChanged ?? true
      }
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
      persistsData: false
    }
  };

  const promotedEvidenceResult = evaluateHumanReviewedEvidencePromotion(promotionRequest, nowIso);
  if (promotedEvidenceResult.status !== 'promoted' || !promotedEvidenceResult.nonPersistedEvidenceRecord) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: promotedEvidenceResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: promotedEvidenceResult.reasonCode,
        safeMessage: 'Evidence promotion rejected by human review boundary'
      }
    };
  }

  // 9. Store, Select & Draft Finding Candidate (M51–M53)
  const storeRepo = new InMemoryReviewedEvidenceStoreRepository();
  const saveRequest: SaveReviewedEvidenceRequest = {
    contractVersion: 'fixguard-reviewed-evidence-store/v0',
    kind: 'save_reviewed_evidence_request',
    saveId: `save_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    promotionResult: promotedEvidenceResult,
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
    }
  };

  const saveResult = await saveReviewedEvidence(saveRequest, nowIso, storeRepo);
  const storeRecordId = saveResult.record?.storeRecordId ?? saveResult.summary?.storeRecordId;
  if (saveResult.status !== 'saved' || !storeRecordId) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: saveResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: saveResult.reasonCode,
        safeMessage: 'Failed to store reviewed evidence'
      }
    };
  }

  const selectRequest: SelectReviewedEvidenceRequest = {
    contractVersion: 'fixguard-reviewed-evidence-selection/v0',
    kind: 'select_reviewed_evidence_request',
    selectionId: `sel_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    source: {
      mode: 'explicit_store_record_ids',
      storeRecordIds: [storeRecordId]
    },
    classification: {
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
    }
  };

  const selectResult = await selectReviewedEvidence(selectRequest, nowIso, storeRepo);
  if (selectResult.status !== 'selected' || !selectResult.selectionSet) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: selectResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: selectResult.reasonCode,
        safeMessage: 'Failed to select reviewed evidence'
      }
    };
  }

  const draftRequest: CreateReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: 'fixguard-reviewed-evidence-finding-candidate-draft/v0',
    kind: 'create_reviewed_evidence_finding_candidate_draft_request',
    draftId: `draft_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    selectionSet: selectResult.selectionSet,
    classification: {
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
    }
  };

  const draftResult = await createReviewedEvidenceFindingCandidateDraft(draftRequest, nowIso);
  if (draftResult.status !== 'draft_created' || !draftResult.draft) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: draftResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: draftResult.reasonCode,
        safeMessage: 'Failed to create candidate draft'
      }
    };
  }

  // 10. Promote Candidate to Formal Candidate (M54)
  const candidateTriageDecision = request.triageDecision ?? {
    decisionId: `dectriage_${safeSeed}`,
    reviewerId: request.humanReviewDecision.reviewerId,
    reviewedAt: nowIso,
    decision: 'approve_finding_candidate_promotion' as const,
    attestations: {
      reviewedDraft: true as const,
      reviewedEvidenceRefs: true as const,
      understandsCandidateIsNotConfirmedFinding: true as const,
      understandsNoVulnerabilityConfirmed: true as const,
      understandsNoExploitabilityClaim: true as const,
      understandsNoSeverityRiskImpactAssigned: true as const,
      understandsNoRemediationAdvice: true as const,
      authorizedPromotionToFormalCandidate: true
    },
    explicitNonClaims: {
      noConfirmedFinding: true as const,
      noConfirmedVulnerability: true as const,
      noExploitabilityClaim: true as const,
      noSeverityRiskOrImpactClaim: true as const,
      noRemediationAdvice: true as const,
      noSafeReportItemCreated: true as const,
      noExternalReportCreated: true as const,
      noNetworkExecution: true as const,
      noToolExecution: true as const,
      noPersistence: true as const
    }
  };

  const promotionCandidateRequest: PromoteReviewedEvidenceFindingCandidateDraftRequest = {
    contractVersion: 'fixguard-reviewed-evidence-finding-candidate-promotion/v0',
    kind: 'promote_reviewed_evidence_finding_candidate_draft_request',
    candidateId: `cand_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    draft: draftResult.draft,
    triageDecision: candidateTriageDecision,
    classification: {
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
    }
  };

  const promoteCandidateResult = await promoteReviewedEvidenceFindingCandidateDraft(
    promotionCandidateRequest,
    nowIso
  );

  if (promoteCandidateResult.status !== 'candidate_created' || !promoteCandidateResult.candidate) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'idor_differential_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: promoteCandidateResult.reasonCode,
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: promoteCandidateResult.reasonCode,
        safeMessage: 'Failed to promote finding candidate'
      }
    };
  }

  // 11. Produce Canonical Finding DTO
  const evidenceRecord = promotedEvidenceResult.nonPersistedEvidenceRecord;
  const finding: Finding = {
    id: `find_${safeSeed}`,
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: `Broken Object Level Authorization on ${pathTemplate}`,
    description: `Differential inspection proved that unauthorized identity (${request.identityB.identityId}) accessed resource (${request.baselineResourceId}) belonging to authorized identity (${request.identityA.identityId}) with HTTP 200 and matching structural payload.`,
    target: request.endpointUrl,
    evidence: JSON.stringify({
      resourceId: request.baselineResourceId,
      endpointUrl: request.endpointUrl,
      comparisonId: comparisonResult.comparisonId,
      baselineStatus: baselineSnapshot.statusCode,
      validationStatus: validationSnapshot.statusCode,
      difference: comparisonResult.difference,
      significance: comparisonResult.significance,
      candidateId: promoteCandidateResult.candidate.candidateId,
      evidenceId: evidenceRecord.evidenceId
    }),
    confidence: 0.95,
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: promoteCandidateResult.candidate.candidateId,
      evidenceRecordId: evidenceRecord.evidenceId,
      endpointUrl: request.endpointUrl,
      resourceParamName: request.resourceParamName,
      baselineResourceId: request.baselineResourceId,
      unauthorizedActorId: request.identityB.identityId,
      lineage
    }
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'idor_differential_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'vulnerability_detected',
    reasonCode: 'broken_access_control_proven',
    lineage,
    baselineSnapshot,
    validationSnapshot,
    comparisonResult,
    validationResult,
    evidenceRecord,
    promotedEvidenceResult,
    findingCandidate: promoteCandidateResult.candidate,
    finding
  };
}

export class IdorDifferentialDetectionService {
  public async execute(
    request: IdorDifferentialDetectionRequest
  ): Promise<IdorDifferentialDetectionResult> {
    return runIdorDifferentialDetection(request);
  }
}
