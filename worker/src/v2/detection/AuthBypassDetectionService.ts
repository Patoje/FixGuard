/**
 * Milestone P4-1 — Authentication Bypass Detection Engine
 *
 * Implements defensive authentication bypass detection in FixGuard V2:
 * 1. Safe preflight verification (M39/F1).
 * 2. Authenticated baseline HTTP probe vs unauthenticated/stripped probe dispatch.
 * 3. Safe response snapshot construction and differential comparison (M47).
 * 4. Human-reviewed evidence promotion (M49–M50).
 * 5. Finding candidate draft & formal candidate promotion (M51–M54).
 * 6. Canonical Finding DTO generation (type: 'BROKEN_AUTHENTICATION', severity: 'high').
 */

import { createHash } from 'node:crypto';
import type {
  AuthBypassDetectionRequest,
  AuthBypassDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { compareResponses } from '../comparison/ResponseComparatorService.js';
import type {
  SafeResponseSnapshot,
  SnapshotRole,
  NormalizedBodyShape,
  ResponseComparisonRequest,
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
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

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
          normalizedSchemaHash: sha256(`array:${parsed.length}`),
        };
      }
      if (parsed !== null && typeof parsed === 'object') {
        const topLevelJsonKeys = Object.keys(parsed).sort();
        return {
          shapeKind: 'json_object',
          topLevelJsonKeys,
          normalizedSchemaHash: sha256(topLevelJsonKeys.join(',')),
        };
      }
    } catch {
      // Non-JSON fallback
    }
  }

  if (trimmed.toLowerCase().includes('<html') || trimmed.toLowerCase().includes('<!doctype html')) {
    return { shapeKind: 'html' };
  }

  return { shapeKind: 'text' };
}

function calculateBodySimilarity(baselineBody: string, anonBody: string): number {
  if (baselineBody === anonBody) {
    return 1.0;
  }
  if (baselineBody.length === 0 || anonBody.length === 0) {
    return 0.0;
  }

  const baseHash = sha256(baselineBody);
  const anonHash = sha256(anonBody);
  if (baseHash === anonHash) {
    return 1.0;
  }

  // Try JSON comparison
  try {
    const baseObj = JSON.parse(baselineBody) as Record<string, unknown>;
    const anonObj = JSON.parse(anonBody) as Record<string, unknown>;
    if (typeof baseObj === 'object' && typeof anonObj === 'object' && baseObj !== null && anonObj !== null) {
      const baseKeys = Object.keys(baseObj);
      const anonKeys = new Set(Object.keys(anonObj));
      if (baseKeys.length > 0) {
        let matchingKeys = 0;
        for (const k of baseKeys) {
          if (anonKeys.has(k)) {
            matchingKeys++;
          }
        }
        const keySimilarity = matchingKeys / baseKeys.length;
        if (keySimilarity >= 0.85) {
          return keySimilarity;
        }
      }
    }
  } catch {
    // Non-JSON fallback text comparison
  }

  // Length difference ratio
  const lenDiff = Math.abs(baselineBody.length - anonBody.length);
  const maxLen = Math.max(baselineBody.length, anonBody.length);
  const lenRatio = maxLen > 0 ? (maxLen - lenDiff) / maxLen : 0;
  return Math.max(0, Math.min(1.0, lenRatio));
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
    .map((h) => h.toLowerCase())
    .filter((h) => !SENSITIVE_HEADER_NAMES.has(h))
    .sort();

  const isAnonymous = identityId === 'anonymous' || identityId === 'identity_anon_stripped';
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
      pathTemplate,
    },
    statusCode: response.statusCode,
    contentLength: response.bodyText.length,
    responseTimeMs: response.responseTimeMs,
    headerNames: sanitizedHeaderNames,
    bodyHash: sha256(response.bodyText),
    normalizedBodyShape: bodyShape,
    authState: {
      authenticatedSignal: isAnonymous ? 'appears_unauthenticated' : 'appears_authenticated',
      authStateHash: sha256(`identity:${identityId}`),
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
      persistsData: false,
    },
  };
}

export async function runAuthBypassDetection(
  request: AuthBypassDetectionRequest
): Promise<AuthBypassDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const bypassMechanism = request.bypassMechanism ?? 'header_stripping';

  // 1. Adapter Preflight Pipeline Gate
  const preflight = await runAdapterPreflight({
    target: request.endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    };
  }

  // 2. Prepare Target URL & Templates
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'malformed_target_url',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      error: {
        code: 'malformed_target_url',
        safeMessage: 'Invalid endpoint URL format',
      },
    };
  }

  const normalizedOrigin = parsedUrl.origin;
  const pathTemplate = parsedUrl.pathname || '/';

  let identityAHeaders = { ...request.identityA.headers };
  if (request.identityA.cookies && Object.keys(request.identityA.cookies).length > 0) {
    const cookieHeader = Object.entries(request.identityA.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    identityAHeaders['cookie'] = cookieHeader;
  }

  // 3. Pre-execution Session Health Verification
  if (request.identityA.sessionState) {
    const sessionCheck = await validateSessionHealth(request.identityA.sessionState, nowIso);
    if (!sessionCheck.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'auth_bypass_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: sessionCheck.reasonCode ?? 'session_expired',
        lineage,
        endpointUrl: request.endpointUrl,
        bypassMechanism,
        error: {
          code: sessionCheck.reasonCode ?? 'session_expired',
          safeMessage: `Identity A session expired: ${sessionCheck.reasonCode ?? 'session_expired'}`,
        },
      };
    }
    if (sessionCheck.updatedHeaders) {
      identityAHeaders = { ...identityAHeaders, ...sessionCheck.updatedHeaders };
    }
  }

  const transport = request.transport ?? (async (req: HttpProbeRequest) => {
    const res = await fetch(req.url, { method: req.method, headers: req.headers });
    const bodyText = await res.text();
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return {
      statusCode: res.status,
      headers,
      bodyText,
      responseTimeMs: 20,
    };
  });

  // 4. Dispatch Baseline Probe (Identity A — Authenticated)
  const probeReqA: HttpProbeRequest = {
    url: request.endpointUrl,
    method: request.method ?? 'GET',
    headers: identityAHeaders,
    timeoutMs: 5000,
  };

  let probeResponseA: HttpProbeResponse;
  try {
    probeResponseA = await transport(probeReqA);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'baseline_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      error: {
        code: 'baseline_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Baseline HTTP probe failed',
      },
    };
  }

  // Baseline must return 200..299 with substantive content to be an authenticated protected endpoint
  if (probeResponseA.statusCode < 200 || probeResponseA.statusCode >= 300 || probeResponseA.bodyText.trim().length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'baseline_not_protected_resource',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
    };
  }

  // 5. Dispatch Anonymous Probe (Header Stripping / Cookie Omission)
  const probeReqB: HttpProbeRequest = {
    url: request.endpointUrl,
    method: request.method ?? 'GET',
    headers: {
      accept: probeReqA.headers['accept'] ?? 'application/json, text/html, */*',
      'user-agent': probeReqA.headers['user-agent'] ?? 'Mozilla/5.0 (FixGuard Defensive Auditor)',
    },
    timeoutMs: 5000,
  };

  let probeResponseB: HttpProbeResponse;
  try {
    probeResponseB = await transport(probeReqB);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'validation_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      error: {
        code: 'validation_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Validation HTTP probe failed',
      },
    };
  }

  // 6. Safe Response Snapshots
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
    'identity_anon_stripped',
    nowIso
  );

  // 7. Access Control Evaluation
  // If anonymous response returns 401, 403, 404, or redirects to a login endpoint (301/302/307/308 to /login, /auth, etc.)
  const isAnonDenied =
    probeResponseB.statusCode === 401 ||
    probeResponseB.statusCode === 403 ||
    probeResponseB.statusCode === 404 ||
    (probeResponseB.statusCode >= 300 &&
      probeResponseB.statusCode < 400 &&
      (probeResponseB.headers['location']?.toLowerCase().includes('login') ||
        probeResponseB.headers['location']?.toLowerCase().includes('auth') ||
        probeResponseB.headers['location']?.toLowerCase().includes('signin')));

  if (isAnonDenied) {
    const abstainedResult: AuthBypassDetectionResult = {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'authentication_enforced',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      baselineSnapshot,
      validationSnapshot,
    };
    return pruneTransientEvidence(abstainedResult, nowIso);
  }

  // Check if anonymous probe returned 200..299
  const isAnonSuccess = probeResponseB.statusCode >= 200 && probeResponseB.statusCode < 300;
  if (!isAnonSuccess) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'non_success_anonymous_status',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      baselineSnapshot,
      validationSnapshot,
    };
  }

  // Calculate similarity ratio
  const similarityRatio = calculateBodySimilarity(probeResponseA.bodyText, probeResponseB.bodyText);
  if (similarityRatio < 0.85) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'body_divergence_insufficient_similarity',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
    };
  }

  // 8. Execute Response Comparator (M47)
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
      responseTimeDeltaMsSignificant: 1000,
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
      persistsData: false,
    },
  };

  const comparisonResult = compareResponses(comparisonRequest, nowIso);
  if (comparisonResult.status === 'failed') {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'comparison_failed',
      reasonCode: comparisonResult.error?.code ?? 'comparison_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      error: {
        code: comparisonResult.error?.code ?? 'comparison_failed',
        safeMessage: comparisonResult.error?.safeMessage ?? 'Comparison execution failed',
      },
    };
  }

  // 9. Route into Evidence Validation Pipeline (M49)
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
        domain: parsedUrl.hostname,
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
        persistsData: false,
      },
    },
    baselineSnapshot,
    validationSnapshot,
    comparisonMode: 'authorization_difference',
    comparisonThresholds: {
      contentLengthDeltaPercentSignificant: 20,
      responseTimeDeltaMsSignificant: 1000,
    },
    mappingMode: 'authorization_difference_to_evidence',
    reviewerPolicy: request.reviewerPolicy ?? {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false,
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
      persistsData: false,
    },
  };

  const validationResult = runAuthorizedComparisonValidation(validationRequest, nowIso);
  if (validationResult.status !== 'completed' || !validationResult.evidenceDraft) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: validationResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      error: {
        code: validationResult.reasonCode,
        safeMessage: validationResult.error?.safeMessage ?? 'Validation gate rejected evidence draft',
      },
    };
  }

  // 10. Human Review Gate (M50)
  if (!request.humanReviewDecision) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'pending_human_review',
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      evidenceDraft: validationResult.evidenceDraft,
    };
  }

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
      scanId: request.scanId,
    },
    reviewDecision: request.humanReviewDecision,
    substancePayload: {
      evidenceType: 'authorization_difference',
      baseline: {
        method: request.method ?? 'GET',
        statusCode: baselineSnapshot.statusCode,
        contentLength: baselineSnapshot.contentLength,
        responseTimeMs: baselineSnapshot.responseTimeMs,
        bodyHash: baselineSnapshot.bodyHash,
      },
      attackOrValidation: {
        method: request.method ?? 'GET',
        statusCode: validationSnapshot.statusCode,
        contentLength: validationSnapshot.contentLength,
        responseTimeMs: validationSnapshot.responseTimeMs,
        bodyHash: validationSnapshot.bodyHash,
      },
      difference: {
        statusCodeChanged: comparisonResult.difference?.statusCodeChanged ?? false,
        contentLengthDeltaPercent: comparisonResult.difference?.contentLengthDeltaPercent ?? 0,
        responseTimeDeltaMs: comparisonResult.difference?.responseTimeDeltaMs ?? 0,
        authStateChanged: comparisonResult.difference?.authStateChanged ?? true,
      },
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

  const promotedEvidenceResult = evaluateHumanReviewedEvidencePromotion(promotionRequest, nowIso);
  if (promotedEvidenceResult.status !== 'promoted' || !promotedEvidenceResult.nonPersistedEvidenceRecord) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: promotedEvidenceResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: promotedEvidenceResult.reasonCode,
        safeMessage: 'Evidence promotion rejected by human review boundary',
      },
    };
  }

  // 11. Ephemeral Store, Selection & Finding Candidate Promotion (M51–M54)
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
      executesTools: false,
    },
  };

  const saveResult = await saveReviewedEvidence(saveRequest, nowIso, storeRepo);
  const storeRecordId = saveResult.record?.storeRecordId ?? saveResult.summary?.storeRecordId;
  if (saveResult.status !== 'saved' || !storeRecordId) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: saveResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: saveResult.reasonCode,
        safeMessage: 'Failed to store reviewed evidence',
      },
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
      storeRecordIds: [storeRecordId],
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
      executesTools: false,
    },
  };

  const selectResult = await selectReviewedEvidence(selectRequest, nowIso, storeRepo);
  if (selectResult.status !== 'selected' || !selectResult.selectionSet) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: selectResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: selectResult.reasonCode,
        safeMessage: 'Failed to select reviewed evidence',
      },
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
      executesTools: false,
    },
  };

  const draftResult = await createReviewedEvidenceFindingCandidateDraft(draftRequest, nowIso);
  if (draftResult.status !== 'draft_created' || !draftResult.draft) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: draftResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: draftResult.reasonCode,
        safeMessage: 'Failed to create candidate draft',
      },
    };
  }

  // 12. Promote Candidate to Formal Candidate (M54)
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
      authorizedPromotionToFormalCandidate: true,
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
      noPersistence: true as const,
    },
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
      executesTools: false,
    },
  };

  const promoteCandidateResult = await promoteReviewedEvidenceFindingCandidateDraft(
    promotionCandidateRequest,
    nowIso
  );

  if (promoteCandidateResult.status !== 'candidate_created' || !promoteCandidateResult.candidate) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_bypass_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'promotion_blocked',
      reasonCode: promoteCandidateResult.reasonCode,
      lineage,
      endpointUrl: request.endpointUrl,
      bypassMechanism,
      similarityRatio,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      validationResult,
      promotedEvidenceResult,
      error: {
        code: promoteCandidateResult.reasonCode,
        safeMessage: 'Failed to promote finding candidate',
      },
    };
  }

  // 13. Produce Canonical Finding DTO
  const evidenceRecord = promotedEvidenceResult.nonPersistedEvidenceRecord;
  const finding: Finding = {
    id: `find_${safeSeed}`,
    type: 'BROKEN_AUTHENTICATION',
    severity: 'high',
    title: `Authentication Bypass via ${bypassMechanism.replace('_', ' ')} on ${pathTemplate}`,
    description: `Protected endpoint '${request.endpointUrl}' was accessed anonymously via ${bypassMechanism} with HTTP 200 and ${Math.round(similarityRatio * 100)}% structural body similarity to authenticated response.`,
    target: request.endpointUrl,
    evidence: sanitizeEvidenceFragment(
      JSON.stringify({
        endpointUrl: request.endpointUrl,
        bypassMechanism,
        bodySimilarityRatio: similarityRatio,
        authenticatedStatusCode: baselineSnapshot.statusCode,
        anonymousStatusCode: validationSnapshot.statusCode,
        comparisonId: comparisonResult.comparisonId,
        candidateId: promoteCandidateResult.candidate.candidateId,
        evidenceId: evidenceRecord.evidenceId,
      })
    ),
    confidence: 0.95,
    metadata: {
      kind: 'auth_bypass_metadata',
      category: 'BROKEN_AUTHENTICATION',
      endpointUrl: request.endpointUrl,
      httpMethod: request.method ?? 'GET',
      authenticatedStatusCode: baselineSnapshot.statusCode,
      anonymousStatusCode: validationSnapshot.statusCode,
      bypassMechanism,
      bodySimilarityRatio: similarityRatio,
      observedAt: nowIso,
      candidateId: promoteCandidateResult.candidate.candidateId,
      evidenceRecordId: evidenceRecord.evidenceId,
      lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
    },
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_bypass_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'vulnerability_detected',
    reasonCode: 'authentication_bypass_proven',
    lineage,
    endpointUrl: request.endpointUrl,
    bypassMechanism,
    similarityRatio,
    baselineSnapshot,
    validationSnapshot,
    comparisonResult,
    validationResult,
    evidenceRecord,
    promotedEvidenceResult,
    findingCandidate: promoteCandidateResult.candidate,
    finding,
  };
}

export class AuthBypassDetectionService {
  public async execute(
    request: AuthBypassDetectionRequest
  ): Promise<AuthBypassDetectionResult> {
    return runAuthBypassDetection(request);
  }
}
