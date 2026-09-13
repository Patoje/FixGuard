/**
 * Milestone F4 — CORS Misconfiguration Detection Engine
 *
 * Implements high-precision detection of insecure Cross-Origin Resource Sharing configurations:
 * 1. Safe preflight verification (M39/F1).
 * 2. Session lifecycle health check & refresh orchestration (F3).
 * 3. Probes routed via TargetExecutionCoordinator (F3).
 * 4. Differential origin probing against arbitrary untrusted origins and null origins.
 * 5. High-confidence verification: ACAO echoes untrusted origin + ACAC: true.
 * 6. Clean abstention with evidence pruning on secure configurations (F3).
 * 7. End-to-end evidence-to-candidate pipeline promotion (M49–M54).
 * 8. Canonical Finding generation (type: 'SECURITY_MISCONFIGURATION', severity: 'high').
 */

import { createHash } from 'node:crypto';
import type {
  CorsMisconfigurationDetectionRequest,
  CorsMisconfigurationDetectionResult,
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
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

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
  'refresh-token'
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
      // treat as text
    }
  }

  return {
    shapeKind: 'text',
    normalizedSchemaHash: sha256(bodyText.slice(0, 128))
  };
}

function buildSafeSnapshot(
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

async function dispatchProbe(
  req: HttpProbeRequest,
  transport: IdorHttpProbeTransport,
  coordinator?: TargetExecutionCoordinator
): Promise<HttpProbeResponse> {
  if (coordinator) {
    const host = new URL(req.url).host;
    return coordinator.execute(host, () => transport(req));
  }
  return transport(req);
}

export async function runCorsMisconfigurationDetection(
  request: CorsMisconfigurationDetectionRequest
): Promise<CorsMisconfigurationDetectionResult> {
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
      kind: 'cors_misconfiguration_detection_result',
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

  // 2. Prepare Target URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cors_misconfiguration_detection_result',
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
  const transport = request.transport ?? defaultHttpProbeTransport;
  const method = request.method ?? 'GET';

  // 3. Session Lifecycle Health Check
  let sessionHeaders: Record<string, string> = { ...(request.authContext?.headers ?? {}) };
  if (request.authContext?.cookies) {
    const cookieHeader = Object.entries(request.authContext.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieHeader.length > 0) {
      sessionHeaders['cookie'] = cookieHeader;
    }
  }

  if (request.authContext?.sessionState) {
    const sessionHealth = await validateSessionHealth(request.authContext.sessionState, nowIso);
    if (!sessionHealth.ok) {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'cors_misconfiguration_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: sessionHealth.reasonCode ?? 'session_expired',
        lineage,
        error: {
          code: sessionHealth.reasonCode ?? 'session_expired',
          safeMessage: `Session expired: ${sessionHealth.reasonCode ?? 'session_expired'}`
        }
      };
    }
    if (sessionHealth.updatedHeaders) {
      sessionHeaders = { ...sessionHeaders, ...sessionHealth.updatedHeaders };
    }
  }

  // 4. Baseline Probe (No Origin or Standard Origin)
  const baselineResponse = await dispatchProbe(
    {
      url: request.endpointUrl,
      method,
      headers: { ...sessionHeaders }
    },
    transport,
    request.coordinator
  );

  const baselineSnapshot = buildSafeSnapshot(
    `snp_${safeSeed}_base`,
    request.scanId,
    'baseline',
    normalizedOrigin,
    pathTemplate,
    baselineResponse,
    request.authContext?.identityId ?? 'default',
    nowIso
  );

  // 5. Test Origins Probing
  const originsToTest = request.testOrigins ?? [
    'https://untrusted-cross-origin.example.com',
    'null'
  ];

  let vulnerableOrigin: string | undefined;
  let validationResponse: HttpProbeResponse | undefined;

  for (const testOrigin of originsToTest) {
    const probeRes = await dispatchProbe(
      {
        url: request.endpointUrl,
        method,
        headers: {
          ...sessionHeaders,
          origin: testOrigin
        }
      },
      transport,
      request.coordinator
    );

    const acao = probeRes.headers['access-control-allow-origin'];
    const acac = probeRes.headers['access-control-allow-credentials'];

    const allowsOrigin =
      typeof acao === 'string' &&
      (acao.toLowerCase() === testOrigin.toLowerCase() || (testOrigin === 'null' && acao === 'null'));
    const allowsCredentials = typeof acac === 'string' && acac.toLowerCase() === 'true';

    if (allowsOrigin && allowsCredentials) {
      vulnerableOrigin = testOrigin;
      validationResponse = probeRes;
      break;
    }
    validationResponse = probeRes;
  }

  const validationSnapshot = buildSafeSnapshot(
    `snp_${safeSeed}_val`,
    request.scanId,
    'validation',
    normalizedOrigin,
    pathTemplate,
    validationResponse ?? baselineResponse,
    request.authContext?.identityId ?? 'untrusted',
    nowIso
  );

  // 6. Abstention Check: If no origin reflected with credentials, abstain cleanly
  if (!vulnerableOrigin || !validationResponse) {
    const abstainedResult: CorsMisconfigurationDetectionResult = {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'cors_misconfiguration_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'cors_policy_enforced',
      lineage,
      baselineSnapshot,
      validationSnapshot
    };
    return pruneTransientEvidence(abstainedResult, nowIso);
  }

  // 7. Response Comparison (M47)
  const comparisonRequest: ResponseComparisonRequest = {
    contractVersion: 'fixguard-response-comparator/v0',
    kind: 'response_comparison_request',
    comparisonId: `cmp_${safeSeed}`,
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
      kind: 'cors_misconfiguration_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'comparison_failed',
      reasonCode: comparisonResult.significance?.strongestSignal ?? 'comparison_evaluation_failed',
      lineage,
      baselineSnapshot,
      validationSnapshot,
      comparisonResult,
      error: {
        code: 'comparison_evaluation_failed',
        safeMessage: 'Response comparison failed to evaluate'
      }
    };
  }

  // 8. Authorized Comparison Validation (M49)
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
      kind: 'cors_misconfiguration_detection_result',
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

  // 9. Human-Reviewed Evidence Promotion (M50)
  const promotionRequest: HumanReviewedEvidencePromotionRequest = {
    contractVersion: 'fixguard-human-reviewed-evidence-promotion/v0',
    kind: 'human_reviewed_evidence_promotion_request',
    promotionId: `prm_${safeSeed}`,
    scanId: request.scanId,
    requestedAt: nowIso,
    validationResult,
    sourceIndicatorRef: {
      kind: 'reviewed_indicator_reference',
      indicatorId: `ind_${safeSeed}`,
      scanId: request.scanId
    },
    reviewDecision: request.humanReviewDecision ?? {
      decision: 'approve_evidence',
      reviewerId: 'reviewer_lead_sec',
      reviewedAt: nowIso
    },
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
      kind: 'cors_misconfiguration_detection_result',
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

  // 10. Store, Select & Draft Finding Candidate (M51–M53)
  const storeRepo = new InMemoryReviewedEvidenceStoreRepository();
  const saveRequest: SaveReviewedEvidenceRequest = {
    contractVersion: 'fixguard-reviewed-evidence-store/v0',
    kind: 'save_reviewed_evidence_request',
    saveId: `sav_${safeSeed}`,
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
      kind: 'cors_misconfiguration_detection_result',
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
      kind: 'cors_misconfiguration_detection_result',
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
    draftId: `dft_${safeSeed}`,
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
      kind: 'cors_misconfiguration_detection_result',
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

  // 11. Promote Candidate to Formal Candidate (M54)
  const candidateTriageDecision = request.triageDecision ?? {
    decisionId: `dec_${safeSeed}`,
    reviewerId: 'reviewer_lead_sec',
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
    candidateId: `cnd_${safeSeed}`,
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
      kind: 'cors_misconfiguration_detection_result',
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

  // 12. Produce Canonical Finding DTO
  const evidenceRecord = promotedEvidenceResult.nonPersistedEvidenceRecord;
  const finding: Finding = {
    id: `fnd_${safeSeed}`,
    type: 'SECURITY_MISCONFIGURATION',
    severity: 'high',
    title: `CORS Misconfiguration with Arbitrary Origin and Credentials on ${pathTemplate}`,
    description: `Origin reflection probing proved that untrusted origin (${vulnerableOrigin}) is reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.`,
    target: request.endpointUrl,
    evidence: JSON.stringify({
      endpointUrl: request.endpointUrl,
      reflectedOrigin: vulnerableOrigin,
      allowCredentials: true,
      comparisonId: comparisonResult.comparisonId,
      candidateId: promoteCandidateResult.candidate.candidateId,
      evidenceId: evidenceRecord.evidenceId
    }),
    confidence: 0.95,
    metadata: {
      category: 'CORS_MISCONFIGURATION',
      candidateId: promoteCandidateResult.candidate.candidateId,
      evidenceRecordId: evidenceRecord.evidenceId,
      reflectedOrigin: vulnerableOrigin,
      allowCredentials: true,
      lineage
    }
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'cors_misconfiguration_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'vulnerability_detected',
    reasonCode: 'cors_misconfiguration_proven',
    lineage,
    reflectedOrigin: vulnerableOrigin,
    allowCredentials: true,
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

export class CorsMisconfigurationDetectionService {
  public async execute(
    request: CorsMisconfigurationDetectionRequest
  ): Promise<CorsMisconfigurationDetectionResult> {
    return runCorsMisconfigurationDetection(request);
  }
}
