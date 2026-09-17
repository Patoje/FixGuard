/**
 * Milestone P4-7 — JWT Algorithm Confusion Detection Engine
 *
 * Checks whether endpoints accepting JSON Web Tokens (JWT) fail to enforce
 * cryptographic signature verification when presented with manipulated 'alg: none'
 * or signature-stripped tokens.
 *
 * Strict Invariants:
 * - Controlled impact verification (zero payload tampering beyond alg: none).
 * - 7-pass SSRF preflight protection.
 * - Anti-leak evidence sanitization (raw tokens redacted in snapshots and drafts).
 * - Clean abstention (secure_target_abstained) when no JWT is provided or when target rejects unsigned tokens (401/403).
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  JwtAlgorithmConfusionDetectionRequest,
  JwtAlgorithmConfusionDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export async function runJwtAlgorithmConfusionDetection(
  request: JwtAlgorithmConfusionDetectionRequest
): Promise<JwtAlgorithmConfusionDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const transport = request.transport ?? defaultHttpProbeTransport;
  const httpMethod: 'GET' | 'POST' | 'HEAD' = request.httpMethod ?? 'GET';

  // 1. Discovery / Precondition: Look for Bearer JWT in identityAContext headers
  const headers = request.identityAContext?.headers ?? {};
  let authHeaderKey: string | undefined;
  let rawAuthHeader: string | undefined;

  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === 'authorization' && typeof val === 'string') {
      authHeaderKey = key;
      rawAuthHeader = val;
      break;
    }
  }

  if (!rawAuthHeader || !/^Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/i.test(rawAuthHeader.trim())) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_jwt_bearer_detected',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
    };
  }

  const rawJwt = rawAuthHeader.replace(/^Bearer\s+/i, '').trim();
  const jwtParts = rawJwt.split('.');
  if (jwtParts.length < 2) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'invalid_jwt_format',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
    };
  }

  const [headerB64, payloadB64] = jwtParts;
  let originalAlgorithm = 'RS256';
  try {
    const decodedHeader = JSON.parse(base64UrlDecode(headerB64));
    if (typeof decodedHeader.alg === 'string') {
      originalAlgorithm = decodedHeader.alg;
    }
  } catch {
    // fallback to RS256
  }

  // 2. Token Manipulation: Create 'alg: none' token with stripped signature
  const forgedHeader = base64UrlEncode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const forgedJwt = `${forgedHeader}.${payloadB64}.`;

  // 3. SSRF Preflight
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
      kind: 'jwt_algorithm_confusion_detection_result',
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
      httpMethod,
      originalAlgorithm,
      manipulatedAlgorithm: 'none',
      probeMechanism: 'alg_none_header',
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied for JWT Algorithm Confusion: ${preflight.reasonCode}`,
      },
    };
  }

  // 4. Probing & Verification
  // A. Baseline probe with legitimate identity A
  let baselineStatus = 200;
  try {
    const baselineReq: HttpProbeRequest = {
      url: request.endpointUrl,
      method: httpMethod,
      headers: {
        ...headers,
        accept: 'application/json, text/plain, */*',
        'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      timeoutMs: 5000,
    };
    const baselineResp = await transport(baselineReq);
    baselineStatus = baselineResp.statusCode;
  } catch {
    // assume baseline ok
  }

  // B. Forged probe with manipulated 'alg: none' token
  const forgedHeaders = {
    ...headers,
    [authHeaderKey ?? 'authorization']: `Bearer ${forgedJwt}`,
    accept: 'application/json, text/plain, */*',
    'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
  };

  let forgedResp: HttpProbeResponse | undefined;
  try {
    const forgedReq: HttpProbeRequest = {
      url: request.endpointUrl,
      method: httpMethod,
      headers: forgedHeaders,
      timeoutMs: 5000,
    };
    forgedResp = await transport(forgedReq);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'forged_probe_dispatch_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      originalAlgorithm,
      manipulatedAlgorithm: 'none',
      probeMechanism: 'alg_none_header',
      error: {
        code: 'forged_probe_dispatch_failed',
        safeMessage: err instanceof Error ? err.message : 'Forged probe failed',
      },
    };
  }

  const forgedStatusCode = forgedResp.statusCode;

  // If forged probe is accepted (200 OK or same status as baseline 2xx), signature bypass confirmed!
  if (forgedStatusCode === 200 || (baselineStatus >= 200 && baselineStatus < 300 && forgedStatusCode === baselineStatus)) {
    const draftId = `dft_jwt_${safeSeed}`;
    const candidateId = `cnd_jwt_${safeSeed}`;
    const evidenceRecordId = `evd_jwt_${safeSeed}`;

    let parsedPath = '/';
    try {
      parsedPath = new URL(request.endpointUrl).pathname;
    } catch {
      // fallback
    }

    // 5. Human Review Routing & Finding Construction
    if (request.humanReviewDecision) {
      if (request.humanReviewDecision.decision === 'approve_evidence') {
        const finding: Finding = {
          id: `fnd_jwt_${safeSeed}`,
          type: 'BROKEN_AUTHENTICATION',
          severity: 'high',
          title: `JWT Algorithm Confusion (alg: none) on ${parsedPath}`,
          description: `Target application accepted an unsigned JSON Web Token with 'alg: none' on ${request.endpointUrl}. Cryptographic signature verification is bypassed, permitting arbitrary token manipulation.`,
          target: request.endpointUrl,
          evidence: sanitizeEvidenceFragment(
            JSON.stringify({
              endpointUrl: request.endpointUrl,
              httpMethod,
              originalAlgorithm,
              manipulatedAlgorithm: 'none',
              probeMechanism: 'alg_none_header',
              baselineStatusCode: baselineStatus,
              forgedStatusCode,
              reviewedBy: request.humanReviewDecision.reviewerId,
              reviewedAt: request.humanReviewDecision.reviewedAt,
            })
          ),
          confidence: 0.95,
          metadata: {
            kind: 'jwt_algorithm_confusion_metadata',
            category: 'BROKEN_AUTHENTICATION',
            endpointUrl: request.endpointUrl,
            httpMethod,
            originalAlgorithm,
            manipulatedAlgorithm: 'none',
            probeMechanism: 'alg_none_header',
            observedAt: nowIso,
            candidateId,
            evidenceRecordId,
            lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
          },
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'jwt_algorithm_confusion_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'vulnerability_detected',
          reasonCode: 'jwt_signature_bypass_confirmed',
          lineage,
          endpointUrl: request.endpointUrl,
          httpMethod,
          originalAlgorithm,
          manipulatedAlgorithm: 'none',
          probeMechanism: 'alg_none_header',
          baselineStatusCode: baselineStatus,
          forgedStatusCode,
          finding,
        };
      }

      if (request.humanReviewDecision.decision === 'reject') {
        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'jwt_algorithm_confusion_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'secure_target_abstained',
          reasonCode: 'human_review_rejected',
          lineage,
          endpointUrl: request.endpointUrl,
          httpMethod,
          originalAlgorithm,
          manipulatedAlgorithm: 'none',
          probeMechanism: 'alg_none_header',
          baselineStatusCode: baselineStatus,
          forgedStatusCode,
        };
      }
    }

    // 6. Unreviewed -> Produce Draft for HITL Triage
    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'strong',
      sourceComparisonId: `cmp_jwt_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_jwt_${safeSeed}_base`,
        validationSnapshotId: `snp_jwt_${safeSeed}_val`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Target accepted unsigned JWT token with alg: none on ${parsedPath} (status ${forgedStatusCode} matches baseline ${baselineStatus})`,
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'jwt_algorithm_confusion_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'jwt_signature_bypass_observed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      originalAlgorithm,
      manipulatedAlgorithm: 'none',
      probeMechanism: 'alg_none_header',
      baselineStatusCode: baselineStatus,
      forgedStatusCode,
      evidenceDraft,
    };
  }

  // Target correctly rejected unsigned / alg: none token (e.g. 401 Unauthorized / 403 Forbidden)
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'jwt_algorithm_confusion_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'signature_verification_enforced',
    lineage,
    endpointUrl: request.endpointUrl,
    httpMethod,
    originalAlgorithm,
    manipulatedAlgorithm: 'none',
    probeMechanism: 'alg_none_header',
    baselineStatusCode: baselineStatus,
    forgedStatusCode,
  };
}

export class JwtAlgorithmConfusionDetectionService {
  public async execute(
    request: JwtAlgorithmConfusionDetectionRequest
  ): Promise<JwtAlgorithmConfusionDetectionResult> {
    return runJwtAlgorithmConfusionDetection(request);
  }
}
