/**
 * Milestone P4-9 — Credentialed CORS Detection Upgrade
 *
 * Tests whether target endpoints reflect arbitrary external origins
 * while simultaneously setting Access-Control-Allow-Credentials: true
 * under authenticated context (Identity A).
 *
 * Strict Invariants:
 * - Safe verification of cross-origin leakages.
 * - 7-pass SSRF preflight protection.
 * - Anti-leak evidence sanitization (sensitive tokens/headers redacted).
 * - Clean abstention (secure_target_abstained) when origin is rejected or Allow-Credentials is false/missing.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  CredentialedCorsDetectionRequest,
  CredentialedCorsDetectionResult,
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

export async function runCredentialedCorsDetection(
  request: CredentialedCorsDetectionRequest
): Promise<CredentialedCorsDetectionResult> {
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
  const suppliedOrigin = request.suppliedOrigin ?? 'https://canary.fixguard.internal';

  // 1. 7-Pass SSRF Preflight Protection
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
      kind: 'credentialed_cors_detection_result',
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
      suppliedOrigin,
      reflectedOrigin: '',
      allowCredentialsHeader: false,
      acaoHeader: '',
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied for Credentialed CORS: ${preflight.reasonCode}`,
      },
    };
  }

  // 2. Prepare headers with authenticated context (Identity A)
  const probeHeaders: Record<string, string> = {
    ...(request.identityAContext?.headers ?? {}),
    Origin: suppliedOrigin,
    Accept: 'application/json, text/plain, */*',
    'User-Agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
  };

  if (request.identityAContext?.cookies && Object.keys(request.identityAContext.cookies).length > 0) {
    const cookieHeader = Object.entries(request.identityAContext.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieHeader.length > 0) {
      probeHeaders['Cookie'] = cookieHeader;
    }
  }

  // 3. Dispatch probe
  let probeResp: HttpProbeResponse | undefined;
  try {
    const probeReq: HttpProbeRequest = {
      url: request.endpointUrl,
      method: httpMethod,
      headers: probeHeaders,
      timeoutMs: 5000,
    };
    probeResp = await transport(probeReq);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'cors_probe_dispatch_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      suppliedOrigin,
      reflectedOrigin: '',
      allowCredentialsHeader: false,
      acaoHeader: '',
      error: {
        code: 'cors_probe_dispatch_failed',
        safeMessage: err instanceof Error ? err.message : 'CORS probe dispatch failed',
      },
    };
  }

  const responseStatusCode = probeResp.statusCode;
  const headers = probeResp.headers;

  let rawAcao: string | undefined;
  let rawAcac: string | undefined;

  for (const [key, val] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey === 'access-control-allow-origin' && typeof val === 'string') {
      rawAcao = val;
    } else if (lowerKey === 'access-control-allow-credentials' && typeof val === 'string') {
      rawAcac = val;
    }
  }

  const acaoHeader = rawAcao ?? '';
  const reflectedOrigin = acaoHeader;
  const allowCredentialsHeader = rawAcac?.trim().toLowerCase() === 'true';

  const originReflected =
    acaoHeader.length > 0 &&
    (acaoHeader.toLowerCase() === suppliedOrigin.toLowerCase() || acaoHeader === '*' || acaoHeader === 'null');

  // 4. Misconfiguration evaluation: Origin reflected AND Allow-Credentials: true
  if (originReflected && allowCredentialsHeader) {
    const draftId = `dft_cors_${safeSeed}`;
    const candidateId = `cnd_cors_${safeSeed}`;
    const evidenceRecordId = `evd_cors_${safeSeed}`;

    let parsedPath = '/';
    try {
      parsedPath = new URL(request.endpointUrl).pathname;
    } catch {
      // fallback
    }

    // A. Human Review Decision Handling
    if (request.humanReviewDecision) {
      if (request.humanReviewDecision.decision === 'approve_evidence') {
        const finding: Finding = {
          id: `fnd_cors_${safeSeed}`,
          type: 'SECURITY_MISCONFIGURATION',
          severity: 'high',
          title: `Credentialed Arbitrary CORS Origin Reflection on ${parsedPath}`,
          description: `Target application reflects arbitrary untrusted Origin '${suppliedOrigin}' in Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true. This permits cross-origin theft of authenticated responses.`,
          target: request.endpointUrl,
          evidence: sanitizeEvidenceFragment(
            JSON.stringify({
              endpointUrl: request.endpointUrl,
              httpMethod,
              suppliedOrigin,
              reflectedOrigin,
              allowCredentialsHeader,
              acaoHeader,
              responseStatusCode,
              reviewedBy: request.humanReviewDecision.reviewerId,
              reviewedAt: request.humanReviewDecision.reviewedAt,
            })
          ),
          confidence: 0.95,
          metadata: {
            kind: 'credentialed_cors_metadata',
            category: 'SECURITY_MISCONFIGURATION',
            endpointUrl: request.endpointUrl,
            httpMethod,
            suppliedOrigin,
            reflectedOrigin,
            allowCredentialsHeader,
            acaoHeader,
            observedAt: nowIso,
            candidateId,
            evidenceRecordId,
            lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
          },
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'credentialed_cors_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'vulnerability_detected',
          reasonCode: 'credentialed_cors_confirmed',
          lineage,
          endpointUrl: request.endpointUrl,
          httpMethod,
          suppliedOrigin,
          reflectedOrigin,
          allowCredentialsHeader,
          acaoHeader,
          responseStatusCode,
          finding,
        };
      }

      if (request.humanReviewDecision.decision === 'reject') {
        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'credentialed_cors_detection_result',
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
          suppliedOrigin,
          reflectedOrigin,
          allowCredentialsHeader,
          acaoHeader,
          responseStatusCode,
        };
      }
    }

    // B. Unreviewed -> Produce Draft for HITL Triage
    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'strong',
      sourceComparisonId: `cmp_cors_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_cors_${safeSeed}_base`,
        validationSnapshotId: `snp_cors_${safeSeed}_val`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Target reflected untrusted Origin '${suppliedOrigin}' with Access-Control-Allow-Credentials: true on ${parsedPath} (status ${responseStatusCode})`,
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'credentialed_cors_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'credentialed_cors_observed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      suppliedOrigin,
      reflectedOrigin,
      allowCredentialsHeader,
      acaoHeader,
      responseStatusCode,
      evidenceDraft,
    };
  }

  // 5. Clean Abstention: Origin not reflected or Allow-Credentials not true
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'credentialed_cors_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'cors_policy_enforced',
    lineage,
    endpointUrl: request.endpointUrl,
    httpMethod,
    suppliedOrigin,
    reflectedOrigin,
    allowCredentialsHeader,
    acaoHeader,
    responseStatusCode,
  };
}

export class CredentialedCorsDetectionService {
  public async execute(
    request: CredentialedCorsDetectionRequest
  ): Promise<CredentialedCorsDetectionResult> {
    return runCredentialedCorsDetection(request);
  }
}
