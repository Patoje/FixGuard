/**
 * Milestone P4-8 — Session Fixation Detection Engine
 *
 * Evaluates whether target endpoints accept caller-supplied session identifiers
 * without enforcing session regeneration (Set-Cookie overriding the token),
 * exposing users to session hijacking / fixation vulnerabilities.
 *
 * Strict Invariants:
 * - Safe verification of session regeneration (strictly non-exploitative).
 * - 7-pass SSRF preflight protection.
 * - Anti-leak evidence sanitization (sensitive tokens truncated & sanitized).
 * - Clean abstention (secure_target_abstained) when server properly issues fresh Set-Cookie or rejects with 401/403.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  SessionFixationDetectionRequest,
  SessionFixationDetectionResult,
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

function extractSetCookieHeaders(headers: Record<string, string | string[] | undefined>): string[] {
  const setCookies: string[] = [];
  for (const [key, val] of Object.entries(headers)) {
    if (key.toLowerCase() === 'set-cookie' && val !== undefined) {
      if (Array.isArray(val)) {
        for (const item of val) {
          if (typeof item === 'string') {
            setCookies.push(item);
          }
        }
      } else if (typeof val === 'string') {
        setCookies.push(val);
      }
    }
  }
  return setCookies;
}

function hasSessionRegeneratedCookie(setCookies: readonly string[], cookieName: string): boolean {
  const prefix = `${cookieName.toLowerCase()}=`;
  for (const cookieStr of setCookies) {
    const trimmed = cookieStr.trim().toLowerCase();
    if (trimmed.startsWith(prefix) || trimmed.includes(`; ${prefix}`) || trimmed.includes(`;${prefix}`)) {
      return true;
    }
  }
  return false;
}

export async function runSessionFixationDetection(
  request: SessionFixationDetectionRequest
): Promise<SessionFixationDetectionResult> {
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
  const sessionCookieName = request.sessionCookieName ?? 'PHPSESSID';

  // 1. Generate synthetic in-scope fixed session token
  const fixedSessionToken = `fixguard_fix_${safeSeed}`;
  const fixedSessionExcerpt = sanitizeEvidenceFragment(fixedSessionToken).slice(0, 32);

  // 2. 7-Pass SSRF Preflight Protection
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
      kind: 'session_fixation_detection_result',
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
      sessionCookieName,
      fixedSessionId: fixedSessionExcerpt,
      serverRegeneratedSession: false,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied for Session Fixation: ${preflight.reasonCode}`,
      },
    };
  }

  // 3. Dispatch probe injecting fixed session cookie
  let probeResp: HttpProbeResponse | undefined;
  try {
    const probeReq: HttpProbeRequest = {
      url: request.endpointUrl,
      method: httpMethod,
      headers: {
        Cookie: `${sessionCookieName}=${fixedSessionToken}`,
        Accept: 'text/html,application/xhtml+xml,application/json,text/plain,*/*',
        'User-Agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      },
      timeoutMs: 5000,
    };
    probeResp = await transport(probeReq);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'session_fixation_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      sessionCookieName,
      fixedSessionId: fixedSessionExcerpt,
      serverRegeneratedSession: false,
      error: {
        code: 'session_fixation_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Probe dispatch failed',
      },
    };
  }

  const responseStatusCode = probeResp.statusCode;
  const setCookies = extractSetCookieHeaders(probeResp.headers);
  const serverRegeneratedSession = hasSessionRegeneratedCookie(setCookies, sessionCookieName);

  // 4. Hardened Target Verification
  // If server issues a fresh Set-Cookie overriding the fixed token, or returns 401/403/302, it cleanly abstains.
  if (serverRegeneratedSession || responseStatusCode === 401 || responseStatusCode === 403) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: serverRegeneratedSession ? 'session_regenerated_by_server' : 'session_probe_denied',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      sessionCookieName,
      fixedSessionId: fixedSessionExcerpt,
      serverRegeneratedSession,
      responseStatusCode,
    };
  }

  // 5. If server accepts the request (200 OK or 2xx) without regenerating the session cookie:
  if (responseStatusCode >= 200 && responseStatusCode < 300) {
    const draftId = `dft_fix_${safeSeed}`;
    const candidateId = `cnd_fix_${safeSeed}`;
    const evidenceRecordId = `evd_fix_${safeSeed}`;

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
          id: `fnd_fix_${safeSeed}`,
          type: 'BROKEN_AUTHENTICATION',
          severity: 'medium',
          title: `Session Fixation Vulnerability on ${parsedPath} (${sessionCookieName})`,
          description: `Target application accepts caller-supplied session identifier '${sessionCookieName}' without issuing a fresh Set-Cookie header to regenerate the session. This permits session fixation attacks.`,
          target: request.endpointUrl,
          evidence: sanitizeEvidenceFragment(
            JSON.stringify({
              endpointUrl: request.endpointUrl,
              httpMethod,
              sessionCookieName,
              fixedSessionId: fixedSessionExcerpt,
              serverRegeneratedSession: false,
              responseStatusCode,
              reviewedBy: request.humanReviewDecision.reviewerId,
              reviewedAt: request.humanReviewDecision.reviewedAt,
            })
          ),
          confidence: 0.9,
          metadata: {
            kind: 'session_fixation_metadata',
            category: 'BROKEN_AUTHENTICATION',
            endpointUrl: request.endpointUrl,
            httpMethod,
            sessionCookieName,
            fixedSessionId: fixedSessionExcerpt,
            serverRegeneratedSession: false,
            observedAt: nowIso,
            candidateId,
            evidenceRecordId,
            lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
          },
        };

        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'session_fixation_detection_result',
          detectionId: request.detectionId,
          scanId: request.scanId,
          assessmentId: request.assessmentId,
          authorizationGrantId: request.authorizationGrantId,
          authorizationDecisionId: request.authorizationDecisionId,
          actorId: request.actorId,
          status: 'vulnerability_detected',
          reasonCode: 'session_fixation_confirmed',
          lineage,
          endpointUrl: request.endpointUrl,
          httpMethod,
          sessionCookieName,
          fixedSessionId: fixedSessionExcerpt,
          serverRegeneratedSession: false,
          responseStatusCode,
          finding,
        };
      }

      if (request.humanReviewDecision.decision === 'reject') {
        return {
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'session_fixation_detection_result',
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
          sessionCookieName,
          fixedSessionId: fixedSessionExcerpt,
          serverRegeneratedSession: false,
          responseStatusCode,
        };
      }
    }

    // B. Unreviewed -> Produce Draft for HITL Triage
    const evidenceDraft: EvidenceDraftEnvelope = {
      draftKind: 'non_persisted_comparison_evidence_draft',
      draftId,
      suggestedEvidenceType: 'http_difference',
      suggestedStrength: 'moderate',
      sourceComparisonId: `cmp_fix_${safeSeed}`,
      sourceSnapshotIds: {
        baselineSnapshotId: `snp_fix_${safeSeed}_base`,
        validationSnapshotId: `snp_fix_${safeSeed}_val`,
      },
      requiresHumanReview: true,
      notPersisted: true,
      notARealFinding: true,
      notConfirmedEvidence: true,
      notForExternalDelivery: true,
      notM45EvidenceRecord: true,
      safeRationale: `Target accepted user-supplied session identifier '${sessionCookieName}' without issuing a regenerating Set-Cookie header on ${parsedPath} (status ${responseStatusCode})`,
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'session_fixation_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'session_fixation_observed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      sessionCookieName,
      fixedSessionId: fixedSessionExcerpt,
      serverRegeneratedSession: false,
      responseStatusCode,
      evidenceDraft,
    };
  }

  // Fallback for non-2xx non-error responses
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'session_fixation_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'secure_target_abstained',
    reasonCode: 'non_2xx_response_received',
    lineage,
    endpointUrl: request.endpointUrl,
    httpMethod,
    sessionCookieName,
    fixedSessionId: fixedSessionExcerpt,
    serverRegeneratedSession,
    responseStatusCode,
  };
}

export class SessionFixationDetectionService {
  public async execute(
    request: SessionFixationDetectionRequest
  ): Promise<SessionFixationDetectionResult> {
    return runSessionFixationDetection(request);
  }
}
