/**
 * FixGuard V2 — Milestone P2-1 Security Header Detection Engine
 *
 * Implements high-precision passive/light inspection of HTTP security headers:
 * - Content-Security-Policy (CSP)
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options
 * - Referrer-Policy
 * - Permissions-Policy
 *
 * Crucial Invariant: Missing security headers are hardening gaps, NOT confirmed exploits.
 * When approved through human review, they strictly produce status: 'potential_weakness',
 * never 'exploit_confirmed'.
 */

import { createHash } from 'node:crypto';
import type {
  SecurityHeaderDetectionRequest,
  SecurityHeaderDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

export const DEFAULT_REQUIRED_SECURITY_HEADERS: readonly string[] = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'referrer-policy',
  'permissions-policy',
];

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
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

export async function runSecurityHeaderDetection(
  request: SecurityHeaderDetectionRequest
): Promise<SecurityHeaderDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
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
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation || ps.passiveRecon),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'security_header_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      missingHeaders: [],
      presentHeaders: [],
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    };
  }

  // 2. Prepare Target URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'security_header_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: 'invalid_target_url',
      lineage,
      missingHeaders: [],
      presentHeaders: [],
      error: {
        code: 'invalid_target_url',
        safeMessage: 'Target URL is invalid',
      },
    };
  }

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
      const reason = sessionHealth.reasonCode ?? 'session_expired';
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'security_header_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: reason,
        lineage,
        missingHeaders: [],
        presentHeaders: [],
        error: {
          code: reason,
          safeMessage: `Session health check failed: ${reason}`,
        },
      };
    }
    if (sessionHealth.updatedHeaders) {
      sessionHeaders = { ...sessionHeaders, ...sessionHealth.updatedHeaders };
    }
  }

  // 4. Dispatch Probe
  let probeResponse: HttpProbeResponse;
  try {
    probeResponse = await dispatchProbe(
      {
        url: request.endpointUrl,
        method,
        headers: {
          ...sessionHeaders,
          'User-Agent': 'FixGuard-V2-SecurityHeader-Detector/1.0',
        },
      },
      transport,
      request.coordinator
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'HTTP probe failed';
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'security_header_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'probe_dispatch_error',
      lineage,
      missingHeaders: [],
      presentHeaders: [],
      error: {
        code: 'probe_dispatch_error',
        safeMessage: message,
      },
    };
  }

  // 5. Evaluate Security Headers
  const requiredHeaders = request.requiredHeaders ?? DEFAULT_REQUIRED_SECURITY_HEADERS;
  const normalizedResponseHeaders = new Set(
    Object.keys(probeResponse.headers).map((h) => h.toLowerCase().trim())
  );

  const missing: string[] = [];
  const present: string[] = [];

  for (const header of requiredHeaders) {
    const lower = header.toLowerCase().trim();
    if (normalizedResponseHeaders.has(lower)) {
      present.push(lower);
    } else {
      missing.push(lower);
    }
  }

  // 6. Abstention Check: If all required headers are present, abstain cleanly
  if (missing.length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'security_header_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'all_security_headers_enforced',
      lineage,
      missingHeaders: [],
      presentHeaders: present,
    };
  }

  // 7. Missing Headers Observed (Hardening Gaps)
  // If no explicit human review decision is supplied, halt at human review boundary
  if (!request.humanReviewDecision) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'security_header_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'pending_human_review',
      reasonCode: 'pending_human_review',
      lineage,
      missingHeaders: missing,
      presentHeaders: present,
      evidenceDraft: {
        draftKind: 'non_persisted_comparison_evidence_draft',
        draftId: `dft_${safeSeed}`,
        suggestedEvidenceType: 'http_difference',
        suggestedStrength: 'moderate',
        sourceComparisonId: `cmp_${safeSeed}`,
        sourceSnapshotIds: {
          baselineSnapshotId: `snp_${safeSeed}_base`,
          validationSnapshotId: `snp_${safeSeed}_val`,
        },
        requiresHumanReview: true,
        notPersisted: true,
        notARealFinding: true,
        notConfirmedEvidence: true,
        notForExternalDelivery: true,
        notM45EvidenceRecord: true,
        safeRationale: `Target response on ${pathTemplate} is missing recommended HTTP security headers: ${missing.join(', ')}`,
      },
    };
  }

  // 8. Human Review Decision Approved -> Promotes to Potential Weakness Finding
  // Invariant: Missing headers are hardening gaps, strictly producing 'potential_weakness', never 'exploit_confirmed'.
  const finding: Finding = {
    id: `fnd_sh_${safeSeed}`,
    type: 'SECURITY_MISCONFIGURATION',
    severity: 'low',
    title: `Missing HTTP Security Headers on ${pathTemplate}`,
    description: `Target is missing hardening security headers: ${missing.join(', ')}. Present headers: ${present.join(', ') || 'none'}.`,
    target: request.endpointUrl,
    evidence: JSON.stringify({
      missingHeaders: missing,
      presentHeaders: present,
      endpointUrl: request.endpointUrl,
      observedAt: nowIso,
      reviewerId: request.humanReviewDecision.reviewerId,
      reviewedAt: request.humanReviewDecision.reviewedAt,
    }),
    confidence: 0.95,
    verificationState: 'observed_anomaly',
    metadata: {
      kind: 'missing_security_headers_metadata',
      category: 'SECURITY_MISCONFIGURATION',
      candidateId: `cnd_${safeSeed}`,
      evidenceRecordId: `evd_${safeSeed}`,
      missingHeaders: missing,
      presentHeaders: present,
      observedAt: nowIso,
      endpointUrl: request.endpointUrl,
      lineage,
    },
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'security_header_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'potential_weakness',
    reasonCode: 'missing_security_headers_observed',
    lineage,
    missingHeaders: missing,
    presentHeaders: present,
    finding,
  };
}
