/**
 * Milestone P5-6 — Application Parameter Integrity Detection Engine
 *
 * Core Invariant: Safe verification of resource boundary enforcement.
 * The engine probes endpoints processing resource or file parameters with inert
 * normalization tests to confirm whether boundary sanitization prevents unauthorized
 * file or context access.
 *
 * Anti-Leak & Safety Guarantees:
 * - 7-pass SSRF preflight checks via runAdapterPreflight().
 * - Structural file leakage signature analysis (e.g. root:x:, [boot loader], <web-app).
 * - Evidence excerpt capped at 128 chars and sanitized via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when target enforces boundaries (400/403/404 or sanitized response).
 * - 0 occurrences of 'as any'.
 */

import {
  DETECTION_CONTRACT_VERSION,
  type ParameterIntegrityDetectionRequest,
  type ParameterIntegrityDetectionResult,
  type IdorHttpProbeTransport,
  type HttpProbeRequest,
  type HttpProbeResponse,
} from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';

export const RESOURCE_PARAMETER_NAMES = [
  'file',
  'path',
  'doc',
  'template',
  'page',
  'load',
  'include',
  'view',
  'read',
  'filename',
  'document',
] as const;

export function isResourceParameterCandidate(paramName: string): boolean {
  const lower = paramName.toLowerCase();
  return RESOURCE_PARAMETER_NAMES.some((candidate) => lower === candidate || lower.endsWith(`_${candidate}`) || lower.startsWith(`${candidate}_`));
}

export const INERT_PROBE_PATTERNS = [
  '../../../../etc/passwd',
  '..\\..\\..\\..\\windows\\win.ini',
  '../../../../etc/hosts',
  '../../../../WEB-INF/web.xml',
] as const;

export interface StructuralLeakMatch {
  readonly leaked: boolean;
  readonly signatureKind?: 'unix_passwd' | 'windows_ini' | 'unix_hosts' | 'java_webxml';
  readonly excerpt?: string;
}

export function detectStructuralLeak(body: string): StructuralLeakMatch {
  if (!body || body.trim().length === 0) {
    return { leaked: false };
  }

  // 1. Unix passwd pattern (root:x:0:0: or root:*:0:0:)
  const passwdMatch = /root:[^:]*:[0-9]+:[0-9]+:[^:]*:[^:]*:[^\r\n]*/m.exec(body);
  if (passwdMatch) {
    return {
      leaked: true,
      signatureKind: 'unix_passwd',
      excerpt: passwdMatch[0].slice(0, 128),
    };
  }

  // 2. Windows INI patterns ([extensions] or [boot loader] or [fonts])
  const winIniMatch = /(?:\[boot loader\]|\[extensions\]|\[fonts\])[\r\n]+[^\r\n]+/im.exec(body);
  if (winIniMatch) {
    return {
      leaked: true,
      signatureKind: 'windows_ini',
      excerpt: winIniMatch[0].slice(0, 128),
    };
  }

  // 3. Unix hosts (127.0.0.1 localhost or ::1 localhost)
  const hostsMatch = /(?:127\.0\.0\.1|::1)\s+localhost/m.exec(body);
  if (hostsMatch) {
    return {
      leaked: true,
      signatureKind: 'unix_hosts',
      excerpt: hostsMatch[0].slice(0, 128),
    };
  }

  // 4. Java web.xml (<web-app)
  const webxmlMatch = /<web-app[\s>]/im.exec(body);
  if (webxmlMatch) {
    return {
      leaked: true,
      signatureKind: 'java_webxml',
      excerpt: body.slice(webxmlMatch.index, webxmlMatch.index + 128).replace(/[\r\n]+/g, ' '),
    };
  }

  return { leaked: false };
}

/**
 * Main Detection Service for Application Parameter Integrity (Milestone P5-6).
 */
export async function runParameterIntegrityDetection(
  request: ParameterIntegrityDetectionRequest
): Promise<ParameterIntegrityDetectionResult> {
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const probePattern = request.probePattern ?? '../../../../etc/passwd';
  const paramName = request.parameterName;
  const safeSeed = `${request.detectionId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 12)}${paramName.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 8)}`;

  // Construct target probe URL
  let targetUrlObj: URL;
  try {
    targetUrlObj = new URL(request.endpointUrl);
    targetUrlObj.searchParams.set(paramName, probePattern);
  } catch {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'invalid_endpoint_url',
      lineage,
      endpointUrl: request.endpointUrl,
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: true,
      error: {
        code: 'invalid_endpoint_url',
        safeMessage: 'Unable to parse endpoint URL for parameter integrity probe',
      },
    };
  }

  const probeUrl = targetUrlObj.toString();

  // 1. SSRF Preflight
  const preflight = await runAdapterPreflight({
    target: probeUrl,
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
      kind: 'parameter_integrity_detection_result',
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
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: true,
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for parameter integrity probe',
      },
    };
  }

  // 2. Dispatch Bounded GET Request
  const transport = request.transport ?? defaultHttpProbeTransport;
  let statusCode = 0;
  let bodyText = '';

  try {
    const probeResp = await transport({
      url: probeUrl,
      method: 'GET',
      headers: {
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'FixGuard-Defensive-Scanner/2.0',
      },
      timeoutMs: 5000,
    });
    statusCode = probeResp.statusCode;
    bodyText = probeResp.bodyText ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'parameter_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: true,
      error: {
        code: 'parameter_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Parameter probe request failed',
      },
    };
  }

  // 3. Analyze Response for Structural Leakage
  if (statusCode === 400 || statusCode === 403 || statusCode === 404 || statusCode === 405) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'target_rejected_boundary_traversal',
      lineage,
      endpointUrl: request.endpointUrl,
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: true,
    };
  }

  const leakMatch = detectStructuralLeak(bodyText);

  if (!leakMatch.leaked || !leakMatch.excerpt) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_structural_leakage_detected',
      lineage,
      endpointUrl: request.endpointUrl,
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: true,
    };
  }

  // 4. Boundary Violation Detected
  const sanitizedExcerpt = sanitizeEvidenceFragment(leakMatch.excerpt);
  const sanitizedUrl = sanitizeEvidenceFragment(request.endpointUrl);
  const draftId = `dft_pinteg_${safeSeed}`;
  const candidateId = `cnd_pinteg_${safeSeed}`;
  const evidenceRecordId = `evd_pinteg_${safeSeed}`;

  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const nowIso = new Date().toISOString();
    const finding: Finding = {
      id: `fnd_pinteg_${safeSeed}`,
      type: 'INFORMATION_DISCLOSURE',
      severity: 'high',
      title: `Approved Application Parameter Boundary Violation (${paramName} on ${sanitizedUrl})`,
      description: `Human operator verified parameter boundary violation. Injecting inert traversal sequence '${probePattern}' into parameter '${paramName}' on '${sanitizedUrl}' leaked structural system file contents (${leakMatch.signatureKind}). Sanitized excerpt: ${sanitizedExcerpt}`,
      target: sanitizedUrl,
      evidence: JSON.stringify({
        endpointUrl: sanitizedUrl,
        parameterName: paramName,
        injectedProbePattern: probePattern,
        boundaryEnforced: false,
        sanitizedExcerpt,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'parameter_integrity_metadata',
        category: 'INFORMATION_DISCLOSURE',
        endpointUrl: sanitizedUrl,
        parameterName: paramName,
        injectedProbePattern: probePattern,
        boundaryEnforced: false,
        sanitizedExcerpt,
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'parameter_integrity_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'vulnerability_detected',
      reasonCode: 'parameter_boundary_violation_confirmed_by_operator',
      lineage,
      endpointUrl: sanitizedUrl,
      parameterName: paramName,
      injectedProbePattern: probePattern,
      boundaryEnforced: false,
      sanitizedExcerpt,
      finding,
    };
  }

  // Unattended mode: Route to pending evidence drafts
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_pinteg_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_pinteg_base_${safeSeed}`,
      validationSnapshotId: `snp_pinteg_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Parameter '${paramName}' on '${sanitizedUrl}' leaked system signature with traversal pattern '${probePattern}'. Excerpt: ${sanitizedExcerpt}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'parameter_integrity_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'parameter_boundary_violation_requires_human_approval',
    lineage,
    endpointUrl: sanitizedUrl,
    parameterName: paramName,
    injectedProbePattern: probePattern,
    boundaryEnforced: false,
    sanitizedExcerpt,
    evidenceDraft,
  };
}
