/**
 * Milestone P7-2 — Blind SSRF Detection Probe
 *
 * Core Invariant: Deterministic asynchronous validation of blind SSRF.
 * The engine injects unique OOB canary URLs into parameters processing external
 * links and validates inbound callbacks via OobCanaryManager.
 *
 * Safety & Quality Guarantees:
 * - 7-pass SSRF preflight protection on target endpoint.
 * - Out-of-band ephemeral canary token generation and verification.
 * - Anti-leak evidence sanitization via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when no callback interaction is recorded.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 * - 0 occurrences of 'as any'.
 */

import type {
  BlindSsrfDetectionRequest,
  BlindSsrfDetectionResult,
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
import { defaultOobCanaryManager, OobCanaryManager } from '../oob/OobCanaryManager.js';

const SSRF_SUSPICIOUS_PARAMS = new Set([
  'url',
  'feed',
  'webhook',
  'src',
  'link',
  'endpoint',
  'target',
  'dest',
  'destination',
  'redirect',
  'callback',
  'uri',
  'path',
  'source',
  'host',
  'domain',
  'remote',
  'load',
  'fetch',
  'open',
  'view',
  'file',
  'document',
  'proxy',
  'service',
  'href',
]);

export function isSsrfCandidateParameter(paramName: string): boolean {
  const normalized = paramName.toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (SSRF_SUSPICIOUS_PARAMS.has(normalized)) return true;
  const parts = normalized.split('_');
  for (const part of parts) {
    if (SSRF_SUSPICIOUS_PARAMS.has(part)) return true;
  }
  return false;
}

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function extractHostFromUrl(urlStr: string): string {
  try {
    return new URL(urlStr).hostname;
  } catch {
    return 'target.local';
  }
}

export async function runBlindSsrfDetection(
  request: BlindSsrfDetectionRequest,
  customOobManager?: OobCanaryManager
): Promise<BlindSsrfDetectionResult> {
  const transport = request.transport ?? defaultHttpProbeTransport;
  const oobManager = customOobManager ?? defaultOobCanaryManager;
  const safeSeed = sanitizeToSafeId(request.detectionId);
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const endpointUrl = request.endpointUrl;
  const parameterName = request.parameterName;
  const method = request.method ?? 'GET';

  // 1. 7-Pass SSRF Preflight Protection on the target endpoint
  const preflight = await runAdapterPreflight({
    target: endpointUrl,
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
      kind: 'blind_ssrf_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode ?? 'preflight_denied',
      lineage,
      endpointUrl,
      parameterName,
      injectedCanaryUrl: '',
      canaryToken: '',
      interactionConfirmed: false,
    };
  }

  // 2. Issue unique cryptographic OOB Canary token
  const targetHost = extractHostFromUrl(endpointUrl);
  const tokenDescriptor = oobManager.issueCanaryToken({
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    actorId: request.actorId,
    targetDomain: targetHost,
    targetEndpoint: endpointUrl,
    purpose: 'blind_ssrf',
  });

  const canaryUrl = tokenDescriptor.callbackUrl;

  // 3. Dispatch injection probe request
  try {
    let probeReq: HttpProbeRequest;
    if (method === 'POST') {
      probeReq = {
        url: endpointUrl,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'FixGuard-Security-Auditor/2.0',
          ...(request.identityAContext?.headers ?? {}),
        },
        body: JSON.stringify({ [parameterName]: canaryUrl }),
        timeoutMs: 8000,
      };
    } else {
      const parsedUrl = new URL(endpointUrl);
      parsedUrl.searchParams.set(parameterName, canaryUrl);
      probeReq = {
        url: parsedUrl.toString(),
        method: 'GET',
        headers: {
          'User-Agent': 'FixGuard-Security-Auditor/2.0',
          ...(request.identityAContext?.headers ?? {}),
        },
        timeoutMs: 8000,
      };
    }

    await transport(probeReq);
  } catch {
    // If the remote target times out or errors during fetch, it may still trigger the async callback
  }

  // 4. Validate Inbound OOB Interactions
  const interactions = oobManager.getInteractionsForToken(tokenDescriptor.canaryToken);
  const interactionConfirmed = interactions.length > 0;

  if (!interactionConfirmed) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_ssrf_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_oob_interaction_observed',
      lineage,
      endpointUrl,
      parameterName,
      injectedCanaryUrl: canaryUrl,
      canaryToken: tokenDescriptor.canaryToken,
      interactionConfirmed: false,
    };
  }

  // 5. Build Finding or HITL Evidence Draft
  const firstInteraction = interactions[0];
  const remoteAddress = firstInteraction?.remoteAddress ?? 'unknown';
  const nowIso = new Date().toISOString();
  const draftId = `dft_bssrf_${safeSeed}`;
  const candidateId = `cnd_bssrf_${safeSeed}`;
  const evidenceRecordId = `evd_bssrf_${safeSeed}`;
  const findingId = `fnd_bssrf_${safeSeed}`;

  const sanitizedUrl = sanitizeEvidenceFragment(endpointUrl);
  const sanitizedCanary = sanitizeEvidenceFragment(canaryUrl);

  const safeRationale = `Confirmed blind Server-Side Request Forgery on parameter '${parameterName}' at ${sanitizedUrl}. Target triggered asynchronous OOB HTTP/DNS callback to canary '${tokenDescriptor.canaryToken}' from remote IP ${remoteAddress}.`;

  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const finding: Finding = {
      id: findingId,
      type: 'SERVER_SIDE_REQUEST_FORGERY',
      severity: 'critical',
      title: `Confirmed Blind SSRF via Parameter '${parameterName}'`,
      description: `Target endpoint ${sanitizedUrl} processed external URL injected into parameter '${parameterName}', initiating an asynchronous out-of-band request to ${sanitizedCanary} (originating IP: ${remoteAddress}).`,
      target: endpointUrl,
      evidence: JSON.stringify({
        assessmentId: request.assessmentId,
        scanId: request.scanId,
        parameterName,
        injectedCanaryUrl: canaryUrl,
        canaryToken: tokenDescriptor.canaryToken,
        remoteAddress,
        interactionCount: interactions.length,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'blind_ssrf_detection_metadata',
        category: 'SERVER_SIDE_REQUEST_FORGERY',
        endpointUrl,
        parameterName,
        injectedCanaryUrl: canaryUrl,
        canaryToken: tokenDescriptor.canaryToken,
        interactionConfirmed: true,
        remoteAddress,
        exposureSeverity: 'critical',
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_ssrf_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'vulnerability_detected',
      reasonCode: 'blind_ssrf_oob_confirmed',
      lineage,
      endpointUrl,
      parameterName,
      injectedCanaryUrl: canaryUrl,
      canaryToken: tokenDescriptor.canaryToken,
      interactionConfirmed: true,
      remoteAddress,
      finding,
    };
  }

  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_bssrf_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_base_${safeSeed}`,
      validationSnapshotId: `snp_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'blind_ssrf_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'blind_ssrf_requires_operator_review',
    lineage,
    endpointUrl,
    parameterName,
    injectedCanaryUrl: canaryUrl,
    canaryToken: tokenDescriptor.canaryToken,
    interactionConfirmed: true,
    remoteAddress,
    evidenceDraft,
  };
}
