/**
 * Milestone P5-7 — Object Mapping Anomaly Detection Engine (Mass Assignment / Unconstrained Object Binding)
 *
 * Core Invariant: Safe verification of mass assignment / binding vulnerabilities.
 * The engine probes mutation endpoints (POST/PUT/PATCH) with injected administrative
 * properties (e.g. isAdmin, role, permissions) to test whether unconstrained object
 * mapping permits privilege escalation.
 *
 * Anti-Leak & Safety Guarantees:
 * - 7-pass SSRF preflight checks via runAdapterPreflight().
 * - Structural JSON echo analysis for bound administrative properties.
 * - Echoed responses capped at 128 chars and sanitized via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when target validates strictly (400/422/403) or strips keys.
 * - 0 occurrences of 'as any'.
 */

import {
  DETECTION_CONTRACT_VERSION,
  type ObjectMappingAnomalyDetectionRequest,
  type ObjectMappingAnomalyDetectionResult,
  type IdorHttpProbeTransport,
  type HttpProbeRequest,
  type HttpProbeResponse,
} from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';

export const DEFAULT_INJECTED_PRIVILEGE_PROPS: Record<string, unknown> = {
  isAdmin: true,
  role: 'admin',
  permissions: ['all'],
  isSuperuser: true,
};

export interface BindingEchoEvaluation {
  readonly accepted: boolean;
  readonly matchedKeys: readonly string[];
  readonly sanitizedEcho?: string;
}

export function evaluateBindingEcho(
  body: string,
  injectedProps: Record<string, unknown>
): BindingEchoEvaluation {
  if (!body || body.trim().length === 0) {
    return { accepted: false, matchedKeys: [] };
  }

  try {
    const parsed = JSON.parse(body);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { accepted: false, matchedKeys: [] };
    }

    const matched: string[] = [];
    for (const [k, expectedVal] of Object.entries(injectedProps)) {
      if (k in parsed) {
        const actual = parsed[k];
        if (
          actual === expectedVal ||
          (Array.isArray(expectedVal) && Array.isArray(actual) && actual.includes('all')) ||
          actual === 'admin' ||
          actual === true
        ) {
          matched.push(k);
        }
      }
    }

    if (matched.length > 0) {
      const snippet = JSON.stringify(parsed).slice(0, 128);
      return {
        accepted: true,
        matchedKeys: matched,
        sanitizedEcho: snippet,
      };
    }
  } catch {
    // Non-JSON responses do not demonstrate JSON mass assignment
    return { accepted: false, matchedKeys: [] };
  }

  return { accepted: false, matchedKeys: [] };
}

/**
 * Main Detection Service for Object Mapping Anomaly / Mass Assignment (Milestone P5-7).
 */
export async function runObjectMappingAnomalyDetection(
  request: ObjectMappingAnomalyDetectionRequest
): Promise<ObjectMappingAnomalyDetectionResult> {
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const httpMethod = request.httpMethod ?? 'POST';
  const injectedProps = request.injectedProperties ?? DEFAULT_INJECTED_PRIVILEGE_PROPS;
  const injectedKeys = Object.keys(injectedProps);
  const safeSeed = `${request.detectionId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 12)}${httpMethod.toLowerCase()}`;

  // 1. SSRF Preflight
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
      kind: 'object_mapping_anomaly_detection_result',
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
      injectedProperties: injectedKeys,
      bindingAccepted: false,
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for object mapping probe',
      },
    };
  }

  // 2. Dispatch Bounded JSON Mutation Request
  const transport = request.transport ?? defaultHttpProbeTransport;
  let statusCode = 0;
  let bodyText = '';

  try {
    const probeResp = await transport({
      url: request.endpointUrl,
      method: httpMethod,
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'FixGuard-Defensive-Scanner/2.0',
      },
      body: JSON.stringify(injectedProps),
      timeoutMs: 5000,
    });
    statusCode = probeResp.statusCode;
    bodyText = probeResp.bodyText ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'object_mapping_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      injectedProperties: injectedKeys,
      bindingAccepted: false,
      error: {
        code: 'object_mapping_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'Object mapping probe request failed',
      },
    };
  }

  // 3. Strict Validation & Abstention Check
  // If target rejects with 400, 422, 403, 405 or 404: strict binding enforcement
  if (statusCode === 400 || statusCode === 422 || statusCode === 403 || statusCode === 404 || statusCode === 405) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'target_rejected_unbound_properties',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      injectedProperties: injectedKeys,
      bindingAccepted: false,
    };
  }

  const echoEval = evaluateBindingEcho(bodyText, injectedProps);

  if (!echoEval.accepted || echoEval.matchedKeys.length === 0) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'unbound_properties_stripped_or_not_reflected',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      injectedProperties: injectedKeys,
      bindingAccepted: false,
    };
  }

  // 4. Object Mapping Anomaly Detected
  const sanitizedEcho = sanitizeEvidenceFragment(echoEval.sanitizedEcho ?? '');
  const sanitizedUrl = sanitizeEvidenceFragment(request.endpointUrl);
  const draftId = `dft_objmap_${safeSeed}`;
  const candidateId = `cnd_objmap_${safeSeed}`;
  const evidenceRecordId = `evd_objmap_${safeSeed}`;

  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const nowIso = new Date().toISOString();
    const finding: Finding = {
      id: `fnd_objmap_${safeSeed}`,
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: `Approved Object Mapping Mass Assignment (${echoEval.matchedKeys.join(', ')} on ${sanitizedUrl})`,
      description: `Human operator verified unconstrained object mapping / mass assignment vulnerability. Mutation request (${httpMethod}) accepted and reflected elevated administrative properties (${echoEval.matchedKeys.join(', ')}). Sanitized response: ${sanitizedEcho}`,
      target: sanitizedUrl,
      evidence: JSON.stringify({
        endpointUrl: sanitizedUrl,
        httpMethod,
        injectedProperties: echoEval.matchedKeys,
        bindingAccepted: true,
        sanitizedEchoResponse: sanitizedEcho,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'object_mapping_anomaly_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        endpointUrl: sanitizedUrl,
        httpMethod,
        injectedProperties: echoEval.matchedKeys,
        bindingAccepted: true,
        sanitizedEchoResponse: sanitizedEcho,
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'object_mapping_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'vulnerability_detected',
      reasonCode: 'mass_assignment_confirmed_by_operator',
      lineage,
      endpointUrl: sanitizedUrl,
      httpMethod,
      injectedProperties: echoEval.matchedKeys,
      bindingAccepted: true,
      sanitizedEchoResponse: sanitizedEcho,
      finding,
    };
  }

  // Unattended mode: Route to pending evidence drafts
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_objmap_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_obj_base_${safeSeed}`,
      validationSnapshotId: `snp_obj_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Endpoint '${sanitizedUrl}' accepted unconstrained properties (${echoEval.matchedKeys.join(', ')}). Echoed: ${sanitizedEcho}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'object_mapping_anomaly_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'object_mapping_anomaly_requires_human_approval',
    lineage,
    endpointUrl: sanitizedUrl,
    httpMethod,
    injectedProperties: echoEval.matchedKeys,
    bindingAccepted: true,
    sanitizedEchoResponse: sanitizedEcho,
    evidenceDraft,
  };
}
