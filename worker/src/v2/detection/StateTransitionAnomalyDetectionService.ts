/**
 * Milestone P5-8 — State Transition Anomaly Detection Engine (Business Workflow Integrity)
 *
 * Core Invariant: Safe verification of business workflow integrity.
 * The engine probes multi-step or transaction endpoints (e.g. checkouts, approvals,
 * finalization) to test whether prerequisite states can be bypassed to execute
 * restricted final actions without authorization.
 *
 * Anti-Leak & Safety Guarantees:
 * - 7-pass SSRF preflight checks via runAdapterPreflight().
 * - Business logic state bypass evaluation (missing prior state verification).
 * - Response excerpts capped at 128 chars and sanitized via sanitizeEvidenceFragment().
 * - Clean abstention (secure_target_abstained) when target enforces state machines (400/422/409/412).
 * - 0 occurrences of 'as any'.
 */

import {
  DETECTION_CONTRACT_VERSION,
  type StateTransitionAnomalyDetectionRequest,
  type StateTransitionAnomalyDetectionResult,
  type IdorHttpProbeTransport,
  type HttpProbeRequest,
  type HttpProbeResponse,
} from './DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';

export const TRANSACTION_ENDPOINT_INDICATORS = [
  'checkout',
  'finalize',
  'complete',
  'confirm',
  'process',
  'approve',
  'activate',
  'execute',
  'fulfill',
] as const;

export function isStateTransitionCandidateEndpoint(url: string): boolean {
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();
    return TRANSACTION_ENDPOINT_INDICATORS.some((indicator) => path.includes(indicator));
  } catch {
    return false;
  }
}

export const DEFAULT_PREREQUISITE_STEPS: readonly string[] = [
  'cart_validation',
  'shipping_address_set',
  'payment_authorization',
  'approval_token_verified',
];

export interface StateBypassEvaluation {
  readonly bypassed: boolean;
  readonly excerpt?: string;
}

export function evaluateStateBypass(statusCode: number, body: string): StateBypassEvaluation {
  if (statusCode !== 200 && statusCode !== 201 && statusCode !== 204) {
    return { bypassed: false };
  }

  if (!body || body.trim().length === 0) {
    return { bypassed: false };
  }

  try {
    const parsed = JSON.parse(body);
    if (parsed && typeof parsed === 'object') {
      const statusField = String(parsed.status ?? parsed.state ?? '').toLowerCase();
      const isSuccess =
        statusField === 'completed' ||
        statusField === 'success' ||
        statusField === 'approved' ||
        statusField === 'paid' ||
        statusField === 'confirmed' ||
        parsed.success === true ||
        Boolean(parsed.orderId) ||
        Boolean(parsed.transactionId) ||
        Boolean(parsed.confirmationNumber);

      if (isSuccess) {
        return {
          bypassed: true,
          excerpt: JSON.stringify(parsed).slice(0, 128),
        };
      }
    }
  } catch {
    // Non-JSON responses
    if (
      body.includes('Order Placed') ||
      body.includes('Payment Successful') ||
      body.includes('Action Approved') ||
      body.includes('Transaction Completed')
    ) {
      return {
        bypassed: true,
        excerpt: body.slice(0, 128).replace(/[\r\n]+/g, ' '),
      };
    }
  }

  return { bypassed: false };
}

/**
 * Main Detection Service for State Transition Anomaly / Business Logic Bypass (Milestone P5-8).
 */
export async function runStateTransitionAnomalyDetection(
  request: StateTransitionAnomalyDetectionRequest
): Promise<StateTransitionAnomalyDetectionResult> {
  const lineage = {
    assessmentId: request.assessmentId,
    scanId: request.scanId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const httpMethod = request.httpMethod ?? 'POST';
  const expectedSteps = request.expectedPrerequisiteSteps ?? DEFAULT_PREREQUISITE_STEPS;
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
      kind: 'state_transition_anomaly_detection_result',
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
      expectedPrerequisiteSteps: expectedSteps,
      bypassedSuccessfully: false,
      error: {
        code: preflight.reasonCode,
        safeMessage: preflight.reason ?? 'Preflight denied for state transition probe',
      },
    };
  }

  // 2. Dispatch Direct Terminal Action Request Without Prior State
  const transport = request.transport ?? defaultHttpProbeTransport;
  const payload = request.payload ?? {
    action: 'finalize',
    confirm: true,
    skipVerification: true,
    step: 'complete',
  };

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
      body: JSON.stringify(payload),
      timeoutMs: 5000,
    });
    statusCode = probeResp.statusCode;
    bodyText = probeResp.bodyText ?? '';
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'state_transition_probe_failed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      expectedPrerequisiteSteps: expectedSteps,
      bypassedSuccessfully: false,
      error: {
        code: 'state_transition_probe_failed',
        safeMessage: err instanceof Error ? err.message : 'State transition probe request failed',
      },
    };
  }

  // 3. Evaluate State Enforcement & Abstention
  // If target rejects with 400, 422, 403, 409, 412, 404: state sequencing is enforced
  if (
    statusCode === 400 ||
    statusCode === 422 ||
    statusCode === 403 ||
    statusCode === 404 ||
    statusCode === 405 ||
    statusCode === 409 ||
    statusCode === 412
  ) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'target_enforced_prerequisite_state',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      expectedPrerequisiteSteps: expectedSteps,
      bypassedSuccessfully: false,
    };
  }

  const bypassEval = evaluateStateBypass(statusCode, bodyText);

  if (!bypassEval.bypassed || !bypassEval.excerpt) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'terminal_action_not_executed_or_unconfirmed',
      lineage,
      endpointUrl: request.endpointUrl,
      httpMethod,
      expectedPrerequisiteSteps: expectedSteps,
      bypassedSuccessfully: false,
    };
  }

  // 4. State Transition Bypass Detected
  const sanitizedExcerpt = sanitizeEvidenceFragment(bypassEval.excerpt);
  const sanitizedUrl = sanitizeEvidenceFragment(request.endpointUrl);
  const draftId = `dft_statetr_${safeSeed}`;
  const candidateId = `cnd_statetr_${safeSeed}`;
  const evidenceRecordId = `evd_statetr_${safeSeed}`;

  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const nowIso = new Date().toISOString();
    const finding: Finding = {
      id: `fnd_statetr_${safeSeed}`,
      type: 'BUSINESS_LOGIC_BYPASS',
      severity: 'high',
      title: `Approved Business Logic State Transition Bypass on ${sanitizedUrl}`,
      description: `Human operator verified business workflow bypass. Terminal action request (${httpMethod}) executed successfully without mandatory prerequisite steps (${expectedSteps.join(', ')}). Sanitized confirmation: ${sanitizedExcerpt}`,
      target: sanitizedUrl,
      evidence: JSON.stringify({
        endpointUrl: sanitizedUrl,
        httpMethod,
        expectedPrerequisiteSteps: expectedSteps,
        bypassedSuccessfully: true,
        responseExcerpt: sanitizedExcerpt,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      metadata: {
        kind: 'state_transition_anomaly_metadata',
        category: 'BUSINESS_LOGIC_BYPASS',
        endpointUrl: sanitizedUrl,
        expectedPrerequisiteSteps: expectedSteps,
        bypassedSuccessfully: true,
        responseExcerpt: sanitizedExcerpt,
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'state_transition_anomaly_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'vulnerability_detected',
      reasonCode: 'state_transition_bypass_confirmed_by_operator',
      lineage,
      endpointUrl: sanitizedUrl,
      httpMethod,
      expectedPrerequisiteSteps: expectedSteps,
      bypassedSuccessfully: true,
      responseExcerpt: sanitizedExcerpt,
      finding,
    };
  }

  // Unattended mode: Route to pending evidence drafts
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_statetr_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_st_base_${safeSeed}`,
      validationSnapshotId: `snp_st_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Terminal endpoint '${sanitizedUrl}' completed without prerequisites (${expectedSteps.join(', ')}). Confirmation: ${sanitizedExcerpt}`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'state_transition_anomaly_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'state_transition_anomaly_requires_human_approval',
    lineage,
    endpointUrl: sanitizedUrl,
    httpMethod,
    expectedPrerequisiteSteps: expectedSteps,
    bypassedSuccessfully: true,
    responseExcerpt: sanitizedExcerpt,
    evidenceDraft,
  };
}
