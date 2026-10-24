/**
 * Session fixation probe capability — wraps
 * SessionFixationDetectionService. Succeeds on vulnerability_detected or
 * potential_weakness; never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runSessionFixationDetection } from '../../detection/SessionFixationDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type SessionFixationDetectionRequest,
  type SessionFixationDetectionResult,
  type IdorHttpProbeTransport,
} from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';

function succeeded(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'succeeded',
    reasonCode,
    safeMessage,
    ...(evidenceId ? { evidenceId } : {}),
  };
}

function refuted(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'refuted', reasonCode, safeMessage };
}

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

function mapResult(
  result: SessionFixationDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'vulnerability_detected':
    case 'potential_weakness':
      return succeeded(
        result.reasonCode,
        'Session fixation observed by detection service',
        `ev_fix_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No session fixation observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Session fixation observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Session fixation probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `Session fixation probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('session_fixation_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface SessionFixationProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates session_fixation_probe AttackCapabilityPort. */
export function createSessionFixationProbeCapability(
  options?: SessionFixationProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'session_fixation_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('session_fixation_target_missing', 'Session fixation probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'session_fixation_authorization_missing',
          'Session fixation probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: SessionFixationDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'session_fixation_detection_request',
        detectionId: `det_fix_${ctx.step.stepId}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        endpointUrl: ctx.targetUrl,
        ...(normalized.transport ? { transport: normalized.transport } : {}),
        ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(ctx.transport ? { transport: ctx.transport } : {}),
      };

      let result: SessionFixationDetectionResult;
      try {
        result = await runSessionFixationDetection(request);
      } catch (err: unknown) {
        return failed(
          'session_fixation_tool_error',
          err instanceof Error ? err.message : 'Session fixation detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
