/**
 * CORS misconfiguration probe capability — wraps
 * CorsMisconfigurationDetectionService.
 *
 * Note (ADR-013 scope, operator decision 2026-10-24): CORS misconfiguration
 * is one of the 6 detectors frozen from FixGuard's own automatic
 * read-investigation loop (ReadDetectionPass.ts). This wrapper does NOT
 * reopen that automatic path — it only makes the capability reachable
 * through the fully-authorized AttackPlan -> authorize -> execute flow,
 * which already requires explicit per-target activeValidation permission
 * and a human-authorized plan before a single request is sent. The operator
 * confirmed this path's existing authorization gate is sufficient: no
 * target gets probed here without the same explicit authorization every
 * other capability in this registry already requires.
 *
 * Succeeds only on vulnerability_detected; never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runCorsMisconfigurationDetection } from '../../detection/CorsMisconfigurationDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type CorsMisconfigurationDetectionRequest,
  type CorsMisconfigurationDetectionResult,
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
  result: CorsMisconfigurationDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'vulnerability_detected':
      return succeeded(
        result.reasonCode,
        'CORS misconfiguration confirmed by detection service',
        `ev_cors_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No CORS misconfiguration observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'CORS misconfiguration observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'CORS probe preflight denied');
    case 'comparison_failed':
    case 'promotion_blocked':
    case 'unexpected_failure':
      return failed(
        result.reasonCode,
        result.error?.safeMessage ?? `CORS probe status: ${result.status}`
      );
    default: {
      const _exhaustive: never = result.status;
      return failed('cors_misconfiguration_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface CorsMisconfigurationProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates cors_misconfiguration_probe AttackCapabilityPort. */
export function createCorsMisconfigurationProbeCapability(
  options?: CorsMisconfigurationProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'cors_misconfiguration_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('cors_misconfiguration_target_missing', 'CORS probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'cors_misconfiguration_authorization_missing',
          'CORS probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: CorsMisconfigurationDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'cors_misconfiguration_detection_request',
        detectionId: `det_cors_${ctx.step.stepId}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        endpointUrl: ctx.targetUrl,
        ...(ctx.primaryIdentity
          ? {
              authContext: {
                identityId: ctx.primaryIdentity.identityId,
                ...(ctx.primaryIdentity.headers ? { headers: ctx.primaryIdentity.headers } : {}),
              },
            }
          : {}),
        ...(normalized.transport ? { transport: normalized.transport } : {}),
        ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(ctx.transport ? { transport: ctx.transport } : {}),
      };

      let result: CorsMisconfigurationDetectionResult;
      try {
        result = await runCorsMisconfigurationDetection(request);
      } catch (err: unknown) {
        return failed(
          'cors_misconfiguration_tool_error',
          err instanceof Error ? err.message : 'CORS misconfiguration detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
