/**
 * Auth bypass probe capability — wraps AuthBypassDetectionService.
 * Succeeds only on vulnerability_detected. Never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { AuthBypassDetectionService } from '../../detection/AuthBypassDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type AuthBypassDetectionRequest,
  type AuthBypassDetectionResult,
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

function mapAuthBypassResult(
  result: AuthBypassDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'vulnerability_detected':
      return succeeded(
        result.reasonCode,
        'Auth bypass confirmed by detection service',
        `ev_auth_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'Auth bypass not confirmed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Auth bypass differential observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Auth bypass preflight denied');
    case 'comparison_failed':
    case 'promotion_blocked':
    case 'unexpected_failure':
      return failed(
        result.reasonCode,
        result.error?.safeMessage ?? `Auth bypass detection status: ${result.status}`
      );
    default: {
      const _exhaustive: never = result.status;
      return failed('auth_bypass_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface AuthBypassProbeCapabilityOptions {
  readonly service?: AuthBypassDetectionService;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/**
 * Creates auth_bypass_probe AttackCapabilityPort.
 * Injectable service enables hermetic smoke proofs that execute() is invoked.
 */
export function createAuthBypassProbeCapability(
  options?: AuthBypassProbeCapabilityOptions | AuthBypassDetectionService
): AttackCapabilityPort {
  const normalized: AuthBypassProbeCapabilityOptions =
    options instanceof AuthBypassDetectionService
      ? { service: options }
      : (options ?? {});
  const detectionService = normalized.service ?? new AuthBypassDetectionService();

  return {
    capability: 'auth_bypass_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('auth_bypass_target_missing', 'Auth bypass capability requires a target URL');
      }

      const primary = ctx.primaryIdentity;
      if (
        !primary ||
        typeof primary.identityId !== 'string' ||
        primary.identityId.trim().length === 0
      ) {
        return failed(
          'auth_bypass_identity_missing',
          'Auth bypass probe requires primaryIdentity (authenticated baseline)'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'auth_bypass_authorization_missing',
          'Auth bypass probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: AuthBypassDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'auth_bypass_detection_request',
        detectionId: `det_auth_${ctx.step.stepId}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        endpointUrl: ctx.targetUrl,
        identityA: {
          identityId: primary.identityId,
          ...(primary.headers ? { headers: primary.headers } : {}),
        },
        ...(normalized.transport ? { transport: normalized.transport } : {}),
        ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(ctx.transport ? { transport: ctx.transport } : {}),
      };

      let result: AuthBypassDetectionResult;
      try {
        result = await detectionService.execute(request);
      } catch (err: unknown) {
        return failed(
          'auth_bypass_tool_error',
          err instanceof Error ? err.message : 'Auth bypass detection service threw'
        );
      }

      return mapAuthBypassResult(result, ctx.step.stepId);
    },
  };
}
