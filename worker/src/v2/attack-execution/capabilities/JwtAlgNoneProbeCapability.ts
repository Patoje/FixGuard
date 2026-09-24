/**
 * JWT alg:none probe capability — wraps JwtAlgorithmConfusionDetectionService.
 * Succeeds only on vulnerability_detected. Never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { JwtAlgorithmConfusionDetectionService } from '../../detection/JwtAlgorithmConfusionDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type IdorHttpProbeTransport,
  type JwtAlgorithmConfusionDetectionRequest,
  type JwtAlgorithmConfusionDetectionResult,
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

function hasBearerJwt(headers: Readonly<Record<string, string>> | undefined): boolean {
  if (!headers) return false;
  for (const [key, val] of Object.entries(headers)) {
    if (
      key.toLowerCase() === 'authorization' &&
      typeof val === 'string' &&
      /^Bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/i.test(val.trim())
    ) {
      return true;
    }
  }
  return false;
}

function mapJwtResult(
  result: JwtAlgorithmConfusionDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'vulnerability_detected':
      return succeeded(
        result.reasonCode,
        'JWT alg:none signature bypass confirmed by detection service',
        `ev_jwt_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'JWT alg:none probe abstained; bypass not confirmed');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'JWT alg:none differential observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'JWT detection preflight denied');
    case 'unexpected_failure':
      return failed(
        result.reasonCode,
        result.error?.safeMessage ?? 'JWT detection unexpected failure'
      );
    default: {
      const _exhaustive: never = result.status;
      return failed('jwt_unexpected_status', `Unexpected JWT status: ${String(_exhaustive)}`);
    }
  }
}

export interface JwtAlgNoneProbeCapabilityOptions {
  readonly service?: JwtAlgorithmConfusionDetectionService;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/**
 * Creates jwt_alg_none_probe AttackCapabilityPort.
 * Injectable service enables hermetic smoke proofs that execute() is invoked.
 */
export function createJwtAlgNoneProbeCapability(
  options?: JwtAlgNoneProbeCapabilityOptions | JwtAlgorithmConfusionDetectionService
): AttackCapabilityPort {
  const normalized: JwtAlgNoneProbeCapabilityOptions =
    options instanceof JwtAlgorithmConfusionDetectionService
      ? { service: options }
      : (options ?? {});
  const detectionService = normalized.service ?? new JwtAlgorithmConfusionDetectionService();

  return {
    capability: 'jwt_alg_none_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('jwt_target_missing', 'JWT alg-none capability requires a target URL');
      }

      const primary = ctx.primaryIdentity;
      if (
        !primary ||
        typeof primary.identityId !== 'string' ||
        primary.identityId.trim().length === 0
      ) {
        return failed(
          'jwt_identity_missing',
          'JWT alg-none probe requires primaryIdentity with a Bearer JWT'
        );
      }

      if (!hasBearerJwt(primary.headers)) {
        return failed(
          'jwt_bearer_missing',
          'JWT alg-none probe requires Authorization Bearer JWT in primaryIdentity headers'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'jwt_authorization_missing',
          'JWT alg-none probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: JwtAlgorithmConfusionDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'jwt_algorithm_confusion_detection_request',
        detectionId: `det_jwt_${ctx.step.stepId}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        endpointUrl: ctx.targetUrl,
        identityAContext: {
          identityId: primary.identityId,
          ...(primary.headers ? { headers: primary.headers } : {}),
        },
        ...(normalized.transport ? { transport: normalized.transport } : {}),
        ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(ctx.transport ? { transport: ctx.transport } : {}),
      };

      let result: JwtAlgorithmConfusionDetectionResult;
      try {
        result = await detectionService.execute(request);
      } catch (err: unknown) {
        return failed(
          'jwt_tool_error',
          err instanceof Error ? err.message : 'JWT detection service threw'
        );
      }

      return mapJwtResult(result, ctx.step.stepId);
    },
  };
}
