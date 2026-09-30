/**
 * Auth boundary differential capability — wraps AuthBoundaryDifferentialDetectionService.
 * GET-only A / anon (/ optional B). Distinct from idor_read_differential (BOLA).
 * Never invents object IDs. Soft-404 / WAF / expired session → interfered/inconclusive.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import {
  AuthBoundaryDifferentialDetectionService,
} from '../../detection/AuthBoundaryDifferentialDetectionService.js';
import type { AuthBoundaryDifferentialDetectionResult } from '../../detection/AuthBoundaryDifferentialContracts.js';
import { DETECTION_CONTRACT_VERSION } from '../../detection/DetectionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { toStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';

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

function observed(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'observed',
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

/**
 * Map investigation outcomes onto AttackStepExecutionOutcome + reason codes
 * that TestValidity understands (interfered/inconclusive must not mutate state).
 */
export function mapAuthBoundaryResult(
  result: AuthBoundaryDifferentialDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  const evidenceId = toStrictSafeId(`ev_abnd_${stepId}`);

  switch (result.investigationOutcome) {
    case 'validated':
      return succeeded(result.reasonCode, result.safeMessage, evidenceId);
    case 'suspicious':
      return observed(result.reasonCode, result.safeMessage, evidenceId);
    case 'secure':
      // Broken-boundary hypothesis refuted — boundary holds
      return refuted(result.reasonCode, result.safeMessage);
    case 'refuted':
      return refuted(result.reasonCode, result.safeMessage);
    case 'interfered':
      return failed(result.reasonCode, result.safeMessage);
    case 'inconclusive':
      return failed(result.reasonCode, result.safeMessage);
    default: {
      const _exhaustive: never = result.investigationOutcome;
      return failed(
        'auth_boundary_unexpected_outcome',
        `Unexpected investigation outcome: ${String(_exhaustive)}`
      );
    }
  }
}

export interface AuthBoundaryDifferentialCapabilityOptions {
  readonly service?: AuthBoundaryDifferentialDetectionService;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/**
 * Creates auth_boundary_differential AttackCapabilityPort.
 * Executable when primaryIdentity present (A+anon); secondaryIdentity optional.
 */
export function createAuthBoundaryDifferentialCapability(
  options?: AuthBoundaryDifferentialCapabilityOptions | AuthBoundaryDifferentialDetectionService
): AttackCapabilityPort {
  const normalized: AuthBoundaryDifferentialCapabilityOptions =
    options instanceof AuthBoundaryDifferentialDetectionService
      ? { service: options }
      : (options ?? {});
  const detectionService =
    normalized.service ?? new AuthBoundaryDifferentialDetectionService();

  return {
    capability: 'auth_boundary_differential',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'auth_boundary_target_missing',
          'Auth boundary capability requires a target URL'
        );
      }

      const primary = ctx.primaryIdentity;
      if (
        !primary ||
        typeof primary.identityId !== 'string' ||
        primary.identityId.trim().length === 0
      ) {
        return failed(
          'auth_boundary_identity_missing',
          'Auth boundary differential requires primaryIdentity (authenticated A); anon probe is empty headers'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'auth_boundary_authorization_missing',
          'Auth boundary differential requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const secondary = ctx.secondaryIdentity;

      let result: AuthBoundaryDifferentialDetectionResult;
      try {
        result = await detectionService.execute({
          contractVersion: DETECTION_CONTRACT_VERSION,
          kind: 'auth_boundary_differential_detection_request',
          detectionId: `det_abnd_${ctx.step.stepId}`,
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
          ...(secondary &&
          typeof secondary.identityId === 'string' &&
          secondary.identityId.trim().length > 0
            ? {
                identityB: {
                  identityId: secondary.identityId,
                  ...(secondary.headers ? { headers: secondary.headers } : {}),
                },
              }
            : {}),
          ...(normalized.transport ? { transport: normalized.transport } : {}),
          ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
          ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
          ...(ctx.transport ? { transport: ctx.transport } : {}),
        });
      } catch (err: unknown) {
        return failed(
          'auth_boundary_tool_error',
          err instanceof Error ? err.message : 'Auth boundary detection service threw'
        );
      }

      if (result.status === 'preflight_denied') {
        return {
          outcome: 'preflight_denied',
          reasonCode: result.reasonCode,
          safeMessage: result.safeMessage,
        };
      }

      return mapAuthBoundaryResult(result, ctx.step.stepId);
    },
  };
}
