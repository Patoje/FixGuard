/**
 * Next.js Server Action differential capability (Plan A Fase 5 → Attack Mode).
 *
 * Wraps runNextServerActionDifferential. Advisory until human authorize+execute.
 * Fail-closed without OBSERVED action id. BYOT optional (unauth-only still runs).
 * Does not invent action IDs. No Critical severity claims.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { runNextServerActionDifferential } from '../../detection/NextServerActionDifferentialDetectionService.js';
import { NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION } from '../../detection/NextServerActionDifferentialContracts.js';

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

/**
 * OBSERVED Next-Action id from plan.parameterName (surface/finding seed) only.
 * Never invents ids.
 */
function extractObservedActionId(ctx: AttackCapabilityInvocationContext): string | undefined {
  const fromPlan = ctx.plan.parameterName?.trim();
  if (fromPlan && fromPlan.length >= 8) return fromPlan;
  return undefined;
}

export interface NextServerActionDiffCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export function createNextServerActionDiffCapability(
  options?: NextServerActionDiffCapabilityOptions
): AttackCapabilityPort {
  return {
    capability: 'next_server_action_diff',
    async execute(
      ctx: AttackCapabilityInvocationContext
    ): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'next_server_action_target_missing',
          'Server Action differential requires an OBSERVED endpoint URL'
        );
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'next_server_action_authorization_missing',
          'Server Action differential requires verifiedAuthorizationDecision'
        );
      }

      const actionId = extractObservedActionId(ctx);
      if (!actionId) {
        return failed(
          'next_server_action_id_not_observed',
          'OBSERVED Next-Action id required on plan.parameterName (min length 8)'
        );
      }

      const lineage = ctx.plan.lineage;
      const primary = ctx.primaryIdentity;

      const result = await runNextServerActionDifferential({
        contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
        kind: 'next_server_action_diff_request',
        detectionId: `det_nsa_${ctx.step.stepId}`.slice(0, 96),
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        endpointUrl: ctx.targetUrl,
        actionId,
        ...(primary
          ? {
              authenticatedContext: {
                identityId: primary.identityId,
                ...(primary.headers ? { headers: primary.headers } : {}),
              },
            }
          : {}),
        ...(options?.transport || ctx.transport
          ? { transport: options?.transport ?? ctx.transport }
          : {}),
        ...(options?.dnsResolver || ctx.dnsResolver
          ? { dnsResolver: options?.dnsResolver ?? ctx.dnsResolver }
          : {}),
      });

      const evidenceId = `ev_nsa_${ctx.step.stepId}`;

      if (result.status === 'differential_observed') {
        return succeeded(
          result.reasonCode,
          `Server Action differential OBSERVED (action=${result.actionIdRedacted})`,
          evidenceId
        );
      }

      if (result.status === 'secure_target_abstained') {
        return refuted(
          result.reasonCode,
          `Server Action differential abstained (action=${result.actionIdRedacted})`
        );
      }

      if (
        result.status === 'preflight_denied' ||
        result.status === 'prerequisite_missing'
      ) {
        return failed(
          result.reasonCode,
          result.error?.safeMessage ?? `Server Action differential denied (${result.status})`
        );
      }

      return failed(
        result.reasonCode,
        result.error?.safeMessage ?? 'Server Action differential unexpected failure'
      );
    },
  };
}
