/**
 * F6.5 — graphql_auth_delta capability.
 * Same authorization gate as auth_boundary_differential. No severity.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';
import { observeGraphqlAuthDelta } from '../../observation/GraphqlAuthDeltaObservation.js';

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

export function createGraphqlAuthDeltaCapability(options?: {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}): AttackCapabilityPort {
  return {
    capability: 'graphql_auth_delta',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.verifiedAuthorizationDecision) {
        return failed(
          'graphql_auth_delta_authorization_missing',
          'GraphQL auth delta requires a verified authorization decision'
        );
      }
      if (!ctx.targetUrl || !ctx.primaryIdentity) {
        return failed(
          'graphql_auth_delta_target_missing',
          'GraphQL auth delta requires an already observed endpoint and identity A'
        );
      }
      const transport = ctx.transport ?? options?.transport;
      if (!transport) {
        return failed('graphql_auth_delta_transport_missing', 'GraphQL auth delta has no transport');
      }
      const observed = await observeGraphqlAuthDelta({
        endpointUrl: ctx.targetUrl,
        identityA: {
          identityId: ctx.primaryIdentity.identityId,
          ...(ctx.primaryIdentity.headers ? { headers: ctx.primaryIdentity.headers } : {}),
        },
        ...(ctx.secondaryIdentity
          ? {
              identityB: {
                identityId: ctx.secondaryIdentity.identityId,
                ...(ctx.secondaryIdentity.headers ? { headers: ctx.secondaryIdentity.headers } : {}),
              },
            }
          : {}),
        verifiedAuthorizationDecision: ctx.verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        lineage: ctx.plan.lineage,
        transport,
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(options?.dnsResolver ? { dnsResolver: options.dnsResolver } : {}),
        observedAt: new Date().toISOString(),
      });
      if (!observed.fact) {
        return failed(observed.reasonCode, 'GraphQL auth delta produced no observed fact');
      }
      return {
        outcome: 'observed',
        reasonCode: observed.reasonCode,
        safeMessage: `graphql_auth_delta ${observed.fact.factId}`,
      };
    },
  };
}
