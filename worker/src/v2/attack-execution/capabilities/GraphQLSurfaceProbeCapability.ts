/**
 * GraphQL surface probe capability — wraps GraphQLSurfaceDetectionService.
 * Succeeds on graphql_surface_detected, security_misconfiguration, or
 * information_disclosure; never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runGraphQLSurfaceDetection } from '../../detection/GraphQLSurfaceDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type GraphQLSurfaceDetectionRequest,
  type GraphQLSurfaceDetectionResult,
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
  result: GraphQLSurfaceDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'graphql_surface_detected':
    case 'security_misconfiguration':
    case 'information_disclosure':
      return succeeded(
        result.reasonCode,
        'GraphQL surface signal observed by detection service',
        `ev_gql_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No GraphQL surface signal observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'GraphQL surface signal observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'GraphQL surface probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `GraphQL surface probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('graphql_surface_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface GraphQLSurfaceProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates graphql_surface_probe AttackCapabilityPort. */
export function createGraphQLSurfaceProbeCapability(
  options?: GraphQLSurfaceProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'graphql_surface_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('graphql_surface_target_missing', 'GraphQL surface probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'graphql_surface_authorization_missing',
          'GraphQL surface probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: GraphQLSurfaceDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'graphql_surface_detection_request',
        detectionId: `det_gql_${ctx.step.stepId}`,
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

      let result: GraphQLSurfaceDetectionResult;
      try {
        result = await runGraphQLSurfaceDetection(request);
      } catch (err: unknown) {
        return failed(
          'graphql_surface_tool_error',
          err instanceof Error ? err.message : 'GraphQL surface detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
