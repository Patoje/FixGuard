/**
 * Open redirect probe capability — wraps OpenRedirectDetectionService.
 * Succeeds on exploit_confirmed or potential_weakness; never synthetic
 * success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runOpenRedirectDetection } from '../../detection/OpenRedirectDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type OpenRedirectDetectionRequest,
  type OpenRedirectDetectionResult,
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
  result: OpenRedirectDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'exploit_confirmed':
    case 'potential_weakness':
      return succeeded(
        result.reasonCode,
        'Open redirect observed by detection service',
        `ev_redir_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No open redirect observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Open redirect observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Open redirect probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `Open redirect probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('open_redirect_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface OpenRedirectProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates open_redirect_probe AttackCapabilityPort. */
export function createOpenRedirectProbeCapability(
  options?: OpenRedirectProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'open_redirect_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('open_redirect_target_missing', 'Open redirect probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'open_redirect_authorization_missing',
          'Open redirect probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: OpenRedirectDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'open_redirect_detection_request',
        detectionId: `det_redir_${ctx.step.stepId}`,
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

      let result: OpenRedirectDetectionResult;
      try {
        result = await runOpenRedirectDetection(request);
      } catch (err: unknown) {
        return failed(
          'open_redirect_tool_error',
          err instanceof Error ? err.message : 'Open redirect detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
