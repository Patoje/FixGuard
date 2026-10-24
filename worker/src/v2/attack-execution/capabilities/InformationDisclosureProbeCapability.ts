/**
 * Information disclosure probe capability — wraps
 * InformationDisclosureDetectionService. Passive read-only check. Succeeds
 * only on potential_weakness (a disclosure observed); never synthetic
 * success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runInformationDisclosureDetection } from '../../detection/InformationDisclosureDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type InformationDisclosureDetectionRequest,
  type InformationDisclosureDetectionResult,
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
  result: InformationDisclosureDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'potential_weakness':
      return succeeded(
        result.reasonCode,
        'Information disclosure observed by detection service',
        `ev_info_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No information disclosure observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Information disclosure observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Information disclosure probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `Information disclosure probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('information_disclosure_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface InformationDisclosureProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates information_disclosure_probe AttackCapabilityPort. */
export function createInformationDisclosureProbeCapability(
  options?: InformationDisclosureProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'information_disclosure_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('information_disclosure_target_missing', 'Information disclosure probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'information_disclosure_authorization_missing',
          'Information disclosure probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: InformationDisclosureDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'information_disclosure_detection_request',
        detectionId: `det_info_${ctx.step.stepId}`,
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

      let result: InformationDisclosureDetectionResult;
      try {
        result = await runInformationDisclosureDetection(request);
      } catch (err: unknown) {
        return failed(
          'information_disclosure_tool_error',
          err instanceof Error ? err.message : 'Information disclosure detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
