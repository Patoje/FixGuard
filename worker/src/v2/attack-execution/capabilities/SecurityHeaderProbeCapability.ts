/**
 * Security header probe capability — wraps SecurityHeaderDetectionService.
 * Passive read-only check. Succeeds only on potential_weakness (missing
 * headers observed); never synthetic success.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runSecurityHeaderDetection } from '../../detection/SecurityHeaderDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type SecurityHeaderDetectionRequest,
  type SecurityHeaderDetectionResult,
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
  result: SecurityHeaderDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'potential_weakness':
      return succeeded(
        result.reasonCode,
        'Missing security headers observed by detection service',
        `ev_hdr_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No missing security headers observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Security header weakness observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Security header probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `Security header probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('security_header_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface SecurityHeaderProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

/** Creates security_header_probe AttackCapabilityPort. */
export function createSecurityHeaderProbeCapability(
  options?: SecurityHeaderProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};

  return {
    capability: 'security_header_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('security_header_target_missing', 'Security header probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'security_header_authorization_missing',
          'Security header probe requires verifiedAuthorizationDecision'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: SecurityHeaderDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'security_header_detection_request',
        detectionId: `det_hdr_${ctx.step.stepId}`,
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

      let result: SecurityHeaderDetectionResult;
      try {
        result = await runSecurityHeaderDetection(request);
      } catch (err: unknown) {
        return failed(
          'security_header_tool_error',
          err instanceof Error ? err.message : 'Security header detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
