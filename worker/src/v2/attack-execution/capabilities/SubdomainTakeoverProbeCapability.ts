/**
 * Subdomain takeover probe capability — wraps SubdomainTakeoverDetectionService.
 * Succeeds on vulnerability_detected or potential_weakness; never synthetic success.
 *
 * AttackPlan carries only targetUrl (the subdomain), not the CNAME target observed
 * during recon — DeferredSurfaceProbePlans has no structured field for it. Rather than
 * parse the free-text plan.reasoning, this re-resolves the CNAME live at execute time,
 * which is also the more honest OBSERVED signal (the CNAME may have changed since the
 * plan was minted). No CNAME observed now -> refuted, not fabricated.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import { runSubdomainTakeoverDetection } from '../../detection/SubdomainTakeoverDetectionService.js';
import {
  DETECTION_CONTRACT_VERSION,
  type SubdomainTakeoverDetectionRequest,
  type SubdomainTakeoverDetectionResult,
  type IdorHttpProbeTransport,
} from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../../recon/adapters/AdapterPreflightPipeline.js';

export type CnameResolver = (host: string) => Promise<readonly string[]>;

const defaultCnameResolver: CnameResolver = async (host) => {
  const dns = await import('node:dns/promises');
  try {
    return await dns.resolveCname(host);
  } catch {
    return [];
  }
};

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
  result: SubdomainTakeoverDetectionResult,
  stepId: string
): AttackCapabilityExecutionResult {
  switch (result.status) {
    case 'vulnerability_detected':
    case 'potential_weakness':
      return succeeded(
        result.reasonCode,
        'Subdomain takeover observed by detection service',
        `ev_takeover_${stepId}`
      );
    case 'secure_target_abstained':
      return refuted(result.reasonCode, 'No subdomain takeover observed; target abstained');
    case 'pending_human_review':
      return failed(
        result.reasonCode,
        'Subdomain takeover observed but pending human review — not confirmed'
      );
    case 'preflight_denied':
      return failed(result.reasonCode, result.error?.safeMessage ?? 'Subdomain takeover probe preflight denied');
    case 'unexpected_failure':
      return failed(result.reasonCode, result.error?.safeMessage ?? `Subdomain takeover probe status: ${result.status}`);
    default: {
      const _exhaustive: never = result.status;
      return failed('subdomain_takeover_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
    }
  }
}

export interface SubdomainTakeoverProbeCapabilityOptions {
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly cnameResolver?: CnameResolver;
}

/** Creates subdomain_takeover_probe AttackCapabilityPort. */
export function createSubdomainTakeoverProbeCapability(
  options?: SubdomainTakeoverProbeCapabilityOptions
): AttackCapabilityPort {
  const normalized = options ?? {};
  const resolveCname = normalized.cnameResolver ?? defaultCnameResolver;

  return {
    capability: 'subdomain_takeover_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('subdomain_takeover_target_missing', 'Subdomain takeover probe requires a target URL');
      }

      const verifiedAuthorizationDecision = ctx.verifiedAuthorizationDecision;
      if (!verifiedAuthorizationDecision) {
        return failed(
          'subdomain_takeover_authorization_missing',
          'Subdomain takeover probe requires verifiedAuthorizationDecision'
        );
      }

      let subdomain: string;
      try {
        subdomain = new URL(ctx.targetUrl).hostname;
      } catch {
        return failed('subdomain_takeover_invalid_target_url', 'Subdomain takeover probe target URL is invalid');
      }

      let cnameTargets: readonly string[];
      try {
        cnameTargets = await resolveCname(subdomain);
      } catch {
        cnameTargets = [];
      }
      const cnameTarget = cnameTargets[0];
      if (!cnameTarget || cnameTarget.trim().length === 0) {
        return refuted(
          'subdomain_takeover_no_cname_observed',
          'No CNAME record observed for this subdomain at probe time'
        );
      }

      const lineage = ctx.plan.lineage;
      const request: SubdomainTakeoverDetectionRequest = {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'subdomain_takeover_detection_request',
        detectionId: `det_takeover_${ctx.step.stepId}`,
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationGrantId: lineage.authorizationGrantId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        actorId: lineage.actorId,
        verifiedAuthorizationDecision,
        scopeGrant: ctx.scopeGrant,
        subdomain,
        cnameTarget,
        endpointUrl: ctx.targetUrl,
        ...(normalized.transport ? { transport: normalized.transport } : {}),
        ...(normalized.dnsResolver ? { dnsResolver: normalized.dnsResolver } : {}),
        ...(ctx.dnsResolver ? { dnsResolver: ctx.dnsResolver } : {}),
        ...(ctx.transport ? { transport: ctx.transport } : {}),
      };

      let result: SubdomainTakeoverDetectionResult;
      try {
        result = await runSubdomainTakeoverDetection(request);
      } catch (err: unknown) {
        return failed(
          'subdomain_takeover_tool_error',
          err instanceof Error ? err.message : 'Subdomain takeover detection service threw'
        );
      }

      return mapResult(result, ctx.step.stepId);
    },
  };
}
