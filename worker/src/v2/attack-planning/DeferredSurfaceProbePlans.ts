/**
 * F4.0 — advisory plans for surface probes that must not auto-run.
 * executable is always false. No HTTP.
 * Observed application routes get one ready read plan per capability.
 * The bare origin stays prerequisite_missing so the read loop does not
 * spend its step budget on https://domain/ again.
 */

import { isPublicStaticAssetUrl } from '../detection/PublicStaticAsset.js';
import { isUrlInsideAuthorizedScope } from '../investigation/ProbeInventory.js';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
  type AttackPlanGeneratorInput,
} from './AttackPlanContracts.js';

const ORIGIN_PROBES: readonly {
  readonly capability: AttackCapabilityKind;
  readonly title: string;
}[] = Object.freeze([
  { capability: 'cors_misconfiguration_probe', title: 'CORS misconfiguration probe' },
  { capability: 'security_header_probe', title: 'Security header probe' },
  { capability: 'open_redirect_probe', title: 'Open redirect probe' },
  { capability: 'information_disclosure_probe', title: 'Information disclosure probe' },
  { capability: 'graphql_surface_probe', title: 'GraphQL surface probe' },
  { capability: 'session_fixation_probe', title: 'Session fixation probe' },
]);

function planId(assessmentId: string, capability: string, sourceKey: string): string {
  let hash = 2166136261;
  const text = `${assessmentId}\u001f${capability}\u001f${sourceKey}`;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `plan_def_${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

function pathLooksLikeGraphql(pathname: string): boolean {
  return pathname.includes('/graphql') || pathname.includes('/query');
}

function advisoryPlan(input: {
  readonly generator: AttackPlanGeneratorInput;
  readonly capability: AttackCapabilityKind;
  readonly title: string;
  readonly sourceKey: string;
  readonly targetUrl: string;
  readonly reasoning: string;
  readonly createdAt: string;
  readonly status?: AttackPlan['status'];
  readonly stepStatus?: 'blocked' | 'ready';
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: planId(input.generator.assessmentId, input.capability, input.sourceKey),
    assessmentId: input.generator.assessmentId,
    scanId: input.generator.scanId,
    capability: input.capability,
    title: input.title,
    reasoning: input.reasoning,
    status: input.status ?? 'prerequisite_missing',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [
      {
        kind: 'observed_surface_signal',
        description: 'Advisory only. This plan does not perform HTTP.',
        satisfied: true,
        detail: `target=${input.targetUrl}`,
      },
    ],
    steps: [
      {
        stepId: `${input.sourceKey}_step_1`,
        ordinal: 1,
        title: 'Authorize probe',
        description: 'Human authorization is required before any request for this step.',
        status: input.stepStatus ?? 'blocked',
        requiredPermissions: ['activeValidation'],
      },
    ],
    targetUrl: input.targetUrl,
    planOrigin: 'observed_surface',
    lineage: { ...input.generator.lineage },
    createdAt: input.createdAt,
    executable: false,
  };
}

function eligibleApplicationUrl(
  rawUrl: string,
  spec: NonNullable<AttackPlanGeneratorInput['deferredSurfaceProbes']>,
  createdAt: string
): URL | null {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (hostname.length === 0 || isInternalOrSsrfTarget(hostname)) return null;
  const pathname = parsed.pathname.length > 0 ? parsed.pathname : '/';
  if (pathname === '/') return null;
  if (isPublicStaticAssetUrl(parsed.toString())) return null;
  const grant = spec.scopeGrant;
  if (!grant) return null;
  if (!isUrlInsideAuthorizedScope(grant, parsed.toString(), createdAt)) return null;
  return parsed;
}

export function buildDeferredSurfaceProbePlans(
  input: AttackPlanGeneratorInput,
  createdAt: string
): readonly AttackPlan[] {
  const spec = input.deferredSurfaceProbes;
  if (!spec || spec.originUrl.trim().length === 0) return Object.freeze([]);
  const plans: AttackPlan[] = [];
  for (const probe of ORIGIN_PROBES) {
    plans.push(
      advisoryPlan({
        generator: input,
        capability: probe.capability,
        title: probe.title,
        sourceKey: probe.capability,
        targetUrl: spec.originUrl,
        reasoning:
          'Recon finished. This surface probe stays a non-executing plan until that step is authorized.',
        createdAt,
      })
    );
  }
  const seenUrls = new Set<string>();
  for (const rawUrl of spec.applicationUrls ?? []) {
    const parsed = eligibleApplicationUrl(rawUrl, spec, createdAt);
    if (!parsed) continue;
    const pathname = parsed.pathname.length > 0 ? parsed.pathname : '/';
    const targetUrl = parsed.toString();
    if (seenUrls.has(targetUrl)) continue;
    seenUrls.add(targetUrl);
    for (const probe of ORIGIN_PROBES) {
      if (probe.capability === 'graphql_surface_probe' && !pathLooksLikeGraphql(pathname)) {
        continue;
      }
      if (
        probe.capability === 'session_fixation_probe' &&
        spec.sessionFixationSuppressed === true
      ) {
        continue;
      }
      plans.push(
        advisoryPlan({
          generator: input,
          capability: probe.capability,
          title: probe.title,
          sourceKey: `${probe.capability}\u001f${targetUrl}`,
          targetUrl,
          reasoning:
            'Observed application route. Read observation stays behind the existing authorization and execution gates.',
          createdAt,
          status: 'ready_for_authorization',
          stepStatus: 'ready',
        })
      );
    }
  }
  for (const pair of spec.cnamePairs ?? []) {
    if (pair.domain.trim().length === 0 || pair.target.trim().length === 0) continue;
    const sourceKey = `takeover_${pair.domain}_${pair.target}`;
    plans.push(
      advisoryPlan({
        generator: input,
        capability: 'subdomain_takeover_probe',
        title: 'Subdomain takeover probe',
        sourceKey,
        targetUrl: `https://${pair.domain}/`,
        reasoning: `Observed CNAME ${pair.domain} -> ${pair.target}. No HTTP until this step is authorized.`,
        createdAt,
      })
    );
  }
  return Object.freeze(plans);
}
