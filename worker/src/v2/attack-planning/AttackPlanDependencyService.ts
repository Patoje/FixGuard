/**
 * F0.2 — Child attack-plan emission.
 * A child plan is created only when the prior step produced the cited fact
 * or capability. Plans stay advisory (executable: false).
 */

import {
  isCapabilityGained,
  type AttackPlan,
  type CapabilityGained,
} from './AttackPlanContracts.js';

export type EmitDependentChildPlanResult =
  | { readonly status: 'emitted'; readonly plan: AttackPlan }
  | { readonly status: 'not_emitted'; readonly reasonCode: string };

export interface PriorStepProduction {
  readonly planId: string;
  readonly producedFactIds: readonly string[];
  readonly capabilityGained: CapabilityGained;
}

function copyStringList(values: readonly string[] | undefined): readonly string[] | undefined {
  if (!values) return undefined;
  return Object.freeze(values.map((value) => value));
}

function copyPlan(plan: AttackPlan): AttackPlan {
  return {
    contractVersion: plan.contractVersion,
    kind: 'attack_plan',
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    scanId: plan.scanId,
    capability: plan.capability,
    title: plan.title,
    reasoning: plan.reasoning,
    status: plan.status,
    blastRadius: plan.blastRadius,
    capabilityGained: plan.capabilityGained,
    sourceFindingIds: Object.freeze([...plan.sourceFindingIds]),
    sourceFindingTypes: Object.freeze([...plan.sourceFindingTypes]),
    prerequisites: Object.freeze(plan.prerequisites.map((item) => ({ ...item }))),
    steps: Object.freeze(plan.steps.map((step) => ({
      ...step,
      requiredPermissions: Object.freeze([...step.requiredPermissions]),
    }))),
    ...(plan.targetUrl !== undefined ? { targetUrl: plan.targetUrl } : {}),
    ...(plan.parameterName !== undefined ? { parameterName: plan.parameterName } : {}),
    ...(plan.planOrigin !== undefined ? { planOrigin: plan.planOrigin } : {}),
    ...(plan.sourceDraftIds !== undefined
      ? { sourceDraftIds: Object.freeze([...plan.sourceDraftIds]) }
      : {}),
    ...(plan.dependsOn !== undefined ? { dependsOn: copyStringList(plan.dependsOn) } : {}),
    ...(plan.requiredCapabilityGained !== undefined
      ? { requiredCapabilityGained: plan.requiredCapabilityGained }
      : {}),
    ...(plan.requiredFactIds !== undefined
      ? { requiredFactIds: copyStringList(plan.requiredFactIds) }
      : {}),
    lineage: { ...plan.lineage },
    createdAt: plan.createdAt,
    executable: false,
  };
}

function nonEmptyStrings(values: readonly string[] | undefined): boolean {
  if (!values) return true;
  return values.every((value) => typeof value === 'string' && value.length > 0);
}

/**
 * Emit a child plan only when `dependsOn` cites the prior plan and that step
 * produced every required fact or the required capability.
 * Missing dependency evidence does not emit a plan.
 */
export function emitDependentChildPlan(input: {
  readonly prior: PriorStepProduction;
  readonly child: AttackPlan;
}): EmitDependentChildPlanResult {
  if (input.child.executable !== false) {
    return { status: 'not_emitted', reasonCode: 'child_not_advisory' };
  }
  if (!isCapabilityGained(input.prior.capabilityGained)) {
    return { status: 'not_emitted', reasonCode: 'invalid_prior_capability' };
  }
  if (input.prior.planId.trim().length === 0) {
    return { status: 'not_emitted', reasonCode: 'dependency_not_declared' };
  }
  const dependsOn = input.child.dependsOn ?? [];
  if (!dependsOn.includes(input.prior.planId)) {
    return { status: 'not_emitted', reasonCode: 'dependency_not_declared' };
  }
  if (!nonEmptyStrings(input.child.requiredFactIds) || !nonEmptyStrings(dependsOn)) {
    return { status: 'not_emitted', reasonCode: 'invalid_dependency_ids' };
  }
  const requiredFacts = input.child.requiredFactIds ?? [];
  const requiredCapability = input.child.requiredCapabilityGained;
  if (requiredFacts.length === 0 && requiredCapability === undefined) {
    return { status: 'not_emitted', reasonCode: 'dependency_requirement_missing' };
  }
  const factsSatisfied =
    requiredFacts.length > 0 &&
    requiredFacts.every((factId) => input.prior.producedFactIds.includes(factId));
  const capabilitySatisfied =
    requiredCapability !== undefined &&
    requiredCapability === input.prior.capabilityGained;
  if (requiredFacts.length > 0 && requiredCapability !== undefined) {
    if (!factsSatisfied || !capabilitySatisfied) {
      return { status: 'not_emitted', reasonCode: 'dependency_not_produced' };
    }
  } else if (!factsSatisfied && !capabilitySatisfied) {
    return { status: 'not_emitted', reasonCode: 'dependency_not_produced' };
  }
  return { status: 'emitted', plan: copyPlan(input.child) };
}
