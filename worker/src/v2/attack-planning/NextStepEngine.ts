/**
 * F2.1 — Single next-step engine.
 *
 * After one observed read fact, propose one advisory child plan.
 * Emission goes through emitDependentChildPlan. The child stays executable: false.
 * Cancel stops the proposal loop before a plan is emitted.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { ObservedFactKind } from '../observation/ObservedFactContracts.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
} from './AttackPlanContracts.js';
import {
  emitDependentChildPlan,
  type EmitDependentChildPlanResult,
  type PriorStepProduction,
} from './AttackPlanDependencyService.js';

export interface NextStepFact {
  readonly factId: string;
  readonly factKind: ObservedFactKind;
}

export interface NextStepRequest {
  readonly prior: PriorStepProduction;
  readonly fact?: NextStepFact;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
  readonly cancelled?: boolean;
}

function notEmitted(reasonCode: string): EmitDependentChildPlanResult {
  return { status: 'not_emitted', reasonCode };
}

function allowedReadCapability(kind: ObservedFactKind): AttackCapabilityKind | null {
  if (kind === 'anon_session_get_delta') return 'auth_boundary_differential';
  if (kind === 'schema_relation') return 'supabase_rls_read_confirm';
  return null;
}

function capabilityForGain(
  gained: PriorStepProduction['capabilityGained']
): AttackCapabilityKind | null {
  if (gained === 'read_authenticated') return 'auth_boundary_differential';
  return null;
}

function buildAdvisoryChild(input: {
  readonly prior: PriorStepProduction;
  readonly fact: NextStepFact;
  readonly capability: AttackCapabilityKind;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
  readonly requiredCapabilityGained?: PriorStepProduction['capabilityGained'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: `plan_next_${input.fact.factId}`,
    assessmentId: input.lineage.assessmentId,
    scanId: input.lineage.scanId,
    capability: input.capability,
    title: 'Advisory read follow-up',
    reasoning:
      'One advisory child bound to the observed read fact. It stays non-executing until a human authorizes that step.',
    status: 'prerequisite_missing',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [],
    steps: [
      {
        stepId: `step_next_${input.fact.factId}`,
        ordinal: 1,
        title: 'Authorized read',
        description: 'GET-class read proposed for human authorization. This plan does not execute it.',
        status: 'blocked',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    dependsOn: [input.prior.planId],
    requiredFactIds: [input.fact.factId],
    ...(input.requiredCapabilityGained !== undefined
      ? { requiredCapabilityGained: input.requiredCapabilityGained }
      : {}),
    lineage: input.lineage,
    createdAt: input.createdAt,
    executable: false,
  };
}

/**
 * Propose at most one advisory child.
 * No produced read fact → nothing is emitted.
 */
export function proposeNextAdvisoryStep(input: NextStepRequest): EmitDependentChildPlanResult {
  const candidates: AttackPlan[] = [];
  if (!input.cancelled && input.fact) {
    const factCapability = allowedReadCapability(input.fact.factKind);
    if (!factCapability) {
      return notEmitted('read_fact_kind_not_allowed');
    }
    const gainCapability = capabilityForGain(input.prior.capabilityGained);
    if (gainCapability && gainCapability !== factCapability) {
      return notEmitted('next_step_ambiguous');
    }
    candidates.push(
      buildAdvisoryChild({
        prior: input.prior,
        fact: input.fact,
        capability: factCapability,
        lineage: input.lineage,
        createdAt: input.createdAt,
        ...(gainCapability ? { requiredCapabilityGained: input.prior.capabilityGained } : {}),
      })
    );
  }

  for (const child of candidates) {
    if (input.cancelled) {
      return notEmitted('cancelled');
    }
    return emitDependentChildPlan({ prior: input.prior, child });
  }

  if (input.cancelled) {
    return notEmitted('cancelled');
  }
  return notEmitted('prior_fact_missing');
}
