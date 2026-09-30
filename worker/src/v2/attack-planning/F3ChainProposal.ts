/**
 * F3 — Investigation follow-ups.
 *
 * Each proposer emits at most one advisory child through emitDependentChildPlan.
 * Writes and Server Actions stay recommendations (executable: false).
 * A chain step is appended only after a GET read actually ran, and its
 * epistemic status cannot rise above the source step or to VERIFIED.
 */

import {
  EPISTEMIC_RANK,
  type AttackChain,
  type AttackChainStepEvidence,
  type EpistemicStatus,
} from '../attack-chain/AttackChainContracts.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { ObservedFact } from '../observation/ObservedFactContracts.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
  type AttackPlanStatus,
  type AttackPrerequisite,
  type AttackStep,
} from './AttackPlanContracts.js';
import {
  emitDependentChildPlan,
  type EmitDependentChildPlanResult,
  type PriorStepProduction,
} from './AttackPlanDependencyService.js';

export interface F3IdentityRef {
  readonly identityId: string;
}

export interface F3ProposalRequest {
  readonly prior: PriorStepProduction;
  readonly fact?: ObservedFact;
  readonly identities: readonly F3IdentityRef[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
}

export interface SupabaseReadWriteProposal {
  readonly status: 'emitted';
  readonly readPlan: AttackPlan;
  readonly writeRecommendation: AttackPlan;
}

export type SupabaseReadWriteResult =
  | SupabaseReadWriteProposal
  | { readonly status: 'not_emitted'; readonly reasonCode: string };

export type RecordExecutedReadResult =
  | { readonly status: 'recorded'; readonly chain: AttackChain }
  | { readonly status: 'not_recorded'; readonly reasonCode: string };

const READ_CHAIN_CAPABILITIES = new Set<AttackCapabilityKind>([
  'auth_boundary_differential',
  'supabase_rls_read_confirm',
]);

const PARAMETER_FEED_SOURCES = new Set([
  'jsluice',
  'api_schema_discovery',
  'openapi',
  'byot_network_harvest',
]);

function notEmitted(reasonCode: string): EmitDependentChildPlanResult {
  return { status: 'not_emitted', reasonCode };
}

function isHttpSourceUrl(sourceUrl: string): boolean {
  try {
    const protocol = new URL(sourceUrl).protocol;
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

function identityCount(identities: readonly F3IdentityRef[]): number {
  const seen = new Set<string>();
  for (const identity of identities) {
    const id = identity.identityId.trim();
    if (id.length === 0 || seen.has(id)) continue;
    seen.add(id);
  }
  return seen.size;
}

function factReady(input: F3ProposalRequest, fact: ObservedFact): boolean {
  return (
    fact.assessmentId === input.lineage.assessmentId &&
    fact.scanId === input.lineage.scanId &&
    fact.epistemicStatus === 'OBSERVED' &&
    input.prior.producedFactIds.includes(fact.factId)
  );
}

function isIdParameter(name: string): boolean {
  return name === 'id' || name.endsWith('_id');
}

function tableFromRelation(value: string): string | null {
  const left = value.split('->')[0] ?? '';
  const table = left.split('.')[0] ?? '';
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(table)) return null;
  return table;
}

function childPlan(input: {
  readonly request: F3ProposalRequest;
  readonly fact: ObservedFact;
  readonly capability: AttackCapabilityKind;
  readonly planId: string;
  readonly stepId: string;
  readonly title: string;
  readonly reasoning: string;
  readonly status: AttackPlanStatus;
  readonly prerequisites: readonly AttackPrerequisite[];
  readonly parameterName?: string;
  readonly dependsOn?: readonly string[];
  readonly requiredCapabilityGained?: PriorStepProduction['capabilityGained'];
  readonly capabilityGained?: AttackPlan['capabilityGained'];
}): AttackPlan | null {
  if (!isHttpSourceUrl(input.fact.sourceUrl)) return null;
  const step: AttackStep = {
    stepId: input.stepId,
    ordinal: 1,
    title: input.title,
    description: input.reasoning,
    status: input.status === 'ready_for_authorization' ? 'ready' : 'blocked',
    requiredPermissions: ['activeValidation'],
  };
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: input.planId,
    assessmentId: input.request.lineage.assessmentId,
    scanId: input.request.lineage.scanId,
    capability: input.capability,
    title: input.title,
    reasoning: input.reasoning,
    status: input.status,
    blastRadius: 'single_endpoint',
    capabilityGained: input.capabilityGained ?? 'none',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: input.prerequisites,
    steps: [step],
    planOrigin: 'observed_surface',
    targetUrl: input.fact.sourceUrl,
    ...(input.parameterName !== undefined ? { parameterName: input.parameterName } : {}),
    dependsOn: input.dependsOn ?? [input.request.prior.planId],
    requiredFactIds: [input.fact.factId],
    ...(input.requiredCapabilityGained !== undefined
      ? { requiredCapabilityGained: input.requiredCapabilityGained }
      : {}),
    lineage: input.request.lineage,
    createdAt: input.request.createdAt,
    executable: false,
  };
}

function emitFactChild(
  request: F3ProposalRequest,
  child: AttackPlan | null
): EmitDependentChildPlanResult {
  if (!child) return notEmitted('source_scheme_not_http');
  return emitDependentChildPlan({ prior: request.prior, child });
}

/**
 * F3.A — Identity A plus an observed endpoint. Session B is not required.
 * The child is a GET auth-boundary read and may run in the read loop.
 */
export function proposeAuthBoundaryResourceRead(
  request: F3ProposalRequest
): EmitDependentChildPlanResult {
  const fact = request.fact;
  if (!fact) return notEmitted('prior_fact_missing');
  if (!factReady(request, fact)) return notEmitted('prior_fact_missing');
  if (fact.sourceUrl.trim().length === 0) return notEmitted('observed_endpoint_missing');
  if (!isHttpSourceUrl(fact.sourceUrl)) return notEmitted('source_scheme_not_http');
  if (identityCount(request.identities) < 1) return notEmitted('identity_a_missing');
  const hasIdentity: AttackPrerequisite = {
    kind: 'identity_present',
    description: 'Requires identity A. Session B is not required for this GET.',
    satisfied: true,
    detail: 'identity_count>=1',
  };
  return emitFactChild(
    request,
    childPlan({
      request,
      fact,
      capability: 'auth_boundary_differential',
      planId: `plan_f3a_${fact.factId}`,
      stepId: `step_f3a_${fact.factId}`,
      title: 'Read the observed endpoint as identity A',
      reasoning:
        'GET auth-boundary read of the observed endpoint. Advisory until authorized. Session B is not required.',
      status: 'ready_for_authorization',
      prerequisites: [hasIdentity],
      capabilityGained: 'read_authenticated',
    })
  );
}

/**
 * F3.B — IDOR read only for an object id harvested on identity A traffic.
 * Without session B the plan stays prerequisite_missing. Without the id, nothing is emitted.
 */
export function proposeSessionBDifferential(
  request: F3ProposalRequest
): EmitDependentChildPlanResult {
  const fact = request.fact;
  if (!fact || fact.factKind !== 'observed_object_id') {
    return notEmitted('observed_object_id_missing');
  }
  if (!factReady(request, fact)) return notEmitted('prior_fact_missing');
  if (fact.sourceLabel !== 'byot_network_harvest') {
    return notEmitted('object_id_not_from_harvest');
  }
  const hasSessionB = identityCount(request.identities) >= 2;
  const sessionB: AttackPrerequisite = {
    kind: 'identity_count_at_least_2',
    description: 'Requires session B in addition to identity A',
    satisfied: hasSessionB,
    detail: `identity_count=${identityCount(request.identities)}`,
  };
  return emitFactChild(
    request,
    childPlan({
      request,
      fact,
      capability: 'idor_read_differential',
      planId: `plan_f3b_${fact.factId}`,
      stepId: `step_f3b_${fact.factId}`,
      title: 'Differential read of the harvested object id',
      reasoning:
        'Advisory differential read of an object id harvested on identity A traffic. It does not run in the read loop.',
      status: hasSessionB ? 'ready_for_authorization' : 'prerequisite_missing',
      prerequisites: [sessionB],
      parameterName: fact.value,
      capabilityGained: 'read_escalated',
    })
  );
}

/**
 * F3.E — An id parameter or a table from jsluice, OpenAPI, or harvest
 * becomes one child with parameterName and dependsOn.
 */
export function proposeParameterFedProbe(
  request: F3ProposalRequest
): EmitDependentChildPlanResult {
  const fact = request.fact;
  if (!fact || !factReady(request, fact)) return notEmitted('parameter_not_observed');
  if (!fact.sourceLabel || !PARAMETER_FEED_SOURCES.has(fact.sourceLabel)) {
    return notEmitted('parameter_not_observed');
  }

  if (fact.factKind === 'observed_param' && isIdParameter(fact.value)) {
    const hasSessionB = identityCount(request.identities) >= 2;
    const sessionB: AttackPrerequisite = {
      kind: 'identity_count_at_least_2',
      description: 'Differential use of this id parameter needs session B',
      satisfied: hasSessionB,
    };
    return emitFactChild(
      request,
      childPlan({
        request,
        fact,
        capability: 'idor_read_differential',
        planId: `plan_f3e_${fact.factId}`,
        stepId: `step_f3e_${fact.factId}`,
        title: 'Probe fed by the observed id parameter',
        reasoning:
          'Child plan cites the observed id parameter. Without that parameter nothing is proposed.',
        status: hasSessionB ? 'ready_for_authorization' : 'prerequisite_missing',
        prerequisites: [sessionB],
        parameterName: fact.value,
      })
    );
  }

  if (fact.factKind === 'schema_relation') {
    const table = tableFromRelation(fact.value);
    if (!table) return notEmitted('parameter_not_observed');
    return emitFactChild(
      request,
      childPlan({
        request,
        fact,
        capability: 'supabase_rls_read_confirm',
        planId: `plan_f3e_${fact.factId}`,
        stepId: `step_f3e_${fact.factId}`,
        title: 'Read confirm fed by the observed table',
        reasoning: 'Child plan cites the observed table name. Without that table nothing is proposed.',
        status: 'ready_for_authorization',
        prerequisites: [],
        parameterName: table,
        capabilityGained: 'read_authenticated',
      })
    );
  }

  return notEmitted('parameter_not_observed');
}

/**
 * F3.D — Server Action stays a recommendation. The action id must be observed.
 * Invoking it needs approval of that step and must not enter the read loop.
 */
export function proposeServerActionRecommendation(
  request: F3ProposalRequest
): EmitDependentChildPlanResult {
  const fact = request.fact;
  if (!fact || fact.factKind !== 'observed_action_id') {
    return notEmitted('action_id_not_observed');
  }
  if (!factReady(request, fact)) return notEmitted('prior_fact_missing');
  const observed: AttackPrerequisite = {
    kind: 'parameter_present',
    description: 'Requires an observed action id. The id is not invented.',
    satisfied: true,
  };
  return emitFactChild(
    request,
    childPlan({
      request,
      fact,
      capability: 'next_server_action_diff',
      planId: `plan_f3d_${fact.factId}`,
      stepId: `step_f3d_${fact.factId}`,
      title: 'Server Action differential recommendation',
      reasoning:
        'Recommendation only. Executing it invokes the action and requires approval of this step.',
      status: 'ready_for_authorization',
      prerequisites: [observed],
      parameterName: fact.value,
      capabilityGained: 'active_validation',
    })
  );
}

/**
 * F3.C — Observed table, then a RLS read, then the write matrix as a recommendation.
 * The write is not executable and is not a read-loop step.
 */
export function proposeSupabaseReadThenWrite(
  request: F3ProposalRequest
): SupabaseReadWriteResult {
  const fact = request.fact;
  if (!fact || fact.factKind !== 'schema_relation' || !factReady(request, fact)) {
    return { status: 'not_emitted', reasonCode: 'observed_table_missing' };
  }
  const table = tableFromRelation(fact.value);
  if (!table) return { status: 'not_emitted', reasonCode: 'observed_table_missing' };

  const read = emitFactChild(
    request,
    childPlan({
      request,
      fact,
      capability: 'supabase_rls_read_confirm',
      planId: `plan_f3c_${fact.factId}`,
      stepId: `step_f3c_${fact.factId}`,
      title: 'Confirm RLS read of the observed table',
      reasoning: 'GET read of a table that was observed. Advisory until authorized.',
      status: 'ready_for_authorization',
      prerequisites: [],
      parameterName: table,
      capabilityGained: 'read_authenticated',
    })
  );
  if (read.status !== 'emitted') {
    return { status: 'not_emitted', reasonCode: read.reasonCode };
  }

  const writeHeld: AttackPrerequisite = {
    kind: 'identity_present',
    description: 'Write matrix stays a recommendation until a human authorizes that step',
    satisfied: false,
  };
  const writeRecommendation = childPlan({
    request,
    fact,
    capability: 'supabase_authz_write_matrix',
    planId: `plan_f3w_${fact.factId}`,
    stepId: `step_f3w_${fact.factId}`,
    title: 'Write matrix recommendation for the observed table',
    reasoning:
      'Recommendation only. The write does not run unless a human authorizes this step.',
    status: 'prerequisite_missing',
    prerequisites: [writeHeld],
    parameterName: table,
    dependsOn: [read.plan.planId],
    requiredCapabilityGained: 'read_authenticated',
    capabilityGained: 'active_validation',
  });
  if (!writeRecommendation) {
    return { status: 'not_emitted', reasonCode: 'source_scheme_not_http' };
  }

  return {
    status: 'emitted',
    readPlan: read.plan,
    writeRecommendation,
  };
}

function capEpistemic(source: EpistemicStatus, requested: EpistemicStatus | undefined): EpistemicStatus {
  const ceiling: EpistemicStatus =
    source === 'VERIFIED' || source === 'OBSERVED' ? 'OBSERVED' : source;
  const asked = requested ?? ceiling;
  if (EPISTEMIC_RANK[asked] > EPISTEMIC_RANK[ceiling]) return ceiling;
  return asked;
}

/**
 * Append one GET that already executed. Refuses writes, Server Actions, and
 * any epistemic status above the source step. Never records VERIFIED.
 */
export async function recordExecutedReadOnChain(
  service: AttackChainService,
  input: {
    readonly chainId: string;
    readonly assessmentId: string;
    readonly scanId: string;
    readonly stepId: string;
    readonly sourceStepId: string;
    readonly capabilityKind: AttackCapabilityKind;
    readonly outcome: 'succeeded' | 'refuted' | 'failed';
    readonly evidence: AttackChainStepEvidence;
    readonly recordedAt: string;
    readonly requestedEpistemicStatus?: EpistemicStatus;
  }
): Promise<RecordExecutedReadResult> {
  if (!READ_CHAIN_CAPABILITIES.has(input.capabilityKind)) {
    return { status: 'not_recorded', reasonCode: 'read_chain_capability_denied' };
  }
  if (input.sourceStepId.trim().length === 0) {
    return { status: 'not_recorded', reasonCode: 'source_step_missing' };
  }
  const existing = await service.getChain(input.chainId);
  if (!existing) return { status: 'not_recorded', reasonCode: 'chain_not_found' };
  const source = existing.steps.find((step) => step.stepId === input.sourceStepId);
  if (!source) return { status: 'not_recorded', reasonCode: 'source_step_missing' };

  const chain = await service.appendExecutedStep({
    chainId: input.chainId,
    assessmentId: input.assessmentId,
    scanId: input.scanId,
    stepId: input.stepId,
    sourceStepId: input.sourceStepId,
    capabilityKind: input.capabilityKind,
    epistemicStatus: capEpistemic(source.epistemicStatus, input.requestedEpistemicStatus),
    capabilityGained: 'read_authenticated',
    outcome: input.outcome,
    evidence: input.evidence,
    recordedAt: input.recordedAt,
  });
  return { status: 'recorded', chain };
}
