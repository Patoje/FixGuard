/**
 * Milestone A6 — Attack Chain Tracker Contracts
 * Contract version: fixguard-attack-chain/v0
 *
 * Attack chains are hypotheses that aggregate executed-step evidence.
 * They MUST NOT invent steps, inflate epistemic status, or claim impact
 * beyond what recorded step outcomes support.
 *
 * Epistemic aggregation (min):
 *   REFUTED < INFERRED < OBSERVED < VERIFIED
 * Any REFUTED step forces overallEpistemicStatus=REFUTED and status=refuted.
 * Any INFERRED step (with no lower) forces overall INFERRED even if others are VERIFIED.
 */

import type { EpistemicStatus } from '../attack-surface/AttackSurfaceContracts.js';
import type { AttackCapabilityKind, CapabilityGained } from '../attack-planning/AttackPlanContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';

export type AttackChainContractVersion = 'fixguard-attack-chain/v0';
export const ATTACK_CHAIN_CONTRACT_VERSION: AttackChainContractVersion = 'fixguard-attack-chain/v0';

export type { EpistemicStatus };

export type ChainObjectiveKind =
  | 'data_access'
  | 'authentication_bypass'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'information_disclosure';

export type AttackChainStatus =
  | 'hypothesis'
  | 'partially_validated'
  | 'fully_validated'
  | 'refuted'
  | 'abandoned';

/**
 * Observed/claimed impact class grounded in validated chain evidence.
 * Never auto-assigned Critical/High severity labels.
 */
export type ImpactLevel =
  | 'information_exposure'
  | 'authentication_bypass'
  | 'authorization_bypass'
  | 'data_access'
  | 'privilege_escalation'
  | 'lateral_movement'
  | 'rce_demonstrated';

export type AttackChainStepOutcome = 'succeeded' | 'refuted' | 'failed';

/**
 * Safe evidence summary attached to a chain step.
 * No raw payloads, secrets, or executable fields.
 */
export interface AttackChainStepEvidence {
  readonly evidenceId?: string;
  readonly reasonCode: string;
  readonly safeMessage: string;
  readonly recordedAt: string;
}

export interface AttackChainStep {
  readonly stepId: string;
  readonly sequence: number;
  readonly capabilityKind: AttackCapabilityKind;
  readonly epistemicStatus: EpistemicStatus;
  readonly evidence: AttackChainStepEvidence;
  readonly capabilityGained: CapabilityGained;
  readonly outcome: AttackChainStepOutcome;
  /** Prior step this depends on (chain linkage); omitted for the first step. */
  readonly sourceStepId?: string;
}

export interface AttackChain {
  readonly contractVersion: AttackChainContractVersion;
  readonly kind: 'attack_chain';
  readonly chainId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hypothesis: string;
  readonly objectiveKind: ChainObjectiveKind;
  readonly steps: readonly AttackChainStep[];
  readonly overallEpistemicStatus: EpistemicStatus;
  readonly status: AttackChainStatus;
  readonly impactLevel: ImpactLevel;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
  readonly completedAt?: string;
}

export interface InitAttackChainHypothesisInput {
  readonly chainId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hypothesis: string;
  readonly objectiveKind: ChainObjectiveKind;
  readonly impactLevel: ImpactLevel;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt?: string;
}

export interface AppendAttackChainStepInput {
  readonly chainId: string;
  /** Must match the chain's assessmentId — cross-assessment injection fails closed. */
  readonly assessmentId: string;
  /** Must match the chain's scanId — cross-scan injection fails closed. */
  readonly scanId: string;
  readonly stepId: string;
  readonly capabilityKind: AttackCapabilityKind;
  readonly epistemicStatus: EpistemicStatus;
  readonly evidence: AttackChainStepEvidence;
  readonly capabilityGained: CapabilityGained;
  readonly outcome: AttackChainStepOutcome;
  readonly sourceStepId?: string;
  readonly recordedAt?: string;
}

export interface RecordAttackChainStepOutcomeInput {
  readonly chainId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly stepId: string;
  readonly outcome: AttackChainStepOutcome;
  readonly epistemicStatus?: EpistemicStatus;
  readonly evidence?: AttackChainStepEvidence;
  readonly recordedAt?: string;
}

export interface GetAttackChainsResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly chainCount: number;
  readonly chains: readonly AttackChain[];
  readonly lineage: AuthorizedExecutionLineageTuple;
}

/**
 * Epistemic rank for min() aggregation.
 * Choice: REFUTED is strictly lowest so it can never be treated as VERIFIED.
 * Order: REFUTED < INFERRED < OBSERVED < VERIFIED
 */
export const EPISTEMIC_RANK: Readonly<Record<EpistemicStatus, number>> = {
  REFUTED: 0,
  INFERRED: 1,
  OBSERVED: 2,
  VERIFIED: 3,
};

export function minEpistemicStatus(
  statuses: readonly EpistemicStatus[]
): EpistemicStatus {
  if (statuses.length === 0) {
    // Empty chain is an unverified hypothesis — never claim OBSERVED/VERIFIED.
    return 'INFERRED';
  }
  let minRank = EPISTEMIC_RANK.VERIFIED;
  let minStatus: EpistemicStatus = 'VERIFIED';
  for (const status of statuses) {
    const rank = EPISTEMIC_RANK[status];
    if (rank < minRank) {
      minRank = rank;
      minStatus = status;
    }
  }
  return minStatus;
}

/**
 * Pure status recalculation from recorded steps.
 *
 * Invariants:
 * - failed/refuted steps are never skipped or discarded
 * - fully_validated ONLY when every step outcome is succeeded AND ≥2 steps
 *   (a single success is partial progress on a multi-step hypothesis)
 * - any refuted/failed outcome → refuted
 */
export function recalculateAttackChainStatus(
  steps: readonly AttackChainStep[],
  previousStatus: AttackChainStatus
): AttackChainStatus {
  if (previousStatus === 'abandoned') {
    return 'abandoned';
  }
  if (steps.length === 0) {
    return 'hypothesis';
  }

  let hasSucceeded = false;
  let hasRefutedOrFailed = false;
  for (const step of steps) {
    if (step.outcome === 'refuted' || step.outcome === 'failed') {
      hasRefutedOrFailed = true;
    } else if (step.outcome === 'succeeded') {
      hasSucceeded = true;
    }
  }

  if (hasRefutedOrFailed) {
    return 'refuted';
  }

  const allSucceeded = steps.every((s) => s.outcome === 'succeeded');
  if (allSucceeded && steps.length >= 2) {
    return 'fully_validated';
  }

  if (hasSucceeded || allSucceeded) {
    return 'partially_validated';
  }

  return 'hypothesis';
}

export function recalculateOverallEpistemicStatus(
  steps: readonly AttackChainStep[]
): EpistemicStatus {
  return minEpistemicStatus(steps.map((s) => s.epistemicStatus));
}

/**
 * Pure recalculation of derived chain fields after step mutation.
 * Does not invent steps or inflate epistemic status.
 */
export function recalculateAttackChain(chain: AttackChain, nowIso: string): AttackChain {
  const overallEpistemicStatus = recalculateOverallEpistemicStatus(chain.steps);
  const status = recalculateAttackChainStatus(chain.steps, chain.status);

  const base: AttackChain = {
    contractVersion: chain.contractVersion,
    kind: chain.kind,
    chainId: chain.chainId,
    assessmentId: chain.assessmentId,
    scanId: chain.scanId,
    hypothesis: chain.hypothesis,
    objectiveKind: chain.objectiveKind,
    steps: chain.steps,
    overallEpistemicStatus,
    status,
    impactLevel: chain.impactLevel,
    lineage: chain.lineage,
    createdAt: chain.createdAt,
  };

  if (status === 'fully_validated' || status === 'refuted' || status === 'abandoned') {
    return {
      ...base,
      completedAt: chain.completedAt ?? nowIso,
    };
  }

  return base;
}
