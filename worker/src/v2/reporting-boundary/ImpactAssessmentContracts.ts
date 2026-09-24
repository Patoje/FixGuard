/**
 * Milestone A12 — Impact Assessment Contracts
 * Contract version: fixguard-impact-assessment/v0
 *
 * Impact assessments are factual summaries derived from completed attack chains.
 * They MUST NOT speculate, invent evidence, or claim epistemic status above the
 * source chain's overallEpistemicStatus.
 *
 * Invariant: high-impact / impact_confirmed claims require chain VERIFIED.
 * If the chain is INFERRED, the impact assessment epistemicStatus is INFERRED.
 */

import type { EpistemicStatus } from '../attack-surface/AttackSurfaceContracts.js';
import type { ImpactLevel } from '../attack-chain/AttackChainContracts.js';
import {
  EPISTEMIC_RANK,
  HIGH_IMPACT_LEVELS,
  isHighImpactLevel,
} from '../attack-chain/AttackChainContracts.js';

export type ImpactAssessmentContractVersion = 'fixguard-impact-assessment/v0';
export const IMPACT_ASSESSMENT_CONTRACT_VERSION: ImpactAssessmentContractVersion =
  'fixguard-impact-assessment/v0';

export type { EpistemicStatus, ImpactLevel };
export { HIGH_IMPACT_LEVELS, isHighImpactLevel };

export interface ImpactAssessment {
  readonly contractVersion: ImpactAssessmentContractVersion;
  readonly kind: 'impact_assessment';
  readonly assessmentId: string;
  readonly chainId: string;
  readonly impactLevel: ImpactLevel;
  /** Plain factual description — no speculative severity or exploit claims. */
  readonly impactDescription: string;
  /** Evidence IDs grounding this assessment (from chain step evidence). */
  readonly evidenceBasis: readonly string[];
  readonly epistemicStatus: EpistemicStatus;
  readonly assessedAt: string;
}

/**
 * Cap an epistemic claim so it never exceeds the chain's overall status.
 */
export function capEpistemicToChain(
  claimed: EpistemicStatus,
  chainOverall: EpistemicStatus
): EpistemicStatus {
  if (EPISTEMIC_RANK[claimed] <= EPISTEMIC_RANK[chainOverall]) {
    return claimed;
  }
  return chainOverall;
}

/**
 * True when a VERIFIED high-impact claim is permitted for the given chain status.
 */
export function permitsVerifiedHighImpact(chainOverall: EpistemicStatus): boolean {
  return chainOverall === 'VERIFIED';
}

/**
 * Explicit epistemic badge text for adversarial HTML reports.
 * These strings MUST appear verbatim in rendered report sections.
 */
export function formatEpistemicBadge(status: EpistemicStatus): string {
  switch (status) {
    case 'VERIFIED':
      return '[VERIFIED]';
    case 'INFERRED':
      return '[INFERRED - NOT VERIFIED]';
    case 'REFUTED':
      return '[REFUTED - TARGET RESISTED]';
    case 'OBSERVED':
      return '[OBSERVED]';
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

const IMPACT_ASSESSMENT_KEYS = new Set([
  'contractVersion',
  'kind',
  'assessmentId',
  'chainId',
  'impactLevel',
  'impactDescription',
  'evidenceBasis',
  'epistemicStatus',
  'assessedAt',
]);

const IMPACT_LEVELS: ReadonlySet<string> = new Set([
  'information_exposure',
  'authentication_bypass',
  'authorization_bypass',
  'data_access',
  'privilege_escalation',
  'lateral_movement',
  'rce_demonstrated',
]);

const EPISTEMIC_STATUSES: ReadonlySet<string> = new Set([
  'OBSERVED',
  'INFERRED',
  'VERIFIED',
  'REFUTED',
]);

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isStrictSafeId(val: unknown): val is string {
  return typeof val === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(val);
}

export function validateImpactAssessment(value: unknown): value is ImpactAssessment {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Record<string, unknown>;
  const keys = Object.keys(raw);
  if (keys.length !== IMPACT_ASSESSMENT_KEYS.size) return false;
  for (const k of keys) {
    if (!IMPACT_ASSESSMENT_KEYS.has(k)) return false;
  }
  if (raw.contractVersion !== IMPACT_ASSESSMENT_CONTRACT_VERSION) return false;
  if (raw.kind !== 'impact_assessment') return false;
  if (!isStrictSafeId(raw.assessmentId)) return false;
  if (!isStrictSafeId(raw.chainId)) return false;
  if (typeof raw.impactLevel !== 'string' || !IMPACT_LEVELS.has(raw.impactLevel)) return false;
  if (typeof raw.impactDescription !== 'string') return false;
  if (raw.impactDescription.length < 1 || raw.impactDescription.length > 2000) return false;
  if (!Array.isArray(raw.evidenceBasis)) return false;
  for (const id of raw.evidenceBasis) {
    if (typeof id !== 'string' || id.length < 1 || id.length > 128) return false;
  }
  if (typeof raw.epistemicStatus !== 'string' || !EPISTEMIC_STATUSES.has(raw.epistemicStatus)) {
    return false;
  }
  if (!isStrictIsoTimestamp(raw.assessedAt)) return false;
  return true;
}
