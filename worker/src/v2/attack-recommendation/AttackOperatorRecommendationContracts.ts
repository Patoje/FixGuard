/**
 * Operator Attack Recommendation contracts (thin vertical slice)
 * Contract version: fixguard-attack-operator-recommendation/v0
 *
 * Deterministic A/B attack recommendations for human authorization.
 * Recommendations are advisory — never auto-execute.
 * suggestedFlags / commandSummary are safe DTOs (no secrets).
 */

import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import type { TechEcosystemProfile } from '../core/TechnologyContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { DefenseObservation } from '../test-validity/TestValidityContracts.js';

export type AttackOperatorRecommendationContractVersion =
  'fixguard-attack-operator-recommendation/v0';
export const ATTACK_OPERATOR_RECOMMENDATION_CONTRACT_VERSION: AttackOperatorRecommendationContractVersion =
  'fixguard-attack-operator-recommendation/v0';

export type OperatorRecommendationRank = 'A' | 'B';

export type OperatorRecommendationReasonKind = 'OBSERVED' | 'INFERRED';

/**
 * Safe capability params for operator display / later authorize+execute.
 * Values are strings/numbers/booleans only — never secrets or raw tokens.
 */
export type OperatorSuggestedFlags = Readonly<
  Record<string, string | number | boolean>
>;

export interface OperatorAttackRecommendation {
  readonly recommendationId: string;
  readonly rank: OperatorRecommendationRank;
  readonly capabilityKind: AttackCapabilityKind;
  readonly humanLabel: string;
  readonly suggestedFlags: OperatorSuggestedFlags;
  /** Safe one-line command / capability invocation summary (no secrets). */
  readonly commandSummary: string;
  /**
   * True when the capability is registered AND prerequisites for running are met.
   * False when capability_not_implemented or unmet preconditions (BYOT, JWT, etc.).
   * Never means auto-execute — humans still authorize.
   */
  readonly executable: boolean;
  readonly reasonKind: OperatorRecommendationReasonKind;
  readonly reason: string;
  /** Why this rank is preferred over the other candidate (deterministic). */
  readonly whyPreferred: string;
  readonly disabilityReason?: string;
  /** Linked advisory plan when one already exists for this capability+finding. */
  readonly planId?: string;
  readonly sourceFindingId?: string;
  readonly sourceFindingType?: string;
  readonly score: number;
}

export interface OperatorStackHints {
  readonly hasSpa?: boolean;
  readonly spaFramework?: TechEcosystemProfile['spaFramework'];
  readonly hasPhpLegacy?: boolean;
  readonly hasCms?: boolean;
  readonly cmsType?: TechEcosystemProfile['cmsType'];
  readonly hasVercel?: boolean;
  readonly hasNextJs?: boolean;
  readonly technologyNames?: readonly string[];
}

export interface OperatorPreconditions {
  readonly identityCount: number;
  readonly hasJwtIdentity: boolean;
  readonly hasCredentialedCorsSignal: boolean;
  readonly hasObservedParameter: boolean;
  readonly hasCredentialReference: boolean;
}

export interface AttackRecommendationServiceInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly finding?: Finding;
  readonly plan?: AttackPlan;
  readonly findings?: readonly Finding[];
  readonly plans?: readonly AttackPlan[];
  readonly stackHints?: OperatorStackHints;
  readonly preconditions: OperatorPreconditions;
  /** Capability kinds present in AttackCapabilityRegistry (registered ports). */
  readonly registeredCapabilities: ReadonlySet<AttackCapabilityKind>;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly generatedAt?: string;
  readonly investigationId?: string;
  /**
   * Optional DefenseObservations for the target (F3 foundation).
   * Blocking defenses soft-penalize spray-style capabilities — not a hard deny.
   */
  readonly defenseObservations?: readonly DefenseObservation[];
}

export interface AttackRecommendationServiceResult {
  readonly contractVersion: AttackOperatorRecommendationContractVersion;
  readonly kind: 'attack_operator_recommendation_set';
  readonly assessmentId: string;
  readonly scanId: string;
  readonly subjectFindingId?: string;
  readonly subjectPlanId?: string;
  readonly investigationId?: string;
  readonly recommendations: readonly OperatorAttackRecommendation[];
  readonly rulesApplied: readonly string[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly generatedAt: string;
}

export interface GetAttackRecommendationsResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly subjectFindingId?: string;
  readonly subjectPlanId?: string;
  readonly investigationId?: string;
  readonly recommendationCount: number;
  readonly recommendations: readonly OperatorAttackRecommendation[];
  readonly rulesApplied: readonly string[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly generatedAt: string;
}
