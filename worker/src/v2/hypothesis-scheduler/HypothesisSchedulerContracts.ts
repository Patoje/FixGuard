/**
 * Etapa 2 · F2 — HypothesisScheduler contracts (thin).
 * ASG / findings / fingerprint → ranked SecurityHypothesis.
 * Never auto-executes. Humans authorize AttackPlan execute separately.
 */

export type HypothesisSchedulerContractVersion = 'fixguard-hypothesis-scheduler/v0';
export const HYPOTHESIS_SCHEDULER_CONTRACT_VERSION: HypothesisSchedulerContractVersion =
  'fixguard-hypothesis-scheduler/v0';

export type SecurityHypothesisKind =
  | 'idor_differential'
  | 'auth_bypass'
  | 'auth_boundary_differential'
  | 'supabase_rls_read_confirm'
  | 'credentialed_cors'
  | 'jwt_confusion'
  | 'sql_oracle'
  | 'parameter_reflection'
  | 'graphql_surface_probe'
  | 'spa_surface_probe'
  | 'header_hardening_gap';

export type HypothesisEpistemicStatus = 'INFERRED' | 'OBSERVED' | 'RECOMMENDED';

export type HypothesisBlockReason =
  | 'missing_byot_identities'
  | 'missing_jwt_identity'
  | 'missing_parameter'
  | 'stack_policy_deprioritized'
  | 'none';

export type HypothesisLifecycleState =
  | 'candidate'
  | 'supported'
  | 'weakened'
  | 'refuted'
  | 'validated'
  | 'confirmed'
  | 'inconclusive'
  | 'exhausted';

export type HypothesisPriorityBand = 'critical' | 'high' | 'medium' | 'low';

export interface SecurityHypothesis {
  readonly contractVersion: HypothesisSchedulerContractVersion;
  readonly kind: 'security_hypothesis';
  readonly hypothesisId: string;
  readonly hypothesisKind: SecurityHypothesisKind;
  readonly title: string;
  readonly epistemicStatus: HypothesisEpistemicStatus;
  readonly score: number;
  readonly rationale: string;
  readonly sourceFindingIds: readonly string[];
  readonly suggestedCapability?: string;
  readonly blocked: boolean;
  readonly blockReason: HypothesisBlockReason;
  readonly blockDetail?: string;
  /** Sub-hypothesis to pursue when blocked (e.g. obtain BYOT). */
  readonly subHypothesis?: {
    readonly hypothesisKind: SecurityHypothesisKind | 'obtain_byot_identities';
    readonly title: string;
    readonly rationale: string;
  };

  /** Block B — Lifecycle state and deterministic feedback fields */
  readonly createdAt?: string;
  readonly state?: HypothesisLifecycleState;
  readonly targetUrl?: string;
  readonly normalizedRoutePattern?: string;
  readonly parameterName?: string;
  readonly priorityBand?: HypothesisPriorityBand;
  readonly explanation?: readonly string[];
  readonly supportingEvidence?: readonly string[];
  readonly contradictingEvidence?: readonly string[];
  readonly dependencies?: {
    readonly requiresAuth: boolean;
    readonly requiresSecondaryAuth: boolean;
    readonly requiresParameter: boolean;
    readonly satisfied: boolean;
    readonly blockReason: HypothesisBlockReason;
    readonly blockDetail?: string;
  };
  readonly investigationCount?: number;
  readonly lastTestedAt?: string;
  readonly nextRecommendedAction?: string;
  /** Preserved raw object IDs for parameterized routes (e.g. ['1', '2', '3']). */
  readonly observedObjectIds?: readonly string[];
  /** Preserved individual target URLs matching the structural route. */
  readonly candidateTargetUrls?: readonly string[];
  readonly originatingObservation?: {
    readonly observationId?: string;
    readonly sourceKind: string;
    readonly summary: string;
  };
}

export interface HypothesisSchedulerStackHints {
  readonly hasSpa?: boolean;
  readonly hasVercel?: boolean;
  readonly hasNextJs?: boolean;
  readonly hasSupabase?: boolean;
  readonly hasPostgrest?: boolean;
  readonly technologyNames?: readonly string[];
}

export interface HypothesisSchedulerInput {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly findings: readonly {
    readonly id: string;
    readonly type: string;
    readonly metadataKind?: string;
    readonly target?: string;
  }[];
  readonly asgNodeKinds?: readonly string[];
  readonly stackHints?: HypothesisSchedulerStackHints;
  readonly identityCount: number;
  readonly hasJwtIdentity: boolean;
  /** True when an OBSERVED parameter exists. Surface SQL stays blocked when absent. */
  readonly hasObservedParameter?: boolean;
  readonly maxHypotheses?: number;
}

export interface HypothesisSchedulerResult {
  readonly contractVersion: HypothesisSchedulerContractVersion;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly rulesApplied: readonly string[];
  readonly generatedAt: string;
}
