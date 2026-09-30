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
  | 'credentialed_cors'
  | 'jwt_confusion'
  | 'sql_oracle'
  | 'parameter_reflection'
  | 'spa_surface_probe'
  | 'header_hardening_gap';

export type HypothesisEpistemicStatus = 'INFERRED' | 'OBSERVED' | 'RECOMMENDED';

export type HypothesisBlockReason =
  | 'missing_byot_identities'
  | 'missing_jwt_identity'
  | 'missing_parameter'
  | 'stack_policy_deprioritized'
  | 'none';

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
