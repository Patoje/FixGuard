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
  | 'header_hardening_gap'
  /**
   * P1 (recon-first pivot) — recon/classification gap hypotheses. These are
   * not vulnerability hypotheses: they recommend an investigation step
   * (always a passive/classification capability, never an active probe)
   * that would reduce what's still unknown about the target. Scheduled
   * with epistemicStatus 'RECOMMENDED'.
   */
  | 'endpoint_classification_gap'
  | 'technology_unconfirmed'
  | 'auth_boundary_unmapped';

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

/**
 * ADR-013 (2026-10-24): hypothesis/capability names that represent active,
 * injection- or identity-differential-style confirmation. These are no
 * longer treated as FixGuard's own "next actionable step" — they remain
 * visible (useful provenance for a future manual handoff to Parrot) but are
 * tagged `deferredToManualValidation: true` and excluded from automatic
 * recommendation boosting. Extends ADR-013's explicit 6-detector list to the
 * two capabilities (`supabase_rls_read_confirm`, `graphql_auth_delta`) that
 * share the same read_authenticated/read_escalated identity-differential
 * shape in `InvestigationRuntimeCoordinator`'s existing blast-radius
 * classification, plus the write/state-changing capabilities that were
 * already gated behind `AttackExecutionService` and never auto-suggested.
 */
const DEFERRED_TO_MANUAL_VALIDATION_NAMES: ReadonlySet<string> = new Set([
  // Hypothesis kinds (HypothesisSchedulerService.schedule)
  'idor_differential',
  'auth_bypass',
  'auth_boundary_differential',
  'credentialed_cors',
  'jwt_confusion',
  'sql_oracle',
  'parameter_reflection',
  'supabase_rls_read_confirm',
  // Capability names (InvestigationRuntimeCoordinator / AttackPlan.capability)
  'idor_read_differential',
  'auth_bypass_probe',
  'cors_misconfiguration_probe',
  'cors_chain_exploit',
  'jwt_alg_none_probe',
  'sql_oracle_advancement',
  'sql_injection_verification',
  'parameter_reflection_probe',
  'open_redirect_probe',
  'graphql_auth_delta',
  'nuclei_xss_scan',
  'lfi_path_traversal',
  'credential_reuse',
  'supabase_rls_write_probe',
  'supabase_authz_write_matrix',
  'next_server_action_diff',
  'serverless_race_condition_probe',
]);

/**
 * True when a hypothesis kind or suggested/plan capability name is part of
 * the active-confirmation layer deferred to manual (Parrot) validation under
 * ADR-013. Used to tag `SecurityHypothesis.deferredToManualValidation` and to
 * exclude these hypotheses from automatic recommendation preference boosts.
 */
export function isDeferredToManualValidation(name: string | undefined): boolean {
  if (!name) return false;
  return DEFERRED_TO_MANUAL_VALIDATION_NAMES.has(name);
}

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
  /** ADR-013: true when this hypothesis belongs to the active/aggressive
   * confirmation layer frozen for automatic use — kept as provenance for a
   * future manual Parrot handoff, never auto-preferred as the next step. */
  readonly deferredToManualValidation?: boolean;
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

/**
 * P1 — precomputed recon/classification gap signals (from R2's
 * AttackSurfaceQueryService). Passed as a projection, not the raw graph,
 * keeping the scheduler decoupled and pure — same pattern as `asgNodeKinds`.
 */
export interface HypothesisSchedulerSurfaceGapSignals {
  readonly totalEndpointCount: number;
  readonly unclassifiedEndpointCount: number;
  readonly sampleUnclassifiedEndpointUrls?: readonly string[];
  readonly unknownAuthRequirementEndpointCount: number;
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
  /** P1 — recon/classification gap signals; omit to skip gap-hypothesis rules. */
  readonly surfaceGaps?: HypothesisSchedulerSurfaceGapSignals;
}

export interface HypothesisSchedulerResult {
  readonly contractVersion: HypothesisSchedulerContractVersion;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly rulesApplied: readonly string[];
  readonly generatedAt: string;
}
