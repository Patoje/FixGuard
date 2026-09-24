/**
 * Etapa 2 · F1 — ActiveInvestigationRuntime contracts
 * Contract version: fixguard-active-investigation/v0
 *
 * Stateful investigation unit: execution state, request budget, timeout,
 * kill-switch/cancel, and a process-local authorization bundle that binds
 * existing WeakSet brands for multi-step work.
 *
 * MUST NOT auto-execute AttackPlans. Humans authorize execute separately.
 * Hypothesis scheduling / ASG-driven investigation (F2) remains out of scope.
 * DefenseObservation + TestValidity foundation lives in `test-validity/` (F3 stub).
 */

import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

export type ActiveInvestigationContractVersion = 'fixguard-active-investigation/v0';
export const ACTIVE_INVESTIGATION_CONTRACT_VERSION: ActiveInvestigationContractVersion =
  'fixguard-active-investigation/v0';

/**
 * Hard ceilings for a single investigation run.
 * Rate/concurrency ceilings are applied to TargetExecutionCoordinator when bound.
 */
export interface InvestigationBudget {
  readonly maxRequests: number;
  readonly maxDurationMs: number;
  /** Soft advisory for multi-step concurrency within the investigation (not a host gate). */
  readonly maxConcurrentSteps?: number;
  readonly requestsPerSecondCeiling?: number;
  readonly maxConcurrencyCeiling?: number;
}

export const DEFAULT_INVESTIGATION_BUDGET: InvestigationBudget = Object.freeze({
  maxRequests: 50,
  maxDurationMs: 15 * 60 * 1000,
  maxConcurrentSteps: 1,
  requestsPerSecondCeiling: 5,
  maxConcurrencyCeiling: 2,
});

export type ActiveInvestigationStatus =
  | 'running'
  | 'completed'
  | 'cancelled'
  | 'timed_out'
  | 'budget_exceeded'
  | 'denied';

export interface InvestigationBudgetConsumption {
  readonly requestsConsumed: number;
  readonly stepsRecorded: number;
  readonly startedAt: string;
  readonly lastActivityAt: string;
}

export interface ActiveInvestigationLineage {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
}

/**
 * Minimal working memory for F1. Hypothesis ASG expansion is deferred to F2.
 */
export interface ActiveInvestigationWorkingMemory {
  readonly confirmedFactIds: readonly string[];
  readonly openHypothesisRefs: readonly string[];
  readonly executedStepIds: readonly string[];
}

export interface ActiveInvestigationSnapshot {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'active_investigation_snapshot';
  readonly investigationId: string;
  readonly status: ActiveInvestigationStatus;
  readonly lineage: ActiveInvestigationLineage;
  readonly budget: InvestigationBudget;
  readonly consumption: InvestigationBudgetConsumption;
  readonly workingMemory: ActiveInvestigationWorkingMemory;
  readonly cancelRequested: boolean;
  readonly killSwitchEngaged: boolean;
  readonly denialReasonCode?: string;
  readonly completedAt?: string;
}

/**
 * Process-local unified auth handle for multi-step investigations.
 * Sealed only via ActiveInvestigationRuntimeService.establishAuthorizationBundle().
 * Nested VerifiedAuthorizationDecision / AttackAuthorizationToken brands remain
 * authoritative — this bundle does not replace them; it binds them for the run.
 */
export interface InvestigationAuthorizationBundle {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'investigation_authorization_bundle';
  readonly investigationId: string;
  readonly assessmentId: string;
  readonly sealedAt: string;
  readonly hasVerifiedAuthorizationDecision: true;
  readonly hasAttackAuthorizationToken: boolean;
  readonly [Symbol.toStringTag]: string;
}

export type StartActiveInvestigationReasonCode =
  | 'investigation_started'
  | 'request_invalid'
  | 'authorization_brand_missing'
  | 'authorization_brand_invalid'
  | 'lineage_invalid';

export interface StartActiveInvestigationRequest {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'start_active_investigation_request';
  readonly investigationId: string;
  readonly lineage: ActiveInvestigationLineage;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly budget?: InvestigationBudget;
  readonly startedAt?: string;
  readonly openHypothesisRefs?: readonly string[];
  /** Optional attack token bound at start (plan already human-authorized). */
  readonly attackAuthorizationToken?: AttackAuthorizationToken;
}

export type StartActiveInvestigationResult =
  | {
      readonly status: 'started';
      readonly reasonCode: 'investigation_started';
      readonly snapshot: ActiveInvestigationSnapshot;
      readonly authorizationBundle: InvestigationAuthorizationBundle;
    }
  | {
      readonly status: 'denied';
      readonly reasonCode: StartActiveInvestigationReasonCode;
      readonly safeMessage: string;
    };

export type CancelActiveInvestigationReasonCode =
  | 'investigation_cancelled'
  | 'kill_switch_engaged'
  | 'investigation_not_found'
  | 'investigation_not_running'
  | 'request_invalid';

export type InvestigationCancelMode = 'cancel' | 'kill_switch';

export interface CancelActiveInvestigationRequest {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'cancel_active_investigation_request';
  readonly investigationId: string;
  readonly operatorId: string;
  readonly mode: InvestigationCancelMode;
  readonly cancelledAt?: string;
}

export type CancelActiveInvestigationResult =
  | {
      readonly status: 'cancelled';
      readonly reasonCode: 'investigation_cancelled' | 'kill_switch_engaged';
      readonly snapshot: ActiveInvestigationSnapshot;
    }
  | {
      readonly status: 'denied';
      readonly reasonCode: CancelActiveInvestigationReasonCode;
      readonly safeMessage: string;
    };

export type GateAuthorizedStepReasonCode =
  | 'step_authorized'
  | 'investigation_not_found'
  | 'investigation_not_running'
  | 'cancel_requested'
  | 'kill_switch_engaged'
  | 'timed_out'
  | 'budget_exceeded'
  | 'authorization_bundle_invalid'
  | 'verified_authorization_missing'
  | 'attack_authorization_required'
  | 'attack_authorization_invalid'
  | 'assessment_mismatch'
  | 'request_invalid'
  | 'concurrent_step_limit';

export interface GateAuthorizedStepRequest {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'gate_authorized_step_request';
  readonly investigationId: string;
  readonly assessmentId: string;
  /** Expected outbound request cost for this step (default 1). */
  readonly expectedRequestCost?: number;
  /** When true, a runtime-branded AttackAuthorizationToken must be bound. */
  readonly requireAttackAuthorization?: boolean;
  readonly planId?: string;
  readonly gatedAt?: string;
}

export type GateAuthorizedStepResult =
  | {
      readonly status: 'authorized';
      readonly reasonCode: 'step_authorized';
      readonly snapshot: ActiveInvestigationSnapshot;
      readonly authorizationBundle: InvestigationAuthorizationBundle;
      readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
      readonly attackAuthorizationToken?: AttackAuthorizationToken;
    }
  | {
      readonly status: 'denied';
      readonly reasonCode: GateAuthorizedStepReasonCode;
      readonly safeMessage: string;
      readonly snapshot?: ActiveInvestigationSnapshot;
    };

export interface BindAttackAuthorizationRequest {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'bind_attack_authorization_request';
  readonly investigationId: string;
  readonly attackAuthorizationToken: AttackAuthorizationToken;
}

export type BindAttackAuthorizationResult =
  | {
      readonly status: 'bound';
      readonly reasonCode: 'attack_authorization_bound';
      readonly authorizationBundle: InvestigationAuthorizationBundle;
    }
  | {
      readonly status: 'denied';
      readonly reasonCode:
        | 'investigation_not_found'
        | 'investigation_not_running'
        | 'attack_authorization_invalid'
        | 'assessment_mismatch'
        | 'request_invalid';
      readonly safeMessage: string;
    };

export interface RecordInvestigationStepRequest {
  readonly contractVersion: ActiveInvestigationContractVersion;
  readonly kind: 'record_investigation_step_request';
  readonly investigationId: string;
  readonly stepId: string;
  readonly requestCost?: number;
  readonly producedFactIds?: readonly string[];
  readonly recordedAt?: string;
}

export type RecordInvestigationStepResult =
  | {
      readonly status: 'recorded';
      readonly reasonCode: 'step_recorded' | 'budget_exceeded' | 'timed_out' | 'cancelled';
      readonly snapshot: ActiveInvestigationSnapshot;
    }
  | {
      readonly status: 'denied';
      readonly reasonCode: GateAuthorizedStepReasonCode;
      readonly safeMessage: string;
      readonly snapshot?: ActiveInvestigationSnapshot;
    };

export interface BindCoordinatorCeilingsRequest {
  readonly investigationId: string;
  readonly coordinator: TargetExecutionCoordinator;
  readonly host: string;
}
