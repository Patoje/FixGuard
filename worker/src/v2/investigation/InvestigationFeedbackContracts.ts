/**
 * Block B — Investigation Runtime Activation & Hypothesis Feedback Contracts
 * Contract version: fixguard-investigation-feedback/v0
 *
 * Defines the deterministic closed-loop investigation types:
 * - InvestigationPlan (bounded, explicit, read-only plan derived from hypothesis)
 * - InvestigationExecutionResult (result evaluated for validity and comparative evidence)
 * - InvestigationFeedbackStepRecord (step history with state transitions and lineage)
 * - InvestigationFeedbackLoopState (in-memory, process-local state)
 *
 * INVARIANTS:
 * - executable is strictly read_only / non-destructive.
 * - Test validity MUST be evaluated: WAF/challenge interference cannot confirm vulnerabilities.
 * - Negative evidence refutes/deprioritizes hypotheses.
 * - Context kind (anonymous vs authenticated vs authenticated_secondary) is explicit.
 */

import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import type { HttpMethod } from '../comparison/ResponseComparatorContracts.js';
import type {
  HypothesisLifecycleState,
  SecurityHypothesis,
} from '../hypothesis-scheduler/HypothesisSchedulerContracts.js';
import type { TestValidityVerdict } from '../test-validity/TestValidityContracts.js';

export const INVESTIGATION_FEEDBACK_CONTRACT_VERSION =
  'fixguard-investigation-feedback/v0' as const;

export type InvestigationContextKind =
  | 'anonymous'
  | 'authenticated'
  | 'authenticated_secondary';

export interface InvestigationPlan {
  readonly contractVersion: typeof INVESTIGATION_FEEDBACK_CONTRACT_VERSION;
  readonly kind: 'investigation_plan';
  readonly planId: string;
  readonly hypothesisId: string;
  readonly capability: AttackCapabilityKind;
  readonly targetUrl: string;
  readonly method: HttpMethod;
  readonly contextKind: InvestigationContextKind;
  readonly requestPurpose: string;
  readonly expectedObservation: string;
  readonly safetyLevel: 'read_only';
  readonly requestCost: number;
  readonly dependenciesReady: boolean;
  readonly createdAt: string;
}

export interface DiscoveredSurface {
  readonly url: string;
  readonly parameterName?: string;
  readonly source: string;
}

export interface InvestigationExecutionResult {
  readonly contractVersion: typeof INVESTIGATION_FEEDBACK_CONTRACT_VERSION;
  readonly kind: 'investigation_execution_result';
  readonly planId: string;
  readonly hypothesisId: string;
  readonly targetUrl: string;
  readonly executedAt: string;
  readonly status: 'completed' | 'interfered' | 'failed' | 'denied';
  readonly statusCode?: number;
  readonly testValidityVerdict: TestValidityVerdict;
  readonly outcome: 'supported' | 'weakened' | 'refuted' | 'inconclusive';
  readonly reasonCode: string;
  readonly safeEvidenceMessage: string;
  readonly observedNewSurfaces?: readonly DiscoveredSurface[];
}

export interface InvestigationFeedbackStepRecord {
  readonly stepIndex: number;
  readonly hypothesisId: string;
  readonly planId: string;
  readonly capability: AttackCapabilityKind;
  readonly targetUrl: string;
  readonly contextKind: InvestigationContextKind;
  readonly testValidityVerdict: TestValidityVerdict;
  readonly outcome: 'supported' | 'weakened' | 'refuted' | 'inconclusive';
  readonly stateTransition: {
    readonly from: HypothesisLifecycleState;
    readonly to: HypothesisLifecycleState;
  };
  readonly scoreDelta: number;
  readonly reasonCode: string;
  readonly safeEvidenceMessage: string;
  readonly executedAt: string;
}

export interface InvestigationFeedbackLoopState {
  readonly investigationId: string;
  readonly assessmentId: string;
  readonly hypotheses: readonly SecurityHypothesis[];
  readonly executedSteps: readonly InvestigationFeedbackStepRecord[];
  readonly stepsExecuted: number;
  readonly stepBudget: number;
  readonly stopReason?: string;
  readonly completedAt?: string;
}
