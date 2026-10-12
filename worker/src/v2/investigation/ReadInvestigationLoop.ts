/**
 * Block B.1 — ReadInvestigationLoop Application Entry & Compatibility Layer
 *
 * Directs the canonical assessment lifecycle through InvestigationRuntimeCoordinator.
 * Preserves full contract compatibility with OrchestratedAssessmentApplicationService
 * and existing regression suites while ensuring a single, authoritative execution loop.
 */

import {
  InvestigationRuntimeCoordinator,
  type InvestigationRuntimeCoordinatorInput,
  type InvestigationRuntimeCoordinatorResult,
} from './InvestigationRuntimeCoordinator.js';

export type RunReadInvestigationLoopInput = InvestigationRuntimeCoordinatorInput;
export type RunReadInvestigationLoopResult = InvestigationRuntimeCoordinatorResult;

/**
 * Canonical Application Entry Point for the FixGuard V2 Investigation Loop.
 * Delegates to the canonical InvestigationRuntimeCoordinator.
 */
export async function runReadInvestigationLoop(
  input: RunReadInvestigationLoopInput
): Promise<RunReadInvestigationLoopResult> {
  const coordinator = new InvestigationRuntimeCoordinator();
  return coordinator.execute(input);
}
