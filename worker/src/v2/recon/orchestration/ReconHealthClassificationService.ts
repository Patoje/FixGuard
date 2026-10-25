/**
 * FixGuard V2 — Recon Health Classification Service (Milestone R7, Hito 1;
 * extended by Milestone R9, Hito 3 — suggestedNextConfig).
 *
 * Classifies whether a recon run is complete or degraded, using only signals
 * already captured during orchestration — never a fabricated or inferred
 * baseline. See docs/decisions/RECON-DEPTH-ANALYSIS-2026-10-25.md section 10.
 */

import type {
  ReconHealthAssessment,
  ReconHealthSignals,
  ReconStageExecutionResult,
} from './ActiveReconOrchestrationContracts.js';

const RECON_HEALTH_CONTRACT_VERSION = 'fixguard-recon-health/v0' as const;
const MAX_SUGGESTED_CRAWL_REQUEST_BUDGET = 600;

export interface ReconHealthClassificationInput {
  readonly stages: readonly ReconStageExecutionResult[];
  readonly signals?: ReconHealthSignals;
}

export class ReconHealthClassificationService {
  public static classify(input: ReconHealthClassificationInput): ReconHealthAssessment {
    // A host that failed and later succeeded on a retry within the same run is
    // not blocked — resolution always overrides an earlier unresolved mark.
    const resolvedHosts = new Set(input.signals?.resolvedChallengeHosts ?? []);
    const unresolvedHosts = (input.signals?.unresolvedChallengeHosts ?? []).filter(
      (host) => !resolvedHosts.has(host)
    );
    if (unresolvedHosts.length > 0) {
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'degraded_blocked',
        reasonCodes: unresolvedHosts.map((host) => `edge_challenge_unresolved:${host}`),
      };
    }

    if (input.signals?.crawlStoppedByBudgetCap === true) {
      const budgetUsed = input.signals.crawlRequestBudgetUsed;
      const suggestedNextConfig =
        typeof budgetUsed === 'number' && budgetUsed > 0
          ? { crawlRequestBudget: Math.min(budgetUsed * 2, MAX_SUGGESTED_CRAWL_REQUEST_BUDGET) }
          : undefined;
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'insufficiently_explored',
        reasonCodes: ['crawl_request_budget_exhausted'],
        ...(suggestedNextConfig ? { suggestedNextConfig } : {}),
      };
    }

    const partialFailureStages = input.stages.filter((stage) => stage.status === 'partial_failure');
    if (partialFailureStages.length > 0) {
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'degraded_unexplained',
        reasonCodes: partialFailureStages.map((stage) => `stage_partial_failure:${stage.stage}`),
      };
    }

    return {
      contractVersion: RECON_HEALTH_CONTRACT_VERSION,
      status: 'complete',
      reasonCodes: [],
    };
  }
}
