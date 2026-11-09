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
    // Corrective pass — reasonCodes are collected from every independently
    // true signal FIRST, before any status decision. Status precedence
    // below is unchanged (circuitBroken > unresolved challenge >
    // budget/depth ceiling > unexplained partial failure > complete); only
    // which reasonCodes get returned alongside the winning status changes —
    // a lower-priority signal (e.g. depth-cap) never overrides a
    // higher-priority one, it is only represented alongside it.
    const reasonCodes: string[] = [];

    // 1. Circuit breaker — a known, structural cause (FixGuard's own
    // coordinator detected and reacted to it). stageNeverStarted
    // distinguishes a stage that never began from one that tripped
    // mid-execution — structural, not text-parsed.
    const circuitBroken = input.signals?.circuitBroken === true;
    if (circuitBroken) {
      const brokenStages = input.stages.filter((stage) => stage.status === 'partial_failure');
      reasonCodes.push(
        ...(brokenStages.length > 0
          ? brokenStages.map((stage) =>
              stage.stageNeverStarted === true
                ? `circuit_breaker_blocked_before_start:${stage.stage}`
                : `circuit_breaker_tripped_during:${stage.stage}`
            )
          : ['circuit_breaker_tripped'])
      );
    }

    // 2. Edge challenge unresolved. A host that failed and later succeeded
    // on a retry within the same run is not blocked — resolution always
    // overrides an earlier unresolved mark.
    const resolvedHosts = new Set(input.signals?.resolvedChallengeHosts ?? []);
    const unresolvedHosts = (input.signals?.unresolvedChallengeHosts ?? []).filter(
      (host) => !resolvedHosts.has(host)
    );
    if (unresolvedHosts.length > 0) {
      reasonCodes.push(...unresolvedHosts.map((host) => `edge_challenge_unresolved:${host}`));
    }

    // 2b. Milestone: Challenge Continuation Reliability (corrected) — hosts
    // where automatic continuation already tried every configured strategy
    // and the challenge still requires an interactive/owner-controlled
    // mechanism FixGuard does not perform automatically (e.g. a
    // Turnstile/CAPTCHA). Distinct reasonCode prefix from "unresolved"
    // above: this is never a confirmed-blocked/failed result — it stays a
    // recoverable state (automatic continuation retries it on the next
    // run; nothing requires a manual resume step). Folded into the same
    // degraded_blocked status so it is never silently reported as
    // 'complete'.
    const interactiveChallengeHostsList = input.signals?.interactiveChallengeHosts ?? [];
    if (interactiveChallengeHostsList.length > 0) {
      reasonCodes.push(
        ...interactiveChallengeHostsList.map(
          (host) => `edge_challenge_requires_interactive_resolution:${host}`
        )
      );
    }

    // 3. Crawl request budget ceiling.
    const budgetCapped = input.signals?.crawlStoppedByBudgetCap === true;
    let suggestedNextConfig: { crawlRequestBudget: number } | undefined;
    if (budgetCapped) {
      reasonCodes.push('crawl_request_budget_exhausted');
      const budgetUsed = input.signals?.crawlRequestBudgetUsed;
      if (typeof budgetUsed === 'number' && budgetUsed > 0) {
        suggestedNextConfig = {
          crawlRequestBudget: Math.min(budgetUsed * 2, MAX_SUGGESTED_CRAWL_REQUEST_BUDGET),
        };
      }
    }

    // 4. Hardcoded depth-2 mining gate. No suggestedNextConfig here:
    // raising crawlMaxDepth would not actually change anything, since the
    // hardcoded gate ignores it — suggesting a config change would be
    // misleading.
    const depthCapped = input.signals?.crawlTruncatedByDepthCap === true;
    if (depthCapped) {
      reasonCodes.push('crawl_depth_cap_reached');
    }

    // Status decision — priority unchanged from before this corrective pass.
    if (circuitBroken || unresolvedHosts.length > 0 || interactiveChallengeHostsList.length > 0) {
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'degraded_blocked',
        reasonCodes,
      };
    }

    if (budgetCapped || depthCapped) {
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'insufficiently_explored',
        reasonCodes,
        ...(suggestedNextConfig ? { suggestedNextConfig } : {}),
      };
    }

    const partialFailureStages = input.stages.filter((stage) => stage.status === 'partial_failure');
    if (partialFailureStages.length > 0) {
      reasonCodes.push(...partialFailureStages.map((stage) => `stage_partial_failure:${stage.stage}`));
      return {
        contractVersion: RECON_HEALTH_CONTRACT_VERSION,
        status: 'degraded_unexplained',
        reasonCodes,
      };
    }

    return {
      contractVersion: RECON_HEALTH_CONTRACT_VERSION,
      status: 'complete',
      reasonCodes,
    };
  }
}
