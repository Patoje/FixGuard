/**
 * Milestone R7 (Hito 1 — Observabilidad del reconocimiento) smoke.
 *
 * Verifies that ReconHealthClassificationService correctly identifies a
 * degraded run and preserves its real cause, using only signals already
 * captured during orchestration — never a fabricated baseline. See
 * docs/decisions/RECON-DEPTH-ANALYSIS-2026-10-25.md section 10.
 */
import assert from 'node:assert/strict';
import { ReconHealthClassificationService } from '../recon/orchestration/ReconHealthClassificationService.js';
import type {
  ReconHealthSignals,
  ReconStageExecutionResult,
} from '../recon/orchestration/ActiveReconOrchestrationContracts.js';

function stage(
  overrides: Partial<ReconStageExecutionResult> & { stage: ReconStageExecutionResult['stage'] }
): ReconStageExecutionResult {
  return {
    status: 'completed',
    durationMs: 100,
    observationsCount: 1,
    ...overrides,
  };
}

const CLEAN_STAGES: readonly ReconStageExecutionResult[] = [
  stage({ stage: 'stage_1_domain_zone' }),
  stage({ stage: 'stage_2_port_service' }),
  stage({
    stage: 'stage_3_web_tls',
    warnings: ['Crawl frontier exhausted: all reachable in-scope HTML routes discovered'],
  }),
  stage({ stage: 'stage_4_crawling_parameters', observationsCount: 172 }),
];

async function main(): Promise<void> {
  console.log('=== Recon Health Classification (Hito 1) smoke ===');

  // 1. Challenge never resolved within budget (3 failed attempts) → degraded_blocked.
  const neverResolvedSignals: ReconHealthSignals = {
    unresolvedChallengeHosts: ['firma-nu.vercel.app'],
    resolvedChallengeHosts: [],
    crawlStoppedByBudgetCap: false,
  };
  const blocked = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: neverResolvedSignals,
  });
  assert.equal(blocked.status, 'degraded_blocked');
  assert.ok(blocked.reasonCodes.includes('edge_challenge_unresolved:firma-nu.vercel.app'));
  console.log('[+] unresolved edge challenge → degraded_blocked, cause preserved');

  // 2. Challenge resolved on a later attempt for the SAME host → not blocked.
  const resolvedSignals: ReconHealthSignals = {
    unresolvedChallengeHosts: ['firma-nu.vercel.app'],
    resolvedChallengeHosts: ['firma-nu.vercel.app'],
    crawlStoppedByBudgetCap: false,
  };
  const resolved = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: resolvedSignals,
  });
  assert.equal(resolved.status, 'complete');
  assert.deepEqual(resolved.reasonCodes, []);
  console.log('[+] challenge resolved on retry → complete, not flagged blocked');

  // 3. Crawl frontier stopped by the request-budget ceiling, not natural exhaustion → insufficiently_explored.
  const budgetCapSignals: ReconHealthSignals = {
    unresolvedChallengeHosts: [],
    resolvedChallengeHosts: [],
    crawlStoppedByBudgetCap: true,
  };
  const capped = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: budgetCapSignals,
  });
  assert.equal(capped.status, 'insufficiently_explored');
  assert.deepEqual(capped.reasonCodes, ['crawl_request_budget_exhausted']);
  assert.equal(capped.suggestedNextConfig, undefined, 'no budgetUsed → no guessed suggestion');
  console.log('[+] crawl stopped by request budget → insufficiently_explored');

  // 3b. Milestone R9 (Hito 3) — suggestion is derived from the real budget used, never guessed.
  const cappedWithBudget = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: {
      unresolvedChallengeHosts: [],
      resolvedChallengeHosts: [],
      crawlStoppedByBudgetCap: true,
      crawlRequestBudgetUsed: 150,
    },
  });
  assert.deepEqual(cappedWithBudget.suggestedNextConfig, { crawlRequestBudget: 300 });
  console.log('[+] insufficiently_explored with budgetUsed=150 → suggests 300 (never applied automatically)');

  // 3c. Suggestion respects the hard ceiling — doubling never runs away unbounded.
  const cappedNearCeiling = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: {
      unresolvedChallengeHosts: [],
      resolvedChallengeHosts: [],
      crawlStoppedByBudgetCap: true,
      crawlRequestBudgetUsed: 400,
    },
  });
  assert.deepEqual(cappedNearCeiling.suggestedNextConfig, { crawlRequestBudget: 600 });
  console.log('[+] insufficiently_explored with budgetUsed=400 → suggests 600, not 800 (ceiling respected)');

  // 4. Clean run: frontier exhausted naturally, no challenge, no cap → complete.
  const clean = ReconHealthClassificationService.classify({
    stages: CLEAN_STAGES,
    signals: {
      unresolvedChallengeHosts: [],
      resolvedChallengeHosts: [],
      crawlStoppedByBudgetCap: false,
    },
  });
  assert.equal(clean.status, 'complete');
  assert.deepEqual(clean.reasonCodes, []);
  console.log('[+] natural frontier exhaustion, no blocking signal → complete');

  // 5. Adversarial: a stage reports partial_failure with none of the tracked
  // signals present. Must NOT fabricate a cause — falls to degraded_unexplained.
  const unexplainedStages: readonly ReconStageExecutionResult[] = [
    stage({ stage: 'stage_1_domain_zone', status: 'partial_failure', warnings: ['Passive CT discovery denied: crt_sh_http_error'] }),
    ...CLEAN_STAGES.slice(1),
  ];
  const unexplained = ReconHealthClassificationService.classify({
    stages: unexplainedStages,
    signals: { unresolvedChallengeHosts: [], resolvedChallengeHosts: [], crawlStoppedByBudgetCap: false },
  });
  assert.equal(unexplained.status, 'degraded_unexplained');
  assert.deepEqual(unexplained.reasonCodes, ['stage_partial_failure:stage_1_domain_zone']);
  console.log('[+] partial_failure with no known cause → degraded_unexplained (no fabricated cause)');

  // 6. Backward compatibility: no signals at all (older record shape) must not throw,
  // and must fall back to stage-only classification.
  const noSignals = ReconHealthClassificationService.classify({ stages: CLEAN_STAGES });
  assert.equal(noSignals.status, 'complete');
  const noSignalsWithFailure = ReconHealthClassificationService.classify({ stages: unexplainedStages });
  assert.equal(noSignalsWithFailure.status, 'degraded_unexplained');
  console.log('[+] missing signals (legacy record) → no exception, falls back to stage-only read');

  console.log('=== Recon Health Classification smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
