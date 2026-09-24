/**
 * Phase D2 Step 2 — Durable Attack Plans + Attack Chains Smoke
 *
 * Hermetic (no live DB required):
 * 1. InMemory port-level roundtrip preserves plan status + chain epistemic/status
 * 2. Simulated Postgres adapter roundtrip + corruption fail-closed + secret rejection
 * 3. Composition defaults to memory; createDurableV2CompositionFromEnv(forceMemory) stays hermetic
 *
 * Live Postgres (optional): FIXGUARD_PG_TEST_URL — skipped when unset (ADR-011).
 * Post-exploitation durable persistence is deferred.
 */

import assert from 'node:assert/strict';
import process from 'node:process';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import type { AttackPlanRepository } from '../attack-planning/AttackPlanRepository.js';
import {
  ATTACK_CHAIN_CONTRACT_VERSION,
  type AttackChain,
  type EpistemicStatus,
} from '../attack-chain/AttackChainContracts.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import type { AttackChainRepository } from '../attack-chain/AttackChainRepository.js';
import {
  adaptAttackPlanDb,
  PostgresAttackPlanRepository,
} from '../storage/postgres/PostgresAttackPlanRepository.js';
import {
  adaptAttackChainDb,
  PostgresAttackChainRepository,
} from '../storage/postgres/PostgresAttackChainRepository.js';
import {
  v2_attack_chains,
  v2_attack_plans,
} from '../storage/postgres/schema.js';
import {
  PersistenceConflictError,
  RecordCorruptedError,
} from '../storage/StorageErrors.js';
import { createDurableV2CompositionFromEnv } from '../storage/composition/PostgresOrchestratedComposition.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function buildPlan(
  assessmentId: string,
  scanId: string,
  planId: string,
  status: AttackPlan['status']
): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId,
    capability: 'idor_read_differential',
    title: 'IDOR differential read',
    reasoning: 'Two identities observed with overlapping resource access.',
    status,
    blastRadius: 'single_resource',
    capabilityGained: 'read_escalated',
    sourceFindingIds: ['fnd_d2_plan_001'],
    sourceFindingTypes: ['IDOR'],
    prerequisites: [
      {
        kind: 'identity_count_at_least_2',
        description: 'At least two identities required',
        satisfied: true,
      },
    ],
    steps: [
      {
        stepId: 'step_1',
        ordinal: 1,
        title: 'Compare reads',
        description: 'Compare authorized reads across identities',
        status: 'ready',
        requiredPermissions: ['read'],
      },
    ],
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_d2_plan_001',
      authorizationDecisionId: 'dec_d2_plan_001',
      actorId: 'act_d2_operator',
    },
    createdAt: '2026-09-24T12:00:00.000Z',
    executable: false,
  };
}

function buildChain(
  assessmentId: string,
  scanId: string,
  chainId: string,
  overallEpistemicStatus: EpistemicStatus,
  status: AttackChain['status']
): AttackChain {
  const stepEpistemic: EpistemicStatus =
    overallEpistemicStatus === 'REFUTED' ? 'REFUTED' : overallEpistemicStatus;
  return {
    contractVersion: ATTACK_CHAIN_CONTRACT_VERSION,
    kind: 'attack_chain',
    chainId,
    assessmentId,
    scanId,
    hypothesis: 'CORS misconfig enables cross-origin IDOR read',
    objectiveKind: 'data_access',
    steps: [
      {
        stepId: 'cstep_1',
        sequence: 1,
        capabilityKind: 'cors_chain_exploit',
        epistemicStatus: stepEpistemic,
        evidence: {
          reasonCode: 'cors_origin_reflected',
          safeMessage: 'Origin reflected with credentials',
          recordedAt: '2026-09-24T12:01:00.000Z',
        },
        capabilityGained: 'active_validation',
        outcome: stepEpistemic === 'REFUTED' ? 'refuted' : 'succeeded',
      },
      {
        stepId: 'cstep_2',
        sequence: 2,
        capabilityKind: 'idor_read_differential',
        epistemicStatus:
          overallEpistemicStatus === 'INFERRED' ? 'INFERRED' : stepEpistemic,
        evidence: {
          reasonCode: 'differential_body',
          safeMessage: 'Body differed across identities',
          recordedAt: '2026-09-24T12:02:00.000Z',
        },
        capabilityGained: 'read_escalated',
        outcome: stepEpistemic === 'REFUTED' ? 'refuted' : 'succeeded',
        sourceStepId: 'cstep_1',
      },
    ],
    overallEpistemicStatus,
    status,
    impactLevel:
      status === 'fully_validated' && overallEpistemicStatus === 'VERIFIED'
        ? 'data_access'
        : 'information_exposure',
    declaredImpactLevel: 'data_access',
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_d2_chain_001',
      authorizationDecisionId: 'dec_d2_chain_001',
      actorId: 'act_d2_operator',
    },
    createdAt: '2026-09-24T12:00:00.000Z',
  };
}

async function assertPlanRoundtrip(
  repository: AttackPlanRepository,
  label: string
): Promise<void> {
  const assessmentId = `asm_d2_plan_${label}`;
  const scanId = `scn_d2_plan_${label}`;
  const plan = buildPlan(
    assessmentId,
    scanId,
    `plan_${label}_001`,
    'ready_for_authorization'
  );

  const saved = await repository.savePlan(plan);
  assert.equal(saved.status, 'ready_for_authorization', `${label}: status`);
  assert.equal(saved.executable, false, `${label}: executable`);

  const reloaded = await repository.getPlan(plan.planId);
  assert.ok(reloaded, `${label}: getPlan null`);
  assert.equal(reloaded.status, 'ready_for_authorization');
  assert.equal(reloaded.capability, 'idor_read_differential');
  assert.equal(reloaded.lineage.actorId, 'act_d2_operator');
  assert.equal(reloaded.executable, false);

  const listed = await repository.listByAssessmentId(assessmentId);
  assert.equal(listed.length, 1);
  assert.equal(listed[0]!.planId, plan.planId);

  await assert.rejects(
    () => repository.savePlan(plan),
    (err: unknown) => err instanceof PersistenceConflictError
  );

  const removed = await repository.deleteByAssessmentId(assessmentId);
  assert.equal(removed, 1);
  assert.equal(await repository.getPlan(plan.planId), null);
}

async function assertChainRoundtrip(
  repository: AttackChainRepository,
  label: string
): Promise<void> {
  const assessmentId = `asm_d2_chain_${label}`;
  const scanId = `scn_d2_chain_${label}`;

  const inferred = buildChain(
    assessmentId,
    scanId,
    `chain_${label}_inferred`,
    'INFERRED',
    'hypothesis'
  );
  const verified = buildChain(
    assessmentId,
    scanId,
    `chain_${label}_verified`,
    'VERIFIED',
    'fully_validated'
  );

  await repository.saveChain(inferred);
  await repository.saveChain(verified);

  const reloadedInferred = await repository.getChain(inferred.chainId);
  assert.ok(reloadedInferred);
  assert.equal(reloadedInferred.overallEpistemicStatus, 'INFERRED');
  assert.equal(reloadedInferred.status, 'hypothesis');
  assert.equal(reloadedInferred.steps[0]!.epistemicStatus, 'INFERRED');
  assert.equal(reloadedInferred.steps[1]!.epistemicStatus, 'INFERRED');

  const reloadedVerified = await repository.getChain(verified.chainId);
  assert.ok(reloadedVerified);
  assert.equal(reloadedVerified.overallEpistemicStatus, 'VERIFIED');
  assert.equal(reloadedVerified.status, 'fully_validated');
  assert.equal(reloadedVerified.impactLevel, 'data_access');

  const updated = await repository.updateChain({
    ...reloadedInferred,
    status: 'partially_validated',
    overallEpistemicStatus: 'OBSERVED',
    steps: reloadedInferred.steps.map((s, i) =>
      i === 0
        ? { ...s, epistemicStatus: 'OBSERVED' as const }
        : { ...s, epistemicStatus: 'OBSERVED' as const }
    ),
  });
  assert.equal(updated.overallEpistemicStatus, 'OBSERVED');
  assert.equal(updated.status, 'partially_validated');

  const afterUpdate = await repository.getChain(inferred.chainId);
  assert.ok(afterUpdate);
  assert.equal(afterUpdate.overallEpistemicStatus, 'OBSERVED');
  assert.equal(afterUpdate.status, 'partially_validated');

  const listed = await repository.listByAssessmentId(assessmentId);
  assert.equal(listed.length, 2);

  await assert.rejects(
    () => repository.saveChain(inferred),
    (err: unknown) => err instanceof PersistenceConflictError
  );

  const removed = await repository.deleteByAssessmentId(assessmentId);
  assert.equal(removed, 2);
}

type StoredPlanRow = Record<string, unknown> & {
  plan_id: string;
  plan_json: AttackPlan;
};
type StoredChainRow = Record<string, unknown> & {
  chain_id: string;
  chain_json: AttackChain;
  overall_epistemic_status: string;
  status: string;
  step_count: number;
};

class MockPlanChainDb {
  public plans = new Map<string, StoredPlanRow>();
  public chains = new Map<string, StoredChainRow>();

  private extractEqParams(
    expr: unknown
  ): { column: string; value: unknown } | null {
    if (
      expr &&
      typeof expr === 'object' &&
      Array.isArray((expr as { queryChunks?: unknown[] }).queryChunks)
    ) {
      const chunks = (expr as { queryChunks: unknown[] }).queryChunks;
      if (chunks.length >= 4) {
        const colName = (chunks[1] as { name?: string } | undefined)?.name;
        const val = (chunks[3] as { value?: unknown } | undefined)?.value;
        if (colName && val !== undefined) {
          return { column: colName, value: val };
        }
      }
    }
    return null;
  }

  insert(table: unknown) {
    return {
      values: (data: Record<string, unknown>) => ({
        onConflictDoUpdate: async (config: {
          target: unknown;
          set: Record<string, unknown>;
        }) => {
          if (table === v2_attack_plans) {
            const id = String(data.plan_id);
            const existing = this.plans.get(id);
            const merged = existing
              ? { ...existing, ...config.set, plan_id: id }
              : { ...data, plan_id: id };
            this.plans.set(id, JSON.parse(JSON.stringify(merged)) as StoredPlanRow);
            return;
          }
          if (table === v2_attack_chains) {
            const id = String(data.chain_id);
            const existing = this.chains.get(id);
            const merged = existing
              ? { ...existing, ...config.set, chain_id: id }
              : { ...data, chain_id: id };
            this.chains.set(
              id,
              JSON.parse(JSON.stringify(merged)) as StoredChainRow
            );
            return;
          }
          throw new Error('MockPlanChainDb: unknown insert table');
        },
      }),
    };
  }

  select() {
    return {
      from: (table: unknown) => {
        const getRows = (): Record<string, unknown>[] => {
          if (table === v2_attack_plans) {
            return Array.from(this.plans.values()).map((r) =>
              JSON.parse(JSON.stringify(r))
            );
          }
          if (table === v2_attack_chains) {
            return Array.from(this.chains.values()).map((r) =>
              JSON.parse(JSON.stringify(r))
            );
          }
          return [];
        };

        return {
          where: (expr: unknown) => {
            const params = this.extractEqParams(expr);
            const filterRows = () => {
              const rows = getRows();
              if (!params) return rows;
              return rows.filter((r) => r[params.column] === params.value);
            };
            return {
              limit: async (lim: number) => filterRows().slice(0, lim),
              orderBy: async () => filterRows(),
            };
          },
          orderBy: async () => getRows(),
        };
      },
    };
  }

  delete(table: unknown) {
    return {
      where: async (expr: unknown) => {
        const params = this.extractEqParams(expr);
        if (!params) return;
        if (table === v2_attack_plans) {
          for (const [key, row] of this.plans.entries()) {
            if (row[params.column] === params.value) {
              this.plans.delete(key);
            }
          }
        }
        if (table === v2_attack_chains) {
          for (const [key, row] of this.chains.entries()) {
            if (row[params.column] === params.value) {
              this.chains.delete(key);
            }
          }
        }
      },
    };
  }
}

async function runInMemoryRoundtrip(): Promise<void> {
  console.log('=== Phase D2 Step 2: InMemory plan+chain roundtrip ===');
  await assertPlanRoundtrip(new InMemoryAttackPlanRepository(), 'memory');
  await assertChainRoundtrip(new InMemoryAttackChainRepository(), 'memory');
  console.log('[+] InMemory roundtrip preserved plan status and chain epistemic/status');
}

async function runSimulatedPostgresRoundtrip(): Promise<void> {
  console.log('=== Phase D2 Step 2: Simulated Postgres adapter roundtrip ===');
  const mock = new MockPlanChainDb();
  const planRepo = new PostgresAttackPlanRepository(adaptAttackPlanDb(mock));
  const chainRepo = new PostgresAttackChainRepository(adaptAttackChainDb(mock));

  await assertPlanRoundtrip(planRepo, 'pgmock');
  await assertChainRoundtrip(chainRepo, 'pgmock');

  // Re-seed for adversarial checks
  const assessmentId = 'asm_d2_chain_corrupt';
  const scanId = 'scn_d2_chain_corrupt';
  const chain = buildChain(
    assessmentId,
    scanId,
    'chain_corrupt_001',
    'INFERRED',
    'hypothesis'
  );
  await chainRepo.saveChain(chain);

  const stored = mock.chains.get('chain_corrupt_001');
  assert.ok(stored);
  // Epistemic laundering: JSON says VERIFIED, indexed column still INFERRED
  stored.chain_json = {
    ...stored.chain_json,
    overallEpistemicStatus: 'VERIFIED',
    status: 'fully_validated',
  };
  stored.overall_epistemic_status = 'INFERRED';
  stored.status = 'hypothesis';

  let blocked = false;
  try {
    await chainRepo.getChain('chain_corrupt_001');
  } catch (err: unknown) {
    if (err instanceof RecordCorruptedError) {
      blocked = true;
    }
  }
  assert.ok(blocked, 'expected RecordCorruptedError on epistemic desync');
  console.log('[+] Adversarial epistemic desync fail-closed with RecordCorruptedError');

  const badPlan = {
    ...buildPlan('asm_secret', 'scn_secret', 'plan_secret', 'ready_for_authorization'),
    rawSecret: 'should-not-persist',
  };
  await assert.rejects(
    () => planRepo.savePlan(badPlan as AttackPlan),
    (err: unknown) =>
      err instanceof Error &&
      err.message.includes('failed persistence-boundary validation')
  );

  const badChain = {
    ...buildChain('asm_secret', 'scn_secret', 'chain_secret', 'OBSERVED', 'hypothesis'),
    apiKey: 'sk_live_should_not_persist',
  };
  await assert.rejects(
    () => chainRepo.saveChain(badChain as AttackChain),
    (err: unknown) =>
      err instanceof Error &&
      err.message.includes('failed persistence-boundary validation')
  );
  console.log('[+] Forbidden secret keys rejected at persistence boundary');
}

async function runCompositionSwitch(): Promise<void> {
  console.log('=== Phase D2 Step 2: Composition switch (hermetic memory default) ===');
  const defaultRoot = V2CompositionRoot.createDefault();
  assert.ok(defaultRoot.attackPlanRepository);
  assert.ok(defaultRoot.attackChainRepository);

  const durable = await createDurableV2CompositionFromEnv({ forceMemory: true });
  assert.equal(durable.mode, 'memory');
  await assertPlanRoundtrip(durable.root.attackPlanRepository, 'durable_mem');
  await assertChainRoundtrip(durable.root.attackChainRepository, 'durable_mem_c');
  await durable.close();
  console.log('[+] createDurableV2CompositionFromEnv(forceMemory) stays InMemory for plans+chains');
}

async function main(): Promise<void> {
  console.log('=== FixGuard V2 Phase D2 Step 2: Durable Attack Plans + Chains ===');
  await runInMemoryRoundtrip();
  await runSimulatedPostgresRoundtrip();
  await runCompositionSwitch();

  if (process.env.FIXGUARD_PG_TEST_URL) {
    console.log(
      '[*] FIXGUARD_PG_TEST_URL set — live PG suite not required for D2 Step 2 hermetic gate'
    );
  } else {
    console.log('[*] Live PostgreSQL skipped (FIXGUARD_PG_TEST_URL unset; ADR-011)');
  }

  console.log('[*] Post-exploitation durable persistence deferred (credential vault boundary)');
  console.log('=== Phase D2 Durable Plans+Chains: ALL TESTS PASSED ===');
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
});
