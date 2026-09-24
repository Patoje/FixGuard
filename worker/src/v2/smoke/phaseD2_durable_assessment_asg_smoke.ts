/**
 * Phase D2 Step 1 — Durable Orchestrated Assessment + ASG Smoke
 *
 * Hermetic (no live DB required):
 * 1. InMemory port-level roundtrip preserves OBSERVED vs INFERRED epistemic data
 * 2. Simulated Postgres adapter roundtrip + projection ASG reload + corruption fail-closed
 * 3. Composition defaults to memory; createDurableV2CompositionFromEnv(forceMemory) stays hermetic
 *
 * Live Postgres (optional): FIXGUARD_PG_TEST_URL — skipped when unset (ADR-011).
 */

import assert from 'node:assert/strict';
import process from 'node:process';
import {
  ATTACK_SURFACE_CONTRACT_VERSION,
  type AttackSurfaceGraph,
  type EpistemicStatus,
} from '../attack-surface/AttackSurfaceContracts.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
  type OrchestratedAssessmentRepository,
} from '../application/OrchestratedAssessmentContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  adaptOrchestratedAssessmentDb,
  PostgresOrchestratedAssessmentRepository,
} from '../storage/postgres/PostgresOrchestratedAssessmentRepository.js';
import {
  v2_attack_surface_graphs,
  v2_orchestrated_assessments,
} from '../storage/postgres/schema.js';
import { RecordCorruptedError } from '../storage/StorageErrors.js';
import { createDurableV2CompositionFromEnv } from '../storage/composition/PostgresOrchestratedComposition.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { countEpistemicByStatus } from '../storage/OrchestratedAssessmentPersistenceValidation.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function buildGraph(assessmentId: string, scanId: string, actorId: string): AttackSurfaceGraph {
  const nowIso = new Date().toISOString();
  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grn_d2_001',
    authorizationDecisionId: 'dec_d2_001',
    actorId,
  };

  return {
    contractVersion: ATTACK_SURFACE_CONTRACT_VERSION,
    kind: 'attack_surface_graph',
    graphId: `asg_${assessmentId}`,
    assessmentId,
    scanId,
    targetHost: 'app.example.com',
    builtAt: nowIso,
    lineage,
    nodes: [
      {
        id: 'node_domain',
        kind: 'domain',
        epistemicStatus: 'OBSERVED',
        provenance: {
          assessmentId,
          scanId,
          sourceKind: 'recon_observation',
          observedAt: nowIso,
        },
        label: 'app.example.com',
        metadata: { hostname: 'app.example.com' },
      },
      {
        id: 'node_svc',
        kind: 'service',
        epistemicStatus: 'INFERRED',
        provenance: {
          assessmentId,
          scanId,
          sourceKind: 'graph_derivation',
        },
        label: 'https',
        metadata: { name: 'https', host: 'app.example.com', port: 443 },
      },
      {
        id: 'node_vuln',
        kind: 'vulnerability',
        epistemicStatus: 'VERIFIED',
        provenance: {
          assessmentId,
          scanId,
          sourceKind: 'finding',
          sourceId: 'fnd_d2_001',
          verificationState: 'validated_vulnerability',
        },
        label: 'CORS misconfiguration',
        metadata: {
          findingId: 'fnd_d2_001',
          findingType: 'CORS_MISCONFIGURATION',
          title: 'CORS reflects origin',
          target: 'https://app.example.com/api',
          verificationState: 'validated_vulnerability',
        },
      },
    ],
    edges: [
      {
        id: 'edge_hosts',
        kind: 'hosts',
        fromNodeId: 'node_domain',
        toNodeId: 'node_svc',
        epistemicStatus: 'INFERRED',
        provenance: {
          assessmentId,
          scanId,
          sourceKind: 'graph_derivation',
        },
      },
      {
        id: 'edge_vuln',
        kind: 'has_vulnerability',
        fromNodeId: 'node_svc',
        toNodeId: 'node_vuln',
        epistemicStatus: 'VERIFIED',
        provenance: {
          assessmentId,
          scanId,
          sourceKind: 'finding',
          sourceId: 'fnd_d2_001',
        },
      },
    ],
  };
}

function buildRecord(
  assessmentId: string,
  scanId: string,
  actorId: string,
  graph: AttackSurfaceGraph
): OrchestratedAssessmentRecord {
  const nowIso = new Date().toISOString();
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: 'app.example.com',
    status: 'completed',
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_d2_001',
      authorizationDecisionId: 'dec_d2_001',
      actorId,
    },
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 12 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
    attackSurfaceGraph: graph,
  };
}

function assertEpistemicPreserved(
  original: AttackSurfaceGraph,
  reloaded: AttackSurfaceGraph,
  label: string
): void {
  assert.equal(reloaded.graphId, original.graphId, `${label}: graphId`);
  assert.equal(reloaded.nodes.length, original.nodes.length, `${label}: node count`);
  assert.equal(reloaded.edges.length, original.edges.length, `${label}: edge count`);

  const byId = new Map(reloaded.nodes.map((n) => [n.id, n.epistemicStatus]));
  for (const node of original.nodes) {
    assert.equal(
      byId.get(node.id),
      node.epistemicStatus,
      `${label}: node ${node.id} epistemicStatus`
    );
  }

  const edgeById = new Map(reloaded.edges.map((e) => [e.id, e.epistemicStatus]));
  for (const edge of original.edges) {
    assert.equal(
      edgeById.get(edge.id),
      edge.epistemicStatus,
      `${label}: edge ${edge.id} epistemicStatus`
    );
  }

  const counts = countEpistemicByStatus(reloaded);
  assert.equal(counts.observed, 1, `${label}: OBSERVED count`);
  assert.equal(counts.inferred, 1, `${label}: INFERRED count`);
  assert.equal(counts.verified, 1, `${label}: VERIFIED count`);
  assert.equal(counts.refuted, 0, `${label}: REFUTED count`);

  const statuses = new Set<EpistemicStatus>(
    reloaded.nodes.map((n) => n.epistemicStatus)
  );
  assert.ok(statuses.has('OBSERVED'), `${label}: OBSERVED present`);
  assert.ok(statuses.has('INFERRED'), `${label}: INFERRED present`);
  assert.ok(statuses.has('VERIFIED'), `${label}: VERIFIED present`);
}

async function assertPortRoundtrip(
  repository: OrchestratedAssessmentRepository,
  label: string
): Promise<void> {
  const assessmentId = `asm_d2_${label}`;
  const scanId = `scn_d2_${label}`;
  const actorId = 'act_d2_operator';
  const graph = buildGraph(assessmentId, scanId, actorId);
  const record = buildRecord(assessmentId, scanId, actorId, graph);

  await repository.save(record);
  const reloaded = await repository.findById(assessmentId);
  assert.ok(reloaded, `${label}: findById returned null`);
  assert.equal(reloaded.assessmentId, assessmentId);
  assert.equal(reloaded.lineage.actorId, actorId);
  assert.ok(reloaded.attackSurfaceGraph, `${label}: ASG missing after reload`);
  assertEpistemicPreserved(graph, reloaded.attackSurfaceGraph, label);

  const updated = await repository.update(assessmentId, (prev) => ({
    ...prev,
    warningCount: prev.warningCount + 1,
  }));
  assert.equal(updated.warningCount, 1);
  assert.ok(updated.attackSurfaceGraph);
  assertEpistemicPreserved(graph, updated.attackSurfaceGraph, `${label}_update`);
}

type StoredAssessmentRow = Record<string, unknown> & {
  assessment_id: string;
  record_json: OrchestratedAssessmentRecord;
};
type StoredAsgRow = Record<string, unknown> & {
  graph_id: string;
  assessment_id: string;
  graph_json: AttackSurfaceGraph;
};

class MockDurableDb {
  public assessments = new Map<string, StoredAssessmentRow>();
  public graphs = new Map<string, StoredAsgRow>();

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
          if (table === v2_orchestrated_assessments) {
            const id = String(data.assessment_id);
            const existing = this.assessments.get(id);
            const merged = existing
              ? { ...existing, ...config.set, assessment_id: id }
              : { ...data, assessment_id: id };
            this.assessments.set(
              id,
              JSON.parse(JSON.stringify(merged)) as StoredAssessmentRow
            );
            return;
          }
          if (table === v2_attack_surface_graphs) {
            const id = String(data.graph_id);
            const existing = this.graphs.get(id);
            const merged = existing
              ? { ...existing, ...config.set, graph_id: id }
              : { ...data, graph_id: id };
            this.graphs.set(id, JSON.parse(JSON.stringify(merged)) as StoredAsgRow);
            return;
          }
          throw new Error('MockDurableDb: unknown insert table');
        },
      }),
    };
  }

  select() {
    return {
      from: (table: unknown) => {
        const getRows = (): Record<string, unknown>[] => {
          if (table === v2_orchestrated_assessments) {
            return Array.from(this.assessments.values()).map((r) =>
              JSON.parse(JSON.stringify(r))
            );
          }
          if (table === v2_attack_surface_graphs) {
            return Array.from(this.graphs.values()).map((r) =>
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
        if (table === v2_attack_surface_graphs) {
          for (const [key, row] of this.graphs.entries()) {
            if (row[params.column] === params.value) {
              this.graphs.delete(key);
            }
          }
        }
        if (table === v2_orchestrated_assessments) {
          for (const [key, row] of this.assessments.entries()) {
            if (row[params.column] === params.value) {
              this.assessments.delete(key);
            }
          }
        }
      },
    };
  }
}

async function runInMemoryRoundtrip(): Promise<void> {
  console.log('=== Phase D2: InMemory assessment+ASG roundtrip ===');
  const repository = new InMemoryOrchestratedAssessmentRepository();
  await assertPortRoundtrip(repository, 'memory');
  console.log('[+] InMemory roundtrip preserved OBSERVED/INFERRED/VERIFIED epistemic data');
}

async function runSimulatedPostgresRoundtrip(): Promise<void> {
  console.log('=== Phase D2: Simulated Postgres adapter roundtrip ===');
  const mock = new MockDurableDb();
  const repository = new PostgresOrchestratedAssessmentRepository(
    adaptOrchestratedAssessmentDb(mock)
  );

  await assertPortRoundtrip(repository, 'pgmock');

  const projected = await repository.findAttackSurfaceGraphByAssessmentId(
    'asm_d2_pgmock'
  );
  assert.ok(projected, 'projected ASG missing');
  assert.equal(projected.nodes.find((n) => n.id === 'node_domain')?.epistemicStatus, 'OBSERVED');
  assert.equal(projected.nodes.find((n) => n.id === 'node_svc')?.epistemicStatus, 'INFERRED');
  console.log('[+] ASG projection table reload preserved distinct epistemic statuses');

  // Adversarial: collapse INFERRED → OBSERVED in stored JSON (epistemic laundering)
  const stored = mock.assessments.get('asm_d2_pgmock');
  assert.ok(stored);
  const tamperedGraph = stored.record_json.attackSurfaceGraph;
  assert.ok(tamperedGraph);
  const svc = tamperedGraph.nodes.find((n) => n.id === 'node_svc');
  assert.ok(svc);
  (svc as { epistemicStatus: EpistemicStatus }).epistemicStatus = 'OBSERVED';
  // Keep indexed counts stale relative to JSON to also trip cross-column checks on projection
  const asgRow = mock.graphs.get('asg_asm_d2_pgmock');
  assert.ok(asgRow);
  asgRow.graph_json = JSON.parse(JSON.stringify(tamperedGraph)) as AttackSurfaceGraph;
  // Leave observed/inferred counts as originally written → desync
  asgRow.observed_node_count = 1;
  asgRow.inferred_node_count = 1;

  let blocked = false;
  try {
    await repository.findAttackSurfaceGraphByAssessmentId('asm_d2_pgmock');
  } catch (err: unknown) {
    if (err instanceof RecordCorruptedError) {
      blocked = true;
    }
  }
  assert.ok(blocked, 'expected RecordCorruptedError on epistemic count desync');
  console.log('[+] Adversarial epistemic desync fail-closed with RecordCorruptedError');

  // Forbidden secret key rejected on save
  const assessmentId = 'asm_d2_secret';
  const scanId = 'scn_d2_secret';
  const graph = buildGraph(assessmentId, scanId, 'act_d2');
  const bad = {
    ...buildRecord(assessmentId, scanId, 'act_d2', graph),
    rawSecret: 'should-not-persist',
  };
  await assert.rejects(
    () => repository.save(bad as OrchestratedAssessmentRecord),
    (err: unknown) =>
      err instanceof Error &&
      err.message.includes('failed persistence-boundary validation')
  );
  console.log('[+] Forbidden secret key rejected at persistence boundary');
}

async function runCompositionSwitch(): Promise<void> {
  console.log('=== Phase D2: Composition switch (hermetic memory default) ===');
  const defaultRoot = V2CompositionRoot.createDefault();
  assert.ok(defaultRoot.orchestratedRepository);

  const durable = await createDurableV2CompositionFromEnv({ forceMemory: true });
  assert.equal(durable.mode, 'memory');
  await assertPortRoundtrip(durable.root.orchestratedRepository, 'durable_mem');
  await durable.close();
  console.log('[+] createDurableV2CompositionFromEnv(forceMemory) stays InMemory');
}

async function main(): Promise<void> {
  console.log('=== FixGuard V2 Phase D2 Step 1: Durable Assessment + ASG ===');
  await runInMemoryRoundtrip();
  await runSimulatedPostgresRoundtrip();
  await runCompositionSwitch();

  if (process.env.FIXGUARD_PG_TEST_URL) {
    console.log('[*] FIXGUARD_PG_TEST_URL set — live PG suite not required for D2 Step 1 hermetic gate');
  } else {
    console.log('[*] Live PostgreSQL skipped (FIXGUARD_PG_TEST_URL unset; ADR-011)');
  }

  console.log('=== Phase D2 Durable Assessment+ASG: ALL TESTS PASSED ===');
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
});
