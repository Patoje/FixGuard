/**
 * Milestone R9 (Hito 3 — Profundidad adaptativa) smoke.
 *
 * Verifies getCoverageSummary() correctly cross-references real
 * AttackSurfaceGraph service_boundary groupings against the real AttackPlan
 * list — "how much of what we discovered did we actually investigate,"
 * sorted least-covered first. See docs/decisions/RECON-DEPTH-ANALYSIS-2026-10-25.md
 * section 4/8.
 */
import assert from 'node:assert/strict';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { AsgNode, AsgEdge, AttackSurfaceGraph } from '../attack-surface/AttackSurfaceContracts.js';

const ASSESSMENT_ID = 'asmt_cov_001';
const SCAN_ID = 'scn_cov_001';
const TARGET_DOMAIN = 'app.example.com';

function endpointNode(id: string, url: string, path: string): AsgNode {
  return {
    id,
    kind: 'endpoint',
    epistemicStatus: 'OBSERVED',
    provenance: { assessmentId: ASSESSMENT_ID, scanId: SCAN_ID, sourceKind: 'recon_observation' },
    label: path,
    metadata: { url, path, method: 'GET', authRequirement: 'unknown', flawCategories: [] },
  };
}

function boundaryNode(id: string, pathPrefix: string, endpointCount: number): AsgNode {
  return {
    id,
    kind: 'service_boundary',
    epistemicStatus: 'INFERRED',
    provenance: { assessmentId: ASSESSMENT_ID, scanId: SCAN_ID, sourceKind: 'graph_derivation' },
    label: pathPrefix,
    metadata: { pathPrefix, endpointCount },
  };
}

function groupsEdge(id: string, boundaryId: string, endpointId: string): AsgEdge {
  return {
    id,
    kind: 'groups',
    fromNodeId: boundaryId,
    toNodeId: endpointId,
    epistemicStatus: 'INFERRED',
    provenance: { assessmentId: ASSESSMENT_ID, scanId: SCAN_ID, sourceKind: 'graph_derivation' },
  };
}

function buildPlan(planId: string, targetUrl: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    capability: 'security_header_probe',
    title: 'Coverage smoke plan',
    reasoning: 'Hermetic plan for coverage-by-boundary smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `${planId}_step1`,
        ordinal: 1,
        title: 'Observe',
        description: 'Advisory',
        status: 'ready',
        requiredPermissions: [],
      },
    ],
    targetUrl,
    executable: false,
    createdAt: new Date().toISOString(),
    lineage: {
      assessmentId: ASSESSMENT_ID,
      scanId: SCAN_ID,
      authorizationGrantId: 'grn_cov',
      authorizationDecisionId: 'dec_cov',
      actorId: 'actor_cov_test',
    },
  };
}

function buildRecord(graph?: AttackSurfaceGraph): OrchestratedAssessmentRecord {
  return {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    targetDomain: TARGET_DOMAIN,
    status: 'completed',
    lineage: {
      assessmentId: ASSESSMENT_ID,
      scanId: SCAN_ID,
      authorizationGrantId: 'grn_cov',
      authorizationDecisionId: 'dec_cov',
      actorId: 'actor_cov_test',
    },
    stages: [],
    timing: { startedAt: new Date().toISOString() },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
    ...(graph ? { attackSurfaceGraph: graph } : {}),
  };
}

async function main(): Promise<void> {
  console.log('=== Coverage by Service Boundary (Hito 3) smoke ===');

  // /api: 2 endpoints, 1 investigated (has a matching plan). /admin: 2 endpoints, 0 investigated.
  const apiUsers = endpointNode('ep_api_users', 'https://app.example.com/api/users', '/api/users');
  const apiOrders = endpointNode('ep_api_orders', 'https://app.example.com/api/orders', '/api/orders');
  const adminPanel = endpointNode('ep_admin_panel', 'https://app.example.com/admin/panel', '/admin/panel');
  const adminSettings = endpointNode(
    'ep_admin_settings',
    'https://app.example.com/admin/settings',
    '/admin/settings'
  );
  const apiBoundary = boundaryNode('bnd_api', '/api', 2);
  const adminBoundary = boundaryNode('bnd_admin', '/admin', 2);

  const graph: AttackSurfaceGraph = {
    contractVersion: 'fixguard-attack-surface/v0',
    kind: 'attack_surface_graph',
    graphId: 'asg_cov_001',
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    targetHost: TARGET_DOMAIN,
    builtAt: new Date().toISOString(),
    lineage: {
      assessmentId: ASSESSMENT_ID,
      scanId: SCAN_ID,
      authorizationGrantId: 'grn_cov',
      authorizationDecisionId: 'dec_cov',
      actorId: 'actor_cov_test',
    },
    nodes: [apiUsers, apiOrders, adminPanel, adminSettings, apiBoundary, adminBoundary],
    edges: [
      groupsEdge('e1', 'bnd_api', 'ep_api_users'),
      groupsEdge('e2', 'bnd_api', 'ep_api_orders'),
      groupsEdge('e3', 'bnd_admin', 'ep_admin_panel'),
      groupsEdge('e4', 'bnd_admin', 'ep_admin_settings'),
    ],
  };

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const attackPlanRepository = new InMemoryAttackPlanRepository();
  await repository.save(buildRecord(graph));
  await attackPlanRepository.savePlans([
    buildPlan('plan_cov_1', 'https://app.example.com/api/users'),
  ]);

  const service = new OrchestratedAssessmentApplicationService({ repository, attackPlanRepository });
  const summary = await service.getCoverageSummary(ASSESSMENT_ID);

  assert.equal(summary.boundaries.length, 2);
  // Least-covered first: /admin (0%) before /api (50%).
  assert.equal(summary.boundaries[0]!.pathPrefix, '/admin');
  assert.equal(summary.boundaries[0]!.totalEndpoints, 2);
  assert.equal(summary.boundaries[0]!.investigatedEndpoints, 0);
  assert.equal(summary.boundaries[0]!.coverageRatio, 0);
  assert.equal(summary.boundaries[1]!.pathPrefix, '/api');
  assert.equal(summary.boundaries[1]!.totalEndpoints, 2);
  assert.equal(summary.boundaries[1]!.investigatedEndpoints, 1);
  assert.equal(summary.boundaries[1]!.coverageRatio, 0.5);
  console.log('[+] /admin (0% investigated) sorts before /api (50% investigated)');

  // Adversarial: no attackSurfaceGraph at all (recon never completed) → empty, no fabricated number.
  const noGraphAssessmentId = 'asmt_cov_002';
  const record2 = { ...buildRecord(undefined), assessmentId: noGraphAssessmentId };
  await repository.save(record2);
  const emptySummary = await service.getCoverageSummary(noGraphAssessmentId);
  assert.deepEqual(emptySummary.boundaries, []);
  console.log('[+] missing attackSurfaceGraph → empty boundaries, no fabricated coverage');

  console.log('=== Coverage by Service Boundary smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
