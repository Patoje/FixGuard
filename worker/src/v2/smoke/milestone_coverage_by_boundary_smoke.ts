/**
 * Milestone R9 (Hito 3 — Profundidad adaptativa) smoke, corrected 2026-10-25
 * audit pass.
 *
 * Verifies getPlanningActivitySummary() correctly cross-references real
 * AttackSurfaceGraph service_boundary groupings against the real AttackPlan
 * list, sorted by least actionable-plan activity first. This is planning
 * activity, not investigation or execution coverage — see
 * docs/decisions/RECON-DEPTH-ANALYSIS-2026-10-25.md sections 2/3/4/8.
 *
 * Audit regression covered (2026-10-25): a 'rejected' AttackPlan must count
 * toward plannedEndpoints (a plan was generated) but NOT toward
 * actionableEndpoints (it was explicitly decided not to pursue it) — the
 * previous getCoverageSummary() counted it toward "investigated" either way.
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

function buildPlan(
  planId: string,
  targetUrl: string,
  status: AttackPlan['status'] = 'ready_for_authorization'
): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId: ASSESSMENT_ID,
    scanId: SCAN_ID,
    capability: 'security_header_probe',
    title: 'Coverage smoke plan',
    reasoning: 'Hermetic plan for coverage-by-boundary smoke',
    status,
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
  console.log('=== Planning Activity by Service Boundary (Hito 3) smoke ===');

  // /api: 4 endpoints — users (live plan), orders (rejected plan),
  // legacy (superseded plan), billing (no plan).
  // /admin: 2 endpoints, no plans at all.
  const apiUsers = endpointNode('ep_api_users', 'https://app.example.com/api/users', '/api/users');
  const apiOrders = endpointNode('ep_api_orders', 'https://app.example.com/api/orders', '/api/orders');
  const apiLegacy = endpointNode('ep_api_legacy', 'https://app.example.com/api/legacy', '/api/legacy');
  const apiBilling = endpointNode('ep_api_billing', 'https://app.example.com/api/billing', '/api/billing');
  const adminPanel = endpointNode('ep_admin_panel', 'https://app.example.com/admin/panel', '/admin/panel');
  const adminSettings = endpointNode(
    'ep_admin_settings',
    'https://app.example.com/admin/settings',
    '/admin/settings'
  );
  const apiBoundary = boundaryNode('bnd_api', '/api', 4);
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
    nodes: [apiUsers, apiOrders, apiLegacy, apiBilling, adminPanel, adminSettings, apiBoundary, adminBoundary],
    edges: [
      groupsEdge('e1', 'bnd_api', 'ep_api_users'),
      groupsEdge('e2', 'bnd_api', 'ep_api_orders'),
      groupsEdge('e3', 'bnd_api', 'ep_api_legacy'),
      groupsEdge('e4', 'bnd_api', 'ep_api_billing'),
      groupsEdge('e5', 'bnd_admin', 'ep_admin_panel'),
      groupsEdge('e6', 'bnd_admin', 'ep_admin_settings'),
    ],
  };

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const attackPlanRepository = new InMemoryAttackPlanRepository();
  await repository.save(buildRecord(graph));
  await attackPlanRepository.savePlans([
    buildPlan('plan_cov_1', 'https://app.example.com/api/users', 'ready_for_authorization'),
    buildPlan('plan_cov_2', 'https://app.example.com/api/orders', 'rejected'),
    buildPlan('plan_cov_3', 'https://app.example.com/api/legacy', 'superseded'),
  ]);

  const service = new OrchestratedAssessmentApplicationService({ repository, attackPlanRepository });
  const summary = await service.getPlanningActivitySummary(ASSESSMENT_ID);

  assert.equal(summary.boundaries.length, 2);
  // Least actionable-plan activity first: /admin (0) before /api (1 of 4 actionable).
  assert.equal(summary.boundaries[0]!.pathPrefix, '/admin');
  assert.equal(summary.boundaries[0]!.totalEndpoints, 2);
  assert.equal(summary.boundaries[0]!.plannedEndpoints, 0);
  assert.equal(summary.boundaries[0]!.actionableEndpoints, 0);
  assert.equal(summary.boundaries[0]!.actionablePlanRatio, 0);

  const api = summary.boundaries[1]!;
  assert.equal(api.pathPrefix, '/api');
  assert.equal(api.totalEndpoints, 4);
  // plannedEndpoints counts users + orders + legacy (a plan was generated for all three,
  // regardless of status) — this is the raw "generated" count. billing has no plan at all.
  assert.equal(
    api.plannedEndpoints,
    3,
    'rejected AND superseded plans must still count as planned (a plan was generated for both)'
  );
  // actionableEndpoints counts users ONLY — orders (rejected) and legacy (superseded) must be excluded.
  assert.equal(api.actionableEndpoints, 1, 'rejected and superseded plans must NOT count as actionable');
  assert.equal(api.actionablePlanRatio, 1 / 4);
  console.log('[+] rejected AND superseded plans count as planned but not actionable — /admin (0 actionable) sorts before /api (1/4 actionable)');

  // Adversarial: no attackSurfaceGraph at all (recon never completed) → empty, no fabricated number.
  const noGraphAssessmentId = 'asmt_cov_002';
  const record2 = { ...buildRecord(undefined), assessmentId: noGraphAssessmentId };
  await repository.save(record2);
  const emptySummary = await service.getPlanningActivitySummary(noGraphAssessmentId);
  assert.deepEqual(emptySummary.boundaries, []);
  console.log('[+] missing attackSurfaceGraph → empty boundaries, no fabricated activity');

  console.log('=== Planning Activity by Service Boundary smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
