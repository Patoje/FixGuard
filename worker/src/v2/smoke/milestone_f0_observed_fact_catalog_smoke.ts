/**
 * F0.1 — Observed fact catalog smoke.
 * Persists grounded facts. Rejects object/action ids that were not observed.
 */
import assert from 'node:assert/strict';
import { buildDetectionTargetsFromRecon } from '../detection/DetectionTargetBridge.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { validateAttackPlan } from '../storage/AttackPlanChainPersistenceValidation.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import {
  formatAnonSessionGetDeltaValue,
  type ObservedFact,
} from '../observation/ObservedFactContracts.js';
import { InMemoryObservedFactRepository } from '../observation/ObservedFactCatalogService.js';

const lineage = {
  assessmentId: 'asmt_f0_facts_001',
  scanId: 'scan_f0_facts_001',
  authorizationGrantId: 'grant_f0_facts_001',
  authorizationDecisionId: 'dec_f0_facts_001',
  actorId: 'act_f0_facts_op',
} as const;

const observedAt = '2026-09-28T12:00:00.000Z';

function emptyAggregated(
  urls: AggregatedReconObservations['urls'],
  parameters: AggregatedReconObservations['parameters'] = []
): AggregatedReconObservations {
  return {
    subdomains: [],
    dnsRecords: [],
    ports: [],
    webObservations: [],
    tlsCertificates: [],
    urls,
    content: [],
    parameters,
    secrets: [],
  };
}

function advisoryPlan(requiredFactIds: readonly string[]): AttackPlan {
  return {
    contractVersion: 'fixguard-attack-planning/v0',
    kind: 'attack_plan',
    planId: 'plan_f0_cite_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    capability: 'idor_read_differential',
    title: 'Cite observed object id',
    reasoning: 'Advisory plan cites a persisted observed fact. No severity.',
    status: 'prerequisite_missing',
    blastRadius: 'single_resource',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [],
    requiredFactIds,
    lineage,
    createdAt: observedAt,
    executable: false,
  };
}

async function main(): Promise<void> {
  console.log('=== F0.1 observed fact catalog smoke ===');
  const repo = new InMemoryObservedFactRepository();
  const orderUrl = 'https://app.example.com/orders/ord_123';

  const persisted = repo.record({
    factKind: 'observed_object_id',
    value: 'ord_123',
    observationText: orderUrl,
    sourceUrl: orderUrl,
    observationKind: 'url',
    lineage,
    observedAt,
    sourceLabel: 'rest_path',
  });
  assert.equal(persisted.status, 'persisted');
  if (persisted.status !== 'persisted') return;
  assert.equal(persisted.fact.epistemicStatus, 'OBSERVED');
  assert.equal(persisted.fact.value, 'ord_123');
  assert.equal('severity' in persisted.fact, false);

  const reloaded = repo.get(persisted.fact.factId);
  assert.ok(reloaded);
  assert.equal(reloaded?.value, 'ord_123');
  const listed = repo.listByAssessmentId(lineage.assessmentId);
  assert.equal(listed.length, 1);
  const mutable = listed[0] as ObservedFact & { value: string };
  mutable.value = 'mutated';
  assert.equal(repo.get(persisted.fact.factId)?.value, 'ord_123');
  console.log('[+] object id from a real URL persists and is mutation-safe');

  const inventedObject = repo.record({
    factKind: 'observed_object_id',
    value: 'ord_999',
    observationText: orderUrl,
    sourceUrl: orderUrl,
    observationKind: 'url',
    lineage,
    observedAt,
    sourceLabel: 'rest_path',
  });
  assert.equal(inventedObject.status, 'rejected');
  if (inventedObject.status === 'rejected') {
    assert.equal(inventedObject.reasonCode, 'identifier_not_in_observation');
  }
  assert.equal(repo.listByAssessmentId(lineage.assessmentId).length, 1);
  console.log('[+] invented object id is not persisted');

  const actionText = 'script next-action="act_observed_1"';
  const inventedAction = repo.record({
    factKind: 'observed_action_id',
    value: 'act_invented',
    observationText: actionText,
    sourceUrl: 'https://app.example.com/checkout',
    observationKind: 'http_body',
    lineage,
    observedAt,
    sourceLabel: 'byot_network_harvest',
  });
  assert.equal(inventedAction.status, 'rejected');
  const action = repo.record({
    factKind: 'observed_action_id',
    value: 'act_observed_1',
    observationText: actionText,
    sourceUrl: 'https://app.example.com/checkout',
    observationKind: 'http_body',
    lineage,
    observedAt,
    sourceLabel: 'byot_network_harvest',
  });
  assert.equal(action.status, 'persisted');
  console.log('[+] action id persists only when present in body text');

  const withSeverity = repo.recordUnknown({
    factKind: 'observed_object_id',
    value: 'ord_123',
    observationText: orderUrl,
    sourceUrl: orderUrl,
    observationKind: 'url',
    lineage,
    observedAt,
    severity: 'high',
  });
  assert.equal(withSeverity.status, 'rejected');
  if (withSeverity.status === 'rejected') {
    assert.equal(withSeverity.reasonCode, 'exact_key_rejected');
  }
  console.log('[+] severity and unknown keys are rejected');

  const paramUrl = 'https://app.example.com/api/items?user_id=42';
  const param = repo.record({
    factKind: 'observed_param',
    value: 'user_id',
    observationText: paramUrl,
    sourceUrl: paramUrl,
    observationKind: 'url',
    lineage,
    observedAt,
    sourceLabel: 'query_param',
  });
  assert.equal(param.status, 'persisted');
  const missingParam = repo.record({
    factKind: 'observed_param',
    value: 'account_id',
    observationText: paramUrl,
    sourceUrl: paramUrl,
    observationKind: 'url',
    lineage,
    observedAt,
    sourceLabel: 'query_param',
  });
  assert.equal(missingParam.status, 'rejected');

  const schemaText = 'relationship orders.user_id references profiles.id';
  const relation = repo.record({
    factKind: 'schema_relation',
    value: 'orders.user_id->profiles.id',
    observationText: schemaText,
    sourceUrl: 'https://app.example.com/rest/v1/',
    observationKind: 'schema_document',
    lineage,
    observedAt,
    sourceLabel: 'openapi',
  });
  assert.equal(relation.status, 'persisted');

  const deltaValue = formatAnonSessionGetDeltaValue({
    anonStatus: 401,
    sessionStatus: 200,
    anonBodyHash: 'aaaaaaaaaaaaaaaa',
    sessionBodyHash: 'bbbbbbbbbbbbbbbb',
    interfered: false,
  });
  const delta = repo.record({
    factKind: 'anon_session_get_delta',
    value: deltaValue,
    observationText: `GET /api/me ${deltaValue}`,
    sourceUrl: 'https://app.example.com/api/me',
    observationKind: 'differential_get',
    lineage,
    observedAt,
  });
  assert.equal(delta.status, 'persisted');
  const forgedDelta = formatAnonSessionGetDeltaValue({
    anonStatus: 200,
    sessionStatus: 200,
    anonBodyHash: 'aaaaaaaaaaaaaaaa',
    sessionBodyHash: 'bbbbbbbbbbbbbbbb',
    interfered: false,
  });
  const forged = repo.record({
    factKind: 'anon_session_get_delta',
    value: forgedDelta,
    observationText: `GET /api/me ${deltaValue}`,
    sourceUrl: 'https://app.example.com/api/me',
    observationKind: 'differential_get',
    lineage,
    observedAt,
  });
  assert.equal(forged.status, 'rejected');
  console.log('[+] param, schema relation, and anon/session delta stay grounded');

  const bridge = buildDetectionTargetsFromRecon({
    targetDomain: 'app.example.com',
    aggregatedObservations: emptyAggregated(
      [
        {
          url: orderUrl,
          host: 'app.example.com',
          path: '/orders/ord_123',
          sources: ['fixture'],
          discoveredAt: observedAt,
        },
      ],
      [
        {
          url: paramUrl,
          method: 'GET',
          parameterName: 'user_id',
          discoveredAt: observedAt,
        },
        {
          url: 'https://app.example.com/api/items',
          method: 'GET',
          parameterName: 'ghost_id',
          discoveredAt: observedAt,
        },
      ]
    ),
    lineage,
    observedAt,
  });
  assert.ok(bridge.observedFacts.some((fact) => fact.factKind === 'observed_object_id' && fact.value === 'ord_123'));
  assert.ok(bridge.observedFacts.some((fact) => fact.factKind === 'observed_param' && fact.value === 'user_id'));
  assert.equal(
    bridge.observedFacts.some((fact) => fact.value === 'ghost_id'),
    false
  );
  const unscoped = buildDetectionTargetsFromRecon({
    targetDomain: 'app.example.com',
    aggregatedObservations: emptyAggregated([
      {
        url: orderUrl,
        host: 'app.example.com',
        path: '/orders/ord_123',
        sources: ['fixture'],
        discoveredAt: observedAt,
      },
    ]),
  });
  assert.equal(unscoped.observedFacts.length, 0);
  console.log('[+] detection bridge emits only URL-grounded facts when lineage is present');

  if (persisted.status === 'persisted') {
    const plan = advisoryPlan([persisted.fact.factId]);
    assert.equal(validateAttackPlan(plan), true);
    assert.equal(plan.executable, false);
  }
  console.log('[+] plans may cite requiredFactIds without becoming executable');

  console.log('=== F0.1 observed fact catalog smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
