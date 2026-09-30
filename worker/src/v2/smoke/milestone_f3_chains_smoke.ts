/**
 * F3.A–F3.C — Advisory chains. Hermetic: no live CLIs, no network.
 */
import assert from 'node:assert/strict';
import { ACTIVE_INVESTIGATION_CONTRACT_VERSION } from '../active-investigation/ActiveInvestigationContracts.js';
import { ActiveInvestigationRuntimeService } from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { authorizePlan } from '../attack-authorization/AttackAuthorizationService.js';
import type {
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../attack-execution/AttackExecutionContracts.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import type { AttackCapabilityKind, AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { PriorStepProduction } from '../attack-planning/AttackPlanDependencyService.js';
import {
  proposeAuthBoundaryResourceRead,
  proposeParameterFedProbe,
  proposeServerActionRecommendation,
  proposeSessionBDifferential,
  proposeSupabaseReadThenWrite,
  recordExecutedReadOnChain,
} from '../attack-planning/F3ChainProposal.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { formatAnonSessionGetDeltaValue } from '../observation/ObservedFactContracts.js';
import { tryBuildObservedFact } from '../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../observation/ObservedFactContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const nowIso = new Date().toISOString();
const lineage = {
  assessmentId: 'asmt_f3_chain_001',
  scanId: 'scan_f3_chain_001',
  authorizationGrantId: 'grant_f3_chain_001',
  authorizationDecisionId: 'dec_f3_chain_001',
  actorId: 'act_f3_chain_op',
} as const;

function mustFact(fact: ObservedFact | null, label: string): ObservedFact {
  if (!fact) throw new Error(`fact was not grounded: ${label}`);
  return fact;
}

function prior(factIds: readonly string[]): PriorStepProduction {
  return { planId: 'plan_f3_parent_001', producedFactIds: factIds, capabilityGained: 'none' };
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: nowIso,
    expiresAt: '2027-09-28T00:00:00.000Z',
    subject: { targetKind: 'origin', normalizedOrigin: `https://${HOST}` },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for F3 chain smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [HOST],
      allowedHosts: [HOST],
      allowedOrigins: [`https://${HOST}`],
      allowedMethods: ['GET', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
}

function startRuntime(investigationId: string): {
  runtime: ActiveInvestigationRuntimeService;
  decision: VerifiedAuthorizationDecision;
} {
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: scopeGrant(),
    },
    nowIso
  );
  assert.equal(auth.status, 'established');
  if (auth.status !== 'established' || !auth.decision) throw new Error('auth missing');
  const runtime = new ActiveInvestigationRuntimeService();
  const started = runtime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId,
    lineage,
    verifiedAuthorizationDecision: auth.decision,
    budget: {
      maxRequests: 10,
      maxDurationMs: 600_000,
      maxConcurrentSteps: 1,
      requestsPerSecondCeiling: 5,
      maxConcurrencyCeiling: 2,
    },
    openHypothesisRefs: [],
    startedAt: nowIso,
  });
  assert.equal(started.status, 'started');
  return { runtime, decision: auth.decision };
}

function contextFor(
  plan: AttackPlan,
  decision: VerifiedAuthorizationDecision,
  blast: 'read_public' | 'read_authenticated'
): AttackCapabilityInvocationContext {
  const token = authorizePlan(plan.planId, plan.assessmentId, blast, lineage.actorId, nowIso);
  assert.equal(token.status, 'established');
  if (token.status !== 'established') throw new Error('token missing');
  return {
    plan,
    step: {
      stepId: `step_${plan.planId}`,
      ordinal: 1,
      title: 'Read',
      description: 'GET',
      status: 'blocked',
      requiredPermissions: ['activeValidation'],
      blastRadiusClass: blast,
    },
    token: token.token,
    targetHost: HOST,
    targetUrl: plan.targetUrl ?? `https://${HOST}/items`,
    scopeGrant: scopeGrant(),
    findings: [],
    verifiedAuthorizationDecision: decision,
  };
}

function port(capability: AttackCapabilityKind, calls: string[]): AttackCapabilityPort {
  return {
    capability,
    async execute() {
      calls.push(capability);
      return { outcome: 'observed', reasonCode: 'read_observed', safeMessage: 'hermetic GET' };
    },
  };
}

async function main(): Promise<void> {
  console.log('=== F3 chain smoke ===');

  const endpoint = `https://${HOST}/api/orders/ord_1001`;
  const delta = formatAnonSessionGetDeltaValue({
    anonStatus: 401,
    sessionStatus: 200,
    anonBodyHash: 'aaaaaaaaaaaaaaaa',
    sessionBodyHash: 'bbbbbbbbbbbbbbbb',
    interfered: false,
  });
  const endpointFact = mustFact(
    tryBuildObservedFact({
      factKind: 'anon_session_get_delta',
      value: delta,
      observationText: `${endpoint} ${delta}`,
      sourceUrl: endpoint,
      observationKind: 'differential_get',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'auth_boundary_differential',
    }),
    'endpoint'
  );
  const objectFact = mustFact(
    tryBuildObservedFact({
      factKind: 'observed_object_id',
      value: 'ord_1001',
      observationText: endpoint,
      sourceUrl: endpoint,
      observationKind: 'url',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'byot_network_harvest',
    }),
    'object'
  );
  const foreignObject = mustFact(
    tryBuildObservedFact({
      factKind: 'observed_object_id',
      value: 'ord_1001',
      observationText: endpoint,
      sourceUrl: endpoint,
      observationKind: 'url',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'rest_path',
    }),
    'foreign object'
  );
  const idParam = mustFact(
    tryBuildObservedFact({
      factKind: 'observed_param',
      value: 'id',
      observationText: `${endpoint}?id=ord_1001`,
      sourceUrl: `${endpoint}?id=ord_1001`,
      observationKind: 'url',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'jsluice',
    }),
    'id param'
  );
  const queryParam = mustFact(
    tryBuildObservedFact({
      factKind: 'observed_param',
      value: 'q',
      observationText: `https://${HOST}/search?q=1`,
      sourceUrl: `https://${HOST}/search?q=1`,
      observationKind: 'url',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'jsluice',
    }),
    'q param'
  );
  const actionId = 'act_12345678';
  const actionFact = mustFact(
    tryBuildObservedFact({
      factKind: 'observed_action_id',
      value: actionId,
      observationText: `next-action ${actionId}`,
      sourceUrl: endpoint,
      observationKind: 'http_header',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'byot_network_harvest',
    }),
    'action'
  );
  const relation = 'orders.id->users.id';
  const tableFact = mustFact(
    tryBuildObservedFact({
      factKind: 'schema_relation',
      value: relation,
      observationText: `schema ${relation} from openapi`,
      sourceUrl: `https://${HOST}/rest/v1/`,
      observationKind: 'schema_document',
      lineage,
      observedAt: nowIso,
      sourceLabel: 'api_schema_discovery',
    }),
    'table'
  );

  const base = {
    identities: [{ identityId: 'id_a' }],
    lineage,
    createdAt: nowIso,
  };

  const noIdentity = proposeAuthBoundaryResourceRead({
    ...base,
    identities: [],
    prior: prior([endpointFact.factId]),
    fact: endpointFact,
  });
  assert.equal(noIdentity.status, 'not_emitted');
  const boundary = proposeAuthBoundaryResourceRead({
    ...base,
    prior: prior([endpointFact.factId]),
    fact: endpointFact,
  });
  assert.equal(boundary.status, 'emitted');
  if (boundary.status !== 'emitted') throw new Error('boundary missing');
  assert.equal(boundary.plan.capability, 'auth_boundary_differential');
  assert.equal(boundary.plan.executable, false);
  assert.equal(boundary.plan.targetUrl, endpoint);
  assert.equal(boundary.plan.status, 'ready_for_authorization');
  assert.deepEqual(boundary.plan.dependsOn, ['plan_f3_parent_001']);
  console.log('[+] F3.A proposes one GET auth-boundary read for identity A');

  const noObject = proposeSessionBDifferential({
    ...base,
    prior: prior([]),
    identities: [{ identityId: 'id_a' }, { identityId: 'id_b' }],
  });
  assert.equal(noObject.status, 'not_emitted');
  const notHarvest = proposeSessionBDifferential({
    ...base,
    prior: prior([foreignObject.factId]),
    fact: foreignObject,
    identities: [{ identityId: 'id_a' }, { identityId: 'id_b' }],
  });
  assert.equal(notHarvest.status, 'not_emitted');
  const missingB = proposeSessionBDifferential({
    ...base,
    prior: prior([objectFact.factId]),
    fact: objectFact,
  });
  assert.equal(missingB.status, 'emitted');
  if (missingB.status !== 'emitted') throw new Error('missing B plan');
  assert.equal(missingB.plan.status, 'prerequisite_missing');
  assert.equal(missingB.plan.capability, 'idor_read_differential');
  assert.equal(missingB.plan.parameterName, 'ord_1001');
  assert.equal(missingB.plan.executable, false);
  const withB = proposeSessionBDifferential({
    ...base,
    prior: prior([objectFact.factId]),
    fact: objectFact,
    identities: [{ identityId: 'id_a' }, { identityId: 'id_b' }],
  });
  assert.equal(withB.status, 'emitted');
  if (withB.status !== 'emitted') throw new Error('session B plan');
  assert.equal(withB.plan.status, 'ready_for_authorization');
  assert.equal(withB.plan.executable, false);
  console.log('[+] F3.B emits IDOR only for a harvested object id');

  const noParam = proposeParameterFedProbe({ ...base, prior: prior([]) });
  assert.equal(noParam.status, 'not_emitted');
  const notId = proposeParameterFedProbe({
    ...base,
    prior: prior([queryParam.factId]),
    fact: queryParam,
  });
  assert.equal(notId.status, 'not_emitted');
  const fed = proposeParameterFedProbe({
    ...base,
    prior: prior([idParam.factId]),
    fact: idParam,
  });
  assert.equal(fed.status, 'emitted');
  if (fed.status !== 'emitted') throw new Error('param child');
  assert.equal(fed.plan.parameterName, 'id');
  assert.deepEqual(fed.plan.dependsOn, ['plan_f3_parent_001']);
  assert.equal(fed.plan.executable, false);
  const fedTable = proposeParameterFedProbe({
    ...base,
    prior: prior([tableFact.factId]),
    fact: tableFact,
  });
  assert.equal(fedTable.status, 'emitted');
  if (fedTable.status !== 'emitted') throw new Error('table child');
  assert.equal(fedTable.plan.parameterName, 'orders');
  assert.equal(fedTable.plan.capability, 'supabase_rls_read_confirm');
  console.log('[+] F3.E child cites parameterName and dependsOn');

  const noAction = proposeServerActionRecommendation({ ...base, prior: prior([]) });
  assert.equal(noAction.status, 'not_emitted');
  const action = proposeServerActionRecommendation({
    ...base,
    prior: prior([actionFact.factId]),
    fact: actionFact,
  });
  assert.equal(action.status, 'emitted');
  if (action.status !== 'emitted') throw new Error('action plan');
  assert.equal(action.plan.capability, 'next_server_action_diff');
  assert.equal(action.plan.parameterName, actionId);
  assert.equal(action.plan.executable, false);
  console.log('[+] F3.D recommends the observed Server Action');

  const noTable = proposeSupabaseReadThenWrite({ ...base, prior: prior([]) });
  assert.equal(noTable.status, 'not_emitted');
  const supabase = proposeSupabaseReadThenWrite({
    ...base,
    prior: prior([tableFact.factId]),
    fact: tableFact,
  });
  assert.equal(supabase.status, 'emitted');
  if (supabase.status !== 'emitted') throw new Error('supabase chain');
  assert.equal(supabase.readPlan.capability, 'supabase_rls_read_confirm');
  assert.equal(supabase.readPlan.parameterName, 'orders');
  assert.equal(supabase.readPlan.executable, false);
  assert.equal(supabase.writeRecommendation.capability, 'supabase_authz_write_matrix');
  assert.equal(supabase.writeRecommendation.executable, false);
  assert.equal(supabase.writeRecommendation.status, 'prerequisite_missing');
  assert.deepEqual(supabase.writeRecommendation.dependsOn, [supabase.readPlan.planId]);
  console.log('[+] F3.C proposes the RLS read and holds the write matrix');

  const calls: string[] = [];
  const registry = new AttackCapabilityRegistry([
    port('auth_boundary_differential', calls),
    port('supabase_rls_read_confirm', calls),
    port('idor_read_differential', calls),
    port('next_server_action_diff', calls),
    port('supabase_authz_write_matrix', calls),
  ]);
  const first = startRuntime('inv_f3_src');
  const srcLoop = await first.runtime.runReadOnlyLoop({
    investigationId: 'inv_f3_src',
    registry,
    nowIso,
    steps: [
      {
        stepId: 'step_f3_src',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: contextFor(boundary.plan, first.decision, 'read_public'),
      },
    ],
  });
  assert.deepEqual(srcLoop.executedCapabilities, ['auth_boundary_differential']);

  const repo = new InMemoryAttackChainRepository();
  const chains = new AttackChainService(repo);
  await chains.initHypothesis({
    chainId: 'chain_f3_a_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    hypothesis: 'Identity A can read the observed endpoint',
    objectiveKind: 'information_disclosure',
    impactLevel: 'information_exposure',
    lineage,
    createdAt: nowIso,
  });
  await chains.appendExecutedStep({
    chainId: 'chain_f3_a_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    stepId: 'step_f3_src',
    capabilityKind: 'auth_boundary_differential',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'read_authenticated',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'read_observed',
      safeMessage: 'GET auth boundary completed',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });

  const second = startRuntime('inv_f3_follow');
  const follow = await second.runtime.runReadOnlyLoop({
    investigationId: 'inv_f3_follow',
    registry,
    nowIso,
    chainRecord: {
      service: chains,
      chainId: 'chain_f3_a_001',
      sourceStepId: 'step_f3_src',
    },
    steps: [
      {
        stepId: 'step_f3_diff',
        capability: 'idor_read_differential',
        blastRadiusClass: 'read_public',
        context: contextFor(
          withB.status === 'emitted' ? withB.plan : boundary.plan,
          second.decision,
          'read_public'
        ),
      },
      {
        stepId: 'step_f3_action',
        capability: 'next_server_action_diff',
        blastRadiusClass: 'read_public',
        context: contextFor(action.plan, second.decision, 'read_public'),
      },
      {
        stepId: 'step_f3_write',
        capability: 'supabase_authz_write_matrix',
        blastRadiusClass: 'state_change_benign',
      },
      {
        stepId: 'step_f3_res',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: contextFor(boundary.plan, second.decision, 'read_public'),
      },
      {
        stepId: 'step_f3_rls',
        capability: 'supabase_rls_read_confirm',
        blastRadiusClass: 'read_public',
        context: contextFor(supabase.readPlan, second.decision, 'read_public'),
      },
    ],
  });
  assert.deepEqual(follow.executedCapabilities, [
    'auth_boundary_differential',
    'supabase_rls_read_confirm',
  ]);
  assert.ok(calls.includes('auth_boundary_differential'));
  assert.equal(calls.includes('idor_read_differential'), false);
  assert.equal(calls.includes('next_server_action_diff'), false);
  assert.equal(calls.includes('supabase_authz_write_matrix'), false);

  const chained = await chains.getChain('chain_f3_a_001');
  if (!chained) throw new Error('chain missing');
  const resource = chained.steps.find((step) => step.stepId === 'step_f3_res');
  const rlsStep = chained.steps.find((step) => step.stepId === 'step_f3_rls');
  assert.equal(resource?.sourceStepId, 'step_f3_src');
  assert.equal(resource?.epistemicStatus, 'OBSERVED');
  assert.equal(rlsStep?.sourceStepId, 'step_f3_src');
  assert.equal(rlsStep?.epistemicStatus, 'OBSERVED');
  assert.equal(chained.overallEpistemicStatus, 'OBSERVED');
  assert.notEqual(chained.overallEpistemicStatus, 'VERIFIED');
  console.log('[+] executed GET is on the chain with sourceStepId and stays OBSERVED');

  await chains.initHypothesis({
    chainId: 'chain_f3_cap_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    hypothesis: 'Epistemic cap',
    objectiveKind: 'information_disclosure',
    impactLevel: 'information_exposure',
    lineage,
    createdAt: nowIso,
  });
  await chains.appendExecutedStep({
    chainId: 'chain_f3_cap_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    stepId: 'step_f3_src',
    capabilityKind: 'auth_boundary_differential',
    epistemicStatus: 'OBSERVED',
    capabilityGained: 'read_authenticated',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'read_observed',
      safeMessage: 'GET auth boundary completed',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  const deniedWrite = await recordExecutedReadOnChain(chains, {
    chainId: 'chain_f3_cap_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    stepId: 'step_f3_write',
    sourceStepId: 'step_f3_src',
    capabilityKind: 'supabase_authz_write_matrix',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'not_a_read',
      safeMessage: 'write must not be recorded as a read',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
    requestedEpistemicStatus: 'VERIFIED',
  });
  assert.equal(deniedWrite.status, 'not_recorded');
  const capped = await recordExecutedReadOnChain(chains, {
    chainId: 'chain_f3_cap_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    stepId: 'step_f3_res',
    sourceStepId: 'step_f3_src',
    capabilityKind: 'auth_boundary_differential',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'read_observed',
      safeMessage: 'GET resource read completed',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
    requestedEpistemicStatus: 'VERIFIED',
  });
  assert.equal(capped.status, 'recorded');
  if (capped.status !== 'recorded') throw new Error('cap record');
  assert.equal(capped.chain.steps.find((step) => step.stepId === 'step_f3_res')?.epistemicStatus, 'OBSERVED');
  assert.equal(capped.chain.overallEpistemicStatus, 'OBSERVED');
  const deniedAction = await recordExecutedReadOnChain(chains, {
    chainId: 'chain_f3_cap_001',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    stepId: 'step_f3_action',
    sourceStepId: 'step_f3_src',
    capabilityKind: 'next_server_action_diff',
    outcome: 'succeeded',
    evidence: {
      reasonCode: 'not_a_read',
      safeMessage: 'server action must not be recorded as a read',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(deniedAction.status, 'not_recorded');
  console.log('[+] write and Server Action stay off the read chain');

  console.log('=== F3 chain smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
