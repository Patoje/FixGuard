/**
 * F2.1–F2.4 — Next-step engine, read-only investigation loop, and gate check.
 * Hermetic: no live CLIs, no network.
 */
import assert from 'node:assert/strict';
import { ACTIVE_INVESTIGATION_CONTRACT_VERSION } from '../active-investigation/ActiveInvestigationContracts.js';
import {
  ActiveInvestigationRuntimeService,
  type ReadOnlyLoopStep,
} from '../active-investigation/ActiveInvestigationRuntimeService.js';
import { authorizePlan } from '../attack-authorization/AttackAuthorizationService.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import type {
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../attack-execution/AttackExecutionContracts.js';
import {
  AttackCapabilityRegistry,
  createNotImplementedCapability,
} from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { proposeNextAdvisoryStep } from '../attack-planning/NextStepEngine.js';
import type { PriorStepProduction } from '../attack-planning/AttackPlanDependencyService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { validateAttackPlan } from '../storage/AttackPlanChainPersistenceValidation.js';

const SECRET = 'vault-secret-f2-not-in-json';
const HOST = 'app.example.com';
const nowIso = new Date().toISOString();

const lineage = {
  assessmentId: 'asmt_f2_loop_001',
  scanId: 'scan_f2_loop_001',
  authorizationGrantId: 'grant_f2_loop_001',
  authorizationDecisionId: 'dec_f2_loop_001',
  actorId: 'act_f2_loop_op',
} as const;

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: nowIso,
    expiresAt: '2027-09-28T00:00:00.000Z',
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${HOST}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for F2 read-loop smoke',
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

function advisoryPlan(
  planId: string,
  capability: AttackCapabilityKind
): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    capability,
    title: 'Advisory plan',
    reasoning: 'Hermetic advisory plan. It does not execute by itself.',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: ['observed_surface'],
    prerequisites: [],
    steps: [
      {
        stepId: `step_${planId}`,
        ordinal: 1,
        title: 'Read',
        description: 'GET read held until a branded authorization token exists.',
        status: 'blocked',
        requiredPermissions: ['activeValidation'],
      },
    ],
    planOrigin: 'observed_surface',
    lineage,
    createdAt: nowIso,
    targetUrl: `https://${HOST}/items`,
    executable: false,
  };
}

function prior(producedFactIds: readonly string[], capabilityGained: PriorStepProduction['capabilityGained']): PriorStepProduction {
  return {
    planId: 'plan_f2_parent_001',
    producedFactIds,
    capabilityGained,
  };
}

function startRuntime(investigationId: string, maxRequests: number): {
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
  if (auth.status !== 'established' || !auth.decision) {
    throw new Error('verified authorization was not established');
  }
  const runtime = new ActiveInvestigationRuntimeService();
  const started = runtime.startInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'start_active_investigation_request',
    investigationId,
    lineage,
    verifiedAuthorizationDecision: auth.decision,
    budget: {
      maxRequests,
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

function brandedToken(plan: AttackPlan, blast: 'read_public' | 'read_authenticated' | 'read_escalated') {
  const established = authorizePlan(
    plan.planId,
    plan.assessmentId,
    blast,
    lineage.actorId,
    nowIso
  );
  assert.equal(established.status, 'established');
  if (established.status !== 'established') {
    throw new Error('attack authorization was not established');
  }
  return established.token;
}

function invocation(input: {
  plan: AttackPlan;
  decision: VerifiedAuthorizationDecision;
  blast: 'read_public' | 'read_authenticated' | 'read_escalated';
  secretHeader?: string;
}): AttackCapabilityInvocationContext {
  return {
    plan: input.plan,
    step: {
      stepId: `step_${input.plan.planId}`,
      ordinal: 1,
      title: 'Read',
      description: 'GET',
      status: 'blocked',
      requiredPermissions: ['activeValidation'],
      blastRadiusClass: input.blast,
    },
    token: brandedToken(input.plan, input.blast),
    targetHost: HOST,
    targetUrl: `https://${HOST}/items`,
    scopeGrant: scopeGrant(),
    findings: [],
    verifiedAuthorizationDecision: input.decision,
    ...(input.secretHeader ? { primaryIdentity: { identityId: 'id_a', headers: { 'x-smoke': input.secretHeader } } } : {}),
  };
}

function countingPort(capability: AttackCapabilityKind, calls: string[]): AttackCapabilityPort {
  return {
    capability,
    async execute(ctx) {
      if (ctx.credentialVaultService || ctx.credentialReference) {
        throw new Error('credential vault reached the read loop');
      }
      calls.push(capability);
      return {
        outcome: 'observed',
        reasonCode: 'read_observed',
        safeMessage: 'hermetic GET',
      };
    },
  };
}

async function main(): Promise<void> {
  console.log('=== F2 next-step and read-loop smoke ===');

  const missing = proposeNextAdvisoryStep({
    prior: prior([], 'read_authenticated'),
    lineage,
    createdAt: nowIso,
  });
  assert.equal(missing.status, 'not_emitted');
  if (missing.status === 'not_emitted') {
    assert.equal(missing.reasonCode, 'prior_fact_missing');
  }
  console.log('[+] no child plan without a prior fact');

  const notRead = proposeNextAdvisoryStep({
    prior: prior(['fact_param_001'], 'none'),
    fact: { factId: 'fact_param_001', factKind: 'observed_param' },
    lineage,
    createdAt: nowIso,
  });
  assert.equal(notRead.status, 'not_emitted');
  if (notRead.status === 'not_emitted') {
    assert.equal(notRead.reasonCode, 'read_fact_kind_not_allowed');
  }
  console.log('[+] a non-read fact does not emit a child');

  const boundary = proposeNextAdvisoryStep({
    prior: prior(['fact_delta_001'], 'none'),
    fact: { factId: 'fact_delta_001', factKind: 'anon_session_get_delta' },
    lineage,
    createdAt: nowIso,
  });
  assert.equal(boundary.status, 'emitted');
  if (boundary.status !== 'emitted') throw new Error('boundary child missing');
  assert.equal(boundary.plan.capability, 'auth_boundary_differential');
  assert.equal(boundary.plan.executable, false);
  assert.deepEqual(boundary.plan.dependsOn, ['plan_f2_parent_001']);
  assert.deepEqual(boundary.plan.requiredFactIds, ['fact_delta_001']);
  assert.equal(validateAttackPlan(boundary.plan), true);
  assert.equal(JSON.stringify(boundary.plan).includes(SECRET), false);
  console.log('[+] anon/session fact emits exactly auth_boundary_differential');

  const rls = proposeNextAdvisoryStep({
    prior: prior(['fact_schema_001'], 'none'),
    fact: { factId: 'fact_schema_001', factKind: 'schema_relation' },
    lineage,
    createdAt: nowIso,
  });
  assert.equal(rls.status, 'emitted');
  if (rls.status !== 'emitted') throw new Error('rls child missing');
  assert.equal(rls.plan.capability, 'supabase_rls_read_confirm');
  assert.equal(rls.plan.executable, false);
  console.log('[+] schema fact emits exactly supabase_rls_read_confirm');

  const ambiguous = proposeNextAdvisoryStep({
    prior: prior(['fact_schema_002'], 'read_authenticated'),
    fact: { factId: 'fact_schema_002', factKind: 'schema_relation' },
    lineage,
    createdAt: nowIso,
  });
  assert.equal(ambiguous.status, 'not_emitted');
  if (ambiguous.status === 'not_emitted') {
    assert.equal(ambiguous.reasonCode, 'next_step_ambiguous');
  }
  console.log('[+] disagreeing fact and capability emit nothing');

  const cancelled = proposeNextAdvisoryStep({
    prior: prior(['fact_delta_009'], 'none'),
    fact: { factId: 'fact_delta_009', factKind: 'anon_session_get_delta' },
    lineage,
    createdAt: nowIso,
    cancelled: true,
  });
  assert.equal(cancelled.status, 'not_emitted');
  if (cancelled.status === 'not_emitted') {
    assert.equal(cancelled.reasonCode, 'cancelled');
  }
  console.log('[+] cancel emits no child');

  const calls: string[] = [];
  const registry = new AttackCapabilityRegistry([
    countingPort('auth_boundary_differential', calls),
    countingPort('supabase_rls_read_confirm', calls),
    countingPort('credential_reuse', calls),
    countingPort('supabase_rls_write_probe', calls),
    countingPort('nuclei_xss_scan', calls),
  ]);

  const vault = new CredentialVaultService();
  const credentialRef = {
    contractVersion: 'fixguard-post-exploitation/v0' as const,
    kind: 'credential_reference' as const,
    credentialId: 'cred_f2_001',
    credentialKind: 'bearer_token' as const,
    source: 'operator' as const,
    discoveredAt: nowIso,
  };
  vault.store(credentialRef, SECRET);

  const { runtime, decision } = startRuntime('inv_f2_reads', 10);
  const publicPlan = advisoryPlan('plan_f2_public_001', 'auth_boundary_differential');
  const authnPlan = advisoryPlan('plan_f2_authn_001', 'supabase_rls_read_confirm');
  const escalatedPlan = advisoryPlan('plan_f2_esc_001', 'auth_boundary_differential');
  const steps: readonly ReadOnlyLoopStep[] = [
    {
      stepId: 'step_f2_cred',
      capability: 'credential_reuse',
      blastRadiusClass: 'credential_use',
      context: {
        ...invocation({ plan: publicPlan, decision, blast: 'read_public', secretHeader: SECRET }),
        credentialReference: credentialRef,
        credentialVaultService: vault,
      },
    },
    {
      stepId: 'step_f2_state_benign',
      capability: 'supabase_rls_write_probe',
      blastRadiusClass: 'state_change_benign',
    },
    {
      stepId: 'step_f2_state_impact',
      capability: 'supabase_rls_write_probe',
      blastRadiusClass: 'state_change_impact',
    },
    {
      stepId: 'step_f2_lateral',
      capability: 'credential_reuse',
      blastRadiusClass: 'lateral_movement',
    },
    {
      stepId: 'step_f2_nuclei',
      capability: 'nuclei_xss_scan',
      blastRadiusClass: 'read_public',
      context: invocation({ plan: advisoryPlan('plan_f2_nuclei_001', 'nuclei_xss_scan'), decision, blast: 'read_public' }),
    },
    {
      stepId: 'step_f2_boundary',
      capability: 'auth_boundary_differential',
      blastRadiusClass: 'read_public',
      context: invocation({ plan: publicPlan, decision, blast: 'read_public' }),
    },
    {
      stepId: 'step_f2_rls',
      capability: 'supabase_rls_read_confirm',
      blastRadiusClass: 'read_authenticated',
      context: invocation({ plan: authnPlan, decision, blast: 'read_authenticated' }),
    },
    {
      stepId: 'step_f2_unbranded',
      capability: 'auth_boundary_differential',
      blastRadiusClass: 'read_public',
      context: invocation({ plan: escalatedPlan, decision, blast: 'read_escalated' }),
    },
  ];

  const loop = await runtime.runReadOnlyLoop({
    investigationId: 'inv_f2_reads',
    registry,
    steps,
    nowIso,
  });
  assert.equal(loop.status, 'completed');
  assert.deepEqual(loop.executedCapabilities, [
    'auth_boundary_differential',
    'supabase_rls_read_confirm',
  ]);
  assert.deepEqual(calls, ['auth_boundary_differential', 'supabase_rls_read_confirm']);
  const recommended = loop.steps.filter((step) => step.disposition === 'recommended').map((step) => step.capability);
  assert.ok(recommended.includes('credential_reuse'));
  assert.ok(recommended.includes('supabase_rls_write_probe'));
  assert.ok(recommended.includes('nuclei_xss_scan'));
  assert.equal(JSON.stringify(loop).includes(SECRET), false);
  console.log('[+] read loop executes only the two GET reads and keeps the rest as recommendations');

  const killed = startRuntime('inv_f2_kill', 5);
  const kill = killed.runtime.cancelInvestigation({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'cancel_active_investigation_request',
    investigationId: 'inv_f2_kill',
    operatorId: lineage.actorId,
    mode: 'kill_switch',
    cancelledAt: nowIso,
  });
  assert.equal(kill.status, 'cancelled');
  const killCalls: string[] = [];
  const killLoop = await killed.runtime.runReadOnlyLoop({
    investigationId: 'inv_f2_kill',
    registry: new AttackCapabilityRegistry([
      countingPort('auth_boundary_differential', killCalls),
    ]),
    steps: [
      {
        stepId: 'step_f2_after_kill',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: invocation({
          plan: advisoryPlan('plan_f2_kill_001', 'auth_boundary_differential'),
          decision: killed.decision,
          blast: 'read_public',
        }),
      },
    ],
    nowIso,
  });
  assert.equal(killLoop.status, 'stopped');
  assert.equal(killLoop.reasonCode, 'kill_switch_engaged');
  assert.deepEqual(killCalls, []);
  console.log('[+] kill-switch stops the read loop before execution');

  const cancelRuntime = startRuntime('inv_f2_cancel', 5);
  const cancelCalls: string[] = [];
  const cancelRegistry = new AttackCapabilityRegistry([
    {
      capability: 'auth_boundary_differential',
      async execute() {
        cancelCalls.push('auth_boundary_differential');
        cancelRuntime.runtime.cancelInvestigation({
          contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
          kind: 'cancel_active_investigation_request',
          investigationId: 'inv_f2_cancel',
          operatorId: lineage.actorId,
          mode: 'cancel',
          cancelledAt: nowIso,
        });
        return { outcome: 'observed' as const, reasonCode: 'read_observed', safeMessage: 'hermetic GET' };
      },
    },
  ]);
  const cancelLoop = await cancelRuntime.runtime.runReadOnlyLoop({
    investigationId: 'inv_f2_cancel',
    registry: cancelRegistry,
    steps: [
      {
        stepId: 'step_f2_cancel_1',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: invocation({
          plan: advisoryPlan('plan_f2_cancel_001', 'auth_boundary_differential'),
          decision: cancelRuntime.decision,
          blast: 'read_public',
        }),
      },
      {
        stepId: 'step_f2_cancel_2',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: invocation({
          plan: advisoryPlan('plan_f2_cancel_002', 'auth_boundary_differential'),
          decision: cancelRuntime.decision,
          blast: 'read_public',
        }),
      },
    ],
    nowIso,
  });
  assert.equal(cancelLoop.status, 'stopped');
  assert.equal(cancelLoop.reasonCode, 'cancel_requested');
  assert.deepEqual(cancelCalls, ['auth_boundary_differential']);
  console.log('[+] cancel cuts the loop after the in-flight read');

  const budgetRuntime = startRuntime('inv_f2_budget', 1);
  const budgetCalls: string[] = [];
  const budgetLoop = await budgetRuntime.runtime.runReadOnlyLoop({
    investigationId: 'inv_f2_budget',
    registry: new AttackCapabilityRegistry([
      countingPort('auth_boundary_differential', budgetCalls),
      countingPort('supabase_rls_read_confirm', budgetCalls),
    ]),
    steps: [
      {
        stepId: 'step_f2_budget_1',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: invocation({
          plan: advisoryPlan('plan_f2_budget_001', 'auth_boundary_differential'),
          decision: budgetRuntime.decision,
          blast: 'read_public',
        }),
      },
      {
        stepId: 'step_f2_budget_2',
        capability: 'supabase_rls_read_confirm',
        blastRadiusClass: 'read_authenticated',
        context: invocation({
          plan: advisoryPlan('plan_f2_budget_002', 'supabase_rls_read_confirm'),
          decision: budgetRuntime.decision,
          blast: 'read_authenticated',
        }),
      },
    ],
    nowIso,
  });
  assert.equal(budgetLoop.status, 'stopped');
  assert.equal(budgetLoop.reasonCode, 'budget_exceeded');
  assert.deepEqual(budgetCalls, ['auth_boundary_differential']);
  console.log('[+] request budget stops the second read');

  const emptyCalls: string[] = [];
  const unregisteredRuntime = startRuntime('inv_f2_missing', 3);
  const missingPort = await unregisteredRuntime.runtime.runReadOnlyLoop({
    investigationId: 'inv_f2_missing',
    registry: new AttackCapabilityRegistry([countingPort('credential_reuse', emptyCalls)]),
    steps: [
      {
        stepId: 'step_f2_missing_port',
        capability: 'auth_boundary_differential',
        blastRadiusClass: 'read_public',
        context: invocation({
          plan: advisoryPlan('plan_f2_missing_001', 'auth_boundary_differential'),
          decision: unregisteredRuntime.decision,
          blast: 'read_public',
        }),
      },
    ],
    nowIso,
  });
  assert.equal(missingPort.steps[0]?.disposition, 'not_implemented');
  assert.equal(missingPort.steps[0]?.reasonCode, 'capability_not_implemented');
  assert.deepEqual(emptyCalls, []);
  console.log('[+] an unregistered read capability returns capability_not_implemented');

  const defaults = new AttackCapabilityRegistry();
  assert.equal(defaults.get('nuclei_xss_scan')?.capability, 'nuclei_xss_scan');
  assert.equal(defaults.get('sql_injection_verification')?.capability, 'sql_injection_verification');
  assert.equal(defaults.get('parameter_reflection_probe')?.capability, 'parameter_reflection_probe');
  assert.equal(defaults.get('sql_error_oracle_probe'), null);
  assert.equal(defaults.get('session_fixation_probe'), null);
  assert.equal(defaults.get('method_manipulation_probe'), null);
  const stub = await createNotImplementedCapability('sql_error_oracle_probe').execute(
    invocation({
      plan: advisoryPlan('plan_f2_stub_001', 'sql_error_oracle_probe'),
      decision,
      blast: 'read_public',
    })
  );
  assert.equal(stub.outcome, 'capability_not_implemented');

  const orphanPlan = advisoryPlan('plan_f2_orphan_001', 'sql_error_oracle_probe');
  const repo = new InMemoryAttackPlanRepository();
  await repo.savePlan(orphanPlan);
  const orphanToken = authorizePlan(
    orphanPlan.planId,
    orphanPlan.assessmentId,
    'read_public',
    lineage.actorId,
    nowIso
  );
  assert.equal(orphanToken.status, 'established');
  if (orphanToken.status !== 'established') throw new Error('orphan token missing');
  const execution = new AttackExecutionService({
    planRepository: repo,
    capabilityRegistry: new AttackCapabilityRegistry([]),
  });
  const denied = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: orphanPlan.planId,
    assessmentId: orphanPlan.assessmentId,
    token: orphanToken.token,
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 1 }),
    dnsResolver: async () => ['93.184.216.34'],
    findings: [],
    operatorId: lineage.actorId,
    executedAt: nowIso,
  });
  assert.equal(denied.status, 'preflight_denied');
  if (denied.status === 'preflight_denied') {
    assert.equal(denied.reasonCode, 'capability_not_registered');
    assert.equal(denied.record, undefined);
  }
  console.log('[+] unregistered execution is denied before a tool runs');

  console.log('=== F2 next-step and read-loop smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
