/**
 * Milestone A5 Smoke Suite — Attack Execution Engine
 *
 * Verifies:
 * 1. Authorize generated plan (repo existence) → valid WeakSet token
 * 2. Execute authorized plan → all 7 gates + capability succeeds (hermetic)
 * 3. Step success advances VerificationState toward exploitability_confirmed
 * 4. Missing plan / gate bypass / unbranded token fail closed
 */

import assert from 'node:assert/strict';
import type { Finding } from '../core/Evidence.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { isRuntimeAuthorizedForBlastRadius } from '../attack-authorization/AttackAuthorizationService.js';
import {
  AttackCapabilityRegistry,
  createIdorReadDifferentialCapability,
} from '../attack-execution/AttackCapabilityRegistry.js';
import type { AttackCapabilityPort } from '../attack-execution/AttackExecutionContracts.js';
import {
  ATTACK_EXECUTION_CONTRACT_VERSION,
  isScopeAllowed,
} from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import type { Request, Response, NextFunction } from 'express';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function createScopeGrant(host: string): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_smoke_a5_001',
    scanId: 'scn_smoke_a5_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone A5 Smoke testing',
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
      allowedDomains: [host],
      allowedHosts: [host],
      allowedOrigins: [`https://${host}`],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: true,
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

function buildFinding(id: string, target: string): Finding {
  return {
    id,
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'medium',
    title: 'A5 IDOR candidate',
    description: 'Hermetic finding for attack execution smoke',
    target,
    evidence: 'observed differential',
    confidence: 0.9,
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_a5_001',
      evidenceRecordId: 'evr_a5_001',
      lineage: {},
      endpointUrl: target,
    },
    verificationState: 'validated_vulnerability',
  };
}

function buildPlan(planId: string, assessmentId: string, findingId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId: 'scn_smoke_a5_001',
    capability: 'idor_read_differential',
    title: 'A5 IDOR execution plan',
    reasoning: 'Hermetic advisory plan for execution smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'read_escalated',
    sourceFindingIds: [findingId],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_a5_1',
        ordinal: 1,
        title: 'Execute dual-identity differential read',
        description: 'Authorized differential read validation',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: 'https://app.example.com/api/resource/1',
    lineage: {
      assessmentId,
      scanId: 'scn_smoke_a5_001',
      authorizationGrantId: 'grn_smoke_a5_001',
      authorizationDecisionId: 'dec_smoke_a5_001',
      actorId: 'act_smoke_a5_operator',
    },
    createdAt: '2026-09-23T19:00:00.000Z',
    executable: false,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A5: Attack Execution Engine Smoke Suite ===');

  const assessmentId = 'asm_smoke_a5_001';
  const planId = 'plan_smoke_a5_idor';
  const operatorId = 'act_smoke_a5_operator';
  const host = 'app.example.com';
  const findingId = 'fnd_smoke_a5_001';
  const scopeGrant = createScopeGrant(host);
  const finding = buildFinding(findingId, `https://${host}/api/resource/1`);

  const planRepo = new InMemoryAttackPlanRepository();
  await planRepo.savePlan(buildPlan(planId, assessmentId, findingId));
  const authService = new AttackAuthorizationService(planRepo);

  // --- Test 1: Authorize with repo existence → branded token ---
  const authResult = await authService.authorizePlan(
    planId,
    assessmentId,
    'read_escalated',
    operatorId,
    '2026-09-23T19:00:00.000Z'
  );
  assertTrue(authResult.status === 'established', 'authorizePlan must establish for existing plan');
  if (authResult.status !== 'established') fail('unreachable');
  const token = authResult.token;
  assertTrue(
    isRuntimeAuthorizedForBlastRadius(token, 'read_escalated', planId, assessmentId),
    'Token must be WeakSet-branded for read_escalated'
  );
  console.log('[+] Test 1: authorize with plan existence OK');

  // --- Test 2: Execute with all 7 gates + hermetic capability ---
  const succeedingCapability: AttackCapabilityPort = {
    capability: 'idor_read_differential',
    async execute() {
      return {
        outcome: 'succeeded',
        reasonCode: 'idor_hermetic_success',
        safeMessage: 'Hermetic IDOR capability succeeded',
        evidenceId: 'ev_smoke_a5_idor',
      };
    },
  };
  const registry = new AttackCapabilityRegistry([
    succeedingCapability,
    createIdorReadDifferentialCapability(),
  ]);
  // Re-register succeeding override (last wins via register)
  registry.register(succeedingCapability);

  const executionService = new AttackExecutionService({
    planRepository: planRepo,
    capabilityRegistry: registry,
  });

  const coordinator = new TargetExecutionCoordinator();
  const execResult = await executionService.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId,
    assessmentId,
    token,
    scopeGrant,
    coordinator,
    dnsResolver: async () => ['93.184.216.34'],
    findings: [finding],
    operatorId,
    executedAt: '2026-09-23T19:05:00.000Z',
  });

  assertTrue(execResult.status === 'completed', `Execution must complete: ${JSON.stringify(execResult)}`);
  if (execResult.status !== 'completed') fail('unreachable');
  assert.equal(execResult.record.stepRecords.length, 1);
  assert.equal(execResult.record.stepRecords[0]!.outcome, 'succeeded');
  assert.equal(execResult.record.stepRecords[0]!.gatesPassed, true);
  assertTrue(isScopeAllowed(host, scopeGrant), 'isScopeAllowed helper must accept in-scope host');
  console.log('[+] Test 2: 7 gates + capability success OK');

  // --- Test 3: VerificationState advanced ---
  const updated = execResult.record.updatedFindings.find((f) => f.id === findingId);
  assertTrue(!!updated, 'Updated finding must be present');
  assert.equal(updated!.verificationState, 'exploitability_confirmed');
  assert.equal(
    execResult.record.stepRecords[0]!.verificationStateBefore,
    'validated_vulnerability'
  );
  assert.equal(
    execResult.record.stepRecords[0]!.verificationStateAfter,
    'exploitability_confirmed'
  );
  console.log('[+] Test 3: VerificationState advanced OK');

  // --- Test 4a: Missing plan fails closed ---
  const missingPlan = await executionService.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: 'plan_missing_a5',
    assessmentId,
    token,
    scopeGrant,
    coordinator,
    dnsResolver: async () => ['93.184.216.34'],
    findings: [finding],
    operatorId,
  });
  assertTrue(
    missingPlan.status === 'preflight_denied' && missingPlan.reasonCode === 'plan_not_found',
    'Missing plan must fail closed'
  );
  console.log('[+] Test 4a: missing plan fail-closed OK');

  // --- Test 4b: Unbranded / JSON token fails closed ---
  const plainToken = JSON.parse(JSON.stringify(token)) as object;
  const unbranded = await executionService.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId,
    assessmentId,
    token: plainToken,
    scopeGrant,
    coordinator,
    dnsResolver: async () => ['93.184.216.34'],
    findings: [finding],
    operatorId,
  });
  assertTrue(
    unbranded.status === 'preflight_denied' &&
      (unbranded.reasonCode === 'token_not_branded' || unbranded.reasonCode === 'token_missing'),
    'JSON/plain token must fail closed'
  );
  console.log('[+] Test 4b: unbranded token fail-closed OK');

  // --- Test 4c: SSRF gate fails closed ---
  const loopbackPlanId = 'plan_smoke_a5_ssrf';
  await planRepo.savePlan({
    ...buildPlan(loopbackPlanId, assessmentId, findingId),
    planId: loopbackPlanId,
    targetUrl: 'https://127.0.0.1/admin',
  });
  const ssrfAuth = await authService.authorizePlan(
    loopbackPlanId,
    assessmentId,
    'read_escalated',
    operatorId
  );
  assertTrue(ssrfAuth.status === 'established', 'SSRF plan must authorize for gate test');
  if (ssrfAuth.status !== 'established') fail('unreachable');

  const ssrfExec = await executionService.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: loopbackPlanId,
    assessmentId,
    token: ssrfAuth.token,
    scopeGrant: createScopeGrant('127.0.0.1'),
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: async () => ['127.0.0.1'],
    findings: [finding],
    operatorId,
  });
  assertTrue(
    ssrfExec.status === 'preflight_denied' && ssrfExec.reasonCode === 'gate_ssrf_egress',
    `SSRF gate must deny, got ${JSON.stringify(ssrfExec)}`
  );
  console.log('[+] Test 4c: SSRF gate fail-closed OK');

  // --- Test 4d: DNS rebinding gate fails closed ---
  const dnsPlanId = 'plan_smoke_a5_dns';
  await planRepo.savePlan({
    ...buildPlan(dnsPlanId, assessmentId, findingId),
    planId: dnsPlanId,
  });
  const dnsAuth = await authService.authorizePlan(
    dnsPlanId,
    assessmentId,
    'read_escalated',
    operatorId
  );
  assertTrue(dnsAuth.status === 'established', 'DNS plan must authorize');
  if (dnsAuth.status !== 'established') fail('unreachable');

  const dnsExec = await executionService.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: dnsPlanId,
    assessmentId,
    token: dnsAuth.token,
    scopeGrant,
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: async () => ['10.0.0.5'],
    findings: [finding],
    operatorId,
  });
  assertTrue(
    dnsExec.status === 'preflight_denied' && dnsExec.reasonCode === 'gate_dns_rebinding',
    `DNS rebind gate must deny, got ${JSON.stringify(dnsExec)}`
  );
  console.log('[+] Test 4d: DNS rebinding gate fail-closed OK');

  // --- Test 5: CompositionRoot + HTTP execute path (hermetic) ---
  const root = V2CompositionRoot.createDefault();
  const httpPlanId = 'plan_smoke_a5_http';
  await root.attackPlanRepository.savePlan(buildPlan(httpPlanId, assessmentId, findingId));

  const controller = new OrchestratedAssessmentController(
    root.orchestratedService,
    root.attackAuthorizationService,
    root.attackExecutionService
  );

  let authStatus = 0;
  let authNext: unknown;
  await controller.authorizeAttackPlan(
    {
      params: { assessmentId, planId: httpPlanId },
      body: { operatorId, blastRadiusClass: 'read_escalated' },
    } as unknown as Request,
    {
      status(code: number) {
        authStatus = code;
        return this;
      },
      json() {
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      authNext = err;
    }) as NextFunction
  );
  assertTrue(authNext === undefined, `HTTP authorize must succeed: ${String(authNext)}`);
  assert.equal(authStatus, 201);

  // Override capability registry on a dedicated execution service is not on root;
  // default IDOR wrapper also returns succeeded — sufficient for HTTP path.
  let execStatus = 0;
  let execBody: unknown = null;
  let execNext: unknown;
  await controller.executeAttackPlan(
    {
      params: { assessmentId, planId: httpPlanId },
      body: {
        operatorId,
        scopeGrant,
        findings: [finding],
        dnsAnswers: ['93.184.216.34'],
      },
    } as unknown as Request,
    {
      status(code: number) {
        execStatus = code;
        return this;
      },
      json(payload: unknown) {
        execBody = payload;
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      execNext = err;
    }) as NextFunction
  );
  assertTrue(execNext === undefined, `HTTP execute must succeed: ${String(execNext)}`);
  assert.equal(execStatus, 200);
  const body = execBody as {
    status: string;
    record: { stepRecords: Array<{ outcome: string; gatesPassed: boolean }> };
  };
  assert.equal(body.status, 'completed');
  assert.equal(body.record.stepRecords[0]!.outcome, 'succeeded');
  assert.equal(body.record.stepRecords[0]!.gatesPassed, true);
  console.log('[+] Test 5: composition + HTTP execute path OK');

  console.log('=== Milestone A5: ALL CHECKS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error('FAIL: unhandled smoke error', err);
  process.exit(1);
});
