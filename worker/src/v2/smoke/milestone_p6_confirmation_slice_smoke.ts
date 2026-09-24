/**
 * P6 confirmation slice smoke:
 * 1) OOB callback / interactsh poll ingest
 * 2) Multi-identity authz matrix pairs
 * 3) Post-exploitation on exploitability_confirmed → AcquiredAccess + INFERRED lateral
 */

import assert from 'node:assert/strict';
import type { Finding } from '../core/Evidence.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import {
  AttackCapabilityRegistry,
} from '../attack-execution/AttackCapabilityRegistry.js';
import type { AttackCapabilityPort } from '../attack-execution/AttackExecutionContracts.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import { OobCanaryManager } from '../oob/OobCanaryManager.js';
import {
  ingestHttpCallback,
  ingestInteractshPollEvents,
  resolveOobReceiverStatus,
} from '../oob/OobCallbackReceiver.js';
import { buildAuthzMatrixPairs } from '../detection/MultiIdentityAuthzMatrixService.js';
import { InMemoryPostExploitationRepository } from '../post-exploitation/InMemoryPostExploitationRepository.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { PostExploitationService } from '../post-exploitation/PostExploitationService.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function createScopeGrant(host: string, scanId: string): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_smoke_p6_001',
    scanId,
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for P6 smoke',
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

async function testOobReceiver(): Promise<void> {
  const manager = new OobCanaryManager({ defaultCallbackDomain: 'oob.test.local' });
  const status = resolveOobReceiverStatus();
  assert.equal(status.kind, 'oob_receiver_status');

  const token = manager.issueCanaryToken({
    assessmentId: 'asm_p6_oob_001',
    scanId: 'scn_p6_oob_001',
    actorId: 'act_p6_oob',
    targetDomain: 'app.example.com',
    purpose: 'blind_ssrf',
  });

  const httpHit = ingestHttpCallback(manager, {
    host: `${token.canaryToken}.oob.test.local`,
    path: '/',
    remoteAddress: '203.0.113.10',
    httpMethod: 'GET',
  });
  assert.equal(httpHit.recorded, true);
  assert.equal(httpHit.canaryToken, token.canaryToken);

  const poll = ingestInteractshPollEvents(manager, [
    {
      canaryToken: token.canaryToken,
      interactionType: 'dns_query',
      remoteAddress: '203.0.113.11',
    },
    { canaryToken: 'fgc_deadbeefdeadbeef', interactionType: 'http_callback' },
    { evil: true },
  ]);
  assert.equal(poll.accepted, 1);
  assert.equal(poll.rejected, 2);
  assert.equal(manager.getInteractionsForToken(token.canaryToken).length, 2);
  console.log('[+] Test 1: OOB callback + interactsh poll ingest OK');
}

async function testAuthzMatrixPairs(): Promise<void> {
  const identityA = {
    identityId: 'id_a',
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig' },
  };
  const identityB = {
    identityId: 'id_b',
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig2' },
  };
  const pairs = buildAuthzMatrixPairs(identityA, identityB);
  assert.equal(pairs.length, 3);
  assert.equal(pairs[0]!.pairKind, 'identity_a_vs_b');
  assert.equal(pairs[1]!.pairKind, 'unauth_vs_a');
  assert.equal(pairs[2]!.pairKind, 'unauth_vs_b');
  console.log('[+] Test 2: multi-identity authz matrix pairs OK');
}

async function testPostExploitOnConfirmed(): Promise<void> {
  const assessmentId = 'asm_smoke_p6_001';
  const scanId = 'scn_smoke_p6_001';
  const planId = 'plan_smoke_p6_idor';
  const operatorId = 'act_smoke_p6_operator';
  const host = 'app.example.com';
  const findingId = 'fnd_smoke_p6_001';
  const scopeGrant = createScopeGrant(host, scanId);

  const finding: Finding = {
    id: findingId,
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'medium',
    title: 'P6 IDOR candidate',
    description: 'Hermetic finding for post-exploit confirm smoke',
    target: `https://${host}/api/resource/1`,
    evidence: 'observed differential',
    confidence: 0.9,
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_p6_001',
      evidenceRecordId: 'evr_p6_001',
      lineage: {},
      endpointUrl: `https://${host}/api/resource/1`,
    },
    verificationState: 'validated_vulnerability',
  };

  const plan: AttackPlan = {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId,
    capability: 'idor_read_differential',
    title: 'P6 confirm execution plan',
    reasoning: 'Hermetic advisory plan for confirm→post-exploit smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'read_escalated',
    sourceFindingIds: [findingId],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_p6_1',
        ordinal: 1,
        title: 'Execute differential read',
        description: 'Authorized differential read validation',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: `https://${host}/api/resource/1`,
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_smoke_p6_001',
      authorizationDecisionId: 'dec_smoke_p6_001',
      actorId: operatorId,
    },
    createdAt: '2026-09-24T20:00:00.000Z',
    executable: false,
  };

  const planRepo = new InMemoryAttackPlanRepository();
  await planRepo.savePlan(plan);
  const authService = new AttackAuthorizationService(planRepo);
  const authResult = await authService.authorizePlan(
    planId,
    assessmentId,
    'read_escalated',
    operatorId,
    '2026-09-24T20:00:00.000Z'
  );
  assertTrue(authResult.status === 'established', 'authorizePlan must establish');
  if (authResult.status !== 'established') fail('unreachable');

  const postRepo = new InMemoryPostExploitationRepository();
  const postService = new PostExploitationService(postRepo, new CredentialVaultService());

  const succeedingCapability: AttackCapabilityPort = {
    capability: 'idor_read_differential',
    async execute() {
      return {
        outcome: 'succeeded',
        reasonCode: 'differential_confirmed',
        safeMessage: 'Hermetic differential success',
        evidenceId: 'ev_p6_conf_001',
        consoleLines: [],
      };
    },
  };

  const registry = new AttackCapabilityRegistry();
  registry.register(succeedingCapability);

  const exec = new AttackExecutionService({
    planRepository: planRepo,
    capabilityRegistry: registry,
    postExploitationService: postService,
  });

  const result = await exec.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId,
    assessmentId,
    token: authResult.token,
    scopeGrant,
    findings: [finding],
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: async () => ['93.184.216.34'],
    operatorId,
    executedAt: '2026-09-24T20:05:00.000Z',
  });

  assert.equal(result.status, 'completed', JSON.stringify(result));
  const snap = await postService.getSnapshot(assessmentId);
  assertTrue(snap !== null, 'post-exploitation snapshot required');
  assertTrue(
    (snap?.acquiredAccess.length ?? 0) >= 1,
    'expected AcquiredAccess on exploitability_confirmed'
  );
  assertTrue(
    (snap?.lateralMovementHypotheses.length ?? 0) >= 1,
    'expected INFERRED lateral hypothesis'
  );
  assert.equal(snap!.lateralMovementHypotheses[0]!.epistemicStatus, 'INFERRED');
  assertTrue(
    snap!.lateralMovementHypotheses[0]!.mechanism.includes('re-authorization'),
    'lateral must require re-auth'
  );
  console.log('[+] Test 3: exploitability_confirmed → AcquiredAccess + INFERRED lateral OK');
}

async function main(): Promise<void> {
  console.log('=== FixGuard V2: P6 confirmation + post-compromise slice ===');
  await testOobReceiver();
  await testAuthzMatrixPairs();
  await testPostExploitOnConfirmed();
  console.log('=== ALL TESTS PASSED ===');
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
