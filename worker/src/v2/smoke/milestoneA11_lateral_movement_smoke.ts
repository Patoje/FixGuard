/**
 * Milestone A11 Smoke Suite — Lateral Movement Subsystem
 *
 * Verifies:
 * 1. DiscoveredReachableHost enforces inScope: false and rejects network probes
 * 2. AuthorizedLateralTarget requires an explicit AuthorizedScopeGrant
 * 3. Credential reuse against unauthorized host fails closed (zero request dispatch)
 * 4. Authorized credential reuse → ActuallyAccessedTarget + LateralMovementRecord
 *
 * Hermetic. process.exit(1) on failure. No secret logging.
 */

import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import {
  LateralMovementService,
  LateralMovementUnauthorizedError,
} from '../attack-planning/LateralMovementService.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { InMemoryPostExploitationRepository } from '../post-exploitation/InMemoryPostExploitationRepository.js';
import { PostExploitationService } from '../post-exploitation/PostExploitationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';

const SECRET_MARKER = 'a11-hermetic-secret-never-logged';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function createScopeGrant(host: string, allowCredentialUse: boolean): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_smoke_a11_001',
    scanId: 'scn_smoke_a11_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: `https://${host}`,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone A11 Smoke testing',
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
      allowCredentialUse,
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

function buildPlan(planId: string, assessmentId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId: 'scn_smoke_a11_001',
    capability: 'credential_reuse',
    title: 'A11 smoke credential reuse plan',
    reasoning: 'Hermetic advisory plan for lateral credential reuse',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: ['fnd_a11_001'],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_a11_1',
        ordinal: 1,
        title: 'Authorize credential reuse',
        description: 'Advisory step',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: 'https://api.example.com/',
    lineage: {
      assessmentId,
      scanId: 'scn_smoke_a11_001',
      authorizationGrantId: 'grn_smoke_a11_001',
      authorizationDecisionId: 'dec_smoke_a11_001',
      actorId: 'act_smoke_a11_operator',
    },
    createdAt: '2026-09-24T12:00:00.000Z',
    executable: false,
  };
}

class CountingTransport {
  public dispatchCount = 0;
  public lastRequest: HttpProbeRequest | null = null;
  public statusCode = 200;

  readonly transport: IdorHttpProbeTransport = async (
    request: HttpProbeRequest
  ): Promise<HttpProbeResponse> => {
    this.dispatchCount += 1;
    this.lastRequest = request;
    return {
      statusCode: this.statusCode,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"ok":true}',
      responseTimeMs: 1,
    };
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A11: Lateral Movement Subsystem Smoke Suite ===');

  const assessmentId = 'asm_smoke_a11_001';
  const scanId = 'scn_smoke_a11_001';
  const planId = 'plan_smoke_a11_001';
  const sourceHost = 'app.example.com';
  const destinationHost = 'api.example.com';
  const unauthorizedHost = 'evil.example.net';
  const nowIso = '2026-09-24T12:00:00.000Z';

  const lineage: AuthorizedExecutionLineageTuple = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grn_smoke_a11_001',
    authorizationDecisionId: 'dec_smoke_a11_001',
    actorId: 'act_smoke_a11_operator',
  };

  const lateral = new LateralMovementService();
  const vault = new CredentialVaultService();
  const postRepo = new InMemoryPostExploitationRepository();
  const postService = new PostExploitationService(postRepo, vault);
  const transportCounter = new CountingTransport();

  // Seed A10 hypothesis (stays INFERRED)
  const discoveredCred = await postService.recordDiscoveredCredentialAccess({
    assessmentId,
    scanId,
    accessId: 'acc_smoke_a11_001',
    sourceStepId: 'step_a11_discover',
    sourceChainId: 'chain_a11_001',
    description: 'Credential metadata observed (no secret in DTO)',
    credential: {
      credentialId: 'cred_smoke_a11_001',
      credentialKind: 'bearer_token',
      source: 'authorized_step_capture',
      associatedHostname: sourceHost,
      discoveredAt: nowIso,
      secret: SECRET_MARKER,
    },
    lateralHypothesisId: 'hyp_smoke_a11_001',
    lateralMechanism: 'credential_reuse',
    lateralTargetHost: destinationHost,
    newlyReachableTargets: [destinationHost],
    acquiredAt: nowIso,
  });
  assert.equal(discoveredCred.lateralHypothesis.epistemicStatus, 'INFERRED');

  // --- Test 1: DiscoveredReachableHost inScope false; rejects network probes ---
  const fromHypotheses = lateral.evaluateHypothesesFromState(
    (await postService.getSnapshot(assessmentId))!
  );
  assert.ok(fromHypotheses.length >= 1);
  const discoveredHost = lateral.registerDiscoveredHost({
    assessmentId,
    scanId,
    hostname: destinationHost,
    discoveredInStepId: 'step_a11_discover',
    discoveredAt: nowIso,
  });
  assert.equal(discoveredHost.kind, 'discovered_reachable_host');
  assert.equal(discoveredHost.inScope, false);
  assert.equal(discoveredHost.hostname, destinationHost);

  let probeDenied = false;
  try {
    lateral.assertNetworkProbeAllowed(assessmentId, destinationHost);
  } catch (err) {
    assert.ok(err instanceof LateralMovementUnauthorizedError);
    probeDenied = true;
  }
  assert.equal(probeDenied, true, 'Discovery-only host must reject network probes');
  assert.equal(transportCounter.dispatchCount, 0, 'Zero network after discovery');
  console.log('[+] Test 1: DiscoveredReachableHost inScope=false; network probes rejected');

  // --- Test 2: AuthorizedLateralTarget requires explicit AuthorizedScopeGrant ---
  let promoteWithoutGrantDenied = false;
  try {
    lateral.promoteToAuthorizedTarget({
      assessmentId,
      hostname: destinationHost,
      scopeGrant: {
        contractVersion: 'fixguard-authorized-scope-policy/v0',
        kind: 'authorized_scope_grant',
        // Missing usable grantId / boundaries → fail closed
      } as AuthorizedScopeGrant,
      authorizedBy: 'act_smoke_a11_operator',
      authorizedAt: nowIso,
    });
  } catch (err) {
    assert.ok(
      err instanceof LateralMovementUnauthorizedError ||
        err instanceof Error
    );
    promoteWithoutGrantDenied = true;
  }
  assert.equal(promoteWithoutGrantDenied, true, 'Missing scope grant must fail closed');

  const wrongHostGrant = createScopeGrant(sourceHost, true);
  let promoteOutOfScopeDenied = false;
  try {
    lateral.promoteToAuthorizedTarget({
      assessmentId,
      hostname: destinationHost,
      scopeGrant: wrongHostGrant,
      authorizedBy: 'act_smoke_a11_operator',
      authorizedAt: nowIso,
    });
  } catch (err) {
    assert.ok(err instanceof LateralMovementUnauthorizedError);
    promoteOutOfScopeDenied = true;
  }
  assert.equal(promoteOutOfScopeDenied, true, 'Out-of-scope grant must fail closed');

  const destGrant = createScopeGrant(destinationHost, true);
  const authorized = lateral.promoteToAuthorizedTarget({
    assessmentId,
    hostname: destinationHost,
    scopeGrant: destGrant,
    authorizedBy: 'act_smoke_a11_operator',
    authorizedAt: nowIso,
  });
  assert.equal(authorized.kind, 'authorized_lateral_target');
  assert.equal(authorized.hostname, destinationHost);
  assert.equal(authorized.scopeGrantId, destGrant.grantId);
  assert.equal(authorized.authorizedBy, 'act_smoke_a11_operator');
  lateral.assertNetworkProbeAllowed(assessmentId, destinationHost);
  console.log('[+] Test 2: AuthorizedLateralTarget requires explicit AuthorizedScopeGrant');

  // --- Test 3: Credential reuse unauthorized host → fail closed, zero dispatch ---
  const planRepo = new InMemoryAttackPlanRepository();
  await planRepo.savePlan(buildPlan(planId, assessmentId));
  const authService = new AttackAuthorizationService(planRepo);
  const established = await authService.authorizePlan(
    planId,
    assessmentId,
    'credential_use',
    'act_smoke_a11_operator',
    nowIso
  );
  assert.equal(established.status, 'established');
  if (established.status !== 'established') fail('unreachable');

  const beforeUnauthorized = transportCounter.dispatchCount;
  const unauthorizedResult = await lateral.evaluateCredentialReuse({
    assessmentId,
    scanId,
    sourceHost,
    destinationHost: unauthorizedHost,
    mechanism: 'credential_reuse',
    credentialRef: discoveredCred.credentialRef,
    vault,
    token: established.token,
    scopeGrant: destGrant,
    lineage,
    transport: transportCounter.transport,
    dnsResolver: async () => ['93.184.216.34'],
    recordedAt: nowIso,
  });
  assert.equal(unauthorizedResult.status, 'unauthorized');
  assert.equal(unauthorizedResult.networkDispatched, false);
  assert.equal(unauthorizedResult.reuse.networkDispatched, false);
  assert.equal(
    transportCounter.dispatchCount,
    beforeUnauthorized,
    'Unauthorized host must not dispatch HTTP'
  );
  assert.equal(unauthorizedResult.record.status, 'unauthorized');
  assert.equal(unauthorizedResult.record.kind, 'lateral_movement_record');
  console.log('[+] Test 3: unauthorized credential reuse fail-closed with zero dispatch');

  // --- Test 4: Authorized reuse → ActuallyAccessedTarget + LateralMovementRecord ---
  // Fresh credential — prior authorizeAndUse/single-use may have been unused for unauthorized path
  // (unauthorized path never called vault). Use same ref.
  const beforeAuthorized = transportCounter.dispatchCount;
  const authorizedResult = await lateral.evaluateCredentialReuse({
    assessmentId,
    scanId,
    sourceHost,
    destinationHost,
    mechanism: 'credential_reuse',
    credentialRef: discoveredCred.credentialRef,
    vault,
    token: established.token,
    scopeGrant: destGrant,
    lineage,
    targetUrl: `https://${destinationHost}/`,
    transport: transportCounter.transport,
    dnsResolver: async () => ['93.184.216.34'],
    capabilityGained: 'read_authenticated',
    recordedAt: '2026-09-24T12:01:00.000Z',
  });

  assert.equal(authorizedResult.status, 'access_confirmed');
  if (authorizedResult.status !== 'access_confirmed') fail('unreachable');
  assert.equal(authorizedResult.accessed.kind, 'actually_accessed_target');
  assert.equal(authorizedResult.accessed.epistemicStatus, 'VERIFIED');
  assert.equal(authorizedResult.accessed.hostname, destinationHost);
  assert.ok(authorizedResult.accessed.evidenceId.length > 0);
  assert.ok(authorizedResult.pivoted);
  assert.equal(authorizedResult.pivoted?.kind, 'successfully_pivoted_target');
  assert.equal(authorizedResult.pivoted?.epistemicStatus, 'VERIFIED');
  assert.equal(authorizedResult.record.status, 'pivot_complete');
  assert.equal(authorizedResult.record.mechanism, 'credential_reuse');
  assert.equal(authorizedResult.record.destinationHost, destinationHost);
  assert.equal(authorizedResult.record.credentialRefId, discoveredCred.credentialRef.credentialId);
  assert.ok(authorizedResult.record.evidence.length >= 1);
  assert.equal(transportCounter.dispatchCount, beforeAuthorized + 1);
  assert.ok(transportCounter.lastRequest);
  assert.equal(
    JSON.stringify(authorizedResult).includes(SECRET_MARKER),
    false,
    'Result DTO must not contain secret'
  );

  // Registry exposes credential_reuse
  const registry = AttackCapabilityRegistry.createDefault();
  assert.ok(registry.get('credential_reuse') !== null);

  const snapshot = lateral.getSnapshot(assessmentId);
  assert.ok(snapshot !== null);
  if (!snapshot) fail('unreachable');
  assert.equal(snapshot.kind, 'lateral_movement_snapshot');
  assert.ok(snapshot.discoveredHosts.some((h) => h.inScope === false));
  assert.ok(snapshot.authorizedTargets.some((t) => t.kind === 'authorized_lateral_target'));
  assert.ok(snapshot.accessedTargets.some((t) => t.epistemicStatus === 'VERIFIED'));
  assert.ok(snapshot.pivotedTargets.some((t) => t.epistemicStatus === 'VERIFIED'));
  assert.ok(snapshot.records.length >= 2);
  console.log('[+] Test 4: authorized reuse yields ActuallyAccessedTarget + LateralMovementRecord');

  // --- API GET /lateral-movement ---
  const orchRepo = new InMemoryOrchestratedAssessmentRepository();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: sourceHost,
    status: 'completed',
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_smoke_a11_001',
      authorizationDecisionId: 'dec_smoke_a11_001',
      actorId: 'act_smoke_a11_operator',
    },
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 1 },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
  };
  await orchRepo.save(record);

  const appService = new OrchestratedAssessmentApplicationService({
    repository: orchRepo,
    lateralMovementService: lateral,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
  });
  const apiResult = await appService.getLateralMovement(assessmentId);
  assert.equal(apiResult.assessmentId, assessmentId);
  assert.ok(apiResult.snapshot !== null);
  assert.equal(apiResult.snapshot?.accessedTargets.length, 1);

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: orchRepo,
    lateralMovementService: lateral,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
  });
  const controller = new OrchestratedAssessmentController(root.orchestratedService);
  let statusCode = 0;
  let body: unknown;
  const req = { params: { assessmentId } } as unknown as Request;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: unknown) {
      body = payload;
      return this;
    },
  } as unknown as Response;
  const next: NextFunction = (err?: unknown) => {
    if (err) fail(`Controller next() error: ${String(err)}`);
  };
  await controller.getLateralMovement(req, res, next);
  assert.equal(statusCode, 200);
  assert.ok(body && typeof body === 'object');
  assert.equal(JSON.stringify(body).includes(SECRET_MARKER), false);

  console.log('[+] API GET lateral-movement snapshot wired (secret-free)');
  console.log('=== Milestone A11 Smoke Suite: ALL PASSED ===');
}

runSmokeTests().catch((err) => {
  console.error('Milestone A11 smoke failed:', err);
  process.exit(1);
});
