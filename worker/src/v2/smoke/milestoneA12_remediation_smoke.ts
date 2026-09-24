/**
 * Phase 6 / A12 Audit Remediation Smoke
 *
 * Verifies:
 * 1. impactLevel bounded on non-VERIFIED / incomplete chains
 * 2. credential_reuse plan generation + host_in_scope prerequisite
 * 3. GET /impact returns ImpactAssessment[]
 * 4. Lateral write endpoints fail-closed unauthorized / succeed authorized (hermetic)
 *
 * Hermetic. process.exit(1) on failure. No secret logging.
 */

import assert from 'node:assert/strict';
import type { Request, Response, NextFunction } from 'express';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { generateAttackPlans } from '../attack-planning/AttackPlanGeneratorService.js';
import { LateralMovementService } from '../attack-planning/LateralMovementService.js';
import { ImpactAssessmentService } from '../reporting-boundary/ImpactAssessmentService.js';
import { validateImpactAssessment } from '../reporting-boundary/ImpactAssessmentContracts.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { InMemoryPostExploitationRepository } from '../post-exploitation/InMemoryPostExploitationRepository.js';
import { PostExploitationService } from '../post-exploitation/PostExploitationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import { UnauthorizedGatewayError } from '../api/ApiErrors.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION } from '../authorization/VerifiedAuthorizationDecisionContracts.js';

const SECRET_MARKER = 'remediation-hermetic-secret-never-in-dto';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function createScopeGrant(
  hosts: readonly string[],
  allowCredentialUse: boolean
): AuthorizedScopeGrant {
  const now = Date.now();
  const primary = hosts[0]!;
  const apex = primary.includes('.') ? primary.split('.').slice(-2).join('.') : primary;
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grn_remed_a12_001',
    scanId: 'scn_remed_a12_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: apex,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for A12 remediation smoke',
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
      allowedDomains: [apex],
      allowedHosts: [...hosts],
      allowedOrigins: hosts.map((h) => `https://${h}`),
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

function buildCredReusePlan(planId: string, assessmentId: string, scanId: string): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId,
    capability: 'credential_reuse',
    title: 'Remediation credential reuse plan',
    reasoning: 'Hermetic plan for lateral write smoke',
    status: 'ready_for_authorization',
    blastRadius: 'domain_wide',
    capabilityGained: 'read_authenticated',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_remed_1',
        ordinal: 1,
        title: 'Authorize credential reuse',
        description: 'Advisory',
        status: 'ready',
        requiredPermissions: ['credential_use'],
      },
    ],
    targetUrl: 'https://api.example.com/',
    lineage: {
      assessmentId,
      scanId,
      authorizationGrantId: 'grn_remed_a12_001',
      authorizationDecisionId: 'dec_remed_a12_001',
      actorId: 'act_remed_a12',
    },
    createdAt: '2026-09-24T14:00:00.000Z',
    executable: false,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Phase 6 / A12 Audit Remediation Smoke Suite ===');

  const nowIso = '2026-09-24T14:00:00.000Z';
  const assessmentId = 'assess_remed_a12_001';
  const scanId = 'scn_remed_a12_001';
  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grn_remed_a12_001',
    authorizationDecisionId: 'dec_remed_a12_001',
    actorId: 'act_remed_a12',
  };

  // --- 1. Bound impactLevel ---
  const chainRepo = new InMemoryAttackChainRepository();
  const chainService = new AttackChainService(chainRepo);
  let hypo = await chainService.initHypothesis({
    chainId: 'chain_remed_rce_001',
    assessmentId,
    scanId,
    hypothesis: 'RCE must not be claimed without VERIFIED evidence',
    objectiveKind: 'privilege_escalation',
    impactLevel: 'rce_demonstrated',
    lineage,
    createdAt: nowIso,
  });
  assert.equal(hypo.declaredImpactLevel, 'rce_demonstrated');
  assert.equal(hypo.impactLevel, 'information_exposure');
  assert.equal(hypo.status, 'hypothesis');

  hypo = await chainService.appendExecutedStep({
    chainId: hypo.chainId,
    assessmentId,
    scanId,
    stepId: 'step_remed_partial',
    capabilityKind: 'lfi_path_traversal',
    epistemicStatus: 'INFERRED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_remed_partial',
      reasonCode: 'partial_only',
      safeMessage: 'Inferred step only',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(hypo.status, 'partially_validated');
  assert.equal(hypo.impactLevel, 'information_exposure');

  hypo = await chainService.appendExecutedStep({
    chainId: hypo.chainId,
    assessmentId,
    scanId,
    stepId: 'step_remed_inferred_2',
    capabilityKind: 'parameter_reflection_probe',
    epistemicStatus: 'INFERRED',
    capabilityGained: 'none',
    outcome: 'succeeded',
    sourceStepId: 'step_remed_partial',
    evidence: {
      evidenceId: 'ev_remed_inferred_2',
      reasonCode: 'still_inferred',
      safeMessage: 'Second inferred step completes chain without VERIFIED',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(hypo.status, 'fully_validated');
  assert.equal(hypo.overallEpistemicStatus, 'INFERRED');
  assert.equal(hypo.impactLevel, 'information_exposure');
  assert.equal(hypo.declaredImpactLevel, 'rce_demonstrated');

  let verified = await chainService.initHypothesis({
    chainId: 'chain_remed_ok_001',
    assessmentId,
    scanId,
    hypothesis: 'Fully validated VERIFIED may restore declared impact',
    objectiveKind: 'data_access',
    impactLevel: 'data_access',
    lineage,
    createdAt: nowIso,
  });
  verified = await chainService.appendExecutedStep({
    chainId: verified.chainId,
    assessmentId,
    scanId,
    stepId: 'step_remed_ok_1',
    capabilityKind: 'idor_read_differential',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_escalated',
    outcome: 'succeeded',
    evidence: {
      evidenceId: 'ev_remed_ok_1',
      reasonCode: 'ok',
      safeMessage: 'Verified step',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  verified = await chainService.appendExecutedStep({
    chainId: verified.chainId,
    assessmentId,
    scanId,
    stepId: 'step_remed_ok_2',
    capabilityKind: 'auth_bypass_probe',
    epistemicStatus: 'VERIFIED',
    capabilityGained: 'read_authenticated',
    outcome: 'succeeded',
    sourceStepId: 'step_remed_ok_1',
    evidence: {
      evidenceId: 'ev_remed_ok_2',
      reasonCode: 'ok',
      safeMessage: 'Verified step',
      recordedAt: nowIso,
    },
    recordedAt: nowIso,
  });
  assert.equal(verified.status, 'fully_validated');
  assert.equal(verified.overallEpistemicStatus, 'VERIFIED');
  assert.equal(verified.impactLevel, 'data_access');
  console.log('[+] Test 1: impactLevel bounded on non-VERIFIED / incomplete chains');

  // --- 2. credential_reuse plan generation ---
  const missingScope = generateAttackPlans({
    assessmentId,
    scanId,
    findings: [],
    identities: [],
    lineage,
    generatedAt: nowIso,
    credentialReuseContext: {
      credentialHosts: [
        { credentialId: 'cred_remed_001', associatedHostname: 'api.example.com' },
      ],
      inScopeHosts: [],
      authorizedLateralHosts: [],
    },
  });
  const missingPlan = missingScope.plans.find((p) => p.capability === 'credential_reuse');
  assert.ok(missingPlan, 'credential_reuse plan must be generated (not discarded)');
  assert.equal(missingPlan.status, 'prerequisite_missing');
  assert.ok(missingPlan.prerequisites.some((p) => p.kind === 'host_in_scope' && !p.satisfied));
  assert.ok(missingPlan.reasoning.includes('credential_use'));

  const readyPlans = generateAttackPlans({
    assessmentId,
    scanId,
    findings: [],
    identities: [],
    lineage,
    generatedAt: nowIso,
    credentialReuseContext: {
      authorizedLateralHosts: ['api.example.com'],
      credentialHosts: [
        { credentialId: 'cred_remed_001', associatedHostname: 'api.example.com' },
      ],
      inScopeHosts: ['api.example.com'],
    },
  });
  const readyPlan = readyPlans.plans.find((p) => p.capability === 'credential_reuse');
  assert.ok(readyPlan);
  assert.equal(readyPlan.status, 'ready_for_authorization');
  assert.equal(readyPlan.blastRadius, 'domain_wide');
  console.log('[+] Test 2: credential_reuse plan generation + host_in_scope prereq');

  // --- 3. GET impact ---
  const vault = new CredentialVaultService();
  const postRepo = new InMemoryPostExploitationRepository();
  const postService = new PostExploitationService(postRepo, vault);
  const lateral = new LateralMovementService();
  const impactService = new ImpactAssessmentService();
  const orchRepo = new InMemoryOrchestratedAssessmentRepository();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: 'example.com',
    status: 'completed',
    lineage,
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
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
    lateralMovementService: lateral,
    impactAssessmentService: impactService,
  });

  const sealedScope = createScopeGrant(
    ['example.com', 'api.example.com', 'app.example.com'],
    true
  );
  const sealedDecision = establishVerifiedAuthorizationDecision(
    {
      contractVersion: VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION,
      kind: 'establish_verified_authorization_decision_request',
      assessmentId,
      scanId,
      authorizationDecisionId: 'dec_remed_a12_001',
      authorizedActor: { actorId: 'act_remed_a12', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: sealedScope,
    },
    nowIso
  );
  assert.equal(sealedDecision.status, 'established');
  if (sealedDecision.status !== 'established') fail('sealed decision must establish');
  appService.registerRuntimeVerifiedAuthorizationDecision(assessmentId, sealedDecision.decision);

  const impactResult = await appService.getImpactAssessments(assessmentId);
  assert.ok(impactResult.impactCount >= 1);
  for (const impact of impactResult.impactAssessments) {
    assert.ok(validateImpactAssessment(impact));
  }
  assert.ok(
    impactResult.impactAssessments.some(
      (i) => i.chainId === 'chain_remed_ok_001' && i.impactLevel === 'data_access'
    )
  );
  assert.ok(
    impactResult.impactAssessments.some(
      (i) =>
        i.chainId === 'chain_remed_rce_001' && i.impactLevel === 'information_exposure'
    )
  );

  const planRepo = new InMemoryAttackPlanRepository();
  const authService = new AttackAuthorizationService(planRepo);
  const controller = new OrchestratedAssessmentController(appService, authService);
  let impactStatus = 0;
  let impactBody: unknown;
  await controller.getImpactAssessments(
    { params: { assessmentId } } as unknown as Request,
    {
      status(code: number) {
        impactStatus = code;
        return this;
      },
      json(body: unknown) {
        impactBody = body;
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      if (err) fail(`getImpact next: ${String(err)}`);
    }) as NextFunction
  );
  assert.equal(impactStatus, 200);
  assert.ok(impactBody && typeof impactBody === 'object');
  const impactJson = JSON.stringify(impactBody);
  assert.equal(impactJson.includes(SECRET_MARKER), false);
  console.log('[+] Test 3: GET impact returns ImpactAssessment[] without secrets');

  // --- 4. Lateral write HTTP ---
  const destHost = 'api.example.com';
  const evilHost = 'evil.example.net';
  const planId = 'plan_remed_cred_001';
  await planRepo.savePlan(buildCredReusePlan(planId, assessmentId, scanId));

  postService.storeCredentialReference({
    credentialId: 'cred_remed_001',
    credentialKind: 'bearer_token',
    source: 'remediation_smoke',
    associatedHostname: destHost,
    discoveredAt: nowIso,
    secret: SECRET_MARKER,
  });

  // Unauthorized promote — client expands hosts beyond sealed grant
  let promoteDenied = false;
  let promoteDenyCode: string | undefined;
  const expandedClientGrant: AuthorizedScopeGrant = {
    ...sealedScope,
    boundaries: {
      ...sealedScope.boundaries,
      allowedHosts: [...(sealedScope.boundaries.allowedHosts ?? []), evilHost],
      allowedOrigins: [
        ...(sealedScope.boundaries.allowedOrigins ?? []),
        `https://${evilHost}`,
      ],
    },
  };
  try {
    await controller.promoteLateralTarget(
      {
        params: { assessmentId },
        body: {
          hostname: evilHost,
          operatorId: 'act_remed_a12',
          scopeGrant: expandedClientGrant,
        },
      } as unknown as Request,
      {
        status() {
          return this;
        },
        json() {
          return this;
        },
      } as unknown as Response,
      ((err?: unknown) => {
        if (err instanceof UnauthorizedGatewayError) {
          promoteDenied = true;
          promoteDenyCode = err.reasonCode;
          return;
        }
        if (err) fail(`unexpected promote error: ${String(err)}`);
      }) as NextFunction
    );
  } catch (err: unknown) {
    if (err instanceof UnauthorizedGatewayError) {
      promoteDenied = true;
      promoteDenyCode = err.reasonCode;
    } else throw err;
  }
  assert.equal(promoteDenied, true, 'Promote out-of-scope host must fail closed');
  assert.equal(promoteDenyCode, 'scope_violation', 'Expansion must report scope_violation');

  // Authorized promote (in-scope host; client grant is a subset of sealed)
  let promoteStatus = 0;
  let promoteBody: unknown;
  await controller.promoteLateralTarget(
    {
      params: { assessmentId },
      body: {
        hostname: destHost,
        operatorId: 'act_remed_a12',
        scopeGrant: createScopeGrant(['api.example.com'], true),
        authorizedAt: nowIso,
      },
    } as unknown as Request,
    {
      status(code: number) {
        promoteStatus = code;
        return this;
      },
      json(body: unknown) {
        promoteBody = body;
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      if (err) fail(`promote next: ${String(err)}`);
    }) as NextFunction
  );
  assert.equal(promoteStatus, 201);
  assert.ok(promoteBody && typeof promoteBody === 'object');
  assert.equal(JSON.stringify(promoteBody).includes(SECRET_MARKER), false);

  // credential-reuse without token → unauthorized
  let reuseDenied = false;
  await controller.evaluateCredentialReuse(
    {
      params: { assessmentId },
      body: {
        planId,
        sourceHost: 'app.example.com',
        destinationHost: destHost,
        mechanism: 'credential_reuse',
        credentialRefId: 'cred_remed_001',
        operatorId: 'act_remed_a12',
        scopeGrant: createScopeGrant(['api.example.com', 'app.example.com'], true),
      },
    } as unknown as Request,
    {
      status() {
        return this;
      },
      json() {
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      if (err instanceof UnauthorizedGatewayError) {
        reuseDenied = true;
        return;
      }
      if (err) fail(`unexpected reuse error: ${String(err)}`);
    }) as NextFunction
  );
  assert.equal(reuseDenied, true, 'credential-reuse without branded token must fail closed');

  // Authorize + hermetic transport success
  const established = await authService.establishAttackAuthorization({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'establish_attack_authorization_request',
    planId,
    assessmentId,
    blastRadiusClass: 'credential_use',
    operatorId: 'act_remed_a12',
    authorizedAt: nowIso,
  });
  assert.equal(established.status, 'established');

  const hermeticTransport: IdorHttpProbeTransport = async (
    _req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => ({
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    bodyText: '{"ok":true}',
    responseTimeMs: 1,
  });

  const appWithTransport = new OrchestratedAssessmentApplicationService({
    repository: orchRepo,
    attackChainRepository: chainRepo,
    attackChainService: chainService,
    postExploitationRepository: postRepo,
    credentialVaultService: vault,
    postExploitationService: postService,
    lateralMovementService: lateral,
    impactAssessmentService: impactService,
    httpTransport: hermeticTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  appWithTransport.registerRuntimeVerifiedAuthorizationDecision(
    assessmentId,
    sealedDecision.decision
  );
  const controller2 = new OrchestratedAssessmentController(appWithTransport, authService);

  let reuseStatus = 0;
  let reuseBody: unknown;
  await controller2.evaluateCredentialReuse(
    {
      params: { assessmentId },
      body: {
        planId,
        sourceHost: 'app.example.com',
        destinationHost: destHost,
        mechanism: 'credential_reuse',
        credentialRefId: 'cred_remed_001',
        operatorId: 'act_remed_a12',
        scopeGrant: createScopeGrant(['api.example.com', 'app.example.com'], true),
        targetUrl: `https://${destHost}/`,
        recordedAt: nowIso,
      },
    } as unknown as Request,
    {
      status(code: number) {
        reuseStatus = code;
        return this;
      },
      json(body: unknown) {
        reuseBody = body;
        return this;
      },
    } as unknown as Response,
    ((err?: unknown) => {
      if (err) fail(`reuse success next: ${String(err)}`);
    }) as NextFunction
  );
  assert.equal(reuseStatus, 200);
  assert.ok(reuseBody && typeof reuseBody === 'object');
  const reuseObj = reuseBody as { status?: string };
  assert.equal(reuseObj.status, 'access_confirmed');
  assert.equal(JSON.stringify(reuseBody).includes(SECRET_MARKER), false);

  const refresh = await appWithTransport.getAttackModeRefresh(assessmentId);
  assert.ok(Array.isArray(refresh.attackChains));
  assert.ok(refresh.lateralMovementSnapshot !== null);
  assert.equal(JSON.stringify(refresh).includes(SECRET_MARKER), false);
  console.log('[+] Test 4: Lateral write endpoints fail-closed / succeed authorized hermetically');

  console.log('=== Phase 6 / A12 remediation smoke suite PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
