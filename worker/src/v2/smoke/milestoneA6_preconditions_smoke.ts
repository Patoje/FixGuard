/**
 * milestoneA6_preconditions_smoke.ts
 * FixGuard V2 — A6 architectural preconditions (ordered verification, ASG session, real IDOR)
 *
 * Verifies:
 * 1. Illegal verification-state jumps fail closed; refute may reset/downgrade but never upgrade.
 * 2. SessionNode + observed_as_accessible_by are valid ASG entities.
 * 3. idor_read_differential invokes ControlledActiveVerificationService.execute() and
 *    evaluates real differentials (not hardcoded success).
 * 4. cors/auth/jwt capabilities invoke real detection services — never synthetic succeeded.
 * 5. E2E AttackExecutionService.execute wires runtime-branded verifiedAuthorizationDecision
 *    (CORS succeeds with brand; forged JSON rejected; missing → authorization_missing).
 */

import assert from 'node:assert';
import { VerificationStateService } from '../core/VerificationStateService.js';
import {
  IllegalVerificationStateTransitionError,
  VERIFICATION_STATE_ORDER,
} from '../core/VerificationStateContracts.js';
import type { Finding } from '../core/Evidence.js';
import type {
  AsgEdge,
  AttackSurfaceGraph,
  SessionNode,
} from '../attack-surface/AttackSurfaceContracts.js';
import { ATTACK_SURFACE_CONTRACT_VERSION } from '../attack-surface/AttackSurfaceContracts.js';
import { createIdorReadDifferentialCapability } from '../attack-execution/AttackCapabilityRegistry.js';
import { createCorsChainExploitCapability } from '../attack-execution/capabilities/CorsChainExploitCapability.js';
import { createAuthBypassProbeCapability } from '../attack-execution/capabilities/AuthBypassProbeCapability.js';
import { createJwtAlgNoneProbeCapability } from '../attack-execution/capabilities/JwtAlgNoneProbeCapability.js';
import type { AttackCapabilityInvocationContext } from '../attack-execution/AttackExecutionContracts.js';
import type { AttackPlan, AttackStep } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { ControlledActiveVerificationService } from '../verification/ControlledActiveVerificationService.js';
import type {
  IdorDifferentialExecuteRequest,
  IdorDifferentialExecuteResult,
  VerificationHttpResponse,
  VerificationHttpTransport,
} from '../verification/ActiveVerificationContracts.js';
import { CredentialedCorsDetectionService } from '../detection/CredentialedCorsDetectionService.js';
import { AuthBypassDetectionService } from '../detection/AuthBypassDetectionService.js';
import { JwtAlgorithmConfusionDetectionService } from '../detection/JwtAlgorithmConfusionDetectionService.js';
import type {
  AuthBypassDetectionRequest,
  AuthBypassDetectionResult,
  CredentialedCorsDetectionRequest,
  CredentialedCorsDetectionResult,
  JwtAlgorithmConfusionDetectionRequest,
  JwtAlgorithmConfusionDetectionResult,
} from '../detection/DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import { ATTACK_EXECUTION_CONTRACT_VERSION } from '../attack-execution/AttackExecutionContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

function baseFinding(verificationState: Finding['verificationState']): Finding {
  return {
    id: 'fnd_a6_pre_001',
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: 'A6 precondition finding',
    description: 'Hermetic finding for ordered-transition / IDOR preconditions',
    target: 'https://app.example.com/api/resource/1',
    evidence: 'hermetic',
    confidence: 1.0,
    verificationState,
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_a6_pre_001',
      evidenceRecordId: 'evr_a6_pre_001',
      lineage: {},
      endpointUrl: 'https://app.example.com/api/resource/1',
    },
  };
}

function minimalScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_a6_pre_001',
    scanId: 'scan_a6_pre_001',
    issuedAt: '2026-09-23T19:00:00.000Z',
    expiresAt: '2026-09-24T19:00:00.000Z',
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for A6 preconditions smoke',
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
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'HEAD'],
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

function buildInvocationContext(
  overrides?: Partial<AttackCapabilityInvocationContext>
): AttackCapabilityInvocationContext {
  const step: AttackStep = {
    stepId: 'step_a6_idor_001',
    ordinal: 1,
    title: 'Execute dual-identity differential read',
    description: 'IDOR differential precondition probe',
    status: 'ready',
    requiredPermissions: ['active_http_get'],
  };

  const plan: AttackPlan = {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'plan_a6_pre_idor',
    assessmentId: 'asm_a6_pre_001',
    scanId: 'scan_a6_pre_001',
    capability: 'idor_read_differential',
    title: 'A6 IDOR precondition plan',
    reasoning: 'Hermetic advisory plan for IDOR capability honesty',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'read_escalated',
    sourceFindingIds: ['fnd_a6_pre_001'],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [step],
    targetUrl: 'https://app.example.com/api/resource/1',
    lineage: {
      assessmentId: 'asm_a6_pre_001',
      scanId: 'scan_a6_pre_001',
      authorizationGrantId: 'grant_a6_pre_001',
      authorizationDecisionId: 'dec_a6_pre_001',
      actorId: 'act_a6_pre',
    },
    createdAt: '2026-09-23T20:00:00.000Z',
    executable: false,
  };

  const token = Object.freeze({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'attack_authorization_token' as const,
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    blastRadiusClass: 'read_escalated' as const,
    authorizationLevel: 'hitl_plan_approval' as const,
    authorizedBy: 'act_a6_pre',
    authorizedAt: '2026-09-23T20:00:00.000Z',
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  }) as AttackAuthorizationToken;

  return {
    plan,
    step: { ...step, blastRadiusClass: 'read_escalated' },
    token,
    targetHost: 'app.example.com',
    targetUrl: 'https://app.example.com/api/resource/1',
    scopeGrant: minimalScopeGrant(),
    findings: [baseFinding('validated_vulnerability')],
    ...overrides,
  };
}

async function runSmokeSuite(): Promise<void> {
  console.log('=== Milestone A6 Preconditions Smoke Suite ===');
  assert.deepStrictEqual(
    [...VERIFICATION_STATE_ORDER],
    [
      'observed_anomaly',
      'suspected_vulnerability',
      'validated_vulnerability',
      'exploitability_confirmed',
      'impact_confirmed',
    ]
  );

  // -------------------------------------------------------------------------
  // Test 1: Illegal verification jump fails closed; refute may reset
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Ordered VerificationStateService ---');
  {
    const finding = baseFinding('observed_anomaly');

    assert.throws(
      () =>
        VerificationStateService.advanceState(finding, 'exploitability_confirmed', {
          evidenceId: 'ev_illegal',
          reasonCode: 'skip_attempt',
        }),
      (err: unknown) => err instanceof IllegalVerificationStateTransitionError
    );

    const oneStep = VerificationStateService.advanceState(finding, 'suspected_vulnerability', {
      evidenceId: 'ev_legal',
      reasonCode: 'one_step',
    });
    assert.strictEqual(oneStep.updatedFinding.verificationState, 'suspected_vulnerability');

    const refuted = VerificationStateService.refuteState(
      oneStep.updatedFinding,
      'observed_anomaly',
      {
        evidenceId: 'ev_refute',
        reasonCode: 'REFUTED',
      }
    );
    assert.strictEqual(refuted.updatedFinding.verificationState, 'observed_anomaly');

    assert.throws(
      () =>
        VerificationStateService.refuteState(finding, 'suspected_vulnerability', {
          evidenceId: 'ev_upgrade_via_refute',
          reasonCode: 'illegal_upgrade',
        }),
      (err: unknown) => err instanceof IllegalVerificationStateTransitionError
    );

    const sameState = VerificationStateService.refuteState(finding, 'observed_anomaly', {
      evidenceId: 'ev_same',
      reasonCode: 'REFUTED',
    });
    assert.strictEqual(sameState.updatedFinding.verificationState, 'observed_anomaly');

    console.log('[+] Test 1: illegal jump blocked; refute reset OK; upgrade-via-refute blocked');
  }

  // -------------------------------------------------------------------------
  // Test 2: SessionNode + observed_as_accessible_by constructability
  // -------------------------------------------------------------------------
  console.log('--- Test 2: ASG SessionNode + observed_as_accessible_by ---');
  {
    const provenance = {
      assessmentId: 'asm_a6_pre_001',
      scanId: 'scan_a6_pre_001',
      actorId: 'act_a6_pre',
      authorizationGrantId: 'grant_a6_pre_001',
      authorizationDecisionId: 'dec_a6_pre_001',
      sourceKind: 'graph_derivation' as const,
      observedAt: '2026-09-23T20:00:00.000Z',
    };

    const sessionNode: SessionNode = {
      id: 'session_a6_pre_001',
      kind: 'session',
      epistemicStatus: 'OBSERVED',
      provenance,
      label: 'session:identity_alice',
      metadata: {
        identityId: 'identity_alice',
        sessionTokenRef: 'vault://sessions/alice-ref',
        createdAt: '2026-09-23T19:30:00.000Z',
      },
    };

    const endpointId = 'endpoint_a6_pre_001';
    const edge: AsgEdge = {
      id: 'edge_observed_as_accessible_by_001',
      kind: 'observed_as_accessible_by',
      fromNodeId: endpointId,
      toNodeId: sessionNode.id,
      epistemicStatus: 'OBSERVED',
      provenance,
      label: 'endpoint accessible by session',
    };

    assert.strictEqual(edge.epistemicStatus, 'OBSERVED');
    assert.ok(edge.kind === 'observed_as_accessible_by');
    assert.ok(sessionNode.metadata.sessionTokenRef);

    const graph: AttackSurfaceGraph = {
      contractVersion: ATTACK_SURFACE_CONTRACT_VERSION,
      kind: 'attack_surface_graph',
      graphId: 'asg_a6_pre_001',
      assessmentId: provenance.assessmentId,
      scanId: provenance.scanId,
      targetHost: 'app.example.com',
      builtAt: '2026-09-23T20:00:00.000Z',
      lineage: {
        assessmentId: provenance.assessmentId,
        scanId: provenance.scanId,
        authorizationGrantId: provenance.authorizationGrantId!,
        authorizationDecisionId: provenance.authorizationDecisionId!,
        actorId: provenance.actorId!,
      },
      nodes: Object.freeze([
        {
          id: endpointId,
          kind: 'endpoint' as const,
          epistemicStatus: 'OBSERVED' as const,
          provenance,
          label: 'GET /api/resource/1',
          metadata: {
            url: 'https://app.example.com/api/resource/1',
            path: '/api/resource/1',
            method: 'GET',
            authRequirement: 'authenticated' as const,
            flawCategories: [],
          },
        },
        sessionNode,
      ]),
      edges: Object.freeze([edge]),
    };

    assert.strictEqual(graph.nodes.filter((n) => n.kind === 'session').length, 1);
    assert.strictEqual(
      graph.edges.filter((e) => e.kind === 'observed_as_accessible_by').length,
      1
    );
    console.log('[+] Test 2: SessionNode + observed_as_accessible_by OK');
  }

  // -------------------------------------------------------------------------
  // Test 3: Real IDOR path via ControlledActiveVerificationService.execute
  // -------------------------------------------------------------------------
  console.log('--- Test 3: idor_read_differential real verification path ---');
  {
    let executeCalls = 0;
    const responses: VerificationHttpResponse[] = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"owner":"alice","secret":"alpha"}',
        responseTimeMs: 5,
      },
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"owner":"alice","secret":"alpha"}',
        responseTimeMs: 5,
      },
    ];

    const fakeTransport: VerificationHttpTransport = async () => {
      const next = responses.shift();
      if (!next) {
        throw new Error('unexpected extra transport call');
      }
      return next;
    };

    const realService = new ControlledActiveVerificationService(fakeTransport);
    const originalExecute = realService.execute.bind(realService);
    realService.execute = async (
      request: IdorDifferentialExecuteRequest
    ): Promise<IdorDifferentialExecuteResult> => {
      executeCalls += 1;
      return originalExecute(request);
    };

    const capability = createIdorReadDifferentialCapability(realService);

    const missingIdentities = await capability.execute(buildInvocationContext());
    assert.strictEqual(missingIdentities.outcome, 'failed');
    assert.strictEqual(missingIdentities.reasonCode, 'idor_identities_missing');
    assert.strictEqual(executeCalls, 0);

    const confirmed = await capability.execute(
      buildInvocationContext({
        primaryIdentity: {
          identityId: 'identity_alice',
          headers: { authorization: 'Bearer alice' },
        },
        secondaryIdentity: {
          identityId: 'identity_bob',
          headers: { authorization: 'Bearer bob' },
        },
      })
    );
    assert.strictEqual(executeCalls, 1);
    assert.strictEqual(confirmed.outcome, 'succeeded');
    assert.strictEqual(confirmed.reasonCode, 'idor_differential_access_observed');

    // Refute path: secondary denied
    const denyResponses: VerificationHttpResponse[] = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"owner":"alice"}',
        responseTimeMs: 5,
      },
      {
        statusCode: 403,
        headers: { 'content-type': 'application/json' },
        bodyText: '{"error":"forbidden"}',
        responseTimeMs: 5,
      },
    ];
    const denyTransport: VerificationHttpTransport = async () => {
      const next = denyResponses.shift();
      if (!next) throw new Error('unexpected extra deny transport call');
      return next;
    };
    let denyExecuteCalls = 0;
    const denyService = new ControlledActiveVerificationService(denyTransport);
    const denyOriginal = denyService.execute.bind(denyService);
    denyService.execute = async (request: IdorDifferentialExecuteRequest) => {
      denyExecuteCalls += 1;
      return denyOriginal(request);
    };
    const denyCapability = createIdorReadDifferentialCapability(denyService);
    const denied = await denyCapability.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice', headers: { authorization: 'Bearer alice' } },
        secondaryIdentity: { identityId: 'identity_bob', headers: { authorization: 'Bearer bob' } },
      })
    );
    assert.strictEqual(denyExecuteCalls, 1);
    assert.strictEqual(denied.outcome, 'refuted');
    assert.strictEqual(denied.reasonCode, 'http_403');

    console.log('[+] Test 3: IDOR real execute path + differential evaluation OK');
  }

  // -------------------------------------------------------------------------
  // Test 4: CORS / Auth / JWT capabilities — no synthetic succeeded
  // -------------------------------------------------------------------------
  console.log('--- Test 4: CORS/Auth/JWT capability honesty (no stubs) ---');
  {
    const decidedAt = '2026-09-23T20:00:00.000Z';
    const authEstablish = establishVerifiedAuthorizationDecision(
      {
        contractVersion: VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION,
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: 'asm_a6_pre_001',
        scanId: 'scan_a6_pre_001',
        authorizationDecisionId: 'dec_a6_pre_001',
        authorizedActor: { actorId: 'act_a6_pre', actorType: 'human' },
        decision: 'authorized',
        decidedAt,
        scopeGrant: minimalScopeGrant(),
      },
      decidedAt
    );
    assert.strictEqual(authEstablish.status, 'established');
    if (authEstablish.status !== 'established') {
      throw new Error('authorization establishment failed');
    }
    const verifiedDecision: VerifiedAuthorizationDecision = authEstablish.decision;

    const lineageFields = {
      assessmentId: 'asm_a6_pre_001',
      scanId: 'scan_a6_pre_001',
      authorizationGrantId: 'grant_a6_pre_001',
      authorizationDecisionId: 'dec_a6_pre_001',
      actorId: 'act_a6_pre',
    };

    // --- CORS ---
    let corsCalls = 0;
    const corsService = new CredentialedCorsDetectionService();
    corsService.execute = async (
      _req: CredentialedCorsDetectionRequest
    ): Promise<CredentialedCorsDetectionResult> => {
      corsCalls += 1;
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'credentialed_cors_detection_result',
        detectionId: 'det_cors_mock',
        ...lineageFields,
        status: 'vulnerability_detected',
        reasonCode: 'credentialed_cors_confirmed',
        lineage: lineageFields,
        endpointUrl: 'https://app.example.com/api/resource/1',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: true,
        acaoHeader: 'https://canary.fixguard.internal',
      };
    };

    const corsCap = createCorsChainExploitCapability(corsService);
    const corsMissing = await corsCap.execute(buildInvocationContext());
    assert.strictEqual(corsMissing.outcome, 'failed');
    assert.strictEqual(corsMissing.reasonCode, 'cors_identity_missing');
    assert.strictEqual(corsCalls, 0);

    const corsNoAuth = await corsCap.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice', headers: { cookie: 's=1' } },
      })
    );
    assert.strictEqual(corsNoAuth.outcome, 'failed');
    assert.strictEqual(corsNoAuth.reasonCode, 'cors_authorization_missing');
    assert.strictEqual(corsCalls, 0);

    const corsOk = await corsCap.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice', headers: { cookie: 's=1' } },
        verifiedAuthorizationDecision: verifiedDecision,
      })
    );
    assert.strictEqual(corsCalls, 1);
    assert.strictEqual(corsOk.outcome, 'succeeded');
    assert.strictEqual(corsOk.reasonCode, 'credentialed_cors_confirmed');

    const defaultCors = createCorsChainExploitCapability();
    const defaultCorsResult = await defaultCors.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice' },
      })
    );
    assert.notEqual(defaultCorsResult.outcome, 'succeeded');

    // --- Auth bypass ---
    let authCalls = 0;
    const authService = new AuthBypassDetectionService();
    authService.execute = async (
      _req: AuthBypassDetectionRequest
    ): Promise<AuthBypassDetectionResult> => {
      authCalls += 1;
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'auth_bypass_detection_result',
        detectionId: 'det_auth_mock',
        ...lineageFields,
        status: 'secure_target_abstained',
        reasonCode: 'auth_enforced',
        lineage: lineageFields,
        endpointUrl: 'https://app.example.com/api/resource/1',
        bypassMechanism: 'header_stripping',
      };
    };

    const authCap = createAuthBypassProbeCapability(authService);
    const authMissing = await authCap.execute(buildInvocationContext());
    assert.strictEqual(authMissing.outcome, 'failed');
    assert.strictEqual(authMissing.reasonCode, 'auth_bypass_identity_missing');
    assert.strictEqual(authCalls, 0);

    const authRefuted = await authCap.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice', headers: { authorization: 'Bearer x' } },
        verifiedAuthorizationDecision: verifiedDecision,
      })
    );
    assert.strictEqual(authCalls, 1);
    assert.strictEqual(authRefuted.outcome, 'refuted');
    assert.strictEqual(authRefuted.reasonCode, 'auth_enforced');

    // --- JWT ---
    let jwtCalls = 0;
    const jwtService = new JwtAlgorithmConfusionDetectionService();
    jwtService.execute = async (
      _req: JwtAlgorithmConfusionDetectionRequest
    ): Promise<JwtAlgorithmConfusionDetectionResult> => {
      jwtCalls += 1;
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'jwt_algorithm_confusion_detection_result',
        detectionId: 'det_jwt_mock',
        ...lineageFields,
        status: 'vulnerability_detected',
        reasonCode: 'jwt_signature_bypass_confirmed',
        lineage: lineageFields,
        endpointUrl: 'https://app.example.com/api/resource/1',
        httpMethod: 'GET',
      };
    };

    const jwtCap = createJwtAlgNoneProbeCapability(jwtService);
    const jwtMissingBearer = await jwtCap.execute(
      buildInvocationContext({
        primaryIdentity: { identityId: 'identity_alice', headers: { authorization: 'Bearer notajwt' } },
        verifiedAuthorizationDecision: verifiedDecision,
      })
    );
    assert.strictEqual(jwtMissingBearer.outcome, 'failed');
    assert.strictEqual(jwtMissingBearer.reasonCode, 'jwt_bearer_missing');
    assert.strictEqual(jwtCalls, 0);

    const hermeticJwt =
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.sig';
    const jwtOk = await jwtCap.execute(
      buildInvocationContext({
        primaryIdentity: {
          identityId: 'identity_alice',
          headers: { authorization: `Bearer ${hermeticJwt}` },
        },
        verifiedAuthorizationDecision: verifiedDecision,
      })
    );
    assert.strictEqual(jwtCalls, 1);
    assert.strictEqual(jwtOk.outcome, 'succeeded');
    assert.strictEqual(jwtOk.reasonCode, 'jwt_signature_bypass_confirmed');

    console.log('[+] Test 4: CORS/Auth/JWT invoke services; no synthetic succeeded OK');
  }

  // -------------------------------------------------------------------------
  // Test 5: E2E execute() wires branded verifiedAuthorizationDecision (not forgeable)
  // -------------------------------------------------------------------------
  console.log('--- Test 5: E2E AttackExecutionService.execute auth wiring ---');
  {
    const decidedAt = '2026-09-23T20:00:00.000Z';
    const e2eScope = minimalScopeGrant();
    const authEstablish = establishVerifiedAuthorizationDecision(
      {
        contractVersion: VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION,
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: 'asm_a6_e2e_001',
        scanId: e2eScope.scanId,
        authorizationDecisionId: 'dec_a6_e2e_001',
        authorizedActor: { actorId: 'act_a6_e2e', actorType: 'human' },
        decision: 'authorized',
        decidedAt,
        scopeGrant: e2eScope,
      },
      decidedAt
    );
    assert.strictEqual(
      authEstablish.status,
      'established',
      `establish failed: ${JSON.stringify(authEstablish)}`
    );
    if (authEstablish.status !== 'established') {
      throw new Error('authorization establishment failed');
    }
    const verifiedDecision: VerifiedAuthorizationDecision = authEstablish.decision;

    const corsPlan: AttackPlan = {
      contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
      kind: 'attack_plan',
      planId: 'plan_a6_e2e_cors',
      assessmentId: 'asm_a6_e2e_001',
      scanId: e2eScope.scanId,
      capability: 'cors_chain_exploit',
      title: 'A6 E2E CORS execute plan',
      reasoning: 'Hermetic E2E auth wiring',
      status: 'ready_for_authorization',
      blastRadius: 'single_resource',
      capabilityGained: 'read_escalated',
      sourceFindingIds: ['fnd_a6_e2e_cors'],
      sourceFindingTypes: ['SECURITY_MISCONFIGURATION'],
      prerequisites: [],
      steps: [
        {
          stepId: 'step_a6_e2e_cors',
          ordinal: 1,
          title: 'Credentialed CORS probe',
          description: 'E2E auth wiring',
          status: 'ready',
          requiredPermissions: ['active_http_get'],
        },
      ],
      targetUrl: 'https://app.example.com/api/resource/1',
      lineage: {
        assessmentId: 'asm_a6_e2e_001',
        scanId: e2eScope.scanId,
        authorizationGrantId: e2eScope.grantId,
        authorizationDecisionId: 'dec_a6_e2e_001',
        actorId: 'act_a6_e2e',
      },
      createdAt: decidedAt,
      executable: false,
    };

    let e2eCorsCalls = 0;
    const e2eCorsService = new CredentialedCorsDetectionService();
    e2eCorsService.execute = async (
      _req: CredentialedCorsDetectionRequest
    ): Promise<CredentialedCorsDetectionResult> => {
      e2eCorsCalls += 1;
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'credentialed_cors_detection_result',
        detectionId: 'det_cors_e2e',
        assessmentId: 'asm_a6_e2e_001',
        scanId: e2eScope.scanId,
        authorizationGrantId: e2eScope.grantId,
        authorizationDecisionId: 'dec_a6_e2e_001',
        actorId: 'act_a6_e2e',
        status: 'vulnerability_detected',
        reasonCode: 'credentialed_cors_confirmed',
        lineage: {
          assessmentId: 'asm_a6_e2e_001',
          scanId: e2eScope.scanId,
          authorizationGrantId: e2eScope.grantId,
          authorizationDecisionId: 'dec_a6_e2e_001',
          actorId: 'act_a6_e2e',
        },
        endpointUrl: 'https://app.example.com/api/resource/1',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: true,
        acaoHeader: 'https://canary.fixguard.internal',
      };
    };

    const planRepo = new InMemoryAttackPlanRepository();
    await planRepo.savePlan(corsPlan);
    const authService = new AttackAuthorizationService(planRepo);
    const authResult = await authService.authorizePlan(
      corsPlan.planId,
      corsPlan.assessmentId,
      'read_escalated',
      'act_a6_e2e',
      decidedAt
    );
    assert.strictEqual(
      authResult.status,
      'established',
      `authorizePlan failed: ${JSON.stringify(authResult)}`
    );
    const token = authResult.token;

    const registry = new AttackCapabilityRegistry([
      createCorsChainExploitCapability(e2eCorsService),
    ]);
    const executionService = new AttackExecutionService({
      planRepository: planRepo,
      capabilityRegistry: registry,
    });

    const finding: Finding = {
      id: 'fnd_a6_e2e_cors',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'medium',
      title: 'CORS candidate',
      description: 'E2E auth wiring',
      target: 'https://app.example.com/api/resource/1',
      evidence: 'hermetic',
      confidence: 0.8,
      verificationState: 'observed_anomaly',
      metadata: {
        kind: 'security_misconfiguration_metadata',
        category: 'CORS_MISCONFIGURATION',
        candidateId: 'cand_a6_e2e',
        evidenceRecordId: 'evr_a6_e2e',
        lineage: {},
        endpointUrl: 'https://app.example.com/api/resource/1',
      },
    };

    const baseExec = {
      contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
      kind: 'attack_execution_request' as const,
      planId: corsPlan.planId,
      assessmentId: corsPlan.assessmentId,
      token,
      scopeGrant: e2eScope,
      coordinator: new TargetExecutionCoordinator(),
      dnsResolver: async () => ['93.184.216.34'] as const,
      findings: [finding],
      operatorId: 'act_a6_e2e',
      primaryIdentity: {
        identityId: 'identity_alice',
        headers: { cookie: 's=1' },
      },
    };

    // Missing branded decision → capability fail-closed (authorization_missing)
    const missingAuth = await executionService.execute(baseExec);
    assert.strictEqual(missingAuth.status, 'completed');
    if (missingAuth.status === 'completed') {
      assert.strictEqual(missingAuth.record.stepRecords[0]?.outcome, 'failed');
      assert.strictEqual(
        missingAuth.record.stepRecords[0]?.reasonCode,
        'cors_authorization_missing'
      );
    }
    assert.strictEqual(e2eCorsCalls, 0);

    // Forged JSON lookalike → parseRequest reject (not brandable via DTO)
    const forged = {
      ...verifiedDecision,
      authorizationDecisionId: 'dec_forged',
    };
    const forgedResult = await executionService.execute({
      ...baseExec,
      verifiedAuthorizationDecision: forged,
    });
    assert.strictEqual(forgedResult.status, 'preflight_denied');
    if (forgedResult.status === 'preflight_denied') {
      assert.strictEqual(forgedResult.reasonCode, 'request_invalid');
    }
    assert.strictEqual(e2eCorsCalls, 0);

    // Runtime-branded decision through execute() → CORS detection invoked
    const wired = await executionService.execute({
      ...baseExec,
      verifiedAuthorizationDecision: verifiedDecision,
    });
    assert.strictEqual(wired.status, 'completed');
    if (wired.status === 'completed') {
      assert.strictEqual(wired.record.stepRecords[0]?.outcome, 'succeeded');
      assert.strictEqual(wired.record.stepRecords[0]?.reasonCode, 'credentialed_cors_confirmed');
    }
    assert.strictEqual(e2eCorsCalls, 1);

    console.log('[+] Test 5: E2E execute wires branded auth; forge rejected OK');
  }

  console.log('\n=== All A6 Preconditions Smoke Tests PASSED (5/5) ===');
}

runSmokeSuite().catch((err) => {
  console.error('[!] A6 Preconditions Smoke Suite Failed:', err);
  process.exit(1);
});
