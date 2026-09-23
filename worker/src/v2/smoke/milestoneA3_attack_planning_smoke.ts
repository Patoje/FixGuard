/**
 * Milestone A3 Smoke Suite — TargetProfile v2 & Attack Planning Engine
 *
 * Verifies:
 * 1. TargetProfile v2 fields populate from sample assessment/recon output
 * 2. Generator produces correct typed plans for all 6 rules
 * 3. Missing prerequisites → status `prerequisite_missing` (never throw/discard)
 * 4. Plans stored in repo and retrievable via application/API path (hermetic)
 */

import assert from 'node:assert/strict';
import type { Finding } from '../core/Evidence.js';
import { buildTargetProfile } from '../intelligence/TargetProfileBuilder.js';
import {
  AttackPlanGeneratorService,
  generateAttackPlans,
  identityHasJwtHeuristic,
} from '../attack-planning/AttackPlanGeneratorService.js';
import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import type { Request, Response, NextFunction } from 'express';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function baseFinding(
  overrides: Partial<Finding> & Pick<Finding, 'id' | 'type' | 'title' | 'target' | 'metadata'>
): Finding {
  return {
    severity: 'medium',
    description: 'smoke finding',
    evidence: 'observed',
    confidence: 0.9,
    verificationState: 'observed_anomaly',
    ...overrides,
  };
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A3: TargetProfile v2 & Attack Planning Smoke Suite ===');

  const nowIso = '2026-09-23T18:00:00.000Z';
  const assessmentId = 'asm_smoke_a3_001';
  const scanId = 'scn_smoke_a3_001';
  const actorId = 'act_smoke_a3_operator';
  const targetHost = 'app.example.com';

  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grn_smoke_a3_001',
    authorizationDecisionId: 'dec_smoke_a3_001',
    actorId,
  };

  // --- Test 1: TargetProfile v2 enrichment ---
  const profile = buildTargetProfile({
    profileId: 'prf_smoke_a3_001',
    targetHost,
    normalizedOrigin: `https://${targetHost}`,
    lineage,
    buildTimestamp: nowIso,
    findings: [],
    observations: [
      {
        url: 'https://app.example.com/',
        headers: {
          'content-security-policy':
            "default-src 'self'; script-src https://cdn.jsdelivr.net; connect-src https://api.stripe.com",
        },
      },
    ],
    aggregatedObservations: {
      subdomains: [
        {
          subdomain: 'cdn.app.example.com',
          parentDomain: 'example.com',
          ipAddresses: ['203.0.113.50'],
          discoveredAt: nowIso,
        },
      ],
      dnsRecords: [
        {
          domain: 'app.example.com',
          recordType: 'A',
          values: ['203.0.113.10'],
          discoveredAt: nowIso,
        },
        {
          domain: 'app.example.com',
          recordType: 'CNAME',
          values: ['app.example.com.vercel.app.'],
          discoveredAt: nowIso,
        },
      ],
      ports: [
        {
          host: 'app.example.com',
          ip: '203.0.113.10',
          port: 443,
          protocol: 'tcp',
          state: 'open',
        },
      ],
      urls: [
        {
          url: 'https://app.example.com/login',
          host: 'app.example.com',
          path: '/login',
          sources: ['gau'],
          freshness: 'historical',
          sourceReliability: 'historical_archive',
          discoveredAt: nowIso,
        },
        {
          url: 'https://app.example.com/oauth/authorize',
          host: 'app.example.com',
          path: '/oauth/authorize',
          sources: ['live'],
          freshness: 'live',
          sourceReliability: 'direct_observation',
          discoveredAt: nowIso,
        },
      ],
      webObservations: [
        {
          url: 'https://app.example.com/',
          headers: {
            'content-security-policy':
              "default-src 'self'; script-src https://cdn.jsdelivr.net; connect-src https://api.stripe.com",
          },
        },
      ],
    },
  });

  assert.ok(profile.discoveredHosts.length >= 1, 'expected discoveredHosts');
  const rootHost = profile.discoveredHosts.find((h) => h.fqdn === 'app.example.com');
  assert.ok(rootHost, 'root host record missing');
  assert.ok(rootHost.ipAddresses.includes('203.0.113.10'));
  assert.ok(rootHost.ports.some((p) => p.port === 443));
  assert.equal(rootHost.inferredHostingProvider, 'vercel');
  assert.equal(rootHost.inferredCdn, true);

  assert.ok(profile.authSurface.loginPaths.some((p) => p.path === '/login'));
  assert.ok(profile.authSurface.oauthPaths.some((p) => p.path === '/oauth/authorize'));

  assert.equal(profile.historicalAssets.length, 1);
  assert.equal(profile.historicalAssets[0]?.freshness, 'historical');
  assert.equal(profile.historicalAssets[0]?.path, '/login');

  assert.ok(
    profile.externalDependencies.some((d) => d.kind === 'csp_script_src' && d.value.includes('jsdelivr'))
  );
  assert.ok(
    profile.externalDependencies.some((d) => d.kind === 'cname_cloud' && d.inferredProvider === 'vercel')
  );

  console.log('✓ Test 1 Passed: TargetProfile v2 fields populate from sample assessment output');

  // --- Test 2: All 6 generation rules ---
  const findingsSatisfied: Finding[] = [
    baseFinding({
      id: 'fnd_idor_a3',
      type: 'BROKEN_ACCESS_CONTROL',
      title: 'IDOR',
      target: 'https://app.example.com/api/user?id=1',
      metadata: {
        kind: 'broken_access_control_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        candidateId: 'cand_idor',
        evidenceRecordId: 'evr_idor',
        lineage,
        endpointUrl: 'https://app.example.com/api/user',
        resourceParamName: 'id',
      },
    }),
    baseFinding({
      id: 'fnd_cors_a3',
      type: 'CORS_MISCONFIGURATION',
      title: 'Credentialed CORS',
      target: 'https://app.example.com/api/me',
      metadata: {
        kind: 'security_misconfiguration_metadata',
        category: 'CORS_MISCONFIGURATION',
        candidateId: 'cand_cors',
        evidenceRecordId: 'evr_cors',
        lineage,
        endpointUrl: 'https://app.example.com/api/me',
        reflectedOrigin: 'https://evil.example',
        allowCredentials: true,
      },
    }),
    baseFinding({
      id: 'fnd_bypass_a3',
      type: 'BROKEN_AUTHENTICATION',
      title: 'Auth bypass',
      target: 'https://app.example.com/admin',
      metadata: {
        kind: 'auth_bypass_metadata',
        category: 'BROKEN_AUTHENTICATION',
        endpointUrl: 'https://app.example.com/admin',
        httpMethod: 'GET',
        authenticatedStatusCode: 200,
        anonymousStatusCode: 200,
        bypassMechanism: 'header_stripping',
        bodySimilarityRatio: 0.99,
        observedAt: nowIso,
      },
    }),
    baseFinding({
      id: 'fnd_jwt_a3',
      type: 'BROKEN_AUTHENTICATION',
      title: 'JWT alg none',
      target: 'https://app.example.com/api/profile',
      metadata: {
        kind: 'jwt_algorithm_confusion_metadata',
        category: 'BROKEN_AUTHENTICATION',
        endpointUrl: 'https://app.example.com/api/profile',
        httpMethod: 'GET',
        originalAlgorithm: 'RS256',
        manipulatedAlgorithm: 'none',
        probeMechanism: 'alg_none_header',
        observedAt: nowIso,
      },
    }),
    baseFinding({
      id: 'fnd_sql_a3',
      type: 'INFORMATION_DISCLOSURE',
      title: 'SQL error',
      target: 'https://app.example.com/search',
      metadata: {
        kind: 'sql_error_oracle_metadata',
        category: 'INFORMATION_DISCLOSURE',
        databaseEngine: 'postgresql',
        parameterName: 'q',
        injectedProbe: "'",
        errorFragment: 'syntax error at or near',
        endpointUrl: 'https://app.example.com/search',
        observedAt: nowIso,
      },
    }),
    baseFinding({
      id: 'fnd_reflect_a3',
      type: 'INPUT_VALIDATION_FLAW',
      title: 'Reflection',
      target: 'https://app.example.com/echo',
      metadata: {
        kind: 'input_validation_flaw_metadata',
        category: 'PARAMETER_REFLECTION',
        candidateId: 'cand_reflect',
        evidenceRecordId: 'evr_reflect',
        lineage,
        endpointUrl: 'https://app.example.com/echo',
        parameterName: 'msg',
        reflectedCanary: 'fg_canary',
      },
    }),
  ];

  const identitiesSatisfied = [
    {
      identityId: 'id_a',
      hasJwt: true,
    },
    {
      identityId: 'id_b',
      hasJwt: false,
    },
  ];

  assert.equal(
    identityHasJwtHeuristic({
      injectHeaders: { Authorization: 'Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig' },
    }),
    true
  );

  const generator = new AttackPlanGeneratorService();
  const satisfiedResult = generator.generate({
    assessmentId,
    scanId,
    findings: findingsSatisfied,
    identities: identitiesSatisfied,
    lineage,
    generatedAt: nowIso,
  });

  const expectedCapabilities: AttackCapabilityKind[] = [
    'idor_read_differential',
    'cors_chain_exploit',
    'auth_bypass_probe',
    'jwt_alg_none_probe',
    'sql_error_oracle_probe',
    'parameter_reflection_probe',
  ];

  assert.equal(satisfiedResult.plans.length, 6, `expected 6 plans, got ${satisfiedResult.plans.length}`);
  for (const capability of expectedCapabilities) {
    const plan = satisfiedResult.plans.find((p) => p.capability === capability);
    assert.ok(plan, `missing plan for ${capability}`);
    assert.equal(plan.status, 'ready_for_authorization', `${capability} should be ready`);
    assert.equal(plan.executable, false);
    assert.ok(plan.prerequisites.every((pr) => pr.satisfied));
  }

  const idor = satisfiedResult.plans.find((p) => p.capability === 'idor_read_differential');
  assert.equal(idor?.capabilityGained, 'read_escalated');
  const cors = satisfiedResult.plans.find((p) => p.capability === 'cors_chain_exploit');
  assert.equal(cors?.capabilityGained, 'read_escalated');
  const bypass = satisfiedResult.plans.find((p) => p.capability === 'auth_bypass_probe');
  assert.equal(bypass?.capabilityGained, 'read_authenticated');
  const jwt = satisfiedResult.plans.find((p) => p.capability === 'jwt_alg_none_probe');
  assert.equal(jwt?.capabilityGained, 'read_escalated');
  const sql = satisfiedResult.plans.find((p) => p.capability === 'sql_error_oracle_probe');
  assert.equal(sql?.capabilityGained, 'read_authenticated');
  const reflect = satisfiedResult.plans.find((p) => p.capability === 'parameter_reflection_probe');
  assert.equal(reflect?.capabilityGained, 'active_validation');

  console.log('✓ Test 2 Passed: Generator produces correct typed plans for all 6 rules');

  // --- Test 3: Missing prerequisites → prerequisite_missing (never throw) ---
  const missingResult = generateAttackPlans({
    assessmentId,
    scanId,
    findings: findingsSatisfied,
    identities: [], // no identities; JWT/IDOR/CORS/bypass should miss prereqs
    lineage,
    generatedAt: nowIso,
  });

  assert.equal(missingResult.plans.length, 6, 'plans with missing prereqs must be retained');
  const idorMissing = missingResult.plans.find((p) => p.capability === 'idor_read_differential');
  assert.equal(idorMissing?.status, 'prerequisite_missing');
  const corsMissing = missingResult.plans.find((p) => p.capability === 'cors_chain_exploit');
  assert.equal(corsMissing?.status, 'prerequisite_missing');
  const bypassMissing = missingResult.plans.find((p) => p.capability === 'auth_bypass_probe');
  assert.equal(bypassMissing?.status, 'prerequisite_missing');
  const jwtMissing = missingResult.plans.find((p) => p.capability === 'jwt_alg_none_probe');
  assert.equal(jwtMissing?.status, 'prerequisite_missing');

  // SQL + reflection only need parameters (present) → ready even without identities
  assert.equal(
    missingResult.plans.find((p) => p.capability === 'sql_error_oracle_probe')?.status,
    'ready_for_authorization'
  );
  assert.equal(
    missingResult.plans.find((p) => p.capability === 'parameter_reflection_probe')?.status,
    'ready_for_authorization'
  );

  // Reflection without parameter name → prerequisite_missing
  const reflectNoParam = generateAttackPlans({
    assessmentId,
    scanId,
    findings: [
      baseFinding({
        id: 'fnd_reflect_noparam',
        type: 'INPUT_VALIDATION_FLAW',
        title: 'Reflection missing param',
        target: 'https://app.example.com/echo',
        metadata: {
          kind: 'input_validation_flaw_metadata',
          category: 'PARAMETER_REFLECTION',
          candidateId: 'cand_reflect2',
          evidenceRecordId: 'evr_reflect2',
          lineage,
          endpointUrl: 'https://app.example.com/echo',
        },
      }),
    ],
    identities: [],
    lineage,
    generatedAt: nowIso,
  });
  assert.equal(reflectNoParam.plans.length, 1);
  assert.equal(reflectNoParam.plans[0]?.status, 'prerequisite_missing');
  assert.equal(reflectNoParam.plans[0]?.executable, false);

  console.log('✓ Test 3 Passed: Missing prerequisites → prerequisite_missing (not discarded)');

  // --- Test 4: Repository + application getAttackPlans + controller hermetic ---
  const attackPlanRepository = new InMemoryAttackPlanRepository();
  await attackPlanRepository.savePlans(satisfiedResult.plans);

  const listed = await attackPlanRepository.listByAssessmentId(assessmentId);
  assert.equal(listed.length, 6);

  const repository = new InMemoryOrchestratedAssessmentRepository();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: targetHost,
    status: 'completed',
    lineage,
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 1 },
    errorCount: 0,
    warningCount: 0,
    profile,
    findings: findingsSatisfied,
    recommendations: [],
  };
  await repository.save(record);

  const service = new OrchestratedAssessmentApplicationService({
    repository,
    attackPlanRepository,
  });
  const apiResult = await service.getAttackPlans(assessmentId);
  assert.equal(apiResult.assessmentId, assessmentId);
  assert.equal(apiResult.planCount, 6);
  assert.equal(apiResult.plans.length, 6);
  assert.ok(apiResult.plans.every((p) => p.executable === false));
  assert.equal(apiResult.lineage.assessmentId, assessmentId);

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: repository,
    attackPlanRepository,
    orchestratedService: service,
  });
  assert.equal(root.attackPlanRepository, attackPlanRepository);

  const controller = new OrchestratedAssessmentController(root.orchestratedService);
  let statusCode = 0;
  let body: unknown = null;
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
    if (err) throw err;
  };
  await controller.getAttackPlans(req, res, next);
  assert.equal(statusCode, 200);
  assert.ok(body && typeof body === 'object');
  const payload = body as { planCount: number; plans: unknown[] };
  assert.equal(payload.planCount, 6);
  assert.equal(payload.plans.length, 6);

  console.log('✓ Test 4 Passed: Plans stored and retrievable via application/API path');

  console.log('=== Milestone A3 Attack Planning: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
});
