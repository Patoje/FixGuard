/**
 * Phase 7 — a session present at start is used on the first automatic read step.
 * Hermetic transport only. No public network. No invented identity B.
 */
import assert from 'node:assert/strict';
import process from 'node:process';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
  type AttackPlanGeneratorInput,
  type AttackPlanGeneratorResult,
} from '../attack-planning/AttackPlanContracts.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse, ProbeAuthContext } from '../detection/DetectionContracts.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import { runReadDetectionPass } from '../investigation/ReadDetectionPass.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

const HOST = 'app.example.com';
const ACTOR = 'act_sb_op';
const SCAN = 'scan_sb_main';
const GRANT = 'grant_sb_main';
const DECISION = 'dec_sb_main';
const ASSESSMENT = 'asmt_sb_main';
const MARKER = 'fgphase7marker';
const HEADER_MARKER = 'fgphase7header';
const ACCOUNT = `https://${HOST}/api/account`;

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: GRANT,
    scanId: SCAN,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized session bootstrap smoke',
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
      allowedOrigins: [`https://${HOST}`],
      allowedHosts: [HOST],
      allowedDomains: [HOST],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      deniedPathPatterns: [],
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

function lineage(): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
  };
}

function brandedDecision(): VerifiedAuthorizationDecision {
  const grant = scopeGrant();
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: ASSESSMENT,
      scanId: grant.scanId,
      authorizationDecisionId: DECISION,
      authorizedActor: { actorId: ACTOR, actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: grant,
    },
    nowIso
  );
  if (authRes.status !== 'established') {
    throw new Error(`authorization was not established: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

function inventory(path: string): ProbeInventory {
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
    entries: [
      {
        origin: `https://${HOST}`,
        path,
        method: 'GET',
        parameters: [],
        sources: ['web_inspection'],
      },
    ],
  };
}

function identityA(): ProbeAuthContext {
  return {
    identityId: 'id_session_a',
    headers: { accept: 'application/json', 'x-fg-marker': HEADER_MARKER },
    cookies: { sid: MARKER },
  };
}

function countingTransport(): {
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>;
  calls: HttpProbeRequest[];
} {
  const calls: HttpProbeRequest[] = [];
  const transport = async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push(request);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"account":"open"}',
      responseTimeMs: 1,
    };
  };
  return { transport, calls };
}

function headerBlob(request: HttpProbeRequest): string {
  return Object.entries(request.headers)
    .map(([key, value]) => `${key}:${value}`)
    .join('\n')
    .toLowerCase();
}

function plan(args: {
  readonly planId: string;
  readonly capability: AttackPlan['capability'];
  readonly targetUrl: string;
  readonly createdAt: string;
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: args.capability,
    title: args.planId,
    reasoning: 'Hermetic session bootstrap plan',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: args.capability === 'auth_boundary_differential' ? 'read_authenticated' : 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `${args.planId}_step`,
        ordinal: 1,
        title: 'Read step',
        description: 'Observation',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl: args.targetUrl,
    lineage: lineage(),
    createdAt: args.createdAt,
    executable: false,
  };
}

class SinglePlanGenerator extends AttackPlanGeneratorService {
  constructor(private readonly created: AttackPlan) {
    super();
  }

  public override generate(input: AttackPlanGeneratorInput): AttackPlanGeneratorResult {
    return {
      contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
      kind: 'attack_plan_generator_result',
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      plans: [{ ...this.created, assessmentId: input.assessmentId, scanId: input.scanId, lineage: { ...input.lineage } }],
      generatedAt: '2026-09-30T12:00:00.000Z',
      lineage: input.lineage,
    };
  }
}

async function detectionUsesIdentityA(): Promise<void> {
  const counted = countingTransport();
  const pass = await runReadDetectionPass({
    probeInventory: inventory('/api/account'),
    verifiedAuthorizationDecision: brandedDecision(),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: counted.transport,
    dnsResolver: async () => ['93.184.216.34'],
    identityA: identityA(),
  });
  assert.equal(pass.status, 'completed');
  assert.equal(pass.invokedDetectors.includes('auth_bypass'), true);
  assert.equal(pass.invokedDetectors.includes('auth_boundary_differential'), true);
  assert.equal(pass.invokedDetectors.includes('idor_differential'), false);
  assert.equal(
    counted.calls.some((request) => headerBlob(request).includes(HEADER_MARKER)),
    true
  );
}

async function detectionWithoutSessionStaysInconclusive(): Promise<void> {
  const counted = countingTransport();
  const pass = await runReadDetectionPass({
    probeInventory: inventory('/api/orders/ord_9'),
    verifiedAuthorizationDecision: brandedDecision(),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: counted.transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(pass.invokedDetectors.includes('auth_bypass'), false);
  assert.equal(pass.invokedDetectors.includes('auth_boundary_differential'), false);
  assert.equal(pass.invokedDetectors.includes('idor_differential'), false);
  assert.ok(
    pass.skipped.some(
      (skip) =>
        skip.detector === 'idor_differential' &&
        skip.reasonCode === 'two_identity_differential_inconclusive'
    )
  );
  assert.equal(JSON.stringify(pass).includes('id_session_b'), false);
  for (const request of counted.calls) {
    const blob = headerBlob(request);
    assert.equal(blob.includes('cookie'), false);
    assert.equal(blob.includes('authorization'), false);
    assert.equal(blob.includes(MARKER), false);
  }
}

async function bothIdentitiesCallIdorWhenResourceIsObserved(): Promise<void> {
  const counted = countingTransport();
  const identityB: ProbeAuthContext = {
    identityId: 'id_session_b',
    headers: { accept: 'application/json' },
  };
  const pass = await runReadDetectionPass({
    probeInventory: inventory('/api/orders/ord_9'),
    verifiedAuthorizationDecision: brandedDecision(),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: counted.transport,
    dnsResolver: async () => ['93.184.216.34'],
    identityA: identityA(),
    identityB,
  });
  assert.equal(pass.invokedDetectors.includes('idor_differential'), true);
  const plain = countingTransport();
  const noId = await runReadDetectionPass({
    probeInventory: inventory('/health'),
    verifiedAuthorizationDecision: brandedDecision(),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: plain.transport,
    dnsResolver: async () => ['93.184.216.34'],
    identityA: identityA(),
    identityB,
  });
  assert.equal(noId.invokedDetectors.includes('idor_differential'), false);
  assert.ok(
    noId.skipped.some(
      (skip) =>
        skip.detector === 'idor_differential' && skip.reasonCode === 'resource_id_not_observed'
    )
  );
}

async function firstLoopStepUsesIdentityA(): Promise<void> {
  const plans = new InMemoryAttackPlanRepository();
  const seen: string[] = [];
  let idorCalls = 0;
  const counted = countingTransport();
  const registry = AttackCapabilityRegistry.createDefault();
  registry.register({
    capability: 'security_header_probe',
    async execute(ctx) {
      const hop = ctx.transport ?? counted.transport;
      await hop({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_public_read',
        safeMessage: 'Anonymous read',
      };
    },
  });
  registry.register({
    capability: 'auth_boundary_differential',
    async execute(ctx) {
      seen.push(ctx.primaryIdentity?.identityId ?? '');
      const hop = ctx.transport ?? counted.transport;
      await hop({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { ...(ctx.primaryIdentity?.headers ?? {}), cookie: `sid=${MARKER}` },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_auth_boundary',
        safeMessage: 'Identity A read',
      };
    },
  });
  registry.register({
    capability: 'idor_read_differential',
    async execute() {
      idorCalls += 1;
      return { outcome: 'failed', reasonCode: 'should_not_run', safeMessage: 'idor' };
    },
  });
  await plans.savePlans([
    plan({
      planId: 'plan_sb_public',
      capability: 'security_header_probe',
      targetUrl: `https://${HOST}/health`,
      createdAt: '2026-09-30T12:00:00.000Z',
    }),
    plan({
      planId: 'plan_sb_auth',
      capability: 'auth_boundary_differential',
      targetUrl: ACCOUNT,
      createdAt: '2026-09-30T12:05:00.000Z',
    }),
    plan({
      planId: 'plan_sb_idor',
      capability: 'idor_read_differential',
      targetUrl: `https://${HOST}/api/orders/ord_9`,
      createdAt: '2026-09-30T12:06:00.000Z',
    }),
  ]);
  const loop = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: brandedDecision(),
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: counted.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: inventory('/api/account'),
    planRepository: plans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: new AttackAuthorizationService(plans),
    executionService: new AttackExecutionService({
      planRepository: plans,
      capabilityRegistry: registry,
    }),
    recordOutcome: async () => undefined,
    identities: [{ identityId: 'id_session_a', hasJwt: false }],
    primaryIdentity: {
      identityId: 'id_session_a',
      headers: { accept: 'application/json', cookie: `sid=${MARKER}` },
    },
    stepBudget: 4,
  });
  assert.equal(loop.record.executedSteps[0]?.capability, 'auth_boundary_differential');
  assert.equal(seen[0], 'id_session_a');
  assert.equal(idorCalls, 0);
  assert.equal(loop.record.executedSteps.some((step) => step.capability === 'idor_read_differential'), false);
  assert.equal(JSON.stringify(loop.record).includes(MARKER), false);
  assert.equal(JSON.stringify(loop.transcript).includes(MARKER), false);
  assert.equal(JSON.stringify(loop.transcript).includes(HEADER_MARKER), false);
}

async function startWithIdentityA(withSession: boolean): Promise<void> {
  process.env.FIXGUARD_V2_HERMETIC_RECON = '1';
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (!url.startsWith(`https://${HOST}/`) && !url.startsWith(`http://${HOST}/`)) {
      return new Response('', { status: 404 });
    }
    return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const calls: HttpProbeRequest[] = [];
  try {
    const planRepo = new InMemoryAttackPlanRepository();
    const service = new OrchestratedAssessmentApplicationService({
      repository: new InMemoryOrchestratedAssessmentRepository(),
      attackPlanRepository: planRepo,
      attackPlanGenerator: new SinglePlanGenerator(
        plan({
          planId: withSession ? 'plan_sb_start_auth' : 'plan_sb_start_public',
          capability: withSession ? 'auth_boundary_differential' : 'security_header_probe',
          targetUrl: withSession ? ACCOUNT : `https://${HOST}/health`,
          createdAt: '2026-09-30T12:00:00.000Z',
        })
      ),
      dnsResolver: async () => ['93.184.216.34'],
      httpTransport: async (request) => {
        calls.push(request);
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: '{"account":"open"}',
          responseTimeMs: 1,
        };
      },
      heartbeatIntervalMs: 60_000,
    });
    const started = await service.startAssessment({
      targetDomain: HOST,
      actorId: ACTOR,
      ...(withSession
        ? {
            sessionIdentities: {
              identityA: {
                identityId: 'id_session_a',
                injectHeaders: { 'x-fg-marker': HEADER_MARKER },
                injectCookies: { sid: MARKER },
              },
            },
          }
        : {}),
      config: {
        enableDeepRecon: false,
        enableSpaDiscovery: false,
        skipStages: [
          'stage_1_domain_zone',
          'stage_2_port_service',
          'stage_4_crawling_parameters',
          'stage_5_secret_inspection',
        ],
      },
    });
    const record = await service.awaitAssessment(started.assessmentId);
    assert.ok(record);
    assert.equal(record.status, 'completed');
    const status = await service.getStatus(started.assessmentId);
    assert.ok(status.transcript);
    assert.equal(JSON.stringify(status.transcript).includes(MARKER), false);
    assert.equal(JSON.stringify(status.transcript).includes(HEADER_MARKER), false);
    assert.equal(JSON.stringify(record.readInvestigationLoop ?? {}).includes(MARKER), false);
    assert.equal(JSON.stringify(record.readInvestigationLoop ?? {}).includes(HEADER_MARKER), false);
    if (withSession) {
      assert.ok(record.readInvestigationLoop);
      const first = record.readInvestigationLoop.executedSteps[0];
      assert.ok(first);
      assert.equal(
        first.capability === 'auth_boundary_differential' || first.capability === 'auth_bypass_probe',
        true
      );
      assert.equal(
        calls.some((request) => headerBlob(request).includes(MARKER) || headerBlob(request).includes(HEADER_MARKER)),
        true
      );
      assert.equal(service.getEphemeralByotExecuteIdentities(started.assessmentId)?.secondaryIdentity, undefined);
    } else {
      assert.equal(service.getEphemeralByotExecuteIdentities(started.assessmentId), null);
      for (const request of calls) {
        const blob = headerBlob(request);
        assert.equal(blob.includes(MARKER), false);
        assert.equal(blob.includes('cookie'), false);
      }
      assert.equal(
        (record.readInvestigationLoop?.executedSteps ?? []).some(
          (step) => step.capability === 'idor_read_differential'
        ),
        false
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function main(): Promise<void> {
  await detectionUsesIdentityA();
  await detectionWithoutSessionStaysInconclusive();
  await bothIdentitiesCallIdorWhenResourceIsObserved();
  await firstLoopStepUsesIdentityA();
  await startWithIdentityA(true);
  await startWithIdentityA(false);
}

main().catch(fail);
