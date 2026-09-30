/**
 * Observed application routes get ready read plans.
 * Public static assets, out-of-scope hosts, and metadata URLs do not.
 * Step cap 1 runs an app route. Persistence is not branded.
 * Hermetic transport only.
 */
import assert from 'node:assert/strict';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runReadInvestigationLoop } from '../investigation/ReadInvestigationLoop.js';
import { PROBE_INVENTORY_CONTRACT_VERSION } from '../investigation/ProbeInventoryContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const ASSESSMENT = 'asmt_route_read_001';
const SCAN = 'scan_route_read_001';
const GRANT = 'grant_route_read_001';
const DECISION = 'dec_route_read_001';
const ACTOR = 'act_route_read';
const ADMIN = `https://${HOST}/admin`;
const CHUNK = `https://${HOST}/_next/static/chunks/main.js`;
const OUTSIDE = 'https://outsider.example/hidden';
const METADATA = 'http://169.254.169.254/latest/meta-data';
const GRAPHQL = `https://${HOST}/graphql`;

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: GRANT,
    scanId: SCAN,
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized application-route read plan smoke',
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
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
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

function lineage(): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
  };
}

function brandedDecision(grant: AuthorizedScopeGrant): VerifiedAuthorizationDecision {
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

function plansFor(urls: readonly string[], sessionFixationSuppressed: boolean) {
  const grant = scopeGrant();
  return new AttackPlanGeneratorService().generate({
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    findings: [],
    identities: [],
    lineage: lineage(),
    generatedAt: new Date().toISOString(),
    deferredSurfaceProbes: {
      originUrl: `https://${HOST}/`,
      applicationUrls: urls,
      sessionFixationSuppressed,
      scopeGrant: grant,
    },
  }).plans;
}

function manualPlan(args: {
  readonly planId: string;
  readonly targetUrl: string;
  readonly createdAt: string;
  readonly capability?: AttackPlan['capability'];
  readonly authorizationBlastRadiusClass?: AttackPlan['authorizationBlastRadiusClass'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: args.capability ?? 'security_header_probe',
    title: 'Hermetic read plan',
    reasoning: 'Read observation for the application-route smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    ...(args.authorizationBlastRadiusClass
      ? { authorizationBlastRadiusClass: args.authorizationBlastRadiusClass }
      : {}),
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `step_${args.planId}`,
        ordinal: 1,
        title: 'GET the target URL',
        description: 'Observation read of the plan URL',
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

class CountingAuthorization extends AttackAuthorizationService {
  readonly planIds: string[] = [];

  public override async authorizeReadObservationFromVerifiedDecision(
    request: unknown
  ): Promise<Awaited<ReturnType<AttackAuthorizationService['authorizeReadObservationFromVerifiedDecision']>>> {
    if (request && typeof request === 'object' && !Array.isArray(request)) {
      const planId = Reflect.get(request, 'planId');
      if (typeof planId === 'string') this.planIds.push(planId);
    }
    return super.authorizeReadObservationFromVerifiedDecision(request);
  }
}

function countingTransport(): {
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>;
  calls: string[];
} {
  const calls: string[] = [];
  const transport = async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push(request.url);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      bodyText: '{"ok":true}',
      responseTimeMs: 1,
    };
  };
  return { transport, calls };
}

function registryFor(
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>
): AttackCapabilityRegistry {
  const ports = AttackCapabilityRegistry.createDefault();
  ports.register({
    capability: 'security_header_probe',
    async execute(ctx) {
      const hop = ctx.transport ?? transport;
      await hop({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { accept: 'application/json' },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_read_observed',
        safeMessage: 'Hermetic in-scope read completed',
      };
    },
  });
  return ports;
}

async function main(): Promise<void> {
  const grant = scopeGrant();
  const decision = brandedDecision(grant);
  const emitted = plansFor([ADMIN, CHUNK, OUTSIDE, METADATA], false);
  assert.ok(emitted.every((plan) => plan.executable === false));

  const ready = emitted.filter((plan) => plan.status === 'ready_for_authorization');
  assert.ok(ready.length > 0);
  assert.ok(ready.every((plan) => plan.targetUrl === ADMIN));
  assert.equal(
    ready.some((plan) => plan.capability === 'graphql_surface_probe'),
    false
  );
  assert.ok(ready.some((plan) => plan.capability === 'security_header_probe'));
  assert.ok(ready.some((plan) => plan.capability === 'session_fixation_probe'));
  assert.equal(
    emitted.some((plan) => (plan.targetUrl ?? '').includes('/_next/static') && plan.status === 'ready_for_authorization'),
    false
  );
  assert.equal(emitted.some((plan) => (plan.targetUrl ?? '').includes('outsider.example')), false);
  assert.equal(emitted.some((plan) => (plan.targetUrl ?? '').includes('169.254.169.254')), false);
  const originHeader = emitted.find(
    (plan) => plan.capability === 'security_header_probe' && plan.targetUrl === `https://${HOST}/`
  );
  assert.ok(originHeader);
  assert.equal(originHeader.status, 'prerequisite_missing');

  const suppressed = plansFor([ADMIN], true);
  assert.equal(
    suppressed.some(
      (plan) =>
        plan.capability === 'session_fixation_probe' && plan.status === 'ready_for_authorization'
    ),
    false
  );

  const graphqlPlans = plansFor([GRAPHQL, ADMIN], true);
  assert.ok(
    graphqlPlans.some(
      (plan) =>
        plan.capability === 'graphql_surface_probe' &&
        plan.status === 'ready_for_authorization' &&
        plan.targetUrl === GRAPHQL
    )
  );
  assert.equal(
    graphqlPlans.some(
      (plan) =>
        plan.capability === 'graphql_surface_probe' &&
        plan.status === 'ready_for_authorization' &&
        plan.targetUrl === ADMIN
    ),
    false
  );

  const plans = new InMemoryAttackPlanRepository();
  const auth = new CountingAuthorization(plans);
  const counted = countingTransport();
  const staticHeader = manualPlan({
    planId: 'plan_route_static_header',
    targetUrl: CHUNK,
    createdAt: '2026-09-30T12:00:00.000Z',
  });
  const staticBypass = manualPlan({
    planId: 'plan_route_static_bypass',
    targetUrl: CHUNK,
    createdAt: '2026-09-30T12:00:01.000Z',
    capability: 'auth_bypass_probe',
  });
  const persistence = manualPlan({
    planId: 'plan_route_persist',
    targetUrl: `${ADMIN}/persist`,
    createdAt: '2026-09-30T12:00:02.000Z',
    authorizationBlastRadiusClass: 'persistence',
  });
  await plans.savePlans([...emitted, staticHeader, staticBypass, persistence]);

  const result = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: counted.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: {
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
          path: '/admin',
          method: 'GET',
          parameters: [],
          sources: ['url_discovery'],
        },
      ],
    },
    planRepository: plans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: auth,
    executionService: new AttackExecutionService({
      planRepository: plans,
      capabilityRegistry: registryFor(counted.transport),
    }),
    recordOutcome: async () => undefined,
    primaryIdentity: { identityId: 'id_session_a' },
    identities: [{ identityId: 'id_session_a', hasJwt: false }],
    stepBudget: 1,
  });

  assert.equal(result.record.stepsExecuted, 1);
  assert.equal(result.record.stopReason, 'step_budget_exhausted');
  const executed = await plans.getPlan(result.record.executedSteps[0]?.planId ?? '');
  assert.ok(executed?.targetUrl?.includes('/admin'));
  assert.equal(executed?.targetUrl?.includes('/_next/static'), false);
  assert.equal(counted.calls.some((url) => url.includes('/_next/static')), false);
  assert.equal(counted.calls.some((url) => url.includes('169.254.169.254')), false);
  assert.equal(auth.planIds.includes('plan_route_static_bypass'), false);
  assert.equal(auth.planIds.includes('plan_route_static_header'), false);
  assert.equal(auth.planIds.includes('plan_route_persist'), false);
  assert.equal(auth.getRuntimeToken('plan_route_persist', ASSESSMENT), null);
  assert.equal(auth.getRuntimeToken('plan_route_static_bypass', ASSESSMENT), null);

  const metaPlans = new InMemoryAttackPlanRepository();
  const metaAuth = new CountingAuthorization(metaPlans);
  const metaTransport = countingTransport();
  await metaPlans.savePlans([
    manualPlan({
      planId: 'plan_route_meta',
      targetUrl: METADATA,
      createdAt: '2026-09-30T12:00:00.000Z',
    }),
  ]);
  const metaResult = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: metaTransport.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: {
      contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
      kind: 'probe_inventory',
      assessmentId: ASSESSMENT,
      scanId: SCAN,
      authorizationGrantId: GRANT,
      authorizationDecisionId: DECISION,
      actorId: ACTOR,
      entries: [],
    },
    planRepository: metaPlans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: metaAuth,
    executionService: new AttackExecutionService({
      planRepository: metaPlans,
      capabilityRegistry: registryFor(metaTransport.transport),
    }),
    recordOutcome: async () => undefined,
    stepBudget: 1,
  });
  assert.deepEqual(metaTransport.calls, []);
  assert.equal(metaResult.record.stepsExecuted >= 0, true);

  process.stdout.write('[milestone_app_route_read_plans_smoke] passed\n');
}

main().catch(fail);
