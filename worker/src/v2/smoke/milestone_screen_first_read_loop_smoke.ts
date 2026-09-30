/**
 * Screens run before noise and platform paths.
 * preflight_denied does not spend the step budget.
 * Hermetic transport only.
 */
import assert from 'node:assert/strict';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import type { AttackCapabilityKind } from '../attack-planning/AttackPlanContracts.js';
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
import type { ProbeInventoryEntry } from '../investigation/ProbeInventoryContracts.js';
import { READ_INVESTIGATION_PREFLIGHT_DENIED_CAP } from '../investigation/ReadInvestigationLoopContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'app.example.com';
const ASSESSMENT = 'asmt_screen_first_001';
const SCAN = 'scan_screen_first_001';
const GRANT = 'grant_screen_first_001';
const DECISION = 'dec_screen_first_001';
const ACTOR = 'act_screen_first';
const ADMIN = `https://${HOST}/admin`;
const NOISE = `https://${HOST}/a/i`;
const WASM = `https://${HOST}/.well-known/vercel/security/static/challenge.v2.wasm`;
const OUTSIDE = 'https://outsider.example/hidden';

const READ_CAPABILITIES: readonly AttackCapabilityKind[] = [
  'cors_misconfiguration_probe',
  'security_header_probe',
  'open_redirect_probe',
  'information_disclosure_probe',
  'session_fixation_probe',
];

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
      authorizationText: 'Authorized screen-first read loop smoke',
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

function entry(path: string, sources: readonly string[]): ProbeInventoryEntry {
  return {
    origin: `https://${HOST}`,
    path,
    method: 'GET',
    parameters: [],
    sources,
  };
}

function inventory(entries: readonly ProbeInventoryEntry[]) {
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory' as const,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    authorizationGrantId: GRANT,
    authorizationDecisionId: DECISION,
    actorId: ACTOR,
    entries,
  };
}

function manualPlan(args: {
  readonly planId: string;
  readonly targetUrl: string;
  readonly createdAt: string;
  readonly authorizationBlastRadiusClass?: AttackPlan['authorizationBlastRadiusClass'];
}): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: args.planId,
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    capability: 'security_header_probe',
    title: 'Hermetic read plan',
    reasoning: 'Read observation for the screen-first smoke',
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

function countingTransport(allow: (url: string) => boolean): {
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>;
  calls: string[];
} {
  const calls: string[] = [];
  const transport = async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push(request.url);
    if (!allow(request.url)) {
      return {
        statusCode: 403,
        headers: { 'content-type': 'text/plain' },
        bodyText: 'denied',
        responseTimeMs: 1,
      };
    }
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
  transport: (request: HttpProbeRequest) => Promise<HttpProbeResponse>,
  denyUnless: (url: string) => boolean
): AttackCapabilityRegistry {
  const ports = new AttackCapabilityRegistry([]);
  for (const capability of READ_CAPABILITIES) {
    ports.register({
      capability,
      async execute(ctx) {
        const target = ctx.targetUrl ?? '';
        if (!denyUnless(target)) {
          return {
            outcome: 'preflight_denied',
            reasonCode: 'gate_scope',
            safeMessage: 'Scope gate denied this read',
          };
        }
        const hop = ctx.transport ?? transport;
        await hop({
          url: target,
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
  }
  return ports;
}

async function main(): Promise<void> {
  assert.equal(READ_INVESTIGATION_PREFLIGHT_DENIED_CAP, 8);
  const grant = scopeGrant();
  const decision = brandedDecision(grant);
  const emitted = new AttackPlanGeneratorService().generate({
    assessmentId: ASSESSMENT,
    scanId: SCAN,
    findings: [],
    identities: [],
    lineage: lineage(),
    generatedAt: new Date().toISOString(),
    deferredSurfaceProbes: {
      originUrl: `https://${HOST}/`,
      applicationUrls: [ADMIN, NOISE, WASM, OUTSIDE],
      sessionFixationSuppressed: false,
      scopeGrant: grant,
    },
  }).plans;
  assert.ok(emitted.every((plan) => plan.executable === false));
  const ready = emitted.filter((plan) => plan.status === 'ready_for_authorization');
  assert.ok(ready.length > 0);
  assert.ok(ready.every((plan) => plan.targetUrl === ADMIN));
  assert.equal(emitted.some((plan) => (plan.targetUrl ?? '').includes('/a/i')), false);
  assert.equal(emitted.some((plan) => (plan.targetUrl ?? '').includes('challenge.v2.wasm')), false);
  assert.equal(emitted.some((plan) => (plan.targetUrl ?? '').includes('outsider.example')), false);

  const plans = new InMemoryAttackPlanRepository();
  const auth = new AttackAuthorizationService(plans);
  const counted = countingTransport((url) => url.includes('/admin'));
  const noisePlan = manualPlan({
    planId: 'plan_screen_noise',
    targetUrl: NOISE,
    createdAt: '2026-09-30T12:00:00.000Z',
  });
  const wasmPlan = manualPlan({
    planId: 'plan_screen_wasm',
    targetUrl: WASM,
    createdAt: '2026-09-30T12:00:01.000Z',
  });
  const persistence = manualPlan({
    planId: 'plan_screen_persist',
    targetUrl: `${ADMIN}/persist`,
    createdAt: '2026-09-30T12:00:02.000Z',
    authorizationBlastRadiusClass: 'persistence',
  });
  await plans.savePlans([...emitted, noisePlan, wasmPlan, persistence]);

  const capped = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: counted.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: inventory([
      entry('/admin', ['html_link_extraction']),
      entry('/a/i', ['jsluice']),
      entry('/.well-known/vercel/security/static/challenge.v2.wasm', ['url_discovery']),
    ]),
    planRepository: plans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: auth,
    executionService: new AttackExecutionService({
      planRepository: plans,
      capabilityRegistry: registryFor(counted.transport, (url) => url.includes('/admin')),
    }),
    recordOutcome: async () => undefined,
    stepBudget: 1,
  });

  assert.equal(capped.record.stepsExecuted, 1);
  assert.equal(capped.record.stopReason, 'step_budget_exhausted');
  assert.ok(counted.calls.length > 0);
  assert.ok(counted.calls.every((url) => url.includes('/admin')));
  assert.equal(counted.calls.some((url) => url.includes('/a/i')), false);
  assert.equal(counted.calls.some((url) => url.includes('challenge.v2.wasm')), false);
  assert.equal(auth.getRuntimeToken('plan_screen_persist', ASSESSMENT), null);
  assert.equal(auth.getRuntimeToken('plan_screen_noise', ASSESSMENT), null);
  assert.equal(auth.getRuntimeToken('plan_screen_wasm', ASSESSMENT), null);

  const denyPaths = ['/tienda', '/arcade', '/login', '/perfil'];
  const denyPlans = new InMemoryAttackPlanRepository();
  const denyAuth = new AttackAuthorizationService(denyPlans);
  const denyTransport = countingTransport((url) => url.includes('/admin'));
  await denyPlans.savePlans([
    ...denyPaths.map((path, index) =>
      manualPlan({
        planId: `plan_screen_deny_${index}`,
        targetUrl: `https://${HOST}${path}`,
        createdAt: `2026-09-30T12:00:0${index}.000Z`,
      })
    ),
    manualPlan({
      planId: 'plan_screen_admin_after_denies',
      targetUrl: ADMIN,
      createdAt: '2026-09-30T12:00:09.000Z',
    }),
  ]);
  const denied = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: denyTransport.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: inventory([
      ...denyPaths.map((path) => entry(path, ['html_link_extraction'])),
      entry('/admin', ['playwright_spa']),
    ]),
    planRepository: denyPlans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: denyAuth,
    executionService: new AttackExecutionService({
      planRepository: denyPlans,
      capabilityRegistry: registryFor(denyTransport.transport, (url) => url.includes('/admin')),
    }),
    recordOutcome: async () => undefined,
    stepBudget: 4,
  });
  const deniedSteps = denied.record.executedSteps.filter((step) => step.status === 'preflight_denied');
  assert.equal(deniedSteps.length, 4);
  assert.ok(deniedSteps.every((step) => step.reasonCode === 'gate_scope'));
  assert.ok(denyTransport.calls.some((url) => url.includes('/admin')));
  assert.notEqual(denied.record.stopReason, 'step_budget_exhausted');

  const capPaths = ['/uno', '/dos', '/tres', '/cuatro', '/cinco', '/seis', '/siete', '/ocho'];
  const capPlans = new InMemoryAttackPlanRepository();
  const capAuth = new AttackAuthorizationService(capPlans);
  const capTransport = countingTransport(() => false);
  await capPlans.savePlans([
    ...capPaths.map((path, index) =>
      manualPlan({
        planId: `plan_screen_cap_${index}`,
        targetUrl: `https://${HOST}${path}`,
        createdAt: `2026-09-30T13:00:0${index}.000Z`,
      })
    ),
    manualPlan({
      planId: 'plan_screen_perfil_untested',
      targetUrl: `https://${HOST}/perfil`,
      createdAt: '2026-09-30T13:00:09.000Z',
    }),
  ]);
  const cappedDenies = await runReadInvestigationLoop({
    assessmentId: ASSESSMENT,
    lineage: lineage(),
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    coordinator: new TargetExecutionCoordinator({ requestsPerSecond: 5, maxConcurrency: 2 }),
    dnsResolver: async () => ['93.184.216.34'],
    transport: capTransport.transport,
    circuitHost: HOST,
    findings: [],
    probeInventory: inventory([
      ...capPaths.map((path) => entry(path, ['rsc_discovery'])),
      entry('/perfil', ['html_link_extraction']),
    ]),
    planRepository: capPlans,
    planGenerator: new AttackPlanGeneratorService(),
    authorizationService: capAuth,
    executionService: new AttackExecutionService({
      planRepository: capPlans,
      capabilityRegistry: registryFor(capTransport.transport, () => false),
    }),
    recordOutcome: async () => undefined,
    stepBudget: 4,
  });
  assert.equal(cappedDenies.record.stopReason, 'preflight_denied');
  assert.equal(
    cappedDenies.record.executedSteps.filter((step) => step.status === 'preflight_denied').length,
    READ_INVESTIGATION_PREFLIGHT_DENIED_CAP
  );
  assert.equal(capTransport.calls.some((url) => url.includes('/perfil')), false);
  assert.notEqual(cappedDenies.record.stopReason, 'step_budget_exhausted');

  process.stdout.write('[milestone_screen_first_read_loop_smoke] passed\n');
}

main().catch(fail);
