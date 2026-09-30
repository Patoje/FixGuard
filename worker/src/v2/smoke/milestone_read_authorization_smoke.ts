/**
 * Phase 3 — read-class attack authorization from an existing verified decision.
 * Hermetic transport only. No public network.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { isRuntimeAuthorizedForBlastRadius } from '../attack-authorization/AttackAuthorizationService.js';
import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  AUTHORIZABLE_BLAST_RADIUS_CLASSES,
  AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
  PROHIBITED_BLAST_RADIUS_CLASSES,
  READ_OBSERVATION_BLAST_RADIUS_CLASSES,
  type BlastRadiusClass,
  type ReadObservationBlastRadiusClass,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import {
  ATTACK_EXECUTION_CONTRACT_VERSION,
  type AttackCapabilityPort,
} from '../attack-execution/AttackExecutionContracts.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackPlan,
} from '../attack-planning/AttackPlanContracts.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const assessmentA = 'asmt_read_auth_a';
const assessmentB = 'asmt_read_auth_b';
const scanA = 'scan_read_auth_a';
const grantA = 'grant_read_auth_a';
const decisionA = 'dec_read_auth_a';
const operatorId = 'act_read_auth_op';
const host = 'app.example.com';
const inScopeUrl = `https://${host}/robots.txt`;

const ACCEPTED: readonly ReadObservationBlastRadiusClass[] = [
  'read_public',
  'read_authenticated',
  'read_escalated',
];

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: grantA,
    scanId: scanA,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: host,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized read observation smoke for app.example.com',
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
      allowedOrigins: [`https://${host}`],
      allowedHosts: [host],
      allowedDomains: [host],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
      deniedPathPatterns: [],
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

function brandedDecision(): VerifiedAuthorizationDecision {
  const grant = scopeGrant();
  const nowIso = new Date().toISOString();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: assessmentA,
      scanId: grant.scanId,
      authorizationDecisionId: decisionA,
      authorizedActor: { actorId: operatorId, actorType: 'human' },
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

function buildPlan(
  planId: string,
  assessmentId: string,
  targetUrl: string
): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId,
    assessmentId,
    scanId: assessmentId === assessmentA ? scanA : 'scan_read_auth_b',
    capability: 'security_header_probe',
    title: 'Read observation plan',
    reasoning: 'Hermetic advisory plan for read authorization smoke',
    status: 'ready_for_authorization',
    blastRadius: 'single_endpoint',
    capabilityGained: 'none',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: `step_${planId}`,
        ordinal: 1,
        title: 'GET the target URL',
        description: 'Observation read of an in-scope URL',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    targetUrl,
    lineage: {
      assessmentId,
      scanId: assessmentId === assessmentA ? scanA : 'scan_read_auth_b',
      authorizationGrantId: assessmentId === assessmentA ? grantA : 'grant_read_auth_b',
      authorizationDecisionId: assessmentId === assessmentA ? decisionA : 'dec_read_auth_b',
      actorId: operatorId,
    },
    createdAt: '2026-09-30T16:00:00.000Z',
    executable: false,
  };
}

function countingTransport(): { transport: IdorHttpProbeTransport; calls: string[] } {
  const calls: string[] = [];
  const transport: IdorHttpProbeTransport = async (request) => {
    calls.push(request.url);
    return {
      statusCode: 200,
      headers: {},
      bodyText: 'ok',
      responseTimeMs: 1,
    };
  };
  return { transport, calls };
}

function publicDns(): PreSpawnDnsResolver {
  return async () => ['93.184.216.34'];
}

function readPort(): AttackCapabilityPort {
  return {
    capability: 'security_header_probe',
    async execute(ctx) {
      const transport = ctx.transport;
      if (!transport) {
        return {
          outcome: 'failed',
          reasonCode: 'transport_missing',
          safeMessage: 'Hermetic transport was not provided',
        };
      }
      await transport({
        url: ctx.targetUrl,
        method: 'GET',
        headers: { accept: 'text/html' },
      });
      return {
        outcome: 'observed',
        reasonCode: 'hermetic_read_observed',
        safeMessage: 'Hermetic in-scope read completed',
      };
    },
  };
}

function readRequest(
  planId: string,
  assessmentId: string,
  blastRadiusClass: BlastRadiusClass,
  decision: VerifiedAuthorizationDecision | undefined,
  extra?: Record<string, unknown>
): Record<string, unknown> {
  return {
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: AUTHORIZE_READ_OBSERVATION_REQUEST_KIND,
    planId,
    assessmentId,
    blastRadiusClass,
    operatorId,
    ...(decision ? { verifiedAuthorizationDecision: decision } : {}),
    ...(extra ?? {}),
  };
}

async function main(): Promise<void> {
  const pipelineSource = readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      '../application/OrchestratedAssessmentApplicationService.ts'
    ),
    'utf8'
  );
  assert.equal(
    pipelineSource.includes('authorizeReadObservationFromVerifiedDecision'),
    false
  );

  assert.deepEqual([...READ_OBSERVATION_BLAST_RADIUS_CLASSES], [...ACCEPTED]);

  const decision = brandedDecision();
  const planRepo = new InMemoryAttackPlanRepository();
  const planPublic = 'plan_read_auth_public';
  const planAuthn = 'plan_read_auth_authn';
  const planEscalated = 'plan_read_auth_esc';
  const planReject = 'plan_read_auth_reject';
  const planMeta = 'plan_read_auth_meta';
  const planLoop = 'plan_read_auth_loop';
  const planB = 'plan_read_auth_b';

  await planRepo.savePlan(buildPlan(planPublic, assessmentA, inScopeUrl));
  await planRepo.savePlan(buildPlan(planAuthn, assessmentA, inScopeUrl));
  await planRepo.savePlan(buildPlan(planEscalated, assessmentA, inScopeUrl));
  await planRepo.savePlan(buildPlan(planReject, assessmentA, inScopeUrl));
  await planRepo.savePlan(
    buildPlan(planMeta, assessmentA, 'http://169.254.169.254/latest/meta-data/')
  );
  await planRepo.savePlan(buildPlan(planLoop, assessmentA, 'http://127.0.0.1/'));
  await planRepo.savePlan(buildPlan(planB, assessmentB, inScopeUrl));

  const auth = new AttackAuthorizationService(planRepo);
  const execution = new AttackExecutionService({
    planRepository: planRepo,
    capabilityRegistry: new AttackCapabilityRegistry([readPort()]),
  });

  const confirmedOnly = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planPublic, assessmentA, 'read_public', undefined, { confirmed: true })
  );
  assert.equal(confirmedOnly.status, 'failed');
  assert.equal(auth.getRuntimeToken(planPublic, assessmentA), null);

  const confirmedWithDecision = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planPublic, assessmentA, 'read_public', decision, { confirmed: true })
  );
  assert.equal(confirmedWithDecision.status, 'failed');
  assert.equal(auth.getRuntimeToken(planPublic, assessmentA), null);

  const lookalike = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planPublic, assessmentA, 'read_public', { ...decision })
  );
  assert.equal(lookalike.status, 'failed');
  if (lookalike.status === 'failed') {
    assert.equal(lookalike.reasonCode, 'verified_decision_not_branded');
  }
  assert.equal(auth.getRuntimeToken(planPublic, assessmentA), null);

  const minted = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planPublic, assessmentA, 'read_public', decision)
  );
  assert.equal(minted.status, 'established');
  if (minted.status !== 'established') {
    throw new Error('read token was not established');
  }
  const token: AttackAuthorizationToken = minted.token;
  assert.equal(token.planId, planPublic);
  assert.equal(token.assessmentId, assessmentA);
  assert.equal(token.blastRadiusClass, 'read_public');
  assert.equal(
    isRuntimeAuthorizedForBlastRadius(token, 'read_public', planPublic, assessmentA),
    true
  );
  assert.equal(
    isRuntimeAuthorizedForBlastRadius(token, 'read_authenticated', planPublic, assessmentA),
    false
  );
  assert.equal(
    isRuntimeAuthorizedForBlastRadius(token, 'read_escalated', planPublic, assessmentA),
    false
  );
  const stored = await planRepo.getPlan(planPublic);
  assert.equal(stored?.executable, false);

  const secondClass = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planPublic, assessmentA, 'read_authenticated', decision)
  );
  assert.equal(secondClass.status, 'failed');
  if (secondClass.status === 'failed') {
    assert.equal(secondClass.reasonCode, 'read_authorization_already_established');
  }
  assert.equal(auth.getRuntimeToken(planPublic, assessmentA), token);

  const happyTransport = countingTransport();
  const happy = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: planPublic,
    assessmentId: assessmentA,
    token,
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: publicDns(),
    findings: [],
    operatorId,
    transport: happyTransport.transport,
    executedAt: '2026-09-30T16:05:00.000Z',
  });
  assert.equal(happy.status, 'completed', JSON.stringify(happy));
  assert.deepEqual(happyTransport.calls, [inScopeUrl]);
  const afterExecute = await planRepo.getPlan(planPublic);
  assert.equal(afterExecute?.executable, false);

  for (const blast of ['read_authenticated', 'read_escalated'] as const) {
    const planId = blast === 'read_authenticated' ? planAuthn : planEscalated;
    const other = await auth.authorizeReadObservationFromVerifiedDecision(
      readRequest(planId, assessmentA, blast, decision)
    );
    assert.equal(other.status, 'established', blast);
    if (other.status !== 'established') {
      throw new Error(`${blast} token was not established`);
    }
    assert.equal(
      isRuntimeAuthorizedForBlastRadius(other.token, blast, planId, assessmentA),
      true
    );
    assert.equal(other.token.assessmentId, assessmentA);
    assert.equal(other.token.planId, planId);
  }

  for (const blast of PROHIBITED_BLAST_RADIUS_CLASSES) {
    const denied = await auth.authorizeReadObservationFromVerifiedDecision(
      readRequest(planReject, assessmentA, blast, decision)
    );
    assert.equal(denied.status, 'failed', blast);
    if (denied.status === 'failed') {
      assert.equal(denied.reasonCode, 'blast_radius_class_prohibited');
    }
    assert.equal(auth.getRuntimeToken(planReject, assessmentA), null);
  }

  for (const blast of AUTHORIZABLE_BLAST_RADIUS_CLASSES) {
    if (
      blast === 'read_public' ||
      blast === 'read_authenticated' ||
      blast === 'read_escalated'
    ) {
      continue;
    }
    const denied = await auth.authorizeReadObservationFromVerifiedDecision(
      readRequest(planReject, assessmentA, blast, decision)
    );
    assert.equal(denied.status, 'failed', blast);
    if (denied.status === 'failed') {
      assert.equal(denied.reasonCode, 'blast_radius_class_not_read_observation');
    }
    assert.equal(auth.getRuntimeToken(planReject, assessmentA), null);
  }

  const mismatchTransport = countingTransport();
  const mismatch = await execution.execute({
    contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
    kind: 'attack_execution_request',
    planId: planB,
    assessmentId: assessmentB,
    token,
    scopeGrant: scopeGrant(),
    coordinator: new TargetExecutionCoordinator(),
    dnsResolver: publicDns(),
    findings: [],
    operatorId,
    transport: mismatchTransport.transport,
  });
  assert.equal(mismatch.status, 'preflight_denied');
  if (mismatch.status === 'preflight_denied') {
    assert.equal(mismatch.reasonCode, 'token_not_branded');
  }
  assert.deepEqual(mismatchTransport.calls, []);

  const decisionForB = await auth.authorizeReadObservationFromVerifiedDecision(
    readRequest(planB, assessmentB, 'read_public', decision)
  );
  assert.equal(decisionForB.status, 'failed');
  if (decisionForB.status === 'failed') {
    assert.equal(decisionForB.reasonCode, 'verified_decision_assessment_mismatch');
  }
  assert.equal(auth.getRuntimeToken(planB, assessmentB), null);

  for (const [planId, targetUrl] of [
    [planMeta, 'http://169.254.169.254/latest/meta-data/'],
    [planLoop, 'http://127.0.0.1/'],
  ] as const) {
    const internalMint = await auth.authorizeReadObservationFromVerifiedDecision(
      readRequest(planId, assessmentA, 'read_public', decision)
    );
    assert.equal(internalMint.status, 'established', planId);
    if (internalMint.status !== 'established') {
      throw new Error(`${planId} token was not established`);
    }
    const internalTransport = countingTransport();
    const internal = await execution.execute({
      contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
      kind: 'attack_execution_request',
      planId,
      assessmentId: assessmentA,
      token: internalMint.token,
      scopeGrant: scopeGrant(),
      coordinator: new TargetExecutionCoordinator(),
      dnsResolver: async () => ['169.254.169.254'],
      findings: [],
      operatorId,
      transport: internalTransport.transport,
    });
    assert.equal(internal.status, 'preflight_denied', targetUrl);
    if (internal.status === 'preflight_denied') {
      assert.equal(internal.reasonCode, 'gate_ssrf_egress');
    }
    assert.deepEqual(internalTransport.calls, []);
    const internalPlan = await planRepo.getPlan(planId);
    assert.equal(internalPlan?.executable, false);
  }
}

main().catch(fail);
