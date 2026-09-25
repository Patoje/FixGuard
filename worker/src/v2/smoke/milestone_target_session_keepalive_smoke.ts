/**
 * FixGuard V2 — Target session keep-alive + activity deadline smoke.
 *
 * Verifies:
 * 1. Keep-alive interval constant (~3.5 min) and auth-material detection.
 * 2. Gated soft-ping uses BYOT cookies, records operator-safe hint, fail-soft.
 * 3. Preflight denial does not abort (returns preflight_denied status).
 * 4. Activity deadline: idle breach vs hard-max; touch resets idle.
 * 5. Dalfox parameter_reflection_probe is registered and OBSERVED-only.
 */

import assert from 'node:assert/strict';
import process from 'node:process';

import {
  TARGET_SESSION_KEEPALIVE_INTERVAL_MS,
  TargetSessionKeepAlive,
  byotBundleHasAuthenticatedIdentity,
  formatKeepAliveHint,
  identityHasAuthMaterial,
} from '../runtime/TargetSessionKeepAlive.js';
import {
  ASSESSMENT_ACTIVITY_IDLE_MS,
  ASSESSMENT_HARD_MAX_MS,
  AssessmentActivityDeadline,
  deadlineBreachError,
  deadlineBreachReasonCode,
} from '../runtime/AssessmentActivityDeadline.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { ByotSessionIdentityBundle } from '../detection/DetectionContracts.js';
import { buildProbeAuthContext } from '../application/OrchestratedAssessmentApplicationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import {
  buildDalfoxCliArgs,
  createDalfoxParameterReflectionCapability,
} from '../attack-execution/capabilities/DalfoxXssCapability.js';
import type { AttackCapabilityInvocationContext } from '../attack-execution/AttackExecutionContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';

function buildScope(domain: string, grantId: string, scanId: string): AuthorizedScopeGrant {
  const nowIso = new Date().toISOString();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: nowIso,
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    subject: { targetKind: 'domain', domain },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized keep-alive smoke for ${domain}`,
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
      allowedDomains: [domain],
      allowedHosts: [domain, '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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

async function runSmoke(): Promise<void> {
  console.log('[SMOKE] Target session keep-alive + activity deadline');

  assert.equal(TARGET_SESSION_KEEPALIVE_INTERVAL_MS, 210_000);
  assert.equal(ASSESSMENT_HARD_MAX_MS, 60 * 60 * 1000);
  assert.equal(ASSESSMENT_ACTIVITY_IDLE_MS, 15 * 60 * 1000);

  assert.equal(
    identityHasAuthMaterial({ identityId: 'anon', injectHeaders: {} }),
    false
  );
  assert.equal(
    identityHasAuthMaterial({
      identityId: 'a',
      injectCookies: { session: 'tok_placeholder' },
    }),
    true
  );
  assert.equal(
    byotBundleHasAuthenticatedIdentity({
      identityA: { identityId: 'a' },
    }),
    false
  );

  const domain = 'example.com';
  const lineage = {
    assessmentId: 'asmt_keepalive_smoke',
    scanId: 'scan_keepalive_smoke',
    authorizationGrantId: 'grant_keepalive_smoke',
    authorizationDecisionId: 'dec_keepalive_smoke',
    actorId: 'usr_keepalive_smoke',
  };
  const scope = buildScope(domain, lineage.authorizationGrantId, lineage.scanId);
  const decidedAt = scope.issuedAt;

  const authResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: scope,
    },
    decidedAt
  );
  if (authResult.status !== 'established' || !authResult.decision) {
    const detail =
      authResult.status === 'failed'
        ? `${authResult.reasonCode}: ${authResult.safeMessage}`
        : authResult.status;
    throw new Error(`Failed to establish verified authorization: ${detail}`);
  }
  const verified = authResult.decision;

  const bundle: ByotSessionIdentityBundle = {
    identityA: {
      identityId: 'id_a',
      injectCookies: { PHPSESSID: 'smoke_session_a' },
    },
    identityB: {
      identityId: 'id_b',
      injectHeaders: { Authorization: 'Bearer smoke_token_b' },
    },
  };

  const transportCalls: Array<{ url: string; cookie?: string; auth?: string }> = [];
  const ticks: string[] = [];
  let activityTouches = 0;

  const keepAlive = new TargetSessionKeepAlive({
    targetDomain: domain,
    verifiedAuthorizationDecision: verified,
    authorizedScopeGrant: scope,
    lineage,
    sessionIdentities: bundle,
    buildProbeAuthContext,
    dnsResolver: async () => ['93.184.216.34'],
    transport: async (req) => {
      transportCalls.push({
        url: req.url,
        cookie: req.headers['Cookie'] ?? req.headers['cookie'],
        auth: req.headers['authorization'] ?? req.headers['Authorization'],
      });
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: 'ok',
        responseTimeMs: 1,
      };
    },
    onActivity: () => {
      activityTouches += 1;
    },
    onTick: async (tick) => {
      ticks.push(formatKeepAliveHint(tick));
    },
    intervalMs: 50_000,
  });

  const tick = await keepAlive.emitTickForTest();
  assert.ok(tick);
  assert.equal(tick!.identityResults.length, 2);
  assert.equal(tick!.identityResults[0]?.status, 'ok');
  assert.equal(tick!.identityResults[1]?.status, 'ok');
  assert.equal(transportCalls.length, 2);
  assert.ok(transportCalls[0]?.cookie?.includes('PHPSESSID=smoke_session_a'));
  assert.ok(transportCalls[1]?.auth?.includes('Bearer smoke_token_b'));
  assert.equal(activityTouches, 1);
  assert.equal(ticks[0], 'A:ok;B:ok');
  assert.ok(!ticks[0]!.includes('smoke_session'));
  assert.ok(!ticks[0]!.includes('Bearer'));

  const throwing = new TargetSessionKeepAlive({
    targetDomain: domain,
    verifiedAuthorizationDecision: verified,
    authorizedScopeGrant: scope,
    lineage,
    sessionIdentities: bundle,
    buildProbeAuthContext,
    dnsResolver: async () => ['93.184.216.34'],
    transport: async () => ({
      statusCode: 204,
      headers: {},
      bodyText: '',
      responseTimeMs: 1,
    }),
    onTick: async () => {
      throw new Error('persist_failed');
    },
  });
  const soft = await throwing.emitTickForTest();
  assert.ok(soft);

  const oos = new TargetSessionKeepAlive({
    targetDomain: 'evil.example.net',
    verifiedAuthorizationDecision: verified,
    authorizedScopeGrant: scope,
    lineage,
    sessionIdentities: bundle,
    buildProbeAuthContext,
    dnsResolver: async () => ['93.184.216.34'],
    transport: async () => {
      throw new Error('must_not_transport');
    },
    onTick: async () => undefined,
  });
  const denied = await oos.emitTickForTest();
  assert.ok(denied);
  assert.equal(denied!.identityResults[0]?.status, 'preflight_denied');

  let clock = 1_000_000;
  const deadline = new AssessmentActivityDeadline({
    hardMaxMs: 10_000,
    idleMs: 3_000,
    now: () => clock,
    startedAtMs: clock,
  });
  assert.equal(deadline.check(), null);
  clock += 2_500;
  assert.equal(deadline.check(), null);
  deadline.touch();
  clock += 2_500;
  assert.equal(deadline.check(), null);
  clock += 3_000;
  assert.equal(deadline.check(), 'assessment_activity_idle');
  assert.equal(deadlineBreachReasonCode('assessment_activity_idle'), 'assessment_activity_idle');
  assert.equal(deadlineBreachError('assessment_activity_idle').name, 'AssessmentTimeoutError');

  clock = 1_000_000;
  const hard = new AssessmentActivityDeadline({
    hardMaxMs: 5_000,
    idleMs: 60_000,
    now: () => clock,
    startedAtMs: clock,
  });
  clock += 5_000;
  assert.equal(hard.check(), 'assessment_hard_max');

  const registry = AttackCapabilityRegistry.createDefault();
  assert.ok(registry.get('parameter_reflection_probe'));

  const args = buildDalfoxCliArgs({
    targetUrl: 'https://example.com/search',
    parameterName: 'q',
  });
  assert.ok(args.includes('url'));
  assert.ok(args.includes('--skip-mining-all'));
  assert.ok(args.includes('-p'));

  const dalfox = createDalfoxParameterReflectionCapability({
    observationProvider: async () => [
      {
        matchedAt: 'https://example.com/search?q=1',
        evidenceExcerpt: 'reflected_canary',
        epistemicStatus: 'OBSERVED',
      },
    ],
  });

  const fakePlan = {
    planId: 'plan_dalfox_smoke',
    parameterName: 'q',
  } as unknown as AttackPlan;

  const invokeBase = {
    plan: fakePlan,
    token: {} as AttackCapabilityInvocationContext['token'],
    targetHost: 'example.com',
    targetUrl: 'https://example.com/search',
    scopeGrant: scope,
    findings: [],
  };

  const result = await dalfox.execute({
    ...invokeBase,
    step: {
      stepId: 'step_1',
      ordinal: 1,
      title: 't',
      description: 'd',
      status: 'ready',
      requiredPermissions: [],
      blastRadiusClass: 'read_authenticated',
    },
  });
  assert.equal(result.outcome, 'observed');
  assert.equal(result.reasonCode, 'dalfox_reflection_observed');

  const absent = createDalfoxParameterReflectionCapability({
    observationProvider: async () => {
      throw new Error('dalfox_binary_absent');
    },
  });
  const absentResult = await absent.execute({
    ...invokeBase,
    step: {
      stepId: 'step_2',
      ordinal: 1,
      title: 't',
      description: 'd',
      status: 'ready',
      requiredPermissions: [],
      blastRadiusClass: 'read_authenticated',
    },
  });
  assert.equal(absentResult.outcome, 'failed');
  assert.equal(absentResult.reasonCode, 'dalfox_binary_absent');

  console.log('[SMOKE PASS] Target session keep-alive + activity deadline');
}

runSmoke().catch((err) => {
  console.error('[SMOKE FAIL]', err);
  process.exit(1);
});
