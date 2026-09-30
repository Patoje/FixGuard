/**
 * Milestone M1 — Auth Boundary Differential closed-loop smoke (hermetic)
 *
 * Cases:
 * 1. A 200 / anon 302 login → secure (capability refuted)
 * 2. Both 404 → inconclusive
 * 3. HTML soft-404 → inconclusive
 * 4. WAF interfered → interfered (failed + TestValidity blocks mutation)
 * 5. Anon parity (JSON) → validated (succeeded)
 * 6. Anon success moderate similarity → suspicious (observed)
 * 7. Registry + capability wiring (not stub)
 */

import assert from 'node:assert/strict';
import { createAuthBoundaryDifferentialCapability } from '../attack-execution/capabilities/AuthBoundaryDifferentialCapability.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AuthBoundaryDifferentialDetectionService } from '../detection/AuthBoundaryDifferentialDetectionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AttackCapabilityInvocationContext } from '../attack-execution/AttackExecutionContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import {
  evaluateTestValidityFromReasonCode,
  canMutateVerificationState,
} from '../test-validity/TestValidityService.js';

const ENDPOINT = 'https://shop.example.com/myaccount';

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grnt_abnd_m1',
    scanId: 'scn_abnd_m1',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://shop.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for M1 auth boundary hermetic smoke',
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
      allowedDomains: ['shop.example.com'],
      allowedHosts: ['shop.example.com'],
      allowedOrigins: ['https://shop.example.com'],
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

async function establishDecision() {
  const decidedAt = new Date().toISOString();
  const grant = scopeGrant();
  const result = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_abnd_m1',
      scanId: 'scn_abnd_m1',
      authorizationDecisionId: 'dec_abnd_m1',
      authorizedActor: { actorId: 'act_abnd_m1', actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: grant,
    },
    decidedAt
  );
  if (result.status !== 'established' || !result.decision) {
    throw new Error('Failed to establish verified authorization for M1 smoke');
  }
  return { decision: result.decision, grant };
}

function planStub(): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'pln_abnd_m1',
    assessmentId: 'asm_abnd_m1',
    scanId: 'scn_abnd_m1',
    title: 'Auth boundary M1 hermetic',
    reasoning: 'hermetic',
    capability: 'auth_boundary_differential',
    blastRadius: 'user_scoped',
    capabilityGained: 'read_authenticated',
    status: 'ready_for_authorization',
    sourceFindingIds: [],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_abnd_1',
        ordinal: 1,
        title: 'Auth boundary GET',
        description: 'hermetic',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    executable: false,
    planOrigin: 'observed_surface',
    targetUrl: ENDPOINT,
    lineage: {
      assessmentId: 'asm_abnd_m1',
      scanId: 'scn_abnd_m1',
      authorizationGrantId: 'grnt_abnd_m1',
      authorizationDecisionId: 'dec_abnd_m1',
      actorId: 'act_abnd_m1',
    },
    createdAt: new Date().toISOString(),
  };
}

function invocationCtx(
  decision: Awaited<ReturnType<typeof establishDecision>>['decision'],
  grant: AuthorizedScopeGrant,
  transport: IdorHttpProbeTransport
): AttackCapabilityInvocationContext {
  const token = Object.freeze({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'attack_authorization_token' as const,
    planId: 'pln_abnd_m1',
    assessmentId: 'asm_abnd_m1',
    blastRadiusClass: 'read_escalated' as const,
    authorizationLevel: 'hitl_plan_approval' as const,
    authorizedBy: 'act_abnd_m1',
    authorizedAt: new Date().toISOString(),
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  }) as AttackAuthorizationToken;

  const plan = planStub();
  return {
    plan,
    step: {
      ...plan.steps[0]!,
      blastRadiusClass: 'read_escalated',
    },
    token,
    targetHost: 'shop.example.com',
    targetUrl: ENDPOINT,
    scopeGrant: grant,
    findings: [],
    primaryIdentity: {
      identityId: 'id_a',
      headers: { authorization: 'Bearer operator_token_a' },
    },
    verifiedAuthorizationDecision: decision,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  };
}

function jsonBody(obj: Record<string, unknown>): string {
  return JSON.stringify(obj);
}

async function runCase(
  name: string,
  transport: IdorHttpProbeTransport,
  expect: {
    readonly outcome: string;
    readonly reasonIncludes?: RegExp;
    readonly investigationViaService?: string;
  }
): Promise<void> {
  const { decision, grant } = await establishDecision();
  const port = createAuthBoundaryDifferentialCapability({
    service: new AuthBoundaryDifferentialDetectionService(),
    transport,
  });
  const result = await port.execute(invocationCtx(decision, grant, transport));
  assert.equal(result.outcome, expect.outcome, `${name}: outcome`);
  if (expect.reasonIncludes) {
    assert.match(result.reasonCode, expect.reasonIncludes, `${name}: reasonCode`);
  }
  console.log(`  [PASS] ${name} → ${result.outcome}/${result.reasonCode}`);
}

async function main(): Promise<void> {
  console.log('=== M1 Auth Boundary Differential Smoke ===');

  {
    console.log('[*] Case 1: secure A 200 / anon 302 login');
    await runCase(
      'secure_boundary',
      async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
        if (req.headers['authorization']) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: jsonBody({ accountId: 'a1', orders: 2 }),
            responseTimeMs: 10,
          };
        }
        return {
          statusCode: 302,
          headers: { location: 'https://shop.example.com/login' },
          bodyText: '',
          responseTimeMs: 8,
        };
      },
      { outcome: 'refuted', reasonIncludes: /auth_boundary_enforced/ }
    );
  }

  {
    console.log('[*] Case 2: both 404 inconclusive');
    await runCase(
      'both_404',
      async (): Promise<HttpProbeResponse> => ({
        statusCode: 404,
        headers: { 'content-type': 'application/json' },
        bodyText: jsonBody({ error: 'not_found' }),
        responseTimeMs: 5,
      }),
      { outcome: 'failed', reasonIncludes: /both_404_inconclusive/ }
    );
    const validity = evaluateTestValidityFromReasonCode('both_404_inconclusive');
    assert.equal(validity.verdict, 'inconclusive');
    assert.equal(canMutateVerificationState(validity), false);
  }

  {
    console.log('[*] Case 3: HTML soft-404 inconclusive');
    await runCase(
      'html_soft_404',
      async (): Promise<HttpProbeResponse> => ({
        statusCode: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
        bodyText: '<!doctype html><html><body>SPA shell</body></html>',
        responseTimeMs: 12,
      }),
      { outcome: 'failed', reasonIncludes: /soft_404|html_shell/ }
    );
  }

  {
    console.log('[*] Case 4: WAF interfered');
    await runCase(
      'waf_interfered',
      async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
        if (req.headers['authorization']) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: jsonBody({ accountId: 'a1' }),
            responseTimeMs: 10,
          };
        }
        return {
          statusCode: 403,
          headers: {
            'content-type': 'text/html',
            'cf-ray': 'abc123',
            'cf-mitigated': 'challenge',
          },
          bodyText: 'Just a moment... cf-browser-verification challenge',
          responseTimeMs: 40,
        };
      },
      { outcome: 'failed', reasonIncludes: /waf|interfered/ }
    );
    const validity = evaluateTestValidityFromReasonCode('waf_or_challenge_interfered');
    assert.equal(validity.verdict, 'interfered');
    assert.equal(canMutateVerificationState(validity), false);
  }

  {
    console.log('[*] Case 5: validated broken boundary (anon parity)');
    await runCase(
      'validated_leak',
      async (): Promise<HttpProbeResponse> => ({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: jsonBody({ accountId: 'a1', email: 'alice@example.com', balance: 42 }),
        responseTimeMs: 10,
      }),
      { outcome: 'succeeded', reasonIncludes: /auth_boundary_broken/ }
    );
  }

  {
    console.log('[*] Case 6: suspicious anon success (divergent bodies)');
    await runCase(
      'suspicious',
      async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
        if (req.headers['authorization']) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: jsonBody({
              accountId: 'a1',
              email: 'alice@example.com',
              orders: [{ id: 1 }],
              preferences: { theme: 'dark' },
            }),
            responseTimeMs: 10,
          };
        }
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: jsonBody({ public: true, marketing: 'welcome' }),
          responseTimeMs: 9,
        };
      },
      { outcome: 'observed', reasonIncludes: /suspicious/ }
    );
  }

  {
    console.log('[*] Case 7: default registry is real (not stub)');
    const registry = AttackCapabilityRegistry.createDefault();
    const port = registry.get('auth_boundary_differential');
    assert.ok(port);
    const { decision, grant } = await establishDecision();
    const result = await port!.execute(
      invocationCtx(decision, grant, async (req) => {
        if (req.headers['authorization']) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: jsonBody({ ok: true }),
            responseTimeMs: 5,
          };
        }
        return {
          statusCode: 401,
          headers: { 'content-type': 'application/json' },
          bodyText: jsonBody({ error: 'unauthorized' }),
          responseTimeMs: 5,
        };
      })
    );
    assert.notEqual(result.outcome, 'capability_not_implemented');
    assert.equal(result.outcome, 'refuted');
    console.log('  [PASS] registry capability real + secure');
  }

  {
    console.log('[*] Case 8: detection service direct secure path');
    const { decision, grant } = await establishDecision();
    const svc = new AuthBoundaryDifferentialDetectionService();
    const det = await svc.execute({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'auth_boundary_differential_detection_request',
      detectionId: 'det_abnd_direct',
      assessmentId: 'asm_abnd_m1',
      scanId: 'scn_abnd_m1',
      authorizationGrantId: 'grnt_abnd_m1',
      authorizationDecisionId: 'dec_abnd_m1',
      actorId: 'act_abnd_m1',
      verifiedAuthorizationDecision: decision,
      scopeGrant: grant,
      endpointUrl: ENDPOINT,
      identityA: {
        identityId: 'id_a',
        headers: { authorization: 'Bearer t' },
      },
      transport: async (req): Promise<HttpProbeResponse> => {
        if (req.headers['authorization']) {
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            bodyText: jsonBody({ account: 1 }),
            responseTimeMs: 5,
          };
        }
        return {
          statusCode: 302,
          headers: { location: '/account/login' },
          bodyText: '',
          responseTimeMs: 5,
        };
      },
      dnsResolver: async () => ['93.184.216.34'],
    });
    assert.equal(det.investigationOutcome, 'secure');
    assert.equal(det.status, 'boundary_secure');
    console.log('  [PASS] detection service investigationOutcome=secure');
  }

  console.log('\n=== M1 Auth Boundary Differential: ALL PASSED ===');
}

main().catch((err) => {
  console.error('[!] M1 Auth Boundary smoke failed:', err);
  process.exit(1);
});
