/**
 * Supabase RLS write probe (3b) hermetic smoke.
 * Proves fail-closed without mutation scope; succeeds with mock transport canary.
 * Never hits live production.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackExecutionStep } from '../attack-execution/AttackExecutionContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { createSupabaseRlsWriteProbeCapability } from '../attack-execution/capabilities/SupabaseRlsWriteProbeCapability.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';

function baseGrant(mut: boolean): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_sbrls_w_001',
    scanId: 'scan_sbrls_w_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for supabase write probe smoke',
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
      allowedDomains: ['app.example.com', 'xyzcompany.supabase.co'],
      allowedHosts: ['app.example.com', 'xyzcompany.supabase.co'],
      allowedOrigins: [
        'https://app.example.com',
        'https://xyzcompany.supabase.co',
      ],
      allowedMethods: mut
        ? ['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS']
        : ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: mut,
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

function makeFinding(): Finding {
  return {
    id: 'fnd_sbrls_w_001',
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: "Supabase RLS world-readable table 'shop_items'",
    description: 'hermetic',
    target: 'https://xyzcompany.supabase.co/rest/v1/shop_items?select=*&limit=1',
    evidence: '{}',
    confidence: 0.9,
    verificationState: 'suspected_vulnerability',
    metadata: {
      kind: 'supabase_rls_abuse_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      claimKind: 'SUPABASE_RLS_WORLD_READABLE',
      tableName: 'shop_items',
      tableUrl: 'https://xyzcompany.supabase.co/rest/v1/shop_items',
      anonStatusCode: 200,
      anonBodyHash: 'h',
      topLevelJsonKeys: ['id'],
      rowCountHint: 1,
      anonEqualsAuth: true,
      observedAt: '2026-09-24T12:00:00.000Z',
    },
  };
}

function makePlan(finding: Finding): AttackPlan {
  return {
    contractVersion: 'fixguard-attack-planning/v0',
    kind: 'attack_plan',
    planId: 'apl_sbrls_w_001',
    assessmentId: 'asmt_sbrls_w_001',
    scanId: 'scan_sbrls_w_001',
    capability: 'supabase_rls_write_probe',
    title: "Probe Supabase RLS write (canary) on 'shop_items'",
    reasoning: 'hermetic',
    status: 'authorized',
    blastRadius: 'single_resource',
    capabilityGained: 'active_validation',
    sourceFindingIds: [finding.id],
    sourceFindingTypes: [finding.type],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_w_1',
        ordinal: 1,
        title: 'write canary',
        description: 'POST+DELETE',
        status: 'ready',
        requiredPermissions: ['active_http_get', 'active_http_post'],
      },
    ],
    lineage: {
      assessmentId: 'asmt_sbrls_w_001',
      scanId: 'scan_sbrls_w_001',
      authorizationGrantId: 'grant_sbrls_w_001',
      authorizationDecisionId: 'dec_sbrls_w_001',
      actorId: 'act_sbrls_w',
    },
    createdAt: '2026-09-24T12:05:00.000Z',
    targetUrl: finding.target,
    executable: false,
  };
}

async function main(): Promise<void> {
  console.log('=== Supabase RLS write probe (3b) smoke ===');

  const registry = AttackCapabilityRegistry.createDefault();
  assert.ok(registry.get('supabase_rls_write_probe'));
  console.log('[+] write probe registered in capability registry');

  const finding = makeFinding();
  const plan = makePlan(finding);
  const step: AttackExecutionStep = {
    stepId: 'step_w_1',
    ordinal: 1,
    title: 'write canary',
    description: 'POST+DELETE',
    status: 'ready',
    blastRadiusClass: 'state_change_benign',
    requiredPermissions: ['active_http_get', 'active_http_post'],
  };
  const token = {
    contractVersion: 'fixguard-attack-authorization/v0',
    kind: 'attack_authorization_token',
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    blastRadiusClass: 'state_change_benign',
    authorizationLevel: 'hitl_plan_approval',
    authorizedBy: 'act_sbrls_w',
    authorizedAt: '2026-09-24T12:06:00.000Z',
  } as AttackAuthorizationToken;

  // Fail-closed: no state change
  {
    const grant = baseGrant(false);
    const now = '2026-09-24T12:05:00.000Z';
    const auth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: plan.assessmentId,
        scanId: plan.scanId,
        authorizationDecisionId: 'dec_sbrls_w_001',
        authorizedActor: { actorId: 'act_sbrls_w', actorType: 'human' },
        decision: 'authorized',
        decidedAt: now,
        scopeGrant: grant,
      },
      now
    );
    assert.equal(auth.status, 'established');
    const cap = createSupabaseRlsWriteProbeCapability({
      transport: async () => {
        throw new Error('network must not run');
      },
      dnsResolver: async () => ['104.18.32.7'],
    });
    const res = await cap.execute({
      plan,
      step,
      token,
      targetHost: 'xyzcompany.supabase.co',
      targetUrl: finding.target,
      scopeGrant: grant,
      findings: [finding],
      verifiedAuthorizationDecision: auth.decision,
      primaryIdentity: {
        identityId: 'id_a',
        headers: { apikey: 'sb_publishable_hermetic_key_xxxxxxxxxxxx' },
      },
    });
    assert.equal(res.outcome, 'failed');
    assert.equal(res.reasonCode, 'supabase_rls_write_state_change_denied');
    console.log('[+] fail-closed without allowStateChangingRequests');
  }

  // Succeed with mock writable + cleanup
  {
    const grant = baseGrant(true);
    const now = '2026-09-24T12:05:00.000Z';
    const auth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: plan.assessmentId,
        scanId: plan.scanId,
        authorizationDecisionId: 'dec_sbrls_w_001',
        authorizedActor: { actorId: 'act_sbrls_w', actorType: 'human' },
        decision: 'authorized',
        decidedAt: now,
        scopeGrant: grant,
      },
      now
    );
    assert.equal(auth.status, 'established');
    let sawDelete = false;
    const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.method === 'POST') {
        return {
          statusCode: 201,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify([{ id: 'canary-1', name: 'x' }]),
          responseTimeMs: 5,
        };
      }
      if (req.method === 'DELETE') {
        sawDelete = true;
        return {
          statusCode: 204,
          headers: {},
          bodyText: '',
          responseTimeMs: 5,
        };
      }
      return {
        statusCode: 404,
        headers: {},
        bodyText: '',
        responseTimeMs: 5,
      };
    };
    const cap = createSupabaseRlsWriteProbeCapability({
      transport,
      dnsResolver: async () => ['104.18.32.7'],
    });
    const res = await cap.execute({
      plan,
      step,
      token,
      targetHost: 'xyzcompany.supabase.co',
      targetUrl: finding.target,
      scopeGrant: grant,
      findings: [finding],
      verifiedAuthorizationDecision: auth.decision,
      primaryIdentity: {
        identityId: 'id_a',
        headers: { apikey: 'sb_publishable_hermetic_key_xxxxxxxxxxxx' },
      },
    });
    assert.equal(res.outcome, 'succeeded');
    assert.equal(res.reasonCode, 'supabase_rls_world_writable_observed');
    assert.ok(sawDelete);
    console.log('[+] hermetic writable + cleanup succeeded');
  }

  // Refute on 403
  {
    const grant = baseGrant(true);
    const now = '2026-09-24T12:05:00.000Z';
    const auth = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: plan.assessmentId,
        scanId: plan.scanId,
        authorizationDecisionId: 'dec_sbrls_w_001',
        authorizedActor: { actorId: 'act_sbrls_w', actorType: 'human' },
        decision: 'authorized',
        decidedAt: now,
        scopeGrant: grant,
      },
      now
    );
    const cap = createSupabaseRlsWriteProbeCapability({
      transport: async () => ({
        statusCode: 403,
        headers: {},
        bodyText: '{"message":"new row violates"}',
        responseTimeMs: 5,
      }),
      dnsResolver: async () => ['104.18.32.7'],
    });
    assert.equal(auth.status, 'established');
    if (auth.status !== 'established' || !auth.decision) {
      throw new Error('auth failed');
    }
    const res = await cap.execute({
      plan,
      step,
      token,
      targetHost: 'xyzcompany.supabase.co',
      targetUrl: finding.target,
      scopeGrant: grant,
      findings: [finding],
      verifiedAuthorizationDecision: auth.decision,
      primaryIdentity: {
        identityId: 'id_a',
        headers: { apikey: 'sb_publishable_hermetic_key_xxxxxxxxxxxx' },
      },
    });
    assert.equal(res.outcome, 'refuted');
    assert.equal(res.reasonCode, 'supabase_rls_write_denied');
    console.log('[+] write denied (403) refuted cleanly');
  }

  console.log('=== Supabase RLS write probe smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
