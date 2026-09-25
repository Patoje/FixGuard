/**
 * Plan A Fase 4 / A4 thin — Authz matrix write pairs + BOLA/BFLA expansion (hermetic).
 * Skip live without 2 JWTs. No destructive writes against production.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  buildAuthzMatrixWritePairs,
} from '../detection/MultiIdentityAuthzMatrixService.js';
import {
  runSupabaseBolaBflaWriteExpansion,
  SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
} from '../detection/SupabaseBolaBflaWriteExpansionService.js';

function createScopeGrant(mut: boolean): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_s4_write_mx_001',
    scanId: 'scan_s4_write_mx_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for authz write matrix smoke',
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

async function main(): Promise<void> {
  console.log('=== Authz matrix write pairs (A4 thin) smoke ===');

  const identityA = {
    identityId: 'id_a',
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.sigA' },
  };
  const identityB = {
    identityId: 'id_b',
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.sigB' },
  };

  // 1. Write pair builder
  const pairs = buildAuthzMatrixWritePairs(identityA, identityB);
  assert.equal(pairs.length, 3);
  assert.equal(pairs[0]!.pairKind, 'identity_a_vs_b_write');
  assert.equal(pairs[1]!.pairKind, 'unauth_vs_a_write');
  assert.equal(pairs[2]!.pairKind, 'unauth_vs_b_write');
  console.log('[+] buildAuthzMatrixWritePairs OK');

  const scopeMut = createScopeGrant(true);
  const lineage = {
    assessmentId: 'asmt_s4_wmx_001',
    scanId: scopeMut.scanId,
    authorizationGrantId: scopeMut.grantId,
    authorizationDecisionId: 'dec_s4_wmx_001',
    actorId: 'act_s4_wmx_op',
  };
  const now = '2026-09-24T12:05:00.000Z';
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: now,
      scopeGrant: scopeMut,
    },
    now
  );
  assert.equal(auth.status, 'established');

  // 2. Fail-closed without mutation scope
  const denied = await runSupabaseBolaBflaWriteExpansion({
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_request',
    detectionId: 'det_s4_wmx_denied',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant: createScopeGrant(false),
    tableUrl: 'https://xyzcompany.supabase.co/rest/v1/shop_items',
    anonApiKey: 'sb_publishable_hermetic_key_for_smoke_tests_xx',
    identityA,
    identityB,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(denied.status, 'scope_denied');
  assert.equal(denied.reasonCode, 'state_changing_requests_denied');
  console.log('[+] write matrix fail-closed without allowStateChangingRequests');

  // 3. Differential: unauth POST 201 → writeAuthzDifferential
  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    const authz = req.headers.authorization ?? req.headers.Authorization ?? '';
    const isUserJwt = /sigA|sigB/.test(authz);
    // Unauth (anon bearer only) accepts write; user JWT also accepts — unauth pair diffs.
    if (req.method === 'POST') {
      return {
        statusCode: isUserJwt ? 201 : 201,
        headers: { 'content-type': 'application/json' },
        bodyText: '{}',
        responseTimeMs: 5,
      };
    }
    return {
      statusCode: 200,
      headers: {},
      bodyText: '[]',
      responseTimeMs: 5,
    };
  };

  const observed = await runSupabaseBolaBflaWriteExpansion({
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_request',
    detectionId: 'det_s4_wmx_diff',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant: scopeMut,
    tableUrl: 'https://xyzcompany.supabase.co/rest/v1/shop_items',
    anonApiKey: 'sb_publishable_hermetic_key_for_smoke_tests_xx',
    identityA,
    identityB,
    maxPairs: 3,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(observed.status, 'differential_observed');
  assert.ok(observed.pairsExecuted >= 2);
  assert.ok(
    observed.pairObservations.some(
      (p) => p.pairKind.startsWith('unauth_') && p.writeAuthzDifferential
    )
  );
  console.log('[+] unauth write acceptance → differential_observed');

  // 4. Abstain when all writes rejected
  const secureTransport = async (
    _req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => ({
    statusCode: 401,
    headers: { 'content-type': 'application/json' },
    bodyText: '{"message":"JWT required"}',
    responseTimeMs: 5,
  });
  const abstained = await runSupabaseBolaBflaWriteExpansion({
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_request',
    detectionId: 'det_s4_wmx_abstain',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant: scopeMut,
    tableUrl: 'https://xyzcompany.supabase.co/rest/v1/shop_items',
    anonApiKey: 'sb_publishable_hermetic_key_for_smoke_tests_xx',
    identityA,
    identityB,
    maxPairs: 2,
    transport: secureTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(abstained.status, 'secure_target_abstained');
  console.log('[+] all writes rejected → secure_target_abstained');

  // 5. Missing anon key
  const noKey = await runSupabaseBolaBflaWriteExpansion({
    contractVersion: SUPABASE_BOLA_BFLA_WRITE_CONTRACT_VERSION,
    kind: 'supabase_bola_bfla_write_expansion_request',
    detectionId: 'det_s4_wmx_nokey',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant: scopeMut,
    tableUrl: 'https://xyzcompany.supabase.co/rest/v1/shop_items',
    anonApiKey: '',
    identityA,
    identityB,
  });
  assert.equal(noKey.status, 'prerequisite_missing');
  console.log('[+] missing anon key → prerequisite_missing');

  console.log('=== Authz matrix write pairs smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
