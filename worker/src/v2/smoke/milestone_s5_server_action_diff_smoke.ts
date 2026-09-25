/**
 * Plan A Fase 5 thin — Next Server Action differential smoke (hermetic).
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
} from '../detection/NextServerActionDifferentialContracts.js';
import { runNextServerActionDifferential } from '../detection/NextServerActionDifferentialDetectionService.js';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_s5_sa_001',
    scanId: 'scan_s5_sa_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for server action diff smoke',
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
      allowedMethods: ['GET', 'HEAD', 'POST'],
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

async function main(): Promise<void> {
  console.log('=== Next Server Action differential (S5 thin) smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage = {
    assessmentId: 'asmt_s5_sa_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_s5_sa_001',
    actorId: 'act_s5_sa_op',
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
      scopeGrant,
    },
    now
  );
  assert.equal(auth.status, 'established');

  // Missing action id
  const missing = await runNextServerActionDifferential({
    contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
    kind: 'next_server_action_diff_request',
    detectionId: 'det_s5_missing',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    endpointUrl: 'https://app.example.com/perfil',
    actionId: 'short',
  });
  assert.equal(missing.status, 'prerequisite_missing');
  console.log('[+] short action id → prerequisite_missing');

  // Unauth accepts → differential
  const openTransport = async (
    req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => {
    assert.ok(req.headers['next-action']);
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/x-component' },
      bodyText: '1:{"a":"$@1"}',
      responseTimeMs: 5,
    };
  };
  const open = await runNextServerActionDifferential({
    contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
    kind: 'next_server_action_diff_request',
    detectionId: 'det_s5_open',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    endpointUrl: 'https://app.example.com/perfil',
    actionId: '0123456789abcdef0123456789abcdef',
    transport: openTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(open.status, 'differential_observed');
  assert.equal(open.reasonCode, 'unauth_server_action_accepted');
  assert.ok(open.actionIdRedacted.includes('…'));
  assert.ok(!open.actionIdRedacted.includes('0123456789abcdef0123456789abcdef'));
  console.log('[+] unauth accepted action → differential_observed (id redacted)');

  // Both 401 → abstain
  const closedTransport = async (
    _req: HttpProbeRequest
  ): Promise<HttpProbeResponse> => ({
    statusCode: 401,
    headers: {},
    bodyText: 'Unauthorized',
    responseTimeMs: 5,
  });
  const closed = await runNextServerActionDifferential({
    contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
    kind: 'next_server_action_diff_request',
    detectionId: 'det_s5_closed',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    endpointUrl: 'https://app.example.com/perfil',
    actionId: 'abcdef0123456789abcdef0123456789',
    authenticatedContext: {
      identityId: 'id_a',
      headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig' },
    },
    transport: closedTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(closed.status, 'secure_target_abstained');
  console.log('[+] dual 401 → secure_target_abstained');

  // Loopback preflight denied
  const denied = await runNextServerActionDifferential({
    contractVersion: NEXT_SERVER_ACTION_DIFF_CONTRACT_VERSION,
    kind: 'next_server_action_diff_request',
    detectionId: 'det_s5_loop',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant: {
      ...scopeGrant,
      subject: { targetKind: 'domain', domain: '127.0.0.1' },
      boundaries: {
        ...scopeGrant.boundaries,
        allowedHosts: ['127.0.0.1'],
        allowedDomains: ['127.0.0.1'],
        allowedOrigins: ['https://127.0.0.1'],
      },
    },
    endpointUrl: 'https://127.0.0.1/perfil',
    actionId: 'abcdef0123456789abcdef0123456789',
    dnsResolver: async () => ['127.0.0.1'],
  });
  assert.equal(denied.status, 'preflight_denied');
  console.log('[+] loopback preflight denied');

  console.log('=== Next Server Action differential smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
