/**
 * F1.6 — Anon vs session observation smoke.
 * Reuses AuthBoundaryDifferentialDetectionService and records a fact only.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { observeAnonSessionGetDelta } from '../observation/AnonSessionGetDeltaObservation.js';

const TOKEN = 'session-bearer-must-not-enter-fact';
const ENDPOINT = 'https://app.example.com/api/orders/ord_123';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f16_delta_001',
    scanId: 'scan_f16_delta_001',
    issuedAt: '2026-09-28T12:00:00.000Z',
    expiresAt: '2026-09-29T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for anon session observation smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedOrigins: ['https://app.example.com'],
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

function jsonResponse(statusCode: number, body: string): HttpProbeResponse {
  return {
    statusCode,
    headers: { 'content-type': 'application/json' },
    bodyText: body,
    responseTimeMs: 4,
  };
}

async function main(): Promise<void> {
  console.log('=== F1.6 anon vs session observation smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage = {
    assessmentId: 'asmt_f16_delta_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f16_delta_001',
    actorId: 'act_f16_delta_op',
  };
  const now = '2026-09-28T12:05:00.000Z';
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
  assert.ok(auth.decision);

  const methods: string[] = [];
  const observed = await observeAnonSessionGetDelta({
    detectionId: 'obs_delta_orders',
    endpointUrl: ENDPOINT,
    identityA: {
      identityId: 'id_session_a',
      headers: { authorization: `Bearer ${TOKEN}` },
    },
    verifiedAuthorizationDecision: auth.decision,
    scopeGrant,
    lineage,
    observedAt: now,
    dnsResolver: async () => ['93.184.216.34'],
    transport: async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      methods.push(req.method);
      if (req.headers['authorization']) {
        return jsonResponse(200, '{"order":"ord_123"}');
      }
      return jsonResponse(401, '{"error":"unauthorized"}');
    },
  });
  assert.equal(observed.createsFinding, false);
  assert.equal(observed.interfered, false);
  assert.ok(observed.fact);
  assert.equal(observed.fact?.factKind, 'anon_session_get_delta');
  assert.equal(observed.fact?.epistemicStatus, 'OBSERVED');
  assert.match(observed.fact?.value ?? '', /anon=401/);
  assert.match(observed.fact?.value ?? '', /session=200/);
  assert.match(observed.fact?.value ?? '', /anon_shape=json_object/);
  assert.match(observed.fact?.value ?? '', /session_shape=json_object/);
  assert.match(observed.fact?.value ?? '', /interfered=false/);
  assert.ok(methods.every((method) => method === 'GET'));
  assert.equal(JSON.stringify(observed).includes(TOKEN), false);
  assert.equal('finding' in observed, false);
  console.log('[+] anon vs session GET recorded as an observed fact, not a finding');

  const interfered = await observeAnonSessionGetDelta({
    detectionId: 'obs_delta_waf',
    endpointUrl: ENDPOINT,
    identityA: {
      identityId: 'id_session_a',
      headers: { authorization: `Bearer ${TOKEN}` },
    },
    verifiedAuthorizationDecision: auth.decision,
    scopeGrant,
    lineage,
    observedAt: now,
    dnsResolver: async () => ['93.184.216.34'],
    transport: async (): Promise<HttpProbeResponse> => ({
      statusCode: 403,
      headers: { 'cf-ray': 'abc', 'content-type': 'text/html' },
      bodyText: '<html>Just a moment cf-browser-verification</html>',
      responseTimeMs: 4,
    }),
  });
  assert.equal(interfered.createsFinding, false);
  assert.equal(interfered.interfered, true);
  assert.match(interfered.fact?.value ?? '', /interfered=true/);
  assert.equal(JSON.stringify(interfered).includes(TOKEN), false);
  console.log('[+] WAF interference is marked on the fact and still is not a finding');

  console.log('=== F1.6 anon vs session observation smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
