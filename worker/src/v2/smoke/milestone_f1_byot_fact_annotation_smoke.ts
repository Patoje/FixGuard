/**
 * F1.4 — BYOT harvest annotates params and ids seen in XHR / RSC / _next/data.
 * Next-Action ids come only from observed text. No Server Action POST.
 * Tokens are not stored on the harvest record.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runByotNetworkHarvest } from '../recon/deep/ByotNetworkHarvestService.js';

const TOKEN = 'byot-session-token-must-not-persist';
const OBSERVED_ACTION = 'act_from_body_01';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f1_byot_001',
    scanId: 'scan_f1_byot_001',
    issuedAt: '2026-09-28T12:00:00.000Z',
    expiresAt: '2026-09-29T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for BYOT fact annotation smoke',
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

async function main(): Promise<void> {
  console.log('=== F1.4 BYOT harvest fact annotation smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_f1_byot_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f1_byot_001',
    actorId: 'act_f1_byot_op',
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
  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    methods.push(req.method);
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText:
        `<html>fetch("/api/orders/ord_123?user_id=42") ` +
        `fetch("/_next/data/build/index.json?account_id=9") ` +
        `"next-action":"${OBSERVED_ACTION}"</html>`,
      responseTimeMs: 3,
    };
  };

  const harvested = await runByotNetworkHarvest({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    authHeaders: { authorization: `Bearer ${TOKEN}` },
    httpOnly: true,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.equal(harvested.status, 'success');
  if (harvested.status !== 'success') return;
  assert.ok(methods.every((method) => method === 'GET'));
  assert.ok(harvested.observedFacts.some((fact) => fact.factKind === 'observed_param' && fact.value === 'user_id'));
  assert.ok(harvested.observedFacts.some((fact) => fact.factKind === 'observed_param' && fact.value === 'account_id'));
  assert.ok(harvested.observedFacts.some((fact) => fact.factKind === 'observed_object_id' && fact.value === 'ord_123'));
  assert.ok(harvested.observedFacts.some((fact) => fact.factKind === 'observed_action_id' && fact.value === OBSERVED_ACTION));
  assert.equal(
    harvested.observedFacts.some((fact) => fact.value === 'act_not_in_body'),
    false
  );
  const serialized = JSON.stringify(harvested);
  assert.equal(serialized.includes(TOKEN), false);
  assert.equal(serialized.includes('Bearer'), false);
  assert.equal('findings' in harvested, false);
  console.log('[+] XHR/_next/data params and ids are observed facts; no POST and no token in the record');

  console.log('=== F1.4 BYOT harvest fact annotation smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
