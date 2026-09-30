/**
 * F1.3 — api_schema_discovery smoke.
 * OpenAPI tables/relations and GraphQL types are observed surface only.
 * Hosts outside the grant are not requested. No RLS confirm and no writes.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';

const ANON_KEY = 'sb_observed_anon_key_not_for_dto';
const IN_GRANT = 'https://xyzcompany.supabase.co/rest/v1/orders';
const OUTSIDE = 'https://evil.supabase.co/rest/v1/secrets';
const GRAPHQL = 'https://app.example.com/graphql';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f1_schema_001',
    scanId: 'scan_f1_schema_001',
    issuedAt: '2026-09-28T12:00:00.000Z',
    expiresAt: '2026-09-29T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for api schema discovery smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['app.example.com'],
      allowedHosts: ['app.example.com', 'xyzcompany.supabase.co'],
      allowedOrigins: ['https://app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
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

async function main(): Promise<void> {
  console.log('=== F1.3 api_schema_discovery smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_f1_schema_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f1_schema_001',
    actorId: 'act_f1_schema_op',
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

  const calls: { method: string; url: string }[] = [];
  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    calls.push({ method: req.method, url: req.url });
    if (req.url.includes('evil.supabase.co')) {
      throw new Error('probed a host outside the grant');
    }
    if (req.method !== 'GET' && req.method !== 'POST') {
      throw new Error(`unexpected write method ${req.method}`);
    }
    if (req.method === 'POST' && !req.url.includes('/graphql')) {
      throw new Error(`non-graphql POST ${req.url}`);
    }
    if (req.url.includes('/rest/v1') && req.method === 'GET') {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/openapi+json' },
        bodyText: JSON.stringify({
          paths: { '/orders': { get: {} }, '/rpc/health': { post: {} } },
          info: { description: 'orders.user_id references profiles.id' },
        }),
        responseTimeMs: 4,
      };
    }
    if (req.url === GRAPHQL && req.method === 'POST') {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({
          data: { __schema: { types: [{ name: 'Order' }, { name: '__Schema' }] } },
        }),
        responseTimeMs: 4,
      };
    }
    return { statusCode: 404, headers: {}, bodyText: '', responseTimeMs: 1 };
  };

  const orch = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasSupabase: true },
    budget: { maxRequests: 40, remainingRequests: 40 },
    inventoryUrls: [{ url: IN_GRANT }, { url: OUTSIDE }, { url: GRAPHQL }],
    observedAnonApiKey: ANON_KEY,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  const schema = orch.methodResults.find((method) => method.method === 'api_schema_discovery');
  assert.equal(schema?.status, 'ran');
  assert.equal(schema?.reasonCode, 'schema_surface_observed');
  assert.ok(orch.schemaObservations.some((item) => item.surfaceKind === 'postgrest_table' && item.name === 'orders'));
  assert.ok(orch.schemaObservations.some((item) => item.surfaceKind === 'graphql_type' && item.name === 'Order'));
  assert.equal(
    orch.schemaObservations.some((item) => item.name === '__Schema'),
    false
  );
  assert.ok(
    orch.observedFacts.some(
      (fact) => fact.factKind === 'schema_relation' && fact.value === 'orders.user_id->profiles.id'
    )
  );
  assert.ok(orch.urlObservations.some((obs) => obs.url.includes('/rest/v1/orders')));
  assert.equal(calls.some((call) => call.url.includes('evil.supabase.co')), false);
  assert.equal(calls.some((call) => call.method === 'PUT' || call.method === 'PATCH' || call.method === 'DELETE'), false);
  assert.equal(JSON.stringify(orch).includes(ANON_KEY), false);
  assert.equal('findings' in orch, false);
  assert.equal(orch.nonClaims.createsRealFindings, false);
  console.log('[+] OpenAPI and GraphQL stay observed; outside-grant host and writes were not sent');

  console.log('=== F1.3 api_schema_discovery smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
