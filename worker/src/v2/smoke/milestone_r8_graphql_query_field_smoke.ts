/**
 * R8 — GraphQL auth delta uses a query field already written in the introspection body.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import { runApiSchemaDiscovery } from '../recon/deep/ApiSchemaDiscoveryService.js';
import { observeGraphqlAuthDelta } from '../observation/GraphqlAuthDeltaObservation.js';

const DOMAIN = 'app.example.com';
const GRAPHQL = `https://${DOMAIN}/graphql`;
const OBSERVED_AT = '2026-09-28T12:00:00.000Z';

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grnt_r8_001',
    scanId: 'scn_r8_001',
    issuedAt: '2026-09-28T11:00:00.000Z',
    expiresAt: '2026-09-29T11:00:00.000Z',
    subject: { targetKind: 'domain', domain: DOMAIN },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${DOMAIN}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [DOMAIN],
      allowedHosts: [DOMAIN, '93.184.216.34'],
      allowedOrigins: [`https://${DOMAIN}`],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
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
    assessmentId: 'asmt_r8_001',
    scanId: 'scn_r8_001',
    authorizationGrantId: 'grnt_r8_001',
    authorizationDecisionId: 'dec_r8_001',
    actorId: 'usr_secops_api',
  };
}

function establish(grant: AuthorizedScopeGrant) {
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_r8_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_r8_001',
      authorizedActor: { actorId: 'usr_secops_api', actorType: 'human' },
      decision: 'authorized',
      decidedAt: OBSERVED_AT,
      scopeGrant: grant,
    },
    OBSERVED_AT
  );
  if (auth.status !== 'established') {
    throw new Error(`auth not established: ${auth.reasonCode}`);
  }
  return auth.decision;
}

async function discover(bodyText: string): Promise<{
  readonly posts: readonly string[];
  readonly fields: readonly string[];
  readonly types: readonly string[];
}> {
  const posts: string[] = [];
  const grant = scopeGrant();
  const result = await runApiSchemaDiscovery({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: establish(grant),
    authorizedScopeGrant: grant,
    lineage: lineage(),
    inventoryUrls: [{ url: GRAPHQL }],
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
    transport: async (request: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (request.method === 'POST') posts.push(request.body ?? '');
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText,
        responseTimeMs: 1,
      };
    },
  });
  return {
    posts,
    fields: result.schemaObservations
      .filter((item) => item.surfaceKind === 'graphql_query_field')
      .map((item) => item.name),
    types: result.schemaObservations
      .filter((item) => item.surfaceKind === 'graphql_type')
      .map((item) => item.name),
  };
}

async function main(): Promise<void> {
  const typesOnly = JSON.stringify({
    data: { __schema: { types: [{ name: 'Order' }] } },
  });
  const withoutField = await discover(typesOnly);
  assert.equal(withoutField.posts.length, 1);
  assert.equal(withoutField.posts[0]?.includes('mutation'), false);
  assert.equal(withoutField.posts[0]?.includes('queryType'), true);
  assert.deepEqual(withoutField.fields, []);
  assert.deepEqual(withoutField.types, ['Order']);

  let deltaCalls = 0;
  const grant = scopeGrant();
  const missingOperation = await observeGraphqlAuthDelta({
    endpointUrl: GRAPHQL,
    identityA: { identityId: 'id_a', headers: { authorization: 'Bearer operator_a' } },
    verifiedAuthorizationDecision: establish(grant),
    scopeGrant: grant,
    lineage: lineage(),
    transport: async () => {
      deltaCalls += 1;
      throw new Error('transport must not run without an operation');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(missingOperation.requestCount, 0);
  assert.equal(missingOperation.fact, null);
  assert.equal(deltaCalls, 0);

  const withFieldBody = JSON.stringify({
    data: {
      __schema: {
        types: [{ name: 'Order' }],
        queryType: { fields: [{ name: 'orders' }] },
      },
    },
  });
  assert.equal(withFieldBody.includes('orders'), true);
  const withField = await discover(withFieldBody);
  assert.equal(withField.posts.every((body) => !body.includes('mutation')), true);
  assert.deepEqual(withField.types, ['Order']);
  assert.deepEqual(withField.fields, ['orders']);
  const operationName = withField.fields[0];
  assert.equal(operationName, 'orders');
  assert.notEqual(operationName, 'Order');

  const seen: string[] = [];
  const observed = await observeGraphqlAuthDelta({
    endpointUrl: GRAPHQL,
    operationName,
    identityA: { identityId: 'id_a', headers: { authorization: 'Bearer operator_a' } },
    verifiedAuthorizationDecision: establish(grant),
    scopeGrant: grant,
    lineage: lineage(),
    transport: async (request) => {
      seen.push(`${request.method} ${request.url} ${request.body ?? ''}`);
      return {
        statusCode: 200,
        headers: {},
        bodyText: '{"data":{}}',
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(observed.requestCount, 2);
  assert.equal(observed.fact?.factKind, 'graphql_auth_delta');
  assert.equal(seen.length, 2);
  for (const request of seen) {
    assert.equal(request.includes('mutation'), false);
    assert.equal(new URL(request.slice(4).split(' ')[0] ?? '').searchParams.get('query'), '{ orders }');
  }

  console.log('[milestone_r8_graphql_query_field_smoke] ALL PASSED');
}

main().catch((err: unknown) => {
  console.error('[milestone_r8_graphql_query_field_smoke] FAILED', err);
  process.exit(1);
});
