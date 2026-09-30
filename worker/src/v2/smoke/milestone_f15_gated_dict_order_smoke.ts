/**
 * F1.5 — gated_dict_topk stays last and off until inventory methods exist.
 * WAF canary aborts the spray.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeResponse } from '../detection/DetectionContracts.js';
import type { ContentDiscoveryTool } from '../recon/adapters/ContentDiscoveryContracts.js';
import type { ParameterDiscoveryTool } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { planDeepReconMethods } from '../recon/deep/DeepReconMethodPlanner.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f15_gated_001',
    scanId: 'scan_f15_gated_001',
    issuedAt: '2026-09-28T12:00:00.000Z',
    expiresAt: '2026-09-29T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for gated dict ordering smoke',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
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

function quietTransport(): (req: { url: string }) => Promise<HttpProbeResponse> {
  return async () => ({
    statusCode: 200,
    headers: { 'content-type': 'text/plain' },
    bodyText: 'ok',
    responseTimeMs: 1,
  });
}

async function main(): Promise<void> {
  console.log('=== F1.5 gated dict ordering smoke ===');
  const budget = { maxRequests: 80, remainingRequests: 80 };

  const bare = planDeepReconMethods({
    stack: {},
    budget,
    enableGatedDicts: true,
  });
  assert.equal(
    bare.some((entry) => entry.method === 'gated_dict_topk'),
    false
  );
  console.log('[+] gated_dict stays off without F1.1–F1.4 inventory methods');

  const planned = planDeepReconMethods({
    stack: { hasNextJs: true },
    budget,
    enableGatedDicts: true,
  });
  assert.equal(planned[planned.length - 1]?.method, 'gated_dict_topk');
  const plannedNames = planned.map((entry) => entry.method);
  for (const method of ['js_surface_mining', 'sourcemap_surface', 'api_schema_discovery'] as const) {
    assert.ok(plannedNames.indexOf(method) >= 0);
    assert.ok(plannedNames.indexOf(method) < plannedNames.indexOf('gated_dict_topk'));
  }
  console.log('[+] gated_dict is planned last, after inventory methods');

  const scopeGrant = createScopeGrant();
  const lineage = {
    assessmentId: 'asmt_f15_gated_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f15_gated_001',
    actorId: 'act_f15_gated_op',
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

  let sprayCalls = 0;
  const contentTool: ContentDiscoveryTool = {
    async discoverContent() {
      sprayCalls++;
      throw new Error('content spray must not run on WAF canary');
    },
  };
  const parameterTool: ParameterDiscoveryTool = {
    async discoverParameters() {
      sprayCalls++;
      throw new Error('parameter spray must not run on WAF canary');
    },
  };

  const waf = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true },
    budget,
    enableGatedDicts: true,
    inventoryUrls: [{ url: 'https://app.example.com/api/v1/items' }],
    contentTool,
    parameterTool,
    wordlistPath: 'wordlists/modern/api-discovery-gated.txt',
    transport: async (): Promise<HttpProbeResponse> => ({
      statusCode: 403,
      headers: { 'cf-ray': 'abc', 'content-type': 'text/html' },
      bodyText: 'Just a moment cf-browser-verification',
      responseTimeMs: 2,
    }),
    dnsResolver: async () => ['93.184.216.34'],
  });
  const names = waf.methodResults.map((result) => result.method);
  const gatedAt = names.indexOf('gated_dict_topk');
  assert.ok(gatedAt >= 0);
  assert.equal(gatedAt, names.length - 1);
  for (const method of ['js_surface_mining', 'sourcemap_surface', 'api_schema_discovery'] as const) {
    assert.ok(names.indexOf(method) >= 0 && names.indexOf(method) < gatedAt);
  }
  const gated = waf.methodResults[gatedAt];
  assert.equal(gated?.status, 'skipped');
  assert.equal(gated?.reasonCode, 'blocking_defense_on_canary');
  assert.equal(sprayCalls, 0);
  console.log('[+] WAF canary aborts spray and gated_dict runs after inventory methods');

  const unused = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: {},
    budget,
    enableGatedDicts: true,
    transport: quietTransport(),
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(
    unused.methodResults.some((result) => result.method === 'gated_dict_topk'),
    false
  );
  console.log('[+] orchestrator does not run gated_dict before inventory methods exist');

  console.log('=== F1.5 gated dict ordering smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
