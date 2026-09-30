/**
 * F1.1 js_surface_mining + F1.2 sourcemap_surface smoke (hermetic).
 * Seeds URLs and parameter names. Does not create findings or leak secrets.
 * URLs already mined are not fetched again.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  JSLUICE_DISCOVERY_CONTRACT_VERSION,
  JSLUICE_DISCOVERY_NON_CLAIMS,
  type JsLuiceDiscoveryTool,
} from '../recon/adapters/JsLuiceDiscoveryContracts.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';

const SECRET = 'super-secret-token-SHOULD-NOT-LEAK';
const JS_URL = 'https://app.example.com/_next/static/chunks/app/page-orders.js';
const MAP_PATH = '/api/invoices';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_f1_surface_001',
    scanId: 'scan_f1_surface_001',
    issuedAt: '2026-09-28T12:00:00.000Z',
    expiresAt: '2026-09-29T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for js and sourcemap surface smoke',
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

async function main(): Promise<void> {
  console.log('=== F1.1 js_surface_mining + F1.2 sourcemap_surface smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_f1_surface_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f1_surface_001',
    actorId: 'act_f1_surface_op',
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

  const mined: string[] = [];
  const mapFetches: string[] = [];
  const tool: JsLuiceDiscoveryTool = {
    async discoverFromJavaScript(request) {
      mined.push(request.targetJsUrlOrPath);
      return {
        status: 'success',
        contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
        targetJsUrlOrPath: request.targetJsUrlOrPath,
        urlObservations: [
          {
            url: 'https://app.example.com/api/orders',
            host: 'app.example.com',
            path: '/api/orders',
            sources: ['js_surface_mining'],
            discoveredAt: now,
            freshness: 'live',
            sourceReliability: 'direct_observation',
          },
        ],
        parameterObservations: [
          {
            sourceUrl: request.targetJsUrlOrPath,
            parameterName: 'order_id',
            location: 'query',
            discoveredAt: now,
          },
        ],
        secretObservations: [
          {
            locationUrl: request.targetJsUrlOrPath,
            detectorName: 'fixture',
            redactedSecret: SECRET,
            discoveredAt: now,
          },
        ],
        explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: 1,
      };
    },
  };

  const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    if (req.url === `${JS_URL}.map`) {
      mapFetches.push(req.url);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({
          version: 3,
          sources: ['webpack://app/pages/api/invoices.ts'],
          sourcesContent: [`fetch('${MAP_PATH}')`],
          mappings: 'AAAA',
        }),
        responseTimeMs: 4,
      };
    }
    return {
      statusCode: 404,
      headers: {},
      bodyText: '',
      responseTimeMs: 1,
    };
  };

  const orch = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true, hasSpa: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
    inventoryUrls: [{ url: JS_URL }],
    jsLuiceTool: tool,
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  const js = orch.methodResults.find((method) => method.method === 'js_surface_mining');
  assert.equal(js?.status, 'ran');
  assert.equal(js?.reasonCode, 'js_surface_seeded');
  assert.deepEqual(mined, [JS_URL]);
  assert.ok(orch.urlObservations.some((obs) => obs.path === '/api/orders'));
  assert.ok(orch.parameterSeeds.some((seed) => seed.parameterName === 'order_id' && seed.source === 'js_surface_mining'));
  assert.equal(JSON.stringify(orch).includes(SECRET), false);
  assert.equal('findings' in orch, false);
  assert.equal(orch.nonClaims.createsRealFindings, false);
  console.log('[+] F1.1 js_surface_mining ran, seeded urls/params, dropped secrets');

  const again = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true, hasSpa: true },
    budget: { maxRequests: 50, remainingRequests: 50 },
    inventoryUrls: [{ url: JS_URL }],
    jsLuiceTool: tool,
    jsSurfaceExcludeUrls: [JS_URL],
    sourcemapExcludeUrls: [JS_URL],
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  const jsSkipped = again.methodResults.find((method) => method.method === 'js_surface_mining');
  assert.equal(jsSkipped?.status, 'skipped');
  assert.equal(jsSkipped?.reasonCode, 'jsluice_already_mined_in_stage_4');
  assert.equal(jsSkipped?.requestsUsed, 0);
  assert.equal(mined.length, 1);
  const mapSkipped = again.methodResults.find((method) => method.method === 'sourcemap_surface');
  assert.equal(mapSkipped?.status, 'skipped');
  assert.equal(mapSkipped?.reasonCode, 'sourcemap_already_probed_in_stage_4');
  assert.equal(mapFetches.length, 1);
  console.log('[+] stage-4 exclusions are not mined or unpacked again');

  const map = orch.methodResults.find((method) => method.method === 'sourcemap_surface');
  assert.equal(map?.status, 'ran');
  assert.equal(map?.reasonCode, 'sourcemap_paths_seeded');
  assert.equal(mapFetches.length, 1);
  assert.ok(orch.urlObservations.some((obs) => obs.path === MAP_PATH || obs.url.includes(MAP_PATH)));
  assert.equal(orch.nonClaims.createsRealFindings, false);
  console.log('[+] F1.2 sourcemap_surface seeded observed paths and created no finding');

  console.log('=== F1.1 + F1.2 surface smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
