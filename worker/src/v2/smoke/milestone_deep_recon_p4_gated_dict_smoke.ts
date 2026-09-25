/**
 * Deep recon P4 — gated dict top-K + optional hop-3 + orchestrator wire (hermetic).
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import type {
  ContentDiscoveryRequest,
  ContentDiscoveryResult,
  ContentDiscoveryTool,
} from '../recon/adapters/ContentDiscoveryContracts.js';
import { CONTENT_DISCOVERY_CONTRACT_VERSION, CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import type {
  ParameterDiscoveryRequest,
  ParameterDiscoveryResult,
  ParameterDiscoveryTool,
} from '../recon/adapters/ParameterDiscoveryContracts.js';
import {
  PARAMETER_DISCOVERY_CONTRACT_VERSION,
  PARAMETER_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/ParameterDiscoveryContracts.js';
import {
  selectTopKInventoryUrls,
  runGatedDictTopK,
} from '../recon/deep/GatedDictTopKService.js';
import { runHtmlHopExtra } from '../recon/deep/HtmlHopExtraService.js';
import { planDeepReconMethods } from '../recon/deep/DeepReconMethodPlanner.js';
import { runDeepReconOrchestrator } from '../recon/deep/DeepReconOrchestratorService.js';
import { HTML_ROUTE_EXTRACTION_MAX_HOP3 } from '../recon/analysis/HtmlRouteExtractionService.js';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_gated_p4_001',
    scanId: 'scan_gated_p4_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for gated dict P4 smoke',
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

function mockContentTool(): ContentDiscoveryTool & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async discoverContent(req: ContentDiscoveryRequest): Promise<ContentDiscoveryResult> {
      calls.push(req.targetUrl);
      const now = '2026-09-24T12:10:00.000Z';
      return {
        status: 'success',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: req.targetUrl,
        wordlistPath: req.wordlistPath,
        observations: Object.freeze([
          {
            url: `${req.targetUrl.replace(/\/$/, '')}/health`,
            path: '/health',
            statusCode: 200,
            discoveredAt: now,
          },
        ]),
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      };
    },
  };
}

function mockParamTool(): ParameterDiscoveryTool & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async discoverParameters(req: ParameterDiscoveryRequest): Promise<ParameterDiscoveryResult> {
      calls.push(req.targetUrl);
      const now = '2026-09-24T12:10:00.000Z';
      return {
        status: 'success',
        contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
        targetUrl: req.targetUrl,
        observations: Object.freeze([
          {
            url: req.targetUrl,
            method: 'GET',
            parameterName: 'id',
            discoveredAt: now,
          },
        ]),
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      };
    },
  };
}

async function main(): Promise<void> {
  console.log('=== Deep recon P4 gated dict top-K smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_gated_p4_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_gated_p4_001',
    actorId: 'act_gated_p4_op',
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
  assert.ok(auth.decision);

  // 1. Top-K ranking prefers API paths, drops static
  const ranked = selectTopKInventoryUrls({
    inventoryUrls: [
      { url: 'https://app.example.com/_next/static/chunks/main.js' },
      { url: 'https://app.example.com/' },
      { url: 'https://app.example.com/api/v1/items' },
      { url: 'https://app.example.com/rest/v1/profiles' },
      { url: 'https://app.example.com/logo.png' },
    ],
    maxTargets: 2,
  });
  assert.equal(ranked.length, 2);
  assert.ok(ranked[0]!.includes('/rest/v1/') || ranked[0]!.includes('/api/'));
  assert.ok(!ranked.some((u) => u.includes('_next/static') || u.endsWith('.png')));
  console.log('[+] selectTopKInventoryUrls ranks API over static');

  // 2. Planner includes gated_dict when enabled
  const planned = planDeepReconMethods({
    stack: { hasNextJs: true },
    budget: { maxRequests: 80, remainingRequests: 80 },
    enableGatedDicts: true,
  });
  assert.ok(planned.some((p) => p.method === 'gated_dict_topk'));
  console.log('[+] planner includes gated_dict_topk when enabled');

  // 3. Happy path hermetic tools
  const contentTool = mockContentTool();
  const parameterTool = mockParamTool();
  const gated = await runGatedDictTopK({
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    inventoryUrls: [
      { url: 'https://app.example.com/api/v1/items' },
      { url: 'https://app.example.com/' },
      { url: 'https://app.example.com/_next/static/x.js' },
    ],
    contentTool,
    parameterTool,
    wordlistPath: 'wordlists/modern/api-discovery-gated.txt',
    maxFfufRoots: 1,
    maxArjunTargets: 1,
    skipWafCanary: true,
  });
  assert.equal(gated.status, 'success');
  assert.equal(contentTool.calls.length, 1);
  assert.ok(contentTool.calls[0]!.includes('/api/'));
  assert.ok(gated.urlObservations.some((u) => u.url.includes('/health')));
  assert.ok(gated.parameterObservations.some((p) => p.parameterName === 'id'));
  console.log('[+] gated dict runs only on top-K (hermetic tools)');

  // 4. WAF-aware abort
  const wafTransport = async (_req: HttpProbeRequest): Promise<HttpProbeResponse> => ({
    statusCode: 403,
    headers: { server: 'cloudflare', 'cf-ray': 'abc' },
    bodyText: 'Attention Required! Cloudflare',
    responseTimeMs: 50,
  });
  const aborted = await runGatedDictTopK({
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    inventoryUrls: [{ url: 'https://app.example.com/api/v1/items' }],
    contentTool: mockContentTool(),
    parameterTool: mockParamTool(),
    wordlistPath: 'wordlists/modern/api-discovery-gated.txt',
    transport: wafTransport,
    skipWafCanary: false,
  });
  assert.equal(aborted.status, 'waf_aborted');
  assert.equal(aborted.reasonCode, 'blocking_defense_on_canary');
  console.log('[+] WAF canary aborts gated dict spray');

  // 5. Tools missing → honest skip
  const missing = await runGatedDictTopK({
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    inventoryUrls: [{ url: 'https://app.example.com/api' }],
  });
  assert.equal(missing.status, 'tools_missing');
  console.log('[+] missing tools → tools_missing');

  // 6. Optional hop-3 from app_endpoint body
  assert.ok(HTML_ROUTE_EXTRACTION_MAX_HOP3 >= 15);
  const hop = runHtmlHopExtra({
    targetDomain: 'app.example.com',
    authorizedScopeGrant: scopeGrant,
    appEndpointBodies: [
      {
        url: 'https://app.example.com/dashboard',
        bodyText:
          '<html><a href="/api/wallets">w</a><a href="/_next/static/chunk.js">s</a></html>',
      },
    ],
    maxResults: 5,
  });
  assert.equal(hop.reasonCode, 'hop3_seeded');
  assert.ok(hop.urlObservations.some((u) => u.path.includes('/api/wallets')));
  assert.ok(!hop.urlObservations.some((u) => u.path.includes('/_next/static')));
  console.log('[+] html_hop_extra seeds app_endpoint only');

  // 7. Orchestrator wires gated_dict_topk when enabled
  const orch = await runDeepReconOrchestrator({
    originUrl: 'https://app.example.com/',
    verifiedAuthorizationDecision: auth.decision!,
    authorizedScopeGrant: scopeGrant,
    lineage,
    stack: { hasNextJs: true },
    budget: { maxRequests: 80, remainingRequests: 80 },
    enableGatedDicts: true,
    inventoryUrls: [
      { url: 'https://app.example.com/api/v1/items' },
      { url: 'https://app.example.com/' },
    ],
    contentTool,
    parameterTool,
    wordlistPath: 'wordlists/modern/api-discovery-gated.txt',
    maxFfufRoots: 1,
    maxArjunTargets: 1,
    hopExtraBodies: [
      {
        url: 'https://app.example.com/perfil',
        bodyText: '<a href="/api/runs">r</a>',
      },
    ],
    maxHop3: 5,
  });
  const gatedResult = orch.methodResults.find((m) => m.method === 'gated_dict_topk');
  assert.ok(gatedResult);
  assert.equal(gatedResult!.status, 'ran');
  const hopResult = orch.methodResults.find((m) => m.method === 'html_hop_extra');
  assert.ok(hopResult);
  assert.equal(hopResult!.status, 'ran');
  console.log('[+] DeepReconOrchestrator runs gated_dict_topk + html_hop_extra');

  console.log('=== Deep recon P4 gated dict smoke: ALL PASSED ===');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
