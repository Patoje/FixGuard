/**
 * Deep recon P1 — Sourcemap surface extraction smoke (hermetic).
 * Discovery-only: URL seeds from map JSON; never creates findings/Critical.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  extractUrlSeedsFromSourcemapJson,
  runSourcemapSurfaceExtraction,
  SOURCEMAP_SURFACE_SOURCE,
} from '../recon/analysis/SourcemapSurfaceExtractionService.js';
import { buildSupabaseRestCandidatesFromRecon } from '../detection/DetectionTargetBridge.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_smap_surf_001',
    scanId: 'scan_smap_surf_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for sourcemap surface smoke',
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
      allowedMethods: ['GET'],
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
  console.log('=== Deep recon P1 sourcemap surface smoke ===');
  const scopeGrant = createScopeGrant();
  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asmt_smap_surf_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_smap_surf_001',
    actorId: 'act_smap_surf_op',
  };
  const auth = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-24T12:00:00.000Z',
      scopeGrant,
    },
    '2026-09-24T12:00:00.000Z'
  );
  if (auth.status !== 'established' || !auth.decision) {
    throw new Error('auth failed');
  }

  {
    const mined = extractUrlSeedsFromSourcemapJson({
      mapJson: {
        version: 3,
        sources: [
          'webpack://app/lib/supabase/client.ts',
          'https://xyzcompany.supabase.co/rest/v1/orders',
        ],
        sourcesContent: [
          'const u="https://xyzcompany.supabase.co/rest/v1/profiles"; fetch("/api/me");',
        ],
        mappings: 'AAAA',
      },
      resolvePathsBase: 'https://app.example.com/',
      authorizedScopeGrant: scopeGrant,
      discoveredAt: '2026-09-24T12:00:00.000Z',
    });
    assert.ok(mined.urlObservations.length >= 2, 'expected supabase + /api seeds');
    assert.ok(
      mined.urlObservations.some((u) => u.path.includes('/rest/v1/profiles')),
      'expected profiles table seed'
    );
    assert.ok(
      mined.urlObservations.some((u) => u.path === '/api/me' || u.url.includes('/api/me')),
      'expected /api/me seed'
    );
    assert.ok(mined.urlObservations.every((u) => u.sources.includes(SOURCEMAP_SURFACE_SOURCE)));
    assert.ok(
      !JSON.stringify(mined).toLowerCase().includes('critical'),
      'must not invent Critical'
    );
    console.log('[+] hermetic map JSON → URL seeds OK');
  }

  {
    const mapBody = JSON.stringify({
      version: 3,
      sources: ['webpack://_/lib/db.ts'],
      sourcesContent: [
        'from("https://xyzcompany.supabase.co/rest/v1/carreras")',
      ],
      mappings: 'A',
    });
    const transport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      if (req.url.endsWith('.map')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: mapBody,
          responseTimeMs: 1,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: '', responseTimeMs: 1 };
    };

    const result = await runSourcemapSurfaceExtraction({
      sourceJsUrl: 'https://app.example.com/_next/static/chunks/app/page.js',
      explicitMapUrl: 'https://app.example.com/_next/static/chunks/app/page.js.map',
      verifiedAuthorizationDecision: auth.decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      transport,
      dnsResolver: async () => ['93.184.216.34'],
    });
    assert.equal(
      result.status,
      'success',
      `expected success, got ${result.status} ${'reasonCode' in result ? result.reasonCode : ''} ${'reason' in result ? result.reason : ''}`
    );
    if (result.status !== 'success') throw new Error('expected success');
    assert.ok(result.explicitNonClaims.createsRealFindings === false);
    assert.ok(
      result.urlObservations.some((u) => u.path.includes('/rest/v1/carreras')),
      'expected carreras seed from sourcesContent'
    );

    const empty: AggregatedReconObservations = {
      subdomains: [],
      dnsRecords: [],
      ports: [],
      webObservations: [],
      tlsCertificates: [],
      urls: [...result.urlObservations],
      content: [],
      parameters: [],
      secrets: [],
    };
    const candidates = buildSupabaseRestCandidatesFromRecon(empty);
    assert.ok(candidates.length >= 1);
    assert.ok(
      (candidates[0]?.seedTableNames ?? []).includes('carreras') ||
        candidates[0]?.tableName === 'carreras'
    );
    console.log('[+] gated fetch + bridge seedTableNames OK');
  }

  {
    const denied = await runSourcemapSurfaceExtraction({
      sourceJsUrl: 'https://127.0.0.1/app.js',
      explicitMapUrl: 'https://127.0.0.1/app.js.map',
      verifiedAuthorizationDecision: auth.decision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      dnsResolver: async () => ['127.0.0.1'],
    });
    assert.equal(denied.status, 'preflight_denied');
    console.log('[+] SSRF preflight deny OK');
  }

  console.log('=== Deep recon P1 sourcemap surface smoke: ALL PASSED ===');
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
