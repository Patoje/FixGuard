/**
 * Plan A Fase 6 lite — Supabase Storage public-object probe smoke (hermetic).
 * No live signed-URL minting. Fail-closed without paths / mutation-free.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';
import {
  extractSupabaseStoragePathHintsFromText,
  preferSupabaseRlsTableOrder,
  SUPABASE_PREFERRED_RLS_SEED_TABLES,
} from '../supabase/SupabaseSurfaceContracts.js';
import {
  runSupabaseStorageSignedUrlProbe,
} from '../supabase/SupabaseStorageSignedUrlProbeService.js';
import { SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION } from '../supabase/SupabaseStorageSignedUrlProbeContracts.js';

const ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiJ9.signaturepaddingxx';

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_s6_storage_001',
    scanId: 'scan_s6_storage_001',
    issuedAt: '2026-09-24T12:00:00.000Z',
    expiresAt: '2026-09-25T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'app.example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for storage probe smoke',
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
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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
  console.log('=== Storage / signed-URL probe (Fase 6 lite) smoke ===');

  const ordered = preferSupabaseRlsTableOrder(['runs', 'other', 'profiles', 'wallets']);
  assert.deepEqual([...ordered.slice(0, 3)], ['profiles', 'wallets', 'runs']);
  assert.ok(SUPABASE_PREFERRED_RLS_SEED_TABLES.includes('wallets'));
  console.log('[+] preferred RLS seed order includes wallets/runs');

  const hints = extractSupabaseStoragePathHintsFromText(
    `const u="https://xyzcompany.supabase.co/storage/v1/object/public/avatars/u1.png";` +
      `storage.from("docs").getPublicUrl("a.pdf");`
  );
  assert.ok(hints.some((h) => h.includes('avatars/')));
  assert.ok(hints.some((h) => h.includes('docs/')));
  console.log('[+] storage path hints from JS text');

  const scopeGrant = createScopeGrant();
  const lineage = {
    assessmentId: 'asm_s6_storage_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_s6_storage_001',
    actorId: 'usr_secops_lead',
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

  let networkCalls = 0;
  const openTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    networkCalls += 1;
    if (req.url.includes('/object/public/avatars/')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'image/png' },
        bodyText: 'PNGDATA',
        responseTimeMs: 5,
      };
    }
    if (req.url.endsWith('/bucket')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: '[{"name":"avatars"}]',
        responseTimeMs: 3,
      };
    }
    return { statusCode: 404, headers: {}, bodyText: 'not found', responseTimeMs: 1 };
  };

  const open = await runSupabaseStorageSignedUrlProbe({
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_request',
    detectionId: 'det_s6_open',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    storageBaseUrl: 'https://xyzcompany.supabase.co/storage/v1',
    anonApiKey: ANON_KEY,
    objectPaths: ['avatars/u1.png'],
    probeBucketList: true,
    transport: openTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(open.status, 'public_object_observed');
  assert.ok(open.observations.some((o) => o.publicReadable));
  assert.ok(networkCalls >= 1);
  console.log('[+] public object observed');

  networkCalls = 0;
  const closedTransport = async (): Promise<HttpProbeResponse> => {
    networkCalls += 1;
    return { statusCode: 400, headers: {}, bodyText: 'jwt expired', responseTimeMs: 1 };
  };
  const closed = await runSupabaseStorageSignedUrlProbe({
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_request',
    detectionId: 'det_s6_closed',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    storageBaseUrl: 'https://xyzcompany.supabase.co/storage/v1',
    anonApiKey: ANON_KEY,
    objectPaths: ['private/secret.bin'],
    transport: closedTransport,
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(closed.status, 'secure_target_abstained');
  console.log('[+] closed storage abstains');

  const missing = await runSupabaseStorageSignedUrlProbe({
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_request',
    detectionId: 'det_s6_missing',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    storageBaseUrl: 'https://xyzcompany.supabase.co/storage/v1',
    anonApiKey: ANON_KEY,
    objectPaths: [],
    transport: async () => {
      throw new Error('should not network');
    },
    dnsResolver: async () => ['93.184.216.34'],
  });
  assert.equal(missing.status, 'prerequisite_missing');
  assert.equal(missing.reasonCode, 'storage_paths_not_observed');
  console.log('[+] fail-closed without OBSERVED paths');

  const loopbackDenied = await runSupabaseStorageSignedUrlProbe({
    contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
    kind: 'supabase_storage_signed_url_probe_request',
    detectionId: 'det_s6_loop',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision!,
    scopeGrant,
    storageBaseUrl: 'http://127.0.0.1/storage/v1',
    anonApiKey: ANON_KEY,
    objectPaths: ['avatars/x.png'],
    transport: async () => {
      throw new Error('should not network');
    },
    dnsResolver: async () => ['127.0.0.1'],
  });
  assert.equal(loopbackDenied.status, 'preflight_denied');
  console.log('[+] loopback preflight denied');

  console.log('=== Storage probe smoke PASSED ===');
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
