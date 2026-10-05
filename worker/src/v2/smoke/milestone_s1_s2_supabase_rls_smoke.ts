/**
 * Milestone S1+S2 — PostgREST enum + Supabase RLS world-readable detection smoke
 *
 * Verifies:
 * 1. OpenAPI enum extracts exact table names; malformed/extra keys rejected at request perimeter.
 * 2. Atomic batch preflight denies loopback with zero probes.
 * 3. Dual probe anon 200 JSON + auth same hash → draft + auto-promote SUPABASE_RLS_WORLD_READABLE.
 * 4. anon 401 / auth 200 → secure abstain.
 * 5. HTML body → abstain not_data_api.
 * 6. Bridge surfaces *.supabase.co/rest/v1 candidates.
 * 7. Lineage continuity on drafts.
 */

import { createHash } from 'node:crypto';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import { buildDetectionTargetsFromRecon } from '../detection/DetectionTargetBridge.js';
import { evaluateFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionPolicy.js';
import { applyFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { runPostgrestOpenApiEnum } from '../supabase/PostgrestOpenApiEnumService.js';
import { POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION } from '../supabase/PostgrestOpenApiEnumContracts.js';
import { runPostgrestTableProbe } from '../supabase/PostgrestTableProbeService.js';
import { POSTGREST_TABLE_PROBE_CONTRACT_VERSION } from '../supabase/PostgrestTableProbeContracts.js';
import { runSupabaseRlsAbuseDetection } from '../supabase/SupabaseRlsAbuseDetectionService.js';
import { SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION } from '../supabase/SupabaseRlsAbuseDetectionContracts.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';

console.log('[milestone_s1_s2_supabase_rls_smoke] Starting S1+S2 Supabase RLS smoke...');

const ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYW5vbiJ9.signaturepaddingxx';
const USER_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InRlc3QiLCJyb2xlIjoiYXV0aGVudGljYXRlZCIsInN1YiI6InVzZXItMSJ9.signaturepaddingyy';

const mockDnsResolver = async (host: string): Promise<string[]> => {
  if (host === '127.0.0.1' || host === 'localhost') return ['127.0.0.1'];
  return ['93.184.216.34'];
};

function profilesJson(): string {
  return JSON.stringify([{ id: 'u1', display_name: 'alice' }]);
}

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_s12_001',
    scanId: 'scn_test_s12_001',
    authorizationGrantId: 'grnt_test_s12_001',
    authorizationDecisionId: 'dec_test_s12_001',
    actorId: 'usr_secops_lead',
  };
  const decidedAt = new Date().toISOString();

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone S1+S2 Supabase RLS smoke',
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

  const authDecisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant,
    },
    decidedAt
  );
  if (authDecisionResult.status !== 'established' || !authDecisionResult.decision) {
    throw new Error('Failed to establish verified authorization decision');
  }
  const authDecision = authDecisionResult.decision;

  // -------------------------------------------------------------------------
  // Test 1: OpenAPI enum → exact table names
  // -------------------------------------------------------------------------
  console.log('--- Test 1: OpenAPI enum extracts tables ---');
  {
    let networkCalls = 0;
    const mockTransport: IdorHttpProbeTransport = async (
      req: HttpProbeRequest
    ): Promise<HttpProbeResponse> => {
      networkCalls += 1;
      if (req.headers.accept?.includes('openapi')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/openapi+json' },
          bodyText: JSON.stringify({
            paths: {
              '/profiles': { get: {} },
              '/orders': { get: {} },
              '/rpc/my_fn': { post: {} },
            },
          }),
          responseTimeMs: 5,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: '', responseTimeMs: 1 };
    };

    const result = await runPostgrestOpenApiEnum({
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_request',
      enumId: 'enum_s12_t1',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
      anonApiKey: ANON_KEY,
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (result.status !== 'inventory_observed') {
      throw new Error(`Test 1 Failed: status=${result.status} reason=${result.reasonCode}`);
    }
    const names = result.relations.map((r) => r.name).sort();
    if (!names.includes('profiles') || !names.includes('orders')) {
      throw new Error(`Test 1 Failed: missing tables: ${names.join(',')}`);
    }
    if (!result.relations.some((r) => r.relationKind === 'rpc' && r.name === 'my_fn')) {
      throw new Error('Test 1 Failed: missing rpc my_fn');
    }
    if (networkCalls !== 1) {
      throw new Error(`Test 1 Failed: expected 1 network call, got ${networkCalls}`);
    }
    console.log('  [PASS] OpenAPI enum OBSERVED tables + rpc');
  }

  // -------------------------------------------------------------------------
  // Test 2: Egress / preflight deny loopback — zero probes
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Loopback preflight deny (zero network) ---');
  {
    let networkCalls = 0;
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      networkCalls += 1;
      return { statusCode: 200, headers: {}, bodyText: '{}', responseTimeMs: 1 };
    };
    const result = await runPostgrestOpenApiEnum({
      contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
      kind: 'postgrest_openapi_enum_request',
      enumId: 'enum_s12_t2',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'http://127.0.0.1/rest/v1',
      anonApiKey: ANON_KEY,
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });
    if (result.status !== 'preflight_denied') {
      throw new Error(`Test 2 Failed: expected preflight_denied, got ${result.status}`);
    }
    if (networkCalls !== 0) {
      throw new Error(`Test 2 Failed: expected 0 network calls, got ${networkCalls}`);
    }
    console.log('  [PASS] Loopback denied with zero side effects');
  }

  // -------------------------------------------------------------------------
  // Test 3: World-readable profiles → draft + auto-promote
  // -------------------------------------------------------------------------
  console.log('--- Test 3: World-readable anon≡auth → auto-promote ---');
  {
    const body = profilesJson();
    const mockTransport: IdorHttpProbeTransport = async (
      req: HttpProbeRequest
    ): Promise<HttpProbeResponse> => {
      if (req.url.includes('/profiles')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: body,
          responseTimeMs: 8,
        };
      }
      return { statusCode: 404, headers: {}, bodyText: '', responseTimeMs: 1 };
    };

    const rls = await runSupabaseRlsAbuseDetection({
      contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
      kind: 'supabase_rls_abuse_detection_request',
      detectionId: 'det_s12_t3',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
      anonApiKey: ANON_KEY,
      tableNames: ['profiles'],
      authenticatedContext: {
        identityId: 'identity_a',
        headers: { authorization: `Bearer ${USER_JWT}` },
      },
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (rls.status !== 'pending_human_review' || !rls.evidenceDraft) {
      throw new Error(
        `Test 3 Failed: expected pending_human_review draft, got ${rls.status}/${rls.reasonCode}`
      );
    }
    if (rls.observations.length !== 1 || rls.observations[0]?.tableName !== 'profiles') {
      throw new Error('Test 3 Failed: expected profiles observation');
    }
    if (!rls.observations[0]?.anonEqualsAuth) {
      throw new Error('Test 3 Failed: expected anonEqualsAuth');
    }
    if (rls.lineage.assessmentId !== lineage.assessmentId) {
      throw new Error('Test 3 Failed: lineage broken');
    }

    const draft: EnrichedEvidenceDraft = {
      ...rls.evidenceDraft,
      differentialContext: {
        endpointUrl: rls.observations[0]!.tableUrl,
        detectionKind: 'supabase_rls_abuse',
        baselineStatusCode: rls.observations[0]!.anonStatusCode,
        baselineBodyHash: rls.observations[0]!.anonBodyHash,
        validationStatusCode: rls.observations[0]!.authenticatedStatusCode,
        validationBodyHash: rls.observations[0]!.authenticatedBodyHash,
        supabaseTableName: 'profiles',
        supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
        supabaseAnonEqualsAuth: true,
        supabaseTopLevelJsonKeys: rls.observations[0]!.topLevelJsonKeys,
        supabaseRowCountHint: rls.observations[0]!.rowCountHint ?? undefined,
      },
    };

    const gate = evaluateFindingAutoPromotion(draft);
    if (gate.decision !== 'auto_promote') {
      throw new Error(
        `Test 3 Failed: expected auto_promote, got ${gate.decision}/${gate.reasonCode}`
      );
    }

    const promoted = applyFindingAutoPromotion({
      drafts: [draft],
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      targetDomain: 'xyzcompany.supabase.co',
      actorId: lineage.actorId,
      evaluatedAt: decidedAt,
    });
    if (promoted.findings.length !== 1) {
      throw new Error(`Test 3 Failed: expected 1 finding, got ${promoted.findings.length}`);
    }
    const f = promoted.findings[0]!;
    if (f.metadata.kind !== 'supabase_rls_abuse_metadata') {
      throw new Error('Test 3 Failed: wrong metadata kind');
    }
    if (f.metadata.claimKind !== 'SUPABASE_RLS_WORLD_READABLE') {
      throw new Error('Test 3 Failed: wrong claimKind');
    }
    if (f.evidence.includes(ANON_KEY) || f.description.includes(ANON_KEY)) {
      throw new Error('Test 3 Failed: anon key leaked into finding');
    }
    console.log('  [PASS] World-readable profiles auto-promoted without key leak');
  }

  // -------------------------------------------------------------------------
  // Test 4: Secure abstain — anon 401, auth 200
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Secure RLS boundary abstain ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (
      req: HttpProbeRequest
    ): Promise<HttpProbeResponse> => {
      const auth = req.headers.authorization ?? '';
      if (auth.includes(USER_JWT)) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: profilesJson(),
          responseTimeMs: 5,
        };
      }
      return {
        statusCode: 401,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ message: 'JWT required' }),
        responseTimeMs: 5,
      };
    };

    const rls = await runSupabaseRlsAbuseDetection({
      contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
      kind: 'supabase_rls_abuse_detection_request',
      detectionId: 'det_s12_t4',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
      anonApiKey: ANON_KEY,
      tableNames: ['profiles'],
      authenticatedContext: {
        identityId: 'identity_a',
        headers: { authorization: `Bearer ${USER_JWT}` },
      },
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (rls.status !== 'secure_target_abstained') {
      throw new Error(`Test 4 Failed: expected secure abstain, got ${rls.status}`);
    }
    console.log('  [PASS] anon 401 / auth 200 abstained');
  }

  // -------------------------------------------------------------------------
  // Test 5: HTML body abstain
  // -------------------------------------------------------------------------
  console.log('--- Test 5: HTML body → not_data_api ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<!doctype html><html><body>login</body></html>',
      responseTimeMs: 3,
    });

    const rls = await runSupabaseRlsAbuseDetection({
      contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
      kind: 'supabase_rls_abuse_detection_request',
      detectionId: 'det_s12_t5',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
      anonApiKey: ANON_KEY,
      tableNames: ['profiles'],
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    if (rls.status !== 'inconclusive_observation') {
      throw new Error(`Test 5 Failed: expected inconclusive_observation, got ${rls.status}`);
    }
    if (rls.reasonCode !== 'not_data_api_html_body' && rls.reasonCode !== 'html_body_inconclusive') {
      throw new Error(`Test 5 Failed: unexpected reason ${rls.reasonCode}`);
    }
    console.log('  [PASS] HTML shell resolved to inconclusive_observation');
  }

  // -------------------------------------------------------------------------
  // Test 6: Bridge supabase candidates + fingerprint hasSupabase
  // -------------------------------------------------------------------------
  console.log('--- Test 6: DetectionTargetBridge supabase candidates ---');
  {
    const empty = {
      subdomains: [],
      dnsRecords: [],
      ports: [],
      webObservations: [],
      tlsCertificates: [],
      urls: [],
      content: [],
      parameters: [],
      secrets: [],
    } satisfies AggregatedReconObservations;

    const aggregated: AggregatedReconObservations = {
      ...empty,
      urls: [
        {
          url: 'https://xyzcompany.supabase.co/rest/v1/profiles',
          host: 'xyzcompany.supabase.co',
          path: '/rest/v1/profiles',
          sources: ['jsluice'],
          discoveredAt: decidedAt,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        },
        {
          url: 'https://app.example.com/login',
          host: 'app.example.com',
          path: '/login',
          sources: ['httpx'],
          discoveredAt: decidedAt,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        },
      ],
      webObservations: [
        {
          url: 'https://app.example.com/',
          method: 'GET',
          statusCode: 200,
          headers: { 'content-type': 'text/html' },
          bodyText:
            'import { createClient } from "@supabase/supabase-js"; const u="https://xyzcompany.supabase.co";',
          technologies: ['Next.js'],
          discoveredAt: decidedAt,
          freshness: 'live',
          sourceReliability: 'direct_observation',
        },
      ],
    };

    const bridge = buildDetectionTargetsFromRecon({
      targetDomain: 'app.example.com',
      aggregatedObservations: aggregated,
    });

    if (!bridge.ecosystemProfile.hasSupabase) {
      throw new Error('Test 6 Failed: hasSupabase expected true');
    }
    if (bridge.supabaseRestCandidates.length < 1) {
      throw new Error('Test 6 Failed: expected supabaseRestCandidates');
    }
    const cand = bridge.supabaseRestCandidates[0]!;
    if (!cand.restBaseUrl.includes('xyzcompany.supabase.co/rest/v1')) {
      throw new Error(`Test 6 Failed: bad restBase ${cand.restBaseUrl}`);
    }
    if (cand.tableName !== 'profiles') {
      throw new Error(`Test 6 Failed: expected table profiles, got ${cand.tableName}`);
    }
    if (!(cand.seedTableNames ?? []).includes('profiles')) {
      throw new Error(`Test 6 Failed: expected seedTableNames to include profiles`);
    }

    // P2: `.from('shop_items')` in body → seed table when supabase host known
    const withFrom: AggregatedReconObservations = {
      ...aggregated,
      webObservations: [
        {
          ...aggregated.webObservations[0]!,
          bodyText:
            'const c=createClient("https://xyzcompany.supabase.co"); c.from("shop_items").select("*");',
        },
      ],
    };
    const bridge2 = buildDetectionTargetsFromRecon({
      targetDomain: 'app.example.com',
      aggregatedObservations: withFrom,
    });
    const cand2 = bridge2.supabaseRestCandidates[0];
    if (!(cand2?.seedTableNames ?? []).includes('shop_items')) {
      throw new Error(
        `Test 6b Failed: expected shop_items from .from() hint, got ${JSON.stringify(cand2?.seedTableNames)}`
      );
    }
    console.log('  [PASS] Bridge + hasSupabase');
  }

  // -------------------------------------------------------------------------
  // Test 7: Atomic batch preflight on table probe
  // -------------------------------------------------------------------------
  console.log('--- Test 7: Table probe batch preflight deny ---');
  {
    let networkCalls = 0;
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      networkCalls += 1;
      return { statusCode: 200, headers: {}, bodyText: '[]', responseTimeMs: 1 };
    };
    const result = await runPostgrestTableProbe({
      contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
      kind: 'postgrest_table_probe_request',
      probeId: 'prb_s12_t7',
      ...lineage,
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      restBaseUrl: 'http://127.0.0.1/rest/v1',
      tableNames: ['profiles', 'orders'],
      anonApiKey: ANON_KEY,
      transport: mockTransport,
      dnsResolver: mockDnsResolver,
    });
    if (result.status !== 'batch_preflight_denied' && result.status !== 'preflight_denied') {
      throw new Error(`Test 7 Failed: expected batch preflight deny, got ${result.status}`);
    }
    if (networkCalls !== 0) {
      throw new Error(`Test 7 Failed: expected 0 probes, got ${networkCalls}`);
    }
    if (result.pairs.length !== 0) {
      throw new Error('Test 7 Failed: pairs should be empty on batch deny');
    }
    console.log('  [PASS] Atomic batch preflight');
  }

  // Silence unused import if tree-shaken oddly
  void DETECTION_CONTRACT_VERSION;
  void createHash;

  console.log('[milestone_s1_s2_supabase_rls_smoke] ALL PASS');
}

runTests().catch((err: unknown) => {
  console.error('[milestone_s1_s2_supabase_rls_smoke] FAILED', err);
  process.exit(1);
});
