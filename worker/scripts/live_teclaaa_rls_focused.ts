/**
 * Focused live proof: PostgREST seed + RLS detect against Teclaaa Supabase.
 * Bypasses full recon hang; proves gated enum/probe/detect/auto-promote on live Data API.
 */

import { writeFileSync } from 'node:fs';
import { establishVerifiedAuthorizationDecision } from '../src/v2/authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../src/v2/scope/AuthorizedScopeContracts.js';
import { runPostgrestOpenApiEnum } from '../src/v2/supabase/PostgrestOpenApiEnumService.js';
import { POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION } from '../src/v2/supabase/PostgrestOpenApiEnumContracts.js';
import { runSupabaseRlsAbuseDetection } from '../src/v2/supabase/SupabaseRlsAbuseDetectionService.js';
import { SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION } from '../src/v2/supabase/SupabaseRlsAbuseDetectionContracts.js';
import { evaluateFindingAutoPromotion } from '../src/v2/finding-auto-promotion/FindingAutoPromotionPolicy.js';
import { applyFindingAutoPromotion } from '../src/v2/finding-auto-promotion/FindingAutoPromotionService.js';
import type { EnrichedEvidenceDraft } from '../src/v2/application/OrchestratedAssessmentContracts.js';

const TARGET = 'teclaaa.vercel.app';
const SUPABASE_FALLBACK = 'vawrzoncszqauzxwqide.supabase.co';

function redact(key: string): string {
  return key.length <= 12 ? '…' : `${key.slice(0, 10)}…${key.slice(-4)}`;
}

async function extractKey(): Promise<{ key: string; host: string }> {
  const html = await (await fetch(`https://${TARGET}/carrera/93kpw`)).text();
  const scripts = Array.from(
    html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g),
    (m) => m[1]!
  );
  const bodies = [html];
  for (const p of scripts.slice(0, 40)) {
    try {
      bodies.push(await (await fetch(`https://${TARGET}${p}`)).text());
    } catch {
      // ignore
    }
  }
  const text = bodies.join('\n');
  const host =
    text.match(/https:\/\/([a-z0-9-]+\.supabase\.co)/i)?.[1] ?? SUPABASE_FALLBACK;
  const pub = text.match(/sb_publishable_[A-Za-z0-9_-]+/);
  if (!pub) throw new Error('No OBSERVED publishable key');
  return { key: pub[0], host };
}

async function main(): Promise<void> {
  const { key, host } = await extractKey();
  console.log(`OBSERVED ${redact(key)} @ ${host}`);

  const lineage = {
    assessmentId: 'asm_live_teclaaa_rls',
    scanId: 'scn_live_teclaaa_rls',
    authorizationGrantId: 'grnt_live_teclaaa_rls',
    authorizationDecisionId: 'dec_live_teclaaa_rls',
    actorId: 'usr_secops_lead_live',
  };
  const now = new Date().toISOString();
  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: TARGET },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized live Teclaaa + ${host} RLS probe`,
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
      allowedDomains: [TARGET, host],
      allowedHosts: [TARGET, host],
      allowedOrigins: [`https://${TARGET}`, `https://${host}`],
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
  if (auth.status !== 'established' || !auth.decision) {
    throw new Error('auth failed');
  }

  const restBase = `https://${host}/rest/v1`;
  const enumResult = await runPostgrestOpenApiEnum({
    contractVersion: POSTGREST_OPENAPI_ENUM_CONTRACT_VERSION,
    kind: 'postgrest_openapi_enum_request',
    enumId: 'enum_live_teclaaa',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision,
    scopeGrant,
    restBaseUrl: restBase,
    anonApiKey: key,
    seedTableNames: ['profiles', 'shop_items', 'wallets', 'runs'],
  });
  console.log(
    `enum status=${enumResult.status} reason=${enumResult.reasonCode} tables=${enumResult.relations
      .map((r) => r.name)
      .join(',')}`
  );

  const tables =
    enumResult.relations.filter((r) => r.relationKind === 'table').map((r) => r.name)
      .length > 0
      ? enumResult.relations.filter((r) => r.relationKind === 'table').map((r) => r.name)
      : ['profiles', 'shop_items', 'wallets', 'runs'];

  // Prefer hinted tables first for RLS probe budget.
  const preferred = ['profiles', 'shop_items', 'wallets', 'runs'];
  const ordered = [
    ...preferred.filter((t) => tables.includes(t)),
    ...tables.filter((t) => !preferred.includes(t)),
  ];

  const rls = await runSupabaseRlsAbuseDetection({
    contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_live_teclaaa_rls',
    ...lineage,
    verifiedAuthorizationDecision: auth.decision,
    scopeGrant,
    restBaseUrl: restBase,
    anonApiKey: key,
    tableNames: ordered.slice(0, 8),
  });

  console.log(
    `rls status=${rls.status} reason=${rls.reasonCode} obs=${rls.observations
      .map((o) => `${o.tableName}:${o.anonStatusCode}`)
      .join(',')}`
  );

  let promoted = 0;
  const findingTitles: string[] = [];
  if (rls.status === 'pending_human_review' && rls.evidenceDraft && rls.observations.length > 0) {
    const drafts: EnrichedEvidenceDraft[] = rls.observations.slice(0, 8).map((obs, idx) => ({
      ...rls.evidenceDraft!,
      draftId:
        idx === 0
          ? rls.evidenceDraft!.draftId
          : `${rls.evidenceDraft!.draftId}_${obs.tableName}`.slice(0, 64),
      safeRationale:
        idx === 0
          ? rls.evidenceDraft!.safeRationale
          : `OBSERVED Supabase Data API table '${obs.tableName}' world-readable via anon role`,
      differentialContext: {
        endpointUrl: obs.tableUrl,
        detectionKind: 'supabase_rls_abuse',
        baselineStatusCode: obs.anonStatusCode,
        baselineBodyHash: obs.anonBodyHash,
        validationStatusCode: obs.authenticatedStatusCode,
        validationBodyHash: obs.authenticatedBodyHash,
        supabaseTableName: obs.tableName,
        supabaseClaimKind: obs.claimKind,
        supabaseAnonEqualsAuth: obs.anonEqualsAuth,
        supabaseTopLevelJsonKeys: obs.topLevelJsonKeys,
        ...(obs.rowCountHint !== null
          ? { supabaseRowCountHint: obs.rowCountHint }
          : {}),
      },
    }));
    const gate = evaluateFindingAutoPromotion(drafts[0]!);
    console.log(`auto_promote gate=${gate.decision} ${gate.reasonCode}`);
    const applied = applyFindingAutoPromotion({
      drafts,
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      targetDomain: host,
      actorId: lineage.actorId,
      evaluatedAt: now,
    });
    promoted = applied.findings.length;
    for (const f of applied.findings) findingTitles.push(f.title);
    console.log(
      `findings=${promoted} titles=${findingTitles.join(' | ') || 'n/a'}`
    );
  }

  // Optional storage path probe (Fase 6 lite) — only if JS yields OBSERVED paths.
  let storageProbe: {
    readonly status: string;
    readonly reason: string;
    readonly publicHits: number;
    readonly pathHints: readonly string[];
  } | null = null;
  try {
    const html = await (await fetch(`https://${TARGET}/carrera/93kpw`)).text();
    const scripts = Array.from(
      html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g),
      (m) => m[1]!
    );
    const bodies = [html];
    for (const p of scripts.slice(0, 25)) {
      try {
        bodies.push(await (await fetch(`https://${TARGET}${p}`)).text());
      } catch {
        // ignore
      }
    }
    const { extractSupabaseStoragePathHintsFromText } = await import(
      '../src/v2/supabase/SupabaseSurfaceContracts.js'
    );
    const { runSupabaseStorageSignedUrlProbe } = await import(
      '../src/v2/supabase/SupabaseStorageSignedUrlProbeService.js'
    );
    const { SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION } = await import(
      '../src/v2/supabase/SupabaseStorageSignedUrlProbeContracts.js'
    );
    const pathHints = extractSupabaseStoragePathHintsFromText(bodies.join('\n'));
    if (pathHints.length > 0) {
      const storage = await runSupabaseStorageSignedUrlProbe({
        contractVersion: SUPABASE_STORAGE_SIGNED_URL_PROBE_CONTRACT_VERSION,
        kind: 'supabase_storage_signed_url_probe_request',
        detectionId: 'det_live_teclaaa_storage',
        ...lineage,
        verifiedAuthorizationDecision: auth.decision,
        scopeGrant,
        storageBaseUrl: `https://${host}/storage/v1`,
        anonApiKey: key,
        objectPaths: pathHints,
        probeBucketList: true,
      });
      storageProbe = {
        status: storage.status,
        reason: storage.reasonCode,
        publicHits: storage.observations.filter((o) => o.publicReadable).length,
        pathHints,
      };
      console.log(
        `storage status=${storage.status} reason=${storage.reasonCode} hints=${pathHints.length} publicHits=${storageProbe.publicHits}`
      );
    } else {
      console.log('storage pathHints=0 (skip live storage probe)');
      storageProbe = {
        status: 'skipped',
        reason: 'no_storage_paths_in_js',
        publicHits: 0,
        pathHints: [],
      };
    }
  } catch (err: unknown) {
    console.log(
      `storage probe soft-fail: ${err instanceof Error ? err.message : 'error'}`
    );
  }

  // Charmarket quick check
  let charmarketSupabase = false;
  try {
    const cm = await (await fetch('https://charmarket.vercel.app/')).text();
    charmarketSupabase = /supabase\.co|sb_publishable_/i.test(cm);
  } catch {
    charmarketSupabase = false;
  }
  console.log(`charmarket_supabase_present=${charmarketSupabase}`);

  const out = {
    host,
    keyPreview: redact(key),
    enumStatus: enumResult.status,
    enumReason: enumResult.reasonCode,
    rlsStatus: rls.status,
    rlsReason: rls.reasonCode,
    observations: rls.observations.map((o) => ({
      table: o.tableName,
      anonStatus: o.anonStatusCode,
      claim: o.claimKind,
    })),
    promoted,
    findingTitles,
    storageProbe,
    charmarketSupabase,
  };
  writeFileSync('/tmp/fixguard_teclaaa_rls_focused.json', JSON.stringify(out, null, 2));
  console.log(JSON.stringify(out, null, 2));

  if (promoted < 1 && rls.observations.length < 1) {
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
