/**
 * Live quick compare: Teclaaa JS ranking + sourcemap surface seeds (no JWT, no secrets committed).
 * Reports OBSERVED rest/table seeds vs encounter-order baseline (pre–deep-recon-P1).
 */
import {
  selectJsLuiceTargets,
  scoreJsAssetForMining,
} from '../src/v2/recon/adapters/JsLuiceAdapter.js';
import { extractUrlSeedsFromSourcemapJson } from '../src/v2/recon/analysis/SourcemapSurfaceExtractionService.js';
import type { AuthorizedScopeGrant } from '../src/v2/scope/AuthorizedScopeContracts.js';
import {
  classifySupabaseUrl,
  extractSupabaseTableHintsFromText,
} from '../src/v2/supabase/SupabaseSurfaceContracts.js';

const TARGET = 'teclaaa.vercel.app';
const SUPABASE_FALLBACK = 'vawrzoncszqauzxwqide.supabase.co';

function baselineFirstN(urls: readonly string[], n: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const url of urls) {
    if (!url || seen.has(url)) continue;
    try {
      const u = new URL(url);
      if (!/\.js(\?|$)/i.test(u.pathname) && !/\/_next\/static\/chunks\//i.test(u.pathname)) {
        continue;
      }
      seen.add(url);
      out.push(url);
      if (out.length >= n) break;
    } catch {
      continue;
    }
  }
  return out;
}

async function main(): Promise<void> {
  const roots = [`https://${TARGET}/`, `https://${TARGET}/carrera/93kpw`];
  const scriptUrls: string[] = [];
  const bodies: string[] = [];

  for (const root of roots) {
    try {
      const html = await (await fetch(root, { signal: AbortSignal.timeout(12_000) })).text();
      bodies.push(html);
      for (const m of html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g)) {
        scriptUrls.push(`https://${TARGET}${m[1]}`);
      }
    } catch (err) {
      console.log(`HTML fetch soft-fail ${root}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const uniqueScripts = Array.from(new Set(scriptUrls));
  console.log(`OBSERVED script tags: ${uniqueScripts.length}`);

  const baseline6 = baselineFirstN(uniqueScripts, 6);
  const ranked16 = selectJsLuiceTargets({
    inventoryUrls: uniqueScripts.map((url) => ({ url })),
    maxTargets: 16,
  });
  console.log(`baseline first-6: ${baseline6.length}`);
  console.log(
    `ranked top-16 scores: ${ranked16
      .slice(0, 8)
      .map((u) => `${scoreJsAssetForMining(u)}:${u.split('/').pop()}`)
      .join(' | ')}`
  );
  const baselineSet = new Set(baseline6);
  const newOnly = ranked16.filter((u) => !baselineSet.has(u));
  console.log(`ranked-beyond-baseline6: ${newOnly.length}`);

  const host =
    bodies.join('\n').match(/https:\/\/([a-z0-9-]+\.supabase\.co)/i)?.[1] ?? SUPABASE_FALLBACK;

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_live_p1',
    scanId: 'scan_live_p1',
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: TARGET },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Live P1 compare ${TARGET}`,
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
      allowedDomains: [TARGET],
      allowedHosts: [TARGET, host],
      allowedOrigins: [`https://${TARGET}`],
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

  const tableSeeds = new Set<string>();
  const apiPaths = new Set<string>();
  let mapsTried = 0;
  let mapsHit = 0;
  let jsOk = 0;
  let jsFail = 0;

  for (const jsUrl of ranked16) {
    try {
      const jsRes = await fetch(jsUrl, { signal: AbortSignal.timeout(10_000) });
      if (!jsRes.ok) {
        jsFail += 1;
        continue;
      }
      const jsBody = await jsRes.text();
      jsOk += 1;
      for (const hint of extractSupabaseTableHintsFromText(jsBody)) {
        tableSeeds.add(hint);
      }
      const mapHeader = jsRes.headers.get('sourcemap') ?? jsRes.headers.get('x-sourcemap');
      const comment = jsBody.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/i)?.[1];
      const mapRef = mapHeader?.trim() || comment?.trim() || `${jsUrl.split('?')[0]}.map`;
      let mapUrl: string;
      try {
        mapUrl = new URL(mapRef, jsUrl).toString();
      } catch {
        continue;
      }
      mapsTried += 1;
      const mapRes = await fetch(mapUrl, { signal: AbortSignal.timeout(10_000) });
      if (!mapRes.ok) continue;
      const mapText = await mapRes.text();
      let parsed: unknown;
      try {
        parsed = JSON.parse(mapText);
      } catch {
        continue;
      }
      mapsHit += 1;
      const mined = extractUrlSeedsFromSourcemapJson({
        mapJson: parsed,
        resolvePathsBase: `https://${TARGET}/`,
        authorizedScopeGrant: scopeGrant,
        discoveredAt: new Date().toISOString(),
      });
      for (const obs of mined.urlObservations) {
        const c = classifySupabaseUrl(obs.url);
        if (c.tableName) tableSeeds.add(c.tableName);
        if (obs.path.startsWith('/api') || obs.path.includes('/rest/v1')) {
          apiPaths.add(obs.path);
        }
      }
    } catch {
      jsFail += 1;
    }
  }

  console.log(`js bodies: ok=${jsOk} fail=${jsFail}`);
  console.log(`sourcemap probes: tried=${mapsTried} hit=${mapsHit}`);
  console.log(`table seeds: ${tableSeeds.size} → ${Array.from(tableSeeds).sort().join(', ') || '(none)'}`);
  console.log(`api/rest paths: ${apiPaths.size} → ${Array.from(apiPaths).sort().slice(0, 20).join(', ') || '(none)'}`);
  console.log(
    `DELTA vs pre-P1 (budget 6 encounter-order only): +${newOnly.length} ranked JS slots; maps=${mapsHit}; tables=${tableSeeds.size}`
  );
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
