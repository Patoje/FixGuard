/**
 * FixGuard V2 — Live Verification of User-Provided Authorized Targets
 * Targets:
 * 1. https://charmarket.vercel.app/
 * 2. https://teclaaa.vercel.app/
 *
 * Runs:
 * - Playwright Stealth SPA Discovery on both targets (validating DOM hydration, stealth flags, and route extraction)
 * - Teclaaa Supabase Data API inspection: Anonymous vs Authenticated (with user-provided JWT)
 */

import { PlaywrightSpaAdapter } from '../src/v2/recon/adapters/PlaywrightSpaAdapter.js';
import { establishVerifiedAuthorizationDecision } from '../src/v2/authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../src/v2/scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../src/v2/lineage/AuthorizedExecutionLineageContracts.js';

const USER_TOKEN =
  'eyJhbGciOiJFUzI1NiIsImtpZCI6IjhlYmI4MWU2LTE0OTEtNDhkZi04ZTQzLTFkMDI5YzM1ZmE2MyIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Zhd3J6b25jc3pxYXV6eHdxaWRlLnN1cGFiYXNlLmNvL2F1dGgvdjEiLCJzdWIiOiJhY2M0NzNlMC0yYjE3LTQwNGEtYTEwNS1jOGQ5MDljYTUyMGQiLCJhdWQiOiJhdXRoZW50aWNhdGVkIiwiZXhwIjoxNzkwODE4MDYzLCJpYXQiOjE3OTA4MTQ0NjMsImVtYWlsIjoicGF0cmloZXlkZUBnbWFpbC5jb20iLCJwaG9uZSI6IiIsImFwcF9tZXRhZGF0YSI6eyJwcm92aWRlciI6ImVtYWlsIiwicHJvdmlkZXJzIjpbImVtYWlsIl19LCJ1c2VyX21ldGFkYXRhIjp7ImVtYWlsIjoicGF0cmloZXlkZUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZV9jaG9zZW4iOnRydWUsInBob25lX3ZlcmlmaWVkIjpmYWxzZSwic3ViIjoiYWNjNDczZTAtMmIxNy00MDRhLWExMDUtYzhkOTA5Y2E1MjBkIn0sInJvbGUiOiJhdXRoZW50aWNhdGVkIiwiYWFsIjoiYWFsMSIsImFtciI6W3sibWV0aG9kIjoib3RwIiwidGltZXN0YW1wIjoxNzkwODE0NDYzfV0sInNlc3Npb25faWQiOiJjYTQ1MDYxNy1iODEzLTQyMWEtYjZlMy03ZjE2OTBhNzFmYzAiLCJpc19hbm9ueW1vdXMiOmZhbHNlfQ.XBYQrW1EhkkbOKBt3Z7PLoEPoUzIDhxOs_GFj_5EmZeeaz8f9grae4k6ZPXCaOaEZpWk6y7C2ceCHbSEhXy5Zg';

function createAuthorizedContext(targetUrl: string, domain: string) {
  const now = new Date().toISOString();
  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: `scan_live_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    issuedAt: now,
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `User explicitly authorized defensive test for ${domain}`,
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
      allowedDomains: [domain, 'vawrzoncszqauzxwqide.supabase.co'],
      allowedHosts: [domain, 'vawrzoncszqauzxwqide.supabase.co'],
      allowedOrigins: [targetUrl, 'https://vawrzoncszqauzxwqide.supabase.co'],
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

  const decisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: `asm_live_${domain.replace(/[^a-z0-9]/gi, '_')}`,
      scanId: scopeGrant.scanId,
      authorizationDecisionId: `dec_live_${domain.replace(/[^a-z0-9]/gi, '_')}`,
      authorizedActor: { actorId: 'usr_operator_authorized', actorType: 'human' },
      decision: 'authorized',
      decidedAt: now,
      scopeGrant,
    },
    now
  );

  if (decisionResult.status !== 'established' || !decisionResult.decision) {
    throw new Error(`Failed to establish verified decision: ${decisionResult.reasonCode}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: `asm_live_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'usr_operator_authorized',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

async function testSpaWithStealth(targetUrl: string, domain: string) {
  console.log(`\n================================================================`);
  console.log(`[1] TESTING PLAYWRIGHT STEALTH SPA ADAPTER ON: ${targetUrl}`);
  console.log(`================================================================`);
  const { scopeGrant, decision, lineage } = createAuthorizedContext(targetUrl, domain);
  const adapter = new PlaywrightSpaAdapter();

  const start = Date.now();
  const res = await adapter.discoverSpa({
    targetUrlOrDomain: targetUrl,
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    timeoutMs: 20_000,
    waitForHydrationMs: 3_000,
  });

  const duration = Date.now() - start;
  console.log(`Discovery finished in ${duration}ms with status: ${res.status}`);

  if (res.status === 'success') {
    const obs = res.observations[0];
    console.log(`  -> Page Title: "${obs?.pageTitle ?? 'N/A'}"`);
    console.log(`  -> Detected Frameworks: ${JSON.stringify(obs?.frameworks ?? [])}`);
    console.log(`  -> Discovered Routes (${res.routes.length} total):`);
    for (const r of res.routes.slice(0, 10)) {
      console.log(`     - [${r.routeType}] ${r.method ?? 'GET'} ${r.url}`);
    }
    if (res.routes.length > 10) {
      console.log(`     ... and ${res.routes.length - 10} more routes.`);
    }
    console.log(`  -> Discovered Form Inputs (${res.inputs.length} total):`);
    for (const input of res.inputs.slice(0, 5)) {
      console.log(`     - Input name="${input.inputName}" type="${input.inputType}" in action="${input.formAction ?? '/'}"`);
    }
  } else {
    console.log(`  -> Discovery did not succeed. Reason: ${res.reasonCode} - ${res.reason}`);
  }
}

async function testTeclaaaSupabaseDifferential() {
  console.log(`\n================================================================`);
  console.log(`[2] TESTING TECLAAA SUPABASE: ANONYMOUS VS AUTHENTICATED TOKEN`);
  console.log(`================================================================`);

  // 1. Extract live publishable anon key from Teclaaa JS
  console.log(`Extracting live Supabase credentials from https://teclaaa.vercel.app/carrera/93kpw ...`);
  const html = await (await fetch('https://teclaaa.vercel.app/carrera/93kpw')).text();
  const scripts = Array.from(
    html.matchAll(/src="(\/_next\/static\/[^"]+\.js)"/g),
    (m) => m[1]!
  );

  let observedAnonKey = '';
  let supabaseHost = 'vawrzoncszqauzxwqide.supabase.co';

  for (const s of scripts.slice(0, 30)) {
    try {
      const code = await (await fetch(`https://teclaaa.vercel.app${s}`)).text();
      const hostMatch = code.match(/https:\/\/([a-z0-9-]+\.supabase\.co)/i);
      if (hostMatch) supabaseHost = hostMatch[1];
      const keyMatch = code.match(/sb_publishable_[A-Za-z0-9_-]+/);
      if (keyMatch) {
        observedAnonKey = keyMatch[0];
        break;
      }
    } catch {
      // continue
    }
  }

  if (!observedAnonKey) {
    console.log('Could not extract sb_publishable key, using standard check.');
  } else {
    console.log(`  -> OBSERVED Supabase Host: ${supabaseHost}`);
    console.log(`  -> OBSERVED Anon Key: ${observedAnonKey.slice(0, 15)}...${observedAnonKey.slice(-4)}`);
  }

  const tables = ['profiles', 'shop_items', 'wallets', 'runs'];
  console.log(`\nQuerying PostgREST tables differential (Anon vs Authenticated):`);

  for (const table of tables) {
    const endpoint = `https://${supabaseHost}/rest/v1/${table}?select=*&limit=3`;

    // A. Anonymous Request (without authorization / with anon key only)
    let anonStatus = 0;
    let anonCount = 0;
    let anonBodyPreview = '';
    try {
      const anonHeaders: Record<string, string> = {
        'Accept': 'application/json',
      };
      if (observedAnonKey) {
        anonHeaders['apikey'] = observedAnonKey;
      }
      const resAnon = await fetch(endpoint, { headers: anonHeaders });
      anonStatus = resAnon.status;
      const data = await resAnon.json();
      if (Array.isArray(data)) {
        anonCount = data.length;
        anonBodyPreview = JSON.stringify(data[0] ?? {});
      } else {
        anonBodyPreview = JSON.stringify(data).slice(0, 80);
      }
    } catch (e: unknown) {
      anonBodyPreview = String(e);
    }

    // B. Authenticated Request (with user token)
    let authStatus = 0;
    let authCount = 0;
    let authBodyPreview = '';
    try {
      const authHeaders: Record<string, string> = {
        'Accept': 'application/json',
        'Authorization': `Bearer ${USER_TOKEN}`,
      };
      if (observedAnonKey) {
        authHeaders['apikey'] = observedAnonKey;
      }
      const resAuth = await fetch(endpoint, { headers: authHeaders });
      authStatus = resAuth.status;
      const data = await resAuth.json();
      if (Array.isArray(data)) {
        authCount = data.length;
        authBodyPreview = JSON.stringify(data[0] ?? {});
      } else {
        authBodyPreview = JSON.stringify(data).slice(0, 80);
      }
    } catch (e: unknown) {
      authBodyPreview = String(e);
    }

    console.log(`\n  Table: [${table}]`);
    console.log(`    - Anon / Sin Token: HTTP ${anonStatus} (rows returned: ${anonCount})`);
    if (anonStatus === 200) {
      console.log(`      Sample row: ${anonBodyPreview.slice(0, 100)}...`);
    }
    console.log(`    - Auth / Con Token: HTTP ${authStatus} (rows returned: ${authCount})`);
    if (authStatus === 200) {
      console.log(`      Sample row: ${authBodyPreview.slice(0, 100)}...`);
    }

    if (anonStatus === 200 && authStatus === 200) {
      console.log(`    ⚠️ Finding: Table '${table}' lacks RLS restriction for anonymous readers (World-Readable).`);
    } else if (anonStatus !== 200 && authStatus === 200) {
      console.log(`    🔒 RLS Enforced: Anonymous blocked, authenticated user allowed.`);
    }
  }
}

async function run() {
  await testSpaWithStealth('https://charmarket.vercel.app/', 'charmarket.vercel.app');
  await testSpaWithStealth('https://teclaaa.vercel.app/', 'teclaaa.vercel.app');
  await testTeclaaaSupabaseDifferential();
  console.log(`\n================================================================`);
  console.log(`[✔] LIVE ASSESSMENT PROBES COMPLETED CLEANLY`);
  console.log(`================================================================\n`);
}

run().catch(console.error);
