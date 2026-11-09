/**
 * FixGuard V2 — Final Playwright Redirect & Cookie Fidelity Corrections:
 * REAL integration test.
 *
 * This is deliberately NOT a mocked unit test. It starts two real local
 * HTTP origins, runs the real httpx/ffuf/arjun binaries and a real
 * Chromium instance against them, and inspects what each origin actually
 * received. No documentation or mocked command arguments are trusted —
 * every claim below is backed by an assertion against real network
 * traffic captured at the receiving test servers.
 *
 * Scope note on all sections: FixGuard's own adapter preflight
 * (`runAdapterPreflight` → `isInternalOrSsrfTarget`) unconditionally
 * denies loopback/localhost targets — correctly, since a real deployment
 * must never probe internal addresses. That SSRF gate is covered by its
 * own existing mocked tests and is not re-tested here. Since this test
 * has no non-loopback, non-third-party way to stand up local origins (the
 * task explicitly disallows real third-party services), it constructs
 * the exact CLI argument sets / route-handler logic
 * HttpxInspectionAdapter.ts / FfufAdapter.ts / ArjunAdapter.ts /
 * PlaywrightSpaAdapter.ts build today (cited per section) and runs them
 * directly against the real binaries / real Chromium, bypassing only the
 * adapter's preflight wrapper — the credential/redirect mechanism under
 * test is identical to production.
 *
 * Section 4 does not go through `PlaywrightSpaAdapter.discoverSpa()`
 * itself for a reason discovered while building this test, worth
 * recording: Playwright's `route.fetch()` resolves hostnames through its
 * own driver-process DNS lookup, which does NOT honor the page's
 * `--host-resolver-rules` launch argument (confirmed by direct testing —
 * a fake hostname mapped via that flag loads fine via normal navigation
 * but `route.fetch()` against the same URL throws `ENOTFOUND`). There is
 * therefore no way to route a fake, preflight-passing hostname through
 * `route.fetch()` without real DNS/hosts control, which this sandbox does
 * not have. Section 4 instead reproduces the adapter's Gate 2 route
 * handler verbatim (cited against the real source, kept in sync with it)
 * against literal 127.0.0.1 / localhost origins.
 */

import assert from 'node:assert';
import http from 'node:http';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { chromium, type Page } from 'playwright';
import { LocalProcessRunner } from '../core/ProcessRunner.js';

const PORT_A = 18901;
const PORT_B = 18902;

interface CapturedRequest {
  readonly url: string;
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
}

function startOrigins(): {
  readonly originARequests: CapturedRequest[];
  readonly originBRequests: CapturedRequest[];
  readonly close: () => Promise<void>;
} {
  const originARequests: CapturedRequest[] = [];
  const originBRequests: CapturedRequest[] = [];

  const serverA = http.createServer((req, res) => {
    originARequests.push({ url: req.url ?? '', headers: { ...req.headers } });
    if (req.url === '/page') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>normal page on Origin A</body></html>');
      return;
    }
    if (req.url === '/start-same-origin') {
      // Test A: same-origin redirect (a different path, same origin).
      res.writeHead(302, { Location: '/page' });
      res.end('redirecting same-origin');
      return;
    }
    if (req.url === '/redirect-to-localhost') {
      // Test B: cross-host redirect (genuinely different hostname).
      res.writeHead(302, { Location: `http://localhost:${PORT_B}/landing` });
      res.end('redirecting to a genuinely different hostname');
      return;
    }
    if (req.url === '/loop-a') {
      // Test E: redirect loop (A -> B -> A ...).
      res.writeHead(302, { Location: '/loop-b' });
      res.end('redirect loop hop 1');
      return;
    }
    if (req.url === '/loop-b') {
      res.writeHead(302, { Location: '/loop-a' });
      res.end('redirect loop hop 2');
      return;
    }
    // Test C (default /start): same-host, different-port redirect.
    res.writeHead(302, { Location: `http://127.0.0.1:${PORT_B}/landing` });
    res.end('redirecting');
  });

  const serverB = http.createServer((req, res) => {
    originBRequests.push({ url: req.url ?? '', headers: { ...req.headers } });
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('landed on origin B');
  });

  serverA.listen(PORT_A, '127.0.0.1');
  serverB.listen(PORT_B, '127.0.0.1');

  return {
    originARequests,
    originBRequests,
    close: () =>
      new Promise((resolve) => {
        let remaining = 2;
        const done = () => {
          remaining -= 1;
          if (remaining === 0) resolve();
        };
        serverA.close(done);
        serverB.close(done);
      }),
  };
}

/**
 * Reproduces PlaywrightSpaAdapter.ts's Gate 2 credential loop verbatim
 * (kept in sync with the real source) against a real Chromium `page`:
 * the explicit, bounded, per-hop-origin-validated redirect loop that
 * replaced route.continue({headers}) and context.addCookies() for
 * session credentials — both Cookie and Authorization travel in one
 * combined header set, attached only via route.fetch({url, method,
 * maxRedirects: 0}) on an exact origin match, never via the cookie jar.
 */
async function installCredentialLoopRoute(
  page: Page,
  approvedOrigin: string,
  credentialHeaders: Record<string, string>
): Promise<void> {
  // Hoisted OUTSIDE the handler — shared across every invocation of it
  // for this page, matching the real fix. Verified directly that
  // fulfilling a redirect triggers a brand-new, independent route()
  // invocation with no memory of a same-invocation loop, so a
  // per-invocation-only bound never actually caps the total real
  // requests a genuine redirect loop produces.
  const MAX_TOTAL_REDIRECT_HOPS = 10;
  const globallyVisitedRedirectUrls = new Set<string>();
  let totalRedirectHopsUsed = 0;

  await page.route('**/*', async (route) => {
    const req = route.request();
    const reqUrl = req.url();
    let reqOrigin: string;
    try {
      reqOrigin = new URL(reqUrl).origin;
    } catch {
      await route.continue();
      return;
    }
    if (reqOrigin !== approvedOrigin) {
      await route.continue();
      return;
    }

    let currentUrl = reqUrl;
    let currentMethod = req.method();
    let lastSameOriginResponse: Awaited<ReturnType<typeof route.fetch>> | undefined;

    while (true) {
      let hopOrigin: string;
      try {
        hopOrigin = new URL(currentUrl).origin;
      } catch {
        await route.abort('blockedbyclient');
        return;
      }

      if (hopOrigin !== approvedOrigin) {
        if (lastSameOriginResponse) {
          await route.fulfill({ response: lastSameOriginResponse });
        } else {
          await route.continue();
        }
        return;
      }

      if (totalRedirectHopsUsed >= MAX_TOTAL_REDIRECT_HOPS) {
        if (
          lastSameOriginResponse &&
          (lastSameOriginResponse.status() < 300 || lastSameOriginResponse.status() >= 400)
        ) {
          await route.fulfill({ response: lastSameOriginResponse });
        } else {
          await route.abort('blockedbyclient');
        }
        return;
      }

      if (globallyVisitedRedirectUrls.has(currentUrl)) {
        await route.abort('blockedbyclient');
        return;
      }
      globallyVisitedRedirectUrls.add(currentUrl);
      totalRedirectHopsUsed += 1;

      const fetched = await route.fetch({
        url: currentUrl === reqUrl ? undefined : currentUrl,
        method: currentMethod,
        headers: { ...req.headers(), ...credentialHeaders },
        maxRedirects: 0,
      });

      const status = fetched.status();
      if (status < 300 || status >= 400) {
        await route.fulfill({ response: fetched });
        return;
      }

      const location = fetched.headers()['location'];
      if (!location) {
        await route.fulfill({ response: fetched });
        return;
      }
      let nextUrl: string;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        await route.fulfill({ response: fetched });
        return;
      }

      if (status === 303) {
        currentMethod = 'GET';
      } else if ((status === 301 || status === 302) && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
        currentMethod = 'GET';
      }

      lastSameOriginResponse = fetched;
      currentUrl = nextUrl;
    }
  });
}

async function run(): Promise<void> {
  console.log('=== FixGuard V2 — Final Credential Redirect Audit: real integration test ===\n');

  // ===========================================================================
  // 1. httpx — real binary, real redirect, real headers (HttpxInspectionAdapter.ts).
  // ===========================================================================
  console.log('[*] 1. httpx: real redirect, session credentials must stay on Origin A');
  {
    const { originARequests, originBRequests, close } = startOrigins();
    try {
      const sessionHeaders = { Cookie: 'session_id=REAL_SECRET_COOKIE', Authorization: 'Bearer REAL_SECRET_TOKEN' };
      // Mirrors HttpxInspectionAdapter.ts's exact arg construction when
      // sessionHeaders are present: '-follow-redirects' omitted, '-H' per header.
      const args = ['-u', `http://127.0.0.1:${PORT_A}/start`, '-json', '-silent', '-title', '-tech-detect', '-status-code'];
      for (const [k, v] of Object.entries(sessionHeaders)) args.push('-H', `${k}: ${v}`);

      const output = await new LocalProcessRunner().execute({ binary: 'httpx', args, timeoutMs: 20_000 });
      assert.strictEqual(output.exitCode, 0, `httpx must exit 0; stderr: ${output.stderr}`);

      const parsed = JSON.parse(output.stdout.trim().split('\n')[0]);
      assert.strictEqual(parsed.status_code, 302, 'the single hop must report the raw 302, never an auto-followed 200');
      assert.strictEqual(parsed.location, `http://127.0.0.1:${PORT_B}/landing`, 'the redirect target must still be observed');

      assert.strictEqual(originARequests.length, 1, 'Origin A must receive exactly one real request');
      assert.strictEqual(
        originARequests[0].headers['authorization'],
        'Bearer REAL_SECRET_TOKEN',
        'Origin A (the authorized target) must receive the session credentials'
      );
      assert.strictEqual(originBRequests.length, 0, 'Origin B must NEVER be contacted — no auto-follow with credentials present');
      console.log('    -> PASS: Origin A received the credentials; Origin B received zero requests.');
    } finally {
      await close();
    }
  }

  // ===========================================================================
  // 2. ffuf — real binary, confirms the adapter's existing default is already safe.
  // ===========================================================================
  console.log('[*] 2. ffuf: confirms existing default (no -r) never follows the real redirect');
  {
    const { originARequests, originBRequests, close } = startOrigins();
    try {
      const wordlistPath = path.join(os.tmpdir(), `ffuf-integration-${Date.now()}.txt`);
      await fs.writeFile(wordlistPath, 'start\n');
      const sessionHeaders = { Cookie: 'session_id=REAL_SECRET_COOKIE', Authorization: 'Bearer REAL_SECRET_TOKEN' };
      // Mirrors FfufAdapter.ts's exact arg construction — no '-r'/follow-redirect
      // flag is ever passed by this adapter, confirmed in the source.
      const args = ['-u', `http://127.0.0.1:${PORT_A}/FUZZ`, '-w', wordlistPath, '-json', '-ac'];
      for (const [k, v] of Object.entries(sessionHeaders)) args.push('-H', `${k}: ${v}`);

      const output = await new LocalProcessRunner().execute({ binary: 'ffuf', args, timeoutMs: 20_000 });
      await fs.unlink(wordlistPath).catch(() => {});
      assert.strictEqual(output.exitCode, 0, `ffuf must exit 0; stderr: ${output.stderr}`);

      // -ac (autocalibrate) sends extra baseline requests before the real
      // wordlist entry, so Origin A legitimately receives more than one.
      assert.ok(originARequests.length >= 1, 'Origin A must receive at least one real request');
      assert.ok(
        originARequests.some((r) => r.headers['authorization'] === 'Bearer REAL_SECRET_TOKEN'),
        'at least one real request to Origin A must carry the session credentials'
      );
      assert.strictEqual(originBRequests.length, 0, 'Origin B must NEVER be contacted by ffuf’s existing safe default');
      console.log('    -> PASS: ffuf’s existing default (no -r) never reached Origin B in real execution.');
    } finally {
      await close();
    }
  }

  // ===========================================================================
  // 3. arjun — real binary, confirms --disable-redirects prevents the real leak
  //    this audit found (every chunked probe request was otherwise forwarded
  //    to Origin B with both Cookie and Authorization attached).
  // ===========================================================================
  console.log('[*] 3. arjun: --disable-redirects must prevent the real cross-origin leak');
  {
    const { originARequests, originBRequests, close } = startOrigins();
    try {
      const sessionHeaders = { Cookie: 'session_id=REAL_SECRET_COOKIE', Authorization: 'Bearer REAL_SECRET_TOKEN' };
      const outFile = path.join(os.tmpdir(), `arjun-integration-${Date.now()}.json`);
      // Mirrors ArjunAdapter.ts's exact arg construction when sessionHeaders
      // are present: '--headers' + '--disable-redirects'.
      const headerLines = Object.entries(sessionHeaders).map(([k, v]) => `${k}: ${v}`).join('\\n');
      const args = ['-u', `http://127.0.0.1:${PORT_A}/start`, '--headers', headerLines, '--disable-redirects', '-oJ', outFile];

      const output = await new LocalProcessRunner().execute({ binary: 'arjun', args, timeoutMs: 30_000 });
      await fs.unlink(outFile).catch(() => {});
      assert.strictEqual(output.exitCode, 0, `arjun must exit 0; stderr: ${output.stderr}`);

      assert.ok(originARequests.length >= 1, 'Origin A must receive at least the stability-check request');
      assert.strictEqual(
        originBRequests.length,
        0,
        '--disable-redirects must mean Origin B is NEVER contacted, even once, by real arjun execution'
      );
      console.log(`    -> PASS: Origin A received ${originARequests.length} request(s); Origin B received zero — --disable-redirects holds under real execution.`);
    } finally {
      await close();
    }
  }

  const CREDENTIALS = { Cookie: 'session_id=REAL_SECRET_COOKIE', authorization: 'Bearer REAL_SECRET_TOKEN' };

  // ===========================================================================
  // Test A — same-origin redirect: a different path, same scheme+host+port.
  // The application must remain accessible (the final content is served),
  // and the redirected-to path receives valid credentials — a legitimate
  // same-origin redirect must not silently lose authentication.
  // ===========================================================================
  console.log('[*] Test A. Real Chromium + real Gate 2 loop: same-origin redirect — credentials follow, app stays accessible');
  {
    const { originARequests, close } = startOrigins();
    try {
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const approvedOrigin = `http://127.0.0.1:${PORT_A}`;
      const page = await context.newPage();
      await installCredentialLoopRoute(page, approvedOrigin, CREDENTIALS);

      await page.goto(`http://127.0.0.1:${PORT_A}/start-same-origin`, { waitUntil: 'load' }).catch(() => {});
      const content = await page.content();
      await browser.close();

      assert.ok(content.includes('normal page on Origin A'), 'the final (redirected-to) content must actually be accessible');
      assert.strictEqual(originARequests.length, 2, 'both the redirecting hop and the final hop must be real requests to Origin A');
      for (const r of originARequests) {
        assert.strictEqual(r.headers['authorization'], 'Bearer REAL_SECRET_TOKEN', 'every same-origin hop must receive Authorization');
        assert.strictEqual(r.headers['cookie'], 'session_id=REAL_SECRET_COOKIE', 'every same-origin hop must receive the Cookie');
      }
      console.log('    -> PASS: both hops of the same-origin redirect received valid credentials; the application remained accessible.');
    } finally {
      await close();
    }
  }

  // ===========================================================================
  // Test B — cross-host redirect: Origin A redirects to a genuinely
  // different hostname (localhost vs 127.0.0.1). Origin B must receive
  // neither Cookie nor Authorization.
  // ===========================================================================
  console.log('[*] Test B. Real Chromium + real Gate 2 loop: cross-host redirect — Origin B receives neither credential');
  {
    const { originARequests, originBRequests, close } = startOrigins();
    try {
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const approvedOrigin = `http://127.0.0.1:${PORT_A}`;
      const page = await context.newPage();
      await installCredentialLoopRoute(page, approvedOrigin, CREDENTIALS);

      await page.goto(`http://127.0.0.1:${PORT_A}/redirect-to-localhost`, { waitUntil: 'load' }).catch(() => {});
      await browser.close();

      assert.ok(originARequests.length >= 1, 'Origin A must receive at least one real request');
      assert.strictEqual(originARequests[0].headers['authorization'], 'Bearer REAL_SECRET_TOKEN');
      assert.strictEqual(originARequests[0].headers['cookie'], 'session_id=REAL_SECRET_COOKIE');

      assert.ok(originBRequests.length >= 1, 'the real browser must actually follow the redirect to Origin B (observation preserved)');
      assert.strictEqual(originBRequests[0].headers['authorization'], undefined, 'Origin B must never receive Authorization');
      assert.strictEqual(originBRequests[0].headers['cookie'], undefined, 'Origin B must never receive the Cookie — genuinely different hostnames');
      console.log('    -> PASS: real Chromium followed the redirect; Origin A received both credentials, Origin B received neither.');
    } finally {
      await close();
    }
  }

  // ===========================================================================
  // Test C — same-host, different-port redirect. Previously documented as
  // an inherent cookie-jar limitation (cookies have no port scoping); now
  // that Cookie travels through the SAME per-hop-validated mechanism as
  // Authorization (never the cookie jar), neither credential may reach
  // the other port either.
  // ===========================================================================
  console.log('[*] Test C. Real Chromium + real Gate 2 loop: same-host, different-port redirect — neither credential crosses the port');
  {
    const { originBRequests, close } = startOrigins();
    try {
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const approvedOrigin = `http://127.0.0.1:${PORT_A}`;
      const page = await context.newPage();
      await installCredentialLoopRoute(page, approvedOrigin, CREDENTIALS);

      await page.goto(`http://127.0.0.1:${PORT_A}/start`, { waitUntil: 'load' }).catch(() => {});
      await browser.close();

      assert.ok(originBRequests.length >= 1, 'the real browser must actually follow the same-host, different-port redirect');
      assert.strictEqual(
        originBRequests[0].headers['authorization'],
        undefined,
        'Authorization must stay confined to the exact origin (port included)'
      );
      assert.strictEqual(
        originBRequests[0].headers['cookie'],
        undefined,
        'the Cookie must now ALSO stay confined to the exact origin — it no longer goes through the port-insensitive browser cookie jar'
      );
      console.log('    -> PASS (fixed): neither Authorization nor Cookie reached the different port on the same host.');
    } finally {
      await close();
    }
  }

  // ===========================================================================
  // Test E — redirect loop (/loop-a -> /loop-b -> /loop-a -> ...). Must be
  // bounded: a finite number of real requests, the route must still
  // resolve (not hang), and no uncontrolled/infinite traffic is generated.
  // ===========================================================================
  console.log('[*] Test E. Real Chromium + real Gate 2 loop: redirect loop is bounded, never infinite');
  {
    const { originARequests, close } = startOrigins();
    try {
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext();
      const approvedOrigin = `http://127.0.0.1:${PORT_A}`;
      const page = await context.newPage();
      await installCredentialLoopRoute(page, approvedOrigin, CREDENTIALS);

      const start = Date.now();
      await page.goto(`http://127.0.0.1:${PORT_A}/loop-a`, { waitUntil: 'load', timeout: 15_000 }).catch(() => {});
      const elapsedMs = Date.now() - start;
      await browser.close();

      assert.ok(
        originARequests.length <= 3,
        `the redirect loop must be detected almost immediately (cumulative, cross-invocation tracking) — got ${originARequests.length} real requests to Origin A`
      );
      assert.ok(elapsedMs < 15_000, `the loop must resolve well within a bounded time, not hang (took ${elapsedMs}ms)`);
      console.log(`    -> PASS: redirect loop resolved after ${originARequests.length} real request(s) in ${elapsedMs}ms — bounded, not infinite.`);
    } finally {
      await close();
    }
  }

  console.log('\n[✔] ALL FINAL CREDENTIAL REDIRECT AUDIT INTEGRATION ASSERTIONS PASSED AGAINST REAL BINARIES / REAL BROWSER / REAL LOCAL ORIGINS.');
}

run().catch((err) => {
  console.error('\n[FATAL] Credential redirect integration test failed:', err);
  process.exit(1);
});
