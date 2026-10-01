/**
 * Milestone Playwright Stealth, Browser Profile Rotation & Proxy Validation Smoke Test
 *
 * Validates:
 * 1. Curated Browser Profiles & Deterministic Rotation
 * 2. In-Browser Evasion Script Generation (webdriver, chrome.runtime, languages, WebGL, permissions)
 * 3. Context Options Generation & Sec-CH-UA Client Hints
 * 4. Fail-Closed Proxy Validation (SSRF/Loopback/RFC1918/Metadata blocking)
 * 5. Preflight Adapter Gate: Blocks rogue internal proxies with 0 browser spawns
 * 6. Playwright Context Integration: Injects stealth script & launch flags into browser context
 * 7. Simulated DOM Evasion Execution: Verifies evasions evaluate correctly
 */

import assert from 'node:assert';
import vm from 'node:vm';
import {
  BROWSER_PROFILES,
  DEFAULT_BROWSER_PROFILE,
  STEALTH_CHROMIUM_LAUNCH_ARGS,
  selectBrowserProfile,
  getProfileBySeed,
  validateBrowserProxyConfig,
  buildStealthInitScript,
  buildStealthContextOptions,
  applyPlaywrightStealth,
} from '../recon/adapters/PlaywrightStealth.js';
import { PlaywrightSpaAdapter } from '../recon/adapters/PlaywrightSpaAdapter.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type {
  BrowserInstance,
  BrowserContextInstance,
  PageInstance,
  PlaywrightBrowserLauncher,
  BrowserProxyConfig,
} from '../recon/adapters/BrowserAutomationContracts.js';

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);

  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_stealth_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized stealth automation smoke test for ${domain}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [domain],
      allowedHosts: [domain],
      allowedOrigins: [`https://${domain}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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

function setupAuthorizedContext(domain: string) {
  const scopeGrant = createScopeGrant(domain);
  const nowIso = new Date().toISOString();
  const decisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_stealth_001',
      scanId: 'scan_stealth_001',
      authorizationDecisionId: 'dec_stealth_001',
      authorizedActor: { actorId: 'operator_stealth', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (decisionResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${decisionResult.reasonCode}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'asm_stealth_001',
    scanId: 'scan_stealth_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: decisionResult.decision.authorizationDecisionId,
    actorId: 'operator_stealth',
  };

  return { scopeGrant, decision: decisionResult.decision, lineage };
}

async function runPlaywrightStealthSmokeSuite() {
  console.log('--- Playwright Stealth & Legitimate Browser Automation Smoke Suite ---');

  // ---------------------------------------------------------------------------
  // Test 1: Curated Browser Profiles & Deterministic Rotation
  // ---------------------------------------------------------------------------
  console.log('[Test 1] Validating browser profiles and selection...');
  assert.ok(BROWSER_PROFILES.length >= 4, 'Must have at least 4 curated browser profiles');
  for (const profile of BROWSER_PROFILES) {
    assert.ok(profile.id.length > 0, 'Profile ID must not be empty');
    assert.ok(profile.userAgent.startsWith('Mozilla/5.0'), 'UA must start with Mozilla/5.0');
    assert.ok(profile.viewport.width >= 1280 && profile.viewport.height >= 720, 'Viewport must be desktop-sized');
    assert.ok(profile.locale.length > 0, 'Locale must be present');
    assert.ok(profile.timezoneId.length > 0, 'Timezone must be present');
  }

  const defaultProf = selectBrowserProfile();
  assert.strictEqual(defaultProf.id, DEFAULT_BROWSER_PROFILE.id);

  const winProf = selectBrowserProfile('windows-chrome-131');
  assert.strictEqual(winProf.id, 'windows-chrome-131');
  assert.ok(winProf.userAgent.includes('Windows NT 10.0'));

  const seededProfA = getProfileBySeed('target-tenant-alpha');
  const seededProfB = getProfileBySeed('target-tenant-alpha');
  assert.strictEqual(seededProfA.id, seededProfB.id, 'Seed rotation must be deterministic');
  console.log('✓ Test 1 passed: Browser profiles & selection verified');

  // ---------------------------------------------------------------------------
  // Test 2: Stealth Init Script Synthesis
  // ---------------------------------------------------------------------------
  console.log('[Test 2] Validating stealth script synthesis...');
  const script = buildStealthInitScript(DEFAULT_BROWSER_PROFILE);
  assert.ok(script.length > 500, 'Init script must be substantial');
  assert.ok(script.includes('webdriver'), 'Must contain webdriver evasion');
  assert.ok(script.includes('window.chrome'), 'Must contain chrome runtime mock');
  assert.ok(script.includes('languages'), 'Must contain languages normalization');
  assert.ok(script.includes('WebGLRenderingContext'), 'Must contain WebGL vendor patch');
  assert.ok(script.includes('notifications'), 'Must contain permissions mock');
  assert.ok(STEALTH_CHROMIUM_LAUNCH_ARGS.includes('--disable-blink-features=AutomationControlled'));
  console.log('✓ Test 2 passed: Stealth script synthesis verified');

  // ---------------------------------------------------------------------------
  // Test 3: Context Options & Sec-CH-UA Client Hints
  // ---------------------------------------------------------------------------
  console.log('[Test 3] Validating context options & client hints...');
  const contextOpts = buildStealthContextOptions(DEFAULT_BROWSER_PROFILE);
  assert.strictEqual(contextOpts.userAgent, DEFAULT_BROWSER_PROFILE.userAgent);
  assert.deepStrictEqual(contextOpts.viewport, { width: 1920, height: 1080 });
  const headers = contextOpts.extraHTTPHeaders as Record<string, string>;
  assert.ok(headers['sec-ch-ua']?.includes('Google Chrome'), 'Sec-CH-UA must declare Chrome');
  assert.strictEqual(headers['sec-ch-ua-platform'], '"macOS"');
  assert.strictEqual(headers['sec-ch-ua-mobile'], '?0');
  console.log('✓ Test 3 passed: Context options & client hints verified');

  // ---------------------------------------------------------------------------
  // Test 4: Fail-Closed Proxy Validation (SSRF Protection)
  // ---------------------------------------------------------------------------
  console.log('[Test 4] Validating proxy validation SSRF gate...');
  // Loopback / localhost
  const local1 = validateBrowserProxyConfig({ server: 'http://localhost:8080' });
  assert.strictEqual(local1.valid, false);
  const local2 = validateBrowserProxyConfig({ server: 'http://127.0.0.1:8080' });
  assert.strictEqual(local2.valid, false);

  // Private subnets (RFC1918)
  const priv10 = validateBrowserProxyConfig({ server: 'http://10.0.0.1:3128' });
  assert.strictEqual(priv10.valid, false);
  const priv192 = validateBrowserProxyConfig({ server: 'http://192.168.1.50:8080' });
  assert.strictEqual(priv192.valid, false);
  const priv172 = validateBrowserProxyConfig({ server: 'http://172.16.5.1:8080' });
  assert.strictEqual(priv172.valid, false);

  // Cloud metadata
  const meta = validateBrowserProxyConfig({ server: 'http://169.254.169.254:80' });
  assert.strictEqual(meta.valid, false);

  // Unsupported scheme
  const ftp = validateBrowserProxyConfig({ server: 'ftp://proxy.example.com:21' });
  assert.strictEqual(ftp.valid, false);

  // Valid external proxy
  const validProxy = validateBrowserProxyConfig({
    server: 'http://proxy.defense-corp.com:8080',
    username: 'auditor',
    password: 'secure-token',
  });
  assert.strictEqual(validProxy.valid, true);
  console.log('✓ Test 4 passed: Fail-closed proxy validation verified');

  // ---------------------------------------------------------------------------
  // Test 5: PlaywrightSpaAdapter Preflight Denial on Malicious Proxy
  // ---------------------------------------------------------------------------
  console.log('[Test 5] Validating adapter preflight denial on SSRF proxy...');
  const { scopeGrant, decision, lineage } = setupAuthorizedContext('target.example.com');
  const adapter = new PlaywrightSpaAdapter();

  let launchCount = 0;
  const mockLauncher: PlaywrightBrowserLauncher = {
    async launch() {
      launchCount++;
      throw new Error('Launcher should never be called when proxy fails preflight');
    },
  };

  const ssrfProxyResult = await adapter.discoverSpa({
    targetUrlOrDomain: 'https://target.example.com/app',
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    browserLauncher: mockLauncher,
    proxyConfig: { server: 'http://169.254.169.254:8080' },
  });

  assert.strictEqual(ssrfProxyResult.status, 'preflight_denied');
  assert.strictEqual(ssrfProxyResult.reasonCode, 'forbidden_proxy_egress');
  assert.strictEqual(launchCount, 0, 'Zero browser instances spawned when proxy fails preflight');
  console.log('✓ Test 5 passed: Preflight denial on SSRF proxy verified');

  // ---------------------------------------------------------------------------
  // Test 6: Playwright Context Integration with Stealth Mock
  // ---------------------------------------------------------------------------
  console.log('[Test 6] Validating stealth script injection in browser context...');
  let injectedScript = '';
  let capturedContextOptions: Record<string, unknown> | undefined;

  const mockContext: BrowserContextInstance = {
    async newPage(): Promise<PageInstance> {
      return {
        async goto() { return null; },
        async route() {},
        on() {},
        async waitForLoadState() {},
        async waitForTimeout() {},
        async evaluate<T>(_fn: () => T | Promise<T>): Promise<T> {
          const payload = {
            links: ['https://target.example.com/dashboard'],
            forms: [],
            frameworks: ['react'],
            scripts: [],
            rscPaths: [],
          };
          return payload as unknown as T;
        },
        async title() { return 'Test App'; },
        async close() {},
      };
    },
    async addInitScript(scriptInput) {
      injectedScript = typeof scriptInput === 'string' ? scriptInput : (scriptInput.content ?? '');
    },
    async close() {},
  };

  const mockBrowser: BrowserInstance = {
    async newContext(options) {
      capturedContextOptions = options;
      return mockContext;
    },
    async close() {},
  };

  const testLauncher: PlaywrightBrowserLauncher = {
    async launch(options) {
      assert.ok(
        options?.args?.includes('--disable-blink-features=AutomationControlled'),
        'Launcher must include AutomationControlled evasion flag'
      );
      return mockBrowser;
    },
  };

  const successResult = await adapter.discoverSpa({
    targetUrlOrDomain: 'https://target.example.com/app',
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    browserLauncher: testLauncher,
    browserProfileId: 'windows-chrome-131',
  });

  if (successResult.status !== 'success') {
    console.error('Test 6 unexpected failure result:', successResult);
  }
  assert.strictEqual(successResult.status, 'success');
  assert.ok(injectedScript.includes('navigator.webdriver'), 'Stealth init script must be injected');
  assert.ok(
    typeof capturedContextOptions?.userAgent === 'string' &&
      capturedContextOptions.userAgent.includes('Windows NT 10.0'),
    'Context options must adopt chosen profile'
  );
  console.log('✓ Test 6 passed: Playwright context integration verified');

  // ---------------------------------------------------------------------------
  // Test 7: Simulated DOM Execution of Evasion Script
  // ---------------------------------------------------------------------------
  console.log('[Test 7] Validating execution of evasion script in sandbox DOM...');
  const sandboxNavigator: Record<string, unknown> = {
    webdriver: true,
    languages: ['en'],
    plugins: [],
    platform: 'Unknown',
  };
  const sandboxWindow: Record<string, unknown> = {};

  const sandboxContext = vm.createContext({
    navigator: sandboxNavigator,
    window: sandboxWindow,
    Date,
    Notification: { permission: 'default' },
  });

  vm.runInContext(script, sandboxContext);

  // Assertions on sandboxed DOM
  assert.strictEqual(
    (sandboxContext as unknown as { navigator: { webdriver: unknown } }).navigator.webdriver,
    undefined,
    'navigator.webdriver must evaluate to undefined'
  );
  assert.ok(
    (sandboxContext as unknown as { window: { chrome: { runtime: unknown } } }).window.chrome?.runtime,
    'window.chrome.runtime must be simulated'
  );
  assert.deepStrictEqual(
    Array.from((sandboxContext as unknown as { navigator: { languages: string[] } }).navigator.languages),
    ['en-US', 'en'],
    'navigator.languages must be normalized'
  );
  console.log('✓ Test 7 passed: Simulated DOM evasions verified');

  console.log('\n--- ALL 7 PLAYWRIGHT STEALTH & AUTOMATION ASSERTIONS PASSED SUCCESSFULLY ---');
}

runPlaywrightStealthSmokeSuite().catch((err) => {
  console.error('Smoke test failed:', err);
  process.exit(1);
});
