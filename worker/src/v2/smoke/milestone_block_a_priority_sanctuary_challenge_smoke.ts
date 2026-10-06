/**
 * FixGuard V2 — Block A Consolidated Smoke Test Suite
 * (Priority Recon Frontier + Session Sanctuary + Auth Differential Matrix + Challenge-Aware Continuation)
 *
 * Verifies all Block A requirements:
 * 1. Session Sanctuary: isolation, secret redaction, canary health, expiration tracking.
 * 2. Priority Recon Frontier: deterministic scoring, route normalization, explanation, saturation limit.
 * 3. Auth Differential Matrix: anonymous vs authenticated general comparison, closed classifications.
 * 4. Challenge-Aware Continuation: WAF vs auth 403 vs rate limit, browser progression, HITL operator flow.
 */

import assert from 'node:assert/strict';
import { SessionSanctuaryService } from '../session/SessionSanctuaryService.js';
import {
  redactSensitiveHeaders,
  redactSensitiveCookies,
} from '../session/SessionSanctuaryContracts.js';
import { PriorityReconFrontierService } from '../recon/frontier/PriorityReconFrontierService.js';
import { runAuthDifferentialMatrix } from '../differential/AuthDifferentialMatrixService.js';
import { ChallengeClassifierService } from '../challenge/ChallengeClassifierService.js';
import { ChallengeBrowserContinuationService } from '../challenge/ChallengeBrowserContinuationService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  ByotSessionIdentityBundle,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { PlaywrightBrowserLauncher } from '../recon/adapters/BrowserAutomationContracts.js';

const TARGET_DOMAIN = 'target.example.com';
const ORIGIN_URL = `https://${TARGET_DOMAIN}/`;

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_block_a_001',
    scanId: 'scan_block_a_001',
    issuedAt: '2026-10-05T12:00:00.000Z',
    expiresAt: '2026-10-06T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: TARGET_DOMAIN },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized test for Block A smoke suite',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [TARGET_DOMAIN],
      allowedHosts: [TARGET_DOMAIN],
      allowedOrigins: [`https://${TARGET_DOMAIN}`],
      allowedMethods: ['GET', 'HEAD'],
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

async function runBlockASmokeSuite(): Promise<void> {
  console.log('>>> RUNNING FIXGUARD V2 BLOCK A CONSOLIDATED SMOKE SUITE <<<');

  const nowIso = '2026-10-05T12:00:00.000Z';
  const scopeGrant = createScopeGrant();
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_block_a_test',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'dec_block_a_001',
      authorizedActor: { actorId: 'usr_operator', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );

  if (authRes.status !== 'established') {
    throw new Error(`Auth decision failed to establish: ${authRes.reasonCode}`);
  }
  const verifiedDecision = authRes.decision;

  const lineage = {
    assessmentId: 'asm_block_a_test',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: verifiedDecision.authorizationDecisionId,
    actorId: 'usr_operator',
  };

  // =========================================================================
  // SECTION 1: SESSION SANCTUARY
  // =========================================================================
  console.log('\n[+] Section 1: Session Sanctuary Isolation & Canary Health...');

  const SECRET_COOKIE_VALUE = 'secret_session_token_1234567890abcdef';
  const SECRET_BEARER_VALUE = 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret';

  const bundle: ByotSessionIdentityBundle = {
    identityA: {
      identityId: 'operator_session_a',
      injectHeaders: {
        authorization: SECRET_BEARER_VALUE,
        'x-custom-tenant': 'tenant_99',
      },
      injectCookies: {
        session_id: SECRET_COOKIE_VALUE,
      },
    },
  };

  const sanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
    sessionIdentities: bundle,
  });

  // 1.1: Isolation test
  const anonCtx = sanctuary.getContext('anonymous');
  const authCtx = sanctuary.getContext('authenticated');
  assert.ok(anonCtx, 'Anonymous context must be initialized');
  assert.ok(authCtx, 'Authenticated context must be initialized');

  assert.equal(Object.keys(anonCtx.cookies).length, 0, 'Anonymous context must have 0 cookies');
  assert.equal(Object.keys(anonCtx.headers).length, 0, 'Anonymous context must have 0 headers');
  assert.equal(authCtx.cookies['session_id'], SECRET_COOKIE_VALUE, 'Auth context holds session cookie');

  const anonProbeHeaders = sanctuary.createProbeHeaders('anonymous');
  const authProbeHeaders = sanctuary.createProbeHeaders('authenticated');
  assert.equal(anonProbeHeaders['Cookie'], undefined, 'Anon probe headers must not include cookie');
  assert.ok(authProbeHeaders['Cookie']?.includes(SECRET_COOKIE_VALUE), 'Auth probe headers must include cookie');
  assert.equal(authProbeHeaders['authorization'], SECRET_BEARER_VALUE, 'Auth probe headers must include authorization');
  console.log('  [PASS] 1.1: Context isolation verified (anonymous has 0 auth material).');

  // 1.2: Secret redaction test
  const safeDescriptors = sanctuary.getSafeDescriptors();
  assert.equal(safeDescriptors.length, 2);
  const descriptorJson = JSON.stringify(safeDescriptors);
  assert.ok(!descriptorJson.includes(SECRET_COOKIE_VALUE), 'Raw cookie must never appear in safe descriptors');
  assert.ok(!descriptorJson.includes(SECRET_BEARER_VALUE), 'Raw token must never appear in safe descriptors');

  const redactedHeaders = redactSensitiveHeaders(authCtx.headers);
  assert.equal(redactedHeaders['authorization'], '[REDACTED]', 'Sensitive header must be redacted');
  assert.equal(redactedHeaders['x-custom-tenant'], 'tenant_99', 'Non-sensitive header preserved');

  const redactedCookies = redactSensitiveCookies(authCtx.cookies);
  assert.equal(redactedCookies['session_id'], '[REDACTED]', 'Sensitive cookie must be redacted');
  console.log('  [PASS] 1.2: Secret redaction verified (zero raw credentials leaked).');

  // 1.3: Canary health validation (valid session)
  const validMockTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => ({
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    bodyText: JSON.stringify({ user: 'operator', status: 'active' }),
    responseTimeMs: 35,
  });

  const canaryValid = await sanctuary.validateSessionHealth('authenticated', validMockTransport);
  assert.equal(canaryValid.healthState, 'valid');
  assert.equal(canaryValid.authenticationState, 'authenticated');
  assert.equal(sanctuary.getContext('authenticated')?.healthState, 'valid');
  console.log('  [PASS] 1.3: Valid canary response correctly transitions health to valid.');

  // 1.4: Canary health validation (expired session / 401)
  const expiredMockTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => ({
    statusCode: 401,
    headers: { 'content-type': 'application/json' },
    bodyText: JSON.stringify({ error: 'token_expired' }),
    responseTimeMs: 25,
  });

  const canaryExpired = await sanctuary.validateSessionHealth('authenticated', expiredMockTransport);
  assert.equal(canaryExpired.healthState, 'expired');
  assert.equal(canaryExpired.authenticationState, 'auth_lost');
  assert.equal(sanctuary.getContext('authenticated')?.healthState, 'expired');
  console.log('  [PASS] 1.4: Expired 401 response correctly marks health as expired / auth_lost.');

  // 1.5: Canary health validation (login redirect)
  const loginRedirectTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => ({
    statusCode: 302,
    headers: { location: '/login?session_expired=1' },
    bodyText: '',
    responseTimeMs: 15,
  });

  const canaryRedirect = await sanctuary.validateSessionHealth('authenticated', loginRedirectTransport);
  assert.equal(canaryRedirect.healthState, 'expired');
  console.log('  [PASS] 1.5: Login redirect correctly identifies expired session.');

  // =========================================================================
  // SECTION 2: PRIORITY RECON FRONTIER
  // =========================================================================
  console.log('\n[+] Section 2: Priority Recon Frontier & Information-Gain Scoring...');

  // 2.1: Structural route normalization
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/api/v1/tenants/123/users/456'),
    '/api/v1/tenants/{id}/users/{id}',
    'Should normalize numeric IDs into {id}'
  );
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/users/550e8400-e29b-41d4-a716-446655440000/profile'),
    '/users/{uuid}/profile',
    'Should normalize UUIDs into {uuid}'
  );
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/catalog?page=1'),
    '/catalog',
    'Should normalize query parameters out of route pattern'
  );
  console.log('  [PASS] 2.1: Structural route normalization verified.');

  // 2.2: Deterministic scoring and prioritization
  const frontier = new PriorityReconFrontierService({ maxUrlsPerPattern: 3 });

  // Enqueue a repetitive pagination URL
  frontier.enqueue({
    url: 'https://target.example.com/blog?page=1',
    host: 'target.example.com',
    path: '/blog',
    query: 'page=1',
    source: 'html_link_extraction',
    depth: 1,
  });

  // Enqueue a second pagination URL for the same pattern
  frontier.enqueue({
    url: 'https://target.example.com/blog?page=2',
    host: 'target.example.com',
    path: '/blog',
    query: 'page=2',
    source: 'html_link_extraction',
    depth: 1,
  });

  // Enqueue a critical API route with parameters from Playwright network
  frontier.enqueue({
    url: 'https://target.example.com/api/v2/orders?tenant=99&limit=10',
    host: 'target.example.com',
    path: '/api/v2/orders',
    query: 'tenant=99&limit=10',
    source: 'playwright_network',
    depth: 1,
  });

  // Enqueue an auth route
  frontier.enqueue({
    url: 'https://target.example.com/admin/settings',
    host: 'target.example.com',
    path: '/admin/settings',
    source: 'html_link_extraction',
    depth: 1,
  });

  // The first item popped MUST be the API/parameterized route with highest information gain, NOT the first-enqueued blog!
  const firstSelected = frontier.next();
  assert.ok(firstSelected, 'Item must be selected');
  assert.equal(firstSelected.url, 'https://target.example.com/api/v2/orders?tenant=99&limit=10');
  assert.ok(firstSelected.priorityScore >= 0.7, 'API route must receive high/critical priority score');
  assert.ok(firstSelected.priorityReason.includes('API/RPC endpoint'), 'Reason must mention API/RPC endpoint');
  console.log(`  [PASS] 2.2: Priority queue selected high-value API route first (Score: ${firstSelected.priorityScore}).`);

  // 2.3: Pattern saturation limit
  frontier.enqueue({
    url: 'https://target.example.com/blog?page=3',
    host: 'target.example.com',
    path: '/blog',
    query: 'page=3',
    source: 'html_link_extraction',
    depth: 1,
  });
  // 4th URL for /blog exceeds maxUrlsPerPattern of 3
  const enqueued4th = frontier.enqueue({
    url: 'https://target.example.com/blog?page=4',
    host: 'target.example.com',
    path: '/blog',
    query: 'page=4',
    source: 'html_link_extraction',
    depth: 1,
  });
  assert.equal(enqueued4th, false, '4th repetitive URL for the same pattern must be dropped to preserve crawl budget');
  const diagnostics = frontier.getDiagnosticSummary();
  assert.ok(diagnostics.totalSkippedPatternSaturation >= 1, 'Diagnostics must record pattern saturation skips');
  console.log('  [PASS] 2.3: Pattern saturation successfully halted repetitive pagination links.');

  // =========================================================================
  // SECTION 3: ANONYMOUS VS AUTHENTICATED DIFFERENTIAL MATRIX
  // =========================================================================
  console.log('\n[+] Section 3: Anonymous vs Authenticated Differential Matrix...');

  // Reset sanctuary to valid for differential tests
  const freshSanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
    sessionIdentities: bundle,
  });

  const differentialEndpoints = [
    'https://target.example.com/public/about',
    'https://target.example.com/api/v1/profile',
    'https://target.example.com/internal/restricted',
    'https://target.example.com/api/v1/unprotected_admin',
  ];

  const diffMockTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    const hasAuthCookie = req.headers['Cookie']?.includes(SECRET_COOKIE_VALUE);

    if (req.url.endsWith('/public/about')) {
      // Both return identical 200
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><body>About FixGuard</body></html>',
        responseTimeMs: 20,
      };
    }

    if (req.url.endsWith('/api/v1/profile')) {
      // Anon: 401, Auth: 200
      if (!hasAuthCookie) {
        return {
          statusCode: 401,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({ error: 'unauthorized' }),
          responseTimeMs: 15,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ id: 101, username: 'operator' }),
        responseTimeMs: 30,
      };
    }

    if (req.url.endsWith('/internal/restricted')) {
      // Both 403
      return {
        statusCode: 403,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ error: 'forbidden' }),
        responseTimeMs: 15,
      };
    }

    if (req.url.endsWith('/api/v1/unprotected_admin')) {
      // Both 200 with identical admin JSON!
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ adminKey: 'active', role: 'admin' }),
        responseTimeMs: 25,
      };
    }

    return {
      statusCode: 404,
      headers: {},
      bodyText: 'not found',
      responseTimeMs: 10,
    };
  };

  const matrixResult = await runAuthDifferentialMatrix({
    targetDomain: TARGET_DOMAIN,
    endpointUrls: differentialEndpoints,
    sessionSanctuary: freshSanctuary,
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    lineage,
    transport: diffMockTransport,
    maxEndpoints: 10,
  });

  assert.equal(matrixResult.totalEvaluated, 4, 'Should evaluate all 4 endpoints');

  // Verify /public/about -> expected_auth_difference (public identical)
  const aboutResult = matrixResult.results.find((r) => r.endpointUrl.endsWith('/public/about'));
  assert.ok(aboutResult);
  assert.equal(aboutResult.classification, 'expected_auth_difference');
  console.log('  [PASS] 3.1: Public identical route classified as expected_auth_difference (no false positive).');

  // Verify /api/v1/profile -> authentication_required
  const profileResult = matrixResult.results.find((r) => r.endpointUrl.endsWith('/api/v1/profile'));
  assert.ok(profileResult);
  assert.equal(profileResult.classification, 'authentication_required');
  assert.ok(profileResult.observedFact, 'Must emit anon_session_get_delta fact');
  assert.equal(profileResult.observedFact.factKind, 'anon_session_get_delta');
  console.log('  [PASS] 3.2: Protected endpoint classified as authentication_required with ObservedFact.');

  // Verify /internal/restricted -> protected
  const restrictedResult = matrixResult.results.find((r) => r.endpointUrl.endsWith('/internal/restricted'));
  assert.ok(restrictedResult);
  assert.equal(restrictedResult.classification, 'protected');
  console.log('  [PASS] 3.3: Dual denial endpoint classified as protected.');

  // Verify /api/v1/unprotected_admin -> potential_authorization_boundary
  const adminResult = matrixResult.results.find((r) => r.endpointUrl.endsWith('/api/v1/unprotected_admin'));
  assert.ok(adminResult);
  assert.equal(adminResult.classification, 'potential_authorization_boundary');
  console.log('  [PASS] 3.4: Unprotected sensitive API endpoint flagged as potential_authorization_boundary.');

  // 3.5: Missing authenticated context -> inconclusive
  const emptySanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
  });
  const unauthMatrixResult = await runAuthDifferentialMatrix({
    targetDomain: TARGET_DOMAIN,
    endpointUrls: ['https://target.example.com/api/test'],
    sessionSanctuary: emptySanctuary,
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    lineage,
    transport: diffMockTransport,
  });
  assert.equal(unauthMatrixResult.results[0]?.classification, 'inconclusive');
  assert.equal(unauthMatrixResult.results[0]?.reasonCode, 'missing_authenticated_context');
  console.log('  [PASS] 3.5: Missing authenticated context cleanly classified as inconclusive.');

  // =========================================================================
  // SECTION 4: CHALLENGE CLASSIFICATION & BROWSER CONTINUATION
  // =========================================================================
  console.log('\n[+] Section 4: Challenge Classification & Browser Continuation...');

  // 4.1: Normal 200 response
  const normalClass = ChallengeClassifierService.classify({
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    bodyText: '<html>Hello World</html>',
  });
  assert.equal(normalClass.verdict, 'no_waf_observed');
  assert.equal(normalClass.isBlocking, false);
  console.log('  [PASS] 4.1: Normal 200 classified as no_waf_observed / non-blocking.');

  // 4.2: Application 403 authorization denial (NOT WAF!)
  const app403Class = ChallengeClassifierService.classify({
    statusCode: 403,
    headers: { 'content-type': 'application/json' },
    bodyText: JSON.stringify({ error: 'unauthorized', message: 'You do not have permission to view this' }),
  });
  assert.equal(app403Class.verdict, 'application_reachable');
  assert.equal(app403Class.isBlocking, false);
  assert.equal(app403Class.reasonCode, 'application_authorization_denied');
  console.log('  [PASS] 4.2: Application 403 correctly distinguished from WAF challenge.');

  // 4.3: HTTP 429 rate limit
  const rateLimitClass = ChallengeClassifierService.classify({
    statusCode: 429,
    headers: { 'retry-after': '60' },
    bodyText: 'Too many requests, slow down.',
  });
  assert.equal(rateLimitClass.verdict, 'rate_limited');
  assert.equal(rateLimitClass.isBlocking, true);
  assert.equal(rateLimitClass.requiresBrowser, false);
  console.log('  [PASS] 4.3: HTTP 429 rate limit correctly distinguished without claiming WAF.');

  // 4.4: Cloudflare / Vercel JS browser challenge
  const challengeSignals = {
    statusCode: 403,
    headers: { 'cf-ray': '89012345abcdef', server: 'cloudflare' },
    bodyText: '<html><title>Just a moment...</title><body>Checking your browser before accessing. cf-browser-verification</body></html>',
  };
  const challengeClass = ChallengeClassifierService.classify(challengeSignals);
  assert.equal(challengeClass.verdict, 'browser_challenge');
  assert.equal(challengeClass.isBlocking, true);
  assert.equal(challengeClass.requiresBrowser, true);
  assert.equal(challengeClass.requiresOperatorHitl, false);
  console.log('  [PASS] 4.4: Cloudflare JS verification correctly classified as browser_challenge.');

  // 4.5: Interactive Turnstile / CAPTCHA challenge
  const interactiveChallengeSignals = {
    statusCode: 403,
    headers: { server: 'cloudflare' },
    bodyText: '<html><title>Attention Required</title><body>Please solve the challenge / Turnstile checkbox to proceed.</body></html>',
  };
  const interactiveClass = ChallengeClassifierService.classify(interactiveChallengeSignals);
  assert.equal(interactiveClass.verdict, 'browser_challenge');
  assert.equal(interactiveClass.requiresOperatorHitl, true);
  console.log('  [PASS] 4.5: Interactive Turnstile/CAPTCHA correctly requiresOperatorHitl.');

  // 4.6: Mock Browser Continuation (Automated Progression Succeeded)
  let mockPageTitle = 'Dashboard - In-Scope Application';
  const mockLauncher: PlaywrightBrowserLauncher = {
    launch: async () => ({
      newContext: async () => ({
        newPage: async () => ({
          goto: async () => {},
          waitForTimeout: async () => {},
          title: async () => mockPageTitle,
          route: async () => {},
          on: () => {},
          waitForLoadState: async () => {},
          evaluate: async <T>(fn: () => T | Promise<T>): Promise<T> => Promise.resolve(fn()),
          close: async () => {},
        }),
        close: async () => {},
      }),
      close: async () => {},
    }),
  };

  const autoProgResult = await ChallengeBrowserContinuationService.evaluateAndProgress({
    challengeUrl: 'https://target.example.com/protected_route',
    signals: challengeSignals,
    sessionSanctuary: freshSanctuary,
    browserLauncher: mockLauncher,
  });

  assert.equal(autoProgResult.state, 'validated');
  assert.equal(autoProgResult.applicationReachable, true);
  assert.equal(freshSanctuary.getContext('anonymous')?.challengeState, 'resolved');
  console.log('  [PASS] 4.6: Browser progression automatically navigated past challenge and updated sanctuary.');

  // 4.7: Mock Browser Continuation (Interactive HITL Pause)
  mockPageTitle = 'Attention Required';
  const hitlProgResult = await ChallengeBrowserContinuationService.evaluateAndProgress({
    challengeUrl: 'https://target.example.com/turnstile_route',
    signals: interactiveChallengeSignals,
    sessionSanctuary: freshSanctuary,
    browserLauncher: mockLauncher,
  });

  assert.equal(hitlProgResult.state, 'waiting_for_operator');
  assert.equal(hitlProgResult.applicationReachable, false);
  assert.ok(hitlProgResult.operatorMessage?.includes('Operator assistance required'));
  console.log('  [PASS] 4.7: Interactive challenge successfully paused at waiting_for_operator (HITL boundary).');

  // 4.8: Operator completes challenge callback & resumes
  const resumedResult = await ChallengeBrowserContinuationService.resumeAfterOperatorCompletion(
    {
      challengeId: 'chl_001',
      confirmedCookies: { cf_clearance: 'cleared_token_abc' },
      operatorNotes: 'Completed Turnstile in interactive session',
    },
    'https://target.example.com/turnstile_route',
    freshSanctuary,
    async () => ({
      statusCode: 200,
      headers: {},
      bodyText: '<html>Welcome to Target App</html>',
      responseTimeMs: 25,
    })
  );

  assert.equal(resumedResult.state, 'validated');
  assert.equal(resumedResult.applicationReachable, true);
  assert.equal(freshSanctuary.getContext('anonymous')?.cookies['cf_clearance'], 'cleared_token_abc');
  console.log('  [PASS] 4.8: Operator completion callback validated application reachability and stored cookies.');

  console.log('\n>>> ALL 20 BLOCK A ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
}

runBlockASmokeSuite().catch((err) => {
  console.error('\n[FATAL] Block A Smoke Suite Failed:', err);
  process.exit(1);
});
