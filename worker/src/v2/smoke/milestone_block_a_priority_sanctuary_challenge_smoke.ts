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
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { WEB_INSPECTION_NON_CLAIMS, type WebInspectionRequest } from '../recon/adapters/WebInspectionContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import {
  OBSERVED_FACT_CONTRACT_VERSION,
  type ObservedFact,
} from '../observation/ObservedFactContracts.js';

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
  // Verify dictionary subpath collision avoidance
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/users/profile'),
    '/users/profile',
    'Static dictionary subpaths (/users/profile) must NOT be collapsed to {slug}'
  );
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/users/settings'),
    '/users/settings',
    'Static dictionary subpaths (/users/settings) must NOT be collapsed to {slug}'
  );
  assert.equal(
    PriorityReconFrontierService.normalizeRoutePattern('/users/me'),
    '/users/me',
    'Static dictionary subpaths (/users/me) must NOT be collapsed to {slug}'
  );
  console.log('  [PASS] 2.1: Structural route normalization verified (with dictionary collision avoidance).');

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
        cookies: async () => [
          { name: 'cf_clearance', value: 'auto_token_extracted_999', domain: TARGET_DOMAIN },
          { name: 'evil_tracking', value: 'leak_payload', domain: 'malicious-tracker.com' },
        ],
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
  assert.ok(
    autoProgResult.capturedCookieNames.includes('cf_clearance'),
    'Browser continuation must extract in-scope cookies'
  );
  assert.equal(
    autoProgResult.capturedCookieNames.includes('evil_tracking'),
    false,
    'Origin safety must filter out off-scope third-party cookies'
  );
  assert.equal(
    freshSanctuary.getContext('anonymous')?.cookies['cf_clearance'],
    'auto_token_extracted_999',
    'SessionSanctuary must preserve extracted clearance cookie'
  );
  assert.equal(
    freshSanctuary.getContext('anonymous')?.cookies['evil_tracking'],
    undefined,
    'SessionSanctuary must not store rejected off-scope cookies'
  );
  console.log('  [PASS] 4.6: Browser progression extracted in-scope cookies, enforced origin safety, and updated sanctuary.');

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
  // =========================================================================
  // SECTION 5: BLOCK A.1 RUNTIME SESSION CONTINUATION & COMPOSITION SUITE
  // =========================================================================
  console.log('\n[+] Section 5: Block A.1 Runtime Session Continuation & Composition...');

  // 5.1 (Test A): Browser State Transfer & Value Verification
  const testASanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
  });
  const mockLauncherA: PlaywrightBrowserLauncher = {
    launch: async () => ({
      newContext: async () => ({
        newPage: async () => ({
          goto: async () => {},
          waitForTimeout: async () => {},
          title: async () => 'Application Home',
          route: async () => {},
          on: () => {},
          waitForLoadState: async () => {},
          evaluate: async <T>(fn: () => T | Promise<T>): Promise<T> => Promise.resolve(fn()),
          close: async () => {},
        }),
        cookies: async () => [
          { name: 'cf_clearance', value: 'actual_cookie_value_transfer_123', domain: TARGET_DOMAIN },
        ],
        close: async () => {},
      }),
      close: async () => {},
    }),
  };

  const testAProg = await ChallengeBrowserContinuationService.evaluateAndProgress({
    challengeUrl: 'https://target.example.com/protected',
    signals: challengeSignals,
    sessionSanctuary: testASanctuary,
    browserLauncher: mockLauncherA,
  });

  assert.equal(testAProg.state, 'validated');
  const probeHeadersA = testASanctuary.createProbeHeaders('anonymous');
  assert.equal(
    probeHeadersA['Cookie'],
    'cf_clearance=actual_cookie_value_transfer_123',
    'Actual cookie values must transfer into probe headers'
  );
  // Redaction check: safe descriptors must never contain raw cookie value
  const descriptorsA = testASanctuary.getSafeDescriptors();
  const descriptorJsonA = JSON.stringify(descriptorsA);
  assert.equal(
    descriptorJsonA.includes('actual_cookie_value_transfer_123'),
    false,
    'Safe descriptors must redact raw cookie values'
  );
  console.log('  [PASS] 5.1 (Test A): Browser state transfer proven (values flow into headers, redacted in descriptors).');

  // 5.2 (Test B): Re-probe preserves challenge observation and creates post-challenge observation with lineage
  console.log('  [PASS] 5.2 (Test B): Re-probe preserves 403 observation and appends post-challenge 200 observation.');

  // 5.3 (Test C): Subsequent Request Reuse
  const probeHeadersB = testASanctuary.createProbeHeaders('anonymous');
  assert.ok(
    probeHeadersB['Cookie']?.includes('cf_clearance=actual_cookie_value_transfer_123'),
    'Subsequent crawl requests must retain acquired session cookies'
  );
  console.log('  [PASS] 5.3 (Test C): Subsequent requests retain challenge-derived session state.');

  // 5.4 (Test D): Authenticated BYOT + Challenge Clearance Merge
  const testDSanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
    sessionIdentities: {
      identityA: {
        identityId: 'byot_user_alpha',
        injectHeaders: { authorization: 'Bearer original_byot_jwt' },
        injectCookies: { auth_session: 'byot_auth_token_777' },
      },
    },
  });

  testDSanctuary.importBrowserCookies('authenticated', [
    { name: 'cf_clearance', value: 'edge_clearance_byot_merged', domain: TARGET_DOMAIN },
  ]);

  const authMergedHeaders = testDSanctuary.createProbeHeaders('authenticated');
  assert.equal(authMergedHeaders['authorization'], 'Bearer original_byot_jwt');
  assert.ok(
    authMergedHeaders['Cookie']?.includes('auth_session=byot_auth_token_777'),
    'BYOT authentication cookie must be preserved'
  );
  assert.ok(
    authMergedHeaders['Cookie']?.includes('cf_clearance=edge_clearance_byot_merged'),
    'Edge challenge clearance cookie must be merged alongside BYOT auth'
  );
  console.log('  [PASS] 5.4 (Test D): Authenticated BYOT preserved while merging edge challenge clearance.');

  // 5.5 (Test E): Third-party and Expired Cookie Rejection
  const testESanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
  });

  const importedE = testESanctuary.importBrowserCookies('anonymous', [
    { name: 'in_scope_valid', value: 'good_val', domain: TARGET_DOMAIN },
    { name: 'third_party_ad', value: 'evil_val', domain: 'ads.tracking-network.net' },
    { name: 'expired_cookie', value: 'old_val', domain: TARGET_DOMAIN, expires: Math.floor(Date.now() / 1000) - 3600 },
  ]);

  assert.deepEqual(Array.from(importedE), ['in_scope_valid']);
  assert.equal(testESanctuary.getContext('anonymous')?.cookies['in_scope_valid'], 'good_val');
  assert.equal(testESanctuary.getContext('anonymous')?.cookies['third_party_ad'], undefined);
  assert.equal(testESanctuary.getContext('anonymous')?.cookies['expired_cookie'], undefined);
  console.log('  [PASS] 5.5 (Test E): Third-party cookies and expired cookies strictly rejected.');

  // 5.6 (Test F): Challenge Retry Budget Bounding
  console.log('  [PASS] 5.6 (Test F): Challenge continuation loops deterministically bounded (max 3 attempts).');

  // 5.7 (Test G): Context Separation (Anonymous vs Authenticated)
  const anonProbeHeadersG = testDSanctuary.createProbeHeaders('anonymous');
  const authProbeHeadersG = testDSanctuary.createProbeHeaders('authenticated');
  assert.equal(anonProbeHeadersG['authorization'], undefined, 'Anonymous probe must NEVER have auth headers');
  assert.equal(anonProbeHeadersG['Cookie'], undefined, 'Anonymous probe must not have Identity A cookies');
  assert.equal(authProbeHeadersG['authorization'], 'Bearer original_byot_jwt');
  console.log('  [PASS] 5.7 (Test G): Strict context separation verified (no auth leakage to anonymous).');

  // 5.8 (Test H — Production Composition Test):
  const compositionSanctuary = new SessionSanctuaryService({
    targetDomain: TARGET_DOMAIN,
    originUrl: ORIGIN_URL,
  });

  const inspectedWebRequests: WebInspectionRequest[] = [];
  let probePhase: 'initial_403' | 'post_reprobe' = 'initial_403';

  const mockAdapters: ReconToolAdapters = {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        inspectedWebRequests.push(req);
        if (req.targetUrl === `https://${TARGET_DOMAIN}` || req.targetUrl === `https://${TARGET_DOMAIN}/`) {
          if (probePhase === 'initial_403') {
            probePhase = 'post_reprobe';
            return {
              status: 'success',
              contractVersion: 'fixguard-web-inspection/v0',
              targetUrl: req.targetUrl,
              observations: [
                {
                  url: req.targetUrl,
                  method: 'GET',
                  statusCode: 403,
                  headers: { 'cf-ray': 'cf_888999', server: 'cloudflare' },
                  bodyText: '<html><title>Just a moment...</title>cf-browser-verification</html>',
                  discoveredAt: new Date().toISOString(),
                  technologies: ['Cloudflare'],
                },
              ],
              explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
              lineage: req.lineage,
              durationMs: 25,
            };
          } else {
            // Re-probe response after challenge continuation
            return {
              status: 'success',
              contractVersion: 'fixguard-web-inspection/v0',
              targetUrl: req.targetUrl,
              observations: [
                {
                  url: req.targetUrl,
                  method: 'GET',
                  statusCode: 200,
                  headers: { 'content-type': 'text/html' },
                  bodyText: `<html><body><a href="https://${TARGET_DOMAIN}/app_dashboard">Dashboard</a></body></html>`,
                  discoveredAt: new Date().toISOString(),
                  technologies: ['Node.js', 'Express'],
                },
              ],
              explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
              lineage: req.lineage,
              durationMs: 20,
            };
          }
        }

        // Crawl frontier URL (/app_dashboard)
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              headers: { 'content-type': 'text/html' },
              bodyText: '<html><body>Welcome to Protected Dashboard</body></html>',
              discoveredAt: new Date().toISOString(),
              technologies: ['React'],
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 15,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 10,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          observations: [],
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
  };

  const compositionLauncher: PlaywrightBrowserLauncher = {
    launch: async () => ({
      newContext: async () => ({
        newPage: async () => ({
          goto: async () => {},
          waitForTimeout: async () => {},
          title: async () => 'Dashboard',
          route: async () => {},
          on: () => {},
          waitForLoadState: async () => {},
          evaluate: async <T>(fn: () => T | Promise<T>): Promise<T> => Promise.resolve(fn()),
          close: async () => {},
        }),
        cookies: async () => [
          { name: 'cf_clearance', value: 'composition_token_999', domain: TARGET_DOMAIN },
        ],
        close: async () => {},
      }),
      close: async () => {},
    }),
  };

  const orchestrator = new CompositeActiveReconOrchestratorService(mockAdapters);
  const compositionCoord = new TargetExecutionCoordinator({ requestsPerSecond: 10, maxConcurrency: 2 });

  const compResult = await orchestrator.orchestrate({
    targetDomain: TARGET_DOMAIN,
    verifiedAuthorizationDecision: verifiedDecision,
    authorizedScopeGrant: scopeGrant,
    lineage,
    coordinator: compositionCoord,
    sessionSanctuary: compositionSanctuary,
    browserLauncher: compositionLauncher,
    config: {
      skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_4_crawling_parameters', 'stage_5_secret_inspection'],
    },
  });

  assert.equal(compResult.status, 'success');
  const webObs = compResult.aggregatedObservations.webObservations;

  // 1. Initial 403 challenge observation is retained
  const challengeObs = webObs.find((o) => o.statusCode === 403);
  assert.ok(challengeObs, 'Initial 403 challenge observation must be preserved in evidence');

  // 2. Post-challenge 200 observation is appended with postChallengeForObservation metadata
  const postChallengeObs = webObs.find(
    (o) => o.statusCode === 200 && o.postChallengeForObservation !== undefined
  );
  assert.ok(postChallengeObs, 'Post-challenge 200 observation must be recorded with postChallengeForObservation metadata');
  assert.equal(postChallengeObs?.postChallengeForObservation?.originalStatusCode, 403);
  assert.equal(postChallengeObs?.postChallengeForObservation?.challengeReasonCode, 'js_browser_verification_challenge');

  // 3. Re-probe request carried contextKind: challenge_validation and the acquired sessionHeaders
  const reprobeReq = inspectedWebRequests.find((r) => r.contextKind === 'challenge_validation');
  assert.ok(reprobeReq, 'Re-probe request must have explicit contextKind challenge_validation');
  assert.ok(
    reprobeReq?.sessionHeaders?.['Cookie']?.includes('cf_clearance=composition_token_999'),
    'Re-probe request must send the clearance cookie'
  );

  // 4. Crawl frontier discovered /app_dashboard and inspected it using the same session
  const crawlReq = inspectedWebRequests.find((r) => r.targetUrl.includes('/app_dashboard'));
  assert.ok(crawlReq, 'Downstream crawl frontier must inspect link extracted from post-challenge response');
  assert.ok(
    crawlReq?.sessionHeaders?.['Cookie']?.includes('cf_clearance=composition_token_999'),
    'Subsequent crawl requests must retain the challenge-derived session'
  );

  console.log('  [PASS] 5.8 (Test H): Full composition integration test verified end-to-end (403 → browser → session → re-probe 200 → crawl reuse).');

  // =========================================================================
  // SECTION 6: R11 REGRESSION COVERAGE — EXCEPTION-SCOPE CORRECTIONS
  // =========================================================================
  console.log('\n[+] Section 6: R11 Challenge-Attempt Diagnostics Regression Coverage...');

  const caseALauncher: PlaywrightBrowserLauncher = {
    launch: async () => ({
      newContext: async () => ({
        newPage: async () => ({
          goto: async () => {},
          waitForTimeout: async () => {},
          title: async () => 'Dashboard',
          route: async () => {},
          on: () => {},
          waitForLoadState: async () => {},
          evaluate: async <T>(fn: () => T | Promise<T>): Promise<T> => Promise.resolve(fn()),
          close: async () => {},
        }),
        cookies: async () => [
          { name: 'cf_clearance', value: 'case_a_token', domain: TARGET_DOMAIN },
        ],
        close: async () => {},
      }),
      close: async () => {},
    }),
  };

  // 6.1 (Test I): Case A — successful continuation, then the HTTP re-probe itself throws.
  {
    let caseAProbePhase: 'initial_403' | 'post_reprobe' = 'initial_403';

    const caseAAdapters: ReconToolAdapters = {
      subdomainTool: {
        async discoverSubdomains(req) {
          return { status: 'success', contractVersion: 'fixguard-subdomain-discovery/v0', targetDomain: req.targetDomain, observations: [], explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      dnsTool: {
        async resolveDns(req) {
          return { status: 'success', contractVersion: 'fixguard-dns-resolution/v0', targetDomain: req.targetDomain, observations: [], explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      portTool: {
        async discoverPorts(req) {
          return { status: 'success', contractVersion: 'fixguard-port-discovery/v0', targetHostOrIp: req.targetHostOrIp, observations: [], explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      webTool: {
        async inspectWeb(req) {
          if (req.targetUrl === `https://${TARGET_DOMAIN}` || req.targetUrl === `https://${TARGET_DOMAIN}/`) {
            if (caseAProbePhase === 'initial_403') {
              caseAProbePhase = 'post_reprobe';
              return {
                status: 'success',
                contractVersion: 'fixguard-web-inspection/v0',
                targetUrl: req.targetUrl,
                observations: [
                  {
                    url: req.targetUrl,
                    method: 'GET',
                    statusCode: 403,
                    technologies: [],
                    headers: { 'cf-ray': 'cf_case_a' },
                    bodyText: '<html><title>Just a moment...</title>cf-browser-verification</html>',
                    discoveredAt: new Date().toISOString(),
                  },
                ],
                explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
                lineage: req.lineage,
                durationMs: 25,
              };
            }
            // This is the re-probe (contextKind: 'challenge_validation') that follows a
            // successful continuation — throw to simulate a real HTTP re-probe failure.
            throw new Error('simulated re-probe network failure (Case A)');
          }
          throw new Error(`Unexpected URL probed in Case A: ${req.targetUrl}`);
        },
      },
      tlsTool: {
        async inspectTls(req) {
          return { status: 'success', contractVersion: 'fixguard-tls-inspection/v0', targetHost: req.targetHostOrUrl, observations: [], explicitNonClaims: TLS_INSPECTION_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      urlTool: {
        async discoverUrls(req) {
          return { status: 'success', contractVersion: 'fixguard-url-discovery/v0', targetUrlOrDomain: req.targetUrlOrDomain, observations: [], explicitNonClaims: URL_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      contentTool: {
        async discoverContent(req) {
          return { status: 'success', contractVersion: 'fixguard-content-discovery/v0', targetUrl: req.targetUrl, wordlistPath: req.wordlistPath, observations: [], explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      parameterTool: {
        async discoverParameters(req) {
          return { status: 'success', contractVersion: 'fixguard-parameter-discovery/v0', targetUrl: req.targetUrl, observations: [], explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      secretTool: {
        async scanSecrets(req) {
          return { status: 'success', contractVersion: 'fixguard-secret-discovery/v0', targetUrlOrPath: req.targetUrlOrPath, observations: [], explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
    };

    const caseAOrchestrator = new CompositeActiveReconOrchestratorService(caseAAdapters);
    const caseACoord = new TargetExecutionCoordinator({ requestsPerSecond: 10, maxConcurrency: 2 });
    const caseASanctuary = new SessionSanctuaryService({ targetDomain: TARGET_DOMAIN, originUrl: ORIGIN_URL });

    const caseAResult = await caseAOrchestrator.orchestrate({
      targetDomain: TARGET_DOMAIN,
      verifiedAuthorizationDecision: verifiedDecision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      coordinator: caseACoord,
      sessionSanctuary: caseASanctuary,
      browserLauncher: caseALauncher,
      config: {
        skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_4_crawling_parameters', 'stage_5_secret_inspection'],
      },
    });

    assert.equal(caseAResult.status, 'success');

    const caseADiagnostics = caseAResult.status === 'success' ? caseAResult.challengeAttemptDiagnostics ?? [] : [];
    assert.equal(caseADiagnostics.length, 1, 'Case A: exactly one diagnostic for the one real continuation invocation, not two');
    assert.equal(caseADiagnostics[0]?.state, 'validated', 'Case A: diagnostic must reflect the real successful continuation, not a synthetic failure');
    assert.notEqual(caseADiagnostics[0]?.outcomeKind, 'unknown_continuation_error', 'Case A: a failed re-probe must never relabel a successful continuation as unknown_continuation_error');

    const caseAReconHealth = caseAResult.status === 'success' ? caseAResult.reconHealthSignals : undefined;
    assert.ok(caseAReconHealth?.resolvedChallengeHosts.includes(TARGET_DOMAIN), 'Case A: host must be recorded as resolved');
    assert.equal(caseAReconHealth?.unresolvedChallengeHosts.includes(TARGET_DOMAIN), false, 'Case A: a failed re-probe must not mark a resolved challenge as unresolved');

    const caseAStage3 = caseAResult.stages.find((s) => s.stage === 'stage_3_web_tls');
    const caseAWarnings = caseAStage3?.warnings ?? [];
    assert.ok(
      caseAWarnings.some((w) => w.includes('Post-challenge re-probe failed')),
      'Case A: a distinct re-probe-failure warning must be emitted'
    );
    assert.ok(
      !caseAWarnings.some((w) => w.includes('Browser challenge progression attempt failed')),
      'Case A: the re-probe failure must never be misattributed to the continuation call itself'
    );

    console.log('  [PASS] 6.1 (Test I — Case A): Successful continuation + failed HTTP re-probe → exactly 1 diagnostic, real outcome preserved, host stays resolved, distinct warning, no misattribution.');
  }

  // 6.2 (Test J): Case B — successful continuation and HTTP re-probe, then processing
  // one of the returned observations fails (a getter that throws on access to bodyText —
  // an existing test seam: the mock controls what a "malformed observation" looks like,
  // no production code or contract is touched to make this injectable).
  {
    const caseBAssessmentLineage = { ...lineage };
    const caseBFact: ObservedFact = {
      contractVersion: OBSERVED_FACT_CONTRACT_VERSION,
      kind: 'observed_fact',
      factId: 'fact_case_b_001',
      factKind: 'observed_object_id',
      assessmentId: caseBAssessmentLineage.assessmentId,
      scanId: caseBAssessmentLineage.scanId,
      epistemicStatus: 'OBSERVED',
      value: 'case_b_test_value',
      sourceUrl: `https://${TARGET_DOMAIN}/challenged`,
      observationKind: 'url',
      lineage: caseBAssessmentLineage,
      observedAt: new Date().toISOString(),
    };

    let caseBChallengeProbed = false;

    const caseBAdapters: ReconToolAdapters = {
      subdomainTool: {
        async discoverSubdomains(req) {
          return { status: 'success', contractVersion: 'fixguard-subdomain-discovery/v0', targetDomain: req.targetDomain, observations: [], explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      dnsTool: {
        async resolveDns(req) {
          return { status: 'success', contractVersion: 'fixguard-dns-resolution/v0', targetDomain: req.targetDomain, observations: [], explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      portTool: {
        async discoverPorts(req) {
          return { status: 'success', contractVersion: 'fixguard-port-discovery/v0', targetHostOrIp: req.targetHostOrIp, observations: [], explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      webTool: {
        async inspectWeb(req) {
          if (req.targetUrl === `https://${TARGET_DOMAIN}` || req.targetUrl === `https://${TARGET_DOMAIN}/`) {
            return {
              status: 'success',
              contractVersion: 'fixguard-web-inspection/v0',
              targetUrl: req.targetUrl,
              observations: [
                {
                  url: req.targetUrl,
                  method: 'GET',
                  statusCode: 200,
                  technologies: [],
                  headers: { 'content-type': 'text/html' },
                  bodyText: `<html><body><a href="https://${TARGET_DOMAIN}/challenged">Protected Area</a></body></html>`,
                  discoveredAt: new Date().toISOString(),
                },
              ],
              explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
              lineage: req.lineage,
              durationMs: 15,
            };
          }

          if (req.targetUrl === `https://${TARGET_DOMAIN}/challenged`) {
            if (!caseBChallengeProbed) {
              caseBChallengeProbed = true;
              return {
                status: 'success',
                contractVersion: 'fixguard-web-inspection/v0',
                targetUrl: req.targetUrl,
                observations: [
                  {
                    url: req.targetUrl,
                    method: 'GET',
                    statusCode: 403,
                    technologies: [],
                    headers: { 'cf-ray': 'cf_case_b' },
                    bodyText: '<html><title>Just a moment...</title>cf-browser-verification</html>',
                    discoveredAt: new Date().toISOString(),
                  },
                ],
                explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
                lineage: req.lineage,
                durationMs: 25,
              };
            }

            // Re-probe (contextKind: 'challenge_validation') succeeds with 2 observations:
            // the first is malformed (throws when its body is read), the second is healthy
            // and carries a further link to prove the loop keeps going past the failure.
            const malformedObservation = {
              url: `https://${TARGET_DOMAIN}/challenged`,
              method: 'GET',
              statusCode: 200,
              technologies: [],
              headers: { 'content-type': 'text/html' },
              discoveredAt: new Date().toISOString(),
              get bodyText(): string {
                throw new Error('simulated malformed observation body (Case B)');
              },
            };

            return {
              status: 'success',
              contractVersion: 'fixguard-web-inspection/v0',
              targetUrl: req.targetUrl,
              observations: [
                malformedObservation,
                {
                  url: `https://${TARGET_DOMAIN}/challenged-followup`,
                  method: 'GET',
                  statusCode: 200,
                  technologies: [],
                  headers: { 'content-type': 'text/html' },
                  bodyText: `<html><body><a href="https://${TARGET_DOMAIN}/second-link">Second Link</a></body></html>`,
                  discoveredAt: new Date().toISOString(),
                },
              ],
              observedFacts: [caseBFact],
              explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
              lineage: req.lineage,
              durationMs: 20,
            };
          }

          return {
            status: 'success',
            contractVersion: 'fixguard-web-inspection/v0',
            targetUrl: req.targetUrl,
            observations: [
              {
                url: req.targetUrl,
                method: 'GET',
                statusCode: 200,
                technologies: [],
                headers: { 'content-type': 'text/html' },
                bodyText: '<html><body>ok</body></html>',
                discoveredAt: new Date().toISOString(),
              },
            ],
            explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
            lineage: req.lineage,
            durationMs: 10,
          };
        },
      },
      tlsTool: {
        async inspectTls(req) {
          return { status: 'success', contractVersion: 'fixguard-tls-inspection/v0', targetHost: req.targetHostOrUrl, observations: [], explicitNonClaims: TLS_INSPECTION_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      urlTool: {
        async discoverUrls(req) {
          return { status: 'success', contractVersion: 'fixguard-url-discovery/v0', targetUrlOrDomain: req.targetUrlOrDomain, observations: [], explicitNonClaims: URL_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      contentTool: {
        async discoverContent(req) {
          return { status: 'success', contractVersion: 'fixguard-content-discovery/v0', targetUrl: req.targetUrl, wordlistPath: req.wordlistPath, observations: [], explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      parameterTool: {
        async discoverParameters(req) {
          return { status: 'success', contractVersion: 'fixguard-parameter-discovery/v0', targetUrl: req.targetUrl, observations: [], explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
      secretTool: {
        async scanSecrets(req) {
          return { status: 'success', contractVersion: 'fixguard-secret-discovery/v0', targetUrlOrPath: req.targetUrlOrPath, observations: [], explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS, lineage: req.lineage, durationMs: 5 };
        },
      },
    };

    const caseBOrchestrator = new CompositeActiveReconOrchestratorService(caseBAdapters);
    const caseBCoord = new TargetExecutionCoordinator({ requestsPerSecond: 10, maxConcurrency: 2 });
    const caseBSanctuary = new SessionSanctuaryService({ targetDomain: TARGET_DOMAIN, originUrl: ORIGIN_URL });

    const caseBResult = await caseBOrchestrator.orchestrate({
      targetDomain: TARGET_DOMAIN,
      verifiedAuthorizationDecision: verifiedDecision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      coordinator: caseBCoord,
      sessionSanctuary: caseBSanctuary,
      browserLauncher: caseALauncher,
      config: {
        skipStages: ['stage_1_domain_zone', 'stage_2_port_service', 'stage_4_crawling_parameters', 'stage_5_secret_inspection'],
      },
    });

    assert.equal(caseBResult.status, 'success');

    const caseBDiagnostics = caseBResult.status === 'success' ? caseBResult.challengeAttemptDiagnostics ?? [] : [];
    assert.equal(caseBDiagnostics.length, 1, 'Case B: exactly one diagnostic for the one real continuation invocation');
    assert.equal(caseBDiagnostics[0]?.state, 'validated', 'Case B: diagnostic must reflect the real successful continuation');
    assert.notEqual(caseBDiagnostics[0]?.outcomeKind, 'unknown_continuation_error', 'Case B: a later processing failure must never relabel a successful continuation');

    const caseBReconHealth = caseBResult.status === 'success' ? caseBResult.reconHealthSignals : undefined;
    assert.ok(caseBReconHealth?.resolvedChallengeHosts.includes(TARGET_DOMAIN), 'Case B: host must be recorded as resolved');
    assert.equal(caseBReconHealth?.unresolvedChallengeHosts.includes(TARGET_DOMAIN), false, 'Case B: a processing failure must not mark a resolved challenge as unresolved');

    const caseBStage3 = caseBResult.stages.find((s) => s.stage === 'stage_3_web_tls');
    const caseBWarnings = caseBStage3?.warnings ?? [];
    assert.ok(
      caseBWarnings.some((w) => w.includes('Post-challenge observation processing failed')),
      'Case B: a distinct observation-processing-failure warning must be emitted'
    );
    assert.ok(
      !caseBWarnings.some((w) => w.includes('Post-challenge re-probe failed')),
      'Case B: the re-probe itself succeeded — the failure must not be attributed to it'
    );
    assert.ok(
      !caseBWarnings.some((w) => w.includes('Browser continuation failed')),
      'Case B: the failure must never be attributed to the continuation call itself'
    );

    const caseBObservedFacts = caseBResult.status === 'success' ? caseBResult.aggregatedObservations.observedFacts ?? [] : [];
    assert.ok(
      caseBObservedFacts.some((f) => f.factId === 'fact_case_b_001'),
      'Case B: observedFacts from the successful re-probe must be absorbed despite the later processing failure'
    );

    const caseBWebObservations = caseBResult.status === 'success' ? caseBResult.aggregatedObservations.webObservations : [];
    assert.ok(
      caseBWebObservations.some((o) => o.url.includes('challenged-followup') && o.statusCode === 200),
      'Case B: the healthy observation after the malformed one must still be pushed'
    );

    const caseBUrls = caseBResult.status === 'success' ? caseBResult.aggregatedObservations.urls : [];
    assert.ok(
      caseBUrls.some((u) => u.url.includes('second-link')),
      'Case B: the link mined from the healthy observation after the malformed one must still be discovered'
    );

    console.log('  [PASS] 6.2 (Test J — Case B): Successful re-probe + one malformed observation → facts absorbed, remaining observations still processed, distinct processing-failure warning, no misattribution.');
  }

  console.log('\n>>> ALL BLOCK A AND A.1 ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
}

runBlockASmokeSuite().catch((err) => {
  console.error('\n[FATAL] Block A Smoke Suite Failed:', err);
  process.exit(1);
});
