/**
 * Phase D1 — Discovery → Detection bridge smoke (hermetic).
 *
 * 1. Next.js fixture + multiple OBSERVED endpoints → primaryProbeUrls include app routes,
 *    exclude /_next/static from heavy probes.
 * 2. Next.js tech → PHPSESSID session-fixation probe suppressed with explainable reason.
 * 3. Identical 404/404 IDOR (same body hash) → secure_target_abstained, no draft.
 * 4. Orchestrated path spy: detection transport receives OBSERVED app endpoint URLs.
 */

import assert from 'node:assert';
import process from 'node:process';
import { createHash } from 'node:crypto';

import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { URL_DISCOVERY_NON_CLAIMS } from '../recon/adapters/UrlDiscoveryContracts.js';
import { CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import type { IdorHttpProbeTransport, HttpProbeRequest } from '../detection/DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import { runIdorDifferentialDetection } from '../detection/IdorDifferentialDetectionService.js';
import {
  buildDetectionTargetsFromRecon,
  evaluatePhpSessionFixationTechGate,
  isIdenticalErrorDifferential,
} from '../detection/DetectionTargetBridge.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import type { RawExecutionOutput } from '../core/ExecutionContracts.js';

const APP_PATHS = [
  '/',
  '/login',
  '/perfil',
  '/arcade',
  '/carrera/93kpw',
] as const;

const NEXT_BUNDLE = 'https://example.com/_next/static/chunks/main-app.js';

function emptyAggregated(): AggregatedReconObservations {
  return {
    subdomains: [],
    dnsRecords: [],
    ports: [],
    webObservations: [],
    tlsCertificates: [],
    urls: [],
    content: [],
    parameters: [],
    secrets: [],
  };
}

function createNextJsFixtureObservations(): AggregatedReconObservations {
  const now = new Date().toISOString();
  const body = [
    '<!DOCTYPE html><html><head>',
    '<script src="/_next/static/chunks/main-app.js"></script>',
    '<script>self.__NEXT_DATA__={}</script>',
    '</head><body>',
    '<a href="/login">Login</a>',
    '<a href="/perfil">Perfil</a>',
    '<a href="/arcade">Arcade</a>',
    '<a href="/carrera/93kpw">Carrera</a>',
    '</body></html>',
  ].join('');

  return {
    ...emptyAggregated(),
    dnsRecords: [
      {
        domain: 'example.com',
        recordType: 'A',
        values: ['93.184.216.34'],
        discoveredAt: now,
      },
    ],
    webObservations: [
      {
        url: 'https://example.com/',
        method: 'GET',
        statusCode: 200,
        headers: {
          'content-type': 'text/html',
          vary: 'RSC, Next-Router-State-Tree',
          server: 'Vercel',
          'x-matched-path': '/',
        },
        bodyText: body,
        technologies: ['Next.js', 'React', 'Vercel'],
        resolvedIp: '93.184.216.34',
        discoveredAt: now,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    urls: [
      ...APP_PATHS.map((p) => ({
        url: `https://example.com${p === '/' ? '/' : p}`,
        host: 'example.com',
        path: p,
        sources: ['html_link_extraction'],
        freshness: 'live' as const,
        sourceReliability: 'direct_observation' as const,
        discoveredAt: now,
      })),
      {
        url: NEXT_BUNDLE,
        host: 'example.com',
        path: '/_next/static/chunks/main-app.js',
        sources: ['html_link_extraction'],
        freshness: 'live' as const,
        sourceReliability: 'direct_observation' as const,
        discoveredAt: now,
      },
    ],
  };
}

function createAllAvailableRunner(): ProcessRunner {
  return {
    async execute(req): Promise<RawExecutionOutput> {
      if (req.binary === 'which') {
        return {
          stdout: `/usr/local/bin/${req.args[0] ?? 'tool'}\n`,
          stderr: '',
          exitCode: 0,
          durationMs: 1,
          timedOut: false,
        };
      }
      return {
        stdout: 'version: 1.0.0\n',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
        timedOut: false,
      };
    },
  };
}

function createBridgeAwareReconAdapters(
  fixture: AggregatedReconObservations,
  invocationCount: { count: number }
): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: fixture.dnsRecords,
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-port-discovery/v0',
          targetHostOrIp: req.targetHostOrIp,
          observations: [],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: fixture.webObservations,
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: fixture.urls,
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        invocationCount.count += 1;
        return {
          status: 'success' as const,
          contractVersion: 'fixguard-content-discovery/v0' as const,
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath ?? '/dev/null',
          observations: [] as const,
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-secret-discovery/v0',
          targetUrlOrPath: req.targetUrlOrPath,
          observations: [],
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
  };
}

function createScopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_d1_bridge_001',
    scanId: 'scan_d1_bridge_001',
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Phase D1 detection bridge smoke',
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
      allowedDomains: ['example.com'],
      allowedHosts: ['example.com', '93.184.216.34'],
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST', 'OPTIONS'],
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

async function runPhaseD1DetectionBridgeSmoke(): Promise<void> {
  console.log('[phaseD1_detection_bridge_smoke] Starting Discovery→Detection bridge suite...');

  // -------------------------------------------------------------------------
  // 1. Bridge selects OBSERVED app endpoints; excludes static bundles
  // -------------------------------------------------------------------------
  console.log('-> Test 1: Bridge feeds OBSERVED app endpoints; excludes /_next/static...');
  const fixture = createNextJsFixtureObservations();
  const bridge = buildDetectionTargetsFromRecon({
    targetDomain: 'example.com',
    aggregatedObservations: fixture,
  });

  assert.ok(bridge.appEndpoints.length >= 4, 'Expected multiple OBSERVED app endpoints');
  const paths = new Set(bridge.appEndpoints.map((e) => e.path));
  assert.ok(paths.has('/login'), 'Must include /login');
  assert.ok(paths.has('/perfil'), 'Must include /perfil');
  assert.ok(paths.has('/arcade'), 'Must include /arcade');
  assert.ok(paths.has('/carrera/93kpw'), 'Must include /carrera/93kpw');
  assert.ok(
    !bridge.primaryProbeUrls.some((u) => u.includes('/_next/static/')),
    'Heavy probe URLs must exclude /_next/static bundles'
  );
  assert.ok(
    bridge.staticBundleUrls.some((u) => u.includes('/_next/static/')),
    'Static bundles must still be retained separately'
  );
  assert.ok(
    bridge.primaryProbeUrls.some((u) => u.includes('/login')),
    'Detection primaryProbeUrls must include app route /login'
  );
  assert.ok(
    bridge.idorCandidates.every((c) => !c.endpointUrl.includes('/api/user/1')),
    'Must not invent /api/user/1 when OBSERVED app endpoints exist'
  );
  assert.ok(
    bridge.idorCandidates.some((c) => c.endpointUrl.includes('/login') || c.endpointUrl.includes('/carrera')),
    'IDOR candidates must target OBSERVED app endpoints'
  );
  console.log('  [PASS] Bridge selects app endpoints and excludes static bundles from heavy probes.');

  // -------------------------------------------------------------------------
  // 2. Next.js → PHPSESSID session fixation suppressed
  // -------------------------------------------------------------------------
  console.log('-> Test 2: Next.js tech suppresses PHPSESSID session-fixation probe...');
  assert.strictEqual(bridge.ecosystemProfile.spaFramework, 'nextjs');
  assert.strictEqual(bridge.phpSessionFixationGate.suppress, true);
  assert.ok(
    bridge.phpSessionFixationGate.reasonCode.startsWith('php_session_probe_suppressed'),
    `Expected suppressed reason, got ${bridge.phpSessionFixationGate.reasonCode}`
  );
  const gateDirect = evaluatePhpSessionFixationTechGate(bridge.ecosystemProfile, bridge.detectedTechnologies);
  assert.strictEqual(gateDirect.suppress, true);
  assert.ok(
    bridge.suppressions.some((s) => s.detectorKind === 'session_fixation' && s.reasonCode === gateDirect.reasonCode),
    'Suppression must be recorded with explainable reason'
  );
  console.log(`  [PASS] PHPSESSID probe suppressed (${gateDirect.reasonCode}).`);

  // -------------------------------------------------------------------------
  // 3. Identical 404/404 IDOR → abstain, no draft
  // -------------------------------------------------------------------------
  console.log('-> Test 3: Identical 404/404 IDOR abstains with no draft...');
  assert.strictEqual(
    isIdenticalErrorDifferential({
      baselineStatusCode: 404,
      validationStatusCode: 404,
      baselineBodyHash: 'abc',
      validationBodyHash: 'abc',
    }),
    true
  );
  assert.strictEqual(
    isIdenticalErrorDifferential({
      baselineStatusCode: 200,
      validationStatusCode: 200,
      baselineBodyHash: 'abc',
      validationBodyHash: 'abc',
    }),
    false
  );

  const scopeGrant = createScopeGrant();
  const nowIso = new Date().toISOString();
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'assess_d1_bridge_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_d1_bridge_001',
      authorizedActor: { actorId: 'usr_d1_bridge', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant,
    },
    nowIso
  );
  assert.strictEqual(established.status, 'established');
  if (established.status !== 'established') {
    throw new Error('authorization setup failed');
  }

  const notFoundBody = '<html><body>Not Found</body></html>';
  const identical404Transport: IdorHttpProbeTransport = async () => ({
    statusCode: 404,
    headers: { 'content-type': 'text/html' },
    bodyText: notFoundBody,
    responseTimeMs: 1,
  });

  const idorResult = await runIdorDifferentialDetection({
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'idor_differential_detection_request',
    detectionId: 'det_d1_bridge_idor_404',
    assessmentId: 'assess_d1_bridge_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_d1_bridge_001',
    actorId: 'usr_d1_bridge',
    endpointUrl: 'https://example.com/carrera/93kpw',
    resourceParamName: 'id',
    baselineResourceId: '1',
    identityA: { identityId: 'id_a' },
    identityB: { identityId: 'id_b' },
    verifiedAuthorizationDecision: established.decision,
    scopeGrant,
    transport: identical404Transport,
    dnsResolver: async () => ['93.184.216.34'],
  });

  assert.strictEqual(idorResult.status, 'secure_target_abstained');
  assert.strictEqual(idorResult.reasonCode, 'identical_error_responses_no_differential');
  assert.strictEqual(idorResult.evidenceDraft, undefined);
  assert.strictEqual(idorResult.finding, undefined);
  const expectedHash = createHash('sha256').update(notFoundBody).digest('hex');
  assert.strictEqual(idorResult.baselineSnapshot?.bodyHash, expectedHash);
  assert.strictEqual(idorResult.validationSnapshot?.bodyHash, expectedHash);
  console.log('  [PASS] Identical 404/404 IDOR abstained; no bogus draft.');

  // -------------------------------------------------------------------------
  // 4. Orchestrated path: spy asserts OBSERVED URLs reach detection transport
  // -------------------------------------------------------------------------
  console.log('-> Test 4: Orchestrated detection transport receives OBSERVED app URLs...');
  const probedUrls: string[] = [];
  const spyTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest) => {
    probedUrls.push(req.url);
    // Never claim PHPSESSID fixation: return Set-Cookie regeneration if cookie present.
    const cookie = req.headers['Cookie'] ?? req.headers['cookie'] ?? '';
    if (typeof cookie === 'string' && cookie.toLowerCase().includes('phpsessid=')) {
      throw new Error('PHPSESSID session-fixation probe must be suppressed on Next.js');
    }
    return {
      statusCode: 200,
      headers: {
        'content-type': 'text/html',
        'content-security-policy': "default-src 'self'",
        'x-frame-options': 'DENY',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'strict-transport-security': 'max-age=31536000',
        'permissions-policy': 'geolocation=()',
      },
      bodyText: '<html><body>ok</body></html>',
      responseTimeMs: 1,
    };
  };

  const inv = { count: 0 };
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createBridgeAwareReconAdapters(fixture, inv),
    httpTransport: spyTransport,
    dnsResolver: async (host: string) => (host === 'example.com' ? ['93.184.216.34'] : []),
    availabilityService: new ReconToolAvailabilityService(createAllAvailableRunner()),
  });

  const start = await service.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_d1_bridge_orch',
    seedUrls: ['https://example.com/login', 'https://example.com/perfil'],
  });
  const record = await service.awaitAssessment(start.assessmentId);
  assert.ok(record);
  assert.strictEqual(record.status, 'completed', `Expected completed, got ${record.status}: ${record.error ?? ''}`);

  const probedJoined = probedUrls.join('\n');
  assert.ok(
    probedUrls.some((u) => u.includes('/login')),
    `Detection must probe OBSERVED /login; probed=${probedUrls.slice(0, 20).join(', ')}`
  );
  assert.ok(
    probedUrls.some((u) => u.includes('/perfil') || u.includes('/arcade') || u.includes('/carrera')),
    'Detection must probe at least one additional OBSERVED app endpoint'
  );
  assert.ok(
    !probedJoined.includes('PHPSESSID=') &&
      !(record.degradedCapabilities ?? []).some((d) => d.includes('php_session_probe_suppressed') === false && d.includes('session_fixation') && !d.includes('suppressed')),
    'PHPSESSID must not be injected on Next.js'
  );
  assert.ok(
    (record.degradedCapabilities ?? []).some((d) =>
      d.includes('detection_suppressed:session_fixation:php_session_probe_suppressed')
    ),
    `Expected session_fixation suppression notice in degradedCapabilities, got ${JSON.stringify(record.degradedCapabilities)}`
  );
  assert.strictEqual(
    (record.pendingEvidenceDrafts ?? []).filter(
      (d) => d.differentialContext?.detectionKind === 'session_fixation'
    ).length,
    0,
    'No PHPSESSID session_fixation drafts on Next.js'
  );
  assert.strictEqual(
    (record.pendingEvidenceDrafts ?? []).filter(
      (d) => d.differentialContext?.detectionKind === 'idor_access_control'
    ).length,
    0,
    'No bogus IDOR drafts when differentials are empty/secure'
  );
  console.log('  [PASS] Orchestrated detection received OBSERVED endpoints; PHPSESSID gated.');

  console.log('\n[✔] ALL phaseD1_detection_bridge_smoke ASSERTIONS PASSED.');
}

runPhaseD1DetectionBridgeSmoke().catch((err) => {
  console.error('[!] phaseD1_detection_bridge_smoke FAILED:', err);
  process.exit(1);
});
