/**
 * Phase D1 — Discovery Depth & URL Seeding + Next.js fingerprint + HTML route extraction smoke suite.
 *
 * Hermetic assertions:
 * 1. Deep seed URL lands in ASG as OBSERVED (direct_observation / live).
 * 2. Out-of-scope seed fails closed with seed_out_of_scope before recon network.
 * 3. Vary: RSC header fingerprints Next.js with high confidence (unit).
 * 4. Seed HTTP probe with Vary: RSC / X-Matched-Path → TargetProfile Next.js high confidence.
 * 5. Missing CLI → explicit degraded_mode_missing_binary notice (not silent empty success).
 * 6. HTML body with <a href="/dashboard"> → /dashboard OBSERVED in ASG; Next.js bundle retained.
 * 7. External / out-of-scope links in HTML are excluded from ASG.
 */

import assert from 'node:assert';
import process from 'node:process';

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
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { TechnologyFingerprintService } from '../recon/analysis/TechnologyFingerprintService.js';
import { UnauthorizedGatewayError } from '../api/ApiErrors.js';
import type { EndpointNode } from '../attack-surface/AttackSurfaceContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import type { RawExecutionOutput } from '../core/ExecutionContracts.js';

const DEEP_SEED = 'https://example.com/deep/admin/settings';
const NEXT_SEED = 'https://example.com/dashboard';
const OUT_OF_SCOPE_SEED = 'https://evil-out-of-scope.example/steal';

function createMockReconAdapters(invocationCount: { count: number }): ReconToolAdapters {
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
          observations: [
            {
              domain: req.targetDomain,
              recordType: 'A',
              values: ['93.184.216.34'],
              discoveredAt: new Date().toISOString(),
            },
          ],
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
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              technologies: [],
              discoveredAt: new Date().toISOString(),
            },
          ],
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
          observations: [],
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

function createAllAvailableRunner(): ProcessRunner {
  return {
    async execute(): Promise<RawExecutionOutput> {
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

/** Marks selected binaries as missing; others report available. */
function createAvailabilityRunner(missing: ReadonlySet<string>): ProcessRunner {
  return {
    async execute(req): Promise<RawExecutionOutput> {
      const binary = req.binary;
      if (binary === 'which') {
        const tool = req.args[0] ?? '';
        if (missing.has(tool)) {
          return {
            stdout: '',
            stderr: '',
            exitCode: 1,
            durationMs: 1,
            timedOut: false,
          };
        }
        return {
          stdout: `/usr/local/bin/${tool}\n`,
          stderr: '',
          exitCode: 0,
          durationMs: 1,
          timedOut: false,
        };
      }
      if (missing.has(binary)) {
        throw new Error(`Command not found: ${binary}. Ensure it is installed and in PATH.`);
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

function createService(
  invocationCount: { count: number },
  options?: {
    httpTransport?: IdorHttpProbeTransport;
    availabilityRunner?: ProcessRunner;
    /** When true, omit custom reconAdapters so default stubs + loud degradation apply. */
    useDefaultReconAdapters?: boolean;
  }
): OrchestratedAssessmentApplicationService {
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockDnsResolver = async (host: string): Promise<string[]> => {
    if (host === 'example.com') return ['93.184.216.34'];
    return [];
  };
  const mockHttpTransport: IdorHttpProbeTransport =
    options?.httpTransport ??
    (async () => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html></html>',
      responseTimeMs: 1,
    }));
  const mockAvailabilityService = new ReconToolAvailabilityService(
    options?.availabilityRunner ?? createAllAvailableRunner()
  );

  return new OrchestratedAssessmentApplicationService({
    repository,
    ...(options?.useDefaultReconAdapters
      ? {}
      : { reconAdapters: createMockReconAdapters(invocationCount) }),
    httpTransport: mockHttpTransport,
    dnsResolver: mockDnsResolver,
    availabilityService: mockAvailabilityService,
  });
}

async function runPhaseD1Smoke(): Promise<void> {
  console.log('[phaseD1_seeding_discovery_smoke] Starting Phase D1 seeding + Next.js fingerprint suite...');

  // ---------------------------------------------------------------------------
  // 1. Deep seed URL → ASG endpoint with OBSERVED provenance
  // ---------------------------------------------------------------------------
  console.log('-> Test 1: Deep seed URL appears in ASG as OBSERVED...');
  const inv1 = { count: 0 };
  const service1 = createService(inv1);
  const start1 = await service1.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_phase_d1_seed',
    seedUrls: [DEEP_SEED],
    seedPaths: ['/deep/from-path'],
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        'stage_3_web_tls',
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record1 = await service1.awaitAssessment(start1.assessmentId);
  assert.ok(record1, 'Assessment record must exist');
  assert.strictEqual(record1.status, 'completed', `Expected completed, got ${record1.status}: ${record1.error ?? ''}`);

  const asg = record1.attackSurfaceGraph;
  assert.ok(asg, 'Attack surface graph must be present');

  const deepEndpoint = asg.nodes.find(
    (n): n is EndpointNode =>
      n.kind === 'endpoint' && n.metadata.url === DEEP_SEED
  );
  assert.ok(deepEndpoint, `ASG must contain seeded endpoint ${DEEP_SEED}`);
  assert.strictEqual(
    deepEndpoint.epistemicStatus,
    'OBSERVED',
    `Seeded endpoint must be OBSERVED, got ${deepEndpoint.epistemicStatus}`
  );
  assert.strictEqual(deepEndpoint.provenance.sourceKind, 'recon_observation');
  assert.strictEqual(deepEndpoint.provenance.sourceId, DEEP_SEED);

  const pathSeedEndpoint = asg.nodes.find(
    (n): n is EndpointNode =>
      n.kind === 'endpoint' && n.metadata.url === 'https://example.com/deep/from-path'
  );
  assert.ok(pathSeedEndpoint, 'ASG must contain path-derived seed endpoint');
  assert.strictEqual(pathSeedEndpoint.epistemicStatus, 'OBSERVED');

  const profileHasDeep = record1.profile?.endpoints.some((e) => e.url === DEEP_SEED);
  assert.ok(profileHasDeep, 'TargetProfile endpoints must include deep seed URL');
  console.log('  [PASS] Deep seed URL and seedPath are OBSERVED endpoints in ASG + profile.');

  // ---------------------------------------------------------------------------
  // 2. Out-of-scope seed → fail-closed before recon network
  // ---------------------------------------------------------------------------
  console.log('-> Test 2: Out-of-scope seed fails closed before network...');
  const inv2 = { count: 0 };
  const service2 = createService(inv2);

  let denied = false;
  try {
    await service2.startAssessment({
      targetDomain: 'example.com',
      actorId: 'usr_phase_d1_oos',
      seedUrls: [OUT_OF_SCOPE_SEED],
    });
  } catch (err: unknown) {
    denied = true;
    assert.ok(
      err instanceof UnauthorizedGatewayError,
      `Expected UnauthorizedGatewayError, got ${err instanceof Error ? err.name : typeof err}`
    );
    assert.strictEqual(err.reasonCode, 'seed_out_of_scope');
  }
  assert.ok(denied, 'Out-of-scope seed must throw');
  assert.strictEqual(
    inv2.count,
    0,
    'Out-of-scope seed must not dispatch any recon tool invocations'
  );
  console.log('  [PASS] Out-of-scope seed rejected with seed_out_of_scope and zero recon network.');

  // ---------------------------------------------------------------------------
  // 3. Vary: RSC → Next.js high-confidence fingerprint (unit)
  // ---------------------------------------------------------------------------
  console.log('-> Test 3: Vary: RSC fingerprints Next.js...');
  const fingerprint = new TechnologyFingerprintService();
  const rscResult = fingerprint.analyze({
    url: 'https://example.com/',
    headers: {
      vary: 'RSC, Next-Router-State-Tree, Next-Router-Prefetch',
    },
  });
  const nextTech = rscResult.technologies.find((t) => t.name === 'Next.js');
  assert.ok(nextTech, 'Next.js must be detected from Vary: RSC');
  assert.strictEqual(nextTech.confidence, 'high');
  assert.ok(
    nextTech.detectionSignal.toLowerCase().includes('vary'),
    `Detection signal should cite Vary header: ${nextTech.detectionSignal}`
  );
  assert.strictEqual(rscResult.ecosystemProfile.spaFramework, 'nextjs');

  const matchedPathResult = fingerprint.analyze({
    url: 'https://example.com/dashboard',
    headers: {
      'x-matched-path': '/dashboard',
    },
  });
  const nextFromMatched = matchedPathResult.technologies.find((t) => t.name === 'Next.js');
  assert.ok(nextFromMatched, 'Next.js must be detected from X-Matched-Path');
  assert.strictEqual(nextFromMatched.confidence, 'high');
  console.log('  [PASS] Vary: RSC and X-Matched-Path produce high-confidence Next.js fingerprints.');

  // ---------------------------------------------------------------------------
  // 4. Seed HTTP probe → TargetProfile Next.js (high confidence)
  // ---------------------------------------------------------------------------
  console.log('-> Test 4: Seed probe with Vary: RSC populates TargetProfile Next.js...');
  const inv4 = { count: 0 };
  const nextAwareTransport: IdorHttpProbeTransport = async (req) => {
    if (req.url === NEXT_SEED || req.url.includes('/dashboard')) {
      return {
        statusCode: 200,
        headers: {
          'content-type': 'text/html',
          vary: 'RSC, Next-Router-State-Tree',
          'x-matched-path': '/dashboard',
          'x-powered-by': 'Next.js',
        },
        bodyText: '<html><script id="__NEXT_DATA__" type="application/json">{}</script></html>',
        responseTimeMs: 1,
      };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' } as Readonly<Record<string, string>>,
      bodyText: '<html><title>root</title></html>',
      responseTimeMs: 1,
    };
  };

  // Use default recon adapters so Stage 3 webTool performs real gated HTTP + header capture.
  const service4 = createService(inv4, {
    httpTransport: nextAwareTransport,
    useDefaultReconAdapters: true,
  });
  const start4 = await service4.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_phase_d1_next_seed',
    seedUrls: [NEXT_SEED],
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        // stage_3_web_tls runs — seed probe + fingerprint enrichment
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record4 = await service4.awaitAssessment(start4.assessmentId);
  assert.ok(record4, 'Assessment record must exist for seed probe test');
  assert.strictEqual(
    record4.status,
    'completed',
    `Expected completed, got ${record4.status}: ${record4.error ?? ''}`
  );

  const profile4 = record4.profile;
  assert.ok(profile4, 'TargetProfile must be present after seed probe');
  assert.ok(
    profile4.technologies.includes('Next.js'),
    `technologies must include Next.js, got: ${profile4.technologies.join(', ')}`
  );
  const detectedNext = profile4.detectedTechnologies?.find((t) => t.name === 'Next.js');
  assert.ok(detectedNext, 'detectedTechnologies must include Next.js');
  assert.strictEqual(detectedNext.confidence, 'high');
  assert.strictEqual(profile4.ecosystemProfile?.spaFramework, 'nextjs');

  const seedWebObs = profile4.rawObservations?.find(
    (o): o is { url: string; headers?: Record<string, string>; freshness?: string } =>
      typeof o === 'object' &&
      o !== null &&
      'url' in o &&
      (o as { url: unknown }).url === NEXT_SEED
  );
  assert.ok(seedWebObs, 'rawObservations must include seed web probe');
  assert.strictEqual(seedWebObs.freshness, 'live');
  console.log('  [PASS] Seed probe headers enrich TargetProfile with high-confidence Next.js.');

  // ---------------------------------------------------------------------------
  // 5. Missing CLI → loud degraded_mode_missing_binary (not silent empty success)
  // ---------------------------------------------------------------------------
  console.log('-> Test 5: Missing CLI records degraded_mode_missing_binary...');
  const inv5 = { count: 0 };
  const missingNaabu = new Set(['naabu']);
  const service5 = createService(inv5, {
    availabilityRunner: createAvailabilityRunner(missingNaabu),
  });
  const start5 = await service5.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_phase_d1_degraded',
    config: {
      skipStages: [
        'stage_1_domain_zone',
        // stage_2_port_service runs — naabu marked missing → loud degradation
        'stage_3_web_tls',
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record5 = await service5.awaitAssessment(start5.assessmentId);
  assert.ok(record5, 'Assessment record must exist for degraded-mode test');
  assert.strictEqual(
    record5.status,
    'completed',
    `Expected completed (loud degrade), got ${record5.status}: ${record5.error ?? ''}`
  );

  const degraded = record5.degradedCapabilities ?? [];
  assert.ok(
    degraded.some((d) => d === 'degraded_mode_missing_binary: naabu'),
    `degradedCapabilities must list naabu, got: ${JSON.stringify(degraded)}`
  );

  const stage2 = record5.stages.find((s) => s.stage === 'stage_2_port_service');
  assert.ok(stage2, 'stage_2_port_service must have run');
  assert.ok(
    (stage2.warnings ?? []).some((w) => w === 'degraded_mode_missing_binary: naabu'),
    `stage_2 warnings must include degraded_mode_missing_binary: naabu, got: ${JSON.stringify(stage2.warnings)}`
  );

  const summary5 = await service5.getSummary(start5.assessmentId);
  assert.ok(
    (summary5.degradedCapabilities ?? []).some(
      (d) => d === 'degraded_mode_missing_binary: naabu'
    ),
    'Assessment summary must surface degradedCapabilities'
  );
  console.log('  [PASS] Missing CLI surfaces degraded_mode_missing_binary on stages + summary.');

  // ---------------------------------------------------------------------------
  // 6. HTML link extraction → /dashboard OBSERVED; Next.js bundle retained
  // ---------------------------------------------------------------------------
  console.log('-> Test 6: HTML <a href="/dashboard"> extracts OBSERVED ASG endpoint...');
  const ROOT_WITH_LINKS_HTTPS = 'https://example.com';
  const ROOT_WITH_LINKS_HTTP = 'http://example.com';
  const DASHBOARD_EXTRACTED = 'https://example.com/dashboard';
  const NEXT_BUNDLE = 'https://example.com/_next/static/chunks/main.js';
  const HTML_WITH_INTERNAL_LINKS = [
    '<html><body>',
    '<a href="/dashboard">Dashboard</a>',
    '<script src="/_next/static/chunks/main.js"></script>',
    '<img src="/logo.png" />',
    '<link rel="stylesheet" href="/styles.css" />',
    '</body></html>',
  ].join('');

  const inv6 = { count: 0 };
  const linkAwareTransport: IdorHttpProbeTransport = async (req) => {
    const normalized = req.url.replace(/\/$/, '') || req.url;
    if (normalized === ROOT_WITH_LINKS_HTTPS || normalized === ROOT_WITH_LINKS_HTTP) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: HTML_WITH_INTERNAL_LINKS,
        responseTimeMs: 1,
      };
    }
    if (req.url === DASHBOARD_EXTRACTED || req.url === NEXT_BUNDLE || req.url.startsWith('http://example.com/dashboard') || req.url.includes('/_next/static/chunks/main.js')) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><title>extracted</title></html>',
        responseTimeMs: 1,
      };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html></html>',
      responseTimeMs: 1,
    };
  };

  const service6 = createService(inv6, {
    httpTransport: linkAwareTransport,
    useDefaultReconAdapters: true,
  });
  const start6 = await service6.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_phase_d1_html_extract',
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        // stage_3_web_tls runs — root body capture + 1-hop HTML extraction
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record6 = await service6.awaitAssessment(start6.assessmentId);
  assert.ok(record6, 'Assessment record must exist for HTML extraction test');
  assert.strictEqual(
    record6.status,
    'completed',
    `Expected completed, got ${record6.status}: ${record6.error ?? ''}`
  );

  const asg6 = record6.attackSurfaceGraph;
  assert.ok(asg6, 'Attack surface graph must be present after HTML extraction');

  const dashboardEndpoint = asg6.nodes.find(
    (n): n is EndpointNode =>
      n.kind === 'endpoint' && n.metadata.url === DASHBOARD_EXTRACTED
  );
  assert.ok(dashboardEndpoint, `ASG must contain extracted endpoint ${DASHBOARD_EXTRACTED}`);
  assert.strictEqual(
    dashboardEndpoint.epistemicStatus,
    'OBSERVED',
    `Extracted /dashboard must be OBSERVED, got ${dashboardEndpoint.epistemicStatus}`
  );
  assert.strictEqual(dashboardEndpoint.provenance.sourceKind, 'recon_observation');
  assert.strictEqual(dashboardEndpoint.provenance.sourceId, DASHBOARD_EXTRACTED);

  const nextBundleEndpoint = asg6.nodes.find(
    (n): n is EndpointNode =>
      n.kind === 'endpoint' && n.metadata.url === NEXT_BUNDLE
  );
  assert.ok(
    nextBundleEndpoint,
    `ASG must retain Next.js bundle route ${NEXT_BUNDLE}`
  );
  assert.strictEqual(nextBundleEndpoint.epistemicStatus, 'OBSERVED');

  const mediaRejected = asg6.nodes.some(
    (n) =>
      n.kind === 'endpoint' &&
      (n.metadata.url === 'https://example.com/logo.png' ||
        n.metadata.url === 'https://example.com/styles.css')
  );
  assert.ok(!mediaRejected, 'Media assets (.png / .css) must not enter endpoint inventory');

  const profileHasDashboard = record6.profile?.endpoints.some(
    (e) => e.url === DASHBOARD_EXTRACTED
  );
  assert.ok(profileHasDashboard, 'TargetProfile endpoints must include extracted /dashboard');
  console.log('  [PASS] HTML extraction registers /dashboard and Next.js bundle as OBSERVED; media rejected.');

  // ---------------------------------------------------------------------------
  // 7. External / OOS links in HTML are excluded
  // ---------------------------------------------------------------------------
  console.log('-> Test 7: External and OOS HTML links are excluded...');
  const HTML_WITH_EXTERNAL = [
    '<html><body>',
    '<a href="https://external.com/steal">External</a>',
    '<a href="https://evil-out-of-scope.example/x">OOS</a>',
    '<a href="/internal-ok">Internal</a>',
    '</body></html>',
  ].join('');
  const INTERNAL_OK = 'https://example.com/internal-ok';

  const inv7 = { count: 0 };
  const externalAwareTransport: IdorHttpProbeTransport = async (req) => {
    const normalized = req.url.replace(/\/$/, '') || req.url;
    if (normalized === ROOT_WITH_LINKS_HTTPS || normalized === ROOT_WITH_LINKS_HTTP) {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: HTML_WITH_EXTERNAL,
        responseTimeMs: 1,
      };
    }
    if (req.url === INTERNAL_OK || req.url === 'http://example.com/internal-ok') {
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><title>ok</title></html>',
        responseTimeMs: 1,
      };
    }
    return {
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html></html>',
      responseTimeMs: 1,
    };
  };

  const service7 = createService(inv7, {
    httpTransport: externalAwareTransport,
    useDefaultReconAdapters: true,
  });
  const start7 = await service7.startAssessment({
    targetDomain: 'example.com',
    actorId: 'usr_phase_d1_html_oos',
    config: {
      skipStages: [
        'stage_1_domain_zone',
        'stage_2_port_service',
        'stage_4_crawling_parameters',
        'stage_5_secret_inspection',
      ],
    },
  });

  const record7 = await service7.awaitAssessment(start7.assessmentId);
  assert.ok(record7, 'Assessment record must exist for OOS HTML exclusion test');
  assert.strictEqual(
    record7.status,
    'completed',
    `Expected completed, got ${record7.status}: ${record7.error ?? ''}`
  );

  const asg7 = record7.attackSurfaceGraph;
  assert.ok(asg7, 'Attack surface graph must be present for OOS exclusion test');

  const externalInAsg = asg7.nodes.some(
    (n) =>
      n.kind === 'endpoint' &&
      (n.metadata.url.startsWith('https://external.com') ||
        n.metadata.url.startsWith('https://evil-out-of-scope.example'))
  );
  assert.ok(!externalInAsg, 'External / OOS HTML links must not appear in ASG');

  const internalOk = asg7.nodes.find(
    (n): n is EndpointNode =>
      n.kind === 'endpoint' && n.metadata.url === INTERNAL_OK
  );
  assert.ok(internalOk, `In-scope extracted link ${INTERNAL_OK} must be present`);
  assert.strictEqual(internalOk.epistemicStatus, 'OBSERVED');
  console.log('  [PASS] External and OOS HTML links excluded; in-scope /internal-ok retained.');

  console.log('[phaseD1_seeding_discovery_smoke] All Phase D1 assertions passed.');
}

runPhaseD1Smoke().catch((err: unknown) => {
  console.error('[phaseD1_seeding_discovery_smoke] FAILED:', err);
  process.exit(1);
});
