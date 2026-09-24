/**
 * Phase D1 — Discovery Depth & URL Seeding + Next.js fingerprint smoke suite.
 *
 * Hermetic assertions:
 * 1. Deep seed URL lands in ASG as OBSERVED (direct_observation / live).
 * 2. Out-of-scope seed fails closed with seed_out_of_scope before recon network.
 * 3. Vary: RSC header fingerprints Next.js with high confidence.
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

const DEEP_SEED = 'https://example.com/deep/admin/settings';
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

function createService(invocationCount: { count: number }): OrchestratedAssessmentApplicationService {
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const mockDnsResolver = async (host: string): Promise<string[]> => {
    if (host === 'example.com') return ['93.184.216.34'];
    return [];
  };
  const mockHttpTransport: IdorHttpProbeTransport = async () => ({
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    bodyText: '<html></html>',
    responseTimeMs: 1,
  });
  const mockAvailabilityService = new ReconToolAvailabilityService({
    async execute() {
      return {
        stdout: 'version: 1.0.0\n',
        stderr: '',
        exitCode: 0,
        durationMs: 1,
        timedOut: false,
      };
    },
  });

  return new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createMockReconAdapters(invocationCount),
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
  // 3. Vary: RSC → Next.js high-confidence fingerprint
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

  console.log('[phaseD1_seeding_discovery_smoke] All Phase D1 assertions passed.');
}

runPhaseD1Smoke().catch((err: unknown) => {
  console.error('[phaseD1_seeding_discovery_smoke] FAILED:', err);
  process.exit(1);
});
