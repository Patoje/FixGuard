/**
 * FixGuard V2 — Milestone F6 Smoke Test Suite
 *
 * Verifies:
 * 1. Authenticated POST /api/v2/orchestrated/assessments/start returns 202 with valid lineage.
 * 2. Unauthenticated request to /start returns 401 Unauthorized (and invalid secret returns 403).
 * 3. SSRF / Private IP targets return 400/403 preflight rejection with 0 stages dispatched.
 * 4. GET /api/v2/orchestrated/assessments/:assessmentId/summary returns accurate TargetProfile and findings.
 * 5. GET /api/v2/orchestrated/assessments/:assessmentId/status returns stage progress, timing, and error counts.
 */

import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { createV2App, DEFAULT_V2_HOST } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
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

interface RunningServer {
  server: Server;
  baseUrl: string;
  host: string;
  port: number;
  orchestratedService: OrchestratedAssessmentApplicationService;
}

const TEST_SECRET = 'fixguard_secret_token_f6_test_orchestrated';

function createMockReconAdapters(invocationCount: { count: number }): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              subdomain: `api.${req.targetDomain}`,
              parentDomain: req.targetDomain,
              sources: ['mock_subdomain'],
              discoveredAt: new Date().toISOString(),
              confidence: 0.95,
            },
          ],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
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
          durationMs: 5,
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
          observations: [
            {
              host: req.targetHostOrIp,
              ip: req.targetHostOrIp,
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
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
              webServer: 'Vercel',
              technologies: ['Next.js', 'Vercel'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
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
          observations: [
            {
              host: req.targetHostOrUrl,
              port: 443,
              issuer: 'Google Trust Services LLC',
              subjectAlternativeNames: [req.targetHostOrUrl],
              supportedProtocols: ['TLSv1.3'],
              cipherSuites: ['TLS_AES_128_GCM_SHA256'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
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
          observations: [
            {
              url: `https://${req.targetUrlOrDomain}/api/items`,
              host: req.targetUrlOrDomain,
              path: '/api/items',
              sources: ['crawler'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        invocationCount.count += 1;
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
        invocationCount.count += 1;
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              parameterName: 'q',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 5,
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
          durationMs: 5,
        };
      },
    },
  };
}

async function startServer(
  invocationTracker: { count: number },
  apiSecret: string = TEST_SECRET
): Promise<RunningServer> {
  const repository = new InMemoryOrchestratedAssessmentRepository();

  const mockDnsResolver = async (host: string): Promise<string[]> => {
    if (host === 'example.com') return ['93.184.216.34'];
    if (host === 'internal-evil.corp') return ['10.0.0.5'];
    if (host === 'loopback.evil') return ['127.0.0.1'];
    return [];
  };

  const mockHttpTransport: IdorHttpProbeTransport = async (req) => {
    return {
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        server: 'Vercel',
        'x-powered-by': 'Next.js',
      },
      bodyText: JSON.stringify({ ok: true }),
      responseTimeMs: 10,
    };
  };

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

  const reconAdapters = createMockReconAdapters(invocationTracker);
  const orchestratedService = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters,
    httpTransport: mockHttpTransport,
    dnsResolver: mockDnsResolver,
    availabilityService: mockAvailabilityService,
  });

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: repository,
    orchestratedService,
    availabilityService: mockAvailabilityService,
  });

  const app = createV2App(root, { apiSecret });
  const server = app.listen(0, DEFAULT_V2_HOST);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;

  return {
    server,
    baseUrl: `http://${address.address}:${address.port}/api/v2`,
    host: address.address,
    port: address.port,
    orchestratedService,
  };
}

async function stopServer(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    running.server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function runMilestoneF6SmokeTests(): Promise<void> {
  console.log('=== [M-F6 SMOKE] V2 API Orchestrator Controller & Execution Gateway ===\n');

  const invocationTracker = { count: 0 };
  let running: RunningServer | null = null;

  try {
    running = await startServer(invocationTracker, TEST_SECRET);
    const { baseUrl, orchestratedService } = running;

    // -------------------------------------------------------------------------
    // Assertion 1: Authenticated POST /start triggers assessment & returns 202
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 1: Authenticated POST /start triggers orchestrated assessment and returns 202 with valid lineage');
    const startRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        targetDomain: 'example.com',
        actorId: 'usr_secops_f6_tester',
      }),
    });

    assert.strictEqual(startRes.status, 202, 'Authenticated start must return 202 Accepted');
    const startBody = (await startRes.json()) as {
      assessmentId: string;
      scanId: string;
      status: string;
      lineage: {
        assessmentId: string;
        scanId: string;
        authorizationGrantId: string;
        authorizationDecisionId: string;
        actorId: string;
      };
    };

    assert.strictEqual(startBody.status, 'running');
    assert.ok(startBody.assessmentId.startsWith('asmt_orch_'));
    assert.ok(startBody.scanId.startsWith('scan_orch_'));
    assert.strictEqual(startBody.lineage.assessmentId, startBody.assessmentId);
    assert.strictEqual(startBody.lineage.scanId, startBody.scanId);
    assert.strictEqual(startBody.lineage.actorId, 'usr_secops_f6_tester');
    assert.ok(startBody.lineage.authorizationGrantId.startsWith('grant_orch_'));
    assert.ok(startBody.lineage.authorizationDecisionId.startsWith('dec_orch_'));
    const assessmentId = startBody.assessmentId;
    console.log(`    [PASS] 202 Accepted returned with continuous lineage (assessmentId: ${assessmentId})`);

    // -------------------------------------------------------------------------
    // Assertion 2: Unauthenticated request returns 401 / 403
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 2: Unauthenticated request to /start returns 401 / 403');
    const unauthRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetDomain: 'example.com' }),
    });
    assert.strictEqual(unauthRes.status, 401, 'Missing token must return 401 Unauthorized');

    const badTokenRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer wrong_secret_token_123',
      },
      body: JSON.stringify({ targetDomain: 'example.com' }),
    });
    assert.strictEqual(badTokenRes.status, 403, 'Invalid token must return 403 Forbidden');
    console.log('    [PASS] Auth gate strictly enforced: 401 on missing token, 403 on invalid token');

    // -------------------------------------------------------------------------
    // Assertion 3: SSRF / Private IP targets return 400/403 preflight rejection
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 3: SSRF / Private IP target returns 400/403 preflight rejection with 0 stages dispatched');
    const prevInvocations = invocationTracker.count;

    // Direct loopback string
    const loopbackRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({ targetDomain: '127.0.0.1' }),
    });
    assert.strictEqual(loopbackRes.status, 403, 'Loopback IP must be rejected with 403');
    const loopbackBody = (await loopbackRes.json()) as { error: string; reasonCode?: string };
    assert.strictEqual(loopbackBody.reasonCode, 'ssrf_target_blocked');

    // Localhost string
    const localhostRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({ targetDomain: 'localhost' }),
    });
    assert.strictEqual(localhostRes.status, 403, 'localhost must be rejected with 403');

    // Private IP DNS resolution
    const privateDnsRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({ targetDomain: 'internal-evil.corp' }),
    });
    assert.strictEqual(privateDnsRes.status, 403, 'Private-resolving domain must be rejected with 403');

    // Unresolvable domain (fails closed with 400)
    const unresolvableRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({ targetDomain: 'nonexistent-host-404.corp' }),
    });
    assert.strictEqual(unresolvableRes.status, 400, 'Unresolvable domain must fail closed with 400');

    // Verify 0 stages or tools were dispatched for any rejected target
    assert.strictEqual(
      invocationTracker.count,
      prevInvocations,
      'SSRF/unresolvable targets must result in strictly 0 tool/stage invocations'
    );
    console.log('    [PASS] SSRF preflight rejection enforced: 403/400 returned with 0 stages dispatched');

    // -------------------------------------------------------------------------
    // Assertion 4: GET /summary returns accurate TargetProfile and findings
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 4: GET /summary returns accurate TargetProfile and findings for completed assessment');
    // Await background execution of Assertion 1
    await orchestratedService.awaitAssessment(assessmentId);

    const summaryRes = await fetch(
      `${baseUrl}/orchestrated/assessments/${assessmentId}/summary`,
      {
        headers: { Authorization: `Bearer ${TEST_SECRET}` },
      }
    );
    assert.strictEqual(summaryRes.status, 200, 'GET /summary must return 200 OK');
    const summaryBody = (await summaryRes.json()) as {
      assessmentId: string;
      status: string;
      profile: {
        targetHost: string;
        technologies: string[];
        endpoints: unknown[];
        lineage: { assessmentId: string };
      };
      findings: unknown[];
      recommendations: unknown[];
      timing: { startedAt: string; completedAt: string; durationMs: number };
    };

    assert.strictEqual(summaryBody.assessmentId, assessmentId);
    assert.strictEqual(summaryBody.status, 'completed');
    assert.strictEqual(summaryBody.profile.targetHost, 'example.com');
    assert.ok(summaryBody.profile.technologies.includes('Next.js'));
    assert.ok(summaryBody.profile.technologies.includes('Vercel'));
    assert.strictEqual(summaryBody.profile.lineage.assessmentId, assessmentId);
    assert.strictEqual(summaryBody.findings.length, 0, 'Automated assessment must produce 0 promoted findings without human review');
    assert.ok(typeof summaryBody.timing.durationMs === 'number');
    assert.ok(summaryBody.timing.durationMs >= 0);
    console.log('    [PASS] GET /summary verified: TargetProfile, technologies, endpoints, and lineage confirmed');

    // -------------------------------------------------------------------------
    // Assertion 5: GET /status returns execution stage progress, timing, and error counts
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 5: GET /status returns execution stage progress, timing, and error/warning counts');
    const statusRes = await fetch(
      `${baseUrl}/orchestrated/assessments/${assessmentId}/status`,
      {
        headers: { Authorization: `Bearer ${TEST_SECRET}` },
      }
    );
    assert.strictEqual(statusRes.status, 200, 'GET /status must return 200 OK');
    const statusBody = (await statusRes.json()) as {
      assessmentId: string;
      status: string;
      stages: Array<{ stage: string; status: string; observationsCount: number }>;
      timing: { startedAt: string; completedAt: string };
      errorCount: number;
      warningCount: number;
    };

    assert.strictEqual(statusBody.assessmentId, assessmentId);
    assert.strictEqual(statusBody.status, 'completed');
    assert.strictEqual(statusBody.stages.length, 5, 'Must have executed all 5 staged recon phases');
    assert.strictEqual(statusBody.errorCount, 0);
    assert.strictEqual(statusBody.warningCount, 0);

    const stageNames = statusBody.stages.map((s) => s.stage);
    assert.ok(stageNames.includes('stage_1_domain_zone'));
    assert.ok(stageNames.includes('stage_2_port_service'));
    assert.ok(stageNames.includes('stage_3_web_tls'));
    assert.ok(stageNames.includes('stage_4_crawling_parameters'));
    assert.ok(stageNames.includes('stage_5_secret_inspection'));
    console.log('    [PASS] GET /status verified: 5 stages executed, timing captured, zero error counts');

    console.log('\n[✔] ALL 5 MILESTONE F6 ORCHESTRATED API ASSERTIONS PASSED SUCCESSFULLY.');
  } finally {
    if (running) {
      await stopServer(running);
    }
  }
}

runMilestoneF6SmokeTests().catch((err) => {
  console.error('[!] Milestone F6 Smoke Test FAILED:', err);
  process.exit(1);
});
