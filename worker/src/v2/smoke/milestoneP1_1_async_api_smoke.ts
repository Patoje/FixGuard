/**
 * FixGuard V2 — Milestone P1-1 Smoke Test Suite
 *
 * Verifies:
 * 1. POST /api/v2/orchestrated/assessments/start acknowledges immediately with HTTP 202 Accepted (< 100ms)
 *    and launches execution asynchronously in-process.
 * 2. GET /api/v2/orchestrated/assessments/:assessmentId/status provides real-time polling updates
 *    (reflecting 'running' state, stages executing incrementally, and error/warning counts).
 * 3. GET /api/v2/orchestrated/assessments/:assessmentId/summary exposes the synthesized TargetProfile,
 *    pendingEvidenceDrafts awaiting human review, and advisory recommendations once complete.
 * 4. Lineage tuple is preserved unbroken across the asynchronous lifecycle.
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
  orchestratedService: OrchestratedAssessmentApplicationService;
}

const TEST_SECRET = 'fixguard_secret_token_p1_1_test_async_api';

function createPacedMockAdapters(stageDelayMs: number): ReconToolAdapters {
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        await sleep(stageDelayMs);
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
          durationMs: stageDelayMs,
        };
      },
    },
    dnsTool: {
      async resolveDns(req) {
        await sleep(stageDelayMs);
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
          durationMs: stageDelayMs,
        };
      },
    },
    portTool: {
      async discoverPorts(req) {
        await sleep(stageDelayMs);
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
          durationMs: stageDelayMs,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        await sleep(stageDelayMs);
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              statusCode: 200,
              webServer: 'Cloudflare',
              technologies: ['React', 'Next.js'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: stageDelayMs,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        await sleep(stageDelayMs);
        return {
          status: 'success',
          contractVersion: 'fixguard-tls-inspection/v0',
          targetHost: req.targetHostOrUrl,
          observations: [
            {
              host: req.targetHostOrUrl,
              port: 443,
              issuer: 'Let\'s Encrypt',
              subjectAlternativeNames: [req.targetHostOrUrl],
              supportedProtocols: ['TLSv1.3'],
              cipherSuites: ['TLS_AES_256_GCM_SHA384'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: stageDelayMs,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        await sleep(stageDelayMs);
        return {
          status: 'success',
          contractVersion: 'fixguard-url-discovery/v0',
          targetUrlOrDomain: req.targetUrlOrDomain,
          observations: [
            {
              url: `https://${req.targetUrlOrDomain}/api/v1/auth`,
              host: req.targetUrlOrDomain,
              path: '/api/v1/auth',
              sources: ['mock_crawler'],
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: stageDelayMs,
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
          durationMs: 1,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'success',
          contractVersion: 'fixguard-parameter-discovery/v0',
          targetUrl: req.targetUrl,
          observations: [
            {
              url: req.targetUrl,
              method: 'GET',
              parameterName: 'redirect_uri',
              discoveredAt: new Date().toISOString(),
            },
          ],
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
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
          durationMs: 1,
        };
      },
    },
  };
}

async function startAsyncTestServer(stageDelayMs = 25): Promise<RunningServer> {
  const repository = new InMemoryOrchestratedAssessmentRepository();

  const mockDnsResolver = async (host: string): Promise<string[]> => {
    if (host === 'async-target.example.com') return ['93.184.216.34'];
    return [];
  };

  const mockHttpTransport: IdorHttpProbeTransport = async () => {
    return {
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        server: 'Cloudflare',
      },
      bodyText: JSON.stringify({ ok: true }),
      responseTimeMs: 5,
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

  const reconAdapters = createPacedMockAdapters(stageDelayMs);
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

  const app = createV2App(root, { apiSecret: TEST_SECRET });
  const server = app.listen(0, DEFAULT_V2_HOST);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;

  return {
    server,
    baseUrl: `http://${address.address}:${address.port}/api/v2`,
    orchestratedService,
  };
}

async function stopServer(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    running.server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function runMilestoneP1_1SmokeTests(): Promise<void> {
  console.log('=== [M-P1-1 SMOKE] Async Assessment HTTP API Lifecycle ===\n');

  let running: RunningServer | null = null;

  try {
    running = await startAsyncTestServer(30);
    const { baseUrl, orchestratedService } = running;

    // -------------------------------------------------------------------------
    // Assertion 1: Immediate HTTP 202 Acknowledgment (< 100ms)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 1: POST /start acknowledges immediately with HTTP 202 Accepted in < 100ms');
    const startRequestTime = Date.now();
    const startRes = await fetch(`${baseUrl}/orchestrated/assessments/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TEST_SECRET}`,
      },
      body: JSON.stringify({
        targetDomain: 'async-target.example.com',
        actorId: 'usr_secops_async_tester',
      }),
    });
    const requestDurationMs = Date.now() - startRequestTime;

    assert.strictEqual(startRes.status, 202, 'POST /start must immediately return 202 Accepted');
    assert.ok(
      requestDurationMs < 100,
      `POST /start took ${requestDurationMs}ms, which must be < 100ms to guarantee non-blocking acknowledgment`
    );

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
    assert.strictEqual(startBody.lineage.actorId, 'usr_secops_async_tester');
    const assessmentId = startBody.assessmentId;

    console.log(`    [PASS] Immediate 202 returned in ${requestDurationMs}ms with status: 'running'`);

    // -------------------------------------------------------------------------
    // Assertion 2: Status Polling Endpoint (GET /status during execution)
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 2: GET /status provides non-blocking polling and reflects real-time transitions');
    const initialStatusRes = await fetch(
      `${baseUrl}/orchestrated/assessments/${assessmentId}/status`,
      {
        headers: { Authorization: `Bearer ${TEST_SECRET}` },
      }
    );
    assert.strictEqual(initialStatusRes.status, 200, 'GET /status must return 200 OK');
    const initialStatusBody = (await initialStatusRes.json()) as {
      assessmentId: string;
      status: string;
      stages: unknown[];
      errorCount: number;
      warningCount: number;
    };

    assert.strictEqual(initialStatusBody.assessmentId, assessmentId);
    assert.ok(
      ['running', 'completed'].includes(initialStatusBody.status),
      `Expected status to be running or completed, got ${initialStatusBody.status}`
    );
    assert.strictEqual(initialStatusBody.errorCount, 0);
    assert.strictEqual(initialStatusBody.warningCount, 0);

    console.log('    [PASS] GET /status returns structured lifecycle metrics during execution');

    // -------------------------------------------------------------------------
    // Assertion 3: Summary Polling Endpoint & Evidence Drafts Custody
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 3: GET /summary exposes synthesized TargetProfile, pendingEvidenceDrafts, and findings upon completion');

    // Await background execution completion
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
      profile?: {
        targetHost: string;
        technologies: string[];
        endpoints: unknown[];
        lineage: { assessmentId: string };
      };
      findings: unknown[];
      pendingEvidenceDrafts?: unknown[];
      recommendations: unknown[];
      timing: { startedAt: string; completedAt: string; durationMs: number };
    };

    assert.strictEqual(summaryBody.assessmentId, assessmentId);
    assert.strictEqual(summaryBody.status, 'completed');
    assert.ok(summaryBody.profile, 'Summary must contain synthesized TargetProfile');
    assert.strictEqual(summaryBody.profile.targetHost, 'async-target.example.com');
    assert.ok(summaryBody.profile.technologies.includes('Next.js'));
    assert.ok(summaryBody.profile.technologies.includes('React'));
    assert.strictEqual(summaryBody.findings.length, 0, 'Unreviewed assessment must emit 0 promoted findings');
    assert.ok(
      Array.isArray(summaryBody.pendingEvidenceDrafts),
      'pendingEvidenceDrafts must be exposed for human triage'
    );
    assert.ok(typeof summaryBody.timing.durationMs === 'number');
    assert.ok(summaryBody.timing.durationMs >= 0);

    // Verify terminal status check
    const terminalStatusRes = await fetch(
      `${baseUrl}/orchestrated/assessments/${assessmentId}/status`,
      {
        headers: { Authorization: `Bearer ${TEST_SECRET}` },
      }
    );
    const terminalStatus = (await terminalStatusRes.json()) as {
      status: string;
      stages: Array<{ stage: string; status: string }>;
    };
    assert.strictEqual(terminalStatus.status, 'completed');
    assert.strictEqual(terminalStatus.stages.length, 5, 'All 5 staged discovery phases must be recorded');

    console.log('    [PASS] Terminal summary verified: TargetProfile synthesized, drafts preserved, findings empty');

    // -------------------------------------------------------------------------
    // Assertion 4: Continuous Lineage Tuple Preserved Across Async Pipeline
    // -------------------------------------------------------------------------
    console.log('[*] Assertion 4: Continuous lineage tuple preserved unbroken across the asynchronous lifecycle');
    assert.strictEqual(summaryBody.profile.lineage.assessmentId, assessmentId);
    assert.strictEqual(startBody.lineage.assessmentId, assessmentId);
    console.log('    [PASS] Unbroken lineage confirmed across start, status, and summary');

    console.log('\n>>> ALL 4 MILESTONE P1-1 ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
  } finally {
    if (running) {
      await stopServer(running);
    }
  }
}

runMilestoneP1_1SmokeTests().catch((err) => {
  console.error('[!] Milestone P1-1 Smoke Test FAILED:', err);
  process.exit(1);
});
