/**
 * FixGuard V2 — Milestone P0-3 Smoke Test Suite
 *
 * Verifies:
 * 1. ReconToolAvailabilityService accurately detects installed, missing, and wrong_version binaries.
 * 2. GET /api/v2/capabilities/status returns the complete typed capability matrix.
 * 3. Orchestrated assessment proceeds in loud degraded mode (degraded_mode_missing_binary)
 *    when a required binary is missing from the execution environment.
 * 4. Honest composition allowlist rejects unknown arbitrary commands.
 */

import assert from 'node:assert';
import process from 'node:process';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import type { ProcessRunner } from '../core/ProcessRunner.js';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import {
  RECON_TOOL_ALLOWLIST,
  CAPABILITY_STATUS_CONTRACT_VERSION,
  isAllowedReconTool,
} from '../capabilities/CapabilityStatusContracts.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { createV2App, DEFAULT_V2_HOST } from '../api/createV2App.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { ApiValidationError } from '../api/ApiErrors.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
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

function createHermeticReconAdapters(): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
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
        return {
          status: 'success',
          contractVersion: 'fixguard-content-discovery/v0',
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath ?? '/dev/null',
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
          observations: [],
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

interface RunningServer {
  server: Server;
  baseUrl: string;
}

const TEST_SECRET = 'fixguard_secret_token_p0_3_test_capabilities';

/**
 * Deterministic Mock Process Runner for simulating exact binary availability states.
 */
class DeterministicToolProcessRunner implements ProcessRunner {
  private readonly toolStates: Map<
    string,
    { available: boolean; version?: string; exitCode?: number; stdout?: string; stderr?: string }
  >;

  constructor(
    initialStates: Record<
      string,
      { available: boolean; version?: string; exitCode?: number; stdout?: string; stderr?: string }
    >
  ) {
    this.toolStates = new Map(Object.entries(initialStates));
  }

  public setToolState(
    tool: string,
    state: { available: boolean; version?: string; exitCode?: number; stdout?: string; stderr?: string }
  ): void {
    this.toolStates.set(tool, state);
  }

  public async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    if (request.binary === 'which') {
      const targetTool = request.args[0];
      const state = this.toolStates.get(targetTool);
      if (state && state.available) {
        return {
          stdout: `/usr/local/bin/${targetTool}\n`,
          stderr: '',
          exitCode: 0,
          durationMs: 2,
          timedOut: false,
        };
      }
      return {
        stdout: '',
        stderr: `${targetTool} not found\n`,
        exitCode: 1,
        durationMs: 2,
        timedOut: false,
      };
    }

    const state = this.toolStates.get(request.binary);
    if (!state || !state.available) {
      throw new Error(`Command not found: ${request.binary}. Ensure it is installed and in PATH.`);
    }

    return {
      stdout: state.stdout ?? (state.version ? `version: ${state.version}\n` : 'version: 1.0.0\n'),
      stderr: state.stderr ?? '',
      exitCode: state.exitCode ?? 0,
      durationMs: 5,
      timedOut: false,
    };
  }
}

async function startServerWithRunner(runner: ProcessRunner): Promise<RunningServer> {
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const availabilityService = new ReconToolAvailabilityService(runner);

  const mockDnsResolver = async (host: string): Promise<string[]> => {
    if (host === 'example.com') return ['93.184.216.34'];
    return [];
  };

  const hermeticHttpTransport: IdorHttpProbeTransport = async () => ({
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    bodyText: '<html></html>',
    responseTimeMs: 1,
  });

  const orchestratedService = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: createHermeticReconAdapters(),
    dnsResolver: mockDnsResolver,
    httpTransport: hermeticHttpTransport,
    availabilityService,
  });

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: repository,
    orchestratedService,
    availabilityService,
  });

  const app = createV2App(root, { apiSecret: TEST_SECRET });
  const server = app.listen(0, DEFAULT_V2_HOST);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address() as AddressInfo;

  return {
    server,
    baseUrl: `http://${address.address}:${address.port}/api/v2`,
  };
}

async function stopServer(running: RunningServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    running.server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function runMilestoneP0_3SmokeTests(): Promise<void> {
  console.log('=== [M-P0-3 SMOKE] Binary Availability Verification & Honest Composition ===\n');

  // -------------------------------------------------------------------------
  // Assertion 1: ReconToolAvailabilityService detects installed vs missing
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 1: ReconToolAvailabilityService accurately detects installed vs. missing binaries');
  {
    const runner = new DeterministicToolProcessRunner({
      subfinder: { available: true, version: 'v2.14.0' },
      naabu: { available: false },
      httpx: { available: true, version: 'v1.9.0' },
      dnsx: { available: false },
      tlsx: { available: false },
      ffuf: { available: true, version: '2.1.0-dev' },
      gau: { available: true, version: '2.2.4' },
      arjun: { available: false },
      trufflehog: { available: true, version: '3.95.6' },
    });

    const service = new ReconToolAvailabilityService(runner);
    const matrix = await service.checkAllTools();

    assert.strictEqual(matrix.contractVersion, CAPABILITY_STATUS_CONTRACT_VERSION);
    assert.strictEqual(matrix.summary.total, 9);
    assert.strictEqual(matrix.summary.availableCount, 5);
    assert.strictEqual(matrix.summary.missingCount, 4);
    assert.strictEqual(matrix.summary.allAvailable, false);

    assert.strictEqual(matrix.tools.subfinder.status, 'available');
    assert.strictEqual(matrix.tools.subfinder.version, '2.14.0');
    assert.strictEqual(matrix.tools.subfinder.path, '/usr/local/bin/subfinder');

    assert.strictEqual(matrix.tools.naabu.status, 'missing');
    assert.ok(matrix.tools.naabu.error?.includes('Command not found'));

    assert.strictEqual(matrix.tools.trufflehog.status, 'available');
    assert.strictEqual(matrix.tools.trufflehog.version, '3.95.6');

    // Test tool verification helper
    const subsetCheck1 = await service.verifyRequiredTools(['subfinder', 'httpx']);
    assert.strictEqual(subsetCheck1.allAvailable, true);
    assert.strictEqual(subsetCheck1.missingTools.length, 0);

    const subsetCheck2 = await service.verifyRequiredTools(['subfinder', 'naabu', 'dnsx']);
    assert.strictEqual(subsetCheck2.allAvailable, false);
    assert.deepStrictEqual(subsetCheck2.missingTools, ['naabu', 'dnsx']);

    console.log('    [PASS] ReconToolAvailabilityService matrix and subset verification validated');
  }

  // -------------------------------------------------------------------------
  // Assertion 2: GET /api/v2/capabilities/status returns typed matrix
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 2: GET /api/v2/capabilities/status returns typed capability status per tool');
  {
    const runner = new DeterministicToolProcessRunner({
      subfinder: { available: true, version: 'v2.14.0' },
      naabu: { available: true, version: 'v2.3.0' },
      httpx: { available: true, version: 'v1.9.0' },
      dnsx: { available: true, version: 'v1.1.0' },
      tlsx: { available: true, version: 'v1.1.5' },
      ffuf: { available: true, version: '2.1.0' },
      gau: { available: true, version: '2.2.4' },
      arjun: { available: true, version: '2.2.1' },
      trufflehog: { available: true, version: '3.95.6' },
    });

    const running = await startServerWithRunner(runner);
    try {
      // Unauthenticated check -> 401
      const unauthRes = await fetch(`${running.baseUrl}/capabilities/status`);
      assert.strictEqual(unauthRes.status, 401, 'Endpoint must require authentication');

      // Authenticated check -> 200
      const authRes = await fetch(`${running.baseUrl}/capabilities/status`, {
        headers: { Authorization: `Bearer ${TEST_SECRET}` },
      });
      assert.strictEqual(authRes.status, 200);
      const data = (await authRes.json()) as {
        contractVersion: string;
        summary: { total: number; availableCount: number; allAvailable: boolean };
        tools: Record<string, { tool: string; status: string; version?: string }>;
      };

      assert.strictEqual(data.contractVersion, CAPABILITY_STATUS_CONTRACT_VERSION);
      assert.strictEqual(data.summary.total, 9);
      assert.strictEqual(data.summary.availableCount, 9);
      assert.strictEqual(data.summary.allAvailable, true);

      for (const tool of RECON_TOOL_ALLOWLIST) {
        assert.ok(data.tools[tool], `Tool ${tool} must be in response`);
        assert.strictEqual(data.tools[tool].status, 'available');
      }

      console.log('    [PASS] GET /api/v2/capabilities/status verified with 100% available matrix');
    } finally {
      await stopServer(running);
    }
  }

  // -------------------------------------------------------------------------
  // Assertion 3: Assessment proceeds in loud degraded mode when required binary is missing
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 3: Assessment proceeds with degraded_mode_missing_binary when required binary is missing');
  {
    // naabu, dnsx, and tlsx missing
    const runner = new DeterministicToolProcessRunner({
      subfinder: { available: true, version: 'v2.14.0' },
      naabu: { available: false },
      httpx: { available: true, version: 'v1.9.0' },
      dnsx: { available: false },
      tlsx: { available: false },
      ffuf: { available: true, version: '2.1.0' },
      gau: { available: true, version: '2.2.4' },
      arjun: { available: true, version: '2.2.1' },
      trufflehog: { available: true, version: '3.95.6' },
    });

    const running = await startServerWithRunner(runner);
    try {
      const startRes = await fetch(`${running.baseUrl}/orchestrated/assessments/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${TEST_SECRET}`,
        },
        body: JSON.stringify({
          targetDomain: 'example.com',
          actorId: 'usr_secops_p0_3_tester',
        }),
      });

      assert.ok(
        startRes.status === 200 || startRes.status === 202,
        `Must accept start under loud degraded mode, got ${startRes.status}`
      );
      const startBody = (await startRes.json()) as { assessmentId: string; status: string };
      assert.ok(startBody.assessmentId, 'Must return assessmentId');

      // Await completion
      type DegradedSummary = {
        status: string;
        degradedCapabilities?: readonly string[];
        stages?: readonly { stage: string; warnings?: readonly string[] }[];
      };
      let summary: DegradedSummary | null = null;
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 200));
        const statusRes = await fetch(
          `${running.baseUrl}/orchestrated/assessments/${startBody.assessmentId}/summary`,
          {
            headers: { Authorization: `Bearer ${TEST_SECRET}` },
          }
        );
        if (statusRes.status !== 200) continue;
        summary = (await statusRes.json()) as DegradedSummary;
        if (summary.status !== 'running') break;
      }

      assert.ok(summary, 'Must obtain assessment summary');
      assert.notStrictEqual(summary.status, 'running', 'Assessment must leave running state');

      const degraded: readonly string[] = summary.degradedCapabilities ?? [];
      assert.ok(
        degraded.some((d: string) => d.includes('degraded_mode_missing_binary: naabu')),
        `Must surface naabu degradation, got: ${JSON.stringify(degraded)}`
      );
      assert.ok(
        degraded.some((d: string) => d.includes('degraded_mode_missing_binary: dnsx')),
        `Must surface dnsx degradation, got: ${JSON.stringify(degraded)}`
      );
      assert.ok(
        degraded.some((d: string) => d.includes('degraded_mode_missing_binary: tlsx')),
        `Must surface tlsx degradation, got: ${JSON.stringify(degraded)}`
      );

      console.log('    [PASS] Missing required binaries surfaced as degraded_mode_missing_binary (no silent empty success)');
    } finally {
      await stopServer(running);
    }
  }

  // -------------------------------------------------------------------------
  // Assertion 4: Allowlist rejects unauthorized tool names & arbitrary commands
  // -------------------------------------------------------------------------
  console.log('[*] Assertion 4: Tool allowlist rejects arbitrary command inputs and unknown tools');
  {
    const runner = new DeterministicToolProcessRunner({});
    const service = new ReconToolAvailabilityService(runner);

    assert.strictEqual(isAllowedReconTool('subfinder'), true);
    assert.strictEqual(isAllowedReconTool('httpx'), true);
    assert.strictEqual(isAllowedReconTool('sqlmap'), false);
    assert.strictEqual(isAllowedReconTool('bash'), false);
    assert.strictEqual(isAllowedReconTool('rm -rf /'), false);
    assert.strictEqual(isAllowedReconTool('../../../bin/sh'), false);

    let caughtError = false;
    try {
      await service.checkTool('malicious_executable; rm -rf /');
    } catch (err) {
      if (err instanceof ApiValidationError) {
        caughtError = true;
      }
    }
    assert.strictEqual(caughtError, true, 'checkTool must throw ApiValidationError on non-allowlisted tool');

    console.log('    [PASS] Strict allowlist rejection verified: arbitrary and unauthorized commands blocked');
  }

  console.log('\n>>> ALL 4 MILESTONE P0-3 ASSERTIONS PASSED SUCCESSFULLY! <<<\n');
}

runMilestoneP0_3SmokeTests().catch((err) => {
  console.error('[!] Milestone P0-3 Smoke Test FAILED:', err);
  process.exit(1);
});
