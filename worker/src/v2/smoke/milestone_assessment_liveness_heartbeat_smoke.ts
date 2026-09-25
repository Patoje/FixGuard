/**
 * FixGuard V2 — Assessment liveness heartbeat smoke.
 *
 * Verifies:
 * 1. Canonical interval is 7000ms.
 * 2. AssessmentLivenessHeartbeat advances ticks during a fake long recon wait.
 * 3. OrchestratedAssessmentApplicationService persists lastHeartbeatAt / alive
 *    on GET status while a slow stage is in flight.
 */

import assert from 'node:assert/strict';
import process from 'node:process';

import {
  ASSESSMENT_HEARTBEAT_INTERVAL_MS,
  AssessmentLivenessHeartbeat,
  buildAssessmentHeartbeatState,
  isAssessmentHeartbeatAlive,
} from '../runtime/AssessmentLivenessHeartbeat.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
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
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createSlowReconAdapters(holdMs: number): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        await sleep(holdMs);
        return {
          status: 'success',
          contractVersion: 'fixguard-subdomain-discovery/v0',
          targetDomain: req.targetDomain,
          observations: [
            {
              subdomain: `www.${req.targetDomain}`,
              parentDomain: req.targetDomain,
              sources: ['mock_subdomain'],
              discoveredAt: new Date().toISOString(),
              confidence: 0.95,
            },
          ],
          explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: holdMs,
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
          observations: [],
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

async function main(): Promise<void> {
  console.log('[SMOKE] Assessment liveness heartbeat');

  assert.equal(
    ASSESSMENT_HEARTBEAT_INTERVAL_MS,
    7_000,
    'canonical heartbeat interval must be 7000ms'
  );

  // -------------------------------------------------------------------------
  // Unit: heartbeat ticks advance during a fake long wait
  // -------------------------------------------------------------------------
  {
    const ticks: string[] = [];
    let clock = 1_700_000_000_000;
    const heartbeat = new AssessmentLivenessHeartbeat(
      (tick) => {
        ticks.push(tick.at);
      },
      {
        intervalMs: 40,
        now: () => {
          clock += 1;
          return new Date(clock);
        },
      }
    );
    heartbeat.setHint({ stageHint: 'stage_2_port_service', toolHint: 'naabu' });
    heartbeat.start();
    await sleep(130);
    heartbeat.stop();
    assert.ok(ticks.length >= 2, `expected >=2 heartbeat ticks, got ${ticks.length}`);
    assert.ok(ticks[0] !== ticks[ticks.length - 1], 'heartbeat timestamps must advance');
    const lastTick = ticks[ticks.length - 1];
    assert.ok(lastTick !== undefined);
    const state = buildAssessmentHeartbeatState({
      at: lastTick,
      stageHint: 'stage_2_port_service',
      toolHint: 'naabu',
    });
    assert.equal(state.stageHint, 'stage_2_port_service');
    assert.equal(state.toolHint, 'naabu');
    assert.equal(
      isAssessmentHeartbeatAlive(
        state.lastHeartbeatAt,
        'running',
        Date.parse(state.lastHeartbeatAt) + 1_000
      ),
      true
    );
    assert.equal(
      isAssessmentHeartbeatAlive(state.lastHeartbeatAt, 'completed', Date.now()),
      false
    );
    console.log('[OK] unit heartbeat advances during fake long wait');
  }

  // -------------------------------------------------------------------------
  // Integration: status GET shows alive + advancing lastHeartbeatAt
  // -------------------------------------------------------------------------
  {
    const repository = new InMemoryOrchestratedAssessmentRepository();
    const holdMs = 220;
    const mockHttpTransport: IdorHttpProbeTransport = async () => ({
      statusCode: 200,
      headers: { 'content-type': 'text/html' },
      bodyText: '<html></html>',
      responseTimeMs: 5,
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

    const appService = new OrchestratedAssessmentApplicationService({
      repository,
      reconAdapters: createSlowReconAdapters(holdMs),
      heartbeatIntervalMs: 50,
      dnsResolver: async () => ['93.184.216.34'],
      availabilityService: mockAvailabilityService,
      httpTransport: mockHttpTransport,
    });

    const started = await appService.startAssessment({
      targetDomain: 'example.com',
      actorId: 'usr_hb_smoke',
    });
    assert.equal(started.status, 'running');

    const first = await appService.getStatus(started.assessmentId);
    assert.equal(first.alive, true, 'status should be alive shortly after start');
    assert.ok(
      typeof first.lastHeartbeatAt === 'string' && first.lastHeartbeatAt.length > 0,
      'lastHeartbeatAt must be present while running'
    );
    const firstHb = first.lastHeartbeatAt;

    await sleep(130);
    const mid = await appService.getStatus(started.assessmentId);
    assert.equal(mid.status, 'running', 'slow recon should still be running');
    assert.equal(mid.alive, true, 'mid-run status must remain alive');
    assert.ok(
      typeof mid.lastHeartbeatAt === 'string' && mid.lastHeartbeatAt.length > 0,
      'mid-run lastHeartbeatAt required'
    );
    assert.notEqual(
      mid.lastHeartbeatAt,
      firstHb,
      'heartbeat timestamp must advance during long recon tick'
    );
    assert.ok(
      mid.heartbeatStageHint === 'stage_1_domain_zone' ||
        mid.heartbeatStageHint === 'pipeline_boot',
      `expected stage hint during hold, got ${mid.heartbeatStageHint}`
    );

    await appService.awaitAssessment(started.assessmentId);
    const done = await appService.getStatus(started.assessmentId);
    assert.ok(
      done.status === 'completed' || done.status === 'circuit_broken',
      `expected terminal status, got ${done.status}`
    );
    assert.equal(done.alive, false, 'completed assessments are not alive');
    console.log('[OK] orchestrated status heartbeat advances during slow recon');
  }

  console.log('[SMOKE PASS] Assessment liveness heartbeat');
}

main().catch((err: unknown) => {
  console.error('[SMOKE FAIL]', err);
  process.exit(1);
});
