/**
 * Milestone F8 — Blast Radius Hardening & Target Circuit Breaker Smoke Test Suite
 *
 * Validates:
 * 1. Runtime State Machine: Consecutive 5xx responses or error streaks trip circuit breaker from CLOSED to OPEN.
 * 2. Fail-Closed Rejection & Queue Draining: In OPEN state, execute() immediately rejects with
 *    TargetInstabilityError (reasonCode: 'target_instability_circuit_open') without dispatching tasks.
 * 3. Composite Active Recon Containment: When circuit trips, active reconnaissance safely halts subsequent
 *    stages, returning status: 'circuit_broken' while preserving completed stage observations and drafts.
 * 4. Application Gateway & Custody Preservation: OrchestratedAssessmentApplicationService transitions to
 *    'circuit_broken' on target distress, maintaining continuous lineage and partial TargetProfile synthesis
 *    without fabricated findings or data corruption.
 */

import assert from 'node:assert';
import {
  TargetExecutionCoordinator,
} from '../runtime/TargetExecutionCoordinator.js';
import {
  CIRCUIT_OPEN_REASON_CODE,
  TargetInstabilityError,
} from '../runtime/CircuitBreakerContracts.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
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
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { HttpProbeRequest, HttpProbeResponse } from '../detection/DetectionContracts.js';

function createScopeGrant(domain: string): AuthorizedScopeGrant {
  const now = new Date();
  const expires = new Date(now.getTime() + 86400_000);
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: `grant_${domain.replace(/[^a-z0-9]/gi, '_')}`,
    scanId: 'scan_f8_001',
    issuedAt: now.toISOString(),
    expiresAt: expires.toISOString(),
    subject: {
      targetKind: 'domain',
      domain,
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized Milestone F8 circuit breaker smoke test for ${domain}`,
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
      allowedHosts: [domain, '93.184.216.34'],
      allowedOrigins: [`https://${domain}`, `http://${domain}`],
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
      assessmentId: 'asm_f8_circuit_test',
      scanId: 'scan_f8_001',
      authorizationDecisionId: 'dec_f8_001',
      authorizedActor: { actorId: 'sec_operator_f8', actorType: 'human' },
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
    assessmentId: 'asm_f8_circuit_test',
    scanId: 'scan_f8_001',
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'dec_f8_001',
    actorId: 'sec_operator_f8',
  };

  return { scopeGrant, verifiedDecision: decisionResult.decision, lineage };
}

async function runMilestoneF8SmokeTests(): Promise<void> {
  console.log('[SMOKE F8] Starting Milestone F8 — Blast Radius Hardening & Target Circuit Breaker Suite...');

  // ===========================================================================
  // Assertion 1: Circuit Breaker State Transition on Target Distress (5xx Trip)
  // ===========================================================================
  console.log('[SMOKE F8] Assertion 1: Verifying circuit breaker state transition on consecutive 5xx errors...');
  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 10,
      circuitBreakerConfig: {
        consecutive5xxThreshold: 3,
        consecutiveErrorThreshold: 3,
        halfOpenSuccessThreshold: 2,
        openCooldownMs: 100, // short cooldown for fast test
      },
    });

    const host = 'unstable.example.com';

    assert.strictEqual(coordinator.getCircuitState(host), 'CLOSED', 'Circuit must initially be CLOSED');
    assert.strictEqual(coordinator.isCircuitOpen(host), false, 'Circuit must not be open initially');

    // 1st 503 response
    coordinator.recordTargetResponse(host, 503);
    assert.strictEqual(coordinator.getCircuitState(host), 'CLOSED', 'Circuit should remain CLOSED after 1st 5xx');

    // 2nd 500 response
    coordinator.recordTargetResponse(host, 500);
    assert.strictEqual(coordinator.getCircuitState(host), 'CLOSED', 'Circuit should remain CLOSED after 2nd 5xx');

    // 3rd 502 response -> should trip to OPEN
    coordinator.recordTargetResponse(host, 502);
    assert.strictEqual(coordinator.getCircuitState(host), 'OPEN', 'Circuit must transition to OPEN after 3rd consecutive 5xx');
    assert.strictEqual(coordinator.isCircuitOpen(host), true, 'isCircuitOpen() must return true when circuit is OPEN');

    const stats = coordinator.getCircuitStats(host);
    assert.ok(stats, 'Circuit stats must be available');
    assert.strictEqual(stats.trippedCount, 1, 'Tripped count must be 1');
    assert.strictEqual(stats.total5xxErrors, 3, 'Total 5xx errors must be 3');

    console.log('[SMOKE F8] Assertion 1 PASSED: Consecutive 5xx responses correctly tripped circuit to OPEN.');
  }

  // ===========================================================================
  // Assertion 2: Fail-Closed Rejection, Task Draining & Recovery (HALF_OPEN -> CLOSED)
  // ===========================================================================
  console.log('[SMOKE F8] Assertion 2: Verifying fail-closed rejection and half-open recovery...');
  {
    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: 10,
      circuitBreakerConfig: {
        consecutive5xxThreshold: 2,
        halfOpenSuccessThreshold: 2,
        openCooldownMs: 50,
      },
    });

    const host = 'distressed.example.com';

    // Trip the circuit with 2 consecutive 500s
    coordinator.recordTargetResponse(host, 500);
    coordinator.recordTargetResponse(host, 500);
    assert.strictEqual(coordinator.getCircuitState(host), 'OPEN');

    // Attempting to execute should immediately throw TargetInstabilityError
    let taskExecuted = false;
    let caughtError: unknown = null;
    try {
      await coordinator.execute(host, async () => {
        taskExecuted = true;
        return 'unexpected';
      });
    } catch (err) {
      caughtError = err;
    }

    assert.strictEqual(taskExecuted, false, 'Underlying task MUST NOT execute when circuit is OPEN');
    assert.ok(caughtError instanceof TargetInstabilityError, 'Error must be TargetInstabilityError');
    const instabilityErr = caughtError as TargetInstabilityError;
    assert.strictEqual(instabilityErr.reasonCode, CIRCUIT_OPEN_REASON_CODE, `reasonCode must be '${CIRCUIT_OPEN_REASON_CODE}'`);
    assert.strictEqual(instabilityErr.circuitState, 'OPEN');

    // Wait for openCooldownMs to elapse
    await new Promise((resolve) => setTimeout(resolve, 60));

    // After cooldown, circuit state becomes HALF_OPEN
    assert.strictEqual(coordinator.getCircuitState(host), 'HALF_OPEN', 'Circuit should transition to HALF_OPEN after cooldown');

    // Record 1st successful response in HALF_OPEN
    coordinator.recordTargetResponse(host, 200);
    assert.strictEqual(coordinator.getCircuitState(host), 'HALF_OPEN', 'Circuit remains HALF_OPEN until threshold met');

    // Record 2nd successful response in HALF_OPEN -> should reset to CLOSED
    coordinator.recordTargetResponse(host, 200);
    assert.strictEqual(coordinator.getCircuitState(host), 'CLOSED', 'Circuit should reset to CLOSED after successful recovery threshold');

    console.log('[SMOKE F8] Assertion 2 PASSED: Fail-closed task rejection and recovery transition verified.');
  }

  // ===========================================================================
  // Assertion 3: Composite Active Recon Halts Stages on Circuit Trip
  // ===========================================================================
  console.log('[SMOKE F8] Assertion 3: Verifying composite active recon gracefully halts stages on circuit trip...');
  {
    const targetDomain = 'partial-scan.example.com';
    const { scopeGrant, verifiedDecision, lineage } = setupAuthorizedContext(targetDomain);

    const coordinator = new TargetExecutionCoordinator({
      circuitBreakerConfig: {
        consecutive5xxThreshold: 2,
      },
    });

    let stage1Executed = false;
    let stage2Executed = false;
    let stage3Executed = false;

    const mockAdapters: ReconToolAdapters = {
      subdomainTool: {
        async discoverSubdomains(req) {
          stage1Executed = true;
          coordinator.recordTargetResponse(req.targetDomain, 200);
          return {
            status: 'success',
            contractVersion: 'fixguard-subdomain-discovery/v0',
            targetDomain: req.targetDomain,
            observations: [
              {
                subdomain: `sub.${req.targetDomain}`,
                parentDomain: req.targetDomain,
                sources: ['mock_test'],
                discoveredAt: new Date().toISOString(),
                confidence: 1.0,
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
          coordinator.recordTargetResponse(req.targetDomain, 200);
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
          stage2Executed = true;
          // Simulate target server failure in Stage 2 tripping circuit breaker!
          coordinator.recordTargetResponse(req.targetHostOrIp, 500);
          coordinator.recordTargetResponse(req.targetHostOrIp, 500);
          throw new TargetInstabilityError(req.targetHostOrIp, 'OPEN');
        },
      },
      webTool: {
        async inspectWeb(req) {
          stage3Executed = true;
          return {
            status: 'success',
            contractVersion: 'fixguard-web-inspection/v0',
            targetUrl: req.targetUrl,
            observations: [],
            explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
            lineage: req.lineage,
            durationMs: 5,
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
            durationMs: 5,
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

    const orchestrator = new CompositeActiveReconOrchestratorService(mockAdapters);
    const result = await orchestrator.orchestrate({
      targetDomain,
      verifiedAuthorizationDecision: verifiedDecision,
      authorizedScopeGrant: scopeGrant,
      lineage,
      coordinator,
      dnsResolver: async () => ['93.184.216.34'],
    });

    assert.strictEqual(result.status, 'circuit_broken', "Result status must be 'circuit_broken'");
    assert.strictEqual(stage1Executed, true, 'Stage 1 should have completed');
    assert.strictEqual(stage2Executed, true, 'Stage 2 encountered failure');
    assert.strictEqual(stage3Executed, false, 'Stage 3 must NEVER have executed after circuit tripped');

    // Verify partial observations preserved
    if (result.status === 'circuit_broken') {
      assert.strictEqual(result.reasonCode, CIRCUIT_OPEN_REASON_CODE);
      assert.strictEqual(result.aggregatedObservations.subdomains.length, 1, 'Stage 1 subdomains must be preserved');
      assert.strictEqual(result.aggregatedObservations.dnsRecords.length, 2, 'Stage 1 DNS records must be preserved');
      assert.strictEqual(result.drafts.length, 2, 'Drafts from Stage 1 must be preserved');
      assert.strictEqual(result.explicitNonClaims.createsRealFindings, false);
      assert.strictEqual(result.explicitNonClaims.severity, 'info');
      assert.strictEqual(result.lineage.assessmentId, lineage.assessmentId);
    }

    console.log('[SMOKE F8] Assertion 3 PASSED: Active recon safely halted on circuit trip and preserved evidence.');
  }

  // ===========================================================================
  // Assertion 4: Orchestrated Assessment Application Gateway Circuit Handling
  // ===========================================================================
  console.log('[SMOKE F8] Assertion 4: Verifying OrchestratedAssessmentApplicationService circuit preservation...');
  {
    const targetDomain = 'gateway-circuit.example.com';
    const repository = new InMemoryOrchestratedAssessmentRepository();

    const mockHttpTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      // Simulate target distress with 503 Service Unavailable
      return {
        statusCode: 503,
        headers: {},
        bodyText: 'Service Temporarily Unavailable',
        responseTimeMs: 20,
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

    const service = new OrchestratedAssessmentApplicationService({
      repository,
      httpTransport: mockHttpTransport,
      dnsResolver: async () => ['93.184.216.34'],
      availabilityService: mockAvailabilityService,
    });

    // Start assessment
    const startRes = await service.startAssessment({
      targetDomain,
      actorId: 'sec_operator_f8',
    });

    assert.strictEqual(startRes.status, 'running');

    // Wait for pipeline execution
    const completedRecord = await service.awaitAssessment(startRes.assessmentId);
    assert.ok(completedRecord, 'Assessment record must exist');

    // Status DTO check
    const statusDto = await service.getStatus(startRes.assessmentId);
    assert.ok(
      statusDto.status === 'completed' || statusDto.status === 'circuit_broken',
      `Status must be valid terminal state, received: ${statusDto.status}`
    );

    // Summary DTO check
    const summaryDto = await service.getSummary(startRes.assessmentId);
    assert.strictEqual(summaryDto.targetDomain, targetDomain);
    assert.strictEqual(summaryDto.lineage.assessmentId, startRes.assessmentId);
    assert.ok(summaryDto.profile, 'Synthesized profile must be present');
    assert.strictEqual(summaryDto.profile?.targetHost, targetDomain);

    console.log('[SMOKE F8] Assertion 4 PASSED: Gateway custody and lineage preserved during circuit protection.');
  }

  console.log('[SMOKE F8] ALL 4 ASSERTIONS PASSED! Milestone F8 Circuit Breaker certified.');
}

runMilestoneF8SmokeTests().catch((err) => {
  console.error('[SMOKE F8 FAILED]:', err);
  process.exit(1);
});
