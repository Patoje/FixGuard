/**
 * Katana's non-zero stderr is copied onto the stage warning the
 * orchestrator already surfaces. Exit 0 adds nothing.
 * Hermetic process runner only.
 */
import assert from 'node:assert/strict';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { CompositeUrlDiscoveryAdapter } from '../recon/adapters/CompositeUrlDiscoveryAdapter.js';
import { CONTENT_DISCOVERY_CONTRACT_VERSION, CONTENT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ContentDiscoveryContracts.js';
import { DNS_RESOLUTION_CONTRACT_VERSION, DNS_RESOLUTION_NON_CLAIMS } from '../recon/adapters/DnsResolutionContracts.js';
import { PARAMETER_DISCOVERY_CONTRACT_VERSION, PARAMETER_DISCOVERY_NON_CLAIMS } from '../recon/adapters/ParameterDiscoveryContracts.js';
import { PORT_DISCOVERY_CONTRACT_VERSION, PORT_DISCOVERY_NON_CLAIMS } from '../recon/adapters/PortDiscoveryContracts.js';
import { SECRET_DISCOVERY_CONTRACT_VERSION, SECRET_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SecretDiscoveryContracts.js';
import { SUBDOMAIN_DISCOVERY_CONTRACT_VERSION, SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import { TLS_INSPECTION_CONTRACT_VERSION, TLS_INSPECTION_NON_CLAIMS } from '../recon/adapters/TlsInspectionContracts.js';
import { WEB_INSPECTION_CONTRACT_VERSION, WEB_INSPECTION_NON_CLAIMS } from '../recon/adapters/WebInspectionContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

class MockProcessRunner implements ProcessRunner {
  constructor(private readonly katana: RawExecutionOutput, private readonly gau: RawExecutionOutput) {}

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    if (request.binary === 'katana') return this.katana;
    if (request.binary === 'gau') return this.gau;
    return { stdout: '', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
  }
}

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_katana_stderr_001',
    scanId: 'scan_katana_stderr_001',
    issuedAt: '2026-09-30T12:00:00.000Z',
    expiresAt: '2026-09-30T18:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'example.com' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized katana stderr warning smoke',
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
      allowedDomains: ['example.com'],
      allowedHosts: ['example.com'],
      allowedOrigins: ['https://example.com'],
      allowedMethods: ['GET'],
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

function adapters(runner: ProcessRunner): ReconToolAdapters {
  return {
    subdomainTool: {
      async discoverSubdomains(req) {
        return {
          status: 'success',
          contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
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
          contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
          targetDomain: req.targetDomain,
          observations: [],
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
          contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
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
          contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
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
          contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
          targetHost: req.targetHostOrUrl,
          observations: [],
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    urlTool: new CompositeUrlDiscoveryAdapter(runner),
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'success',
          contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
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
          contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
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
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
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

async function stageWarnings(runner: ProcessRunner): Promise<readonly string[]> {
  const grant = scopeGrant();
  const decidedAt = '2026-09-30T12:00:00.000Z';
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_katana_stderr_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_katana_stderr_001',
      authorizedActor: { actorId: 'act_katana_stderr', actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: grant,
    },
    decidedAt
  );
  if (established.status !== 'established') {
    throw new Error(`authorization was not established: ${established.reasonCode}`);
  }
  const result = await new CompositeActiveReconOrchestratorService(adapters(runner)).orchestrate({
    targetDomain: 'example.com',
    verifiedAuthorizationDecision: established.decision,
    authorizedScopeGrant: grant,
    lineage: {
      assessmentId: 'asmt_katana_stderr_001',
      scanId: grant.scanId,
      authorizationGrantId: grant.grantId,
      authorizationDecisionId: 'dec_katana_stderr_001',
      actorId: 'act_katana_stderr',
    },
    config: {
      enableSpaDiscovery: false,
      enableDeepRecon: false,
    },
    dnsResolver: async () => ['93.184.216.34'],
    probeTransport: async () => ({
      statusCode: 404,
      headers: {},
      bodyText: '',
      responseTimeMs: 1,
    }),
  });
  assert.equal(result.status, 'success');
  if (result.status !== 'success') return [];
  const stage = result.stages.find((item) => item.stage === 'stage_4_crawling_parameters');
  assert.ok(stage);
  return stage.warnings ?? [];
}

async function main(): Promise<void> {
  const degraded = await stageWarnings(
    new MockProcessRunner(
      {
        stdout: `${JSON.stringify({ url: 'https://example.com/from-katana-stdout' })}\n`,
        stderr: 'flag rejected',
        exitCode: 2,
        durationMs: 5,
        timedOut: false,
      },
      {
        stdout: `${JSON.stringify({ url: 'https://example.com/from-gau' })}\n`,
        stderr: '',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      }
    )
  );
  const degradeLine = degraded.find((warning) => warning.includes('katana exit 2'));
  assert.ok(degradeLine, `missing katana degrade line in ${JSON.stringify(degraded)}`);
  assert.ok(degradeLine.includes('flag rejected'));
  assert.equal(degradeLine.includes('from-katana-stdout'), false);

  const clean = await stageWarnings(
    new MockProcessRunner(
      {
        stdout: `${JSON.stringify({ url: 'https://example.com/quiet' })}\n`,
        stderr: 'exit-zero-should-stay-off',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      },
      {
        stdout: '',
        stderr: 'gau-exit-zero-should-stay-off',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      }
    )
  );
  const joined = clean.join('\n');
  assert.equal(joined.includes('exit-zero-should-stay-off'), false);
  assert.equal(joined.includes('gau-exit-zero-should-stay-off'), false);
  assert.equal(joined.includes('katana exit 0'), false);

  const emptyErr = await stageWarnings(
    new MockProcessRunner(
      {
        stdout: '',
        stderr: '   ',
        exitCode: 2,
        durationMs: 5,
        timedOut: false,
      },
      {
        stdout: `${JSON.stringify({ url: 'https://example.com/archive' })}\n`,
        stderr: '',
        exitCode: 0,
        durationMs: 5,
        timedOut: false,
      }
    )
  );
  const emptyLine = emptyErr.find((warning) => warning.includes('katana exit 2'));
  assert.ok(emptyLine);
  assert.ok(emptyLine.includes('stderr_empty'));

  process.stdout.write('[milestone_katana_stderr_warning_smoke] passed\n');
}

main().catch(fail);
