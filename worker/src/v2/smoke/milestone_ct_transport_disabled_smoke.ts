/**
 * Production fail-closed crt.sh transport must not look like a network failure.
 * No live fetch. No network.
 */
import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  CrtShAdapter,
  createFailClosedCtFetch,
} from '../recon/adapters/CrtShAdapter.js';
import {
  CONTENT_DISCOVERY_CONTRACT_VERSION,
  CONTENT_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/ContentDiscoveryContracts.js';
import {
  DNS_RESOLUTION_CONTRACT_VERSION,
  DNS_RESOLUTION_NON_CLAIMS,
} from '../recon/adapters/DnsResolutionContracts.js';
import {
  PARAMETER_DISCOVERY_CONTRACT_VERSION,
  PARAMETER_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/ParameterDiscoveryContracts.js';
import {
  PORT_DISCOVERY_CONTRACT_VERSION,
  PORT_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/PortDiscoveryContracts.js';
import {
  SECRET_DISCOVERY_CONTRACT_VERSION,
  SECRET_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/SecretDiscoveryContracts.js';
import { SUBDOMAIN_DISCOVERY_NON_CLAIMS } from '../recon/adapters/SubdomainDiscoveryContracts.js';
import {
  TLS_INSPECTION_CONTRACT_VERSION,
  TLS_INSPECTION_NON_CLAIMS,
} from '../recon/adapters/TlsInspectionContracts.js';
import {
  URL_DISCOVERY_CONTRACT_VERSION,
  URL_DISCOVERY_NON_CLAIMS,
} from '../recon/adapters/UrlDiscoveryContracts.js';
import {
  WEB_INSPECTION_CONTRACT_VERSION,
  WEB_INSPECTION_NON_CLAIMS,
} from '../recon/adapters/WebInspectionContracts.js';
import { CompositeActiveReconOrchestratorService } from '../recon/orchestration/CompositeActiveReconOrchestratorService.js';
import type { ReconToolAdapters } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

const HOST = 'example.com';

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function scopeGrant(): AuthorizedScopeGrant {
  const now = Date.now();
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_ct_disabled_001',
    scanId: 'scan_ct_disabled_001',
    issuedAt: new Date(now - 3600_000).toISOString(),
    expiresAt: new Date(now + 86400_000).toISOString(),
    subject: { targetKind: 'domain', domain: HOST },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized fail-closed CT transport smoke',
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
      allowedDomains: [HOST],
      allowedHosts: [HOST],
      allowedOrigins: [`https://${HOST}`],
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

function lineage(): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: 'asmt_ct_disabled_001',
    scanId: 'scan_ct_disabled_001',
    authorizationGrantId: 'grant_ct_disabled_001',
    authorizationDecisionId: 'dec_ct_disabled_001',
    actorId: 'act_ct_disabled',
  };
}

async function main(): Promise<void> {
  const grant = scopeGrant();
  const decidedAt = new Date().toISOString();
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_ct_disabled_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_ct_disabled_001',
      authorizedActor: { actorId: 'act_ct_disabled', actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant: grant,
    },
    decidedAt
  );
  if (established.status !== 'established') {
    throw new Error(`authorization was not established: ${established.reasonCode}`);
  }
  const requestLineage = lineage();
  const dnsResolver = async (): Promise<string[]> => ['93.184.216.34'];

  const closed = await new CrtShAdapter({
    dnsResolver,
    fetchApi: createFailClosedCtFetch(),
  }).discoverSubdomains({
    targetDomain: HOST,
    verifiedAuthorizationDecision: established.decision,
    authorizedScopeGrant: grant,
    lineage: requestLineage,
  });
  assert.equal(closed.status, 'execution_failed');
  if (closed.status === 'execution_failed') {
    assert.equal(closed.reasonCode, 'ct_transport_disabled');
  }

  const thrown = await new CrtShAdapter({
    dnsResolver,
    fetchApi: async () => {
      throw new Error('socket hang up');
    },
  }).discoverSubdomains({
    targetDomain: HOST,
    verifiedAuthorizationDecision: established.decision,
    authorizedScopeGrant: grant,
    lineage: requestLineage,
  });
  assert.equal(thrown.status, 'execution_failed');
  if (thrown.status === 'execution_failed') {
    assert.equal(thrown.reasonCode, 'crt_sh_fetch_failed');
  }

  const tools: ReconToolAdapters = {
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
    passiveCtTool: new CrtShAdapter({
      dnsResolver,
      fetchApi: createFailClosedCtFetch(),
    }),
    dnsTool: {
      async resolveDns(req) {
        return {
          status: 'success',
          contractVersion: DNS_RESOLUTION_CONTRACT_VERSION,
          targetDomain: req.targetDomain,
          observations: [
            {
              domain: req.targetDomain,
              recordType: 'A',
              values: ['93.184.216.34'],
              discoveredAt: decidedAt,
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
          status: 'preflight_denied',
          contractVersion: PORT_DISCOVERY_CONTRACT_VERSION,
          targetHostOrIp: req.targetHostOrIp,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    webTool: {
      async inspectWeb(req) {
        return {
          status: 'preflight_denied',
          contractVersion: WEB_INSPECTION_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    tlsTool: {
      async inspectTls(req) {
        return {
          status: 'preflight_denied',
          contractVersion: TLS_INSPECTION_CONTRACT_VERSION,
          targetHost: req.targetHostOrUrl,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    urlTool: {
      async discoverUrls(req) {
        return {
          status: 'preflight_denied',
          contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrDomain: req.targetUrlOrDomain,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    contentTool: {
      async discoverContent(req) {
        return {
          status: 'preflight_denied',
          contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          wordlistPath: req.wordlistPath,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    parameterTool: {
      async discoverParameters(req) {
        return {
          status: 'preflight_denied',
          contractVersion: PARAMETER_DISCOVERY_CONTRACT_VERSION,
          targetUrl: req.targetUrl,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
    secretTool: {
      async scanSecrets(req) {
        return {
          status: 'preflight_denied',
          contractVersion: SECRET_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrPath: req.targetUrlOrPath,
          reasonCode: 'not_used',
          reason: 'stage skipped',
          explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
          lineage: req.lineage,
        };
      },
    },
  };

  const result = await new CompositeActiveReconOrchestratorService(tools).orchestrate({
    targetDomain: HOST,
    verifiedAuthorizationDecision: established.decision,
    authorizedScopeGrant: grant,
    lineage: requestLineage,
    dnsResolver,
    config: {
      skipStages: [
        'stage_2_port_service',
        'stage_3_web_tls',
        'stage_4_crawling_parameters',
        'stage_deep_recon',
        'stage_5_secret_inspection',
      ],
      enableDeepRecon: false,
      enableSpaDiscovery: false,
    },
  });
  assert.equal(result.status, 'success');
  const stage1 = result.stages.find((stage) => stage.stage === 'stage_1_domain_zone');
  assert.ok(stage1);
  assert.equal(stage1.status, 'completed');
  const warnings = (stage1.warnings ?? []).join('\n');
  assert.equal(warnings.includes('crt_sh_fetch_failed'), false);
  assert.ok(warnings.includes('ct_transport_disabled'));
  assert.equal(result.aggregatedObservations.subdomains.length, 0);

  process.stdout.write('[milestone_ct_transport_disabled_smoke] passed\n');
}

main().catch(fail);
