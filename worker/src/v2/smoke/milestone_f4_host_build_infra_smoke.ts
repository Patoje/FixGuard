/**
 * F4 — host build, version, and infrastructure identity.
 * Hermetic recon must finish without calling the seven deferred surface detectors.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import {
  DEFERRED_SURFACE_PROBE_KINDS,
  deferredSurfaceProbeInvocationCount,
  resetDeferredSurfaceProbeLedger,
} from '../detection/DeferredSurfaceProbeLedger.js';
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
import { extractNextBuildId, classifyCapturedWafIdentity } from '../intelligence/CapturedHostIdentity.js';
import { factsFromCapturedRecon } from '../observation/CapturedHostFacts.js';
import { probeNextRouteManifests } from '../recon/deep/NextRouteManifestProbe.js';
import { TechnologyFingerprintService } from '../recon/analysis/TechnologyFingerprintService.js';
import { buildTargetProfile } from '../intelligence/TargetProfileBuilder.js';
import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import type { ExecutionRequest } from '../core/ExecutionContracts.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';

const DOMAIN = 'hostbuild.example.com';
const BUILD_ID = 'abc123def';
const HTML_WITH_BUILD = `<html><script id="__NEXT_DATA__" type="application/json">{"buildId":"${BUILD_ID}","page":"/"}</script></html>`;
const OBSERVED_AT = '2026-09-28T12:00:00.000Z';

function lineage(): AuthorizedExecutionLineageTuple {
  return {
    assessmentId: 'asm_f4_001',
    scanId: 'scn_f4_001',
    authorizationGrantId: 'grnt_f4_001',
    authorizationDecisionId: 'dec_f4_001',
    actorId: 'act_f4_001',
  };
}

function scopeGrant(permissions: Partial<AuthorizedScopeGrant['permissionSet']> = {}): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grnt_f4_001',
    scanId: 'scn_f4_001',
    issuedAt: '2026-09-28T11:00:00.000Z',
    expiresAt: '2026-09-29T11:00:00.000Z',
    subject: { targetKind: 'domain', domain: DOMAIN },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${DOMAIN}`,
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
      ...permissions,
    },
    boundaries: {
      allowedDomains: [DOMAIN],
      allowedHosts: [DOMAIN, '93.184.216.34'],
      allowedOrigins: [`https://${DOMAIN}`],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
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

function establish(grant: AuthorizedScopeGrant) {
  const nowIso = '2026-09-28T12:00:00.000Z';
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_f4_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_f4_001',
      authorizedActor: { actorId: 'act_f4_001', actorType: 'human' },
      decision: 'authorized',
      decidedAt: nowIso,
      scopeGrant: grant,
    },
    nowIso
  );
  if (authRes.status !== 'established') {
    throw new Error(`auth not established: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

function mockAdapters(): ReconToolAdapters {
  const discoveredAt = OBSERVED_AT;
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
              asn: 'AS15133',
              cdn: 'fastly',
              discoveredAt,
            },
            {
              domain: `docs.${req.targetDomain}`,
              recordType: 'CNAME',
              values: [`docs.${req.targetDomain}.github.io`],
              discoveredAt,
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
          observations: [
            {
              host: req.targetHostOrIp,
              ip: '93.184.216.34',
              port: 443,
              protocol: 'tcp',
              state: 'open',
              discoveredAt,
            },
          ],
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
              headers: {
                'cf-ray': '8f3a1b2c3d4e5f6a-EZE',
                'x-powered-by': 'Next.js 14.2.5',
                'set-cookie': 'session=secret; Secure; HttpOnly; SameSite=Lax',
              },
              bodyText: HTML_WITH_BUILD,
              discoveredAt,
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

async function pipelineDoesNotCallDeferredDetectors(): Promise<void> {
  resetDeferredSurfaceProbeLedger();
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const manifestGets: string[] = [];
  const transport: IdorHttpProbeTransport = async (request) => {
    if (request.url.includes('/_next/static/')) manifestGets.push(request.url);
    const path = new URL(request.url).pathname;
    return {
      statusCode: 200,
      headers: {},
      bodyText: request.url.includes('/_next/static/') ? `self.${path}` : '<html></html>',
      responseTimeMs: 1,
    };
  };
  const service = new OrchestratedAssessmentApplicationService({
    repository,
    reconAdapters: mockAdapters(),
    httpTransport: transport,
    dnsResolver: async () => ['93.184.216.34'],
    availabilityService: new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    }),
  });
  const launch = await service.startAssessment({ targetDomain: DOMAIN, actorId: 'act_f4_001' });
  const record = await service.awaitAssessment(launch.assessmentId);
  assert.equal(record?.status, 'completed');
  for (const kind of DEFERRED_SURFACE_PROBE_KINDS) {
    assert.equal(deferredSurfaceProbeInvocationCount(kind), 0, `${kind} must not auto-run`);
  }
  const plans = await service.getAttackPlans(launch.assessmentId);
  const deferred = [
    'cors_misconfiguration_probe',
    'security_header_probe',
    'open_redirect_probe',
    'information_disclosure_probe',
    'subdomain_takeover_probe',
    'graphql_surface_probe',
    'session_fixation_probe',
  ];
  for (const capability of deferred) {
    const plan = plans.plans.find((item) => item.capability === capability);
    assert.ok(plan, `missing plan ${capability}`);
    assert.equal(plan.executable, false);
  }
  const facts = record?.observedFacts ?? [];
  assert.ok(facts.some((fact) => fact.factKind === 'observed_build_id' && fact.value === BUILD_ID));
  assert.equal(facts.some((fact) => fact.factKind === 'observed_build_id' && fact.value !== BUILD_ID), false);
  const cookie = facts.find((fact) => fact.factKind === 'observed_cookie_flags');
  assert.ok(cookie);
  assert.equal(JSON.stringify(cookie).includes('secret'), false);
  assert.equal(cookie.value.includes('Secure'), true);
  const host = record?.profile?.discoveredHosts.find((item) => item.fqdn === DOMAIN);
  assert.equal(host?.nextBuildId, BUILD_ID);
  assert.equal(host?.wafIdentity, 'cf-ray');
  assert.ok(facts.some((fact) => fact.factKind === 'observed_asn' && fact.value === 'AS15133'));
  assert.ok(facts.some((fact) => fact.factKind === 'observed_cdn' && fact.value === 'fastly'));
  assert.ok(facts.some((fact) => fact.factKind === 'observed_tech_version' && fact.value === 'Next.js 14.2.5'));
  assert.ok(manifestGets.length <= 2);
  assert.ok(manifestGets.every((url) => url.includes(`/_next/static/${BUILD_ID}/`)));
  console.log('[milestone_f4_host_build_infra_smoke] pipeline deferred detectors and captured identity passed');
}

function buildIdOnlyFromCapturedHtml(): void {
  assert.equal(extractNextBuildId(HTML_WITH_BUILD), BUILD_ID);
  assert.equal(extractNextBuildId('<html><body>no next data</body></html>'), null);
  const empty = factsFromCapturedRecon({
    webs: [{ url: `https://${DOMAIN}/`, bodyText: '<html></html>', headers: {} }],
    dns: [],
    tls: [],
    externalDependencies: [],
    technologies: [],
    lineage: lineage(),
    observedAt: OBSERVED_AT,
  });
  assert.equal(empty.some((fact) => fact.factKind === 'observed_build_id'), false);
}

async function routeManifestPreflightAndBody(): Promise<void> {
  const grant = scopeGrant({ endpointDiscovery: false, passiveRecon: false, technologyFingerprinting: false });
  const decision = establish(grant);
  let calls = 0;
  const denied = await probeNextRouteManifests({
    originUrl: `https://${DOMAIN}/`,
    buildId: BUILD_ID,
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    lineage: lineage(),
    transport: async () => {
      calls += 1;
      throw new Error('GET must not run');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(denied.status, 'preflight_denied');
  assert.equal(denied.requestCount, 0);
  assert.equal(calls, 0);

  const allowed = establish(scopeGrant());
  const seen: string[] = [];
  const observed = await probeNextRouteManifests({
    originUrl: `https://${DOMAIN}/`,
    buildId: BUILD_ID,
    verifiedAuthorizationDecision: allowed,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: async (request) => {
      seen.push(request.url);
      const path = new URL(request.url).pathname;
      const include = path.endsWith('_buildManifest.js');
      return {
        statusCode: 200,
        headers: {},
        bodyText: include ? `routes ${path}` : 'manifest without the path token',
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(seen.length, 2);
  assert.equal(observed.facts.length, 1);
  assert.equal(observed.facts[0]?.value, `/_next/static/${BUILD_ID}/_buildManifest.js`);
}

function nextVersionOnlyFromLiteral(): void {
  const service = new TechnologyFingerprintService();
  const fromHeader = service.analyze({
    url: `https://${DOMAIN}/`,
    headers: { 'x-powered-by': 'Next.js 14.2.5' },
    bodyText: '<html></html>',
  });
  const next = fromHeader.technologies.find((tech) => tech.name === 'Next.js');
  assert.equal(next?.version, '14.2.5');
  const staticOnly = service.analyze({
    url: `https://${DOMAIN}/`,
    bodyText: '<script src="/_next/static/chunks/main.js"></script>',
  });
  const staticNext = staticOnly.technologies.find((tech) => tech.name === 'Next.js');
  assert.equal(staticNext?.version, undefined);
  const fromMap = service.analyze({
    url: `https://${DOMAIN}/`,
    bodyText: '<script src="/_next/static/chunks/main.js"></script>',
    sourcemapText: '/* React 18.2.0 */\nfunction App(){return null}',
  });
  const react = fromMap.technologies.find((tech) => tech.name === 'React');
  assert.equal(react?.version, '18.2.0');

  const htmlBody = '<script src="/_next/static/chunks/main.js"></script>';
  const withComment = buildTargetProfile({
    targetHost: DOMAIN,
    normalizedOrigin: `https://${DOMAIN}`,
    lineage: lineage(),
    observations: [
      {
        url: `https://${DOMAIN}/`,
        bodyText: htmlBody,
        sourcemapText: '/* Next.js 14.2.5 */',
      },
    ],
  });
  const profileNext = withComment.detectedTechnologies?.find((tech) => tech.name === 'Next.js');
  assert.equal(profileNext?.version, '14.2.5');
  const withoutComment = buildTargetProfile({
    targetHost: DOMAIN,
    normalizedOrigin: `https://${DOMAIN}`,
    lineage: lineage(),
    observations: [
      {
        url: `https://${DOMAIN}/`,
        bodyText: htmlBody,
      },
    ],
  });
  const bareNext = withoutComment.detectedTechnologies?.find((tech) => tech.name === 'Next.js');
  assert.equal(bareNext?.version, undefined);
}

async function dnsxAsnCdnAndDeniedProcess(): Promise<void> {
  let launches = 0;
  const runner: ProcessRunner = {
    async execute(request: ExecutionRequest) {
      launches += 1;
      assert.equal(request.args.includes('-axfr'), false);
      assert.equal(request.args.includes('-asn'), true);
      assert.equal(request.args.includes('-cdn'), true);
      const line = JSON.stringify({
        host: DOMAIN,
        a: ['93.184.216.34'],
        asn: 'AS15133',
        cdn: 'fastly',
      });
      const foreign = JSON.stringify({
        host: 'other.example.net',
        a: ['1.2.3.4'],
        asn: 'AS1',
        cdn: 'othercdn',
      });
      return { stdout: `${line}\n${foreign}\n`, stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
    },
  };
  const grant = scopeGrant();
  const decision = establish(grant);
  const adapter = new DnsxAdapter(runner, async () => ['93.184.216.34']);
  const denied = await adapter.resolveDns({
    targetDomain: 'outside.example.net',
    asn: true,
    cdn: true,
    axfr: false,
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: grant,
    lineage: lineage(),
  });
  assert.equal(denied.status, 'preflight_denied');
  assert.equal(launches, 0);

  const allowed = await adapter.resolveDns({
    targetDomain: DOMAIN,
    asn: true,
    cdn: true,
    verifiedAuthorizationDecision: decision,
    authorizedScopeGrant: grant,
    lineage: lineage(),
  });
  assert.equal(allowed.status, 'success');
  if (allowed.status !== 'success') return;
  const own = allowed.observations.find((item) => item.domain === DOMAIN && item.recordType === 'A');
  assert.equal(own?.asn, 'AS15133');
  assert.equal(own?.cdn, 'fastly');
  const foreign = allowed.observations.find((item) => item.domain === 'other.example.net');
  assert.equal(foreign?.asn, undefined);
  assert.equal(foreign?.cdn, undefined);
}

function wafFromCapturedMarkerOnly(): void {
  assert.equal(classifyCapturedWafIdentity({ headers: { 'cf-ray': '8f3a1b2c3d4e5f6a-EZE' } }), 'cf-ray');
  assert.equal(classifyCapturedWafIdentity({ headers: { server: 'nginx' } }), null);
  const coordinator = new TargetExecutionCoordinator({ maxConcurrency: 1, requestsPerSecond: 10 });
  assert.equal(coordinator.getObservedWaf(DOMAIN), null);
  coordinator.noteObservedWaf(DOMAIN, 'cf-ray');
  assert.equal(coordinator.getObservedWaf(DOMAIN), 'cf-ray');
  const source = readFileSync(
    new URL('../application/OrchestratedAssessmentApplicationService.ts', import.meta.url),
    'utf8'
  );
  assert.equal(source.includes('observeWafWithWafw00f'), false);
}

async function main(): Promise<void> {
  await pipelineDoesNotCallDeferredDetectors();
  buildIdOnlyFromCapturedHtml();
  await routeManifestPreflightAndBody();
  nextVersionOnlyFromLiteral();
  await dnsxAsnCdnAndDeniedProcess();
  wafFromCapturedMarkerOnly();
  console.log('[milestone_f4_host_build_infra_smoke] ALL PASSED');
}

main().catch((err: unknown) => {
  console.error('[milestone_f4_host_build_infra_smoke] FATAL', err);
  process.exit(1);
});
