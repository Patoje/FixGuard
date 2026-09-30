/**
 * F5 — related hosts, cookie flags, security.txt, OpenID/OAuth.
 * No new network except the exact well-known GETs under preflight.
 */

import assert from 'node:assert/strict';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  HttpProbeResponse,
  IdorHttpProbeTransport,
} from '../detection/DetectionContracts.js';
import { factsFromCapturedRecon } from '../observation/CapturedHostFacts.js';
import { inspectOpenIdAndOAuth, inspectSecurityTxt } from '../recon/deep/WellKnownInspectService.js';
import { planDeepReconMethods } from '../recon/deep/DeepReconMethodPlanner.js';
import { GuardedHttpHeaderInspectAdapter } from '../recon/passive/GuardedHttpHeaderInspectAdapter.js';
import type { HttpHeaderInspectTransport } from '../recon/passive/HttpHeaderInspectTransport.js';
import type { CapabilityRequest } from '../core/ExecutionContracts.js';
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

const DOMAIN = 'hybrid.example.com';
const AUTH_HOST = 'auth.hybrid.example.com';
const OUTSIDE = 'cdn.other.example.net';
const SUFFIX_ONLY = 'leaf.hybrid.example.com';
const OBSERVED_AT = '2026-09-28T12:00:00.000Z';

function lineage(): AuthorizedExecutionLineageTuple {
  return {
    assessmentId: 'asm_f5_001',
    scanId: 'scn_f5_001',
    authorizationGrantId: 'grnt_f5_001',
    authorizationDecisionId: 'dec_f5_001',
    actorId: 'act_f5_001',
  };
}

function scopeGrant(hosts: readonly string[], discover = true): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grnt_f5_001',
    scanId: 'scn_f5_001',
    issuedAt: '2026-09-28T11:00:00.000Z',
    expiresAt: '2026-09-29T11:00:00.000Z',
    subject: { targetKind: 'domain', domain: DOMAIN },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${DOMAIN}`,
    },
    permissionSet: {
      passiveRecon: discover,
      technologyFingerprinting: true,
      endpointDiscovery: discover,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [DOMAIN, ...hosts.filter((host) => host.endsWith(DOMAIN) || host === DOMAIN)],
      allowedHosts: [DOMAIN, '93.184.216.34', ...hosts],
      allowedOrigins: [`https://${DOMAIN}`, ...hosts.map((host) => `https://${host}`)],
      allowedMethods: ['GET', 'HEAD'],
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

function establish(grant: AuthorizedScopeGrant) {
  const nowIso = OBSERVED_AT;
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_f5_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_f5_001',
      authorizedActor: { actorId: 'act_f5_001', actorType: 'human' },
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

function relatedHostsStayFactsUntilInGrant(): void {
  const body = `<script src="https://${OUTSIDE}/app.js"></script>`;
  const facts = factsFromCapturedRecon({
    webs: [{ url: `https://${DOMAIN}/`, bodyText: body, headers: {} }],
    dns: [],
    tls: [{ host: DOMAIN, subjectAlternativeNames: [`${AUTH_HOST}`, `*.${OUTSIDE}`] }],
    externalDependencies: [
      {
        kind: 'csp_script_src',
        value: OUTSIDE,
        sourceHost: DOMAIN,
        epistemicStatus: 'OBSERVED',
      },
    ],
    technologies: [],
    lineage: lineage(),
    observedAt: OBSERVED_AT,
  });
  const related = facts.filter((fact) => fact.factKind === 'observed_related_host');
  assert.equal(related.some((fact) => fact.value === OUTSIDE && fact.sourceLabel === 'js'), true);
  assert.equal(related.some((fact) => fact.value === OUTSIDE && fact.sourceLabel === 'csp'), true);
  assert.ok(related.some((fact) => fact.value === AUTH_HOST && fact.sourceLabel === 'tls_san'));
  for (const fact of related) {
    assert.equal(fact.epistemicStatus, 'OBSERVED');
  }
  assert.equal(body.includes(OUTSIDE), true);
}

async function cookieFlagsDropTheValue(): Promise<void> {
  const setCookie = 'session=secret; Secure; HttpOnly; SameSite=Lax';
  const facts = factsFromCapturedRecon({
    webs: [{
      url: `https://${DOMAIN}/`,
      bodyText: '<html></html>',
      headers: { 'set-cookie': setCookie },
    }],
    dns: [],
    tls: [],
    externalDependencies: [],
    technologies: [],
    lineage: lineage(),
    observedAt: OBSERVED_AT,
  });
  const cookie = facts.find((fact) => fact.factKind === 'observed_cookie_flags');
  assert.ok(cookie);
  assert.equal(cookie.value, 'session;Secure;HttpOnly;SameSite=Lax');
  assert.equal(JSON.stringify(cookie).includes('secret'), false);

  const transport: HttpHeaderInspectTransport = {
    async execute() {
      return {
        statusCode: 200,
        statusText: 'OK',
        headers: { 'set-cookie': setCookie, server: 'example' },
      };
    },
  };
  const adapter = new GuardedHttpHeaderInspectAdapter(transport, {
    allowedOrigins: [`https://${DOMAIN}`],
    allowSameHostPaths: true,
    allowSubdomains: false,
  });
  const request: CapabilityRequest = {
    capability: 'http.header.inspect',
    target: { uri: `https://${DOMAIN}/` },
    config: {},
  };
  const evidence = await adapter.execute(request);
  const encoded = JSON.stringify(evidence);
  assert.equal(encoded.includes('secret'), false);
  const flags = evidence.metadata.cookieFlags;
  assert.ok(Array.isArray(flags));
  const first = flags[0];
  assert.equal(typeof first === 'object' && first !== null && 'name' in first && first.name, 'session');
}

async function securityTxtPresenceWithoutBody(): Promise<void> {
  const plan = planDeepReconMethods({
    stack: {},
    budget: { maxRequests: 50, remainingRequests: 50 },
  });
  assert.ok(plan.some((entry) => entry.method === 'security_txt'));
  const grant = scopeGrant([]);
  const decision = establish(grant);
  let calls = 0;
  const deniedGrant = scopeGrant([], false);
  const denied = await inspectSecurityTxt({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: establish(deniedGrant),
    scopeGrant: deniedGrant,
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

  const bodySentence = 'Contact: security@hybrid.example.com\nPolicy: internal-only-sentence';
  const observed = await inspectSecurityTxt({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    lineage: lineage(),
    transport: async () => ({
      statusCode: 200,
      headers: {},
      bodyText: bodySentence,
      responseTimeMs: 1,
    }),
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(observed.requestCount, 1);
  assert.ok(observed.fact);
  assert.equal(observed.fact.value.includes('reachable=true'), true);
  assert.equal(observed.fact.value.includes('contact=true'), true);
  assert.equal(JSON.stringify(observed.fact).includes('internal-only-sentence'), false);
  assert.equal(JSON.stringify(observed.fact).includes('security@hybrid.example.com'), false);
}

async function openIdExactPathsNoRedirectFollow(): Promise<void> {
  const plan = planDeepReconMethods({
    stack: {},
    budget: { maxRequests: 50, remainingRequests: 50 },
  });
  assert.ok(plan.some((entry) => entry.method === 'well_known_oauth'));
  const grant = scopeGrant([AUTH_HOST]);
  const decision = establish(grant);
  const urls: string[] = [];
  const transport: IdorHttpProbeTransport = async (request): Promise<HttpProbeResponse> => {
    urls.push(request.url);
    assert.equal(request.method, 'GET');
    const response: HttpProbeResponse = {
      statusCode: 404,
      headers: { 'content-type': 'text/plain' },
      bodyText: '',
      responseTimeMs: 1,
    };
    const host = new URL(request.url).hostname;
    if (host === DOMAIN && request.url.endsWith('/.well-known/openid-configuration')) {
      return {
        ...response,
        statusCode: 302,
        headers: { location: 'https://evil.example/leave' },
        bodyText: '{"issuer":"https://evil.example/leave"}',
      };
    }
    if (host === AUTH_HOST && request.url.endsWith('/.well-known/openid-configuration')) {
      return {
        ...response,
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: `{"issuer":"https://${AUTH_HOST}/realms/app","client_secret":"supersecretvalue"}`,
      };
    }
    return response;
  };
  const observed = await inspectOpenIdAndOAuth({
    originUrl: `https://${DOMAIN}/`,
    authHosts: [AUTH_HOST, OUTSIDE],
    verifiedAuthorizationDecision: decision,
    scopeGrant: grant,
    lineage: lineage(),
    transport,
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(urls.some((url) => url.includes(OUTSIDE)), false);
  assert.equal(urls.filter((url) => url.includes(AUTH_HOST)).length, 2);
  assert.equal(urls.filter((url) => url.includes(`://${DOMAIN}`)).length, 2);
  const encoded = JSON.stringify(observed.facts);
  assert.equal(encoded.includes('supersecretvalue'), false);
  assert.equal(encoded.includes('https://evil.example/leave'), false);
  const authFact = observed.facts.find((fact) => fact.sourceUrl.includes(AUTH_HOST) && fact.value.includes('openid-configuration'));
  assert.ok(authFact);
  assert.equal(authFact.value.includes(`issuer=https://${AUTH_HOST}/realms/app`), true);
  const redirectFact = observed.facts.find((fact) => fact.sourceUrl.includes(`://${DOMAIN}`) && fact.value.includes('openid-configuration'));
  assert.ok(redirectFact);
  assert.equal(redirectFact.value.includes('reachable=false'), true);
  assert.equal(redirectFact.value.includes('issuer='), false);
}

async function sanHostOutsideGrantReceivesNoHttp(): Promise<void> {
  const base = scopeGrant([]);
  const grant: AuthorizedScopeGrant = {
    ...base,
    permissionSet: {
      ...base.permissionSet,
      activeCrawling: true,
    },
  };
  const allowedHosts = grant.boundaries.allowedHosts ?? [];
  const allowedDomains = grant.boundaries.allowedDomains ?? [];
  assert.equal(allowedHosts.includes(OUTSIDE), false);
  assert.equal(allowedHosts.includes(SUFFIX_ONLY), false);
  assert.equal(allowedDomains.includes(DOMAIN), true);
  const decision = establish(grant);
  const seenUrls: string[] = [];
  const seenDns: string[] = [];
  const body = `<script src="https://${OUTSIDE}/app.js"></script>`;
  const captured = factsFromCapturedRecon({
    webs: [{ url: `https://${DOMAIN}/`, bodyText: body, headers: {} }],
    dns: [],
    tls: [{ host: DOMAIN, subjectAlternativeNames: [OUTSIDE, SUFFIX_ONLY] }],
    externalDependencies: [],
    technologies: [],
    lineage: lineage(),
    observedAt: OBSERVED_AT,
  });
  assert.equal(
    captured.some((fact) => fact.factKind === 'observed_related_host' && fact.value === OUTSIDE),
    true
  );
  const adapters: ReconToolAdapters = {
    subdomainTool: {
      discoverSubdomains: async () => ({
        status: 'success',
        contractVersion: 'fixguard-subdomain-discovery/v0',
        targetDomain: DOMAIN,
        observations: [],
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: lineage(),
        durationMs: 1,
      }),
    },
    dnsTool: {
      resolveDns: async (req) => {
        seenDns.push(req.targetDomain);
        return {
          status: 'success',
          contractVersion: 'fixguard-dns-resolution/v0',
          targetDomain: req.targetDomain,
          observations: [],
          explicitNonClaims: DNS_RESOLUTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    portTool: {
      discoverPorts: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-port-discovery/v0',
        targetHostOrIp: req.targetHostOrIp,
        observations: [],
        explicitNonClaims: PORT_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    webTool: {
      inspectWeb: async (req) => {
        seenUrls.push(req.targetUrl);
        const facts = factsFromCapturedRecon({
          webs: [{ url: req.targetUrl, bodyText: body, headers: {} }],
          dns: [],
          tls: [{ host: DOMAIN, subjectAlternativeNames: [OUTSIDE, SUFFIX_ONLY] }],
          externalDependencies: [],
          technologies: [],
          lineage: lineage(),
          observedAt: OBSERVED_AT,
        });
        return {
          status: 'success',
          contractVersion: 'fixguard-web-inspection/v0',
          targetUrl: req.targetUrl,
          observations: [{
            url: req.targetUrl,
            method: 'GET',
            statusCode: 200,
            technologies: [],
            bodyText: body,
            headers: {},
            discoveredAt: OBSERVED_AT,
          }],
          observedFacts: facts,
          explicitNonClaims: WEB_INSPECTION_NON_CLAIMS,
          lineage: req.lineage,
          durationMs: 1,
        };
      },
    },
    tlsTool: {
      inspectTls: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-tls-inspection/v0',
        targetHost: req.targetHostOrUrl,
        observations: [{
          host: DOMAIN,
          port: 443,
          subjectAlternativeNames: [OUTSIDE, SUFFIX_ONLY, `*.${DOMAIN}`],
          supportedProtocols: ['TLSv1.3'],
          cipherSuites: ['TLS_AES_256_GCM_SHA384'],
          discoveredAt: OBSERVED_AT,
        }],
        explicitNonClaims: TLS_INSPECTION_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    urlTool: {
      discoverUrls: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-url-discovery/v0',
        targetUrlOrDomain: req.targetUrlOrDomain,
        observations: [],
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    contentTool: {
      discoverContent: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-content-discovery/v0',
        targetUrl: req.targetUrl,
        wordlistPath: req.wordlistPath ?? '',
        observations: [],
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    parameterTool: {
      discoverParameters: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-parameter-discovery/v0',
        targetUrl: req.targetUrl,
        observations: [],
        explicitNonClaims: PARAMETER_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
    secretTool: {
      scanSecrets: async (req) => ({
        status: 'success',
        contractVersion: 'fixguard-secret-discovery/v0',
        targetUrlOrPath: req.targetUrlOrPath,
        observations: [],
        explicitNonClaims: SECRET_DISCOVERY_NON_CLAIMS,
        lineage: req.lineage,
        durationMs: 1,
      }),
    },
  };
  const fetched: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    fetched.push(url);
    return new Response('', { status: 404 });
  };
  try {
    const result = await new CompositeActiveReconOrchestratorService(adapters).orchestrate({
      targetDomain: DOMAIN,
      verifiedAuthorizationDecision: decision,
      authorizedScopeGrant: grant,
      lineage: lineage(),
      dnsResolver: async () => ['93.184.216.34'],
      config: {
        skipStages: [
          'stage_1_domain_zone',
          'stage_2_port_service',
          'stage_4_crawling_parameters',
          'stage_5_secret_inspection',
          'stage_deep_recon',
        ],
        enableDeepRecon: false,
        enableSpaDiscovery: false,
      },
    });
    assert.equal(result.status, 'success');
    const related = (result.status === 'success' ? result.aggregatedObservations.observedFacts ?? [] : [])
      .filter((fact) => fact.factKind === 'observed_related_host');
    assert.equal(related.some((fact) => fact.value === OUTSIDE), true);
    const touches = (url: string): boolean => url.includes(OUTSIDE) || url.includes(SUFFIX_ONLY);
    assert.equal(seenUrls.filter(touches).length, 0);
    assert.equal(seenDns.filter((host) => host === OUTSIDE || host === SUFFIX_ONLY).length, 0);
    assert.equal(fetched.filter(touches).length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function main(): Promise<void> {
  relatedHostsStayFactsUntilInGrant();
  await sanHostOutsideGrantReceivesNoHttp();
  await cookieFlagsDropTheValue();
  await securityTxtPresenceWithoutBody();
  await openIdExactPathsNoRedirectFollow();
  console.log('[milestone_f5_hybrid_cookies_wellknown_smoke] ALL PASSED');
}

main().catch((err: unknown) => {
  console.error('[milestone_f5_hybrid_cookies_wellknown_smoke] FATAL', err);
  process.exit(1);
});
