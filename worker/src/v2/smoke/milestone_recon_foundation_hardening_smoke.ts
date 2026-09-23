/**
 * Milestone 3 Track R — Recon Foundation Hardening Smoke Suite (R1a–R1d)
 *
 * Hermetic: no live Internet / CT / DNS / targets for core assertions.
 * Verifies:
 *  R1a — CrtShAdapter parse, malformed reject, scope, CT provenance (historical)
 *  R1b — DnsRecordType extension + DnsxAdapter opt-in axfr/asn/cdn (absent by default)
 *  R1c — freshness / collectedAt / sourceReliability tagging
 *  R1d — TLS SAN → subdomain feedback, scope gate, idempotent multi-source
 */

import assert from 'node:assert';
import type { ExecutionRequest, RawExecutionOutput } from '../core/ExecutionContracts.js';
import type { ProcessRunner } from '../core/ProcessRunner.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import { CrtShAdapter } from '../recon/adapters/CrtShAdapter.js';
import { DnsxAdapter } from '../recon/adapters/DnsxAdapter.js';
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

function createScopeGrant(overrides?: Partial<AuthorizedScopeGrant>): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_m3_r1_001',
    scanId: 'scan_m3_r1_001',
    issuedAt: '2026-09-23T12:00:00.000Z',
    expiresAt: '2026-09-24T12:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone 3 recon foundation hardening',
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
      allowedHosts: ['example.com', 'api.example.com', 'cdn.example.com', 'san.example.com'],
      allowedOrigins: ['https://example.com', 'https://api.example.com', 'https://cdn.example.com', 'https://san.example.com'],
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
    ...overrides,
  };
}

function setupAuthorizedContext(scopeGrant = createScopeGrant()) {
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'assess_m3_r1_001',
      scanId: scopeGrant.scanId,
      authorizationDecisionId: 'decision_m3_r1_001',
      authorizedActor: { actorId: 'secops_analyst_1', actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-09-23T12:00:00.000Z',
      scopeGrant,
    },
    '2026-09-23T12:00:00.000Z'
  );

  if (establishResult.status !== 'established') {
    throw new Error(`Failed to establish verified decision: ${establishResult.safeMessage}`);
  }

  const lineage: AuthorizedActiveReconRequestLineage = {
    assessmentId: 'assess_m3_r1_001',
    scanId: scopeGrant.scanId,
    authorizationGrantId: scopeGrant.grantId,
    authorizationDecisionId: 'decision_m3_r1_001',
    actorId: 'secops_analyst_1',
  };

  return {
    verifiedAuthorizationDecision: establishResult.decision,
    authorizedScopeGrant: scopeGrant,
    lineage,
  };
}

class MockProcessRunner implements ProcessRunner {
  public calls: ExecutionRequest[] = [];
  public nextOutput: RawExecutionOutput = {
    stdout: '',
    stderr: '',
    exitCode: 0,
    durationMs: 10,
    timedOut: false,
  };

  async execute(request: ExecutionRequest): Promise<RawExecutionOutput> {
    this.calls.push(request);
    return this.nextOutput;
  }
}

type MockFetchCall = { url: string; init?: RequestInit };

function createMockFetch(handler: (url: string) => Promise<Response> | Response): {
  fetchApi: typeof fetch;
  calls: MockFetchCall[];
} {
  const calls: MockFetchCall[] = [];
  const fetchApi: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    calls.push({ url, init });
    return handler(url);
  }) as typeof fetch;
  return { fetchApi, calls };
}

async function runMilestoneReconFoundationHardeningSmoke() {
  console.log('=== [M3 R1 SMOKE] Recon Foundation Hardening (R1a–R1d) ===\n');

  // -------------------------------------------------------------------------
  // R1a: CrtShAdapter happy path — hermetic mock fetch
  // -------------------------------------------------------------------------
  console.log('[*] R1a-1: CT-log parse, normalize, dedupe, historical provenance');
  {
    const auth = setupAuthorizedContext();
    const { fetchApi, calls } = createMockFetch(() =>
      Response.json([
        { name_value: 'api.example.com\nwww.example.com', common_name: 'example.com' },
        { name_value: '*.cdn.example.com', common_name: 'cdn.example.com' },
        { name_value: 'api.example.com', common_name: 'api.example.com' }, // dedupe
        { name_value: 'evil.other.com', common_name: 'other.com' }, // out of target suffix
        { name_value: 'not a host!!!', common_name: 123 }, // malformed
      ])
    );

    const adapter = new CrtShAdapter({ fetchApi });
    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      ...auth,
      timeoutMs: 5_000,
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      const hosts = result.observations.map((o) => o.subdomain).sort();
      assert.deepStrictEqual(hosts, ['api.example.com', 'cdn.example.com', 'example.com', 'www.example.com']);
      for (const obs of result.observations) {
        assert.strictEqual(obs.freshness, 'historical');
        assert.strictEqual(obs.sourceReliability, 'historical_archive');
        assert.ok(typeof obs.collectedAt === 'string' && obs.collectedAt.endsWith('Z'));
        assert.deepStrictEqual(obs.sources, ['crt_sh_ct_log']);
      }
      assert.ok(!hosts.includes('evil.other.com'), 'out-of-scope host must not appear');
    }
    assert.strictEqual(calls.length, 1);
    assert.ok(calls[0]!.url.includes('crt.sh'));
    assert.ok(calls[0]!.url.includes('output=json'));
    console.log('    -> CT parse/dedupe/provenance verified (hermetic)');
  }

  // -------------------------------------------------------------------------
  // R1a: Malformed JSON / non-array
  // -------------------------------------------------------------------------
  console.log('[*] R1a-2: Malformed JSON rejected; non-array yields empty success');
  {
    const auth = setupAuthorizedContext();
    const badJson = createMockFetch(() => new Response('NOT_JSON{{{', { status: 200 }));
    const adapterBad = new CrtShAdapter({ fetchApi: badJson.fetchApi });
    const failResult = await adapterBad.discoverSubdomains({ targetDomain: 'example.com', ...auth });
    assert.strictEqual(failResult.status, 'execution_failed');
    if (failResult.status === 'execution_failed') {
      assert.strictEqual(failResult.reasonCode, 'crt_sh_json_parse_failed');
    }

    const nonArray = createMockFetch(() => Response.json({ unexpected: true }));
    const adapterEmpty = new CrtShAdapter({ fetchApi: nonArray.fetchApi });
    const emptyResult = await adapterEmpty.discoverSubdomains({ targetDomain: 'example.com', ...auth });
    assert.strictEqual(emptyResult.status, 'success');
    if (emptyResult.status === 'success') {
      assert.strictEqual(emptyResult.observations.length, 0);
    }
    console.log('    -> Malformed / non-array handling verified');
  }

  // -------------------------------------------------------------------------
  // R1a: Preflight denial — zero fetch
  // -------------------------------------------------------------------------
  console.log('[*] R1a-3: Preflight denial with zero network fetch');
  {
    const auth = setupAuthorizedContext();
    const { fetchApi, calls } = createMockFetch(() => Response.json([]));
    const adapter = new CrtShAdapter({ fetchApi });
    const spoofed = { ...auth.verifiedAuthorizationDecision, decision: 'authorized' as const };
    const result = await adapter.discoverSubdomains({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: spoofed,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
    });
    assert.strictEqual(result.status, 'preflight_denied');
    assert.strictEqual(calls.length, 0);
    console.log('    -> Zero-fetch preflight denial verified');
  }

  // -------------------------------------------------------------------------
  // R1b: DNS record types + opt-in flags
  // -------------------------------------------------------------------------
  console.log('[*] R1b-1: Extended record types and opt-in axfr/asn/cdn absent by default');
  {
    const runner = new MockProcessRunner();
    runner.nextOutput = {
      stdout: [
        JSON.stringify({ host: 'example.com', a: ['93.184.216.34'], ns: ['ns1.example.com'], soa: ['ns1.example.com hostmaster.example.com'] }),
      ].join('\n'),
      stderr: '',
      exitCode: 0,
      durationMs: 20,
      timedOut: false,
    };
    const adapter = new DnsxAdapter(runner);
    const auth = setupAuthorizedContext();

    const defaultResult = await adapter.resolveDns({
      targetDomain: 'example.com',
      recordTypes: ['A', 'NS', 'SOA', 'CAA', 'SRV', 'PTR'],
      ...auth,
    });
    assert.strictEqual(defaultResult.status, 'success');
    const defaultArgs = runner.calls[0]!.args;
    assert.ok(defaultArgs.includes('-ns'));
    assert.ok(defaultArgs.includes('-soa'));
    assert.ok(defaultArgs.includes('-caa'));
    assert.ok(defaultArgs.includes('-srv'));
    assert.ok(defaultArgs.includes('-ptr'));
    assert.ok(!defaultArgs.includes('-axfr'), 'axfr must be opt-in');
    assert.ok(!defaultArgs.includes('-asn'), 'asn must be opt-in');
    assert.ok(!defaultArgs.includes('-cdn'), 'cdn must be opt-in');
    if (defaultResult.status === 'success') {
      const ns = defaultResult.observations.find((o) => o.recordType === 'NS');
      assert.ok(ns);
      assert.strictEqual(ns!.freshness, 'live');
      assert.strictEqual(ns!.sourceReliability, 'direct_observation');
      assert.ok(typeof ns!.collectedAt === 'string');
    }

    runner.calls = [];
    runner.nextOutput = { ...runner.nextOutput, stdout: '' };
    await adapter.resolveDns({
      targetDomain: 'example.com',
      axfr: true,
      asn: true,
      cdn: true,
      ...auth,
    });
    const optArgs = runner.calls[0]!.args;
    assert.ok(optArgs.includes('-axfr'));
    assert.ok(optArgs.includes('-asn'));
    assert.ok(optArgs.includes('-cdn'));
    console.log('    -> DNS record types + opt-in flags verified');
  }

  // -------------------------------------------------------------------------
  // R1c + R1d: Orchestrator CT merge + SAN feedback idempotency
  // -------------------------------------------------------------------------
  console.log('[*] R1c/R1d: Orchestrator CT merge, SAN feedback, multi-source idempotency');
  {
    const auth = setupAuthorizedContext();
    const dnsCalls: string[] = [];
    const httpCalls: string[] = [];
    const tlsCalls: string[] = [];

    const tools: ReconToolAdapters = {
      subdomainTool: {
        async discoverSubdomains(req) {
          return {
            status: 'success',
            contractVersion: 'fixguard-subdomain-discovery/v0',
            targetDomain: req.targetDomain,
            observations: [
              {
                subdomain: 'api.example.com',
                parentDomain: req.targetDomain,
                sources: ['subfinder'],
                discoveredAt: '2026-09-23T12:00:00.000Z',
                collectedAt: '2026-09-23T12:00:00.000Z',
                freshness: 'unknown',
                sourceReliability: 'historical_archive',
                confidence: 0.9,
              },
            ],
            explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
            lineage: req.lineage,
            durationMs: 5,
          };
        },
      },
      passiveCtTool: {
        async discoverSubdomains(req) {
          return {
            status: 'success',
            contractVersion: 'fixguard-subdomain-discovery/v0',
            targetDomain: req.targetDomain,
            observations: [
              {
                subdomain: 'api.example.com', // overlap with subfinder — must merge, not duplicate
                parentDomain: req.targetDomain,
                sources: ['crt_sh_ct_log'],
                discoveredAt: '2026-09-23T12:00:01.000Z',
                collectedAt: '2026-09-23T12:00:01.000Z',
                freshness: 'historical',
                sourceReliability: 'historical_archive',
                confidence: 0.85,
              },
              {
                subdomain: 'cdn.example.com',
                parentDomain: req.targetDomain,
                sources: ['crt_sh_ct_log'],
                discoveredAt: '2026-09-23T12:00:01.000Z',
                collectedAt: '2026-09-23T12:00:01.000Z',
                freshness: 'historical',
                sourceReliability: 'historical_archive',
                confidence: 0.85,
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
          dnsCalls.push(req.targetDomain);
          return {
            status: 'success',
            contractVersion: 'fixguard-dns-resolution/v0',
            targetDomain: req.targetDomain,
            observations: [
              {
                domain: req.targetDomain,
                recordType: 'A',
                values: ['93.184.216.34'],
                discoveredAt: '2026-09-23T12:00:02.000Z',
                collectedAt: '2026-09-23T12:00:02.000Z',
                freshness: 'live',
                sourceReliability: 'direct_observation',
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
          return {
            status: 'success',
            contractVersion: 'fixguard-port-discovery/v0',
            targetHostOrIp: req.targetHostOrIp,
            observations: [
              {
                host: typeof req.targetHostOrIp === 'string' ? req.targetHostOrIp : 'example.com',
                ip: '93.184.216.34',
                port: 443,
                protocol: 'tcp',
                state: 'open',
                discoveredAt: '2026-09-23T12:00:03.000Z',
                collectedAt: '2026-09-23T12:00:03.000Z',
                freshness: 'live',
                sourceReliability: 'direct_observation',
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
          const host = new URL(req.targetUrl).hostname;
          httpCalls.push(host);
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
                discoveredAt: '2026-09-23T12:00:04.000Z',
                collectedAt: '2026-09-23T12:00:04.000Z',
                freshness: 'live',
                sourceReliability: 'direct_observation',
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
          tlsCalls.push(req.targetHostOrUrl);
          return {
            status: 'success',
            contractVersion: 'fixguard-tls-inspection/v0',
            targetHost: req.targetHostOrUrl,
            observations: [
              {
                host: req.targetHostOrUrl,
                port: 443,
                subjectAlternativeNames: [
                  'san.example.com',
                  '*.san.example.com',
                  'api.example.com', // already known — must not re-enqueue
                  'evil.out-of-scope.com', // out of AuthorizedScopeGrant
                  'not!!valid',
                ],
                supportedProtocols: ['tls13'],
                cipherSuites: ['TLS_AES_128_GCM_SHA256'],
                discoveredAt: '2026-09-23T12:00:05.000Z',
                collectedAt: '2026-09-23T12:00:05.000Z',
                freshness: 'live',
                sourceReliability: 'direct_observation',
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

    const orchestrator = new CompositeActiveReconOrchestratorService(tools);
    const result = await orchestrator.orchestrate({
      targetDomain: 'example.com',
      verifiedAuthorizationDecision: auth.verifiedAuthorizationDecision,
      authorizedScopeGrant: auth.authorizedScopeGrant,
      lineage: auth.lineage,
      config: {
        skipStages: ['stage_4_crawling_parameters', 'stage_5_secret_inspection'],
      },
    });

    assert.strictEqual(result.status, 'success');
    if (result.status === 'success') {
      const subs = result.aggregatedObservations.subdomains;
      const api = subs.find((s) => s.subdomain === 'api.example.com');
      assert.ok(api, 'api.example.com must exist once after merge');
      assert.ok(api!.sources?.includes('subfinder'));
      assert.ok(api!.sources?.includes('crt_sh_ct_log'));
      assert.strictEqual(subs.filter((s) => s.subdomain === 'api.example.com').length, 1);

      const cdn = subs.find((s) => s.subdomain === 'cdn.example.com');
      assert.ok(cdn);
      assert.strictEqual(cdn!.freshness, 'historical');

      const san = subs.find((s) => s.subdomain === 'san.example.com');
      assert.ok(san, 'SAN host must be enqueued as subdomain candidate');
      assert.deepStrictEqual(san!.sources, ['tls_san']);
      assert.strictEqual(san!.freshness, 'unknown');
      assert.strictEqual(san!.sourceReliability, 'inferred_relationship');
      assert.ok(!subs.some((s) => s.subdomain === 'evil.out-of-scope.com'));

      // DNS must run once per unique host (example.com, api, cdn, + san feedback) — not triple for api
      const dnsUnique = [...new Set(dnsCalls)];
      assert.strictEqual(dnsCalls.length, dnsUnique.length, 'DNS must be idempotent per host');
      assert.ok(dnsCalls.includes('san.example.com'), 'SAN feedback must trigger DNS follow-up');
      assert.ok(httpCalls.includes('san.example.com'), 'SAN feedback must trigger HTTP follow-up');

      // No uncontrolled TLS recursion on SAN-only host
      assert.ok(!tlsCalls.includes('san.example.com'), 'SAN feedback must not recurse into TLS');
    }
    console.log('    -> CT merge + SAN feedback idempotency verified');
  }

  console.log('\n=== [M3 R1 SMOKE] ALL ASSERTIONS PASSED ===');
}

runMilestoneReconFoundationHardeningSmoke().catch((err) => {
  console.error('FAIL', err);
  process.exit(1);
});
