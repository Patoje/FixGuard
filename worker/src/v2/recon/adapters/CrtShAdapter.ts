import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  FQDN_REGEX,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
  SUBDOMAIN_DISCOVERY_NON_CLAIMS,
  type DiscoveredSubdomainObservation,
  type SubdomainDiscoveryRequest,
  type SubdomainDiscoveryResult,
  type SubdomainDiscoveryTool,
} from './SubdomainDiscoveryContracts.js';

export interface CrtShOptions {
  readonly fetchApi?: typeof fetch;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export class CrtShAdapter implements SubdomainDiscoveryTool {
  private readonly fetchImpl: typeof fetch;
  private readonly dnsResolver: PreSpawnDnsResolver | undefined;

  constructor(options?: CrtShOptions) {
    this.fetchImpl = options?.fetchApi ?? fetch;
    this.dnsResolver = options?.dnsResolver;
  }

  async discoverSubdomains(request: SubdomainDiscoveryRequest): Promise<SubdomainDiscoveryResult> {
    const startTime = Date.now();

    // 1. Unified 7-Pass Preflight Gate
    const preflight = await runAdapterPreflight({
      target: request.targetDomain,
      targetKind: 'fqdn',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.passiveRecon),
      missingPermissionReason: 'Scope grant does not permit endpointDiscovery or passiveRecon',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain: request.targetDomain,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const targetDomain = preflight.targetHost;

    // 2. Native CT-Log Direct Query Execution
    const timeoutMs = request.timeoutMs ?? 15_000;
    const url = `https://crt.sh/?q=%25.${encodeURIComponent(targetDomain)}&output=json`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        signal: controller.signal,
        headers: {
          Accept: 'application/json',
          'User-Agent': 'FixGuard-Recon/2.0',
        },
      });
    } catch (err: unknown) {
      clearTimeout(timer);
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'crt_sh_fetch_failed',
        reason: `Failed to query crt.sh API: ${msg}`,
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: Date.now() - startTime,
      };
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      return {
        status: 'execution_failed',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'crt_sh_http_error',
        reason: `crt.sh returned HTTP status ${response.status}`,
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: Date.now() - startTime,
      };
    }

    let records: unknown;
    try {
      records = await response.json();
    } catch {
      return {
        status: 'execution_failed',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        reasonCode: 'crt_sh_json_parse_failed',
        reason: 'Failed to parse JSON response from crt.sh',
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: Date.now() - startTime,
      };
    }

    if (!Array.isArray(records)) {
      return {
        status: 'success',
        contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
        targetDomain,
        observations: [],
        explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: Date.now() - startTime,
      };
    }

    // 3. Extract & Validate Discovered Hostnames
    const observationsMap = new Map<
      string,
      {
        subdomain: string;
        parentDomain: string;
        discoveredAt: string;
      }
    >();

    const nowIso = new Date().toISOString();

    for (const item of records) {
      if (!item || typeof item !== 'object') continue;
      const rec = item as Record<string, unknown>;

      const nameValues: string[] = [];
      if (typeof rec.name_value === 'string') {
        nameValues.push(...rec.name_value.split('\n'));
      }
      if (typeof rec.common_name === 'string') {
        nameValues.push(rec.common_name);
      }

      for (const rawVal of nameValues) {
        let cleaned = rawVal.trim().toLowerCase();
        if (cleaned.startsWith('*.')) {
          cleaned = cleaned.slice(2);
        }
        cleaned = cleaned.replace(/\.$/, '');

        if (!cleaned || !FQDN_REGEX.test(cleaned)) continue;

        // Scope check: must equal targetDomain or end with .targetDomain
        const inScope = cleaned === targetDomain || cleaned.endsWith('.' + targetDomain);
        if (!inScope) continue;

        // SSRF check
        if (isInternalOrSsrfTarget(cleaned)) continue;

        if (!observationsMap.has(cleaned)) {
          observationsMap.set(cleaned, {
            subdomain: cleaned,
            parentDomain: targetDomain,
            discoveredAt: nowIso,
          });
        }
      }
    }

    const observations: DiscoveredSubdomainObservation[] = Array.from(observationsMap.values())
      .sort((a, b) => a.subdomain.localeCompare(b.subdomain))
      .map((obs) => ({
        subdomain: obs.subdomain,
        parentDomain: obs.parentDomain,
        sources: ['crt_sh_ct_log'],
        discoveredAt: obs.discoveredAt,
        collectedAt: obs.discoveredAt,
        freshness: 'historical',
        sourceReliability: 'historical_archive',
        confidence: 0.9,
      }));

    return {
      status: 'success',
      contractVersion: SUBDOMAIN_DISCOVERY_CONTRACT_VERSION,
      targetDomain,
      observations,
      explicitNonClaims: SUBDOMAIN_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: Date.now() - startTime,
    };
  }
}
