import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  extractHost,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  URL_DISCOVERY_CONTRACT_VERSION,
  URL_DISCOVERY_NON_CLAIMS,
  type DiscoveredUrlObservation,
  type UrlDiscoveryRequest,
  type UrlDiscoveryResult,
  type UrlDiscoveryTool,
} from './UrlDiscoveryContracts.js';

export class CompositeUrlDiscoveryAdapter implements UrlDiscoveryTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async discoverUrls(request: UrlDiscoveryRequest): Promise<UrlDiscoveryResult> {
    const rawTarget = typeof request.targetUrlOrDomain === 'string' ? request.targetUrlOrDomain.trim() : '';

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'host_or_url',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      requiredPermissions: ['endpointDiscovery', 'activeCrawling', 'passiveRecon', 'activeValidation', 'activeRecon'],
      missingPermissionReason: 'Scope grant does not permit endpoint discovery or active crawling',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const targetHost = preflight.targetHost!;
    const targetUrl = preflight.targetUrl ?? `https://${targetHost}`;

    // 7. Composite Invocation: Katana (modern crawling) + Gau (legacy archive scraping)
    const timeoutMs = request.timeoutMs ?? 60_000;
    const maxDepth = typeof request.maxDepth === 'number' && request.maxDepth > 0 ? request.maxDepth : 3;

    const [katanaOutput, gauOutput] = await Promise.all([
      this.processRunner.execute({
        binary: 'katana',
        args: ['-u', targetUrl, '-silent', '-json', '-depth', String(maxDepth), '-jc'],
        timeoutMs,
      }),
      this.processRunner.execute({
        binary: 'gau',
        args: ['--json', targetHost],
        timeoutMs,
      }),
    ]);

    // If both engines failed completely or timed out
    if (katanaOutput.exitCode !== 0 && gauOutput.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'composite_execution_failed',
        reason: `Both discovery engines failed: Katana exit ${katanaOutput.exitCode}, Gau exit ${gauOutput.exitCode}`,
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: katanaOutput.exitCode,
        stderr: [katanaOutput.stderr, gauOutput.stderr].filter(Boolean).join('; '),
        durationMs: Math.max(katanaOutput.durationMs, gauOutput.durationMs),
      };
    }

    // 8. Output Parsing, Deduplication, Scope Filtering & SSRF Containment
    const observationsMap = new Map<
      string,
      {
        url: string;
        host: string;
        path: string;
        query?: string;
        sources: Set<string>;
      }
    >();

    const nowIso = new Date().toISOString();

    const grant = request.authorizedScopeGrant;
    const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d) =>
      d.trim().toLowerCase().replace(/\.$/, '')
    );
    const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((h) =>
      h.trim().toLowerCase().replace(/\.$/, '')
    );
    const subjectDomain = grant.subject.domain?.trim().toLowerCase().replace(/\.$/, '');
    const subjectHost = grant.subject.host?.trim().toLowerCase().replace(/\.$/, '');

    const originHosts: string[] = [];
    for (const origin of grant.boundaries.allowedOrigins ?? []) {
      const h = extractHost(origin);
      if (h) originHosts.push(h);
    }

    const parseEngineLines = (stdout: string, sourceName: string) => {
      const lines = stdout.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let rawUrl = '';
        if (trimmed.startsWith('{')) {
          try {
            const parsed = JSON.parse(trimmed) as Record<string, unknown>;
            if (typeof parsed.url === 'string') {
              rawUrl = parsed.url.trim();
            } else if (typeof parsed.endpoint === 'string') {
              rawUrl = parsed.endpoint.trim();
            } else if (parsed.request && typeof parsed.request === 'object') {
              const reqObj = parsed.request as Record<string, unknown>;
              if (typeof reqObj.endpoint === 'string') {
                rawUrl = reqObj.endpoint.trim();
              }
            }
          } catch {
            // Fail-closed on corrupted lines
            continue;
          }
        } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
          rawUrl = trimmed;
        }

        if (!rawUrl) continue;

        let parsedUrl: URL;
        try {
          parsedUrl = new URL(rawUrl);
        } catch {
          continue;
        }

        // Protocol check
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
          continue;
        }

        const urlHost = parsedUrl.hostname.toLowerCase().replace(/\.$/, '');

        // SSRF Gate: Drop loopback, RFC-1918, cloud metadata
        if (isInternalOrSsrfTarget(urlHost)) {
          continue;
        }

        // Strict Scope Gate: Host must be within authorized scope boundaries
        const isUrlInScope =
          allowedDomains.includes(urlHost) ||
          allowedDomains.some((d) => urlHost.endsWith('.' + d)) ||
          allowedHosts.includes(urlHost) ||
          subjectDomain === urlHost ||
          subjectHost === urlHost ||
          originHosts.includes(urlHost) ||
          originHosts.some((h) => urlHost.endsWith('.' + h));

        if (!isUrlInScope) {
          // Drop out-of-scope third party URLs (CDNs, analytics, external APIs)
          continue;
        }

        // URL Normalization: Remove hash fragment
        parsedUrl.hash = '';
        const normalizedUrl = parsedUrl.toString();

        const existing = observationsMap.get(normalizedUrl);
        if (existing) {
          existing.sources.add(sourceName);
        } else {
          observationsMap.set(normalizedUrl, {
            url: normalizedUrl,
            host: urlHost,
            path: parsedUrl.pathname,
            query: parsedUrl.search ? parsedUrl.search.replace(/^\?/, '') : undefined,
            sources: new Set([sourceName]),
          });
        }
      }
    };

    if (katanaOutput.exitCode === 0) {
      parseEngineLines(katanaOutput.stdout, 'modern_crawler');
    }
    if (gauOutput.exitCode === 0) {
      parseEngineLines(gauOutput.stdout, 'archive_legacy');
    }

    const observations: DiscoveredUrlObservation[] = Array.from(observationsMap.values())
      .sort((a, b) => a.url.localeCompare(b.url))
      .map((obs) => {
        const sources = Array.from(obs.sources).sort();
        const hasLive = sources.includes('modern_crawler');
        const hasArchive = sources.includes('archive_legacy');
        const freshness = hasLive ? ('live' as const) : hasArchive ? ('historical' as const) : ('unknown' as const);
        const sourceReliability = hasLive
          ? ('direct_observation' as const)
          : hasArchive
            ? ('historical_archive' as const)
            : ('inferred_relationship' as const);
        return {
          url: obs.url,
          host: obs.host,
          path: obs.path,
          query: obs.query,
          sources,
          discoveredAt: nowIso,
          collectedAt: nowIso,
          freshness,
          sourceReliability,
        };
      });

    return {
      status: 'success',
      contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
      targetUrlOrDomain: rawTarget,
      observations,
      explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: Math.max(katanaOutput.durationMs, gauOutput.durationMs),
    };
  }
}
