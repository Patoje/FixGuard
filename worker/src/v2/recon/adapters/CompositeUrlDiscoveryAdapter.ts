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

/** Hard caps — hung gau must not block assessment_activity_idle (~15m). */
export const GAU_HARD_TIMEOUT_MS = 240_000;
export const KATANA_HARD_TIMEOUT_MS = 300_000;

/** Stage warnings keep a short stderr tail. Stdout is never copied onto the warning. */
export const DISCOVERY_STDERR_WARNING_CAP = 240;

function stderrSnippet(stderr: string): string {
  const trimmed = stderr.trim();
  if (trimmed.length === 0) return '';
  if (trimmed.length <= DISCOVERY_STDERR_WARNING_CAP) return trimmed;
  return trimmed.slice(0, DISCOVERY_STDERR_WARNING_CAP);
}

function nonZeroExitWarning(tool: 'katana' | 'gau', exitCode: number, stderr: string): string {
  const snippet = stderrSnippet(stderr);
  const base = `${tool} exit ${exitCode} — degraded`;
  return snippet.length > 0 ? `${base}: ${snippet}` : base;
}

function capTimeout(requested: number | undefined, hardCap: number): number {
  if (typeof requested === 'number' && Number.isFinite(requested) && requested > 0) {
    return Math.min(requested, hardCap);
  }
  return hardCap;
}

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

    // Per-tool hard timeouts (gau historically hung past idle; kill+degrade loud).
    const katanaTimeoutMs = capTimeout(request.timeoutMs, KATANA_HARD_TIMEOUT_MS);
    const gauTimeoutMs = capTimeout(request.timeoutMs, GAU_HARD_TIMEOUT_MS);
    const maxDepth = typeof request.maxDepth === 'number' && request.maxDepth > 0 ? request.maxDepth : 3;

    const [katanaOutput, gauOutput] = await Promise.all([
      this.processRunner.execute({
        binary: 'katana',
        args: ['-u', targetUrl, '-silent', '-json', '-depth', String(maxDepth), '-jc', '-jsl'],
        timeoutMs: katanaTimeoutMs,
      }),
      this.processRunner.execute({
        binary: 'gau',
        // Host-scoped once — caller must not amplify per path/rootUrl.
        args: ['--json', targetHost],
        timeoutMs: gauTimeoutMs,
      }),
    ]);

    const degradeWarnings: string[] = [];
    if (katanaOutput.timedOut) {
      degradeWarnings.push(
        `katana timed out after ${katanaTimeoutMs}ms — degraded (partial URL discovery)`
      );
    } else if (katanaOutput.exitCode !== 0) {
      degradeWarnings.push(
        nonZeroExitWarning('katana', katanaOutput.exitCode, katanaOutput.stderr)
      );
    }
    if (gauOutput.timedOut) {
      degradeWarnings.push(
        `gau timed out after ${gauTimeoutMs}ms — degraded (archive scrape skipped)`
      );
    } else if (gauOutput.exitCode !== 0) {
      degradeWarnings.push(nonZeroExitWarning('gau', gauOutput.exitCode, gauOutput.stderr));
    }

    // If both engines failed completely or timed out
    if (katanaOutput.exitCode !== 0 && gauOutput.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'composite_execution_failed',
        reason: `Both discovery engines failed: Katana exit ${katanaOutput.exitCode}${katanaOutput.timedOut ? ' (timed out)' : ''}, Gau exit ${gauOutput.exitCode}${gauOutput.timedOut ? ' (timed out)' : ''}${degradeWarnings.length > 0 ? ` · ${degradeWarnings.join('; ')}` : ''}`,
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: katanaOutput.exitCode,
        stderr: [katanaOutput.stderr, gauOutput.stderr, ...degradeWarnings]
          .filter(Boolean)
          .join('; '),
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

    if (katanaOutput.exitCode === 0 && !katanaOutput.timedOut) {
      parseEngineLines(katanaOutput.stdout, 'modern_crawler');
    }
    if (gauOutput.exitCode === 0 && !gauOutput.timedOut) {
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
      ...(degradeWarnings.length > 0 ? { warnings: degradeWarnings } : {}),
    };
  }
}
