import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  CONTENT_DISCOVERY_CONTRACT_VERSION,
  CONTENT_DISCOVERY_NON_CLAIMS,
  type ContentDiscoveryRequest,
  type ContentDiscoveryResult,
  type ContentDiscoveryTool,
  type DiscoveredContentObservation,
} from './ContentDiscoveryContracts.js';

export class FfufAdapter implements ContentDiscoveryTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async discoverContent(request: ContentDiscoveryRequest): Promise<ContentDiscoveryResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';
    const rawWordlist = typeof request.wordlistPath === 'string' ? request.wordlistPath.trim() : '';

    // Unified Atomic Preflight Gate
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'url',
      wordlistOrPath: rawWordlist,
      wordlistOrPathType: 'wordlist',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) =>
        Boolean(
          ps.endpointDiscovery ||
          ps.activeCrawling ||
          ps.activeValidation ||
          ps.lightValidation ||
          ps.passiveRecon ||
          ps.technologyFingerprinting ||
          ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit content discovery or active reconnaissance',
      targetOutOfScopeReason: 'Target URL host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // Execution Phase: Assemble isolated ffuf arguments
    const cleanUrl = rawTarget.replace(/\/$/, '');
    const args = [
      '-u', `${cleanUrl}/FUZZ`,
      '-w', rawWordlist,
      '-json',
    ];

    // Evasion & Depth Knobs
    if (request.autoCalibrate !== false) {
      args.push('-ac');
    }

    if (typeof request.rateLimit === 'number' && request.rateLimit > 0) {
      args.push('-rate', String(request.rateLimit));
    }

    if (typeof request.delaySeconds === 'number' && request.delaySeconds > 0) {
      args.push('-p', String(request.delaySeconds));
    }

    if (typeof request.recursionDepth === 'number' && request.recursionDepth > 0) {
      args.push('-recursion', '-recursion-depth', String(request.recursionDepth));
    }

    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'ffuf',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'execution_timed_out',
        reason: `ffuf execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    if (output.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'process_execution_failed',
        reason: output.stderr.trim() || `ffuf exited with non-zero exit code: ${output.exitCode}`,
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: output.stderr,
        durationMs: output.durationMs,
      };
    }

    // Parsing & Deep SSRF Egress Gate Phase
    const rawItems: Array<Record<string, unknown>> = [];

    // Attempt 1: Parse full stdout as JSON object (e.g. { results: [...] })
    try {
      const fullParsed = JSON.parse(output.stdout);
      if (fullParsed && typeof fullParsed === 'object' && Array.isArray(fullParsed.results)) {
        for (const item of fullParsed.results) {
          if (item && typeof item === 'object') {
            rawItems.push(item as Record<string, unknown>);
          }
        }
      }
    } catch {
      // Attempt 2: Fall back to line-by-line JSON parsing
      const lines = output.stdout.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const parsedLine = JSON.parse(trimmed);
          if (parsedLine && typeof parsedLine === 'object' && !Array.isArray(parsedLine)) {
            rawItems.push(parsedLine as Record<string, unknown>);
          }
        } catch {
          // Malformed lines fail closed and are safely ignored
        }
      }
    }

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
      try {
        const u = new URL(origin);
        originHosts.push(u.hostname.trim().toLowerCase().replace(/\.$/, ''));
      } catch {
        // ignore malformed origin strings
      }
    }

    const isHostInScope = (host: string): boolean =>
      allowedDomains.includes(host) ||
      allowedDomains.some((d) => host.endsWith('.' + d)) ||
      allowedHosts.includes(host) ||
      subjectDomain === host ||
      subjectHost === host ||
      originHosts.includes(host) ||
      originHosts.some((h) => host.endsWith('.' + h));

    const observations: DiscoveredContentObservation[] = [];
    const seen = new Set<string>();

    for (const item of rawItems) {
      const itemUrl = typeof item.url === 'string' ? item.url.trim() : '';
      if (!itemUrl) continue;

      let parsedItemUrl: URL;
      try {
        parsedItemUrl = new URL(itemUrl);
      } catch {
        continue;
      }

      const itemHost = parsedItemUrl.hostname.toLowerCase().replace(/\.$/, '');

      // Deep SSRF Egress Gate on base discovered URL
      if (isInternalOrSsrfTarget(itemHost)) {
        continue;
      }

      // Scope boundary check on base discovered URL
      if (!isHostInScope(itemHost)) {
        continue;
      }

      // Deep SSRF Egress Gate on redirectlocation (if present)
      const redirectLocation =
        typeof item.redirectlocation === 'string' && item.redirectlocation.trim()
          ? item.redirectlocation.trim()
          : undefined;

      if (redirectLocation) {
        try {
          const resolvedRedirect = new URL(redirectLocation, itemUrl);
          const redirectHost = resolvedRedirect.hostname.toLowerCase().replace(/\.$/, '');
          if (isInternalOrSsrfTarget(redirectHost)) {
            // Discovered path redirects to restricted space (loopback, RFC-1918, metadata) -> DROP observation
            continue;
          }
        } catch {
          // If redirect location cannot be resolved, drop observation for safety
          continue;
        }
      }

      const statusCode = typeof item.status === 'number' ? item.status : 0;
      const contentLength = typeof item.length === 'number' ? item.length : undefined;
      const contentType =
        typeof item['content-type'] === 'string' && item['content-type'].trim()
          ? item['content-type'].trim()
          : undefined;

      const pathName = parsedItemUrl.pathname || '/';

      const dedupKey = `${itemUrl}|${statusCode}`;
      if (seen.has(dedupKey)) continue;
      seen.add(dedupKey);

      observations.push({
        url: itemUrl,
        path: pathName,
        statusCode,
        ...(contentLength !== undefined ? { contentLength } : {}),
        ...(contentType !== undefined ? { contentType } : {}),
        ...(redirectLocation !== undefined ? { redirectLocation } : {}),
        discoveredAt: new Date().toISOString(),
        collectedAt: new Date().toISOString(),
        freshness: 'live',
        sourceReliability: 'direct_observation',
      });
    }

    return {
      status: 'success',
      contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
      targetUrl: rawTarget,
      wordlistPath: rawWordlist,
      observations,
      explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
