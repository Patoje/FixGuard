import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  URL_DISCOVERY_CONTRACT_VERSION,
  URL_DISCOVERY_NON_CLAIMS,
  type DiscoveredUrlObservation,
  type UrlDiscoveryRequest,
  type UrlDiscoveryResult,
  type UrlDiscoveryTool,
} from './UrlDiscoveryContracts.js';

const FQDN_REGEX = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/;

function extractHost(urlStr: string): string | null {
  try {
    const u = new URL(urlStr);
    return u.hostname.trim().toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

export class CompositeUrlDiscoveryAdapter implements UrlDiscoveryTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async discoverUrls(request: UrlDiscoveryRequest): Promise<UrlDiscoveryResult> {
    const rawTarget = typeof request.targetUrlOrDomain === 'string' ? request.targetUrlOrDomain.trim() : '';

    // 1. Atomic Preflight: Target URL or Domain format validation
    let targetHost = '';
    let targetUrl = '';

    if (rawTarget.startsWith('http://') || rawTarget.startsWith('https://')) {
      try {
        const u = new URL(rawTarget);
        targetHost = u.hostname.toLowerCase().replace(/\.$/, '');
        targetUrl = u.origin;
      } catch {
        return {
          status: 'preflight_denied',
          contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrDomain: rawTarget,
          reasonCode: 'invalid_target_format',
          reason: 'Target URL is malformed',
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
    } else {
      const cleanHost = rawTarget.toLowerCase().replace(/\.$/, '');
      if (FQDN_REGEX.test(cleanHost)) {
        targetHost = cleanHost;
        targetUrl = `https://${cleanHost}`;
      } else {
        return {
          status: 'preflight_denied',
          contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
          targetUrlOrDomain: rawTarget,
          reasonCode: 'invalid_target_format',
          reason: 'Target is not a valid URL or fully-qualified domain name',
          explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
    }

    if (!targetHost) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'invalid_target_host',
        reason: 'Target does not contain a valid host',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Continuous Lineage tuple integrity verification
    const dec = request.verifiedAuthorizationDecision;
    const grant = request.authorizedScopeGrant;
    const lin = request.lineage;

    if (
      lin.scanId !== dec.scanId ||
      lin.assessmentId !== dec.assessmentId ||
      lin.authorizationGrantId !== grant.grantId ||
      lin.authorizationDecisionId !== dec.authorizationDecisionId
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Scope permissions check
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.endpointDiscovery ||
      ps.activeCrawling ||
      ps.passiveRecon ||
      ps.activeValidation
    );
    if (!hasPermission && 'activeRecon' in ps) {
      const ext = ps as typeof ps & { activeRecon?: boolean };
      if (ext.activeRecon) {
        hasPermission = true;
      }
    }

    if (!hasPermission) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit endpoint discovery or active crawling',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope boundary check
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

    const isTargetInScope =
      allowedDomains.includes(targetHost) ||
      allowedDomains.some((d) => targetHost.endsWith('.' + d)) ||
      allowedHosts.includes(targetHost) ||
      subjectDomain === targetHost ||
      subjectHost === targetHost ||
      originHosts.includes(targetHost) ||
      originHosts.some((h) => targetHost.endsWith('.' + h));

    if (!isTargetInScope) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'target_out_of_scope',
        reason: 'Target host is outside authorized scope boundaries',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: SSRF containment on target hostname
    if (isInternalOrSsrfTarget(targetHost)) {
      return {
        status: 'preflight_denied',
        contractVersion: URL_DISCOVERY_CONTRACT_VERSION,
        targetUrlOrDomain: rawTarget,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target host points to prohibited internal, loopback, or metadata address',
        explicitNonClaims: URL_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

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
      .map((obs) => ({
        url: obs.url,
        host: obs.host,
        path: obs.path,
        query: obs.query,
        sources: Array.from(obs.sources).sort(),
        discoveredAt: nowIso,
      }));

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
