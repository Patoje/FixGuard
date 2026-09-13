import path from 'node:path';
import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  CONTENT_DISCOVERY_CONTRACT_VERSION,
  CONTENT_DISCOVERY_NON_CLAIMS,
  type ContentDiscoveryRequest,
  type ContentDiscoveryResult,
  type ContentDiscoveryTool,
  type DiscoveredContentObservation,
} from './ContentDiscoveryContracts.js';

const FORBIDDEN_WORDLIST_PREFIXES = [
  '/etc',
  '/var',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/sbin',
  '/bin',
  '/usr/sbin',
  '/usr/bin',
];

function validateWordlistPath(wordlistPath: string): { valid: boolean; reason?: string } {
  if (!wordlistPath || typeof wordlistPath !== 'string' || !wordlistPath.trim()) {
    return { valid: false, reason: 'Wordlist path cannot be empty' };
  }

  const raw = wordlistPath.trim();
  if (raw.includes('..')) {
    return { valid: false, reason: 'Path traversal (..) is strictly prohibited in wordlist paths' };
  }

  const normalized = path.normalize(raw);
  if (normalized.includes('..')) {
    return { valid: false, reason: 'Path traversal (..) is strictly prohibited in wordlist paths' };
  }

  for (const prefix of FORBIDDEN_WORDLIST_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(prefix + '/')) {
      return { valid: false, reason: `Wordlist path accesses forbidden system directory: ${prefix}` };
    }
  }

  return { valid: true };
}

export class FfufAdapter implements ContentDiscoveryTool {
  constructor(private readonly processRunner: ProcessRunner) {}

  async discoverContent(request: ContentDiscoveryRequest): Promise<ContentDiscoveryResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';
    const rawWordlist = typeof request.wordlistPath === 'string' ? request.wordlistPath.trim() : '';

    // 1. Atomic Preflight: Target URL format validation
    if (!rawTarget) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: request.targetUrl,
        wordlistPath: request.wordlistPath,
        reasonCode: 'invalid_target_format',
        reason: 'Target URL cannot be empty',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    let targetHost = '';
    try {
      const u = new URL(rawTarget);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') {
        return {
          status: 'preflight_denied',
          contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
          targetUrl: rawTarget,
          wordlistPath: rawWordlist,
          reasonCode: 'invalid_target_format',
          reason: 'Target URL protocol must be HTTP or HTTPS',
          explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
      targetHost = u.hostname.trim().toLowerCase().replace(/\.$/, '');
    } catch {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'invalid_target_format',
        reason: 'Target URL is malformed',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (!targetHost) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'invalid_target_host',
        reason: 'Target URL does not contain a valid host',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 2. Atomic Preflight: Wordlist Path Safety Check
    const wordlistValidation = validateWordlistPath(rawWordlist);
    if (!wordlistValidation.valid) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'unsafe_wordlist_path',
        reason: wordlistValidation.reason ?? 'Wordlist path is unsafe',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 3. Atomic Preflight: Runtime-branded authorization verification
    if (
      !request.verifiedAuthorizationDecision ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(request.verifiedAuthorizationDecision)
    ) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'authorization_unconfirmed',
        reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (request.verifiedAuthorizationDecision.decision !== 'authorized') {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'authorization_denied',
        reason: 'Authorization decision is not in authorized state',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 4. Atomic Preflight: Continuous Lineage tuple integrity verification
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
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'lineage_mismatch',
        reason: 'Execution lineage does not match authorization decision and scope grant',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 5. Atomic Preflight: Scope permissions check
    const ps = grant.permissionSet;
    let hasPermission = Boolean(
      ps.endpointDiscovery ||
      ps.activeCrawling ||
      ps.activeValidation ||
      ps.lightValidation ||
      ps.passiveRecon ||
      ps.technologyFingerprinting
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
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'missing_permission',
        reason: 'Scope grant does not permit content discovery or active reconnaissance',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    // 6. Atomic Preflight: Scope boundaries & SSRF check on target host
    if (isInternalOrSsrfTarget(targetHost)) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target URL host points to prohibited internal, loopback, or metadata address',
        explicitNonClaims: CONTENT_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

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

    if (!isHostInScope(targetHost)) {
      return {
        status: 'preflight_denied',
        contractVersion: CONTENT_DISCOVERY_CONTRACT_VERSION,
        targetUrl: rawTarget,
        wordlistPath: rawWordlist,
        reasonCode: 'target_out_of_scope',
        reason: 'Target URL host is outside authorized scope boundaries',
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
