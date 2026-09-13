import path from 'node:path';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { AuthorizedScopeGrant, PermissionSet } from '../../scope/AuthorizedScopeContracts.js';
import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';

export const FQDN_REGEX =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;

export const FORBIDDEN_SYSTEM_PATH_PREFIXES: readonly string[] = [
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
  '/var/run',
];

export function isValidIpv4(value: string): boolean {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
  const parts = value.split('.').map((p) => parseInt(p, 10));
  return parts.every((p) => !isNaN(p) && p >= 0 && p <= 255);
}

export function extractHost(urlStr: string): string | null {
  try {
    const u = new URL(urlStr);
    return u.hostname.trim().toLowerCase().replace(/\.$/, '');
  } catch {
    return null;
  }
}

export function validateWordlistOrPath(
  pathStr: string,
  type: 'wordlist' | 'filesystem'
): { valid: boolean; reasonCode?: string; reason?: string } {
  const noun = type === 'filesystem' ? 'Filesystem path' : 'Wordlist path';
  const targetNoun = type === 'filesystem' ? 'filesystem targets' : 'wordlist paths';
  const errorCode = type === 'filesystem' ? 'unsafe_target_path' : 'unsafe_wordlist_path';

  if (!pathStr || typeof pathStr !== 'string' || !pathStr.trim()) {
    return {
      valid: false,
      reasonCode: errorCode,
      reason: `${noun} cannot be empty`,
    };
  }

  const raw = pathStr.trim();
  if (raw.includes('..')) {
    return {
      valid: false,
      reasonCode: errorCode,
      reason: `Path traversal (..) is strictly prohibited in ${targetNoun}`,
    };
  }

  const normalized = path.normalize(raw);
  if (normalized.includes('..')) {
    return {
      valid: false,
      reasonCode: errorCode,
      reason: `Path traversal (..) is strictly prohibited in ${targetNoun}`,
    };
  }

  for (const prefix of FORBIDDEN_SYSTEM_PATH_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(prefix + '/')) {
      return {
        valid: false,
        reasonCode: errorCode,
        reason: `${noun} accesses forbidden system directory: ${prefix}`,
      };
    }
  }

  return { valid: true };
}

export type PreSpawnDnsResolver = (hostname: string) => Promise<readonly string[]>;

/**
 * Default DNS resolver attempting lookup in live environments.
 * Returns empty array if resolution fails (offline test harness),
 * preventing false-positive blocking of valid offline test targets.
 */
export async function defaultDnsResolver(hostname: string): Promise<readonly string[]> {
  if (isValidIpv4(hostname) || hostname.includes(':')) {
    return [hostname];
  }
  try {
    const dns = await import('node:dns/promises');
    const results = await dns.lookup(hostname, { all: true });
    return results.map((r) => r.address);
  } catch {
    return [];
  }
}

/**
 * Resolves target hostname immediately before child process invocation.
 * Rejects private IPs (RFC-1918), loopback (127.0.0.0/8, ::1), and cloud metadata (169.254.169.254).
 */
export async function validateDnsRebinding(
  hostname: string,
  customResolver?: PreSpawnDnsResolver
): Promise<{ ok: boolean; blockedIp?: string }> {
  const resolver = customResolver ?? defaultDnsResolver;
  const ips = await resolver(hostname);
  for (const ip of ips) {
    if (isInternalOrSsrfTarget(ip)) {
      return { ok: false, blockedIp: ip };
    }
  }
  return { ok: true };
}

export type TargetValidationKind =
  | 'fqdn'                     // Subfinder, Dnsx
  | 'ipv4_or_fqdn'             // Naabu
  | 'url'                      // Httpx, Arjun, Ffuf
  | 'host_or_url'              // Tlsx, CompositeUrl
  | 'git_url_or_filesystem';   // Trufflehog

export interface AdapterPreflightOptions {
  readonly target: string;
  readonly targetKind: TargetValidationKind;
  readonly scanType?: 'git' | 'filesystem';
  readonly verifiedAuthorizationDecision?: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant?: AuthorizedScopeGrant;
  readonly lineage?: AuthorizedActiveReconRequestLineage;
  readonly permissionCheck?: (permissions: PermissionSet) => boolean;
  readonly requiredPermissions?: readonly (keyof PermissionSet | 'activeRecon')[];
  readonly missingPermissionReason?: string;
  readonly targetOutOfScopeReason?: string;
  readonly unsupportedProtocolReasonCode?: string;
  readonly wordlistOrPath?: string;
  readonly wordlistOrPathType?: 'wordlist' | 'filesystem';
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export type AdapterPreflightResult =
  | {
      readonly ok: true;
      readonly targetHost: string;
      readonly normalizedTarget: string;
      readonly targetUrl?: string;
      readonly extractedPort?: number;
    }
  | {
      readonly ok: false;
      readonly reasonCode: string;
      readonly reason: string;
    };

/**
 * Canonical 7-Pass Preflight Pipeline for FixGuard Layer 6 Tool Adapters.
 *
 * Consolidates:
 * 1. Target format validation
 * 2. Wordlist / Path containment check
 * 3. Runtime authorization brand verification (WeakSet)
 * 4. Lineage tuple integrity check
 * 5. Scope permissions verification
 * 6. Target host scope boundary check
 * 7. SSRF pre-check & Dynamic DNS Rebinding Mitigation
 */
export async function runAdapterPreflight(
  options: AdapterPreflightOptions
): Promise<AdapterPreflightResult> {
  const rawInput = typeof options.target === 'string' ? options.target.trim() : '';

  // ---------------------------------------------------------------------------
  // Pass 1: Target Format Validation
  // ---------------------------------------------------------------------------
  if (!rawInput) {
    const isDomain = options.targetKind === 'fqdn';
    return {
      ok: false,
      reasonCode: isDomain ? 'invalid_target_domain' : 'invalid_target_format',
      reason: isDomain
        ? 'Target domain is not a valid fully-qualified domain name'
        : 'Target cannot be empty',
    };
  }

  let targetHost = '';
  let normalizedTarget = rawInput;
  let targetUrl: string | undefined;
  let extractedPort: number | undefined;

  switch (options.targetKind) {
    case 'fqdn': {
      const cleanFqdn = rawInput.toLowerCase().replace(/\.$/, '');
      if (!cleanFqdn || !FQDN_REGEX.test(cleanFqdn)) {
        return {
          ok: false,
          reasonCode: 'invalid_target_domain',
          reason: 'Target domain is not a valid fully-qualified domain name',
        };
      }
      targetHost = cleanFqdn;
      normalizedTarget = cleanFqdn;
      break;
    }

    case 'ipv4_or_fqdn': {
      const cleanTarget = rawInput.toLowerCase().replace(/\.$/, '');
      const isIpv4 = isValidIpv4(cleanTarget);
      const isFqdn = FQDN_REGEX.test(cleanTarget);
      if (!cleanTarget || (!isIpv4 && !isFqdn)) {
        return {
          ok: false,
          reasonCode: 'invalid_target_format',
          reason: 'Target is not a valid fully-qualified domain name or IPv4 address',
        };
      }
      targetHost = cleanTarget;
      normalizedTarget = cleanTarget;
      break;
    }

    case 'url': {
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(rawInput);
      } catch {
        return {
          ok: false,
          reasonCode: 'invalid_target_format',
          reason: 'Target URL is malformed',
        };
      }

      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return {
          ok: false,
          reasonCode: options.unsupportedProtocolReasonCode ?? 'invalid_target_format',
          reason: 'Target URL protocol must be HTTP or HTTPS',
        };
      }

      targetHost = parsedUrl.hostname.toLowerCase().replace(/\.$/, '');
      if (!targetHost) {
        return {
          ok: false,
          reasonCode: 'invalid_target_host',
          reason: 'Target URL does not contain a valid host',
        };
      }
      normalizedTarget = rawInput;
      break;
    }

    case 'host_or_url': {
      if (rawInput.startsWith('http://') || rawInput.startsWith('https://')) {
        try {
          const u = new URL(rawInput);
          targetHost = u.hostname.toLowerCase().replace(/\.$/, '');
          targetUrl = u.origin;
          if (u.port) {
            const p = parseInt(u.port, 10);
            if (p > 0 && p <= 65535) extractedPort = p;
          }
        } catch {
          return {
            ok: false,
            reasonCode: 'invalid_target_format',
            reason: 'Target URL is malformed',
          };
        }
      } else {
        const parts = rawInput.split(':');
        targetHost = parts[0].toLowerCase().replace(/\.$/, '');
        targetUrl = `https://${targetHost}`;
        if (parts.length === 2 && parts[1]) {
          const p = parseInt(parts[1], 10);
          if (p > 0 && p <= 65535) extractedPort = p;
        }
      }

      if (!targetHost || (!FQDN_REGEX.test(targetHost) && !isValidIpv4(targetHost))) {
        return {
          ok: false,
          reasonCode: 'invalid_target_host',
          reason: 'Target is not a valid fully-qualified domain name',
        };
      }
      normalizedTarget = targetHost;
      break;
    }

    case 'git_url_or_filesystem': {
      const isGit =
        options.scanType === 'git' ||
        rawInput.startsWith('http://') ||
        rawInput.startsWith('https://');

      if (isGit) {
        try {
          const u = new URL(rawInput);
          if (u.protocol !== 'http:' && u.protocol !== 'https:') {
            return {
              ok: false,
              reasonCode: 'invalid_target_format',
              reason: 'Git target URL protocol must be HTTP or HTTPS',
            };
          }
          targetHost = u.hostname.toLowerCase().replace(/\.$/, '');
        } catch {
          return {
            ok: false,
            reasonCode: 'invalid_target_format',
            reason: 'Git target URL is malformed',
          };
        }

        if (!targetHost) {
          return {
            ok: false,
            reasonCode: 'invalid_target_host',
            reason: 'Git target URL does not contain a valid host',
          };
        }
        normalizedTarget = rawInput;
      } else {
        // Filesystem target path
        const fsCheck = validateWordlistOrPath(rawInput, 'filesystem');
        if (!fsCheck.valid) {
          return {
            ok: false,
            reasonCode: fsCheck.reasonCode ?? 'unsafe_target_path',
            reason: fsCheck.reason ?? 'Unsafe filesystem target path',
          };
        }
        // Filesystem target does not bind to network host
        targetHost = 'localhost';
        normalizedTarget = rawInput;
      }
      break;
    }
  }

  // ---------------------------------------------------------------------------
  // Pass 2: Path / Wordlist Containment Check
  // ---------------------------------------------------------------------------
  if (options.wordlistOrPath) {
    const checkType = options.wordlistOrPathType ?? 'wordlist';
    const pathCheck = validateWordlistOrPath(options.wordlistOrPath, checkType);
    if (!pathCheck.valid) {
      return {
        ok: false,
        reasonCode: pathCheck.reasonCode ?? (checkType === 'filesystem' ? 'unsafe_target_path' : 'unsafe_wordlist_path'),
        reason: pathCheck.reason ?? 'Wordlist or path is unsafe',
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Pass 3: Runtime-Branded Authorization Decision Check (WeakSet)
  // ---------------------------------------------------------------------------
  const dec = options.verifiedAuthorizationDecision;
  if (!dec || !isRuntimeEstablishedVerifiedAuthorizationDecision(dec)) {
    return {
      ok: false,
      reasonCode: 'authorization_unconfirmed',
      reason: 'Authorization decision is not runtime-established or lacks valid verification brand',
    };
  }

  if (dec.decision !== 'authorized') {
    return {
      ok: false,
      reasonCode: 'authorization_denied',
      reason: 'Authorization decision is not in authorized state',
    };
  }

  // ---------------------------------------------------------------------------
  // Pass 4: Continuous Lineage Tuple Verification
  // ---------------------------------------------------------------------------
  const grant = options.authorizedScopeGrant;
  const lin = options.lineage;
  if (
    !grant ||
    !lin ||
    lin.scanId !== dec.scanId ||
    lin.assessmentId !== dec.assessmentId ||
    lin.authorizationGrantId !== grant.grantId ||
    lin.authorizationDecisionId !== dec.authorizationDecisionId
  ) {
    return {
      ok: false,
      reasonCode: 'lineage_mismatch',
      reason: 'Execution lineage does not match authorization decision and scope grant',
    };
  }

  // ---------------------------------------------------------------------------
  // Pass 5: Scope Permissions Verification
  // ---------------------------------------------------------------------------
  let hasPermission = false;
  if (typeof options.permissionCheck === 'function') {
    hasPermission = options.permissionCheck(grant.permissionSet);
  } else if (Array.isArray(options.requiredPermissions)) {
    const ps = grant.permissionSet as unknown as Record<string, boolean | undefined>;
    hasPermission = options.requiredPermissions.some((perm) => Boolean(ps[perm]));
  }

  if (!hasPermission) {
    return {
      ok: false,
      reasonCode: 'missing_permission',
      reason: options.missingPermissionReason ?? 'Scope grant does not permit required capability',
    };
  }

  // ---------------------------------------------------------------------------
  // Pass 6: SSRF Pre-Check & Dynamic DNS Rebinding Mitigation
  // ---------------------------------------------------------------------------
  const isFilesystemScan =
    options.targetKind === 'git_url_or_filesystem' && options.scanType === 'filesystem';

  if (!isFilesystemScan) {
    // 6A. Static SSRF validation on targetHost
    if (isInternalOrSsrfTarget(targetHost)) {
      return {
        ok: false,
        reasonCode: 'ssrf_target_blocked',
        reason: 'Target domain resolves or points to a blocked internal/loopback target',
      };
    }

    // 6B. Dynamic DNS Rebinding Validation (pre-spawn resolution check)
    const rebindingCheck = await validateDnsRebinding(targetHost, options.dnsResolver);
    if (!rebindingCheck.ok) {
      return {
        ok: false,
        reasonCode: 'ssrf_target_blocked',
        reason: `Target host resolves to blocked internal or private IP address: ${rebindingCheck.blockedIp}`,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Pass 7: Target Host Scope Boundary Check
  // ---------------------------------------------------------------------------
  if (!isFilesystemScan) {
    const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d: string) =>
      d.trim().toLowerCase().replace(/\.$/, '')
    );
    const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((h: string) =>
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
        // ignore malformed origin strings in grant boundaries
      }
    }

    const isHostInScope =
      allowedDomains.includes(targetHost) ||
      allowedDomains.some((d: string) => targetHost.endsWith('.' + d)) ||
      allowedHosts.includes(targetHost) ||
      subjectDomain === targetHost ||
      subjectHost === targetHost ||
      originHosts.includes(targetHost) ||
      originHosts.some((h: string) => targetHost.endsWith('.' + h));

    if (!isHostInScope) {
      return {
        ok: false,
        reasonCode: 'target_out_of_scope',
        reason: options.targetOutOfScopeReason ?? 'Target domain is outside authorized scope boundaries',
      };
    }
  }

  return {
    ok: true,
    targetHost,
    normalizedTarget,
    targetUrl,
    extractedPort,
  };
}
