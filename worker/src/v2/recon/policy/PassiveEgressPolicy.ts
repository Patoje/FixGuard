import type { AuthorizedScope, EgressPolicyDecision } from './EgressPolicyContracts';
import { normalizeTargetUrl } from './TargetUrlNormalizer';

function parseIpv4(hostname: string): [number, number, number, number] | null {
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) return null;
  const parts = hostname.split('.');
  const octets = parts.map(p => parseInt(p, 10));
  if (octets.some(o => isNaN(o) || o < 0 || o > 255)) return null;
  return [octets[0], octets[1], octets[2], octets[3]];
}

function isBlockedIpv4Address(octets: [number, number, number, number]): boolean {
  const [a, b, c, d] = octets;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 169 && b === 254) return true; // 169.254.0.0/16
  if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 (Multicast)
  if (a >= 240 && a <= 255) return true; // 240.0.0.0/4 (Reserved / Broadcast)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10
  return false;
}

/**
 * Expand an IPv6 address string (without brackets, already lowercase) into
 * exactly 8 16-bit groups represented as numbers.
 * Returns null if the string is not a syntactically valid IPv6 address.
 * Handles :: compressed forms and dotted-decimal suffixes.
 */
function expandIpv6Groups(ip: string): number[] | null {
  // Handle dotted-decimal suffix (::ffff:127.0.0.1)
  const dottedMatch = ip.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dottedMatch) {
    const prefix = dottedMatch[1]; // e.g. "::ffff:"
    const v4str = dottedMatch[2];
    const v4 = parseIpv4(v4str);
    if (!v4) return null;
    // Convert dotted IPv4 into two 16-bit hex groups
    const hi = (v4[0] << 8) | v4[1];
    const lo = (v4[2] << 8) | v4[3];
    const reconstructed = prefix + hi.toString(16) + ':' + lo.toString(16);
    return expandIpv6Groups(reconstructed); // recurse, now fully hex
  }

  // Split on '::'
  const halves = ip.split('::');
  if (halves.length > 2) return null; // multiple :: is invalid

  const parseGroups = (s: string): number[] | null => {
    if (s === '') return [];
    const parts = s.split(':');
    const nums = parts.map(p => {
      if (!/^[0-9a-f]{1,4}$/.test(p)) return NaN;
      return parseInt(p, 16);
    });
    if (nums.some(n => isNaN(n) || n < 0 || n > 0xffff)) return null;
    return nums;
  };

  if (halves.length === 1) {
    // No :: — must be exactly 8 groups
    const groups = parseGroups(halves[0]);
    if (!groups || groups.length !== 8) return null;
    return groups;
  }

  // Has ::
  const left = parseGroups(halves[0]);
  const right = parseGroups(halves[1]);
  if (!left || !right) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  return [...left, ...Array(missing).fill(0), ...right];
}

/**
 * Return the IPv4 octets encoded in an IPv4-mapped IPv6 address,
 * or null if the address is not IPv4-mapped.
 * IPv4-mapped = first 80 bits zero, bits 80–95 are 0xffff, last 32 bits are IPv4.
 */
function ipv4MappedOctets(groups: number[]): [number, number, number, number] | null {
  if (groups.length !== 8) return null;
  for (let i = 0; i < 5; i++) {
    if (groups[i] !== 0) return null;
  }
  if (groups[5] !== 0xffff) return null;
  const hi = groups[6];
  const lo = groups[7];
  return [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff];
}

function isBlockedIpv6Address(hostname: string): boolean {
  let ip = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  ip = ip.toLowerCase();

  if (ip === '::1' || ip === '::') return true; // Loopback and Unspecified

  // Expand to 8 groups; treat malformed as safe-to-fail-closed
  const groups = expandIpv6Groups(ip);
  if (!groups) return false;

  // Loopback: ::1 expanded is [0,0,0,0,0,0,0,1]
  if (groups.every((g, i) => i < 7 ? g === 0 : g === 1)) return true;

  // Unspecified: :: expanded is [0,0,0,0,0,0,0,0]
  if (groups.every(g => g === 0)) return true;

  // Link-local: fe80::/10 — first group starts with 0xfe8x..0xfebx
  const g0 = groups[0];
  if ((g0 & 0xffc0) === 0xfe80) return true;

  // Unique-local: fc00::/7 — starts with fc or fd
  if ((g0 & 0xfe00) === 0xfc00) return true;

  // Multicast: ff00::/8
  if ((g0 & 0xff00) === 0xff00) return true;

  // IPv4-mapped: ::ffff:x.x.x.x
  const mapped = ipv4MappedOctets(groups);
  if (mapped && isBlockedIpv4Address(mapped)) return true;

  return false;
}


export function isInternalOrSsrfTarget(hostname: string): boolean {
  // Loopback / Localhost
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;

  const ipv4 = parseIpv4(hostname);
  if (ipv4 && isBlockedIpv4Address(ipv4)) return true;
  
  if (hostname.includes(':') && isBlockedIpv6Address(hostname)) return true;

  return false;
}

function getCanonicalOrigin(protocol: string, hostname: string, port: string): string {
  let canonicalPort = port;
  if (protocol === 'http:' && port === '80') {
    canonicalPort = '';
  } else if (protocol === 'https:' && port === '443') {
    canonicalPort = '';
  }
  return `${protocol}//${hostname}${canonicalPort ? ':' + canonicalPort : ''}`;
}

export interface PolicyEvaluationRequest {
  targetUrl: string;
  authorizedScope: AuthorizedScope;
  capabilityId: string;
}

export function evaluateEgressPolicy(request: PolicyEvaluationRequest): EgressPolicyDecision {
  const normResult = normalizeTargetUrl(request.targetUrl);
  
  if (!normResult.valid) {
    return {
      decision: 'block',
      blockReason: normResult.blockReason || 'malformed_url',
      safeDisplayUrl: normResult.safeDisplayUrl || '[untrusted-url]'
    };
  }

  if (!normResult.normalizedTarget || !normResult.safeDisplayUrl) {
    return {
      decision: 'block',
      blockReason: 'malformed_url',
      safeDisplayUrl: '[untrusted-url]'
    };
  }

  const { normalizedTarget, safeDisplayUrl, sensitiveQueryKeys } = normResult;

  if (isInternalOrSsrfTarget(normalizedTarget.hostname)) {
    return {
      decision: 'block',
      normalizedTarget,
      blockReason: 'internal_target_blocked',
      safeDisplayUrl
    };
  }

  // Evaluate against AuthorizedScope
  const scopeOrigins = request.authorizedScope.allowedOrigins.map(o => o.toLowerCase());
  
  let exactOriginMatch = false;
  let sameHostMatch = false;
  let isSubdomain = false;
  let matchingOrigin = '';

  const targetOrigin = getCanonicalOrigin(normalizedTarget.scheme, normalizedTarget.hostname, normalizedTarget.port);

  for (const origin of scopeOrigins) {
    try {
      const parsedOrigin = new URL(origin);
      const originHost = parsedOrigin.hostname;
      const originPort = parsedOrigin.port || (parsedOrigin.protocol === 'https:' ? '443' : '80');
      const originTarget = getCanonicalOrigin(parsedOrigin.protocol, originHost, originPort);

      if (targetOrigin === originTarget) {
        exactOriginMatch = true;
        // Check path scope
        if (request.authorizedScope.allowSameHostPaths) {
          sameHostMatch = true;
        } else {
          // If we don't allow same host paths, we'd strictly need an exact path match. 
          // For M30, if allowSameHostPaths is false, we'll only allow it if pathname exactly matches the origin's pathname or is just '/'
          if (normalizedTarget.pathname === parsedOrigin.pathname || (parsedOrigin.pathname === '/' && normalizedTarget.pathname === '/')) {
            sameHostMatch = true;
          }
        }
        break;
      }

      if (normalizedTarget.hostname.endsWith('.' + originHost)) {
        isSubdomain = true;
        matchingOrigin = origin;
      }
    } catch {
      // ignore bad scope origins
    }
  }

  if (exactOriginMatch && sameHostMatch) {
    return {
      decision: 'allow',
      normalizedTarget,
      reasons: ['Authorized public scope matched'],
      sensitiveQueryKeys,
      safeDisplayUrl
    };
  }

  if (isSubdomain) {
    if (request.authorizedScope.allowSubdomains) {
       return {
        decision: 'allow',
        normalizedTarget,
        reasons: ['Authorized subdomain scope matched'],
        sensitiveQueryKeys,
        safeDisplayUrl
      };
    }
    return {
      decision: 'candidate',
      candidate: {
        candidateUrl: normalizedTarget.normalizedUrl,
        discoveredFromOrigin: matchingOrigin,
        capabilityId: request.capabilityId
      },
      reason: 'Discovered subdomain requires explicit authorization',
      safeDisplayUrl
    };
  }

  return {
    decision: 'block',
    normalizedTarget,
    blockReason: 'out_of_scope',
    safeDisplayUrl
  };
}
