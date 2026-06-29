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

function isInternalOrSsrfTarget(hostname: string): boolean {
  // Loopback / Localhost
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return true;

  const ipv4 = parseIpv4(hostname);
  if (ipv4 && isBlockedIpv4Address(ipv4)) return true;
  
  // IPv6
  if (hostname === '[::1]') return true;
  if (hostname.startsWith('[fe80:')) return true;
  if (hostname.startsWith('[fc00:')) return true;
  if (hostname.startsWith('[fd00:')) return true;
  if (hostname.startsWith('[::ffff:')) return true;

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
