import type { NormalizedTargetUrl } from './EgressPolicyContracts';

const MAX_URL_LENGTH = 4096;
const SENSITIVE_QUERY_KEYS = new Set([
  'token',
  'access_token',
  'api_key',
  'apikey',
  'key',
  'secret',
  'password',
  'passwd',
  'auth',
  'authorization',
  'session',
  'jwt'
]);

export interface NormalizationResult {
  valid: boolean;
  normalizedTarget?: NormalizedTargetUrl;
  safeDisplayUrl?: string;
  sensitiveQueryKeys?: string[];
  blockReason?: 'unsupported_scheme' | 'malformed_url' | 'credentials_in_url' | 'empty_host' | 'url_too_long';
}

function isIpv4(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

function isIpv6(host: string): boolean {
  return /^\[.*\]$/.test(host) || /^[a-fA-F0-9:]+$/.test(host); // very basic check, will rely on Policy for exact blocking
}

export function normalizeTargetUrl(rawUrl: string): NormalizationResult {
  if (rawUrl.length > MAX_URL_LENGTH) {
    return { valid: false, blockReason: 'url_too_long' };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    return { valid: false, blockReason: 'malformed_url' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, blockReason: 'unsupported_scheme', safeDisplayUrl: '[unsupported-url]' };
  }

  const sensitiveKeysFound: string[] = [];
  const safeSearchParams = new URLSearchParams(parsed.search);

  for (const [key, _] of Array.from(parsed.searchParams.entries())) {
    if (SENSITIVE_QUERY_KEYS.has(key.toLowerCase())) {
      sensitiveKeysFound.push(key);
      safeSearchParams.set(key, '[REDACTED]');
    }
  }

  const safeSearchString = safeSearchParams.toString() ? `?${safeSearchParams.toString()}` : '';
  const safeDisplayUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}${safeSearchString}`;

  if (parsed.username || parsed.password) {
    return { valid: false, blockReason: 'credentials_in_url', safeDisplayUrl };
  }

  const hostname = parsed.hostname.toLowerCase();
  if (!hostname) {
    return { valid: false, blockReason: 'empty_host', safeDisplayUrl };
  }

  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  
  if (hostname.includes('\\') || hostname.includes(' ')) {
    return { valid: false, blockReason: 'malformed_url', safeDisplayUrl };
  }

  const normalizedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}`;

  return {
    valid: true,
    normalizedTarget: {
      originalUrl: rawUrl,
      normalizedUrl,
      scheme: parsed.protocol,
      hostname,
      port,
      pathname: parsed.pathname,
      search: parsed.search,
      isIpv4: isIpv4(hostname),
      isIpv6: isIpv6(hostname)
    },
    safeDisplayUrl,
    sensitiveQueryKeys: sensitiveKeysFound.length > 0 ? sensitiveKeysFound : undefined
  };
}
