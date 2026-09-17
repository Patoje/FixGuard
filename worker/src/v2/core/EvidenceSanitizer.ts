/**
 * FixGuard V2 — Anti-Leak Evidence Sanitizer
 * Milestone P3-1 (BYOT Session Injection Contract & Anti-Leak Boundary)
 *
 * Enforces anti-leak invariants (BYOT-SI-03 & BYOT-SI-04) ensuring session tokens,
 * JWTs, cookies, bearer tokens, and API keys are never leaked or persisted in
 * free-text evidence excerpts, finding metadata, or human-facing reports.
 */

const JWT_PATTERN = /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g;
const BEARER_PATTERN = /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const BASIC_AUTH_PATTERN = /Basic\s+[A-Za-z0-9+/=]+/gi;
const COOKIE_SECRET_PATTERN =
  /(sessionid|session_id|session|phpsessid|jsessionid|token|auth_token|authtoken|access_token|secret|x-csrf-token|csrf_token)=([A-Za-z0-9%._~+/-]+)/gi;
const KEY_VALUE_SECRET_PATTERN =
  /(["']?(?:token|auth_token|authToken|access_token|refresh_token|session_id|sessionId|sessionid|secret|api_key|apikey|x-api-key|x-auth-token|x-csrf-token|private_key)["']?\s*[:=]\s*["'])([A-Za-z0-9%._~+/-]{6,})(["']?)/gi;

/**
 * Redacts session secrets, credentials, JWTs, cookies, and tokens from a raw string,
 * optionally bounding the maximum character length.
 *
 * @param raw - The raw text fragment to sanitize.
 * @param maxLength - Optional maximum character limit before truncation.
 * @returns Sanitized string with sensitive secrets masked.
 */
export function sanitizeEvidenceFragment(raw: string, maxLength?: number): string {
  if (typeof raw !== 'string') {
    return '';
  }

  let sanitized = raw;

  // 1. Redact Bearer and Basic headers
  sanitized = sanitized.replace(BEARER_PATTERN, 'Bearer [REDACTED_TOKEN]');
  sanitized = sanitized.replace(BASIC_AUTH_PATTERN, 'Basic [REDACTED_AUTH]');

  // 2. Redact JWTs
  sanitized = sanitized.replace(JWT_PATTERN, '[REDACTED_JWT]');

  // 3. Redact Cookie key-value pairs
  sanitized = sanitized.replace(COOKIE_SECRET_PATTERN, '$1=[REDACTED_COOKIE]');

  // 4. Redact Key-Value secret assignments (JSON or URI/headers)
  sanitized = sanitized.replace(KEY_VALUE_SECRET_PATTERN, '$1[REDACTED_SECRET]$3');

  // 5. Apply bounded length truncation if requested
  if (typeof maxLength === 'number' && maxLength > 0 && sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength) + '... [TRUNCATED]';
  }

  return sanitized;
}
