/**
 * Literals already present in captured HTML, headers, or DNS JSON.
 * Nothing here opens a socket or invents a marker.
 */

const BUILD_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

export function extractNextBuildId(html: string): string | null {
  if (!html.includes('__NEXT_DATA__')) return null;
  const script = html.match(
    /<script[^>]*id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i
  );
  const jsonText = script?.[1] ?? '';
  if (!jsonText.includes('"buildId"')) return null;
  let candidate = '';
  try {
    const parsed: unknown = JSON.parse(jsonText);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const buildId = (parsed as { buildId?: unknown }).buildId;
      if (typeof buildId === 'string') candidate = buildId;
    }
  } catch {
    const loose = jsonText.match(/"buildId"\s*:\s*"([^"]+)"/);
    candidate = loose?.[1] ?? '';
  }
  if (!BUILD_ID_RE.test(candidate) || !jsonText.includes(candidate)) return null;
  return candidate;
}

const WAF_HEADER_MARKERS = Object.freeze(['cf-ray', 'x-sucuri-id'] as const);
const WAF_COOKIE_MARKERS = Object.freeze(['__cf_bm', 'cf_clearance'] as const);

export function classifyCapturedWafIdentity(input: {
  readonly headers?: Readonly<Record<string, string | string[] | undefined>>;
  readonly setCookie?: string;
}): string | null {
  const headers = input.headers ?? {};
  for (const marker of WAF_HEADER_MARKERS) {
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === marker) return marker;
    }
  }
  const cookie = input.setCookie ?? '';
  if (cookie.length === 0) return null;
  for (const marker of WAF_COOKIE_MARKERS) {
    if (cookie.includes(`${marker}=`)) return marker;
  }
  return null;
}

export interface CookieFlagRecord {
  readonly name: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: 'Lax' | 'Strict' | 'None' | 'absent';
  readonly factValue: string;
}

export function extractCookieFlagRecords(setCookie: string): readonly CookieFlagRecord[] {
  const chunks = setCookie.split(/,(?=\s*[A-Za-z0-9_]+=)/);
  const out: CookieFlagRecord[] = [];
  for (const chunk of chunks) {
    const trimmed = chunk.trim();
    const nameMatch = trimmed.match(/^([A-Za-z0-9_-]+)=/);
    const name = nameMatch?.[1] ?? '';
    if (!name) continue;
    const secure = /(?:^|;\s*)Secure(?:\s*;|\s*$)/i.test(trimmed);
    const httpOnly = /(?:^|;\s*)HttpOnly(?:\s*;|\s*$)/i.test(trimmed);
    const sameSiteMatch = trimmed.match(/SameSite=(Lax|Strict|None)/i);
    const sameSiteRaw = sameSiteMatch?.[1];
    const sameSite =
      sameSiteRaw?.toLowerCase() === 'lax'
        ? 'Lax'
        : sameSiteRaw?.toLowerCase() === 'strict'
          ? 'Strict'
          : sameSiteRaw?.toLowerCase() === 'none'
            ? 'None'
            : 'absent';
    const parts = [name];
    if (secure) parts.push('Secure');
    if (httpOnly) parts.push('HttpOnly');
    if (sameSite !== 'absent') parts.push(`SameSite=${sameSite}`);
    const factValue = parts.join(';');
    const secret = trimmed.slice(name.length + 1).split(';')[0]?.trim() ?? '';
    if (secret.length > 0 && factValue.includes(secret)) continue;
    out.push({ name, secure, httpOnly, sameSite, factValue });
  }
  return Object.freeze(out);
}

export function headerValue(
  headers: Readonly<Record<string, string | string[] | undefined>> | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name.toLowerCase() || value === undefined) continue;
    return Array.isArray(value) ? value.join(', ') : value;
  }
  return undefined;
}
