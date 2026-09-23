/**
 * Milestone A3 — Light analytical inference helpers for TargetProfile v2.
 * Zero network calls. CNAME cloud map + CSP header parser only.
 */

import type { InferredHostingProvider } from './IntelligenceContracts.js';

const CNAME_CLOUD_MAP: readonly { readonly suffix: string; readonly provider: InferredHostingProvider }[] = [
  { suffix: '.vercel.app', provider: 'vercel' },
  { suffix: '.vercel-dns.com', provider: 'vercel' },
  { suffix: '.netlify.app', provider: 'netlify' },
  { suffix: '.netlify.com', provider: 'netlify' },
  { suffix: '.herokuapp.com', provider: 'heroku' },
  { suffix: '.herokudns.com', provider: 'heroku' },
  { suffix: '.github.io', provider: 'github_pages' },
  { suffix: '.githubusercontent.com', provider: 'github_pages' },
  { suffix: '.s3.amazonaws.com', provider: 'aws_s3' },
  { suffix: '.s3-website', provider: 'aws_s3' },
  { suffix: '.cloudfront.net', provider: 'aws_cloudfront' },
  { suffix: '.azurewebsites.net', provider: 'azure' },
  { suffix: '.cloudapp.net', provider: 'azure' },
  { suffix: '.fastly.net', provider: 'fastly' },
  { suffix: '.cloudflare.net', provider: 'cloudflare' },
  { suffix: '.cdn.cloudflare.net', provider: 'cloudflare' },
  { suffix: '.myshopify.com', provider: 'shopify' },
];

const CDN_PROVIDERS: ReadonlySet<InferredHostingProvider> = new Set([
  'vercel',
  'netlify',
  'aws_cloudfront',
  'fastly',
  'cloudflare',
]);

export function inferHostingProviderFromCname(cnameTarget: string): InferredHostingProvider {
  const target = cnameTarget.toLowerCase().replace(/\.$/, '');
  for (const entry of CNAME_CLOUD_MAP) {
    if (target.endsWith(entry.suffix) || target.includes(entry.suffix)) {
      return entry.provider;
    }
  }
  return 'unknown';
}

export function isInferredCdnProvider(provider: InferredHostingProvider): boolean {
  return CDN_PROVIDERS.has(provider);
}

/**
 * Parse CSP header into directive → source-list tokens.
 * Does not fetch; operates on an already-captured header string only.
 */
export function parseCspHeader(cspValue: string): ReadonlyMap<string, readonly string[]> {
  const result = new Map<string, string[]>();
  const directives = cspValue.split(';');
  for (const raw of directives) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    const name = (parts[0] ?? '').toLowerCase();
    if (!name) continue;
    const sources = parts.slice(1).filter((s) => s.length > 0);
    result.set(name, sources);
  }
  return result;
}

export function extractHeaderValue(
  headers: Readonly<Record<string, string | string[] | undefined>> | undefined,
  name: string
): string | undefined {
  if (!headers) return undefined;
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== target) continue;
    if (typeof v === 'string' && v.trim().length > 0) return v.trim();
    if (Array.isArray(v)) {
      const joined = v.filter((x) => typeof x === 'string' && x.trim().length > 0).join(', ');
      return joined.length > 0 ? joined : undefined;
    }
  }
  return undefined;
}

const AUTH_PATH_PATTERNS: readonly {
  readonly bucket: 'loginPaths' | 'oauthPaths' | 'ssoPaths' | 'registrationPaths' | 'passwordResetPaths' | 'otherAuthPaths';
  readonly match: RegExp;
}[] = [
  { bucket: 'loginPaths', match: /\/(login|signin|sign-in|session\/new)(\/|$)/i },
  { bucket: 'oauthPaths', match: /\/(oauth|oauth2|authorize|auth\/callback)(\/|$)/i },
  { bucket: 'ssoPaths', match: /\/(sso|saml|oidc)(\/|$)/i },
  { bucket: 'registrationPaths', match: /\/(register|signup|sign-up|join)(\/|$)/i },
  { bucket: 'passwordResetPaths', match: /\/(password|reset|forgot|recover)(\/|$)/i },
  { bucket: 'otherAuthPaths', match: /\/(auth|account\/login|users\/sign_in)(\/|$)/i },
];

export function classifyAuthPath(
  path: string
): 'loginPaths' | 'oauthPaths' | 'ssoPaths' | 'registrationPaths' | 'passwordResetPaths' | 'otherAuthPaths' | null {
  for (const entry of AUTH_PATH_PATTERNS) {
    if (entry.match.test(path)) {
      return entry.bucket;
    }
  }
  return null;
}
