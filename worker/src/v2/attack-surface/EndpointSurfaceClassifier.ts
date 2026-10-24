/**
 * R2 — Endpoint Surface Classifier (recon-first pivot).
 *
 * Pure, deterministic, pattern-based classification of a discovered
 * endpoint's surface kind, using only its path and method — no network
 * calls, no severity/exploitability claims. This is descriptive
 * recon/classification metadata, not a vulnerability signal.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { EndpointSurfaceKind } from './AttackSurfaceContracts.js';

const STATIC_ASSET_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.css',
  '.map',
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.webp',
  '.ico',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.pdf',
  '.txt',
  '.xml',
  '.json',
]);

const ADMIN_OR_INTERNAL_PATTERNS: readonly RegExp[] = [
  /\/admin(\/|$)/i,
  /\/internal(\/|$)/i,
  /\/dashboard(\/|$)/i,
  /\/debug(\/|$)/i,
  /\/actuator(\/|$)/i,
  /\/wp-admin(\/|$)/i,
  /\/_next\/(?!static\/chunks)/i, // Next.js internal/server routes, but not public static chunks
  /\/management(\/|$)/i,
  /\/console(\/|$)/i,
];

const AUTH_BOUNDARY_PATTERNS: readonly RegExp[] = [
  /\/auth(\/|$)/i,
  /\/login(\/|$)/i,
  /\/logout(\/|$)/i,
  /\/signin(\/|$)/i,
  /\/signup(\/|$)/i,
  /\/signout(\/|$)/i,
  /\/oauth(\/|$)/i,
  /\/session(\/|$)/i,
  /\/token(\/|$)/i,
  /\/sso(\/|$)/i,
];

const GRAPHQL_PATTERNS: readonly RegExp[] = [/\/graphql(\/|$)/i, /\/gql(\/|$)/i];

const REST_API_PATTERNS: readonly RegExp[] = [
  /^\/api(\/|$)/i,
  /\/api\/v\d+(\/|$)/i,
  /^\/v\d+(\/|$)/i,
  /\/rest(\/|$)/i,
];

function hasKnownStaticExtension(pathname: string): boolean {
  const lastDot = pathname.lastIndexOf('.');
  if (lastDot === -1) return false;
  const lastSlash = pathname.lastIndexOf('/');
  if (lastDot < lastSlash) return false; // dot is in a directory segment, not the filename
  const ext = pathname.slice(lastDot).toLowerCase();
  return STATIC_ASSET_EXTENSIONS.has(ext);
}

function matchesAny(pathname: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((re) => re.test(pathname));
}

/**
 * Classifies a discovered endpoint's surface kind from its path/method only.
 * Deterministic and order-sensitive: more specific categories are checked
 * before the broad SPA-route fallback. Returns 'unknown' when nothing
 * matches — an honest default, not a guess.
 */
export function classifyEndpointSurface(args: {
  readonly path: string;
  readonly method: string;
}): EndpointSurfaceKind {
  const pathname = args.path && args.path.length > 0 ? args.path : '/';

  if (hasKnownStaticExtension(pathname)) return 'static_asset';
  if (matchesAny(pathname, GRAPHQL_PATTERNS)) return 'graphql_api';
  if (matchesAny(pathname, AUTH_BOUNDARY_PATTERNS)) return 'auth_boundary';
  if (matchesAny(pathname, ADMIN_OR_INTERNAL_PATTERNS)) return 'admin_or_internal';
  if (matchesAny(pathname, REST_API_PATTERNS)) return 'rest_api';

  // GET to a path with no recognized API/auth/admin prefix and no static
  // extension: most consistent with a client-rendered SPA route. Any other
  // method against an unmatched path is left 'unknown' rather than guessed.
  if (args.method.toUpperCase() === 'GET') return 'spa_client_route';

  return 'unknown';
}
