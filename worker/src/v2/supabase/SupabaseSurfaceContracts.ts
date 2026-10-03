/**
 * Supabase / PostgREST surface contracts (Fase 0).
 * Epistemic honesty: OBSERVED / INFERRED / RECOMMENDED only.
 * Never embeds JWT / anon key material.
 */

export type SupabaseSurfaceContractVersion = 'fixguard-supabase-surface/v0';
export const SUPABASE_SURFACE_CONTRACT_VERSION: SupabaseSurfaceContractVersion =
  'fixguard-supabase-surface/v0';

export type SupabaseEpistemicStatus = 'OBSERVED' | 'INFERRED' | 'RECOMMENDED';

export type SupabaseRoleHint = 'anon' | 'authenticated' | 'unknown';

/**
 * Safe surface identity for a Supabase project (no secrets).
 */
export interface SupabaseProjectSurface {
  readonly projectRef: string;
  readonly restBaseUrl: string;
  readonly authBaseUrl: string;
  readonly epistemicStatus: SupabaseEpistemicStatus;
  readonly sourceUrl?: string;
}

/**
 * OBSERVED table / RPC inventory entry (names only — never row payloads).
 */
export interface PostgrestExposedRelation {
  readonly name: string;
  readonly relationKind: 'table' | 'view' | 'rpc' | 'unknown';
  readonly epistemicStatus: SupabaseEpistemicStatus;
}

export function isSupabaseHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  return host === 'supabase.co' || host.endsWith('.supabase.co');
}

/**
 * Generic / empty seed table defaults.
 * Target-specific table lists (e.g. historical profiles/shop_items/wallets/runs) are deprecated
 * to avoid synthetic/historical bias in discovery. Tables are prioritized strictly by
 * target-derived evidence (discovery order).
 */
export const SUPABASE_PREFERRED_RLS_SEED_TABLES: readonly string[] = Object.freeze([]);

/**
 * Preserves discovered table order with case-insensitive deduplication,
 * avoiding target-specific bias.
 */
export function preferSupabaseRlsTableOrder(
  tableNames: readonly string[]
): readonly string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const push = (name: string): void => {
    const key = name.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(name);
  };
  for (const t of tableNames) push(t);
  return Object.freeze(out);
}

/**
 * Hermetic: mine Storage public-object path hints from JS/HTML.
 * Sources: /storage/v1/object/public/{bucket}/{key}, storage.from('bucket').
 * Returns "bucket/key" or "bucket/" seeds — never secrets.
 */
export function extractSupabaseStoragePathHintsFromText(
  text: string,
  maxHints: number = 20
): readonly string[] {
  if (typeof text !== 'string' || text.length === 0) return Object.freeze([]);
  const cap = maxHints > 0 ? Math.floor(maxHints) : 20;
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string): void => {
    if (out.length >= cap) return;
    let p = raw.trim().replace(/^\/+/, '');
    if (p.startsWith('object/public/')) p = p.slice('object/public/'.length);
    if (p.startsWith('storage/v1/object/public/')) {
      p = p.slice('storage/v1/object/public/'.length);
    }
    if (!/^[A-Za-z0-9_][A-Za-z0-9_./-]{0,200}$/.test(p)) return;
    const key = p.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push(p);
  };

  for (const m of text.matchAll(
    /\/storage\/v1\/object\/public\/([A-Za-z0-9_./-]+)/g
  )) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(
    /storage\.from\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)/g
  )) {
    if (m[1]) push(`${m[1]}/`);
  }
  return Object.freeze(out);
}

/**
 * Hermetic: mine OBSERVED Next-Action id hints from RSC/flight/JS text.
 * Never invents ids; returns opaque hashes/ids only (min length 8).
 */
export function extractNextServerActionIdHintsFromText(
  text: string,
  maxHints: number = 10
): readonly string[] {
  if (typeof text !== 'string' || text.length === 0) return Object.freeze([]);
  const cap = maxHints > 0 ? Math.floor(maxHints) : 10;
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string): void => {
    if (out.length >= cap) return;
    const id = raw.trim();
    if (id.length < 8 || id.length > 128) return;
    if (!/^[A-Za-z0-9_+\/=.-]+$/.test(id)) return;
    if (seen.has(id)) return;
    seen.add(id);
    out.push(id);
  };

  for (const m of text.matchAll(/["']next-action["']\s*[:=]\s*["']([^"']+)["']/gi)) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(/Next-Action["']?\s*[:=]\s*["']([^"']+)["']/g)) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(/\$ACTION_ID_([A-Za-z0-9]+)/g)) {
    if (m[1]) push(m[1]);
  }
  return Object.freeze(out);
}

export function extractSupabaseProjectRef(hostname: string): string | undefined {
  const host = hostname.trim().toLowerCase().replace(/\.$/, '');
  const match = /^([a-z0-9]+)\.supabase\.co$/i.exec(host);
  return match?.[1];
}

export function classifySupabaseUrl(rawUrl: string): {
  readonly isSupabase: boolean;
  readonly projectRef?: string;
  readonly restBaseUrl?: string;
  readonly authBaseUrl?: string;
  readonly tableName?: string;
  readonly pathKind?: 'rest' | 'auth' | 'rpc' | 'other';
} {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { isSupabase: false };
  }
  if (!isSupabaseHost(parsed.hostname)) {
    return { isSupabase: false };
  }
  const projectRef = extractSupabaseProjectRef(parsed.hostname);
  const restBaseUrl = `${parsed.protocol}//${parsed.hostname}/rest/v1`;
  const authBaseUrl = `${parsed.protocol}//${parsed.hostname}/auth/v1`;
  const path = parsed.pathname || '/';
  let pathKind: 'rest' | 'auth' | 'rpc' | 'other' = 'other';
  let tableName: string | undefined;
  if (path.includes('/rest/v1')) {
    pathKind = 'rest';
    const after = path.split('/rest/v1/')[1];
    if (after) {
      const segment = after.split('/')[0]?.split('?')[0];
      if (segment && segment.length > 0 && segment !== 'rpc') {
        tableName = segment;
      }
      if (segment === 'rpc' || path.includes('/rpc/')) {
        pathKind = 'rpc';
      }
    }
  } else if (path.includes('/auth/v1')) {
    pathKind = 'auth';
  }
  return {
    isSupabase: true,
    ...(projectRef ? { projectRef } : {}),
    restBaseUrl,
    authBaseUrl,
    ...(tableName ? { tableName } : {}),
    pathKind,
  };
}

const TABLE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

/**
 * Hermetic: mine PostgREST / Supabase client table name hints from JS or HTML text.
 * Sources: `.from('table')`, `.from("table")`, `/rest/v1/{table}` path segments.
 * Never returns secrets; names only.
 */
export function extractSupabaseTableHintsFromText(
  text: string,
  maxHints: number = 40
): readonly string[] {
  if (typeof text !== 'string' || text.length === 0) return Object.freeze([]);
  const cap = maxHints > 0 ? Math.floor(maxHints) : 40;
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string): void => {
    if (out.length >= cap) return;
    const name = raw.trim();
    if (!TABLE_NAME_RE.test(name)) return;
    const lower = name.toLowerCase();
    // Skip common non-table identifiers
    if (
      lower === 'schema' ||
      lower === 'rpc' ||
      lower === 'select' ||
      lower === 'public' ||
      lower === 'storage' ||
      lower === 'auth'
    ) {
      return;
    }
    if (seen.has(lower)) return;
    seen.add(lower);
    out.push(name);
  };

  for (const m of text.matchAll(/\.from\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\)/g)) {
    if (m[1]) push(m[1]);
  }
  for (const m of text.matchAll(/\/rest\/v1\/([A-Za-z_][A-Za-z0-9_]*)/g)) {
    if (m[1]) push(m[1]);
  }
  return Object.freeze(out);
}

/**
 * Build absolute /rest/v1/{table} URL observation seeds for a known Supabase project.
 */
export function buildSupabaseRestTableUrlSeeds(args: {
  readonly restBaseUrl: string;
  readonly tableNames: readonly string[];
  readonly source: string;
  readonly discoveredAt: string;
}): readonly {
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly sources: readonly string[];
  readonly discoveredAt: string;
  readonly collectedAt: string;
  readonly freshness: 'live';
  readonly sourceReliability: 'inferred_relationship' | 'direct_observation';
}[] {
  let host = '';
  try {
    host = new URL(args.restBaseUrl).hostname;
  } catch {
    return Object.freeze([]);
  }
  if (!isSupabaseHost(host)) return Object.freeze([]);
  const base = args.restBaseUrl.replace(/\/$/, '');
  const out: {
    readonly url: string;
    readonly host: string;
    readonly path: string;
    readonly sources: readonly string[];
    readonly discoveredAt: string;
    readonly collectedAt: string;
    readonly freshness: 'live';
    readonly sourceReliability: 'inferred_relationship' | 'direct_observation';
  }[] = [];
  const seen = new Set<string>();
  for (const name of args.tableNames) {
    if (!TABLE_NAME_RE.test(name)) continue;
    const url = `${base}/${name}`;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push(
      Object.freeze({
        url,
        host,
        path: `/rest/v1/${name}`,
        sources: Object.freeze([args.source]),
        discoveredAt: args.discoveredAt,
        collectedAt: args.discoveredAt,
        freshness: 'live' as const,
        sourceReliability: 'inferred_relationship' as const,
      })
    );
  }
  return Object.freeze(out);
}
