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
