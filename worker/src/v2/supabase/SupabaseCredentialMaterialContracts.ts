/**
 * Supabase credential material contracts (Fase 0).
 *
 * Anon keys are public-by-design in Supabase clients but MUST NOT be persisted
 * in findings, drafts, reports, or git. Only epistemic kind + redaction helpers
 * live here; raw material stays in-process on probe requests.
 */

export type SupabaseCredentialMaterialContractVersion =
  'fixguard-supabase-credential-material/v0';
export const SUPABASE_CREDENTIAL_MATERIAL_CONTRACT_VERSION: SupabaseCredentialMaterialContractVersion =
  'fixguard-supabase-credential-material/v0';

/**
 * Only OBSERVED anon keys may drive probes. Never invent or hardcode.
 */
export type SupabaseAnonKeyKind = 'OBSERVED';

export interface SupabaseAnonKeyPresence {
  readonly kind: SupabaseAnonKeyKind;
  /** Redacted preview for operator DTOs — never the full key. */
  readonly redactedPreview: string;
}

export function redactSupabaseKeyPreview(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length <= 12) {
    return '…';
  }
  return `${trimmed.slice(0, 6)}…${trimmed.slice(-4)}`;
}

/**
 * Heuristic: Supabase anon/service JWTs are typically long eyJ… strings.
 * Does not validate signature — only shape gate for in-process use.
 */
export function looksLikeSupabaseAnonKey(value: string): boolean {
  const v = value.trim();
  if (v.length < 20 || v.length > 4096) return false;
  if (/^sb_publishable_[A-Za-z0-9_-]+$/.test(v)) return true;
  return /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
}

function decodeJwtPayloadJson(jwt: string): { readonly role?: string; readonly iss?: string } | null {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) return null;
    const pad = '='.repeat((4 - (payload.length % 4)) % 4);
    const parsed: unknown = JSON.parse(
      Buffer.from(payload + pad, 'base64url').toString('utf8')
    );
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const role = Reflect.get(parsed, 'role');
    const iss = Reflect.get(parsed, 'iss');
    return {
      ...(typeof role === 'string' ? { role } : {}),
      ...(typeof iss === 'string' ? { iss } : {}),
    };
  } catch {
    return null;
  }
}

/** JWT `role` claim when the value is a JWT. Publishable keys have none. */
export function supabaseJwtClaimRole(value: string): string | undefined {
  const role = decodeJwtPayloadJson(value.trim())?.role?.trim() ?? '';
  return role.length > 0 ? role : undefined;
}

/**
 * Mine OBSERVED anon/publishable key material from JS/HTML body text.
 * Never invents keys. Prefer sb_publishable_*, then eyJ… with role=anon / iss=supabase.
 * Raw key stays in-process only — never persist to findings/drafts/reports.
 */
export function extractSupabaseAnonKeyFromText(text: string): string | undefined {
  if (typeof text !== 'string' || text.length === 0) return undefined;

  const publishable = text.match(/sb_publishable_[A-Za-z0-9_-]+/);
  if (publishable && looksLikeSupabaseAnonKey(publishable[0])) {
    return publishable[0];
  }

  const jwts = text.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g);
  if (!jwts) return undefined;
  for (const jwt of jwts) {
    if (!looksLikeSupabaseAnonKey(jwt)) continue;
    const json = decodeJwtPayloadJson(jwt);
    if (!json) continue;
    if (json.role !== undefined && json.role !== 'anon') continue;
    if (json.role === 'anon' || json.iss === 'supabase') {
      return jwt;
    }
  }
  return undefined;
}
