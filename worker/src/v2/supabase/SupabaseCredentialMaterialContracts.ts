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
