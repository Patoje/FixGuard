/**
 * Safe ID Generator & Client-Side Validators
 *
 * Enforces backend constraint: /^[A-Za-z0-9_-]{1,64}$/ (isStrictSafeId).
 */

const STRICT_SAFE_ID_REGEX = /^[A-Za-z0-9_-]{1,64}$/;

export function isStrictSafeId(id: unknown): id is string {
  return typeof id === 'string' && id.length >= 1 && id.length <= 64 && STRICT_SAFE_ID_REGEX.test(id);
}

export function generateCandidateId(): string {
  const rand = Math.random().toString(36).slice(2, 7);
  return `cand_${Date.now()}_${rand}`;
}

export function generateTriageDecisionId(): string {
  const rand = Math.random().toString(36).slice(2, 7);
  return `dec_${Date.now()}_${rand}`;
}

export function generateReportId(): string {
  const rand = Math.random().toString(36).slice(2, 7);
  return `rep_${Date.now()}_${rand}`;
}

export function isValidTargetUri(uri: string): boolean {
  if (!uri || typeof uri !== 'string') return false;
  try {
    const parsed = new URL(uri);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}
