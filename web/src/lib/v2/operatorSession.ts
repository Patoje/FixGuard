/**
 * FixGuard V2 — Operator Session Identity Management
 *
 * Manages explicit development/runtime operator identity.
 * Avoids hardcoding fake senior roles (e.g. "op_sec_admin", "usr_secops_lead")
 * while providing an honest, operator-controlled identifier for audit trails.
 */

const STORAGE_KEY = "fg_v2_operator_id";

/**
 * Honest default identifier representing local developer/analyst session.
 * Clearly marked as local development rather than claiming authenticated senior SecOps status.
 */
export const DEFAULT_DEV_OPERATOR_ID = "op_local_analyst";

export function getOperatorSessionIdentity(): string {
  if (typeof window === "undefined") {
    return DEFAULT_DEV_OPERATOR_ID;
  }
  try {
    const stored = window.sessionStorage?.getItem(STORAGE_KEY);
    if (stored && stored.trim().length >= 3) {
      return stored.trim();
    }
  } catch {
    // sessionStorage not accessible
  }
  return DEFAULT_DEV_OPERATOR_ID;
}

export function setOperatorSessionIdentity(id: string): void {
  if (typeof window === "undefined") return;
  try {
    const clean = id.trim();
    if (clean.length >= 3) {
      window.sessionStorage?.setItem(STORAGE_KEY, clean);
    }
  } catch {
    // ignore
  }
}
