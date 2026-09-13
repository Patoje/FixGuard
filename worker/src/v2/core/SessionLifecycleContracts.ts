/**
 * Milestone F3 — Session Lifecycle Contracts
 *
 * Defines structured session state, lifecycle transitions, token refresh hooks,
 * and pre-execution health check result types.
 */

export type SessionLifecycleState = 'active' | 'expired' | 'refreshing' | 'invalid';

export interface TokenRefreshResult {
  readonly ok: boolean;
  readonly updatedHeaders?: Readonly<Record<string, string>>;
  readonly newExpiresAt?: string;
  readonly error?: string;
}

export type TokenRefreshHook = () => Promise<TokenRefreshResult>;

export interface TargetSessionState {
  readonly state: SessionLifecycleState;
  readonly expiresAt?: string;
  readonly tokenRefreshHook?: TokenRefreshHook;
  readonly lastValidatedAt?: string;
}

export interface SessionValidationResult {
  readonly ok: boolean;
  readonly sessionState: TargetSessionState;
  readonly updatedHeaders?: Readonly<Record<string, string>>;
  readonly reasonCode?: string;
}
