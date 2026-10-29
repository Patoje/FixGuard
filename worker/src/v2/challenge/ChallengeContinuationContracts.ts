/**
 * FixGuard V2 — Challenge Continuation Contracts.
 * Contract version: fixguard-challenge-continuation/v0
 *
 * Defines models and lifecycle states for challenge-aware assessment
 * and browser-mediated session continuation.
 *
 * Invariants:
 * 1. Challenge != Vulnerability: an edge challenge is never reported as an application bug.
 * 2. Strict distinction:
 *    - 403 WAF challenge vs 403 application authorization denial.
 *    - 429 rate limiting vs bot checkpoint.
 *    - JS browser challenge vs static denial.
 * 3. Operator HITL boundary: interactive challenges pause at explicit state waiting_for_operator.
 * 4. Validation requirement: resumed sessions must demonstrate observable application reachability.
 */

import type { DefenseObservation } from '../test-validity/TestValidityContracts.js';

export const CHALLENGE_CONTINUATION_CONTRACT_VERSION =
  'fixguard-challenge-continuation/v0' as const;
export type ChallengeContinuationContractVersion =
  typeof CHALLENGE_CONTINUATION_CONTRACT_VERSION;

export type EdgeChallengeClassificationVerdict =
  | 'no_waf_observed'
  | 'waf_suspected'
  | 'waf_confirmed'
  | 'challenge_present'
  | 'rate_limited'
  | 'browser_challenge'
  | 'application_reachable'
  | 'application_not_reached';

export interface EdgeChallengeClassification {
  readonly contractVersion: ChallengeContinuationContractVersion;
  readonly verdict: EdgeChallengeClassificationVerdict;
  readonly isBlocking: boolean;
  readonly requiresBrowser: boolean;
  readonly requiresOperatorHitl: boolean;
  readonly reasonCode: string;
  readonly explanation: string;
  readonly defenses: readonly DefenseObservation[];
}

export type ChallengeContinuationState =
  | 'challenge_detected'
  | 'waiting_for_operator'
  | 'operator_completed'
  | 'validation_pending'
  | 'validated'
  | 'failed'
  | 'expired';

export interface ChallengeContinuationResult {
  readonly state: ChallengeContinuationState;
  readonly challengeUrl: string;
  readonly reasonCode: string;
  readonly applicationReachable: boolean;
  /** Captured cookies held safely in memory; never printed in cleartext reports. */
  readonly capturedCookieNames: readonly string[];
  readonly validatedAt?: string;
  readonly operatorMessage?: string;
  /**
   * Milestone R11 — secondary diagnostic, independent of the final outcome
   * above: true only when the browser-mediated flow progressed far enough
   * to attempt cookie extraction, and that extraction itself threw. Never
   * overwrites `state`/`reasonCode`/`applicationReachable` — a continuation
   * can still validate successfully even when this is true. Absent when
   * extraction was never attempted or succeeded.
   */
  readonly cookieExtractionFailed?: boolean;
}

export interface OperatorChallengeCallbackInput {
  readonly challengeId: string;
  readonly operatorNotes?: string;
  readonly confirmedCookies?: Readonly<Record<string, string>>;
}

/**
 * Milestone R11 — per-attempt diagnostic for a single
 * ChallengeBrowserContinuationService.evaluateAndProgress() call, meant to
 * be persisted (unlike the ephemeral ReconHealthSignals). Deliberately
 * minimal: no raw messages, no full URLs, no cookie or header values — see
 * outcomeKind below for the closed set of distinctions the current
 * implementation can actually establish.
 */
export type ChallengeAttemptOutcomeKind =
  | 'validated_without_browser'
  | 'blocked_without_browser'
  | 'waiting_for_operator'
  | 'challenge_unresolved'
  | 'browser_progression_succeeded'
  | 'still_challenged_after_progression'
  | 'application_unreachable_after_progression'
  | 'canary_validation_failed'
  | 'unknown_continuation_error';

export interface ChallengeAttemptDiagnostic {
  readonly contractVersion: ChallengeContinuationContractVersion;
  /** One-based ordinal of the actual continuation call within the assessment, shared across both caller sites. Range 1-3 under the existing budget. */
  readonly attemptNumber: number;
  /** Normalized hostname only — never a full URL, which may carry sensitive query parameters. */
  readonly host: string;
  readonly state: ChallengeContinuationState;
  readonly reasonCode: string;
  readonly outcomeKind: ChallengeAttemptOutcomeKind;
  /** Secondary diagnostic — see ChallengeContinuationResult.cookieExtractionFailed. Never changes outcomeKind. */
  readonly cookieExtractionFailed?: boolean;
  readonly attemptedAt: string;
}
