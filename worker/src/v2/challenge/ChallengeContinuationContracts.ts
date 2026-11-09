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
  /**
   * Milestone: Challenge Continuation Reliability — which known challenge
   * mechanism the evidence matches, derived only from matching signatures.
   * 'generic' means a challenge is present but no vendor-exclusive marker
   * matched. 'unknown' means no challenge evidence was found at all. Never
   * guessed beyond what the signature match actually establishes.
   */
  readonly providerHint: ChallengeProviderHint;
}

/**
 * Milestone: Challenge Continuation Reliability — closed set of known
 * challenge mechanisms distinguishable from matching evidence (body/title
 * signatures). 'generic' = some challenge marker matched, but none specific
 * to a known vendor. 'unknown' = no challenge marker matched at all.
 */
export type ChallengeProviderHint = 'vercel' | 'cloudflare' | 'generic' | 'unknown';

/**
 * Milestone: Challenge Continuation Reliability — which signal ultimately
 * decided a continuation's resolution outcome. Absent when resolution was
 * never attempted (e.g. no-browser-required paths). 'insufficient_evidence'
 * is distinct from 'title_and_content': the latter means available evidence
 * (title and/or body) was definitive; the former means the browser-side
 * check could not obtain enough content to decide, and no independent
 * canary was available either to decide for it.
 */
export type ChallengeResolutionMethod =
  | 'title_and_content'
  | 'canary_probe'
  | 'operator_confirmed'
  | 'insufficient_evidence';

/**
 * Milestone: Challenge Continuation Reliability (Recovery, Not Terminal
 * State) — which approach a single evaluateAndProgress() attempt used.
 * 'fresh_context': today's only behavior — isolated browser+context per
 * attempt, closed when the attempt ends. 'persistent_context': reuses a
 * caller-supplied browser+context across multiple attempts for the SAME
 * URL's retry sequence, still inside the existing per-assessment budget.
 * 'operator_intervention' is never dispatched by evaluateAndProgress itself
 * — it names the state classification.requiresOperatorHitl already
 * produces (state: 'waiting_for_operator'); listed here so the strategy
 * type documents the full recovery picture, not just the automated half.
 *
 * Deferred milestone extension point (not implemented here): an
 * 'owner_bypass_credential' strategy, reusing CredentialVaultService's
 * WeakMap-keyed single-use-accessor pattern
 * (worker/src/v2/post-exploitation/CredentialVaultService.ts) for
 * retrieving an owner-provided bypass credential/header, gated by a branded
 * AttackAuthorizationToken + AuthorizedScopeGrant match — no such contract
 * field exists yet anywhere in AuthorizedScopeContracts.ts.
 */
export type ChallengeContinuationStrategyKind =
  | 'fresh_context'
  | 'persistent_context'
  | 'operator_intervention';

/** Default retry order: an isolated attempt first, then one context-reuse attempt. */
export const DEFAULT_CHALLENGE_CONTINUATION_STRATEGY_ORDER: readonly ChallengeContinuationStrategyKind[] =
  Object.freeze(['fresh_context', 'persistent_context']);

/**
 * 'validation_pending' (fix: Correct Challenge Resolution) — the
 * browser-side check never obtained sufficient evidence (no known challenge
 * signature matched, but the body sample was also never available/non-empty
 * long enough to positively confirm the real application) AND no transport
 * was supplied to let an independent HTTP/session canary decide instead.
 * Distinct from both 'validated' (never claimed without positive evidence)
 * and 'failed' (never claimed as a confirmed-unreachable result the absence
 * of evidence does not support).
 */
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
  /**
   * Milestone: Challenge Continuation Reliability — which known mechanism
   * the observed title/body evidence matched. Absent when no browser-side
   * resolution check ran (e.g. pre-browser classifier early-returns).
   */
  readonly providerHint?: ChallengeProviderHint;
  /** Which signal ultimately decided this result. Absent when not attempted. */
  readonly resolutionMethod?: ChallengeResolutionMethod;
  /** Which retry approach this attempt used. Absent on pre-browser early-returns. */
  readonly strategyUsed?: ChallengeContinuationStrategyKind;
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
  | 'unknown_continuation_error'
  /**
   * Fix: Correct Challenge Resolution — no challenge signature matched, but
   * the body sample was never available/non-empty and no canary ran to
   * independently confirm the real application. Distinct from
   * 'challenge_unresolved' (a signature DID match) and from
   * 'application_unreachable_after_progression' (a canary DID run and
   * failed) — this is genuine absence of evidence either way.
   */
  | 'resolution_evidence_insufficient';

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
  /** See ChallengeContinuationResult.providerHint. Absent on records written before this field existed. */
  readonly providerHint?: ChallengeProviderHint;
  /** See ChallengeContinuationResult.resolutionMethod. Absent on records written before this field existed. */
  readonly resolutionMethod?: ChallengeResolutionMethod;
  /** See ChallengeContinuationResult.strategyUsed. Absent on records written before this field existed. */
  readonly strategyUsed?: ChallengeContinuationStrategyKind;
  readonly attemptedAt: string;
}
