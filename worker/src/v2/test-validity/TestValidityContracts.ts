/**
 * Etapa 2 · F3-foundation slice — DefenseObservation + TestValidity
 * Contract version: fixguard-test-validity/v0
 *
 * DefenseObservation = OBSERVED intermediate control (WAF/CDN/bot/rate-limit/…).
 * TestValidity = derived verdict: valid | interfered | inconclusive.
 *
 * Invariant: testValidity != valid MUST NOT advance or refute verification state.
 * interfered ≠ safe. This is honesty labeling, not evasion.
 *
 * Full HypothesisScheduler / ASG defense nodes / wafw00f host probes are deferred.
 */

export type TestValidityContractVersion = 'fixguard-test-validity/v0';
export const TEST_VALIDITY_CONTRACT_VERSION: TestValidityContractVersion =
  'fixguard-test-validity/v0';

export type DefenseControlKind =
  | 'waf'
  | 'cdn'
  | 'rate_limit'
  | 'bot'
  | 'auth_gateway'
  | 'api_gateway'
  | 'unknown';

export type DefenseSignalSource =
  | 'header'
  | 'status'
  | 'challenge_body'
  | 'timing'
  | 'error_signal'
  | 'control_differential';

export type TestValidityVerdict = 'valid' | 'interfered' | 'inconclusive';

/**
 * Passive observation of an intermediate defense. Not a vulnerability judgment.
 */
export interface DefenseObservation {
  readonly contractVersion: TestValidityContractVersion;
  readonly kind: 'defense_observation';
  readonly observationId: string;
  readonly controlKind: DefenseControlKind;
  readonly signalSource: DefenseSignalSource;
  /** Closed reason codes only — no free-form exploit claims. */
  readonly reasonCode: string;
  readonly observedAt: string;
  readonly targetHost?: string;
  readonly evidenceSnippet?: string;
}

/**
 * Safe HTTP response facets for passive defense detection.
 * Never include raw cookies / Authorization headers.
 */
export interface HttpResponseDefenseSignals {
  readonly statusCode?: number;
  readonly headerNames?: readonly string[];
  /** Lowercased header name → truncated value (server/cdn/waf markers only). */
  readonly headerValues?: Readonly<Record<string, string>>;
  readonly bodyExcerpt?: string;
  readonly responseTimeMs?: number;
  readonly errorSignals?: readonly string[];
  readonly targetHost?: string;
}

/**
 * Optional control-vs-probe differential for interference_check.
 * Suspicious probe blocked/altered while equivalent benign control passes → interfered.
 */
export interface InterferenceCheckInput {
  readonly probe: HttpResponseDefenseSignals;
  readonly control: HttpResponseDefenseSignals;
}

export interface TestValidityEvaluation {
  readonly contractVersion: TestValidityContractVersion;
  readonly kind: 'test_validity_evaluation';
  readonly verdict: TestValidityVerdict;
  readonly reasonCode: string;
  readonly defenses: readonly DefenseObservation[];
  readonly evaluatedAt: string;
  /**
   * When false, VerificationState MUST NOT advance or refute.
   * Always false unless verdict === 'valid'.
   */
  readonly allowsVerificationMutation: boolean;
}

export type TestValidityEvaluationInput = Readonly<{
  readonly probe: HttpResponseDefenseSignals;
  readonly control?: HttpResponseDefenseSignals;
  readonly observedAt?: string;
  readonly observationIdPrefix?: string;
}>;
