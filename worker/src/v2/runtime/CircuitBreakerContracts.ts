/**
 * FixGuard V2 — Target Circuit Breaker & Blast Radius Contracts
 *
 * Defines state machines, configurations, health telemetry, and error representations
 * for adaptive target protection against server instability and service denial.
 */

export type CircuitBreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export const CIRCUIT_OPEN_REASON_CODE = 'target_instability_circuit_open' as const;

export interface TargetCircuitBreakerConfig {
  /**
   * Number of consecutive 5xx (500, 502, 503, 504) responses before tripping circuit to OPEN.
   * Default: 3
   */
  readonly consecutive5xxThreshold: number;

  /**
   * Number of consecutive network errors or timeouts before tripping circuit to OPEN.
   * Default: 3
   */
  readonly consecutiveErrorThreshold: number;

  /**
   * Number of consecutive successful responses in HALF_OPEN state before resetting to CLOSED.
   * Default: 2
   */
  readonly halfOpenSuccessThreshold: number;

  /**
   * Time in milliseconds the circuit remains OPEN before transitioning to HALF_OPEN.
   * Default: 30,000ms (30 seconds)
   */
  readonly openCooldownMs: number;
}

export const DEFAULT_CIRCUIT_BREAKER_CONFIG: TargetCircuitBreakerConfig = Object.freeze({
  consecutive5xxThreshold: 3,
  consecutiveErrorThreshold: 3,
  halfOpenSuccessThreshold: 2,
  openCooldownMs: 30_000,
});

export interface HostCircuitHealth {
  readonly state: CircuitBreakerState;
  readonly consecutiveFailures: number;
  readonly consecutiveSuccesses: number;
  readonly total5xxErrors: number;
  readonly totalTimeouts: number;
  readonly totalErrors: number;
  readonly lastFailureTimeMs: number | null;
  readonly lastStateChangeTimeMs: number;
  readonly trippedCount: number;
}

export class TargetInstabilityError extends Error {
  public readonly reasonCode = CIRCUIT_OPEN_REASON_CODE;

  constructor(
    public readonly host: string,
    public readonly circuitState: CircuitBreakerState,
    message?: string
  ) {
    super(
      message ??
        `Target host '${host}' is exhibiting instability: circuit breaker is ${circuitState}. Execution halted to prevent service degradation.`
    );
    this.name = 'TargetInstabilityError';
  }
}
