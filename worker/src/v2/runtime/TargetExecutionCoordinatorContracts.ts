/**
 * Milestone F3 — Target Execution Coordinator Contracts
 *
 * Defines contracts for per-host concurrency limits, rate-limiting quotas,
 * and execution telemetry.
 */

import type {
  TargetCircuitBreakerConfig,
  CircuitBreakerState,
  HostCircuitHealth
} from './CircuitBreakerContracts.js';

export interface TargetQuotaConfig {
  readonly requestsPerSecond: number;
  readonly maxConcurrency: number;
  readonly maxQueueDepth?: number;
  readonly circuitBreakerConfig?: Partial<TargetCircuitBreakerConfig>;
}

export interface TargetExecutionStats {
  readonly activeCount: number;
  readonly queuedCount: number;
  readonly totalCompleted: number;
  readonly totalRejected: number;
  readonly circuitState: CircuitBreakerState;
  readonly circuitHealth?: HostCircuitHealth;
}
