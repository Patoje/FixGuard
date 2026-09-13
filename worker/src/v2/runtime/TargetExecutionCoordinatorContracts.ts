/**
 * Milestone F3 — Target Execution Coordinator Contracts
 *
 * Defines contracts for per-host concurrency limits, rate-limiting quotas,
 * and execution telemetry.
 */

export interface TargetQuotaConfig {
  readonly requestsPerSecond: number;
  readonly maxConcurrency: number;
  readonly maxQueueDepth?: number;
}

export interface TargetExecutionStats {
  readonly activeCount: number;
  readonly queuedCount: number;
  readonly totalCompleted: number;
  readonly totalRejected: number;
}
