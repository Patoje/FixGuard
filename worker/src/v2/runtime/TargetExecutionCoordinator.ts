/**
 * Milestone F3 & F8 — Shared Target Concurrency, Rate-Limit & Circuit Breaker Coordinator
 *
 * Coordinates outbound requests across concurrent operations targeting the same host.
 * Enforces:
 * 1. Global per-host rate limiter (requests/sec).
 * 2. Concurrency ceiling per host (max concurrent active probes/processes).
 * 3. Queue depth limits to prevent unbounded memory growth.
 * 4. Adaptive Target Circuit Breaker (Acción 13 / Milestone F8):
 *    - Trips to OPEN upon consecutive 5xx server responses or network timeouts/errors.
 *    - Immediately halts active queued requests for distressed hosts.
 *    - Transitions to HALF_OPEN after cooldown period to test recovery.
 */

import type {
  TargetQuotaConfig,
  TargetExecutionStats
} from './TargetExecutionCoordinatorContracts.js';
import type {
  CircuitBreakerState,
  HostCircuitHealth,
  TargetCircuitBreakerConfig
} from './CircuitBreakerContracts.js';
import {
  DEFAULT_CIRCUIT_BREAKER_CONFIG,
  TargetInstabilityError
} from './CircuitBreakerContracts.js';

interface QueuedTask<T> {
  readonly task: () => Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason?: unknown) => void;
  readonly enqueuedAt: number;
}

interface CircuitBreakerInternal {
  state: CircuitBreakerState;
  consecutiveFailures: number;
  consecutiveSuccesses: number;
  total5xxErrors: number;
  totalTimeouts: number;
  totalErrors: number;
  lastFailureTimeMs: number | null;
  lastStateChangeTimeMs: number;
  trippedCount: number;
}

interface HostExecutionState {
  activeCount: number;
  lastDispatchTimeMs: number;
  timer: NodeJS.Timeout | null;
  queue: Array<QueuedTask<unknown>>;
  totalCompleted: number;
  totalRejected: number;
  circuit: CircuitBreakerInternal;
}

export class TargetExecutionCoordinator {
  private readonly defaultQuota: TargetQuotaConfig;
  private readonly defaultCircuitConfig: TargetCircuitBreakerConfig;
  private readonly hostQuotas = new Map<string, TargetQuotaConfig>();
  private readonly hostStates = new Map<string, HostExecutionState>();

  constructor(defaultQuota?: Partial<TargetQuotaConfig>) {
    this.defaultQuota = {
      requestsPerSecond: defaultQuota?.requestsPerSecond ?? 10,
      maxConcurrency: defaultQuota?.maxConcurrency ?? 3,
      maxQueueDepth: defaultQuota?.maxQueueDepth ?? 500,
      circuitBreakerConfig: defaultQuota?.circuitBreakerConfig
    };

    this.defaultCircuitConfig = {
      consecutive5xxThreshold:
        defaultQuota?.circuitBreakerConfig?.consecutive5xxThreshold ??
        DEFAULT_CIRCUIT_BREAKER_CONFIG.consecutive5xxThreshold,
      consecutiveErrorThreshold:
        defaultQuota?.circuitBreakerConfig?.consecutiveErrorThreshold ??
        DEFAULT_CIRCUIT_BREAKER_CONFIG.consecutiveErrorThreshold,
      halfOpenSuccessThreshold:
        defaultQuota?.circuitBreakerConfig?.halfOpenSuccessThreshold ??
        DEFAULT_CIRCUIT_BREAKER_CONFIG.halfOpenSuccessThreshold,
      openCooldownMs:
        defaultQuota?.circuitBreakerConfig?.openCooldownMs ??
        DEFAULT_CIRCUIT_BREAKER_CONFIG.openCooldownMs
    };
  }

  public setHostQuota(host: string, config: TargetQuotaConfig): void {
    const normalizedHost = host.toLowerCase().trim();
    this.hostQuotas.set(normalizedHost, config);
  }

  private getHostCircuitConfig(host: string): TargetCircuitBreakerConfig {
    const quota = this.hostQuotas.get(host) ?? this.defaultQuota;
    return {
      consecutive5xxThreshold:
        quota.circuitBreakerConfig?.consecutive5xxThreshold ??
        this.defaultCircuitConfig.consecutive5xxThreshold,
      consecutiveErrorThreshold:
        quota.circuitBreakerConfig?.consecutiveErrorThreshold ??
        this.defaultCircuitConfig.consecutiveErrorThreshold,
      halfOpenSuccessThreshold:
        quota.circuitBreakerConfig?.halfOpenSuccessThreshold ??
        this.defaultCircuitConfig.halfOpenSuccessThreshold,
      openCooldownMs:
        quota.circuitBreakerConfig?.openCooldownMs ??
        this.defaultCircuitConfig.openCooldownMs
    };
  }

  private getOrCreateHostState(normalizedHost: string): HostExecutionState {
    let state = this.hostStates.get(normalizedHost);
    if (!state) {
      state = {
        activeCount: 0,
        lastDispatchTimeMs: 0,
        timer: null,
        queue: [],
        totalCompleted: 0,
        totalRejected: 0,
        circuit: {
          state: 'CLOSED',
          consecutiveFailures: 0,
          consecutiveSuccesses: 0,
          total5xxErrors: 0,
          totalTimeouts: 0,
          totalErrors: 0,
          lastFailureTimeMs: null,
          lastStateChangeTimeMs: Date.now(),
          trippedCount: 0
        }
      };
      this.hostStates.set(normalizedHost, state);
    }
    return state;
  }

  private updateCircuitState(host: string): CircuitBreakerState {
    const state = this.getOrCreateHostState(host);
    const config = this.getHostCircuitConfig(host);

    if (state.circuit.state === 'OPEN') {
      const elapsed = Date.now() - state.circuit.lastStateChangeTimeMs;
      if (elapsed >= config.openCooldownMs) {
        state.circuit.state = 'HALF_OPEN';
        state.circuit.consecutiveSuccesses = 0;
        state.circuit.lastStateChangeTimeMs = Date.now();
      }
    }

    return state.circuit.state;
  }

  /**
   * Returns true if the circuit breaker for this host is currently OPEN (blocking all requests).
   */
  public isCircuitOpen(host: string): boolean {
    const normalizedHost = host.toLowerCase().trim();
    const currentState = this.updateCircuitState(normalizedHost);
    return currentState === 'OPEN';
  }

  /**
   * Returns the current state of the circuit breaker ('CLOSED' | 'OPEN' | 'HALF_OPEN').
   */
  public getCircuitState(host: string): CircuitBreakerState {
    const normalizedHost = host.toLowerCase().trim();
    return this.updateCircuitState(normalizedHost);
  }

  /**
   * Returns detailed circuit health telemetry for a target host.
   */
  public getCircuitStats(host: string): HostCircuitHealth {
    const normalizedHost = host.toLowerCase().trim();
    const state = this.getOrCreateHostState(normalizedHost);
    this.updateCircuitState(normalizedHost);

    return {
      state: state.circuit.state,
      consecutiveFailures: state.circuit.consecutiveFailures,
      consecutiveSuccesses: state.circuit.consecutiveSuccesses,
      total5xxErrors: state.circuit.total5xxErrors,
      totalTimeouts: state.circuit.totalTimeouts,
      totalErrors: state.circuit.totalErrors,
      lastFailureTimeMs: state.circuit.lastFailureTimeMs,
      lastStateChangeTimeMs: state.circuit.lastStateChangeTimeMs,
      trippedCount: state.circuit.trippedCount
    };
  }

  /**
   * Records target response feedback to update circuit breaker health.
   */
  public recordTargetResponse(
    host: string,
    status: number | 'timeout' | 'error'
  ): void {
    const normalizedHost = host.toLowerCase().trim();
    const state = this.getOrCreateHostState(normalizedHost);
    const config = this.getHostCircuitConfig(normalizedHost);
    const now = Date.now();

    const isFailure =
      status === 'timeout' ||
      status === 'error' ||
      (typeof status === 'number' && status >= 500 && status < 600);

    if (isFailure) {
      state.circuit.consecutiveFailures++;
      state.circuit.consecutiveSuccesses = 0;
      state.circuit.lastFailureTimeMs = now;

      if (status === 'timeout') {
        state.circuit.totalTimeouts++;
      } else if (status === 'error') {
        state.circuit.totalErrors++;
      } else {
        state.circuit.total5xxErrors++;
      }

      const threshold =
        typeof status === 'number'
          ? config.consecutive5xxThreshold
          : config.consecutiveErrorThreshold;

      if (state.circuit.state === 'HALF_OPEN') {
        // Immediate re-trip on failure during recovery probe
        this.tripCircuitToOpen(normalizedHost, state);
      } else if (
        state.circuit.state === 'CLOSED' &&
        state.circuit.consecutiveFailures >= threshold
      ) {
        this.tripCircuitToOpen(normalizedHost, state);
      }
    } else {
      // 2xx, 3xx, 4xx responses represent a healthy/responsive target application
      state.circuit.consecutiveFailures = 0;

      if (state.circuit.state === 'HALF_OPEN') {
        state.circuit.consecutiveSuccesses++;
        if (state.circuit.consecutiveSuccesses >= config.halfOpenSuccessThreshold) {
          state.circuit.state = 'CLOSED';
          state.circuit.lastStateChangeTimeMs = now;
        }
      }
    }
  }

  private tripCircuitToOpen(host: string, state: HostExecutionState): void {
    state.circuit.state = 'OPEN';
    state.circuit.lastStateChangeTimeMs = Date.now();
    state.circuit.trippedCount++;

    // Immediately drain and reject all queued tasks for this host
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }

    const rejectionError = new TargetInstabilityError(host, 'OPEN');
    const drained = state.queue.splice(0, state.queue.length);
    for (const item of drained) {
      state.totalRejected++;
      item.reject(rejectionError);
    }
  }

  public getHostStats(host: string): TargetExecutionStats {
    const normalizedHost = host.toLowerCase().trim();
    const state = this.hostStates.get(normalizedHost);
    const circuitHealth = this.getCircuitStats(normalizedHost);

    return {
      activeCount: state?.activeCount ?? 0,
      queuedCount: state?.queue.length ?? 0,
      totalCompleted: state?.totalCompleted ?? 0,
      totalRejected: state?.totalRejected ?? 0,
      circuitState: circuitHealth.state,
      circuitHealth
    };
  }

  public async execute<T>(host: string, task: () => Promise<T>): Promise<T> {
    const normalizedHost = host.toLowerCase().trim();
    const state = this.getOrCreateHostState(normalizedHost);

    // Circuit Breaker Gate: Reject immediately if circuit is OPEN
    if (this.isCircuitOpen(normalizedHost)) {
      state.totalRejected++;
      throw new TargetInstabilityError(normalizedHost, 'OPEN');
    }

    const quota = this.hostQuotas.get(normalizedHost) ?? this.defaultQuota;
    const maxQueue = quota.maxQueueDepth ?? 500;

    if (state.queue.length >= maxQueue) {
      state.totalRejected++;
      throw new Error(`Execution queue for host ${normalizedHost} is full (max: ${maxQueue})`);
    }

    return new Promise<T>((resolve, reject) => {
      const queueItem: QueuedTask<unknown> = {
        task: task as () => Promise<unknown>,
        resolve: resolve as (val: unknown) => void,
        reject,
        enqueuedAt: Date.now()
      };

      state.queue.push(queueItem);
      this.drainQueue(normalizedHost);
    });
  }

  private drainQueue(host: string): void {
    const state = this.hostStates.get(host);
    if (!state || state.queue.length === 0) {
      return;
    }

    // Check circuit breaker before dispatching
    if (this.isCircuitOpen(host)) {
      return;
    }

    const quota = this.hostQuotas.get(host) ?? this.defaultQuota;
    const minIntervalMs = quota.requestsPerSecond > 0 ? 1000 / quota.requestsPerSecond : 0;

    // Check concurrency ceiling
    if (state.activeCount >= quota.maxConcurrency) {
      return;
    }

    // Check rate limiter delay
    const now = Date.now();
    const timeSinceLast = now - state.lastDispatchTimeMs;
    const delayNeeded = Math.max(0, minIntervalMs - timeSinceLast);

    if (delayNeeded > 0) {
      if (!state.timer) {
        state.timer = setTimeout(() => {
          if (state) {
            state.timer = null;
          }
          this.drainQueue(host);
        }, delayNeeded);
      }
      return;
    }

    // Ready to dispatch
    const nextItem = state.queue.shift();
    if (!nextItem) {
      return;
    }

    state.activeCount++;
    state.lastDispatchTimeMs = Date.now();

    // Execute task
    nextItem
      .task()
      .then((val) => {
        nextItem.resolve(val);
      })
      .catch((err: unknown) => {
        // If error indicates connection refusal / timeout, record target error
        if (err instanceof Error) {
          const msg = err.message.toLowerCase();
          if (
            msg.includes('econnrefused') ||
            msg.includes('etimedout') ||
            msg.includes('network error') ||
            msg.includes('timeout')
          ) {
            this.recordTargetResponse(host, 'timeout');
          }
        }
        nextItem.reject(err);
      })
      .finally(() => {
        state.activeCount--;
        state.totalCompleted++;
        this.drainQueue(host);
      });

    // If concurrency permits more, try dispatching next immediately (or scheduling)
    if (state.activeCount < quota.maxConcurrency && state.queue.length > 0) {
      this.drainQueue(host);
    }
  }

  public clear(): void {
    for (const state of this.hostStates.values()) {
      if (state.timer) {
        clearTimeout(state.timer);
      }
      for (const item of state.queue) {
        item.reject(new Error('TargetExecutionCoordinator cleared'));
      }
      state.queue = [];
      state.activeCount = 0;
      state.circuit.state = 'CLOSED';
      state.circuit.consecutiveFailures = 0;
      state.circuit.consecutiveSuccesses = 0;
    }
    this.hostStates.clear();
    this.hostQuotas.clear();
  }
}
