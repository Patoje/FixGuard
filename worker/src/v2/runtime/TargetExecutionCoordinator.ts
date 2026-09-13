/**
 * Milestone F3 — Shared Target Concurrency & Rate-Limit Coordinator
 *
 * Coordinates outbound requests across concurrent operations targeting the same host.
 * Enforces:
 * 1. Global per-host rate limiter (requests/sec).
 * 2. Concurrency ceiling per host (max concurrent active probes/processes).
 * 3. Queue depth limits to prevent unbounded memory growth.
 */

import type {
  TargetQuotaConfig,
  TargetExecutionStats
} from './TargetExecutionCoordinatorContracts.js';

interface QueuedTask<T> {
  readonly task: () => Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason?: unknown) => void;
  readonly enqueuedAt: number;
}

interface HostExecutionState {
  activeCount: number;
  lastDispatchTimeMs: number;
  timer: NodeJS.Timeout | null;
  // Use unknown for generic storage in array, cast safely in runner
  queue: Array<QueuedTask<unknown>>;
  totalCompleted: number;
  totalRejected: number;
}

export class TargetExecutionCoordinator {
  private readonly defaultQuota: TargetQuotaConfig;
  private readonly hostQuotas = new Map<string, TargetQuotaConfig>();
  private readonly hostStates = new Map<string, HostExecutionState>();

  constructor(defaultQuota?: Partial<TargetQuotaConfig>) {
    this.defaultQuota = {
      requestsPerSecond: defaultQuota?.requestsPerSecond ?? 10,
      maxConcurrency: defaultQuota?.maxConcurrency ?? 3,
      maxQueueDepth: defaultQuota?.maxQueueDepth ?? 500
    };
  }

  public setHostQuota(host: string, config: TargetQuotaConfig): void {
    const normalizedHost = host.toLowerCase().trim();
    this.hostQuotas.set(normalizedHost, config);
  }

  public getHostStats(host: string): TargetExecutionStats {
    const normalizedHost = host.toLowerCase().trim();
    const state = this.hostStates.get(normalizedHost);
    return {
      activeCount: state?.activeCount ?? 0,
      queuedCount: state?.queue.length ?? 0,
      totalCompleted: state?.totalCompleted ?? 0,
      totalRejected: state?.totalRejected ?? 0
    };
  }

  public async execute<T>(host: string, task: () => Promise<T>): Promise<T> {
    const normalizedHost = host.toLowerCase().trim();
    const quota = this.hostQuotas.get(normalizedHost) ?? this.defaultQuota;
    const maxQueue = quota.maxQueueDepth ?? 500;

    let state = this.hostStates.get(normalizedHost);
    if (!state) {
      state = {
        activeCount: 0,
        lastDispatchTimeMs: 0,
        timer: null,
        queue: [],
        totalCompleted: 0,
        totalRejected: 0
      };
      this.hostStates.set(normalizedHost, state);
    }

    if (state.queue.length >= maxQueue) {
      state.totalRejected++;
      throw new Error(`Execution queue for host ${normalizedHost} is full (max: ${maxQueue})`);
    }

    return new Promise<T>((resolve, reject) => {
      // Type-safe wrapper without any
      const queueItem: QueuedTask<unknown> = {
        task: task as () => Promise<unknown>,
        resolve: resolve as (val: unknown) => void,
        reject,
        enqueuedAt: Date.now()
      };

      state?.queue.push(queueItem);
      this.drainQueue(normalizedHost);
    });
  }

  private drainQueue(host: string): void {
    const state = this.hostStates.get(host);
    if (!state || state.queue.length === 0) {
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
    }
    this.hostStates.clear();
    this.hostQuotas.clear();
  }
}
