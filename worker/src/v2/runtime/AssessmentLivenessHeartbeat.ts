/**
 * FixGuard V2 — assessment / recon liveness heartbeat.
 *
 * Soft-touches orchestrated assessment status while long-running recon (and
 * similar pipeline work) is in flight so status GETs and the Stage 2 terminal
 * show movement. This is liveness signaling only — it must NOT reset or
 * weaken security / global execution timeouts.
 */

/** Canonical heartbeat interval for long-running orchestrated work. */
export const ASSESSMENT_HEARTBEAT_INTERVAL_MS = 7_000;

/** Status is considered alive if the last heartbeat is within this window. */
export const ASSESSMENT_HEARTBEAT_ALIVE_WINDOW_MS =
  ASSESSMENT_HEARTBEAT_INTERVAL_MS * 2;

export interface AssessmentHeartbeatHint {
  readonly stageHint?: string;
  readonly toolHint?: string;
}

export interface AssessmentHeartbeatTick {
  readonly at: string;
  readonly stageHint?: string;
  readonly toolHint?: string;
}

export interface AssessmentHeartbeatScheduleHandle {
  clear(): void;
}

export type AssessmentHeartbeatScheduler = (
  handler: () => void,
  intervalMs: number
) => AssessmentHeartbeatScheduleHandle;

const defaultScheduler: AssessmentHeartbeatScheduler = (handler, intervalMs) => {
  const id = setInterval(handler, intervalMs);
  if (typeof id.unref === 'function') {
    id.unref();
  }
  return {
    clear(): void {
      clearInterval(id);
    },
  };
};

export function isAssessmentHeartbeatAlive(
  lastHeartbeatAt: string | undefined,
  status: string,
  nowMs: number,
  aliveWindowMs: number = ASSESSMENT_HEARTBEAT_ALIVE_WINDOW_MS
): boolean {
  if (status !== 'running' && status !== 'pending') {
    return false;
  }
  if (typeof lastHeartbeatAt !== 'string' || lastHeartbeatAt.length === 0) {
    return false;
  }
  const parsed = Date.parse(lastHeartbeatAt);
  if (!Number.isFinite(parsed)) {
    return false;
  }
  return nowMs - parsed <= aliveWindowMs;
}

export function buildAssessmentHeartbeatState(
  tick: AssessmentHeartbeatTick
): {
  readonly lastHeartbeatAt: string;
  readonly stageHint?: string;
  readonly toolHint?: string;
} {
  return {
    lastHeartbeatAt: tick.at,
    ...(tick.stageHint !== undefined ? { stageHint: tick.stageHint } : {}),
    ...(tick.toolHint !== undefined ? { toolHint: tick.toolHint } : {}),
  };
}

/**
 * Periodic liveness emitter. Callers persist ticks onto assessment records /
 * status DTOs. Failures in `onTick` are swallowed so heartbeat never aborts
 * the pipeline.
 */
export class AssessmentLivenessHeartbeat {
  private handle: AssessmentHeartbeatScheduleHandle | null = null;
  private hint: AssessmentHeartbeatHint = {};
  private stopped = true;
  private readonly intervalMs: number;
  private readonly now: () => Date;
  private readonly schedule: AssessmentHeartbeatScheduler;
  private readonly onTick: (tick: AssessmentHeartbeatTick) => void | Promise<void>;

  constructor(
    onTick: (tick: AssessmentHeartbeatTick) => void | Promise<void>,
    options?: {
      readonly intervalMs?: number;
      readonly now?: () => Date;
      readonly schedule?: AssessmentHeartbeatScheduler;
    }
  ) {
    this.onTick = onTick;
    this.intervalMs = options?.intervalMs ?? ASSESSMENT_HEARTBEAT_INTERVAL_MS;
    this.now = options?.now ?? (() => new Date());
    this.schedule = options?.schedule ?? defaultScheduler;
  }

  public setHint(hint: AssessmentHeartbeatHint): void {
    this.hint = {
      ...(hint.stageHint !== undefined ? { stageHint: hint.stageHint } : {}),
      ...(hint.toolHint !== undefined ? { toolHint: hint.toolHint } : {}),
    };
  }

  public start(): void {
    if (!this.stopped && this.handle !== null) {
      return;
    }
    this.stopped = false;
    void this.emitTick();
    this.handle = this.schedule(() => {
      void this.emitTick();
    }, this.intervalMs);
  }

  public stop(): void {
    this.stopped = true;
    if (this.handle !== null) {
      this.handle.clear();
      this.handle = null;
    }
  }

  public getHint(): AssessmentHeartbeatHint {
    return this.hint;
  }

  private async emitTick(): Promise<void> {
    if (this.stopped) {
      return;
    }
    const tick: AssessmentHeartbeatTick = {
      at: this.now().toISOString(),
      ...(this.hint.stageHint !== undefined
        ? { stageHint: this.hint.stageHint }
        : {}),
      ...(this.hint.toolHint !== undefined ? { toolHint: this.hint.toolHint } : {}),
    };
    try {
      await this.onTick(tick);
    } catch {
      // Non-blocking: liveness must never take down the assessment pipeline.
    }
  }
}
