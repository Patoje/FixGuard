/**
 * FixGuard V2 — assessment activity deadline (idle + hard max).
 *
 * Replaces a pure wall-clock kill with:
 * 1. Hard absolute max from pipeline start (safety ceiling — never removed).
 * 2. Activity idle window that soft-extends when pipeline stages progress or
 *    target session keep-alive succeeds.
 *
 * UI AssessmentLivenessHeartbeat (~7s) must NOT touch this deadline.
 */

/** Absolute safety ceiling from pipeline start. */
export const ASSESSMENT_HARD_MAX_MS = 60 * 60 * 1000; // 60 minutes

/**
 * Kill if no pipeline / keep-alive activity within this window.
 * Soft-extends on stage progress and successful target session keep-alive.
 */
export const ASSESSMENT_ACTIVITY_IDLE_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Back-compat alias: historical name for the absolute ceiling.
 * Prefer ASSESSMENT_HARD_MAX_MS in new code.
 */
export const ASSESSMENT_GLOBAL_TIMEOUT_MS = ASSESSMENT_HARD_MAX_MS;

export type AssessmentDeadlineBreach = 'assessment_hard_max' | 'assessment_activity_idle';

export interface AssessmentActivityDeadlineOptions {
  readonly hardMaxMs?: number;
  readonly idleMs?: number;
  readonly now?: () => number;
  readonly startedAtMs?: number;
}

export class AssessmentActivityDeadline {
  private readonly startedAtMs: number;
  private readonly hardMaxMs: number;
  private readonly idleMs: number;
  private readonly now: () => number;
  private lastActivityAtMs: number;

  constructor(options?: AssessmentActivityDeadlineOptions) {
    this.now = options?.now ?? (() => Date.now());
    this.startedAtMs = options?.startedAtMs ?? this.now();
    this.hardMaxMs =
      typeof options?.hardMaxMs === 'number' &&
      Number.isFinite(options.hardMaxMs) &&
      options.hardMaxMs > 0
        ? options.hardMaxMs
        : ASSESSMENT_HARD_MAX_MS;
    this.idleMs =
      typeof options?.idleMs === 'number' && Number.isFinite(options.idleMs) && options.idleMs > 0
        ? options.idleMs
        : ASSESSMENT_ACTIVITY_IDLE_MS;
    this.lastActivityAtMs = this.startedAtMs;
  }

  /** Soft-extend idle window (pipeline stage / keep-alive). Not for UI liveness. */
  public touch(): void {
    this.lastActivityAtMs = this.now();
  }

  public check(): AssessmentDeadlineBreach | null {
    const nowMs = this.now();
    if (nowMs - this.startedAtMs >= this.hardMaxMs) {
      return 'assessment_hard_max';
    }
    if (nowMs - this.lastActivityAtMs >= this.idleMs) {
      return 'assessment_activity_idle';
    }
    return null;
  }

  public getLastActivityAtMs(): number {
    return this.lastActivityAtMs;
  }

  public getStartedAtMs(): number {
    return this.startedAtMs;
  }
}

export interface AssessmentDeadlineMonitorHandle {
  clear(): void;
}

/**
 * Polls the activity deadline and rejects when hard max or idle is breached.
 */
export function startAssessmentDeadlineMonitor(
  deadline: AssessmentActivityDeadline,
  onBreach: (breach: AssessmentDeadlineBreach) => void,
  pollIntervalMs: number = 5_000
): AssessmentDeadlineMonitorHandle {
  const id = setInterval(() => {
    const breach = deadline.check();
    if (breach !== null) {
      onBreach(breach);
    }
  }, pollIntervalMs);
  if (typeof id.unref === 'function') {
    id.unref();
  }
  return {
    clear(): void {
      clearInterval(id);
    },
  };
}

export function deadlineBreachError(breach: AssessmentDeadlineBreach): Error {
  if (breach === 'assessment_hard_max') {
    const err = new Error(
      'Assessment exceeded absolute hard-max execution limit (safety ceiling)'
    );
    err.name = 'AssessmentTimeoutError';
    return err;
  }
  const err = new Error(
    'Assessment exceeded activity idle timeout (no pipeline / keep-alive progress)'
  );
  err.name = 'AssessmentTimeoutError';
  return err;
}

export function deadlineBreachReasonCode(breach: AssessmentDeadlineBreach): string {
  return breach;
}

export function deadlineBreachMessage(breach: AssessmentDeadlineBreach): string {
  if (breach === 'assessment_hard_max') {
    return 'Assessment absolute hard-max timeout exceeded';
  }
  return 'Assessment activity idle timeout exceeded';
}
