/**
 * FixGuard V2 — API Layer Error Types
 *
 * Lightweight, closed error definitions for the HTTP gateway perimeter.
 */

export class ApiValidationError extends Error {
  constructor(
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ApiValidationError';
  }
}

export class UnauthorizedGatewayError extends Error {
  constructor(
    message: string,
    public readonly reasonCode?: string
  ) {
    super(message);
    this.name = 'UnauthorizedGatewayError';
  }
}

export class UnavailableToolsError extends Error {
  constructor(
    message: string,
    public readonly missingTools: readonly string[],
    public readonly reasonCode: string = 'unavailable_tools'
  ) {
    super(message);
    this.name = 'UnavailableToolsError';
  }
}

export class ConcurrencyLimitExceededError extends Error {
  constructor(
    message: string = 'Maximum concurrent orchestrated assessments limit reached',
    public readonly reasonCode: string = 'concurrency_limit_exceeded'
  ) {
    super(message);
    this.name = 'ConcurrencyLimitExceededError';
  }
}

/**
 * Fail-closed per-target cooldown, not a bot-detection workaround: it
 * exists so FixGuard's own repeated full-pipeline runs against the same
 * domain in a short window don't look like abusive traffic volume to the
 * target's own WAF/bot-protection. Overridable via
 * config.skipCooldown — the operator's own call.
 */
export class TargetCooldownActiveError extends Error {
  constructor(
    message: string,
    public readonly retryAfterMs: number,
    public readonly reasonCode: string = 'target_cooldown_active'
  ) {
    super(message);
    this.name = 'TargetCooldownActiveError';
  }
}

