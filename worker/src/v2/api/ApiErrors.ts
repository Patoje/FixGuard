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

