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
