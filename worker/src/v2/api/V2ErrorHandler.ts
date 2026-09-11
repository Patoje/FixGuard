import type { Request, Response, NextFunction } from 'express';
import {
  PersistenceConflictError,
  SessionNotFoundError,
  RecordNotFoundError,
  RecordCorruptedError,
  StaleStateError
} from '../storage/StorageErrors.js';
import { ReportGenerationError } from '../reporting-boundary/DefensiveReportContracts.js';
import { RuntimeLifecycleError } from '../runtime/RuntimeLifecycleError.js';
import { ApiValidationError, UnauthorizedGatewayError } from './ApiErrors.js';

export interface SafeErrorResponseBody {
  readonly error: string;
  readonly message: string;
  readonly conflictKey?: string;
  readonly sessionId?: string;
  readonly recordId?: string;
  readonly reasonCode?: string;
  readonly details?: Record<string, unknown>;
}

/**
 * V2 Centralized Error Handler Middleware
 *
 * Catches all domain and infrastructure errors, maps them strictly to HTTP status codes,
 * and guarantees zero leakage of stack traces, SQL fragments, database topologies,
 * or raw internal state to external clients.
 */
export function v2ErrorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Prevent double sending if headers were already sent
  if (res.headersSent) {
    return;
  }

  // 1. PersistenceConflictError -> 409 Conflict
  if (err instanceof PersistenceConflictError) {
    const body: SafeErrorResponseBody = {
      error: 'Conflict',
      message: err.message,
      ...(err.conflictKey ? { conflictKey: err.conflictKey } : {})
    };
    res.status(409).json(body);
    return;
  }

  // 2. SessionNotFoundError -> 404 Not Found
  if (err instanceof SessionNotFoundError) {
    const body: SafeErrorResponseBody = {
      error: 'NotFound',
      message: err.message,
      ...(err.sessionId ? { sessionId: err.sessionId } : {})
    };
    res.status(404).json(body);
    return;
  }

  // 3. RecordNotFoundError -> 404 Not Found
  if (err instanceof RecordNotFoundError) {
    const body: SafeErrorResponseBody = {
      error: 'NotFound',
      message: err.message,
      ...(err.recordId ? { recordId: err.recordId } : {})
    };
    res.status(404).json(body);
    return;
  }

  // 4. RecordCorruptedError -> 403 Forbidden (Integrity failure)
  if (err instanceof RecordCorruptedError) {
    const body: SafeErrorResponseBody = {
      error: 'Forbidden',
      message: 'Integrity check failed: corrupted record detected',
      ...(err.recordId ? { recordId: err.recordId } : {})
    };
    res.status(403).json(body);
    return;
  }

  // 5. ReportGenerationError -> Domain-Specific 4xx / 5xx
  if (err instanceof ReportGenerationError) {
    switch (err.code) {
      case 'missing_operator_signature':
      case 'invalid_report_request':
      case 'report_generation_aborted_insufficient_substance': {
        const body: SafeErrorResponseBody = {
          error: err.code,
          message: err.message
        };
        res.status(400).json(body);
        return;
      }
      case 'report_generation_aborted_corrupted_candidate': {
        const body: SafeErrorResponseBody = {
          error: err.code,
          message: err.message
        };
        res.status(403).json(body);
        return;
      }
      case 'report_validation_failed':
      default: {
        const body: SafeErrorResponseBody = {
          error: 'InternalServerError',
          message: 'Defensive report failed final schema validation'
        };
        res.status(500).json(body);
        return;
      }
    }
  }

  // 6. ApiValidationError -> 400 Bad Request
  if (err instanceof ApiValidationError) {
    const body: SafeErrorResponseBody = {
      error: 'BadRequest',
      message: err.message,
      ...(err.details ? { details: err.details } : {})
    };
    res.status(400).json(body);
    return;
  }

  // 7. UnauthorizedGatewayError -> 403 Forbidden
  if (err instanceof UnauthorizedGatewayError) {
    const body: SafeErrorResponseBody = {
      error: 'Forbidden',
      message: err.message,
      ...(err.reasonCode ? { reasonCode: err.reasonCode } : {})
    };
    res.status(403).json(body);
    return;
  }

  // 8. RuntimeLifecycleError -> 409 Conflict
  if (err instanceof RuntimeLifecycleError) {
    const body: SafeErrorResponseBody = {
      error: 'Conflict',
      message: err.message
    };
    res.status(409).json(body);
    return;
  }

  // 9. Malformed JSON Body (SyntaxError from express.json parser)
  if (
    err instanceof SyntaxError &&
    typeof err === 'object' &&
    'status' in err &&
    (err as { status?: unknown }).status === 400
  ) {
    const body: SafeErrorResponseBody = {
      error: 'BadRequest',
      message: 'Malformed JSON payload in request body'
    };
    res.status(400).json(body);
    return;
  }

  // 10. StaleStateError -> 409 Conflict (Optimistic Concurrency Conflict)
  if (err instanceof StaleStateError) {
    const body: SafeErrorResponseBody = {
      error: 'Conflict',
      message: 'Assessment session state is stale due to a concurrent update',
      sessionId: err.sessionId
    };
    res.status(409).json(body);
    return;
  }

  // 11. Fallback / Unhandled / Infrastructure Errors -> 500 Internal Server Error
  // Strictly sanitize: NEVER leak stack traces, database terms, or file paths.
  const fallbackBody: SafeErrorResponseBody = {
    error: 'InternalServerError',
    message: 'An unexpected error occurred'
  };
  res.status(500).json(fallbackBody);
}
