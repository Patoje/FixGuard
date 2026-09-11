import type { Request, Response, NextFunction } from 'express';
import { establishVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { UnauthorizedGatewayError, ApiValidationError } from '../ApiErrors.js';

/**
 * AuthorizationController
 *
 * Enforces Runtime-Branded Authorization (ADR-001) at the HTTP perimeter boundary.
 * Invokes establishVerifiedAuthorizationDecision() directly on the incoming request payload,
 * minting the in-memory WeakSet brand before authorization artifacts travel into internal layers.
 */
export class AuthorizationController {
  public establishDecision = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        throw new ApiValidationError('Establishment request body must be a non-empty object');
      }

      const evaluatedAt = new Date().toISOString();
      const result = establishVerifiedAuthorizationDecision(req.body, evaluatedAt);

      if (result.status === 'failed') {
        throw new UnauthorizedGatewayError(result.safeMessage, result.reasonCode);
      }

      res.status(201).json({
        status: 'established',
        reasonCode: result.reasonCode,
        decision: result.decision
      });
    } catch (err) {
      next(err);
    }
  };
}
