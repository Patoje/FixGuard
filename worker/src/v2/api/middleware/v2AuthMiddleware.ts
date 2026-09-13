import type { Request, Response, NextFunction } from 'express';

export interface V2AuthOptions {
  /**
   * Pre-shared secret required in Authorization: Bearer <secret>
   * If omitted, falls back to process.env.FIXGUARD_API_SECRET
   */
  readonly apiSecret?: string;
}

/**
 * Creates an Express middleware that enforces Bearer token authentication across FixGuard V2 routes.
 *
 * Directives & Behavior:
 * - When an API secret is configured (via options or FIXGUARD_API_SECRET env):
 *   - Missing or non-Bearer Authorization header returns HTTP 401 Unauthorized.
 *   - Incorrect Bearer token returns HTTP 403 Forbidden.
 *   - Correct Bearer token invokes next().
 * - When in production (NODE_ENV === 'production') and no secret is configured:
 *   - Fails closed with HTTP 500 / 401 Configuration Error (zero unauthenticated exposure).
 * - When in dev/test (NODE_ENV !== 'production') and no secret is configured:
 *   - Permitted for local development and backwards-compatibility with unconfigured test runners.
 */
export function createV2AuthMiddleware(options?: V2AuthOptions) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const configuredSecret = options?.apiSecret ?? process.env.FIXGUARD_API_SECRET;

    if (!configuredSecret) {
      if (process.env.NODE_ENV === 'production') {
        res.status(500).json({
          error: 'ConfigurationError',
          message: 'FIXGUARD_API_SECRET is required in production environments but not configured.'
        });
        return;
      }
      // In dev/test without configured secret, bypass
      return next();
    }

    const authHeader = req.headers['authorization'];
    if (!authHeader || typeof authHeader !== 'string') {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Missing or invalid Authorization header. Expected Bearer token.'
      });
      return;
    }

    const match = authHeader.match(/^Bearer\s+(.+)$/i);
    if (!match || !match[1]) {
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Missing or invalid Authorization header. Expected Bearer token.'
      });
      return;
    }

    const token = match[1].trim();
    if (token !== configuredSecret) {
      res.status(403).json({
        error: 'Forbidden',
        message: 'Invalid API secret token.'
      });
      return;
    }

    next();
  };
}
