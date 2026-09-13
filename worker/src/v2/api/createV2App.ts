import express, { type Express } from 'express';
import cors, { type CorsOptions } from 'cors';
import { V2CompositionRoot } from './V2CompositionRoot.js';
import { createV2Router } from './routes/v2Routes.js';
import { v2ErrorHandler } from './V2ErrorHandler.js';
import { createV2AuthMiddleware, type V2AuthOptions } from './middleware/v2AuthMiddleware.js';

export const DEFAULT_V2_HOST = '127.0.0.1';

export interface V2AppOptions extends V2AuthOptions {
  readonly allowedOrigins?: readonly string[];
}

export const DEFAULT_ALLOWED_ORIGINS: readonly string[] = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:4000',
  'http://127.0.0.1:4000'
];

export function buildCorsOptions(customOrigins?: readonly string[]): CorsOptions {
  const envOrigins = process.env.FIXGUARD_ALLOWED_ORIGINS
    ? process.env.FIXGUARD_ALLOWED_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
    : [];
  const allowed = new Set([...DEFAULT_ALLOWED_ORIGINS, ...(customOrigins ?? []), ...envOrigins]);

  return {
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server, curl, non-browser smoke tests)
      if (!origin || allowed.has(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Origin '${origin}' not allowed by FixGuard CORS security policy`));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
  };
}

/**
 * Creates and configures a dedicated Express 5 application instance for FixGuard V2.
 *
 * Mounts standard JSON body parsing, strict local CORS origin whitelisting,
 * Bearer token authentication middleware across all `/api/v2` routes,
 * the isolated V2 routing tree under `/api/v2`, and registers the centralized domain error handler.
 */
export function createV2App(root?: V2CompositionRoot, options?: V2AppOptions): Express {
  const compositionRoot = root ?? V2CompositionRoot.createDefault();
  const app = express();

  app.use(cors(buildCorsOptions(options?.allowedOrigins)));
  app.use(express.json());
  app.use(
    '/api/v2',
    createV2AuthMiddleware({ apiSecret: options?.apiSecret }),
    createV2Router(compositionRoot)
  );
  app.use(v2ErrorHandler);

  return app;
}

