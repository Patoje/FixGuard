import express, { type Express } from 'express';
import cors from 'cors';
import { V2CompositionRoot } from './V2CompositionRoot.js';
import { createV2Router } from './routes/v2Routes.js';
import { v2ErrorHandler } from './V2ErrorHandler.js';

/**
 * Creates and configures a dedicated Express 5 application instance for FixGuard V2.
 *
 * Mounts standard JSON body parsing, CORS, the isolated V2 routing tree under `/api/v2`,
 * and registers the centralized domain error handler.
 */
export function createV2App(root?: V2CompositionRoot): Express {
  const compositionRoot = root ?? V2CompositionRoot.createDefault();
  const app = express();

  app.use(cors());
  app.use(express.json());
  app.use('/api/v2', createV2Router(compositionRoot));
  app.use(v2ErrorHandler);

  return app;
}
