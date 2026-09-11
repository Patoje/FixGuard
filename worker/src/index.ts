import express, { type Request, type Response } from 'express';
import cors from 'cors';
import { V2CompositionRoot } from './v2/api/V2CompositionRoot.js';
import { createV2Router } from './v2/api/routes/v2Routes.js';
import { v2ErrorHandler } from './v2/api/V2ErrorHandler.js';

/**
 * FixGuard Server Bootstrap (Milestone 63)
 *
 * Dedicated host for FixGuard V2 API Gateway (/api/v2).
 * Legacy V1 monolith endpoints are formally decommissioned and return HTTP 410 Gone.
 */
const app = express();

// Standard middleware
app.use(cors());
app.use(express.json());

// Health & Info endpoints
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({
    status: 'ok',
    apiVersion: 'v2',
    v1Status: 'decommissioned'
  });
});

app.get('/', (_req: Request, res: Response) => {
  res.status(200).json({
    name: 'FixGuard API Gateway',
    version: 'v2',
    v1Status: 'decommissioned',
    docs: '/api/v2'
  });
});

// Containment: Intercept and deprecate all legacy V1 routes with HTTP 410 Gone
const decommissionedHandler = (_req: Request, res: Response) => {
  res.status(410).json({
    error: 'Gone',
    message: 'Legacy FixGuard V1 endpoint has been decommissioned. Please use FixGuard V2 at /api/v2.'
  });
};

app.use(['/api/scan', '/api/scans', '/api/attack'], decommissionedHandler);

// Mount Canonical FixGuard V2 Routing Tree
const compositionRoot = V2CompositionRoot.createDefault();
app.use('/api/v2', createV2Router(compositionRoot));

// Centralized V2 Error Shield (information disclosure protection)
app.use(v2ErrorHandler);

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 4000;

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[+] FixGuard V2 API Gateway listening on http://localhost:${PORT}/api/v2`);
    console.log(`[!] Legacy V1 Monolith endpoints decommissioned (HTTP 410 Gone)`);
  });
}

export { app };
