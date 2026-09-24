/**
 * OOB callback / interactsh-poll ingest controller (P6 thin slice).
 * No secrets. Unknown canaries fail closed (recorded=false).
 */

import type { Request, Response, NextFunction } from 'express';
import {
  defaultOobCanaryManager,
} from '../../oob/OobCanaryManager.js';
import {
  ingestHttpCallback,
  ingestInteractshPollEvents,
  resolveOobReceiverStatus,
} from '../../oob/OobCallbackReceiver.js';

function readStringField(body: unknown, key: string): string | undefined {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const value = Reflect.get(body, key);
  return typeof value === 'string' ? value : undefined;
}

export class OobCallbackController {
  public getStatus = (_req: Request, res: Response, next: NextFunction): void => {
    try {
      res.status(200).json(resolveOobReceiverStatus());
    } catch (err) {
      next(err);
    }
  };

  public receiveCallback = (req: Request, res: Response, next: NextFunction): void => {
    try {
      const hostHeader = req.headers.host;
      const host = typeof hostHeader === 'string' ? hostHeader : undefined;
      const bodyText =
        typeof req.body === 'string'
          ? req.body
          : req.body && typeof req.body === 'object'
            ? JSON.stringify(req.body)
            : undefined;
      const canaryToken = readStringField(req.body, 'canaryToken');
      const result = ingestHttpCallback(defaultOobCanaryManager, {
        host,
        path: typeof req.path === 'string' ? req.path : undefined,
        ...(bodyText !== undefined ? { bodyText } : {}),
        ...(canaryToken !== undefined ? { canaryToken } : {}),
        remoteAddress:
          typeof req.ip === 'string'
            ? req.ip
            : typeof req.socket?.remoteAddress === 'string'
              ? req.socket.remoteAddress
              : undefined,
        httpMethod: typeof req.method === 'string' ? req.method : undefined,
      });
      res.status(result.recorded ? 202 : 404).json({
        contractVersion: 'fixguard-oob-receiver/v0',
        kind: 'oob_callback_ingest_result',
        recorded: result.recorded,
        canaryToken: result.canaryToken,
      });
    } catch (err) {
      next(err);
    }
  };

  public ingestPollEvents = (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        res.status(400).json({
          contractVersion: 'fixguard-oob-receiver/v0',
          kind: 'oob_poll_ingest_result',
          reasonCode: 'invalid_body',
        });
        return;
      }
      const keys = Object.keys(req.body).sort();
      if (keys.length !== 1 || keys[0] !== 'events') {
        res.status(400).json({
          contractVersion: 'fixguard-oob-receiver/v0',
          kind: 'oob_poll_ingest_result',
          reasonCode: 'exact_key_violation',
        });
        return;
      }
      const events = Reflect.get(req.body, 'events');
      const result = ingestInteractshPollEvents(defaultOobCanaryManager, events);
      res.status(202).json({
        contractVersion: 'fixguard-oob-receiver/v0',
        kind: 'oob_poll_ingest_result',
        accepted: result.accepted,
        rejected: result.rejected,
        recordedTokens: result.recordedTokens,
        receiver: resolveOobReceiverStatus(),
      });
    } catch (err) {
      next(err);
    }
  };
}
