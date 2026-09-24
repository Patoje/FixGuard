/**
 * Minimal OOB callback / interactsh-poll ingest hook.
 *
 * Full interactsh self-host is deferred (FIXGUARD_OOB_MODE=deferred_self_host).
 * Working path: HTTP callback ingest + operator-fed poll events → OobCanaryManager.
 */

import type {
  OobCanaryManager,
  OobInboundInteraction,
  OobInteractionType,
} from './OobCanaryManager.js';

export type OobReceiverMode = 'http_callback' | 'interactsh_poll_ingest' | 'deferred_self_host';

export interface OobReceiverStatus {
  readonly contractVersion: 'fixguard-oob-receiver/v0';
  readonly kind: 'oob_receiver_status';
  readonly mode: OobReceiverMode;
  readonly callbackDomain: string;
  readonly selfHostDeferred: boolean;
  readonly note: string;
}

export interface InteractshPollEvent {
  readonly canaryToken: string;
  readonly interactionType: OobInteractionType;
  readonly remoteAddress?: string;
  readonly receivedAt?: string;
  readonly httpMethod?: string;
}

const CANARY_RE = /\b(fgc_[a-f0-9]{16,})\b/i;

function extractCanaryToken(sources: readonly string[]): string | null {
  for (const source of sources) {
    const match = CANARY_RE.exec(source);
    if (match?.[1]) {
      return match[1].toLowerCase().startsWith('fgc_')
        ? match[1]
        : match[1];
    }
  }
  return null;
}

/**
 * Resolve operating mode from env. Self-host interactsh remains deferred unless
 * FIXGUARD_OOB_CALLBACK_DOMAIN is set (HTTP callback path is live regardless).
 */
export function resolveOobReceiverStatus(): OobReceiverStatus {
  const callbackDomain =
    (typeof process.env.FIXGUARD_OOB_CALLBACK_DOMAIN === 'string' &&
    process.env.FIXGUARD_OOB_CALLBACK_DOMAIN.trim().length > 0
      ? process.env.FIXGUARD_OOB_CALLBACK_DOMAIN.trim()
      : null) ?? 'oob.fixguard.internal';
  const modeEnv = process.env.FIXGUARD_OOB_MODE?.trim().toLowerCase();
  const selfHostDeferred =
    modeEnv === 'deferred_self_host' ||
    modeEnv === 'interactsh_self_host_deferred' ||
    callbackDomain === 'oob.fixguard.internal';

  return {
    contractVersion: 'fixguard-oob-receiver/v0',
    kind: 'oob_receiver_status',
    mode: selfHostDeferred ? 'deferred_self_host' : 'http_callback',
    callbackDomain,
    selfHostDeferred,
    note: selfHostDeferred
      ? 'interactsh self-host deferred; use POST /api/v2/oob/callback or /api/v2/oob/ingest for canary hits'
      : 'HTTP callback receiver active for configured FIXGUARD_OOB_CALLBACK_DOMAIN',
  };
}

/**
 * Ingest an inbound HTTP callback. Canary may appear in Host, path, or body.
 */
export function ingestHttpCallback(
  manager: OobCanaryManager,
  args: {
    readonly host?: string;
    readonly path?: string;
    readonly bodyText?: string;
    readonly remoteAddress?: string;
    readonly httpMethod?: string;
    readonly receivedAt?: string;
    readonly canaryToken?: string;
  }
): { readonly recorded: boolean; readonly canaryToken: string | null } {
  const canaryToken =
    (typeof args.canaryToken === 'string' && args.canaryToken.startsWith('fgc_')
      ? args.canaryToken
      : null) ??
    extractCanaryToken([
      args.host ?? '',
      args.path ?? '',
      args.bodyText ?? '',
    ]);

  if (!canaryToken) {
    return { recorded: false, canaryToken: null };
  }

  const interaction: OobInboundInteraction = {
    canaryToken,
    interactionType: 'http_callback',
    ...(args.remoteAddress !== undefined ? { remoteAddress: args.remoteAddress } : {}),
    receivedAt: args.receivedAt ?? new Date().toISOString(),
    ...(args.httpMethod !== undefined ? { httpMethod: args.httpMethod } : {}),
  };

  return {
    recorded: manager.recordInteraction(interaction),
    canaryToken,
  };
}

/**
 * Operator / poll harness ingest for interactsh-lite style events.
 * Exact-key validation: only known fields accepted.
 */
export function ingestInteractshPollEvents(
  manager: OobCanaryManager,
  events: unknown
): {
  readonly accepted: number;
  readonly rejected: number;
  readonly recordedTokens: readonly string[];
} {
  if (!Array.isArray(events)) {
    return { accepted: 0, rejected: 0, recordedTokens: [] };
  }

  let accepted = 0;
  let rejected = 0;
  const recordedTokens: string[] = [];

  for (const raw of events) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      rejected += 1;
      continue;
    }
    const keys = Object.keys(raw).sort();
    const allowed = new Set([
      'canaryToken',
      'interactionType',
      'remoteAddress',
      'receivedAt',
      'httpMethod',
    ]);
    if (keys.some((k) => !allowed.has(k))) {
      rejected += 1;
      continue;
    }
    const canaryToken = Reflect.get(raw, 'canaryToken');
    const interactionType = Reflect.get(raw, 'interactionType');
    if (typeof canaryToken !== 'string' || !canaryToken.startsWith('fgc_')) {
      rejected += 1;
      continue;
    }
    if (interactionType !== 'http_callback' && interactionType !== 'dns_query') {
      rejected += 1;
      continue;
    }
    const remoteAddress = Reflect.get(raw, 'remoteAddress');
    const receivedAt = Reflect.get(raw, 'receivedAt');
    const httpMethod = Reflect.get(raw, 'httpMethod');
    if (remoteAddress !== undefined && typeof remoteAddress !== 'string') {
      rejected += 1;
      continue;
    }
    if (receivedAt !== undefined && typeof receivedAt !== 'string') {
      rejected += 1;
      continue;
    }
    if (httpMethod !== undefined && typeof httpMethod !== 'string') {
      rejected += 1;
      continue;
    }

    const interaction: OobInboundInteraction = {
      canaryToken,
      interactionType,
      ...(typeof remoteAddress === 'string' ? { remoteAddress } : {}),
      receivedAt: typeof receivedAt === 'string' ? receivedAt : new Date().toISOString(),
      ...(typeof httpMethod === 'string' ? { httpMethod } : {}),
    };

    if (manager.recordInteraction(interaction)) {
      accepted += 1;
      recordedTokens.push(canaryToken);
    } else {
      rejected += 1;
    }
  }

  return {
    accepted,
    rejected,
    recordedTokens: Object.freeze(recordedTokens),
  };
}
