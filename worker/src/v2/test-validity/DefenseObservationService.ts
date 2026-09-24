/**
 * Passive DefenseObservation producer — header/status/challenge/timing signals.
 * OBSERVED only. Does not judge vulnerability presence.
 */

import { createHash } from 'node:crypto';
import {
  TEST_VALIDITY_CONTRACT_VERSION,
  type DefenseControlKind,
  type DefenseObservation,
  type DefenseSignalSource,
  type HttpResponseDefenseSignals,
} from './TestValidityContracts.js';

const WAF_HEADER_NAMES = new Set([
  'cf-ray',
  'cf-mitigated',
  'x-sucuri-id',
  'x-sucuri-cache',
  'x-akamai-request-id',
  'x-azure-ref',
  'x-iinfo',
  'x-denied-reason',
  'x-firewall-block',
]);

const CDN_HEADER_NAMES = new Set([
  'cf-cache-status',
  'x-cache',
  'x-cdn',
  'x-amz-cf-id',
  'via',
  'server-timing',
]);

const BOT_CHALLENGE_BODY =
  /vercel\s*security\s*checkpoint|attention\s+required|enable\s+javascript|captcha|bot\s+detection|just\s+a\s+moment|cf-browser-verification|challenge-platform|_cf_chl/i;

const RATE_LIMIT_BODY = /rate\s*limit|too\s+many\s+requests|retry\s+later|slow\s+down/i;

function sha8(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 8);
}

function normalizeHeaderNames(
  signals: HttpResponseDefenseSignals
): readonly string[] {
  const fromNames = (signals.headerNames ?? []).map((n) => n.toLowerCase());
  const fromValues = Object.keys(signals.headerValues ?? {}).map((n) =>
    n.toLowerCase()
  );
  return Object.freeze([...new Set([...fromNames, ...fromValues])]);
}

function headerValue(
  signals: HttpResponseDefenseSignals,
  name: string
): string | undefined {
  const values = signals.headerValues;
  if (!values) return undefined;
  const direct = values[name] ?? values[name.toLowerCase()];
  if (typeof direct === 'string') return direct;
  for (const [k, v] of Object.entries(values)) {
    if (k.toLowerCase() === name.toLowerCase() && typeof v === 'string') {
      return v;
    }
  }
  return undefined;
}

function observation(args: {
  readonly prefix: string;
  readonly controlKind: DefenseControlKind;
  readonly signalSource: DefenseSignalSource;
  readonly reasonCode: string;
  readonly observedAt: string;
  readonly targetHost?: string;
  readonly evidenceSnippet?: string;
}): DefenseObservation {
  const idSeed = `${args.prefix}:${args.controlKind}:${args.reasonCode}:${args.signalSource}`;
  return Object.freeze({
    contractVersion: TEST_VALIDITY_CONTRACT_VERSION,
    kind: 'defense_observation' as const,
    observationId: `def_${sha8(idSeed)}`,
    controlKind: args.controlKind,
    signalSource: args.signalSource,
    reasonCode: args.reasonCode,
    observedAt: args.observedAt,
    ...(args.targetHost ? { targetHost: args.targetHost } : {}),
    ...(args.evidenceSnippet
      ? { evidenceSnippet: args.evidenceSnippet.slice(0, 120) }
      : {}),
  });
}

/**
 * Derive DefenseObservations from a single HTTP response's safe facets.
 * Deduplicates by reasonCode within one response.
 */
export function observeDefensesFromHttpResponse(
  signals: HttpResponseDefenseSignals,
  options?: {
    readonly observedAt?: string;
    readonly observationIdPrefix?: string;
  }
): readonly DefenseObservation[] {
  const observedAt = options?.observedAt ?? new Date().toISOString();
  const prefix = options?.observationIdPrefix ?? 'http';
  const found: DefenseObservation[] = [];
  const seen = new Set<string>();

  const push = (obs: DefenseObservation): void => {
    if (seen.has(obs.reasonCode)) return;
    seen.add(obs.reasonCode);
    found.push(obs);
  };

  const names = normalizeHeaderNames(signals);
  const body = signals.bodyExcerpt ?? '';
  const status = signals.statusCode;
  const host = signals.targetHost;

  for (const name of names) {
    if (WAF_HEADER_NAMES.has(name)) {
      push(
        observation({
          prefix,
          controlKind: 'waf',
          signalSource: 'header',
          reasonCode: `waf_header_${name.replace(/[^a-z0-9]+/g, '_')}`,
          observedAt,
          targetHost: host,
          evidenceSnippet: headerValue(signals, name) ?? name,
        })
      );
    }
    if (CDN_HEADER_NAMES.has(name)) {
      push(
        observation({
          prefix,
          controlKind: 'cdn',
          signalSource: 'header',
          reasonCode: `cdn_header_${name.replace(/[^a-z0-9]+/g, '_')}`,
          observedAt,
          targetHost: host,
          evidenceSnippet: name,
        })
      );
    }
    if (name === 'x-vercel-id' || name === 'x-vercel-cache') {
      push(
        observation({
          prefix,
          controlKind: 'cdn',
          signalSource: 'header',
          reasonCode: 'cdn_vercel_edge',
          observedAt,
          targetHost: host,
          evidenceSnippet: name,
        })
      );
    }
  }

  const server = headerValue(signals, 'server')?.toLowerCase() ?? '';
  if (
    /cloudflare|akamai|sucuri|imperva|incapsula|aws.?waf|mod_security|barracuda/.test(
      server
    )
  ) {
    push(
      observation({
        prefix,
        controlKind: 'waf',
        signalSource: 'header',
        reasonCode: 'waf_server_fingerprint',
        observedAt,
        targetHost: host,
        evidenceSnippet: server.slice(0, 80),
      })
    );
  }

  if (status === 429) {
    push(
      observation({
        prefix,
        controlKind: 'rate_limit',
        signalSource: 'status',
        reasonCode: 'rate_limit_status_429',
        observedAt,
        targetHost: host,
      })
    );
  }

  if (status === 403 || status === 503) {
    if (BOT_CHALLENGE_BODY.test(body) || /cf-ray|challenge/.test(names.join(','))) {
      push(
        observation({
          prefix,
          controlKind: 'bot',
          signalSource: status === 403 ? 'status' : 'challenge_body',
          reasonCode: 'bot_or_waf_challenge_status',
          observedAt,
          targetHost: host,
          evidenceSnippet: body.slice(0, 80),
        })
      );
    }
  }

  if (BOT_CHALLENGE_BODY.test(body)) {
    push(
      observation({
        prefix,
        controlKind: 'bot',
        signalSource: 'challenge_body',
        reasonCode: 'bot_challenge_body',
        observedAt,
        targetHost: host,
        evidenceSnippet: body.slice(0, 80),
      })
    );
  }

  if (RATE_LIMIT_BODY.test(body) || (signals.errorSignals ?? []).includes('rate_limit_like')) {
    push(
      observation({
        prefix,
        controlKind: 'rate_limit',
        signalSource: (signals.errorSignals ?? []).includes('rate_limit_like')
          ? 'error_signal'
          : 'challenge_body',
        reasonCode: 'rate_limit_signal',
        observedAt,
        targetHost: host,
      })
    );
  }

  if (
    typeof signals.responseTimeMs === 'number' &&
    signals.responseTimeMs >= 8_000 &&
    (status === 403 || status === 429 || status === 503)
  ) {
    push(
      observation({
        prefix,
        controlKind: 'unknown',
        signalSource: 'timing',
        reasonCode: 'slow_block_timing',
        observedAt,
        targetHost: host,
      })
    );
  }

  return Object.freeze(found);
}

export function isBlockingDefense(obs: DefenseObservation): boolean {
  return (
    obs.controlKind === 'waf' ||
    obs.controlKind === 'bot' ||
    obs.controlKind === 'rate_limit' ||
    obs.controlKind === 'auth_gateway'
  );
}
