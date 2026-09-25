/**
 * Etapa 2 · P3 — jsluice discovery adapter (discovery-only).
 * Parses JS for URLs / params / secret kinds. Secrets are redacted.
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { ProcessRunner } from '../../core/ProcessRunner.js';
import {
  runAdapterPreflight,
  extractHost,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import { isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import {
  JSLUICE_DISCOVERY_CONTRACT_VERSION,
  JSLUICE_DISCOVERY_NON_CLAIMS,
  type DiscoveredJsParameterObservation,
  type JsLuiceDiscoveryRequest,
  type JsLuiceDiscoveryResult,
  type JsLuiceDiscoveryTool,
} from './JsLuiceDiscoveryContracts.js';
import type { DiscoveredUrlObservation } from './UrlDiscoveryContracts.js';
import type { DiscoveredSecretObservation } from './SecretDiscoveryContracts.js';

/** Default budget for ranked JS mining (deep recon P1 — was effectively 6 in orchestrator). */
export const JSLUICE_MAX_TARGETS_DEFAULT = 16;

/** Soft cap on sourcemap surface probes per stage_4 root (discovery-only). */
export const SOURCEMAP_SURFACE_MAX_TARGETS_DEFAULT = 4;

const MAX_JS_TARGETS_DEFAULT = JSLUICE_MAX_TARGETS_DEFAULT;

/**
 * Rank JS assets for mining: app chunks > webpack/runtime > vendor/framework.
 * Higher score = higher priority. Used by selectJsLuiceTargets.
 */
export function scoreJsAssetForMining(url: string): number {
  let pathname = '';
  try {
    pathname = new URL(url).pathname.toLowerCase();
  } catch {
    return 0;
  }
  const file = pathname.split('/').pop() ?? pathname;

  // Explicit vendor / framework / polyfill — lowest priority
  if (
    /(?:^|\/)(?:vendor|framework|polyfills?)(?:[-.]|$)/i.test(file) ||
    /(?:^|\/)(?:vendor|framework|polyfills?)(?:\/|$)/i.test(pathname) ||
    /node_modules|react-dom|scheduler\.production/i.test(pathname)
  ) {
    return 10;
  }

  // Next.js app / pages router chunks — highest
  if (/\/_next\/static\/chunks\/(?:app|pages)\//i.test(pathname)) {
    return 100;
  }
  if (/(?:^|\/)(?:page|layout|template|loading|error|route)-/i.test(file)) {
    return 95;
  }
  if (/\/_next\/static\/chunks\/app[-_/]/i.test(pathname)) {
    return 90;
  }

  // Named app-ish chunks (exclude main-app which is often framework shell)
  if (/\/_next\/static\/chunks\//i.test(pathname) && !/main-app|webpack|polyfill/i.test(file)) {
    if (/^[0-9a-f]{4,}-/i.test(file) || /chunk/i.test(file)) {
      return 75;
    }
    return 70;
  }

  // Webpack runtime / main entry — medium (needed for chunk graph hints)
  if (/webpack|runtime|main[-.]|main-app/i.test(file)) {
    return 45;
  }

  // Generic *.js on origin
  if (/\.js$/i.test(pathname)) {
    return 40;
  }

  return 20;
}

function redactSecretValue(raw: string): string {
  if (raw.length <= 8) return '***';
  return `${raw.slice(0, 4)}…${raw.slice(-2)} (len=${raw.length})`;
}

function extractSecretValue(data: unknown): string {
  if (typeof data === 'string') return data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return '';
  for (const key of ['key', 'secret', 'token', 'value', 'password', 'api_key']) {
    const v = Reflect.get(data, key);
    if (typeof v === 'string' && v.length > 0) return v;
  }
  const first = Object.values(data as Record<string, unknown>).find(
    (v) => typeof v === 'string' && (v as string).length > 0
  );
  return typeof first === 'string' ? first : '';
}

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

export class JsLuiceAdapter implements JsLuiceDiscoveryTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  async discoverFromJavaScript(request: JsLuiceDiscoveryRequest): Promise<JsLuiceDiscoveryResult> {
    const rawTarget =
      typeof request.targetJsUrlOrPath === 'string' ? request.targetJsUrlOrPath.trim() : '';
    if (!rawTarget) {
      return {
        status: 'preflight_denied',
        contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
        targetJsUrlOrPath: rawTarget,
        reasonCode: 'target_invalid',
        reason: 'jsluice target must be a non-empty URL or filesystem path',
        explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const isRemote = isHttpUrl(rawTarget);
    if (isRemote) {
      const preflight = await runAdapterPreflight({
        target: rawTarget,
        targetKind: 'url',
        verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
        authorizedScopeGrant: request.authorizedScopeGrant,
        lineage: request.lineage,
        requiredPermissions: [
          'endpointDiscovery',
          'activeCrawling',
          'passiveRecon',
          'technologyFingerprinting',
        ],
        missingPermissionReason:
          'Scope grant does not permit JavaScript endpoint discovery',
        dnsResolver: this.dnsResolver,
      });
      if (!preflight.ok) {
        return {
          status: 'preflight_denied',
          contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
          targetJsUrlOrPath: rawTarget,
          reasonCode: preflight.reasonCode,
          reason: preflight.reason,
          explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
    }

    const timeoutMs = request.timeoutMs ?? 45_000;
    const resolveBase =
      typeof request.resolvePathsBase === 'string' && request.resolvePathsBase.trim().length > 0
        ? request.resolvePathsBase.trim()
        : isRemote
          ? rawTarget
          : undefined;

    const urlArgs = ['urls', '-u'];
    if (resolveBase) {
      urlArgs.push('-R', resolveBase);
    }
    urlArgs.push(rawTarget);

    const started = Date.now();
    let urlsOut;
    let secretsOut;
    try {
      urlsOut = await this.processRunner.execute({
        binary: 'jsluice',
        args: urlArgs,
        timeoutMs,
      });
      secretsOut = await this.processRunner.execute({
        binary: 'jsluice',
        args: ['secrets', rawTarget],
        timeoutMs,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (/ENOENT|not found|spawn jsluice/i.test(msg)) {
        return {
          status: 'tool_unavailable',
          contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
          targetJsUrlOrPath: rawTarget,
          reasonCode: 'jsluice_binary_missing',
          reason: 'jsluice binary is not installed or not on PATH',
          explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
          lineage: request.lineage,
        };
      }
      return {
        status: 'execution_failed',
        contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
        targetJsUrlOrPath: rawTarget,
        reasonCode: 'jsluice_execution_error',
        reason: msg,
        explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        durationMs: Date.now() - started,
      };
    }

    if (urlsOut.exitCode !== 0 && secretsOut.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
        targetJsUrlOrPath: rawTarget,
        reasonCode: 'jsluice_execution_failed',
        reason:
          urlsOut.stderr.trim() ||
          secretsOut.stderr.trim() ||
          `jsluice exited urls=${urlsOut.exitCode} secrets=${secretsOut.exitCode}`,
        explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: urlsOut.exitCode,
        stderr: [urlsOut.stderr, secretsOut.stderr].filter(Boolean).join('; '),
        durationMs: Date.now() - started,
      };
    }

    const grant = request.authorizedScopeGrant;
    const allowedDomains = (grant.boundaries.allowedDomains ?? []).map((d) =>
      d.trim().toLowerCase().replace(/\.$/, '')
    );
    const allowedHosts = (grant.boundaries.allowedHosts ?? []).map((h) =>
      h.trim().toLowerCase().replace(/\.$/, '')
    );
    const subjectDomain = grant.subject.domain?.trim().toLowerCase().replace(/\.$/, '');
    const subjectHost = grant.subject.host?.trim().toLowerCase().replace(/\.$/, '');
    const originHosts: string[] = [];
    for (const origin of grant.boundaries.allowedOrigins ?? []) {
      const h = extractHost(origin);
      if (h) originHosts.push(h);
    }

    const hostInScope = (host: string): boolean => {
      const h = host.trim().toLowerCase().replace(/\.$/, '');
      if (!h) return false;
      if (isInternalOrSsrfTarget(h)) return false;
      if (subjectHost && (h === subjectHost || h.endsWith(`.${subjectHost}`))) return true;
      if (subjectDomain && (h === subjectDomain || h.endsWith(`.${subjectDomain}`))) return true;
      if (allowedHosts.some((a) => h === a || h.endsWith(`.${a}`))) return true;
      if (allowedDomains.some((a) => h === a || h.endsWith(`.${a}`))) return true;
      if (originHosts.some((a) => h === a || h.endsWith(`.${a}`))) return true;
      return false;
    };

    const nowIso = new Date().toISOString();
    const urlObservations: DiscoveredUrlObservation[] = [];
    const parameterObservations: DiscoveredJsParameterObservation[] = [];
    const seenUrls = new Set<string>();
    const seenParams = new Set<string>();

    for (const line of urlsOut.stdout.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
      const urlRaw = Reflect.get(parsed, 'url');
      if (typeof urlRaw !== 'string' || urlRaw.trim().length === 0) continue;
      let absolute = urlRaw.trim();
      if (absolute.startsWith('/') && resolveBase) {
        try {
          absolute = new URL(absolute, resolveBase).toString();
        } catch {
          continue;
        }
      }
      if (!isHttpUrl(absolute)) continue;
      let host = '';
      let path = '/';
      let query: string | undefined;
      try {
        const u = new URL(absolute);
        host = u.hostname;
        path = u.pathname || '/';
        query = u.search ? u.search.slice(1) : undefined;
      } catch {
        continue;
      }
      if (!hostInScope(host)) continue;
      if (!seenUrls.has(absolute)) {
        seenUrls.add(absolute);
        urlObservations.push(
          Object.freeze({
            url: absolute,
            host,
            path,
            ...(query ? { query } : {}),
            sources: Object.freeze(['jsluice']),
            discoveredAt: nowIso,
            collectedAt: nowIso,
            freshness: 'live' as const,
            sourceReliability: 'direct_observation' as const,
          })
        );
      }

      const queryParams = Reflect.get(parsed, 'queryParams');
      const bodyParams = Reflect.get(parsed, 'bodyParams');
      const addParams = (arr: unknown, location: 'query' | 'body') => {
        if (!Array.isArray(arr)) return;
        for (const p of arr) {
          if (typeof p !== 'string' || p.trim().length === 0) continue;
          const name = p.trim();
          const key = `${absolute}|${location}|${name}`;
          if (seenParams.has(key)) continue;
          seenParams.add(key);
          parameterObservations.push(
            Object.freeze({
              sourceUrl: absolute,
              parameterName: name,
              location,
              discoveredAt: nowIso,
            })
          );
        }
      };
      addParams(queryParams, 'query');
      addParams(bodyParams, 'body');
    }

    const secretObservations: DiscoveredSecretObservation[] = [];
    for (const line of secretsOut.stdout.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        continue;
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
      const kind = Reflect.get(parsed, 'kind');
      const detectorName = typeof kind === 'string' && kind.length > 0 ? kind : 'jsluice_secret';
      const rawValue = extractSecretValue(Reflect.get(parsed, 'data'));
      if (!rawValue) continue;
      secretObservations.push(
        Object.freeze({
          locationUrl: rawTarget,
          detectorName: `jsluice:${detectorName}`,
          redactedSecret: redactSecretValue(rawValue),
          discoveredAt: nowIso,
          verified: false,
          collectedAt: nowIso,
          freshness: 'live' as const,
          sourceReliability: 'direct_observation' as const,
        })
      );
    }

    return {
      status: 'success',
      contractVersion: JSLUICE_DISCOVERY_CONTRACT_VERSION,
      targetJsUrlOrPath: rawTarget,
      urlObservations: Object.freeze(urlObservations),
      parameterObservations: Object.freeze(parameterObservations),
      secretObservations: Object.freeze(secretObservations),
      explicitNonClaims: JSLUICE_DISCOVERY_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: Date.now() - started,
    };
  }
}

export function selectJsLuiceTargets(args: {
  readonly inventoryUrls: readonly { readonly url: string }[];
  readonly maxTargets?: number;
  /** URLs already mined — excluded from selection (re-feed / multi-pass). */
  readonly excludeUrls?: readonly string[];
}): readonly string[] {
  const max =
    typeof args.maxTargets === 'number' && args.maxTargets > 0
      ? Math.floor(args.maxTargets)
      : MAX_JS_TARGETS_DEFAULT;
  const excluded = new Set(
    (args.excludeUrls ?? []).map((u) => u.trim()).filter((u) => u.length > 0)
  );
  const scored: { readonly url: string; readonly score: number }[] = [];
  const seen = new Set<string>();
  for (const item of args.inventoryUrls) {
    const url = typeof item.url === 'string' ? item.url.trim() : '';
    if (!url || seen.has(url) || excluded.has(url)) continue;
    try {
      const u = new URL(url);
      if (!/\.js(\?|$)/i.test(u.pathname) && !/\/_next\/static\/chunks\//i.test(u.pathname)) {
        continue;
      }
      seen.add(url);
      scored.push({ url, score: scoreJsAssetForMining(url) });
    } catch {
      continue;
    }
  }
  scored.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.url.localeCompare(b.url);
  });
  return Object.freeze(scored.slice(0, max).map((s) => s.url));
}
