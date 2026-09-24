/**
 * Etapa 2 · F3 — wafw00f host cache (1× per host per process).
 * Discovery-only DefenseObservation producer. Never claims vulnerability.
 */

import type { ProcessRunner } from '../core/ProcessRunner.js';
import { TEST_VALIDITY_CONTRACT_VERSION, type DefenseObservation } from './TestValidityContracts.js';

export type Wafw00fCacheEntry =
  | {
      readonly status: 'observed';
      readonly observedAt: string;
      readonly defenses: readonly DefenseObservation[];
      readonly vendorHint?: string;
    }
  | {
      readonly status: 'unavailable' | 'failed' | 'none_detected';
      readonly observedAt: string;
      readonly reason: string;
    };

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Process-local 1×/host cache for wafw00f results.
 */
export class Wafw00fHostCache {
  private readonly cache = new Map<string, Wafw00fCacheEntry>();

  public get(host: string): Wafw00fCacheEntry | null {
    const key = normalizeHost(host);
    if (!key) return null;
    return this.cache.get(key) ?? null;
  }

  public set(host: string, entry: Wafw00fCacheEntry): void {
    const key = normalizeHost(host);
    if (!key) return;
    this.cache.set(key, entry);
  }

  public has(host: string): boolean {
    return this.get(host) !== null;
  }
}

export const wafw00fHostCache = new Wafw00fHostCache();

function parseVendorFromStdout(stdout: string): string | undefined {
  // Typical: "The site https://x.com is behind Cloudflare (Cloudflare Inc.) WAF."
  const m =
    /is behind\s+([A-Za-z0-9 ._-]+?)(?:\s+WAF|\s*\(|$)/i.exec(stdout) ??
    /WAF:\s*([A-Za-z0-9 ._-]+)/i.exec(stdout);
  if (!m || typeof m[1] !== 'string') return undefined;
  return m[1].trim().slice(0, 64);
}

/**
 * Run wafw00f once per host (cached). Fail-soft on missing binary.
 */
export async function observeWafWithWafw00f(args: {
  readonly host: string;
  readonly processRunner: ProcessRunner;
  readonly cache?: Wafw00fHostCache;
  readonly timeoutMs?: number;
  readonly binaryPath?: string;
}): Promise<Wafw00fCacheEntry> {
  const host = normalizeHost(args.host);
  const cache = args.cache ?? wafw00fHostCache;
  const existing = cache.get(host);
  if (existing) return existing;

  const now = new Date().toISOString();
  if (!host || /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)/i.test(host)) {
    const denied: Wafw00fCacheEntry = {
      status: 'failed',
      observedAt: now,
      reason: 'ssrf_target_blocked',
    };
    cache.set(host || 'invalid', denied);
    return denied;
  }

  const binary =
    args.binaryPath ??
    process.env.FIXGUARD_WAFW00F_BIN ??
    'wafw00f';
  const targetUrl = `https://${host}/`;

  try {
    const output = await args.processRunner.execute({
      binary,
      args: ['-a', '-v', targetUrl],
      timeoutMs: args.timeoutMs ?? 45_000,
    });

    if (output.exitCode !== 0 && !output.stdout.trim()) {
      const failed: Wafw00fCacheEntry = {
        status: output.stderr.match(/ENOENT|not found/i) ? 'unavailable' : 'failed',
        observedAt: now,
        reason: output.stderr.trim() || `wafw00f exit ${output.exitCode}`,
      };
      cache.set(host, failed);
      return failed;
    }

    const combined = `${output.stdout}\n${output.stderr}`;
    const vendor = parseVendorFromStdout(combined);
    const noWaf = /no\s+waf\s+detected|is not behind a waf/i.test(combined);

    if (noWaf && !vendor) {
      const none: Wafw00fCacheEntry = {
        status: 'none_detected',
        observedAt: now,
        reason: 'wafw00f_no_waf_detected',
      };
      cache.set(host, none);
      return none;
    }

    if (!vendor && !/waf/i.test(combined)) {
      const none: Wafw00fCacheEntry = {
        status: 'none_detected',
        observedAt: now,
        reason: 'wafw00f_inconclusive',
      };
      cache.set(host, none);
      return none;
    }

    const defense: DefenseObservation = Object.freeze({
      contractVersion: TEST_VALIDITY_CONTRACT_VERSION,
      kind: 'defense_observation',
      observationId: `def_wafw00f_${host.replace(/[^a-z0-9]/gi, '_').slice(0, 40)}`,
      controlKind: 'waf',
      signalSource: 'header',
      reasonCode: vendor
        ? `wafw00f_detected_${vendor.toLowerCase().replace(/[^a-z0-9]+/g, '_').slice(0, 40)}`
        : 'wafw00f_detected',
      observedAt: now,
      targetHost: host,
      evidenceSnippet: (vendor ?? 'waf detected').slice(0, 120),
    });

    const observed: Wafw00fCacheEntry = {
      status: 'observed',
      observedAt: now,
      defenses: Object.freeze([defense]),
      ...(vendor ? { vendorHint: vendor } : {}),
    };
    cache.set(host, observed);
    return observed;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const failed: Wafw00fCacheEntry = {
      status: /ENOENT|not found/i.test(msg) ? 'unavailable' : 'failed',
      observedAt: now,
      reason: msg.slice(0, 200),
    };
    cache.set(host, failed);
    return failed;
  }
}
