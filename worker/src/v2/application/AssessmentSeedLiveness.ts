/**
 * Phase D1 / W1 — Seed liveness classification (authorized GET probes).
 *
 * Scope/egress validation stays network-free in AssessmentSeedValidation.
 * This module classifies OBSERVED probe responses and filters dead/soft-404
 * seeds out of the planificable set without aborting the assessment.
 */

import type { IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import {
  isHtmlShellBodySignal,
  looksLikeOpaqueSpaOrCartShellPath,
} from '../detection/DetectionTargetBridge.js';

export type SeedLivenessClass =
  | 'alive'
  | 'soft_404'
  | 'http_404'
  | 'egress_denied'
  | 'inconclusive';

export type SeedLivenessResult = Readonly<{
  readonly seedUrl: string;
  readonly liveness: SeedLivenessClass;
  readonly statusCode?: number;
  readonly contentType?: string;
}>;

/**
 * Pure classifier from OBSERVED probe facets. Account/order HTML pages that
 * are not opaque SPA catch-alls remain `alive`.
 */
export function classifySeedLiveness(input: {
  readonly seedUrl: string;
  readonly statusCode?: number;
  readonly contentType?: string;
  readonly bodyText?: string;
  readonly probeFailed?: boolean;
  readonly egressDenied?: boolean;
}): SeedLivenessClass {
  if (input.egressDenied === true) {
    return 'egress_denied';
  }
  if (input.probeFailed === true) {
    return 'inconclusive';
  }
  const status = input.statusCode;
  if (typeof status !== 'number') {
    return 'inconclusive';
  }
  if (status === 404 || status === 410) {
    return 'http_404';
  }
  if (status >= 500) {
    return 'inconclusive';
  }
  // Auth challenge / forbidden still proves a live boundary resource.
  if (status === 401 || status === 403) {
    return 'alive';
  }
  if (status >= 400 && status < 500) {
    return 'inconclusive';
  }

  const html = isHtmlShellBodySignal({
    contentType: input.contentType,
    sanitizedSnippet: (input.bodyText ?? '').slice(0, 512),
  });
  if (html && looksLikeOpaqueSpaOrCartShellPath(input.seedUrl)) {
    return 'soft_404';
  }
  return 'alive';
}

export function isPlanificableSeedLiveness(liveness: SeedLivenessClass): boolean {
  return liveness === 'alive';
}

/**
 * Probe validated seed URLs (read-only GET) and retain only planificable ones.
 * Failures / soft-404 / http-404 are dropped — never abort the whole assessment.
 */
export async function filterSeedsByLiveness(input: {
  readonly seedUrls: readonly string[];
  readonly transport: IdorHttpProbeTransport;
  readonly timeoutMs?: number;
}): Promise<{
  readonly liveSeedUrls: readonly string[];
  readonly results: readonly SeedLivenessResult[];
}> {
  const results: SeedLivenessResult[] = [];
  const live: string[] = [];
  const timeoutMs =
    typeof input.timeoutMs === 'number' && input.timeoutMs > 0
      ? Math.min(input.timeoutMs, 8000)
      : 4000;

  for (const seedUrl of input.seedUrls) {
    let liveness: SeedLivenessClass;
    let statusCode: number | undefined;
    let contentType: string | undefined;
    try {
      const response = await input.transport({
        url: seedUrl,
        method: 'GET',
        headers: {
          accept: 'application/json, text/html;q=0.9, */*;q=0.8',
          'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
        },
        timeoutMs,
      });
      statusCode = response.statusCode;
      contentType = response.headers['content-type'];
      liveness = classifySeedLiveness({
        seedUrl,
        statusCode: response.statusCode,
        contentType,
        bodyText: response.bodyText,
      });
    } catch {
      liveness = 'inconclusive';
    }
    results.push(
      Object.freeze({
        seedUrl,
        liveness,
        ...(typeof statusCode === 'number' ? { statusCode } : {}),
        ...(contentType ? { contentType } : {}),
      })
    );
    if (isPlanificableSeedLiveness(liveness)) {
      live.push(seedUrl);
    }
  }

  return {
    liveSeedUrls: Object.freeze(live),
    results: Object.freeze(results),
  };
}
