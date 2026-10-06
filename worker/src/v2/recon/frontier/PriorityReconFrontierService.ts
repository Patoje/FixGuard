/**
 * FixGuard V2 — Priority Recon Frontier Service.
 *
 * Replaces naive FIFO crawl queues with an information-gain priority queue.
 *
 * Core capabilities:
 * 1. Structural Route Normalization: recognizes /api/users/123 as /api/users/{id}
 *    to prevent repetitive pagination and ID exhaustion from consuming request budgets.
 * 2. Deterministic Information-Gain Scoring: scores based on route novelty,
 *    parameter richness, API classification, authentication relevance, and source quality.
 * 3. Explainability: every prioritized candidate includes an interpretable justification.
 * 4. Bounded: 100% deterministic, zero network I/O, zero file I/O.
 */

import {
  type CrawlFrontierCandidate,
  type FrontierCandidateInput,
  type FrontierDiagnosticSummary,
  type FrontierPriorityTier,
} from './PriorityReconFrontierContracts.js';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_PATTERN = /^\d+$/;
const HEX_HASH_PATTERN = /^[0-9a-f]{16,64}$/i;

const API_PATH_REGEX = /^\/(?:api|rest|rpc|graphql|_next\/data|v[0-9]+)\b/i;
const AUTH_PATH_REGEX =
  /\/(?:auth|login|signin|signup|register|user|users|account|admin|session|settings|profile|token|oauth|oauth2|saml)\b/i;

const RESOURCE_COLLECTION_SEGMENTS = new Set([
  'users',
  'user',
  'accounts',
  'account',
  'items',
  'item',
  'orders',
  'order',
  'products',
  'product',
  'posts',
  'post',
  'articles',
  'article',
  'tenants',
  'tenant',
  'organizations',
  'org',
  'invoices',
  'invoice',
  'files',
  'file',
  'documents',
  'doc',
]);

export interface PriorityReconFrontierOptions {
  /** Maximum URLs allowed per structural pattern before de-prioritization/saturation. Default: 4 */
  readonly maxUrlsPerPattern?: number;
}

export class PriorityReconFrontierService {
  private readonly maxUrlsPerPattern: number;
  private readonly queue: CrawlFrontierCandidate[] = [];
  private readonly enqueuedUrls = new Set<string>();
  private readonly patternCounts = new Map<string, number>();
  private totalEnqueued = 0;
  private totalSelected = 0;
  private totalSkippedPatternSaturation = 0;
  private readonly selectedReasons: string[] = [];

  constructor(options?: PriorityReconFrontierOptions) {
    this.maxUrlsPerPattern = options?.maxUrlsPerPattern ?? 4;
  }

  /**
   * Normalizes a URL path into a structural route pattern.
   * Example: /api/v1/tenants/123/users/456 -> /api/v1/tenants/{id}/users/{id}
   */
  public static normalizeRoutePattern(path: string): string {
    const cleanPath = path.split('?')[0] || '/';
    const segments = cleanPath.split('/').filter((s) => s.length > 0);
    if (segments.length === 0) return '/';

    const normalized: string[] = [];
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i]!;
      const prevSeg = i > 0 ? segments[i - 1]!.toLowerCase() : '';

      if (UUID_PATTERN.test(seg)) {
        normalized.push('{uuid}');
      } else if (NUMERIC_ID_PATTERN.test(seg)) {
        normalized.push('{id}');
      } else if (HEX_HASH_PATTERN.test(seg)) {
        normalized.push('{hash}');
      } else if (RESOURCE_COLLECTION_SEGMENTS.has(prevSeg) && seg.length >= 2) {
        normalized.push('{slug}');
      } else {
        normalized.push(seg.toLowerCase());
      }
    }

    return '/' + normalized.join('/');
  }

  /**
   * Enqueues a candidate URL. Scores it deterministically and places it into the priority queue.
   * Returns true if enqueued, false if duplicate or saturated.
   */
  public enqueue(input: FrontierCandidateInput): boolean {
    if (this.enqueuedUrls.has(input.url)) {
      return false;
    }
    this.enqueuedUrls.add(input.url);

    const normalizedPattern = PriorityReconFrontierService.normalizeRoutePattern(input.path);
    const seenCount = this.patternCounts.get(normalizedPattern) ?? 0;
    this.patternCounts.set(normalizedPattern, seenCount + 1);

    if (seenCount >= this.maxUrlsPerPattern) {
      this.totalSkippedPatternSaturation++;
      // Pattern is saturated (e.g. 10th pagination link of /catalog?page=X).
      // Skip from active exploration to preserve crawl request budget for diverse routes.
      return false;
    }

    const parameterCount = input.query
      ? input.query.split('&').filter((p) => p.trim().length > 0).length
      : 0;

    const isApi = input.isApiHint === true || API_PATH_REGEX.test(input.path);
    const hasAuthRelevance = AUTH_PATH_REGEX.test(input.path);

    // Novelty calculation: first time seen = 1.0, drops with subsequent instances
    const novelty =
      seenCount === 0 ? 1.0 : seenCount === 1 ? 0.6 : seenCount === 2 ? 0.35 : 0.15;

    // Parameter score
    const paramScore =
      parameterCount === 0
        ? 0.0
        : parameterCount === 1
          ? 0.1
          : parameterCount === 2
            ? 0.2
            : 0.25;

    // Type bonuses
    const apiBonus = isApi ? 0.3 : 0.0;
    const authBonus = hasAuthRelevance ? 0.2 : 0.0;

    // Source diversity bonus
    const sourceBonus =
      input.source === 'playwright_network' || input.source === 'spa_network'
        ? 0.15
        : input.source === 'byot_network_harvest'
          ? 0.15
          : input.source === 'rsc_discovery'
            ? 0.12
            : input.source === 'playwright_spa'
              ? 0.08
              : 0.04;

    // Depth penalty
    const depthFactor =
      input.depth === 0
        ? 1.0
        : input.depth === 1
          ? 0.95
          : input.depth === 2
            ? 0.8
            : 0.6;

    const rawScore =
      (novelty * 0.35 + paramScore + apiBonus + authBonus + sourceBonus) * depthFactor;

    const priorityScore = Math.min(1.0, Math.max(0.05, Math.round(rawScore * 100) / 100));

    const priorityTier: FrontierPriorityTier =
      priorityScore >= 0.7
        ? 'critical'
        : priorityScore >= 0.45
          ? 'high'
          : priorityScore >= 0.25
            ? 'medium'
            : 'low';

    const reasons: string[] = [];
    if (seenCount === 0) reasons.push(`New route pattern (${normalizedPattern})`);
    if (isApi) reasons.push('API/RPC endpoint');
    if (hasAuthRelevance) reasons.push('Authentication-relevant surface');
    if (parameterCount > 0) reasons.push(`${parameterCount} parameter(s)`);
    if (input.source !== 'html_link_extraction') reasons.push(`Source: ${input.source}`);
    reasons.push(`Depth: ${input.depth}`);

    const priorityReason = `[${priorityTier}, ${priorityScore}]: ` + reasons.join('; ');

    const candidate: CrawlFrontierCandidate = Object.freeze({
      candidateId: `cand_${this.totalEnqueued + 1}_${Math.random().toString(36).slice(2, 8)}`,
      url: input.url,
      host: input.host,
      path: input.path,
      ...(input.query ? { query: input.query } : {}),
      normalizedRoutePattern: normalizedPattern,
      source: input.source,
      depth: input.depth,
      priorityScore,
      priorityTier,
      priorityReason,
      estimatedInformationGain: Math.min(1.0, Math.round((novelty * 0.5 + (isApi ? 0.5 : 0.2)) * 100) / 100),
      novelty,
      parameterCount,
      isApi,
      hasAuthRelevance,
      status: 'enqueued',
      enqueuedAt: new Date().toISOString(),
    });

    this.queue.push(candidate);
    this.totalEnqueued++;

    // Sort descending by priorityScore, then ascending by depth
    this.queue.sort((a, b) => {
      if (b.priorityScore !== a.priorityScore) {
        return b.priorityScore - a.priorityScore;
      }
      return a.depth - b.depth;
    });

    return true;
  }

  /**
   * Retrieves the next highest-priority candidate from the frontier.
   */
  public next(): CrawlFrontierCandidate | undefined {
    const item = this.queue.shift();
    if (item) {
      this.totalSelected++;
      this.selectedReasons.push(item.priorityReason);
      return Object.freeze({
        ...item,
        status: 'selected',
      });
    }
    return undefined;
  }

  public hasMore(): boolean {
    return this.queue.length > 0;
  }

  public size(): number {
    return this.queue.length;
  }

  public getDiagnosticSummary(): FrontierDiagnosticSummary {
    return Object.freeze({
      totalEnqueued: this.totalEnqueued,
      totalSelected: this.totalSelected,
      totalSkippedPatternSaturation: this.totalSkippedPatternSaturation,
      activeQueueSize: this.queue.length,
      distinctRoutePatternsObserved: this.patternCounts.size,
      topSelectedReasons: Object.freeze(this.selectedReasons.slice(-10)),
    });
  }
}
