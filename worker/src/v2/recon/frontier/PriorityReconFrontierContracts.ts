/**
 * FixGuard V2 — Priority Recon Frontier Contracts.
 * Contract version: fixguard-priority-frontier/v0
 *
 * Defines contracts and data structures for an information-gain-prioritized
 * exploration frontier replacing naive FIFO crawling.
 *
 * Invariants:
 * 1. Pure deterministic scoring: zero network I/O, zero filesystem access.
 * 2. Explainable diagnostics: every priority score carries an interpretable reason string.
 * 3. Bounded values: all scores and estimations are strictly bounded [0.0, 1.0].
 * 4. Structural route intelligence: recognizes parameter patterns instead of flat string equality.
 */

export const PRIORITY_FRONTIER_CONTRACT_VERSION = 'fixguard-priority-frontier/v0' as const;
export type PriorityFrontierContractVersion = typeof PRIORITY_FRONTIER_CONTRACT_VERSION;

export type FrontierPriorityTier = 'critical' | 'high' | 'medium' | 'low';

export type FrontierItemStatus =
  | 'enqueued'
  | 'selected'
  | 'skipped_budget'
  | 'skipped_duplicate_pattern'
  | 'completed';

export interface CrawlFrontierCandidate {
  readonly candidateId: string;
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly query?: string;
  /** Normalized structural pattern, e.g. /api/v1/users/{id} */
  readonly normalizedRoutePattern: string;
  readonly source: string;
  readonly depth: number;
  /** Normalized score in [0.0, 1.0] */
  readonly priorityScore: number;
  readonly priorityTier: FrontierPriorityTier;
  readonly priorityReason: string;
  readonly estimatedInformationGain: number;
  readonly novelty: number;
  readonly parameterCount: number;
  readonly isApi: boolean;
  readonly hasAuthRelevance: boolean;
  readonly status: FrontierItemStatus;
  readonly enqueuedAt: string;
}

export interface FrontierCandidateInput {
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly query?: string;
  readonly source: string;
  readonly depth: number;
  readonly isApiHint?: boolean;
}

export interface FrontierDiagnosticSummary {
  readonly totalEnqueued: number;
  readonly totalSelected: number;
  readonly totalSkippedPatternSaturation: number;
  readonly activeQueueSize: number;
  readonly distinctRoutePatternsObserved: number;
  readonly topSelectedReasons: readonly string[];
}
