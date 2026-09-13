/**
 * Milestone F3 — Evidence Retention & Pruning Service
 *
 * Enforces evidence retention boundaries:
 * - Promoted findings and verified finding candidates retain full payloads and structural diffs.
 * - Abstained or transient comparisons (secure_target_abstained) retain only structural metadata,
 *   hashes (bodyHash), status codes, and timestamps; raw body excerpts and transient payloads are purged.
 */

import type { SafeResponseSnapshot } from '../comparison/ResponseComparatorContracts.js';

export type PrunableDetectionResult = {
  readonly status: string;
  readonly baselineSnapshot?: SafeResponseSnapshot;
  readonly validationSnapshot?: SafeResponseSnapshot;
  readonly finding?: unknown;
  readonly findingCandidate?: unknown;
};

export function pruneTransientSnapshot(
  snapshot: SafeResponseSnapshot,
  prunedAtIso?: string
): SafeResponseSnapshot {
  const prunedAt = prunedAtIso ?? new Date().toISOString();

  // Return a clean snapshot with safeExcerpt removed, maintaining hash, status, shape, headers, and timings
  return {
    ...snapshot,
    safeExcerpt: undefined,
    headerNames: [...snapshot.headerNames],
    normalizedBodyShape: snapshot.normalizedBodyShape
      ? {
          shapeKind: snapshot.normalizedBodyShape.shapeKind,
          topLevelJsonKeys: snapshot.normalizedBodyShape.topLevelJsonKeys
            ? [...snapshot.normalizedBodyShape.topLevelJsonKeys]
            : undefined,
          normalizedSchemaHash: snapshot.normalizedBodyShape.normalizedSchemaHash
        }
      : undefined
  };
}

export function pruneTransientEvidence<T extends PrunableDetectionResult>(
  result: T,
  prunedAtIso?: string
): T {
  const prunedAt = prunedAtIso ?? new Date().toISOString();

  // If the comparison is an abstention (e.g. secure target), prune transient payload data
  if (result.status === 'secure_target_abstained') {
    return {
      ...result,
      baselineSnapshot: result.baselineSnapshot
        ? pruneTransientSnapshot(result.baselineSnapshot, prunedAt)
        : undefined,
      validationSnapshot: result.validationSnapshot
        ? pruneTransientSnapshot(result.validationSnapshot, prunedAt)
        : undefined,
      finding: undefined,
      findingCandidate: undefined
    };
  }

  // If a vulnerability was detected and promoted, retain full bodies and structural diffs
  return result;
}
