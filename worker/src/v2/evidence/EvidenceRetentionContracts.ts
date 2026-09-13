/**
 * Milestone F3 — Evidence Retention Contracts
 *
 * Defines retention policies and pruning boundaries for response snapshots
 * and transient comparison observations.
 */

export interface EvidenceRetentionPolicy {
  readonly retainFullPayloadsOnPromotedFindings: boolean;
  readonly pruneTransientAbstainedEvidence: boolean;
  readonly maxExcerptLengthBytes: number;
}

export const DEFAULT_EVIDENCE_RETENTION_POLICY: EvidenceRetentionPolicy = {
  retainFullPayloadsOnPromotedFindings: true,
  pruneTransientAbstainedEvidence: true,
  maxExcerptLengthBytes: 300
};

export interface PrunedEvidenceMetadata {
  readonly isPruned: true;
  readonly originalContentLength: number;
  readonly bodyHash: string;
  readonly prunedAt: string;
}
