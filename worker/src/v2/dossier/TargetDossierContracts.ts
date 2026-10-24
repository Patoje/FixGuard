/**
 * R3 — Target Dossier Contracts (recon-first pivot, read-only assembly).
 *
 * A single, clean, structured snapshot of what FixGuard has established
 * about a target: classified surface (R2), ranked hypotheses with
 * ADR-013's deferredToManualValidation provenance preserved (R1), and
 * human-approved findings — strictly OBSERVED/INFERRED, never a fabricated
 * claim. This is the artifact an operator can hand off to manual tooling
 * (Parrot) for active validation; it assembles only, it never probes or
 * executes anything new.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { EndpointSurfaceKind } from '../attack-surface/AttackSurfaceContracts.js';
import type { VerificationState } from '../core/VerificationStateContracts.js';
import {
  isStrictSafeId,
  isStrictIsoTimestamp,
} from '../reporting-boundary/DefensiveReportContracts.js';

export type TargetDossierContractVersion = 'fixguard-target-dossier/v0';
export const TARGET_DOSSIER_CONTRACT_VERSION: TargetDossierContractVersion =
  'fixguard-target-dossier/v0';

export interface TargetDossierSurfaceSummary {
  readonly totalEndpoints: number;
  readonly byClassification: Readonly<Record<EndpointSurfaceKind, number>>;
  /** Sample of endpoint URLs still classified 'unknown' — direct next-investigation gaps. */
  readonly unclassifiedEndpointUrls: readonly string[];
  readonly unclassifiedEndpointUrlsTruncated: boolean;
}

export interface TargetDossierHypothesisEntry {
  readonly hypothesisId: string;
  readonly hypothesisKind: string;
  readonly title: string;
  readonly epistemicStatus: string;
  readonly score: number;
  readonly rationale: string;
  readonly blocked: boolean;
  readonly blockReason: string;
  /** ADR-013: true when this hypothesis is part of the active-confirmation
   * layer FixGuard itself defers to manual (Parrot) validation. */
  readonly deferredToManualValidation: boolean;
  readonly suggestedCapability?: string;
  readonly targetUrl?: string;
}

export interface TargetDossierFindingEntry {
  readonly findingId: string;
  readonly type: string;
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  readonly title: string;
  readonly target: string;
  readonly confidence: number;
  readonly verificationState: VerificationState;
}

export interface TargetDossierExplicitNonClaims {
  readonly noNewProbingPerformed: true;
  readonly noAutonomousExploitation: true;
  readonly hypothesesAreAdvisoryOnly: true;
  readonly deferredHypothesesRequireManualValidation: true;
}

export interface TargetDossier {
  readonly contractVersion: TargetDossierContractVersion;
  readonly kind: 'target_dossier';
  readonly dossierId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly generatedAt: string;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly surfaceSummary: TargetDossierSurfaceSummary;
  readonly hypotheses: readonly TargetDossierHypothesisEntry[];
  readonly hypothesesTruncated: boolean;
  readonly findings: readonly TargetDossierFindingEntry[];
  readonly nonClaims: TargetDossierExplicitNonClaims;
}

const ALLOWED_DOSSIER_KEYS = new Set([
  'contractVersion',
  'kind',
  'dossierId',
  'assessmentId',
  'scanId',
  'targetDomain',
  'generatedAt',
  'lineage',
  'surfaceSummary',
  'hypotheses',
  'hypothesesTruncated',
  'findings',
  'nonClaims',
]);

/** Exact-key closed-world validation (ADR-003) for a TargetDossier. */
export function validateTargetDossier(value: unknown): value is TargetDossier {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const raw = value as Record<string, unknown>;

  const keys = Object.keys(raw);
  if (keys.length !== ALLOWED_DOSSIER_KEYS.size) return false;
  for (const k of keys) {
    if (!ALLOWED_DOSSIER_KEYS.has(k)) return false;
  }

  if (raw.contractVersion !== TARGET_DOSSIER_CONTRACT_VERSION) return false;
  if (raw.kind !== 'target_dossier') return false;
  if (!isStrictSafeId(raw.dossierId)) return false;
  if (!isStrictSafeId(raw.assessmentId)) return false;
  if (!isStrictSafeId(raw.scanId)) return false;
  if (typeof raw.targetDomain !== 'string' || raw.targetDomain.length === 0) return false;
  if (!isStrictIsoTimestamp(raw.generatedAt)) return false;
  if (!raw.lineage || typeof raw.lineage !== 'object') return false;
  if (!raw.surfaceSummary || typeof raw.surfaceSummary !== 'object') return false;
  if (!Array.isArray(raw.hypotheses)) return false;
  if (typeof raw.hypothesesTruncated !== 'boolean') return false;
  if (!Array.isArray(raw.findings)) return false;

  const nc = raw.nonClaims;
  if (!nc || typeof nc !== 'object' || Array.isArray(nc)) return false;
  const ncRecord = nc as Record<string, unknown>;
  if (
    ncRecord.noNewProbingPerformed !== true ||
    ncRecord.noAutonomousExploitation !== true ||
    ncRecord.hypothesesAreAdvisoryOnly !== true ||
    ncRecord.deferredHypothesesRequireManualValidation !== true
  ) {
    return false;
  }

  return true;
}
