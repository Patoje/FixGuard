/**
 * P4 — Parrot Import -> Finding promotion (the missing other half of R4).
 *
 * A separate, small promotion path — deliberately NOT routed through the
 * M45-M54 evidence-draft pipeline (that pipeline is built around
 * FixGuard's own ResponseComparisonResult from active probing; forcing an
 * externally-confirmed Parrot result through it would mean fabricating
 * fake internal comparison objects just to satisfy its types — the same
 * reasoning R4 increment 1 already documented for the import boundary
 * itself).
 *
 * Mirrors the one discipline every detection/*Service.ts in this codebase
 * already enforces (R5-confirmed, zero exceptions): a Finding is only ever
 * created behind an explicit human `decision === 'approve_evidence'`. The
 * severity/type FixGuard assigns here is never taken from the import file
 * (which is explicitly forbidden from carrying severity/type claims,
 * ParrotImportContracts.ts) — it comes from a fixed, FixGuard-internal
 * lookup keyed on the hypothesis kind the observation responds to, the
 * same hypothesisKind -> category mapping HypothesisSchedulerService
 * already uses.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { Finding } from '../core/Evidence.js';
import type { ParrotImportedObservation } from './ParrotImportContracts.js';

/** The minimal shape this service needs from a matched hypothesis — kept
 * narrow (rather than depending on the full SecurityHypothesis shape) so
 * it can be satisfied from either the live hypothesis-scheduler path or
 * the dossier's own (already-projected) hypothesis entries. */
export interface MatchedHypothesisRef {
  readonly hypothesisId: string;
  readonly hypothesisKind: string;
  readonly title: string;
  readonly targetUrl?: string;
}

interface FindingTypeAndSeverity {
  readonly type: string;
  readonly severity: Finding['severity'];
}

/**
 * Deterministic hypothesisKind -> Finding classification. Only covers
 * hypothesis kinds that represent an actual vulnerability class (not the
 * P1 recon-gap kinds, which can never be "confirmed" — there's nothing to
 * confirm about a classification gap). Absent from this table => promotion
 * is refused, fail-closed, rather than guessing a category.
 *
 * Covers BOTH naming conventions actually seen in production hypotheses:
 * HypothesisSchedulerService's own kind names (idor_differential,
 * auth_bypass, ...) AND InvestigationRuntimeCoordinator's — the live path,
 * verified 2026-10-24 against a real assessment — which uses the
 * AttackPlan capability name directly as hypothesisKind
 * (cors_misconfiguration_probe, open_redirect_probe, ...). Same dual-name
 * pattern already used by isDeferredToManualValidation().
 */
const HYPOTHESIS_KIND_TO_FINDING: Readonly<Record<string, FindingTypeAndSeverity>> = Object.freeze({
  // HypothesisSchedulerService kind names
  idor_differential: { type: 'BROKEN_ACCESS_CONTROL', severity: 'high' },
  auth_bypass: { type: 'BROKEN_AUTHENTICATION', severity: 'high' },
  auth_boundary_differential: { type: 'BROKEN_ACCESS_CONTROL', severity: 'medium' },
  credentialed_cors: { type: 'CORS_MISCONFIGURATION', severity: 'high' },
  jwt_confusion: { type: 'BROKEN_AUTHENTICATION', severity: 'high' },
  sql_oracle: { type: 'INFORMATION_DISCLOSURE', severity: 'medium' },
  parameter_reflection: { type: 'INPUT_VALIDATION_FLAW', severity: 'medium' },
  graphql_surface_probe: { type: 'SECURITY_MISCONFIGURATION', severity: 'low' },
  header_hardening_gap: { type: 'SECURITY_MISCONFIGURATION', severity: 'low' },
  supabase_rls_read_confirm: { type: 'BROKEN_ACCESS_CONTROL', severity: 'high' },
  // InvestigationRuntimeCoordinator capability names (the live path)
  idor_read_differential: { type: 'BROKEN_ACCESS_CONTROL', severity: 'high' },
  auth_bypass_probe: { type: 'BROKEN_AUTHENTICATION', severity: 'high' },
  cors_misconfiguration_probe: { type: 'CORS_MISCONFIGURATION', severity: 'high' },
  cors_chain_exploit: { type: 'CORS_MISCONFIGURATION', severity: 'high' },
  open_redirect_probe: { type: 'OPEN_REDIRECT', severity: 'medium' },
  parameter_reflection_probe: { type: 'INPUT_VALIDATION_FLAW', severity: 'medium' },
  jwt_alg_none_probe: { type: 'BROKEN_AUTHENTICATION', severity: 'high' },
  graphql_auth_delta: { type: 'BROKEN_ACCESS_CONTROL', severity: 'medium' },
});

export type ParrotPromotionRejectionReason =
  | 'observation_not_found'
  | 'observation_already_reviewed'
  | 'hypothesis_not_found'
  | 'hypothesis_kind_not_promotable'
  | 'outcome_not_confirmed';

export interface ParrotPromotionResult {
  readonly promoted: boolean;
  readonly reasonCode: ParrotPromotionReasonCodeOrNull;
  readonly finding?: Finding;
}

export type ParrotPromotionReasonCodeOrNull = ParrotPromotionRejectionReason | 'promoted' | 'rejected_by_reviewer' | 'needs_more_review';

/**
 * Pure. Given an already-reviewed observation (decision + matched
 * hypothesis already resolved by the caller), decides whether to produce a
 * Finding. Never promotes on 'reject' or 'needs_more_review', never
 * promotes an outcome other than 'confirmed', never promotes a hypothesis
 * kind absent from the fixed lookup table above.
 */
export function evaluateParrotPromotion(args: {
  readonly observation: ParrotImportedObservation;
  readonly matchedHypothesis: MatchedHypothesisRef;
  readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
  readonly reviewerId: string;
  readonly reviewedAt: string;
}): ParrotPromotionResult {
  const { observation, matchedHypothesis, decision, reviewerId, reviewedAt } = args;

  if (decision === 'reject') {
    return { promoted: false, reasonCode: 'rejected_by_reviewer' };
  }
  if (decision === 'needs_more_review') {
    return { promoted: false, reasonCode: 'needs_more_review' };
  }
  if (observation.outcome !== 'confirmed') {
    return { promoted: false, reasonCode: 'outcome_not_confirmed' };
  }

  const classification = HYPOTHESIS_KIND_TO_FINDING[matchedHypothesis.hypothesisKind];
  if (!classification) {
    return { promoted: false, reasonCode: 'hypothesis_kind_not_promotable' };
  }

  const findingId = `fnd_parrot_${observation.observationId}`.slice(0, 80);
  const target = matchedHypothesis.targetUrl ?? observation.dossierId;

  const finding: Finding = {
    id: findingId,
    type: classification.type,
    severity: classification.severity,
    title: `Parrot-confirmed: ${matchedHypothesis.title}`,
    description: `Manually validated via Parrot and approved by human reviewer. Hypothesis: ${matchedHypothesis.title}. Operator note: ${observation.operatorNote}`,
    target,
    evidence: observation.evidenceExcerpt ?? observation.operatorNote,
    confidence: 0.75,
    metadata: {
      kind: 'parrot_confirmed_metadata',
      category: classification.type,
      sourceKind: 'parrot_file_import',
      hypothesisId: matchedHypothesis.hypothesisId,
      hypothesisKind: matchedHypothesis.hypothesisKind,
      observationId: observation.observationId,
      reviewerId,
      reviewedAt,
    },
    verificationState: 'suspected_vulnerability',
  };

  return { promoted: true, reasonCode: 'promoted', finding };
}
