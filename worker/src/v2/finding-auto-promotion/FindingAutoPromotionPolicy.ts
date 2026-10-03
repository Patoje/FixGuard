/**
 * Finding auto-promotion policy — product correction vs ADR-005 HITL-for-all-findings.
 *
 * Human authorization remains required for AttackPlan **execute**.
 * Confirmed/observed vulnerability signals with attack value auto-promote to Finding.
 * Discovery / SPA / fingerprint / soft anomaly noise stays draft or is dropped.
 *
 * Discipline: OBSERVED/INFERRED only — never invent vulns or Critical/High without signal.
 */

import {
  isIdenticalErrorDifferential,
  isIdorSoft404OrHtmlShellNoise,
} from '../detection/DetectionTargetBridge.js';
import {
  IDENTICAL_BODY_SIMILARITY,
  isPublicStaticAssetUrl,
  isVercelSecurityChallengeUrl,
} from '../detection/PublicStaticAsset.js';
import type {
  DifferentialEvidenceContext,
  EnrichedEvidenceDraft,
} from '../application/OrchestratedAssessmentContracts.js';

export type FindingAutoPromotionDecision =
  | 'auto_promote'
  | 'keep_as_draft'
  | 'drop_as_noise';

export type FindingAutoPromotionEvaluation = Readonly<{
  decision: FindingAutoPromotionDecision;
  reasonCode: string;
  rationale: string;
}>;

export type DetectionKind = DifferentialEvidenceContext['detectionKind'];

/**
 * Detection kinds that may auto-promote when confirmed signal gates pass.
 * These contribute to attack chains (authz differentials, confirmed controls gaps, etc.).
 */
const AUTO_PROMOTE_ELIGIBLE: ReadonlySet<DetectionKind> = new Set([
  'idor_access_control',
  'auth_bypass',
  'cors_misconfiguration',
  'credentialed_cors',
  'parameter_reflection',
  'open_redirect',
  'jwt_algorithm_confusion',
  'sql_error_oracle',
  'subdomain_takeover',
  'static_secret_exposure',
  'blind_ssrf',
  'blind_xss',
  'oob_canary_interaction',
  'session_fixation',
  'parameter_integrity',
  'cms_plugin_vulnerability',
  'cors_idor_compound',
  'cross_finding_chain',
  'http_method_manipulation',
  'information_disclosure',
  'weak_tls_configuration',
  'dependency_vulnerability',
  'dependency_confusion',
  'supabase_rls_abuse',
]);

/**
 * Discovery / surface / delta noise — never findings, never attack plans.
 */
const DROP_AS_NOISE: ReadonlySet<DetectionKind> = new Set([
  'static_route_extraction',
  'attack_surface_delta',
]);

/**
 * Soft / cosmetic / surface drafts kept for optional HITL — not auto findings,
 * and not attack-plan sources (except via explicit investigation for a few high-value leftovers).
 */
const KEEP_AS_DRAFT: ReadonlySet<DetectionKind> = new Set([
  'missing_security_headers',
  'wordpress_surface',
  'graphql_surface',
  'api_versioning_sprawl',
  'manifest_exposure',
  'object_mapping_anomaly',
  'state_transition_anomaly',
  'custom_difference',
]);

/**
 * Kinds that may still feed Attack Mode investigation plans when left as drafts
 * (edge case: eligible kind failed signal gate, or soft draft with attack value).
 * Excludes header cosmetics and discovery noise.
 */
const ATTACK_PLAN_DRAFT_ELIGIBLE: ReadonlySet<DetectionKind> = new Set([
  'idor_access_control',
  'auth_bypass',
  'cors_misconfiguration',
  'credentialed_cors',
  'parameter_reflection',
  'open_redirect',
  'jwt_algorithm_confusion',
  'sql_error_oracle',
  'blind_ssrf',
  'blind_xss',
  'session_fixation',
  'parameter_integrity',
  'http_method_manipulation',
  'cors_idor_compound',
  'supabase_rls_abuse',
]);

function hasAccessDifferential(ctx: DifferentialEvidenceContext): boolean {
  const baseStatus = ctx.baselineStatusCode;
  const valStatus = ctx.validationStatusCode;
  const baseHash = ctx.baselineBodyHash ?? '';
  const valHash = ctx.validationBodyHash ?? '';

  if (
    typeof baseStatus === 'number' &&
    typeof valStatus === 'number' &&
    baseHash.length > 0 &&
    valHash.length > 0 &&
    isIdenticalErrorDifferential({
      baselineStatusCode: baseStatus,
      validationStatusCode: valStatus,
      baselineBodyHash: baseHash,
      validationBodyHash: valHash,
    })
  ) {
    return false;
  }

  if (
    typeof baseStatus === 'number' &&
    typeof valStatus === 'number' &&
    baseStatus !== valStatus
  ) {
    return true;
  }

  if (baseHash.length > 0 && valHash.length > 0 && baseHash !== valHash) {
    return true;
  }

  // Auth-bypass path may carry similarity without dual hashes.
  if (
    typeof ctx.bodySimilarityRatio === 'number' &&
    ctx.bodySimilarityRatio >= 0.85 &&
    typeof ctx.bypassMechanism === 'string'
  ) {
    return true;
  }

  return false;
}

function evaluateSignalGate(
  kind: DetectionKind,
  ctx: DifferentialEvidenceContext
): FindingAutoPromotionEvaluation | null {
  switch (kind) {
    case 'idor_access_control': {
      // Identical error pages are noise. Identical successful bodies across
      // distinct identities is classic BOLA (same privileged payload) — promote.
      const baseStatus = ctx.baselineStatusCode;
      const valStatus = ctx.validationStatusCode;
      const baseHash = ctx.baselineBodyHash ?? '';
      const valHash = ctx.validationBodyHash ?? '';
      if (
        typeof baseStatus === 'number' &&
        typeof valStatus === 'number' &&
        baseHash.length > 0 &&
        valHash.length > 0 &&
        isIdenticalErrorDifferential({
          baselineStatusCode: baseStatus,
          validationStatusCode: valStatus,
          baselineBodyHash: baseHash,
          validationBodyHash: valHash,
        })
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'idor_identical_error_differential',
          rationale:
            'IDOR draft is identical error-page noise; not auto-promoted',
        };
      }
      if (!ctx.endpointUrl || !ctx.resourceParamName) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'idor_context_incomplete',
          rationale: 'IDOR draft missing endpoint/resource context',
        };
      }
      // Soft-404 / SPA HTML shells (/a/b, /cart, text/html catch-alls) must
      // never auto-promote — status≠status or hash≠hash alone is not BOLA.
      if (
        isIdorSoft404OrHtmlShellNoise({
          endpointUrl: ctx.endpointUrl,
          baselineStatusCode: baseStatus,
          validationStatusCode: valStatus,
          baselineContentType: ctx.baselineContentType,
          validationContentType: ctx.validationContentType,
          baselineBodyShapeKind: ctx.baselineBodyShapeKind,
          validationBodyShapeKind: ctx.validationBodyShapeKind,
          sanitizedSnippet: ctx.sanitizedSnippet,
        })
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'idor_soft_404_or_html_shell',
          rationale:
            'IDOR draft is soft-404/HTML shell noise; not auto-promoted',
        };
      }
      return null;
    }
    case 'auth_bypass': {
      const endpoint = ctx.endpointUrl ?? '';
      const similarity = ctx.bodySimilarityRatio;
      if (isVercelSecurityChallengeUrl(endpoint)) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'defense_observation',
          rationale:
            'Vercel security challenge is a platform defense, not an authentication finding',
        };
      }
      if (
        isPublicStaticAssetUrl(endpoint) &&
        (similarity === undefined || similarity === IDENTICAL_BODY_SIMILARITY)
      ) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'public_static_asset_identical_body',
          rationale:
            'Public static asset with an identical body is not an authentication boundary',
        };
      }
      if (!hasAccessDifferential(ctx) && ctx.bypassMechanism === undefined) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'auth_bypass_signal_incomplete',
          rationale: 'Auth bypass draft missing differential or bypass mechanism',
        };
      }
      return null;
    }

    case 'cors_misconfiguration':
    case 'credentialed_cors':
      if (!ctx.reflectedOrigin && !ctx.acaoHeader && !ctx.suppliedOrigin) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'cors_reflected_origin_missing',
          rationale: 'CORS draft missing reflected/supplied origin evidence',
        };
      }
      return null;

    case 'parameter_reflection':
      if (!ctx.reflectedCanary || ctx.reflectedCanary.length === 0) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'reflection_canary_missing',
          rationale: 'Parameter reflection draft missing reflected canary evidence',
        };
      }
      return null;

    case 'open_redirect':
      if (!ctx.finalDestination || ctx.finalDestination.length === 0) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'open_redirect_destination_missing',
          rationale: 'Open redirect draft missing final destination evidence',
        };
      }
      return null;

    case 'blind_ssrf':
    case 'blind_xss':
    case 'oob_canary_interaction':
      if (ctx.interactionConfirmed !== true) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'oob_interaction_not_confirmed',
          rationale: 'OOB/blind draft without confirmed callback interaction',
        };
      }
      return null;

    case 'information_disclosure':
      if (
        ctx.disclosureKind !== 'stack_trace' &&
        ctx.disclosureKind !== 'internal_path'
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'info_disclosure_low_attack_value',
          rationale:
            'Banner/framework version disclosure kept as draft (low attack value)',
        };
      }
      return null;

    case 'weak_tls_configuration': {
      const weakProto = (ctx.weakProtocols ?? []).length > 0;
      const weakCipher = (ctx.weakCiphers ?? []).length > 0;
      const certIssues = (ctx.certificateIssues ?? []).length > 0;
      if (!weakProto && !weakCipher && !certIssues) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'weak_tls_signal_incomplete',
          rationale: 'TLS draft missing weak protocol/cipher/certificate evidence',
        };
      }
      return null;
    }

    case 'cms_plugin_vulnerability':
      if (ctx.isOutdated !== true) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'cms_plugin_not_confirmed_outdated',
          rationale: 'CMS plugin draft without confirmed outdated version',
        };
      }
      return null;

    case 'dependency_confusion':
      if (ctx.isUnclaimedPublicly !== true) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'dependency_confusion_not_confirmed',
          rationale: 'Dependency confusion draft without unclaimed-public confirmation',
        };
      }
      return null;

    case 'http_method_manipulation':
      if (
        ctx.unauthenticatedExposure !== true &&
        typeof ctx.manipulatedStatusCode !== 'number' &&
        ctx.bypassType === undefined
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'method_manipulation_signal_incomplete',
          rationale: 'HTTP method manipulation draft missing bypass evidence',
        };
      }
      return null;

    case 'supabase_rls_abuse': {
      // Hard gates: anon 200 + JSON evidence, not HTML; table name required.
      if (!ctx.endpointUrl || !ctx.supabaseTableName) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'supabase_rls_context_incomplete',
          rationale: 'Supabase RLS draft missing table/endpoint context',
        };
      }
      if (ctx.supabaseClaimKind !== 'SUPABASE_RLS_WORLD_READABLE') {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'supabase_rls_claim_not_world_readable',
          rationale: 'Only SUPABASE_RLS_WORLD_READABLE is auto-promote eligible in this slice',
        };
      }
      if (ctx.baselineStatusCode !== 200) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'supabase_rls_anon_not_200',
          rationale: 'Anon Data API status must be OBSERVED 200 for auto-promote',
        };
      }
      if (!ctx.baselineBodyHash || ctx.baselineBodyHash.length === 0) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'supabase_rls_body_hash_missing',
          rationale: 'Missing anon body hash for world-readable signal',
        };
      }
      // HTML shells must never promote (SPA noise).
      if (
        typeof ctx.disclosureKind === 'string' ||
        (typeof ctx.sanitizedSnippet === 'string' &&
          /<!doctype html|<html/i.test(ctx.sanitizedSnippet))
      ) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'supabase_rls_html_not_data_api',
          rationale: 'HTML body is not a PostgREST Data API signal',
        };
      }
      // Zero rows or empty array must never auto-promote (SEC-01: empty is inconclusive).
      if (ctx.supabaseRowCountHint !== undefined && ctx.supabaseRowCountHint <= 0) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'supabase_rls_zero_rows_inconclusive',
          rationale: 'Zero rows observed; empty dataset is inconclusive regarding data exposure',
        };
      }
      if (
        typeof ctx.sanitizedSnippet === 'string' &&
        /^\s*\[\s*\]\s*$/.test(ctx.sanitizedSnippet)
      ) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'supabase_rls_empty_array_inconclusive',
          rationale: 'Empty array response is inconclusive regarding data exposure',
        };
      }
      return null;
    }

    case 'parameter_integrity':
      if (ctx.boundaryEnforced === true) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'parameter_integrity_boundary_enforced',
          rationale: 'Parameter integrity boundary enforced — no vuln signal',
        };
      }
      return null;

    default:
      return null;
  }
}

/**
 * Evaluate whether an enriched evidence draft should become a Finding,
 * remain a draft, or be dropped as discovery/noise.
 */
export function evaluateFindingAutoPromotion(
  draft: EnrichedEvidenceDraft
): FindingAutoPromotionEvaluation {
  const ctx = draft.differentialContext;
  if (!ctx || typeof ctx.detectionKind !== 'string') {
    return {
      decision: 'keep_as_draft',
      reasonCode: 'missing_differential_context',
      rationale: 'Draft lacks differentialContext; cannot auto-promote',
    };
  }

  const kind = ctx.detectionKind;

  if (DROP_AS_NOISE.has(kind)) {
    return {
      decision: 'drop_as_noise',
      reasonCode: 'discovery_or_surface_noise',
      rationale: `detectionKind=${kind} is discovery/surface noise — not a vulnerability finding`,
    };
  }

  if (KEEP_AS_DRAFT.has(kind)) {
    return {
      decision: 'keep_as_draft',
      reasonCode: 'soft_or_cosmetic_signal',
      rationale: `detectionKind=${kind} is soft/cosmetic/surface — HITL optional, not auto-finding`,
    };
  }

  if (!AUTO_PROMOTE_ELIGIBLE.has(kind)) {
    return {
      decision: 'keep_as_draft',
      reasonCode: 'kind_not_auto_promote_eligible',
      rationale: `detectionKind=${kind} has no auto-promotion rule`,
    };
  }

  const gate = evaluateSignalGate(kind, ctx);
  if (gate) {
    return gate;
  }

  return {
    decision: 'auto_promote',
    reasonCode: 'confirmed_attack_relevant_signal',
    rationale: `detectionKind=${kind} has confirmed/observed vuln signal with attack value`,
  };
}

/** True when a leftover draft may feed Attack Mode investigation plans. */
export function isAttackPlanDraftEligible(detectionKind: string): boolean {
  return ATTACK_PLAN_DRAFT_ELIGIBLE.has(detectionKind as DetectionKind);
}

export function isFindingAutoPromoteEligibleKind(detectionKind: string): boolean {
  return AUTO_PROMOTE_ELIGIBLE.has(detectionKind as DetectionKind);
}
