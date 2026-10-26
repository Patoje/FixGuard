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
import { normalizeOriginFromUrl } from '../intelligence/correlation/CorsIdorChainCorrelator.js';

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
      // Zero rows observed (rowCountHint <= 0) must never auto-promote (SEC-01: empty is inconclusive).
      if (ctx.supabaseRowCountHint !== undefined && ctx.supabaseRowCountHint <= 0) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'supabase_rls_zero_rows_inconclusive',
          rationale: 'Zero rows observed; empty dataset is inconclusive regarding data exposure',
        };
      }
      // When rowCountHint is unavailable, verify sanitizedSnippet is present and non-empty.
      if (ctx.supabaseRowCountHint === undefined) {
        if (!ctx.sanitizedSnippet || typeof ctx.sanitizedSnippet !== 'string' || ctx.sanitizedSnippet.trim().length === 0) {
          return {
            decision: 'drop_as_noise',
            reasonCode: 'supabase_rls_empty_snippet_inconclusive',
            rationale: 'Missing or empty response body is inconclusive regarding data exposure',
          };
        }
      }
      if (typeof ctx.sanitizedSnippet === 'string' && ctx.sanitizedSnippet.trim().length > 0) {
        const trimmedSnippet = ctx.sanitizedSnippet.trim();
        if (
          trimmedSnippet === '[]' ||
          trimmedSnippet === '{}' ||
          /^\s*\[\s*\]\s*$/.test(trimmedSnippet) ||
          /^\s*\{\s*\}\s*$/.test(trimmedSnippet)
        ) {
          return {
            decision: 'drop_as_noise',
            reasonCode: 'supabase_rls_empty_response_inconclusive',
            rationale: 'Empty array or object response is inconclusive regarding data exposure',
          };
        }
        try {
          const parsed = JSON.parse(trimmedSnippet);
          if (Array.isArray(parsed) && parsed.length === 0) {
            return {
              decision: 'drop_as_noise',
              reasonCode: 'supabase_rls_empty_array_inconclusive',
              rationale: 'Empty array response is inconclusive regarding data exposure',
            };
          }
          if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
            const keys = Object.keys(parsed);
            if (keys.length === 0) {
              return {
                decision: 'drop_as_noise',
                reasonCode: 'supabase_rls_empty_object_inconclusive',
                rationale: 'Empty object response is inconclusive regarding data exposure',
              };
            }
            const errorKeys = new Set(['code', 'message', 'details', 'hint', 'error']);
            const nonErrorKeys = keys.filter((k) => !errorKeys.has(k.toLowerCase()));
            if (nonErrorKeys.length === 0) {
              return {
                decision: 'drop_as_noise',
                reasonCode: 'supabase_rls_error_object_inconclusive',
                rationale: 'PostgREST error object response is inconclusive regarding data exposure',
              };
            }
          }
        } catch {
          if (ctx.supabaseRowCountHint === undefined) {
            return {
              decision: 'drop_as_noise',
              reasonCode: 'supabase_rls_invalid_json_inconclusive',
              rationale: 'Non-JSON response is inconclusive regarding data exposure',
            };
          }
        }
      }
      return null;
    }

    // Audit note (2026-10-25): not reachable via applyFindingAutoPromotion
    // today — JwtAlgorithmConfusionDetectionService is not called by
    // ReadDetectionPass.ts (grep-verified, zero occurrences), so no draft
    // of this kind reaches this function in the automatic pipeline. The
    // real human-approval path for it today is reviewEvidenceDraft()
    // (OrchestratedAssessmentApplicationService.ts). This gate is correct
    // and exercised by its own smoke test, but currently inert in production.
    case 'jwt_algorithm_confusion':
      if (!ctx.manipulatedAlgorithm || !ctx.jwtProbeMechanism) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'jwt_confusion_signal_incomplete',
          rationale: 'JWT algorithm confusion draft missing manipulated algorithm or probe mechanism',
        };
      }
      return null;

    // Audit note (2026-10-25): not reachable via applyFindingAutoPromotion
    // today — same reason as jwt_algorithm_confusion above: SqlErrorOracleDetectionService
    // is not called by ReadDetectionPass.ts. Real human-approval path is
    // reviewEvidenceDraft(). Gate is correct, currently inert in production.
    case 'sql_error_oracle':
      if (
        !ctx.sqlErrorFragment ||
        ctx.sqlErrorFragment.length === 0 ||
        !ctx.injectedProbe ||
        ctx.injectedProbe.length === 0
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'sql_error_oracle_signal_incomplete',
          rationale: 'SQL error oracle draft missing injected probe or observed error fragment',
        };
      }
      return null;

    // Audit note (2026-10-25): not reachable via applyFindingAutoPromotion
    // today — same reason as jwt_algorithm_confusion above: SubdomainTakeoverDetectionService
    // is not called by ReadDetectionPass.ts. Real human-approval path is
    // reviewEvidenceDraft(). Gate is correct, currently inert in production.
    case 'subdomain_takeover':
      if (
        !ctx.cnameTarget ||
        ctx.cnameTarget.length === 0 ||
        !ctx.fingerprintMatch ||
        ctx.fingerprintMatch.length === 0
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'subdomain_takeover_fingerprint_missing',
          rationale: 'Subdomain takeover draft missing dangling CNAME target or hosting fingerprint match',
        };
      }
      return null;

    // Audit note (2026-10-25): not reachable via applyFindingAutoPromotion
    // today — same reason as jwt_algorithm_confusion above: SessionFixationDetectionService
    // is not called by ReadDetectionPass.ts. Real human-approval path is
    // reviewEvidenceDraft(). Gate is correct, currently inert in production.
    case 'session_fixation':
      if (
        !ctx.sessionCookieName ||
        !ctx.fixedSessionId ||
        ctx.serverRegeneratedSession !== false
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'session_fixation_regeneration_unconfirmed',
          rationale:
            'Session fixation draft missing cookie/session-id evidence, or server session regeneration was not observed to be false',
        };
      }
      return null;

    // Audit note (2026-10-25): reachable in production via CorsIdorChainCorrelator.ts,
    // which only builds this draft's differentialContext after confirming the
    // two findings share the exact same normalized origin — this gate is a
    // redundant safety net here, not the primary check.
    case 'cors_idor_compound':
      if (!ctx.primaryFindingId || !ctx.secondaryFindingId || !ctx.sharedOrigin) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'cors_idor_compound_context_missing',
          rationale: 'CORS+IDOR compound draft missing constituent finding ids or shared origin context',
        };
      }
      return null;

    // Audit note (2026-10-25): reachable in production via CrossFindingChainCorrelator.ts.
    // Fixed 2026-10-25: that correlator now propagates the real
    // constituentFindingIds/primaryVector/secondaryVector it already computes
    // internally — before that fix, its draft never carried this context, so
    // this gate blocked 100% of real cross_finding_chain promotions
    // regardless of correlation strength (not a selective filter in practice).
    // Audit fix (2026-10-26): presence of ids/vectors alone is not evidence
    // of a real relationship — the correlator now only forms a pair when
    // both findings share a normalized origin (CrossFindingChainCorrelator.ts),
    // so this gate also requires that sharedOrigin survived into the draft
    // and is itself a well-formed origin, not an arbitrary string. This does
    // NOT prove the constituent findings are causally or exploitably
    // related — same-origin is the minimum grounded precondition available
    // from the data these findings carry, nothing more.
    case 'cross_finding_chain':
      if (
        !ctx.constituentFindingIds ||
        ctx.constituentFindingIds.length < 2 ||
        !ctx.primaryVector ||
        !ctx.secondaryVector
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'cross_finding_chain_context_missing',
          rationale: 'Cross-finding chain draft missing at least 2 constituent findings or primary/secondary vectors',
        };
      }
      if (!ctx.sharedOrigin || normalizeOriginFromUrl(ctx.sharedOrigin) !== ctx.sharedOrigin) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'cross_finding_chain_shared_origin_missing',
          rationale: 'Cross-finding chain draft missing a valid shared normalized origin between the constituent findings',
        };
      }
      return null;

    // Audit note (2026-10-25): reachable in production via DependencyVulnerabilityScanService.ts,
    // which only builds a draft after matching a dependency against a real
    // advisory by name — this gate is a redundant safety net here too.
    case 'dependency_vulnerability':
      if (!ctx.packageName || !ctx.advisoryId || !ctx.installedVersion) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'dependency_vulnerability_advisory_missing',
          rationale: 'Dependency vulnerability draft missing package name, advisory id, or installed version',
        };
      }
      return null;

    case 'parameter_integrity':
      if (ctx.boundaryEnforced === true) {
        return {
          decision: 'drop_as_noise',
          reasonCode: 'parameter_integrity_boundary_enforced',
          rationale: 'Parameter integrity boundary enforced — no vuln signal',
        };
      }
      return null;

    case 'static_secret_exposure': {
      if (!ctx.filePath || typeof ctx.filePath !== 'string' || ctx.filePath.trim().length === 0) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'static_secret_filepath_missing',
          rationale: 'Static secret exposure draft missing source filePath context',
        };
      }
      if (
        !ctx.sanitizedSnippet ||
        typeof ctx.sanitizedSnippet !== 'string' ||
        ctx.sanitizedSnippet.trim().length === 0
      ) {
        return {
          decision: 'keep_as_draft',
          reasonCode: 'static_secret_evidence_incomplete',
          rationale: 'Static secret exposure draft missing sanitized evidence snippet',
        };
      }
      return null;
    }

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
