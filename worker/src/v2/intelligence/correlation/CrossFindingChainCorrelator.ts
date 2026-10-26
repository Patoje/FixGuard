/**
 * Milestone P5-10 — Cross-Finding Chain Correlator (Phase 5 Finale)
 *
 * Core Invariant: Cross-correlates multiple independent findings across different
 * detection engines to synthesize multi-step compound attack paths and elevate
 * systemic risk assessment.
 *
 * Anti-Leak & Safety Guarantees:
 * - Purely analytical in-memory correlation with 0 additional network calls.
 * - Links 2+ constituent finding IDs across distinct vulnerability vectors.
 * - Produces Critical compound drafts for human operator triage (HITL).
 * - 0 occurrences of 'as any'.
 */

import type { Finding } from '../../core/Evidence.js';
import type { EnrichedEvidenceDraft } from '../../application/OrchestratedAssessmentContracts.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';
import { normalizeOriginFromUrl } from './CorsIdorChainCorrelator.js';

export interface CrossFindingChainCorrelatorRequest {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly findings: readonly Finding[];
  readonly humanReviewDecision?: {
    readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    readonly reviewerId: string;
    readonly reviewedAt: string;
  };
}

export interface CrossFindingChainCorrelatorResult {
  readonly contractVersion: 'fixguard-detection-expansion/v0';
  readonly kind: 'cross_finding_chain_correlator_result';
  readonly hasChains: boolean;
  /**
   * Audit fix (2026-10-25): now EnrichedEvidenceDraft, carrying a real
   * differentialContext (constituentFindingIds/primaryVector/secondaryVector
   * from the actual primary/secondary pair) instead of a bare
   * EvidenceDraftEnvelope — those ids were already computed below
   * (chainTitle/rationale) but previously discarded before returning,
   * which left FindingAutoPromotionPolicy's cross_finding_chain gate with
   * nothing real to check.
   */
  readonly compoundDrafts: readonly EnrichedEvidenceDraft[];
  readonly compoundFindings: readonly Finding[];
}

const PRIMARY_ACCESS_VECTORS = new Set([
  'BROKEN_ACCESS_CONTROL',
  'AUTH_BYPASS',
  'IDOR',
  'BOLA',
  'HTTP_METHOD_MANIPULATION',
  'BUSINESS_LOGIC_BYPASS',
  'OBJECT_MAPPING_ANOMALY',
  'STATE_TRANSITION_ANOMALY',
  'JWT_ALGORITHM_CONFUSION',
  'SESSION_FIXATION',
  'CREDENTIALED_CORS',
  'SQL_INJECTION',
  'SQL_ERROR_ORACLE',
  'SUBDOMAIN_TAKEOVER',
]);

const SECONDARY_DISCLOSURE_VECTORS = new Set([
  'INFORMATION_DISCLOSURE',
  'SOURCEMAP_EXPOSURE',
  'MANIFEST_EXPOSURE',
  'DEPENDENCY_CONFUSION',
  'PARAMETER_INTEGRITY',
  'INPUT_VALIDATION_FLAW',
  'SECURITY_MISCONFIGURATION',
  'OPEN_REDIRECT',
  'GRAPHQL_SURFACE',
  'API_VERSIONING_SPRAWL',
  'WORDPRESS_SURFACE',
  'CMS_PLUGIN_VULNERABILITY',
]);

export function isPrimaryAccessVector(finding: Finding): boolean {
  const metaKind = finding.metadata.kind;
  if (
    metaKind === 'broken_access_control_metadata' ||
    metaKind === 'auth_bypass_metadata' ||
    metaKind === 'http_method_manipulation_metadata' ||
    metaKind === 'jwt_algorithm_confusion_metadata' ||
    metaKind === 'session_fixation_metadata' ||
    metaKind === 'credentialed_cors_metadata' ||
    metaKind === 'sql_error_oracle_metadata' ||
    metaKind === 'subdomain_takeover_metadata'
  ) {
    return true;
  }
  return PRIMARY_ACCESS_VECTORS.has(finding.type.toUpperCase());
}

export function isSecondaryDisclosureVector(finding: Finding): boolean {
  const metaKind = finding.metadata.kind;
  if (
    metaKind === 'information_disclosure_metadata' ||
    metaKind === 'sourcemap_exposure_metadata' ||
    metaKind === 'manifest_exposure_metadata' ||
    metaKind === 'dependency_confusion_metadata' ||
    metaKind === 'parameter_integrity_metadata' ||
    metaKind === 'input_validation_flaw_metadata' ||
    metaKind === 'security_misconfiguration_metadata' ||
    metaKind === 'open_redirect_metadata' ||
    metaKind === 'graphql_surface_metadata' ||
    metaKind === 'api_versioning_sprawl_metadata' ||
    metaKind === 'wordpress_surface_metadata' ||
    metaKind === 'cms_plugin_vulnerability_metadata'
  ) {
    return true;
  }
  return SECONDARY_DISCLOSURE_VECTORS.has(finding.type.toUpperCase());
}

/**
 * Purely analytical in-memory cross-finding correlation engine.
 */
export function correlateCrossFindingChains(
  request: CrossFindingChainCorrelatorRequest
): CrossFindingChainCorrelatorResult {
  const { assessmentId, scanId, actorId, findings } = request;

  // Filter out existing compound chains to prevent recursive chain explosion
  const atomicFindings = findings.filter(
    (f) =>
      f.metadata.kind !== 'compound_chain_metadata' &&
      f.metadata.kind !== 'cross_finding_chain_metadata'
  );

  if (atomicFindings.length < 2) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'cross_finding_chain_correlator_result',
      hasChains: false,
      compoundDrafts: [],
      compoundFindings: [],
    };
  }

  const primaryFindings = atomicFindings.filter(isPrimaryAccessVector);
  const secondaryFindings = atomicFindings.filter(isSecondaryDisclosureVector);

  if (primaryFindings.length === 0 || secondaryFindings.length === 0) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'cross_finding_chain_correlator_result',
      hasChains: false,
      compoundDrafts: [],
      compoundFindings: [],
    };
  }

  const compoundDrafts: EnrichedEvidenceDraft[] = [];
  const compoundFindings: Finding[] = [];

  // Group pairs (up to 3 primary x secondary pairs max per assessment)
  let chainCounter = 0;
  for (const primary of primaryFindings) {
    for (const secondary of secondaryFindings) {
      if (primary.id === secondary.id) continue;

      // Audit fix (2026-10-26): same pattern as CorsIdorChainCorrelator —
      // require both finding targets to normalize to a non-null, equal
      // origin before a pair is even formed. Same-origin is not proof of a
      // causal or exploitable chain; it is the minimum grounded precondition
      // this correlator can check from the data it actually has. A pair that
      // fails this is simply never formed — not flagged, not promoted.
      const sharedOrigin = normalizeOriginFromUrl(primary.target);
      const secondaryOrigin = normalizeOriginFromUrl(secondary.target);
      if (!sharedOrigin || !secondaryOrigin || sharedOrigin !== secondaryOrigin) continue;

      if (chainCounter >= 3) break;

      chainCounter++;
      const safePrimaryId = sanitizeEvidenceFragment(primary.id);
      const safeSecondaryId = sanitizeEvidenceFragment(secondary.id);
      const safeSeed = `${assessmentId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 8)}_${chainCounter}`;
      const draftId = `dft_xfchain_${safeSeed}`;
      const candidateId = `cnd_xfchain_${safeSeed}`;
      const evidenceRecordId = `evd_xfchain_${safeSeed}`;
      const findingId = `fnd_xfchain_${safeSeed}`;

      const chainTitle = `Cross-Finding Compound Chain (${primary.title} + ${secondary.title})`;
      const rationale = `Systemic risk synthesis: Linked primary vector (${primary.title}) with secondary vector (${secondary.title}) on target ${primary.target}.`;

      if (request.humanReviewDecision?.decision === 'approve_evidence') {
        const nowIso = new Date().toISOString();
        const finding: Finding = {
          id: findingId,
          type: 'BROKEN_ACCESS_CONTROL',
          severity: 'critical',
          title: `Approved Cross-Finding Attack Path: ${primary.title} & ${secondary.title}`,
          description: `Human operator authorized multi-step compound attack path combining ${primary.type} (${primary.id}) and ${secondary.type} (${secondary.id}). Elevates systemic exposure to Critical.`,
          target: primary.target,
          evidence: JSON.stringify({
            assessmentId,
            scanId,
            chainTitle,
            constituentFindingIds: [primary.id, secondary.id],
            primaryVector: primary.title,
            secondaryVector: secondary.title,
            compoundImpactScore: 0.95,
            reviewedBy: request.actorId,
            reviewedAt: nowIso,
          }),
          confidence: 1.0,
          verificationState: 'validated_vulnerability',
          metadata: {
            kind: 'cross_finding_chain_metadata',
            category: 'BROKEN_ACCESS_CONTROL',
            chainTitle,
            constituentFindingIds: [primary.id, secondary.id],
            primaryVector: primary.title,
            secondaryVector: secondary.title,
            compoundImpactScore: 0.95,
            observedAt: nowIso,
            candidateId,
            evidenceRecordId,
            lineage: `${assessmentId}:${scanId}:${actorId}:${nowIso}`,
          },
        };
        compoundFindings.push(finding);
      } else {
        // Audit fix (2026-10-25): propagate the real primary/secondary pair
        // already computed above (chainTitle/rationale) into differentialContext,
        // instead of discarding it — this is the exact evidence the
        // cross_finding_chain auto-promotion gate requires, not a fabricated value.
        const draft: EnrichedEvidenceDraft = {
          draftKind: 'non_persisted_comparison_evidence_draft',
          draftId,
          suggestedEvidenceType: 'http_difference',
          suggestedStrength: 'strong',
          sourceComparisonId: `cmp_xfchain_${safeSeed}`,
          sourceSnapshotIds: {
            baselineSnapshotId: `snp_base_${safePrimaryId.slice(0, 10)}`,
            validationSnapshotId: `snp_val_${safeSecondaryId.slice(0, 10)}`,
          },
          requiresHumanReview: true,
          notPersisted: true,
          notARealFinding: true,
          notConfirmedEvidence: true,
          notForExternalDelivery: true,
          notM45EvidenceRecord: true,
          safeRationale: rationale,
          differentialContext: {
            endpointUrl: primary.target,
            detectionKind: 'cross_finding_chain',
            chainKind: 'cross_finding_compound',
            chainTitle,
            // Audit fix (2026-10-26): real normalized origin shared by both
            // constituent findings — not proof of a causal/exploitable
            // relationship, only the grounded precondition that let this
            // pair form at all. See the sharedOrigin gate above.
            sharedOrigin,
            constituentFindingIds: [primary.id, secondary.id],
            primaryVector: primary.title,
            secondaryVector: secondary.title,
            compoundImpactScore: 0.95,
          },
        };
        compoundDrafts.push(draft);
      }
    }
  }

  return {
    contractVersion: 'fixguard-detection-expansion/v0',
    kind: 'cross_finding_chain_correlator_result',
    hasChains: compoundDrafts.length > 0 || compoundFindings.length > 0,
    compoundDrafts,
    compoundFindings,
  };
}
