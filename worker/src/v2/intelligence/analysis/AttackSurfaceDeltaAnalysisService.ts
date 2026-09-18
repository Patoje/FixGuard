/**
 * Milestone P5-9 — Attack Surface Delta Analysis Service
 *
 * Core Invariant: Purely analytical comparison of discovered endpoints,
 * technologies, and findings against a historical target baseline profile,
 * generating delta insights with zero additional network overhead.
 *
 * Anti-Leak & Safety Guarantees:
 * - Pure in-memory set comparison between current and historical profiles.
 * - Newly exposed paths capped at 15 items.
 * - Clean neutral delta / abstention when no baseline exists or surface is identical.
 * - HITL routing generating non-persisted EvidenceDraftEnvelope for human triage.
 * - 0 occurrences of 'as any'.
 */

import type { Finding } from '../../core/Evidence.js';
import type { TargetProfile } from '../IntelligenceContracts.js';
import type { EvidenceDraftEnvelope } from '../../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';

export const SENSITIVE_PATH_PATTERNS = [
  'admin',
  'debug',
  'internal',
  '.env',
  'graphql',
  'swagger',
  'actuator',
  'backup',
  'config',
  'staging',
  'api/v',
] as const;

export interface AttackSurfaceDeltaAnalysisRequest {
  readonly currentAssessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly targetDomain: string;
  readonly currentProfile: TargetProfile;
  readonly baselineProfile?: TargetProfile;
  readonly baselineAssessmentId?: string;
  readonly humanReviewDecision?: {
    readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    readonly reviewerId: string;
    readonly reviewedAt: string;
  };
}

export interface AttackSurfaceDeltaAnalysisResult {
  readonly contractVersion: 'fixguard-detection-expansion/v0';
  readonly kind: 'attack_surface_delta_analysis_result';
  readonly hasDelta: boolean;
  readonly targetDomain: string;
  readonly baselineAssessmentId?: string;
  readonly newEndpointsCount: number;
  readonly removedEndpointsCount: number;
  readonly newlyExposedPaths: readonly string[];
  readonly technologyDriftDetected: boolean;
  readonly deltaSeverity: 'high' | 'medium' | 'low';
  readonly safeRationale?: string;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly finding?: Finding;
}

export function isSensitivePath(path: string): boolean {
  const lower = path.toLowerCase();
  return SENSITIVE_PATH_PATTERNS.some((pattern) => lower.includes(pattern));
}

export function computeEndpointDifference(
  currentUrls: readonly string[],
  baselineUrls: readonly string[]
): {
  readonly newEndpoints: readonly string[];
  readonly removedEndpoints: readonly string[];
} {
  const normalize = (u: string): string => {
    try {
      const parsed = new URL(u);
      return `${parsed.pathname}${parsed.search}`;
    } catch {
      return u;
    }
  };

  const currentSet = new Set(currentUrls.map(normalize));
  const baselineSet = new Set(baselineUrls.map(normalize));

  const newEndpoints: string[] = [];
  for (const ep of currentSet) {
    if (!baselineSet.has(ep)) {
      newEndpoints.push(ep);
    }
  }

  const removedEndpoints: string[] = [];
  for (const ep of baselineSet) {
    if (!currentSet.has(ep)) {
      removedEndpoints.push(ep);
    }
  }

  return {
    newEndpoints,
    removedEndpoints,
  };
}

export function detectTechDrift(
  currentTechs: readonly string[],
  baselineTechs: readonly string[]
): boolean {
  const currentSet = new Set(currentTechs.map((t) => t.toLowerCase().trim()));
  const baselineSet = new Set(baselineTechs.map((t) => t.toLowerCase().trim()));

  for (const tech of currentSet) {
    if (!baselineSet.has(tech)) {
      return true; // New technology detected
    }
  }

  for (const tech of baselineSet) {
    if (!currentSet.has(tech)) {
      return true; // Removed technology detected
    }
  }

  return false;
}

/**
 * Purely analytical in-memory comparison between current profile and historical baseline.
 */
export function analyzeAttackSurfaceDelta(
  request: AttackSurfaceDeltaAnalysisRequest
): AttackSurfaceDeltaAnalysisResult {
  const { currentAssessmentId, scanId, actorId, targetDomain, currentProfile, baselineProfile, baselineAssessmentId } =
    request;

  // If no baseline profile provided, return neutral result with zero drafts
  if (!baselineProfile) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'attack_surface_delta_analysis_result',
      hasDelta: false,
      targetDomain,
      newEndpointsCount: 0,
      removedEndpointsCount: 0,
      newlyExposedPaths: [],
      technologyDriftDetected: false,
      deltaSeverity: 'low',
    };
  }

  // 1. In-memory endpoint difference
  const currentEndpoints = currentProfile.endpoints.map((e) => e.url);
  const baselineEndpoints = baselineProfile.endpoints.map((e) => e.url);
  const { newEndpoints, removedEndpoints } = computeEndpointDifference(currentEndpoints, baselineEndpoints);

  // 2. In-memory technology drift
  const currentTechs = currentProfile.technologies;
  const baselineTechs = baselineProfile.technologies;
  const techDrift = detectTechDrift(currentTechs, baselineTechs);

  // If no new endpoints and no tech drift, surface is identical -> neutral result
  if (newEndpoints.length === 0 && !techDrift) {
    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'attack_surface_delta_analysis_result',
      hasDelta: false,
      targetDomain,
      baselineAssessmentId,
      newEndpointsCount: 0,
      removedEndpointsCount: removedEndpoints.length,
      newlyExposedPaths: [],
      technologyDriftDetected: false,
      deltaSeverity: 'low',
    };
  }

  // 3. Compute severity & cap paths
  const newlyExposedPaths = newEndpoints.slice(0, 15);
  const hasSensitiveNewPaths = newlyExposedPaths.some(isSensitivePath);

  let deltaSeverity: 'high' | 'medium' | 'low' = 'low';
  if (hasSensitiveNewPaths || newlyExposedPaths.length >= 10) {
    deltaSeverity = 'high';
  } else if (newlyExposedPaths.length > 0 || techDrift) {
    deltaSeverity = 'medium';
  }

  const safeDomain = sanitizeEvidenceFragment(targetDomain);
  const safeBaseId = baselineAssessmentId ? sanitizeEvidenceFragment(baselineAssessmentId) : 'baseline';
  const safeSeed = `${currentAssessmentId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 10)}${safeBaseId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase().slice(0, 6)}`;
  const draftId = `dft_asdelta_${safeSeed}`;
  const candidateId = `cnd_asdelta_${safeSeed}`;
  const evidenceRecordId = `evd_asdelta_${safeSeed}`;

  const rationale = `Longitudinal delta identified ${newlyExposedPaths.length} new endpoints and ${techDrift ? 'technology drift' : 'no technology drift'} compared to baseline ${safeBaseId}. Paths: ${newlyExposedPaths.slice(0, 5).join(', ')}`;

  // 4. Human review approval -> formal Finding
  if (request.humanReviewDecision?.decision === 'approve_evidence') {
    const nowIso = new Date().toISOString();
    const finding: Finding = {
      id: `fnd_asdelta_${safeSeed}`,
      type: 'SECURITY_MISCONFIGURATION',
      severity: deltaSeverity,
      title: `Approved Attack Surface Delta & Expansion on ${safeDomain}`,
      description: `Human operator verified longitudinal attack surface expansion against baseline ${safeBaseId}. Discovered ${newlyExposedPaths.length} new endpoints (${newlyExposedPaths.slice(0, 5).join(', ')})${techDrift ? ' and detected technology stack drift' : ''}.`,
      target: `https://${safeDomain}/`,
      evidence: JSON.stringify({
        targetDomain: safeDomain,
        baselineAssessmentId: safeBaseId,
        newEndpointsCount: newEndpoints.length,
        removedEndpointsCount: removedEndpoints.length,
        newlyExposedPaths,
        technologyDriftDetected: techDrift,
        deltaSeverity,
        reviewedBy: request.actorId,
        reviewedAt: nowIso,
      }),
      confidence: 1.0,
      metadata: {
        kind: 'attack_surface_delta_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        baselineAssessmentId: safeBaseId,
        newEndpointsCount: newEndpoints.length,
        removedEndpointsCount: removedEndpoints.length,
        newlyExposedPaths,
        technologyDriftDetected: techDrift,
        deltaSeverity,
        observedAt: nowIso,
        candidateId,
        evidenceRecordId,
        lineage: `${currentAssessmentId}:${scanId}:${actorId}:${nowIso}`,
      },
    };

    return {
      contractVersion: 'fixguard-detection-expansion/v0',
      kind: 'attack_surface_delta_analysis_result',
      hasDelta: true,
      targetDomain: safeDomain,
      baselineAssessmentId: safeBaseId,
      newEndpointsCount: newEndpoints.length,
      removedEndpointsCount: removedEndpoints.length,
      newlyExposedPaths,
      technologyDriftDetected: techDrift,
      deltaSeverity,
      safeRationale: rationale,
      finding,
    };
  }

  // 5. Unattended mode -> Evidence Draft Envelope
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: deltaSeverity === 'high' ? 'strong' : 'moderate',
    sourceComparisonId: `cmp_asdelta_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_as_base_${safeSeed}`,
      validationSnapshotId: `snp_as_val_${safeSeed}`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: rationale,
  };

  return {
    contractVersion: 'fixguard-detection-expansion/v0',
    kind: 'attack_surface_delta_analysis_result',
    hasDelta: true,
    targetDomain: safeDomain,
    baselineAssessmentId: safeBaseId,
    newEndpointsCount: newEndpoints.length,
    removedEndpointsCount: removedEndpoints.length,
    newlyExposedPaths,
    technologyDriftDetected: techDrift,
    deltaSeverity,
    safeRationale: rationale,
    evidenceDraft,
  };
}
