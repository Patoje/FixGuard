/**
 * Milestone F5 — Real Intelligence Layer: TargetRecommendationEngine
 *
 * Implements rule-based correlation reasoning over immutable TargetProfiles.
 * Emits strictly non-executable advisory recommendations adhering to the Approval Boundary.
 */

import type {
  TargetProfile,
  TargetRecommendation,
  RecommendationEngineResult,
  RecommendationCategory,
} from './IntelligenceContracts.js';
import { INTELLIGENCE_CONTRACT_VERSION } from './IntelligenceContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { RequiredPermission } from '../scope/AuthorizedScopeContracts.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function getFindingCategory(finding: Finding): string {
  if (typeof finding.metadata?.category === 'string') {
    return finding.metadata.category;
  }
  return finding.type;
}

export function correlateTargetProfile(profile: TargetProfile): RecommendationEngineResult {
  const recommendations: TargetRecommendation[] = [];
  const safeSeed = sanitizeToSafeId(profile.targetHost);
  const nowIso = new Date().toISOString();
  let recIndex = 0;

  const findings = profile.knownFindings ?? [];

  // Group findings by category
  const corsFindings = findings.filter(f => {
    const cat = getFindingCategory(f);
    const allowCredentials = f.metadata?.kind === 'security_misconfiguration_metadata'
      ? f.metadata.allowCredentials === true
      : false;
    return (
      (cat === 'CORS_MISCONFIGURATION' || cat === 'SECURITY_MISCONFIGURATION') &&
      allowCredentials
    );
  });

  const reflectionFindings = findings.filter(f => {
    const cat = getFindingCategory(f);
    return cat === 'INPUT_VALIDATION_FLAW' || cat === 'PARAMETER_REFLECTION';
  });

  const accessControlFindings = findings.filter(f => {
    const cat = getFindingCategory(f);
    return cat === 'BROKEN_ACCESS_CONTROL';
  });

  // Check endpoint-level configurations
  const hasCorsWithCreds = corsFindings.length > 0 || profile.endpoints.some(
    ep => ep.corsConfiguration?.allowCredentials === true
  );

  const hasReflection = reflectionFindings.length > 0 || profile.endpoints.some(
    ep => ep.flawCategories.includes('INPUT_VALIDATION_FLAW') || ep.flawCategories.includes('PARAMETER_REFLECTION')
  );

  // 1. Cross-Origin Exploit Chain Correlation
  if (hasCorsWithCreds && hasReflection) {
    recIndex += 1;
    const sourceFindingIds: string[] = [];
    for (const f of corsFindings) {
      if (!sourceFindingIds.includes(f.id)) sourceFindingIds.push(f.id);
    }
    for (const f of reflectionFindings) {
      if (!sourceFindingIds.includes(f.id)) sourceFindingIds.push(f.id);
    }

    const permissions: readonly RequiredPermission[] = ['activeValidation', 'authenticatedTesting'];

    recommendations.push({
      contractVersion: INTELLIGENCE_CONTRACT_VERSION,
      kind: 'target_recommendation',
      recommendationId: `rec_chain_${safeSeed}_${recIndex}`,
      targetHost: profile.targetHost,
      category: 'cross_origin_exploit_chain',
      title: 'Cross-Origin Credentialed Data Exposure Chain',
      reasoning:
        'Target reflects input parameters while allowing credentialed cross-origin reads (CORS misconfiguration). An attacker can potentially execute cross-origin requests to read sensitive reflected data.',
      suggestedCapability: 'cross_origin_escalation',
      requiredPermissions: permissions,
      confidence: 0.95,
      severity: 'high',
      sourceFindingIds,
      lineage: { ...profile.lineage },
      createdAt: nowIso,
    });
  }

  // 2. Access Control Verification Correlation
  if (accessControlFindings.length > 0 || profile.endpoints.some(ep => ep.flawCategories.includes('BROKEN_ACCESS_CONTROL'))) {
    recIndex += 1;
    const sourceFindingIds: string[] = [];
    for (const f of accessControlFindings) {
      if (!sourceFindingIds.includes(f.id)) sourceFindingIds.push(f.id);
    }

    const permissions: readonly RequiredPermission[] = ['activeValidation'];

    recommendations.push({
      contractVersion: INTELLIGENCE_CONTRACT_VERSION,
      kind: 'target_recommendation',
      recommendationId: `rec_access_${safeSeed}_${recIndex}`,
      targetHost: profile.targetHost,
      category: 'access_control_verification',
      title: 'Systematic Broken Object Level Authorization Verification',
      reasoning:
        'Target endpoint demonstrated broken access control across distinct identity boundaries. Systematic verification of adjacent object identifiers is recommended.',
      suggestedCapability: 'active_validation',
      requiredPermissions: permissions,
      confidence: 0.90,
      severity: 'high',
      sourceFindingIds,
      lineage: { ...profile.lineage },
      createdAt: nowIso,
    });
  }

  // 3. Unauthenticated Parameterized Surface Fuzzing
  const unauthParamEndpoints = profile.endpoints.filter(
    ep => ep.parameters.length > 0 &&
      (ep.authRequirement === 'none' || ep.authRequirement === 'unknown') &&
      !ep.flawCategories.includes('BROKEN_ACCESS_CONTROL')
  );

  if (unauthParamEndpoints.length > 0 && recommendations.length === 0) {
    // Only recommend if there's no major verified flaw or to explore further
    recIndex += 1;
    const permissions: readonly RequiredPermission[] = ['endpointDiscovery', 'lightValidation'];

    recommendations.push({
      contractVersion: INTELLIGENCE_CONTRACT_VERSION,
      kind: 'target_recommendation',
      recommendationId: `rec_param_${safeSeed}_${recIndex}`,
      targetHost: profile.targetHost,
      category: 'parameter_fuzzing',
      title: 'Unauthenticated Parameterized Attack Surface Exploration',
      reasoning:
        'Discovered unauthenticated endpoints accepting query or body parameters without verified flaws. Input validation probe expansion is recommended.',
      suggestedCapability: 'endpoint_discovery',
      requiredPermissions: permissions,
      confidence: 0.75,
      severity: 'medium',
      sourceFindingIds: [],
      lineage: { ...profile.lineage },
      createdAt: nowIso,
    });
  }

  return {
    contractVersion: INTELLIGENCE_CONTRACT_VERSION,
    kind: 'recommendation_engine_result',
    profileId: profile.profileId,
    targetHost: profile.targetHost,
    recommendations,
    correlatedAt: nowIso,
    lineage: { ...profile.lineage },
  };
}

export class TargetRecommendationEngine {
  public correlate(profile: TargetProfile): RecommendationEngineResult {
    return correlateTargetProfile(profile);
  }
}
