/**
 * Milestone F5 — Real Intelligence Layer Contracts
 * Contract version: fixguard-intelligence/v0
 *
 * Defines contracts for immutable TargetProfile construction,
 * rule-based correlation, and advisory TargetRecommendation generation.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { RequiredPermission } from '../scope/AuthorizedScopeContracts.js';

export type IntelligenceContractVersion = 'fixguard-intelligence/v0';
export const INTELLIGENCE_CONTRACT_VERSION: IntelligenceContractVersion = 'fixguard-intelligence/v0';

export type AuthRequirementKind = 'unknown' | 'none' | 'authenticated';

export interface CorsProfileConfiguration {
  readonly allowOrigin?: string;
  readonly allowCredentials?: boolean;
}

export interface TargetProfileEndpoint {
  readonly url: string;
  readonly path: string;
  readonly method: string;
  readonly parameters: readonly string[];
  readonly authRequirement: AuthRequirementKind;
  readonly corsConfiguration?: CorsProfileConfiguration;
  readonly flawCategories: readonly string[];
}

export interface TargetProfile {
  readonly contractVersion: IntelligenceContractVersion;
  readonly kind: 'target_profile';
  readonly profileId: string;
  readonly targetHost: string;
  readonly normalizedOrigin?: string;
  readonly updatedAt: string;
  readonly technologies: readonly string[];
  readonly endpoints: readonly TargetProfileEndpoint[];
  readonly knownFindings: readonly Finding[];
  readonly rawObservations?: readonly unknown[];
  readonly lineage: AuthorizedExecutionLineageTuple;
}

export interface TargetProfileBuilderInput {
  readonly profileId?: string;
  readonly targetHost: string;
  readonly normalizedOrigin?: string;
  readonly findings?: readonly Finding[];
  readonly observations?: readonly unknown[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly buildTimestamp?: string;
}

export type RecommendationCategory =
  | 'cross_origin_exploit_chain'
  | 'access_control_verification'
  | 'parameter_fuzzing'
  | 'technology_hardening';

export interface TargetRecommendation {
  readonly contractVersion: IntelligenceContractVersion;
  readonly kind: 'target_recommendation';
  readonly recommendationId: string;
  readonly targetHost: string;
  readonly category: RecommendationCategory;
  readonly title: string;
  readonly reasoning: string;
  readonly suggestedCapability: string;
  readonly requiredPermissions: readonly RequiredPermission[];
  readonly confidence: number;
  readonly severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  readonly sourceFindingIds: readonly string[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly createdAt: string;
}

export interface RecommendationEngineResult {
  readonly contractVersion: IntelligenceContractVersion;
  readonly kind: 'recommendation_engine_result';
  readonly profileId: string;
  readonly targetHost: string;
  readonly recommendations: readonly TargetRecommendation[];
  readonly correlatedAt: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
}
