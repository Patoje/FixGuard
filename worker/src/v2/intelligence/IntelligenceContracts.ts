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
import type { DetectedTechnology, TechEcosystemProfile } from '../core/TechnologyContracts.js';

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

/** Milestone A3 — hosting/CDN provider inferred analytically from CNAME (never claimed as vulnerability). */
export type InferredHostingProvider =
  | 'vercel'
  | 'netlify'
  | 'heroku'
  | 'github_pages'
  | 'aws_s3'
  | 'aws_cloudfront'
  | 'azure'
  | 'fastly'
  | 'cloudflare'
  | 'shopify'
  | 'unknown';

export interface DiscoveredHostPortRecord {
  readonly port: number;
  readonly protocol: 'tcp' | 'udp';
  readonly state: 'open' | 'filtered' | 'closed' | 'unknown';
}

/**
 * Milestone A3 — DiscoveredHostRecord
 * FQDN + IPs + ports + CDN/ASN/hosting inferred from CNAME. Inference is analytical only.
 */
export interface DiscoveredHostRecord {
  readonly fqdn: string;
  readonly ipAddresses: readonly string[];
  readonly ports: readonly DiscoveredHostPortRecord[];
  readonly cnameTargets: readonly string[];
  readonly inferredHostingProvider?: InferredHostingProvider;
  readonly inferredCdn?: boolean;
  readonly asn?: string;
  readonly epistemicStatus: 'OBSERVED' | 'INFERRED';
}

export interface AuthSurfacePathRecord {
  readonly path: string;
  readonly url?: string;
  readonly source: 'well_known_heuristic' | 'url_observation' | 'endpoint_observation';
  readonly formHints: readonly string[];
}

/**
 * Milestone A3 — AuthSurfaceMap
 * Well-known auth paths & forms discovered analytically from URL/endpoint observations.
 */
export interface AuthSurfaceMap {
  readonly loginPaths: readonly AuthSurfacePathRecord[];
  readonly oauthPaths: readonly AuthSurfacePathRecord[];
  readonly ssoPaths: readonly AuthSurfacePathRecord[];
  readonly registrationPaths: readonly AuthSurfacePathRecord[];
  readonly passwordResetPaths: readonly AuthSurfacePathRecord[];
  readonly otherAuthPaths: readonly AuthSurfacePathRecord[];
}

/**
 * Milestone A3 — HistoricalAssetRecord
 * Freshness-tagged gau-style historical URL assets (no live network).
 */
export interface HistoricalAssetRecord {
  readonly url: string;
  readonly host: string;
  readonly path: string;
  readonly query?: string;
  readonly sources: readonly string[];
  readonly freshness: 'live' | 'historical' | 'unknown';
  readonly sourceReliability: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
  readonly discoveredAt: string;
  readonly collectedAt?: string;
}

export type ExternalDependencyKind = 'csp_script_src' | 'csp_connect_src' | 'csp_frame_src' | 'csp_img_src' | 'csp_other' | 'cname_cloud';

/**
 * Milestone A3 — ExternalDependency
 * Derived from CSP header parsing and CNAME cloud inference. Zero network calls.
 */
export interface ExternalDependency {
  readonly kind: ExternalDependencyKind;
  readonly value: string;
  readonly inferredProvider?: InferredHostingProvider;
  readonly sourceHost?: string;
  readonly epistemicStatus: 'OBSERVED' | 'INFERRED';
}

export interface TargetProfile {
  readonly contractVersion: IntelligenceContractVersion;
  readonly kind: 'target_profile';
  readonly profileId: string;
  readonly targetHost: string;
  readonly normalizedOrigin?: string;
  readonly updatedAt: string;
  readonly technologies: readonly string[];
  readonly detectedTechnologies?: readonly DetectedTechnology[];
  readonly ecosystemProfile?: TechEcosystemProfile;
  readonly endpoints: readonly TargetProfileEndpoint[];
  readonly knownFindings: readonly Finding[];
  readonly rawObservations?: readonly unknown[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  /** Milestone A3 — additive TargetProfile v2 fields (always present; may be empty). */
  readonly discoveredHosts: readonly DiscoveredHostRecord[];
  readonly authSurface: AuthSurfaceMap;
  readonly historicalAssets: readonly HistoricalAssetRecord[];
  readonly externalDependencies: readonly ExternalDependency[];
}

export interface TargetProfileBuilderInput {
  readonly profileId?: string;
  readonly targetHost: string;
  readonly normalizedOrigin?: string;
  readonly findings?: readonly Finding[];
  readonly observations?: readonly unknown[];
  /** Optional structured recon aggregate for TargetProfile v2 enrichment (Milestone A3). */
  readonly aggregatedObservations?: {
    readonly subdomains?: readonly {
      readonly subdomain: string;
      readonly parentDomain: string;
      readonly ipAddresses?: readonly string[];
      readonly freshness?: 'live' | 'historical' | 'unknown';
      readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
      readonly discoveredAt?: string;
      readonly collectedAt?: string;
    }[];
    readonly dnsRecords?: readonly {
      readonly domain: string;
      readonly recordType: string;
      readonly values: readonly string[];
      readonly freshness?: 'live' | 'historical' | 'unknown';
      readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
      readonly discoveredAt?: string;
      readonly collectedAt?: string;
    }[];
    readonly ports?: readonly {
      readonly host: string;
      readonly ip: string;
      readonly port: number;
      readonly protocol: 'tcp' | 'udp';
      readonly state: 'open' | 'filtered' | 'closed' | 'unknown';
      readonly freshness?: 'live' | 'historical' | 'unknown';
    }[];
    readonly urls?: readonly {
      readonly url: string;
      readonly host: string;
      readonly path: string;
      readonly query?: string;
      readonly sources: readonly string[];
      readonly freshness?: 'live' | 'historical' | 'unknown';
      readonly sourceReliability?: 'direct_observation' | 'historical_archive' | 'inferred_relationship';
      readonly discoveredAt: string;
      readonly collectedAt?: string;
    }[];
    readonly webObservations?: readonly {
      readonly url: string;
      readonly method?: string;
      readonly headers?: Readonly<Record<string, string | string[] | undefined>>;
      readonly bodyText?: string;
      readonly technologies?: readonly string[];
      readonly resolvedIp?: string;
    }[];
  };
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
