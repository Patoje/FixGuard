/**
 * Deep recon P0 — method kit contracts (not a crawler-centric design).
 * Methods increase OBSERVED/INFERRED surface for ASG + DetectionTargetBridge.
 */

export const DEEP_RECON_CONTRACT_VERSION = 'fixguard-deep-recon/v0' as const;
export type DeepReconContractVersion = typeof DEEP_RECON_CONTRACT_VERSION;

export type DeepReconMethodKind =
  | 'robots_sitemap_feed'
  | 'js_surface_mining'
  | 'sourcemap_surface'
  | 'api_schema_discovery'
  | 'byot_network_harvest'
  | 'gated_dict_topk'
  | 'html_hop_extra'
  | 'security_txt'
  | 'well_known_oauth';

export type DeepReconEpistemicTag = 'OBSERVED' | 'INFERRED' | 'RECOMMENDED';

export interface DeepReconMethodPlanEntry {
  readonly method: DeepReconMethodKind;
  readonly expectedRequestCost: number;
  readonly priority: number;
  readonly rationale: string;
  readonly epistemicIntent: DeepReconEpistemicTag;
}

export interface DeepReconStackSignals {
  readonly hasNextJs?: boolean;
  readonly hasVercel?: boolean;
  readonly hasSupabase?: boolean;
  readonly hasSpa?: boolean;
  readonly hasJwtIdentity?: boolean;
}

export interface DeepReconBudget {
  readonly maxRequests: number;
  readonly remainingRequests: number;
}

export interface DeepReconExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const DEEP_RECON_NON_CLAIMS: DeepReconExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

export interface DeepReconMethodResultSummary {
  readonly method: DeepReconMethodKind;
  readonly status: 'ran' | 'skipped' | 'budget_exceeded' | 'preflight_denied' | 'failed';
  readonly reasonCode: string;
  readonly requestsUsed: number;
  readonly urlsSeeded: number;
}

/** Parameter names seeded by js_surface_mining. Values and secrets are never included. */
export interface DeepReconParameterSeed {
  readonly url: string;
  readonly parameterName: string;
  readonly source: 'js_surface_mining';
}

/** Schema names read from OpenAPI or GraphQL introspection. Not findings. */
export interface DeepReconSchemaObservation {
  readonly sourceUrl: string;
  readonly surfaceKind: 'postgrest_table' | 'postgrest_rpc' | 'graphql_type' | 'graphql_query_field';
  readonly name: string;
  readonly epistemicStatus: 'OBSERVED';
}
