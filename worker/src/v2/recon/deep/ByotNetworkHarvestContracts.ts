/**
 * Deep recon P3 — BYOT authenticated network harvest contracts.
 * Discovery-only: Playwright (preferred) or HTTP harvest of XHR/RSC/Server Action metadata.
 * Never persists tokens or claims severity.
 */

export const BYOT_NETWORK_HARVEST_CONTRACT_VERSION =
  'fixguard-byot-network-harvest/v1' as const;
export type ByotNetworkHarvestContractVersion =
  typeof BYOT_NETWORK_HARVEST_CONTRACT_VERSION;

export const BYOT_NETWORK_HARVEST_SOURCE = 'byot_network_harvest' as const;

export type ByotHarvestMode = 'playwright' | 'http_fallback';

export const BYOT_HARVEST_MAX_PAGES = 3;
export const BYOT_HARVEST_MAX_SCRIPTS = 8;
export const BYOT_HARVEST_MAX_ACTION_IDS = 12;
export const BYOT_HARVEST_MAX_URLS = 40;
export const BYOT_HARVEST_HYDRATION_WAIT_MS = 800;
export const BYOT_HARVEST_NETWORKIDLE_WAIT_MS = 2_500;

export interface ByotHarvestServerActionHint {
  readonly endpointUrl: string;
  readonly actionId: string;
  readonly source: typeof BYOT_NETWORK_HARVEST_SOURCE | 'rsc_body_mine' | string;
}

export interface ByotNetworkHarvestExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const BYOT_NETWORK_HARVEST_NON_CLAIMS: ByotNetworkHarvestExplicitNonClaims =
  Object.freeze({
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetworkPayloads: false,
    severity: 'info',
  });
