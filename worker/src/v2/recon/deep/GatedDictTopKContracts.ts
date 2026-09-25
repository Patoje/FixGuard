/**
 * Deep recon P4 — gated dictionary discovery on top-K inventory URLs only.
 * Discovery-only. Never creates findings or severity claims.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { DiscoveredUrlObservation } from '../adapters/UrlDiscoveryContracts.js';
import type { DiscoveredContentObservation } from '../adapters/ContentDiscoveryContracts.js';
import type { DiscoveredParameterObservation } from '../adapters/ParameterDiscoveryContracts.js';
import type { ContentDiscoveryTool } from '../adapters/ContentDiscoveryContracts.js';
import type { ParameterDiscoveryTool } from '../adapters/ParameterDiscoveryContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import type { DefenseObservation } from '../../test-validity/TestValidityContracts.js';
import {
  DEEP_RECON_NON_CLAIMS,
  type DeepReconExplicitNonClaims,
} from './DeepReconContracts.js';

export const GATED_DICT_TOPK_CONTRACT_VERSION =
  'fixguard-gated-dict-topk/v0' as const;
export type GatedDictTopKContractVersion = typeof GATED_DICT_TOPK_CONTRACT_VERSION;

export const GATED_DICT_TOPK_SOURCE = 'gated_dict_topk' as const;

/** Default max roots for ffuf/content discovery. */
export const GATED_DICT_MAX_FFUF_ROOTS_DEFAULT = 3;
/** Default max endpoints for arjun parameter discovery. */
export const GATED_DICT_MAX_ARJUN_TARGETS_DEFAULT = 5;

export interface GatedDictTopKRequest {
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  /** Inventory URLs already discovered (seeds + crawl + JS). */
  readonly inventoryUrls: readonly { readonly url: string }[];
  readonly contentTool?: ContentDiscoveryTool;
  readonly parameterTool?: ParameterDiscoveryTool;
  /** Absolute wordlist path; defaults via resolveApiDiscoveryWordlistPath. */
  readonly wordlistPath?: string;
  readonly maxFfufRoots?: number;
  readonly maxArjunTargets?: number;
  readonly timeoutMs?: number;
  /** Canary GET transport for WAF-aware abort (optional). */
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  /** Skip WAF canary (hermetic unit tests). */
  readonly skipWafCanary?: boolean;
}

export type GatedDictTopKStatus =
  | 'success'
  | 'skipped'
  | 'waf_aborted'
  | 'preflight_denied'
  | 'tools_missing'
  | 'empty_inventory';

export interface GatedDictTopKResult {
  readonly contractVersion: GatedDictTopKContractVersion;
  readonly status: GatedDictTopKStatus;
  readonly reasonCode: string;
  readonly selectedFfufRoots: readonly string[];
  readonly selectedArjunTargets: readonly string[];
  readonly contentObservations: readonly DiscoveredContentObservation[];
  readonly parameterObservations: readonly DiscoveredParameterObservation[];
  readonly urlObservations: readonly DiscoveredUrlObservation[];
  readonly defenses?: readonly DefenseObservation[];
  readonly requestsUsed: number;
  readonly nonClaims: DeepReconExplicitNonClaims;
}

export { DEEP_RECON_NON_CLAIMS };
