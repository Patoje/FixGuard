/**
 * Milestone 73 — Composite Active Reconnaissance Orchestrator Contracts
 * Contract version: fixguard-active-recon-orchestration/v0
 *
 * Defines contracts for the 5-stage composite active reconnaissance pipeline,
 * tool adapter ports bundle, evidence draft representations, and non-claims.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';
import type { TargetSessionState } from '../../core/SessionLifecycleContracts.js';
import type { TargetExecutionCoordinator } from '../../runtime/TargetExecutionCoordinator.js';
import type { DeepReconSchemaObservation } from '../deep/DeepReconContracts.js';

import type {
  SubdomainDiscoveryTool,
  DiscoveredSubdomainObservation,
} from '../adapters/SubdomainDiscoveryContracts.js';
import type {
  DnsResolutionTool,
  DiscoveredDnsObservation,
} from '../adapters/DnsResolutionContracts.js';
import type {
  PortDiscoveryTool,
  DiscoveredPortObservation,
} from '../adapters/PortDiscoveryContracts.js';
import type {
  WebInspectionTool,
  DiscoveredWebObservation,
} from '../adapters/WebInspectionContracts.js';
import type {
  TlsInspectionTool,
  DiscoveredTlsObservation,
} from '../adapters/TlsInspectionContracts.js';
import type {
  UrlDiscoveryTool,
  DiscoveredUrlObservation,
} from '../adapters/UrlDiscoveryContracts.js';
import type {
  ContentDiscoveryTool,
  DiscoveredContentObservation,
} from '../adapters/ContentDiscoveryContracts.js';
import type {
  ParameterDiscoveryTool,
  DiscoveredParameterObservation,
} from '../adapters/ParameterDiscoveryContracts.js';
import type {
  SecretScannerTool,
  DiscoveredSecretObservation,
} from '../adapters/SecretDiscoveryContracts.js';

export type ActiveReconOrchestrationContractVersion =
  'fixguard-active-recon-orchestration/v0';
export const ACTIVE_RECON_ORCHESTRATION_CONTRACT_VERSION: ActiveReconOrchestrationContractVersion =
  'fixguard-active-recon-orchestration/v0';

export interface ReconOrchestrationExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const RECON_ORCHESTRATION_NON_CLAIMS: ReconOrchestrationExplicitNonClaims =
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

export type ReconStageName =
  | 'stage_1_domain_zone'
  | 'stage_2_port_service'
  | 'stage_3_web_tls'
  | 'stage_4_crawling_parameters'
  | 'stage_deep_recon'
  | 'stage_5_secret_inspection';

import type {
  BrowserAutomationTool,
  DiscoveredSpaObservation,
} from '../adapters/BrowserAutomationContracts.js';
import type { JsLuiceDiscoveryTool } from '../adapters/JsLuiceDiscoveryContracts.js';

export interface ReconToolAdapters {
  readonly subdomainTool: SubdomainDiscoveryTool;
  /** Optional passive CT-log adapter (crt.sh). Merged into Stage 1 subdomain queue alongside subdomainTool. */
  readonly passiveCtTool?: SubdomainDiscoveryTool;
  readonly dnsTool: DnsResolutionTool;
  readonly portTool: PortDiscoveryTool;
  readonly webTool: WebInspectionTool;
  readonly tlsTool: TlsInspectionTool;
  readonly urlTool: UrlDiscoveryTool;
  readonly contentTool: ContentDiscoveryTool;
  readonly parameterTool: ParameterDiscoveryTool;
  readonly secretTool: SecretScannerTool;
  readonly spaDiscoveryTool?: BrowserAutomationTool;
  /** Optional jsluice JS URL/param/secret mining (discovery-only). */
  readonly jsLuiceTool?: JsLuiceDiscoveryTool;
}


export interface ReconStageExecutionResult {
  readonly stage: ReconStageName;
  readonly status: 'completed' | 'skipped' | 'partial_failure';
  readonly durationMs: number;
  readonly observationsCount: number;
  readonly warnings?: readonly string[];
}

export interface OrchestratedReconEvidenceDraft {
  readonly draftId: string;
  readonly stage: ReconStageName;
  readonly targetHost: string;
  readonly observationType: string;
  readonly observationsCount: number;
  readonly explicitNonClaims: ReconOrchestrationExplicitNonClaims;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly createdAt: string;
}

export interface ActiveReconOrchestrationConfig {
  readonly skipStages?: readonly ReconStageName[];
  readonly targetPorts?: readonly (number | string)[];
  readonly wordlistPath?: string;
  readonly timeoutMs?: number;
  /**
   * Opt-in Playwright SPA/RSC mining.
   * - `true`: force enable (still egress/scope gated).
   * - `false`: force disable.
   * - omitted: enable when seedUrls present OR Next.js/RSC signals observed in Stage 3.
   */
  readonly enableSpaDiscovery?: boolean;
  /** Cap on Playwright page navigations (default SPA_DISCOVERY_MAX_PAGES). */
  readonly spaDiscoveryMaxPages?: number;
  /** Cap on ranked jsluice JS targets per stage_4 root (default JSLUICE_MAX_TARGETS_DEFAULT). */
  readonly jsLuiceMaxTargets?: number;
  /**
   * Cap on sourcemap surface probes per stage_4 root (discovery-only URL seeds).
   * Does not create exposure findings — see SourcemapExposureDetection for that.
   */
  readonly sourcemapSurfaceMaxTargets?: number;
  /**
   * Opt-in Deep recon P4: run ffuf/arjun only on top-K inventory URLs
   * (skip spray on every root). Requires wordlistPath for ffuf.
   */
  readonly enableGatedDictTopK?: boolean;
  /** Max ffuf roots when enableGatedDictTopK (default 3). */
  readonly gatedDictMaxFfufRoots?: number;
  /** Max arjun targets when enableGatedDictTopK (default 5). */
  readonly gatedDictMaxArjunTargets?: number;
  /**
   * Opt-in Deep recon method kit (robots/BYOT harvest/gated dicts/hop-extra).
   * - `true`: force enable (fail-soft).
   * - `false`: force disable.
   * - omitted: enable when Next/SPA/Supabase signals or BYOT/harvest token present.
   */
  readonly enableDeepRecon?: boolean;
  /** Shared request budget for deep recon methods (default 40). */
  readonly deepReconMaxRequests?: number;
  /** Force BYOT harvest planning when Identity A / FG_ACCESS_TOKEN available. */
  readonly enableByotHarvest?: boolean;
  /** Skip Playwright and harvest with the assessment HTTP transport. */
  readonly byotHarvestHttpOnly?: boolean;
  /**
   * Crawl frontier maximum request budget for HTML link discovery.
   * Default: 150 requests. Crawling halts when exhausted or frontier empties.
   */
  readonly crawlRequestBudget?: number;
  /**
   * Crawl frontier maximum link depth.
   * Default: 3.
   */
  readonly crawlMaxDepth?: number;
  /**
   * Maximum consecutive inspected pages with zero new in-scope link yield
   * before terminating due to duplicate saturation. Default: 10.
   */
  readonly crawlDuplicateSaturationThreshold?: number;
  /** Legacy / optional caller override for hop-1 extracted routes limit. */
  readonly maxHop1Routes?: number;
  /** Legacy / optional caller override for hop-2 extracted routes limit. */
  readonly maxHop2Routes?: number;
}

import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import type { PlaywrightBrowserLauncher } from '../adapters/BrowserAutomationContracts.js';
import type { ByotHarvestServerActionHint } from '../deep/ByotNetworkHarvestContracts.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';

export interface ActiveReconOrchestrationRequest {
  readonly targetDomain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly authContext?: {
    readonly identityId?: string;
    readonly sessionState?: TargetSessionState;
  };
  readonly coordinator?: TargetExecutionCoordinator;
  readonly config?: ActiveReconOrchestrationConfig;
  readonly dnsResolver?: PreSpawnDnsResolver;
  /** Optional HTTP probe transport (tests / hermetic composition). */
  readonly probeTransport?: IdorHttpProbeTransport;
  readonly onStageComplete?: (stageResult: ReconStageExecutionResult) => Promise<void> | void;
  /**
   * Fired when a stage begins executing (not when skipped). Used for liveness
   * heartbeat stage/tool hints — must never authorize or execute network work.
   */
  readonly onStageStart?: (info: {
    readonly stage: ReconStageName;
    readonly toolHint: string;
  }) => Promise<void> | void;
  /**
   * Soft-extend assessment activity idle during long in-stage tool work.
   * Must never authorize or execute network work.
   */
  readonly onActivityPulse?: (info: {
    readonly stage: ReconStageName;
    readonly toolHint: string;
  }) => Promise<void> | void;
  /**
   * Phase D1 — pre-validated absolute seed URLs (scope + egress already enforced).
   * Injected as live OBSERVED URL observations; also used as crawl roots.
   * Stage 3 issues an HTTP GET probe per seed alongside root host probes.
   */
  readonly seedUrls?: readonly string[];
  /**
   * Phase D1 Step 2 — CLI binaries known missing or replaced by shallow stubs.
   * Surfaced as stage warnings: `degraded_mode_missing_binary: <binary>`.
   */
  readonly degradedBinaries?: readonly string[];
  /**
   * BYOT Identity A headers for authenticated deep-recon harvest (process-local).
   * Never serialized to clients; never logged.
   */
  readonly byotHarvestHeaders?: Readonly<Record<string, string>>;
  /** Injectable Playwright launcher for authenticated BYOT harvest (tests). */
  readonly byotBrowserLauncher?: PlaywrightBrowserLauncher;
  /** Force HTTP-only BYOT harvest (skip Playwright). */
  readonly byotHarvestHttpOnly?: boolean;
  /** Optional session sanctuary holding isolated contexts & challenge states. */
  readonly sessionSanctuary?: import('../../session/SessionSanctuaryService.js').SessionSanctuaryService;
  /** Injectable browser launcher for challenge progression. */
  readonly browserLauncher?: PlaywrightBrowserLauncher;
}

export interface AggregatedReconObservations {
  readonly subdomains: readonly DiscoveredSubdomainObservation[];
  readonly dnsRecords: readonly DiscoveredDnsObservation[];
  readonly ports: readonly DiscoveredPortObservation[];
  readonly webObservations: readonly DiscoveredWebObservation[];
  readonly tlsCertificates: readonly DiscoveredTlsObservation[];
  readonly urls: readonly DiscoveredUrlObservation[];
  readonly content: readonly DiscoveredContentObservation[];
  readonly parameters: readonly DiscoveredParameterObservation[];
  readonly secrets: readonly DiscoveredSecretObservation[];
  readonly spaObservations?: readonly DiscoveredSpaObservation[];
  /** OBSERVED Next-Action ids from BYOT/deep harvest (discovery-only). */
  readonly serverActionHints?: readonly ByotHarvestServerActionHint[];
  /** F0.1 grounded facts harvested during recon. No severity. */
  readonly observedFacts?: readonly ObservedFact[];
  /** Sourcemap JSON already downloaded. No second GET. */
  readonly sourcemapTexts?: readonly string[];
  /** Schema names already read. A type name is not an operation. */
  readonly schemaObservations?: readonly DeepReconSchemaObservation[];
}


export type ActiveReconOrchestrationResult =
  | {
      readonly status: 'success';
      readonly contractVersion: ActiveReconOrchestrationContractVersion;
      readonly targetDomain: string;
      readonly stages: readonly ReconStageExecutionResult[];
      readonly drafts: readonly OrchestratedReconEvidenceDraft[];
      readonly aggregatedObservations: AggregatedReconObservations;
      readonly explicitNonClaims: ReconOrchestrationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
      /** Phase D1 Step 2 — explicit degradation notices (never silent empty success). */
      readonly degradedCapabilities?: readonly string[];
    }
  | {
      readonly status: 'circuit_broken';
      readonly contractVersion: ActiveReconOrchestrationContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: 'target_instability_circuit_open';
      readonly reason: string;
      readonly stages: readonly ReconStageExecutionResult[];
      readonly drafts: readonly OrchestratedReconEvidenceDraft[];
      readonly aggregatedObservations: AggregatedReconObservations;
      readonly explicitNonClaims: ReconOrchestrationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
      readonly degradedCapabilities?: readonly string[];
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: ActiveReconOrchestrationContractVersion;
      readonly targetDomain: string;
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: ReconOrchestrationExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
    };

