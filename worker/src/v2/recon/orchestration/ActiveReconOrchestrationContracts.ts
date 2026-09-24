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
  | 'stage_5_secret_inspection';

import type {
  BrowserAutomationTool,
  DiscoveredSpaObservation,
} from '../adapters/BrowserAutomationContracts.js';

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
}

import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';

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
  readonly onStageComplete?: (stageResult: ReconStageExecutionResult) => Promise<void> | void;
  /**
   * Phase D1 — pre-validated absolute seed URLs (scope + egress already enforced).
   * Injected as live OBSERVED URL observations; also used as crawl roots.
   */
  readonly seedUrls?: readonly string[];
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

