/**
 * FixGuard V2 — Milestone F6 Orchestrated Assessment Contracts
 *
 * Defines domain contracts, commands, DTOs, and repository interfaces for the
 * Orchestrated Assessment API Gateway.
 */

import type {
  ActiveReconOrchestrationConfig,
  ReconStageExecutionResult,
} from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import type { TargetProfile, TargetRecommendation } from '../intelligence/IntelligenceContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import type { ByotSessionIdentityBundle } from '../detection/DetectionContracts.js';
import type { AttackSurfaceGraph } from '../attack-surface/AttackSurfaceContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { AttackChain } from '../attack-chain/AttackChainContracts.js';
import type { PostExploitationState } from '../post-exploitation/PostExploitationContracts.js';

export const ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION =
  'fixguard-orchestrated-assessment/v0' as const;

export type OrchestratedAssessmentStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'preflight_denied'
  | 'circuit_broken';

export interface StartOrchestratedAssessmentCommand {
  readonly targetDomain: string;
  readonly actorId?: string;
  readonly config?: ActiveReconOrchestrationConfig;
  readonly sessionIdentities?: ByotSessionIdentityBundle;
}

export interface StartOrchestratedAssessmentResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly status: 'running';
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

export interface OrchestratedAssessmentTiming {
  readonly startedAt: string;
  readonly completedAt?: string;
  readonly durationMs?: number;
}

export interface DifferentialEvidenceContext {
  readonly endpointUrl: string;
  readonly detectionKind:
    | 'cors_misconfiguration'
    | 'parameter_reflection'
    | 'idor_access_control'
    | 'missing_security_headers'
    | 'open_redirect'
    | 'information_disclosure'
    | 'subdomain_takeover'
    | 'weak_tls_configuration'
    | 'auth_bypass'
    | 'sourcemap_exposure'
    | 'wordpress_surface'
    | 'sql_error_oracle'
    | 'graphql_surface'
    | 'jwt_algorithm_confusion'
    | 'session_fixation'
    | 'credentialed_cors'
    | 'cms_plugin_vulnerability'
    | 'cors_idor_compound'
    | 'api_versioning_sprawl'
    | 'http_method_manipulation'
    | 'dependency_confusion'
    | 'manifest_exposure'
    | 'parameter_integrity'
    | 'object_mapping_anomaly'
    | 'state_transition_anomaly'
    | 'attack_surface_delta'
    | 'cross_finding_chain'
    | 'static_secret_exposure'
    | 'dependency_vulnerability'
    | 'static_route_extraction'
    | 'oob_canary_interaction'
    | 'blind_ssrf'
    | 'blind_xss'
    | 'custom_difference';
  readonly baselineStatusCode?: number;
  readonly baselineBodyHash?: string;
  readonly validationStatusCode?: number;
  readonly validationBodyHash?: string;
  readonly reflectedOrigin?: string;
  readonly allowCredentials?: boolean;
  readonly parameterName?: string;
  readonly reflectedCanary?: string;
  readonly resourceParamName?: string;
  readonly baselineResourceId?: string;
  readonly missingHeaders?: readonly string[];
  readonly presentHeaders?: readonly string[];
  readonly injectedCanary?: string;
  readonly finalDestination?: string;
  readonly redirectChain?: readonly string[];
  readonly disclosureKind?: 'stack_trace' | 'framework_version' | 'server_banner' | 'internal_path';
  readonly disclosedFragment?: string;
  readonly trigger?: string;
  readonly subdomain?: string;
  readonly cnameTarget?: string;
  readonly hostingProvider?: 'github_pages' | 'heroku' | 'aws_s3' | 'azure' | 'fastly' | 'netlify' | 'shopify' | 'unknown';
  readonly fingerprintMatch?: string;
  readonly targetHost?: string;
  readonly port?: number;
  readonly weakProtocols?: readonly string[];
  readonly weakCiphers?: readonly string[];
  readonly certificateIssues?: readonly ('expired' | 'self_signed' | 'invalid_san')[];
  readonly supportedTlsVersions?: readonly string[];
  readonly bypassMechanism?: 'header_stripping' | 'cookie_omission' | 'verb_tampering';
  readonly bodySimilarityRatio?: number;
  readonly httpMethod?: string;
  readonly exposedMapUrl?: string;
  readonly sourceJsUrl?: string;
  readonly sampleSourcesCount?: number;
  readonly mapFileSizeBytes?: number;
  readonly wpProbeKind?: 'xmlrpc_capabilities' | 'rest_user_enumeration';
  readonly xmlRpcMethodsExposed?: readonly string[];
  readonly multicallSupported?: boolean;
  readonly exposedUsersCount?: number;
  readonly sampleUserSlugs?: readonly string[];
  readonly databaseEngine?: 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown';
  readonly sqlErrorFragment?: string;
  readonly injectedProbe?: string;
  readonly introspectionEnabled?: boolean;
  readonly batchingEnabled?: boolean;
  readonly fieldSuggestionsEnabled?: boolean;
  readonly discoveredRootTypes?: readonly string[];
  readonly suggestionLeak?: string;
  readonly originalAlgorithm?: string;
  readonly manipulatedAlgorithm?: 'none' | 'None' | 'NONE';
  readonly jwtProbeMechanism?: 'signature_stripping' | 'alg_none_header';
  readonly sessionCookieName?: string;
  readonly fixedSessionId?: string;
  readonly serverRegeneratedSession?: boolean;
  readonly suppliedOrigin?: string;
  readonly allowCredentialsHeader?: boolean;
  readonly acaoHeader?: string;
  readonly cmsType?: 'wordpress' | 'joomla' | 'drupal';
  readonly pluginSlug?: string;
  readonly detectedVersion?: string;
  readonly minimumSafeVersion?: string;
  readonly isOutdated?: boolean;
  readonly evidenceSourceUrl?: string;
  readonly chainKind?: 'cors_idor_compound' | 'cross_finding_compound';
  readonly primaryFindingId?: string;
  readonly secondaryFindingId?: string;
  readonly sharedOrigin?: string;
  readonly targetEndpointUrl?: string;
  readonly compoundImpactScore?: number;
  readonly chainTitle?: string;
  readonly constituentFindingIds?: readonly string[];
  readonly primaryVector?: string;
  readonly secondaryVector?: string;
  readonly currentEndpointUrl?: string;
  readonly legacyEndpointUrl?: string;
  readonly currentStatusCode?: number;
  readonly legacyStatusCode?: number;
  readonly detectedVersions?: readonly string[];
  readonly unauthenticatedExposure?: boolean;
  readonly targetOperation?: string;
  readonly baselineMethod?: string;
  readonly bypassMethodOrHeader?: string;
  readonly manipulatedStatusCode?: number;
  readonly bypassType?: 'method_override_header' | 'query_param_override' | 'trace_enabled';
  readonly packageName?: string;
  readonly sourceManifestUrl?: string;
  readonly publicRegistryUrl?: string;
  readonly registryStatusCode?: number;
  readonly isUnclaimedPublicly?: boolean;
  readonly exposedFilePath?: string;
  readonly fileKind?: 'env_file' | 'git_config' | 'package_manifest' | 'dependency_lockfile';
  readonly exposureSeverity?: 'critical' | 'high' | 'medium';
  readonly sanitizedSnippet?: string;
  readonly injectedProbePattern?: string;
  readonly boundaryEnforced?: boolean;
  readonly sanitizedExcerpt?: string;
  readonly injectedProperties?: readonly string[];
  readonly bindingAccepted?: boolean;
  readonly sanitizedEchoResponse?: string;
  readonly expectedPrerequisiteSteps?: readonly string[];
  readonly bypassedSuccessfully?: boolean;
  readonly responseExcerpt?: string;
  readonly baselineAssessmentId?: string;
  readonly newEndpointsCount?: number;
  readonly removedEndpointsCount?: number;
  readonly newlyExposedPaths?: readonly string[];
  readonly technologyDriftDetected?: boolean;
  readonly deltaSeverity?: 'high' | 'medium' | 'low';
  readonly filePath?: string;
  readonly lineNumber?: number;
  readonly secretKind?: 'aws_key' | 'private_key' | 'generic_api_key' | 'database_uri' | 'jwt_secret';
  readonly ecosystem?: 'npm' | 'pip' | 'composer';
  readonly installedVersion?: string;
  readonly vulnerableRange?: string;
  readonly advisoryId?: string;
  readonly sourceManifestPath?: string;
  readonly frameworkType?: 'express' | 'nextjs' | 'fastapi' | 'spring' | 'generic';
  readonly sourceFilePath?: string;
  readonly extractedRoutePattern?: string;
  readonly supportedMethods?: readonly string[];
  readonly isInternalOnly?: boolean;
  readonly canaryToken?: string;
  readonly callbackDomain?: string;
  readonly interactionType?: 'http_callback' | 'dns_query';
  readonly remoteAddress?: string;
  readonly interactionTimestamp?: string;
  readonly injectedCanaryUrl?: string;
  readonly interactionConfirmed?: boolean;
  readonly injectedPayloadSnippet?: string;
}




export type EnrichedEvidenceDraft = EvidenceDraftEnvelope & {
  readonly differentialContext?: DifferentialEvidenceContext;
};

export interface OrchestratedAssessmentRecord {
  readonly contractVersion: typeof ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: OrchestratedAssessmentStatus;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly stages: readonly ReconStageExecutionResult[];
  readonly timing: OrchestratedAssessmentTiming;
  readonly errorCount: number;
  readonly warningCount: number;
  readonly profile?: TargetProfile;
  readonly findings: readonly Finding[];
  readonly pendingEvidenceDrafts?: readonly EnrichedEvidenceDraft[];
  readonly recommendations: readonly TargetRecommendation[];
  /** Milestone A2 — immutable Attack Surface Graph built at assessment completion. */
  readonly attackSurfaceGraph?: AttackSurfaceGraph;
  readonly error?: string;
  readonly reasonCode?: string;
}

export interface OrchestratedAssessmentStatusDto {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: OrchestratedAssessmentStatus;
  readonly stages: readonly ReconStageExecutionResult[];
  readonly timing: OrchestratedAssessmentTiming;
  readonly errorCount: number;
  readonly warningCount: number;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly pendingEvidenceDraftCount?: number;
  readonly error?: string;
  readonly reasonCode?: string;
}

export interface OrchestratedAssessmentSummaryDto {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: OrchestratedAssessmentStatus;
  readonly profile?: TargetProfile;
  readonly findings: readonly Finding[];
  readonly pendingEvidenceDrafts?: readonly EnrichedEvidenceDraft[];
  readonly recommendations: readonly TargetRecommendation[];
  readonly attackSurfaceGraph?: AttackSurfaceGraph;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timing: OrchestratedAssessmentTiming;
  readonly error?: string;
  readonly reasonCode?: string;
}

export interface GetAttackSurfaceResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly targetDomain: string;
  readonly status: OrchestratedAssessmentStatus;
  readonly attackSurfaceGraph: AttackSurfaceGraph | null;
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/** Milestone A3 — advisory attack plans read model (never executable). */
export interface GetAttackPlansResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly planCount: number;
  readonly plans: readonly AttackPlan[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/** Milestone A6 — attack chain hypotheses aggregated from executed-step evidence. */
export interface GetAttackChainsResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly chainCount: number;
  readonly chains: readonly AttackChain[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/** Milestone A10 — post-exploitation snapshot (never contains raw secrets). */
export interface GetPostExploitationResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly state: PostExploitationState | null;
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

export interface ReviewEvidenceDraftCommand {
  readonly assessmentId: string;
  readonly draftId: string;
  readonly decision: 'approve_evidence' | 'reject_evidence';
  readonly reviewerId: string;
  readonly reviewedAt: string;
  readonly notes?: string;
}

export interface ReviewEvidenceDraftResult {
  readonly assessmentId: string;
  readonly draftId: string;
  readonly decision: 'approve_evidence' | 'reject_evidence';
  readonly reviewerId: string;
  readonly reviewedAt: string;
  readonly findingCreated?: Finding;
  readonly remainingDraftCount: number;
}

export interface GetEvidenceDraftsResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly draftCount: number;
  readonly drafts: readonly EnrichedEvidenceDraft[];
}

export interface OrchestratedAssessmentRepository {
  save(record: OrchestratedAssessmentRecord): Promise<void>;
  findById(assessmentId: string): Promise<OrchestratedAssessmentRecord | null>;
  list?(): Promise<readonly OrchestratedAssessmentRecord[]>;
  update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord>;
}

