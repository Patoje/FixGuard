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
import type { ObservedFact } from '../observation/ObservedFactContracts.js';
import type {
  AttackCapabilityKind,
  AttackPlan,
  AttackPlanStatus,
  AttackStepStatus,
} from '../attack-planning/AttackPlanContracts.js';
import type { ActiveInvestigationSnapshot } from '../active-investigation/ActiveInvestigationContracts.js';
import type { AttackChain } from '../attack-chain/AttackChainContracts.js';
import type {
  GetAttackRecommendationsResult,
  OperatorAttackRecommendation,
} from '../attack-recommendation/AttackOperatorRecommendationContracts.js';
import type {
  CredentialReference,
  PostExploitationState,
} from '../post-exploitation/PostExploitationContracts.js';
import type { ImpactAssessment } from '../reporting-boundary/ImpactAssessmentContracts.js';
import type {
  AuthorizedLateralTarget,
  LateralMovementMechanism,
  LateralMovementRecord,
  LateralMovementSnapshot,
} from '../attack-planning/LateralMovementContracts.js';
import type { AuthorizedScopeGrant, HttpMethod } from '../scope/AuthorizedScopeContracts.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import type { ReadInvestigationLoopRecord } from '../investigation/ReadInvestigationLoopContracts.js';
import type { AssessmentTranscript } from '../investigation/AssessmentTranscript.js';

export const ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION =
  'fixguard-orchestrated-assessment/v0' as const;

export type OrchestratedAssessmentStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'preflight_denied'
  | 'circuit_broken';

/**
 * Phase D1 — operator-supplied discovery seeds for deep URL/path inventory.
 * Every seed MUST validate against sealed AuthorizedScopeGrant + egress before use.
 */
export interface AssessmentSeed {
  readonly targetDomain: string;
  readonly seedUrls?: readonly string[];
  readonly seedPaths?: readonly string[];
}

export interface StartOrchestratedAssessmentCommand {
  readonly targetDomain: string;
  readonly actorId: string;
  readonly config?: ActiveReconOrchestrationConfig;
  readonly sessionIdentities?: ByotSessionIdentityBundle;
  /** Absolute in-scope URLs to seed into crawl / endpoint inventory (OBSERVED). */
  readonly seedUrls?: readonly string[];
  /** Relative paths combined with targetDomain into absolute HTTPS URLs. */
  readonly seedPaths?: readonly string[];
  /**
   * Operator-explicit related API hosts (e.g. *.supabase.co) sealed into the grant.
   * Human authorization of those hosts — never auto-inferred into scope.
   */
  readonly relatedAllowedHosts?: readonly string[];
  /**
   * Explicit opt-in for state-changing HTTP operations (POST, PUT, PATCH, DELETE).
   * Defaults to false (strictly read-only GET/HEAD/OPTIONS) when omitted.
   */
  readonly allowStateChangingRequests?: boolean;
  /**
   * Explicitly permitted HTTP methods. Defaults to ['GET', 'HEAD', 'OPTIONS'] when omitted.
   */
  readonly allowedMethods?: readonly HttpMethod[];
}

export interface AuthorizeStateChangingScopeCommand {
  readonly assessmentId: string;
  readonly operatorId: string;
  readonly allowedMethods: readonly HttpMethod[];
  readonly rationale: string;
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

/**
 * Soft liveness signal while orchestrated recon / pipeline work is in flight.
 * Does not authorize anything and must not weaken security timeouts.
 * Optional sessionKeepAlive* fields are operator-safe hints from target
 * soft-pings (no secrets).
 */
export interface OrchestratedAssessmentHeartbeat {
  readonly lastHeartbeatAt: string;
  readonly stageHint?: string;
  readonly toolHint?: string;
  /** ISO timestamp of the most recent target session keep-alive tick. */
  readonly sessionKeepAliveAt?: string;
  /** Operator-safe summary, e.g. "A:ok;B:error" — never cookies/tokens. */
  readonly sessionKeepAliveHint?: string;
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
    | 'supabase_rls_abuse'
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
  /** OBSERVED content-type from baseline probe (IDOR soft-404 / HTML shell gate). */
  readonly baselineContentType?: string;
  /** OBSERVED content-type from validation probe. */
  readonly validationContentType?: string;
  /** OBSERVED body shape from baseline probe (`html` blocks IDOR auto-promote). */
  readonly baselineBodyShapeKind?:
    | 'json_object'
    | 'json_array'
    | 'html'
    | 'text'
    | 'empty'
    | 'unknown';
  /** OBSERVED body shape from validation probe. */
  readonly validationBodyShapeKind?:
    | 'json_object'
    | 'json_array'
    | 'html'
    | 'text'
    | 'empty'
    | 'unknown';
  readonly reflectedOrigin?: string;
  readonly allowCredentials?: boolean;
  readonly parameterName?: string;
  readonly reflectedCanary?: string;
  readonly resourceParamName?: string;
  readonly baselineResourceId?: string;
  /** Pair kind when IDOR ran via multi-identity authz matrix. */
  readonly authzMatrixPair?: 'identity_a_vs_b' | 'unauth_vs_a' | 'unauth_vs_b';
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
  readonly supabaseTableName?: string;
  readonly supabaseClaimKind?: 'SUPABASE_RLS_WORLD_READABLE';
  readonly supabaseAnonEqualsAuth?: boolean;
  readonly supabaseTopLevelJsonKeys?: readonly string[];
  readonly supabaseRowCountHint?: number;
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
  /** F0.1 — OBSERVED facts (no severity). Absent when none were grounded. */
  readonly observedFacts?: readonly ObservedFact[];
  /**
   * Phase 1 — in-scope URLs taken from recon observations already returned.
   * Absent on records written before this field existed.
   */
  readonly probeInventory?: ProbeInventory;
  /**
   * Phase 4 — read-investigation loop outcome. Absent on records written
   * before this field existed, and when the loop did not run.
   */
  readonly readInvestigationLoop?: ReadInvestigationLoopRecord;
  /**
   * Phase 6 — operator transcript. Absent on records written before this
   * field existed. Built from stored inventory, findings, and loop steps.
   */
  readonly transcript?: AssessmentTranscript;
  /**
   * Phase D1 Step 2 — loud degradation notices when CLI binaries are missing
   * or replaced by shallow stubs (e.g. `degraded_mode_missing_binary: naabu`).
   */
  readonly degradedCapabilities?: readonly string[];
  /** Soft liveness while status is running/pending. */
  readonly heartbeat?: OrchestratedAssessmentHeartbeat;
  /**
   * C1 read-loop result. Absent when the loop did not run (circuit open,
   * no allowlisted steps, or investigation start denied).
   */
  readonly phase1ReadLoop?: Phase1ReadLoopRecord;
  readonly error?: string;
  readonly reasonCode?: string;
}

/** Advisory plan row returned with assessment status and summary. */
export interface OperatorPlanStepView {
  readonly stepId: string;
  readonly status: AttackStepStatus;
}

export interface OperatorPlanView {
  readonly planId: string;
  readonly capability: AttackCapabilityKind;
  readonly status: AttackPlanStatus;
  readonly executable: false;
  readonly dependsOn: readonly string[];
  readonly steps: readonly OperatorPlanStepView[];
}

export interface Phase1ReadLoopStepRecord {
  readonly stepId: string;
  readonly capability: AttackCapabilityKind;
  readonly disposition: 'executed' | 'recommended' | 'not_implemented';
  readonly reasonCode: string;
}

/** Stored read-loop outcome. The status DTO projects status, reason, and steps. */
export interface Phase1ReadLoopRecord {
  readonly status: 'completed' | 'stopped';
  readonly reasonCode: string;
  readonly steps: readonly Phase1ReadLoopStepRecord[];
  readonly executedCapabilities: readonly AttackCapabilityKind[];
}

export interface Phase1ReadLoopView {
  readonly status: 'completed' | 'stopped';
  readonly reasonCode: string;
  readonly steps: readonly Phase1ReadLoopStepRecord[];
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
  /** ISO timestamp of the most recent pipeline heartbeat tick. */
  readonly lastHeartbeatAt?: string;
  /** True when status is in-flight and lastHeartbeatAt is within the alive window. */
  readonly alive: boolean;
  readonly heartbeatStageHint?: string;
  readonly heartbeatToolHint?: string;
  /** ISO timestamp of last target session keep-alive soft-ping (BYOT). */
  readonly sessionKeepAliveAt?: string;
  /** Operator-safe keep-alive summary (no secrets). */
  readonly sessionKeepAliveHint?: string;
  readonly error?: string;
  readonly reasonCode?: string;
  /** Child and surface plans for this assessment. */
  readonly plans: readonly OperatorPlanView[];
  /** Deterministic investigation id used by the phase-1 read loop. */
  readonly investigationId: string;
  /** Present when that investigation has a process-local snapshot. */
  readonly investigationSnapshot?: ActiveInvestigationSnapshot;
  /** Present when the phase-1 read loop returned a result. */
  readonly phase1ReadLoop?: Phase1ReadLoopView;
  /** idor_read_differential plans still missing session B. Empty after B attaches. */
  readonly identityBMissingPlanIds: readonly string[];
  /** Phase 6 transcript. Absent on records written before the field existed. */
  readonly transcript?: AssessmentTranscript;
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
  /** Milestone A12 — completed-chain impact assessments (no vault secrets). */
  readonly impactAssessments?: readonly ImpactAssessment[];
  /** Milestone A12 — attack chain hypotheses for summary consumers. */
  readonly attackChains?: readonly AttackChain[];
  /** Milestone A12 — post-exploitation snapshot (CredentialReference metadata only). */
  readonly postExploitationState?: PostExploitationState | null;
  /** Milestone A12 — credential references only (never raw secrets). */
  readonly credentialReferences?: readonly CredentialReference[];
  /** Phase D1 Step 2 — degraded/stub CLI capabilities surfaced for operators. */
  readonly degradedCapabilities?: readonly string[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timing: OrchestratedAssessmentTiming;
  readonly observedFacts: readonly ObservedFact[];
  readonly error?: string;
  readonly reasonCode?: string;
  readonly plans: readonly OperatorPlanView[];
  readonly investigationId: string;
  readonly investigationSnapshot?: ActiveInvestigationSnapshot;
  readonly phase1ReadLoop?: Phase1ReadLoopView;
  readonly identityBMissingPlanIds: readonly string[];
  /** Phase 6 transcript. Absent on records written before the field existed. */
  readonly transcript?: AssessmentTranscript;
}

export interface AttachSessionIdentityBResult {
  readonly assessmentId: string;
  readonly identityCount: 2;
  readonly updatedPlanIds: readonly string[];
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

/** Operator A/B attack recommendations (deterministic; never auto-execute). */
export type { GetAttackRecommendationsResult, OperatorAttackRecommendation };

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

/** Milestone A11 — lateral-movement snapshot (discovery ≠ authorization). */
export interface GetLateralMovementResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly snapshot: LateralMovementSnapshot | null;
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/** Milestone A12/A13 — structured impact assessments (no vault secrets). */
export interface GetImpactAssessmentsResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly impactCount: number;
  readonly impactAssessments: readonly ImpactAssessment[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/**
 * Minimal post-execute refresh payload for Attack Mode UI (A13 readiness).
 * Secret-free; clients may also re-GET dedicated endpoints.
 */
export interface AttackModeRefreshDto {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly attackChains: readonly AttackChain[];
  readonly postExploitationState: PostExploitationState | null;
  readonly lateralMovementSnapshot: LateralMovementSnapshot | null;
  readonly impactAssessments: readonly ImpactAssessment[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly nextRecommendations?: readonly OperatorAttackRecommendation[];
}

/** Milestone A13 — promote discovered/known host to AuthorizedLateralTarget (no secrets). */
export interface PromoteLateralTargetCommand {
  readonly assessmentId: string;
  readonly hostname: string;
  readonly operatorId: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly authorizedAt?: string;
}

export interface PromoteLateralTargetResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly target: AuthorizedLateralTarget;
  readonly snapshot: LateralMovementSnapshot;
  readonly lineage: AuthorizedActiveReconRequestLineage;
}

/** Milestone A13 — evaluate credential reuse (credentialRefId only; vault server-side). */
export interface EvaluateCredentialReuseCommand {
  readonly assessmentId: string;
  readonly planId: string;
  readonly sourceHost: string;
  readonly destinationHost: string;
  readonly mechanism: LateralMovementMechanism;
  readonly credentialRefId: string;
  readonly operatorId: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly targetUrl?: string;
  readonly recordedAt?: string;
}

export interface EvaluateCredentialReuseHttpResult {
  readonly assessmentId: string;
  readonly scanId: string;
  readonly status: 'access_confirmed' | 'access_denied' | 'unauthorized';
  readonly networkDispatched: boolean;
  readonly record: LateralMovementRecord;
  readonly snapshot: LateralMovementSnapshot;
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

