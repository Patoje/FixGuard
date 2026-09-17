/**
 * Milestone F2 — Real Vulnerability Detection Contracts
 * Contract version: fixguard-detection/v0
 *
 * Defines contracts for differential access control (IDOR / BOLA) inspection,
 * isolated transport interfaces, and end-to-end detection results.
 */

import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { SafeResponseSnapshot, ResponseComparisonResult } from '../comparison/ResponseComparatorContracts.js';
import type { AuthorizedComparisonValidationResult } from '../validation/AuthorizedComparisonValidationContracts.js';
import type { ReviewerPolicy, EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import type { HumanReviewedEvidencePromotionResult } from '../evidence-review/HumanReviewedEvidencePromotionContracts.js';
import type { EvidenceRecord } from '../evidence/EvidenceBoundaryContracts.js';
import type { ReviewedEvidenceFormalFindingCandidate, ReviewedEvidenceFindingCandidateTriageDecision } from '../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { DiscoveredTlsObservation } from '../recon/adapters/TlsInspectionContracts.js';

export type DetectionContractVersion = 'fixguard-detection/v0';
export const DETECTION_CONTRACT_VERSION: DetectionContractVersion = 'fixguard-detection/v0';

export type AuthorizedExecutionLineageTuple = Readonly<{
  assessmentId: string;
  scanId: string;
  authorizationGrantId: string;
  authorizationDecisionId: string;
  actorId: string;
}>;

export interface HumanReviewDecision {
  readonly decision: 'approve_evidence' | 'reject' | 'needs_more_review';
  readonly reviewerId: string;
  readonly reviewedAt: string;
}

import type { TargetSessionState } from '../core/SessionLifecycleContracts.js';

export interface ProbeAuthContext {
  readonly identityId: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly cookies?: Readonly<Record<string, string>>;
  readonly sessionState?: TargetSessionState;
}

export interface ByotIdentity {
  readonly identityId: string;
  readonly injectHeaders?: Readonly<Record<string, string>>;
  readonly injectCookies?: Readonly<Record<string, string>>;
}

export interface ByotSessionIdentityBundle {
  readonly identityA: ByotIdentity;
  readonly identityB?: ByotIdentity;
}

export interface HttpProbeRequest {
  readonly url: string;
  readonly method: 'GET' | 'HEAD' | 'POST';
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly timeoutMs?: number;
}

export interface HttpProbeResponse {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyText: string;
  readonly responseTimeMs: number;
}

export type IdorHttpProbeTransport = (request: HttpProbeRequest) => Promise<HttpProbeResponse>;

export interface IdorDifferentialDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'idor_differential_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly method?: 'GET' | 'HEAD';
  readonly resourceParamName: string;
  readonly baselineResourceId: string;
  readonly identityA: ProbeAuthContext;
  readonly identityB: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export type IdorDetectionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'comparison_failed'
  | 'promotion_blocked'
  | 'unexpected_failure';

export interface IdorDifferentialDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'idor_differential_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: IdorDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly baselineSnapshot?: SafeResponseSnapshot;
  readonly validationSnapshot?: SafeResponseSnapshot;
  readonly comparisonResult?: ResponseComparisonResult;
  readonly validationResult?: AuthorizedComparisonValidationResult;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone F4 — CORS Misconfiguration Detection Contracts
// ---------------------------------------------------------------------------

export type CorsDetectionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'comparison_failed'
  | 'promotion_blocked'
  | 'unexpected_failure';

export interface CorsMisconfigurationDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'cors_misconfiguration_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly method?: 'GET' | 'HEAD';
  readonly authContext?: ProbeAuthContext;
  readonly testOrigins?: readonly string[];
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface CorsMisconfigurationDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'cors_misconfiguration_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: CorsDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly reflectedOrigin?: string;
  readonly allowCredentials?: boolean;
  readonly baselineSnapshot?: SafeResponseSnapshot;
  readonly validationSnapshot?: SafeResponseSnapshot;
  readonly comparisonResult?: ResponseComparisonResult;
  readonly validationResult?: AuthorizedComparisonValidationResult;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone F4 — Parameter Reflection Detection Contracts
// ---------------------------------------------------------------------------

export type ParameterReflectionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'comparison_failed'
  | 'promotion_blocked'
  | 'unexpected_failure';

export interface ParameterReflectionDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'parameter_reflection_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly parameterName: string;
  readonly baselineValue?: string;
  readonly canaryPayload?: string;
  readonly method?: 'GET' | 'HEAD';
  readonly authContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface ParameterReflectionDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'parameter_reflection_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: ParameterReflectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly reflectedCanary?: string;
  readonly baselineSnapshot?: SafeResponseSnapshot;
  readonly validationSnapshot?: SafeResponseSnapshot;
  readonly comparisonResult?: ResponseComparisonResult;
  readonly validationResult?: AuthorizedComparisonValidationResult;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P2-1 — Security Header Detection Contracts
// ---------------------------------------------------------------------------

export type SecurityHeaderDetectionStatus =
  | 'potential_weakness'
  | 'secure_target_abstained'
  | 'pending_human_review'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface SecurityHeaderDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'security_header_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly method?: 'GET' | 'HEAD';
  readonly requiredHeaders?: readonly string[];
  readonly authContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SecurityHeaderDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'security_header_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SecurityHeaderDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly missingHeaders: readonly string[];
  readonly presentHeaders: readonly string[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P2-2 — Open Redirect Detection Contracts
// ---------------------------------------------------------------------------

export type OpenRedirectDetectionStatus =
  | 'exploit_confirmed'
  | 'potential_weakness'
  | 'secure_target_abstained'
  | 'pending_human_review'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface OpenRedirectDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'open_redirect_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly parameterName?: string;
  readonly testParameters?: readonly string[];
  readonly canaryDestination?: string;
  readonly method?: 'GET' | 'HEAD';
  readonly authContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface OpenRedirectDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'open_redirect_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: OpenRedirectDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly parameterName?: string;
  readonly injectedCanary?: string;
  readonly finalDestination?: string;
  readonly redirectChain?: readonly string[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P2-3 — Information Disclosure Detection Contracts
// ---------------------------------------------------------------------------

export type InformationDisclosureDetectionStatus =
  | 'potential_weakness'
  | 'secure_target_abstained'
  | 'pending_human_review'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface InformationDisclosureDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'information_disclosure_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly method?: 'GET' | 'HEAD';
  readonly authContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface DisclosedItem {
  readonly disclosureKind: 'stack_trace' | 'framework_version' | 'server_banner' | 'internal_path';
  readonly disclosedFragment: string;
  readonly trigger: string;
}

export interface InformationDisclosureDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'information_disclosure_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: InformationDisclosureDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly disclosures: readonly DisclosedItem[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P2-4 — Subdomain Takeover Detection Contracts
// ---------------------------------------------------------------------------

export type SubdomainTakeoverHostingProvider =
  | 'github_pages'
  | 'heroku'
  | 'aws_s3'
  | 'azure'
  | 'fastly'
  | 'netlify'
  | 'shopify'
  | 'unknown';

export type SubdomainTakeoverDetectionStatus =
  | 'vulnerability_detected'
  | 'potential_weakness'
  | 'secure_target_abstained'
  | 'pending_human_review'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface SubdomainTakeoverDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'subdomain_takeover_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly subdomain: string;
  readonly cnameTarget: string;
  readonly endpointUrl?: string;
  readonly hostingProvider?: SubdomainTakeoverHostingProvider;
  readonly authContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly coordinator?: TargetExecutionCoordinator;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SubdomainTakeoverDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'subdomain_takeover_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SubdomainTakeoverDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly subdomain: string;
  readonly cnameTarget: string;
  readonly hostingProvider: SubdomainTakeoverHostingProvider;
  readonly fingerprintMatch?: string;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P2-5 — TLS Configuration Analysis Contracts
// ---------------------------------------------------------------------------

export type TlsCertificateIssue = 'expired' | 'self_signed' | 'invalid_san';

export type TlsAnalysisStatus =
  | 'vulnerability_detected'
  | 'potential_weakness'
  | 'secure_target_abstained'
  | 'pending_human_review'
  | 'unexpected_failure';

export interface TlsConfigurationAnalysisRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'tls_configuration_analysis_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly targetHost: string;
  readonly port?: number;
  readonly tlsObservation: DiscoveredTlsObservation;
  readonly humanReviewDecision?: HumanReviewDecision;
}

export interface TlsConfigurationAnalysisResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'tls_configuration_analysis_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: TlsAnalysisStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly targetHost: string;
  readonly port: number;
  readonly weakProtocols: readonly string[];
  readonly weakCiphers: readonly string[];
  readonly certificateIssues: readonly TlsCertificateIssue[];
  readonly supportedTlsVersions: readonly string[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-1 — Authentication Bypass Detection Contracts
// ---------------------------------------------------------------------------

export type AuthBypassDetectionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'comparison_failed'
  | 'promotion_blocked'
  | 'unexpected_failure';

export interface AuthBypassDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'auth_bypass_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly method?: 'GET' | 'HEAD';
  readonly identityA: ProbeAuthContext;
  readonly bypassMechanism?: 'header_stripping' | 'cookie_omission' | 'verb_tampering';
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface AuthBypassDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'auth_bypass_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: AuthBypassDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly bypassMechanism: 'header_stripping' | 'cookie_omission' | 'verb_tampering';
  readonly similarityRatio?: number;
  readonly baselineSnapshot?: SafeResponseSnapshot;
  readonly validationSnapshot?: SafeResponseSnapshot;
  readonly comparisonResult?: ResponseComparisonResult;
  readonly validationResult?: AuthorizedComparisonValidationResult;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-3 — Sourcemap Exposure Detection Contracts
// ---------------------------------------------------------------------------

export type SourcemapExposureDetectionStatus =
  | 'potential_weakness'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface SourcemapExposureDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'sourcemap_exposure_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly sourceJsUrl: string;
  readonly exposedMapUrl?: string;
  readonly jsBodyText?: string;
  readonly jsHeaders?: Readonly<Record<string, string>>;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SourcemapExposureDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'sourcemap_exposure_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SourcemapExposureDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly sourceJsUrl: string;
  readonly exposedMapUrl?: string;
  readonly detectionSignal?: 'sourcemapping_url_comment' | 'sourcemap_header' | 'deterministic_path_probe';
  readonly mapFileSizeBytes?: number;
  readonly sampleSourcesCount?: number;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-4 — WordPress Surface Detection Contracts (XML-RPC & Users)
// ---------------------------------------------------------------------------

export type WordPressSurfaceDetectionStatus =
  | 'potential_weakness'
  | 'information_disclosure'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface WordPressSurfaceDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'wordpress_surface_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly targetBaseUrl: string;
  readonly probeKind?: 'all' | 'xmlrpc_capabilities' | 'rest_user_enumeration';
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface WordPressSurfaceDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'wordpress_surface_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: WordPressSurfaceDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly targetBaseUrl: string;
  readonly probeKind?: 'xmlrpc_capabilities' | 'rest_user_enumeration';
  readonly endpointUrl?: string;
  readonly xmlRpcMethodsExposed?: readonly string[];
  readonly multicallSupported?: boolean;
  readonly exposedUsersCount?: number;
  readonly sampleUserSlugs?: readonly string[];
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-5 — SQL Error Oracle Detection Contracts
// ---------------------------------------------------------------------------

export type SqlErrorOracleDetectionStatus =
  | 'potential_weakness'
  | 'information_disclosure'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface SqlErrorOracleDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'sql_error_oracle_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly parameterName: string;
  readonly method?: 'GET' | 'POST';
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SqlErrorOracleDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'sql_error_oracle_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SqlErrorOracleDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly parameterName: string;
  readonly databaseEngine?: 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown';
  readonly injectedProbe?: string;
  readonly errorFragment?: string;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-6 — GraphQL Surface Detection Contracts
// ---------------------------------------------------------------------------

export type GraphQLSurfaceDetectionStatus =
  | 'graphql_surface_detected'
  | 'security_misconfiguration'
  | 'information_disclosure'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface GraphQLSurfaceDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'graphql_surface_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly customPaths?: readonly string[];
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface GraphQLSurfaceDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'graphql_surface_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: GraphQLSurfaceDetectionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly introspectionEnabled: boolean;
  readonly batchingEnabled: boolean;
  readonly fieldSuggestionsEnabled: boolean;
  readonly discoveredRootTypes?: readonly string[];
  readonly suggestionLeak?: string;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-7 — JWT Algorithm Confusion Detection Contracts
// ---------------------------------------------------------------------------

export type JwtAlgorithmConfusionStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface JwtAlgorithmConfusionDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'jwt_algorithm_confusion_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly httpMethod?: 'GET' | 'POST' | 'HEAD';
  readonly identityAContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface JwtAlgorithmConfusionDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'jwt_algorithm_confusion_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: JwtAlgorithmConfusionStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly originalAlgorithm?: string;
  readonly manipulatedAlgorithm?: 'none' | 'None' | 'NONE';
  readonly probeMechanism?: 'signature_stripping' | 'alg_none_header';
  readonly baselineStatusCode?: number;
  readonly forgedStatusCode?: number;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-8 — Session Fixation Detection Contracts
// ---------------------------------------------------------------------------

export type SessionFixationStatus =
  | 'vulnerability_detected'
  | 'potential_weakness'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface SessionFixationDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'session_fixation_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly httpMethod?: 'GET' | 'POST' | 'HEAD';
  readonly sessionCookieName?: string;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface SessionFixationDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'session_fixation_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: SessionFixationStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly sessionCookieName: string;
  readonly fixedSessionId: string;
  readonly serverRegeneratedSession: boolean;
  readonly responseStatusCode?: number;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}

// ---------------------------------------------------------------------------
// Milestone P4-9 — Credentialed CORS Detection Upgrade Contracts
// ---------------------------------------------------------------------------

export type CredentialedCorsStatus =
  | 'vulnerability_detected'
  | 'pending_human_review'
  | 'secure_target_abstained'
  | 'preflight_denied'
  | 'unexpected_failure';

export interface CredentialedCorsDetectionRequest {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'credentialed_cors_detection_request';
  readonly detectionId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly endpointUrl: string;
  readonly httpMethod?: 'GET' | 'POST' | 'HEAD';
  readonly suppliedOrigin?: string;
  readonly identityAContext?: ProbeAuthContext;
  readonly reviewerPolicy?: ReviewerPolicy;
  readonly humanReviewDecision?: HumanReviewDecision;
  readonly triageDecision?: ReviewedEvidenceFindingCandidateTriageDecision;
  readonly transport?: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}

export interface CredentialedCorsDetectionResult {
  readonly contractVersion: DetectionContractVersion;
  readonly kind: 'credentialed_cors_detection_result';
  readonly detectionId: string;
  readonly scanId: string;
  readonly assessmentId: string;
  readonly authorizationGrantId: string;
  readonly authorizationDecisionId: string;
  readonly actorId: string;
  readonly status: CredentialedCorsStatus;
  readonly reasonCode: string;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly endpointUrl: string;
  readonly httpMethod: string;
  readonly suppliedOrigin: string;
  readonly reflectedOrigin: string;
  readonly allowCredentialsHeader: boolean;
  readonly acaoHeader: string;
  readonly responseStatusCode?: number;
  readonly evidenceDraft?: EvidenceDraftEnvelope;
  readonly evidenceRecord?: EvidenceRecord;
  readonly promotedEvidenceResult?: HumanReviewedEvidencePromotionResult;
  readonly findingCandidate?: ReviewedEvidenceFormalFindingCandidate;
  readonly finding?: Finding;
  readonly error?: {
    readonly code: string;
    readonly safeMessage: string;
  };
}











