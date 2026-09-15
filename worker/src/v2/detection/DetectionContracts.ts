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

export interface HttpProbeRequest {
  readonly url: string;
  readonly method: 'GET' | 'HEAD';
  readonly headers: Readonly<Record<string, string>>;
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




