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
  readonly detectionKind: 'cors_misconfiguration' | 'parameter_reflection' | 'idor_access_control' | 'missing_security_headers' | 'open_redirect' | 'information_disclosure' | 'custom_difference';
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
  readonly error?: string;
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
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timing: OrchestratedAssessmentTiming;
  readonly error?: string;
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
  update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord>;
}

