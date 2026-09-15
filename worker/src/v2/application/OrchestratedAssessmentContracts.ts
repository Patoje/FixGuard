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
  readonly pendingEvidenceDrafts?: readonly EvidenceDraftEnvelope[];
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
  readonly pendingEvidenceDrafts?: readonly EvidenceDraftEnvelope[];
  readonly recommendations: readonly TargetRecommendation[];
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timing: OrchestratedAssessmentTiming;
  readonly error?: string;
}

export interface OrchestratedAssessmentRepository {
  save(record: OrchestratedAssessmentRecord): Promise<void>;
  findById(assessmentId: string): Promise<OrchestratedAssessmentRecord | null>;
  update(
    assessmentId: string,
    updater: (prev: OrchestratedAssessmentRecord) => OrchestratedAssessmentRecord
  ): Promise<OrchestratedAssessmentRecord>;
}
