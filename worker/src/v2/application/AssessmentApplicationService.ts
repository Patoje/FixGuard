import type { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime';
import type { AssessmentState } from '../runtime/AssessmentState';
import type { Finding } from '../core/Evidence';
import type { AttackRecommendation } from '../intelligence/AttackRecommendation';
import type { 
  CreateAssessmentCommand, 
  StartInitialReconCommand, 
  LoadAssessmentQuery, 
  ApproveRecommendationCommand, 
  RejectRecommendationCommand, 
  CompleteAssessmentCommand, 
  AssessmentSummaryDto, 
  AssessmentDetailsDto,
  SafeFindingSummaryDto,
  SafeRecommendationSummaryDto
} from './ApplicationDtos';

export class AssessmentApplicationService {
  constructor(private readonly runtime: V2AssessmentRuntime) {}

  public async createAssessment(command: CreateAssessmentCommand): Promise<AssessmentSummaryDto> {
    const session = await this.runtime.createSession(command.targetUri);
    return this.toAssessmentSummaryDto(session.getState());
  }

  public async startInitialRecon(command: StartInitialReconCommand): Promise<AssessmentDetailsDto> {
    const state = await this.runtime.startInitialRecon(command.sessionId);
    return this.toAssessmentDetailsDto(state);
  }

  public async loadAssessment(query: LoadAssessmentQuery): Promise<AssessmentDetailsDto | null> {
    const session = await this.runtime.loadSession(query.sessionId);
    if (!session) {
      return null;
    }
    return this.toAssessmentDetailsDto(session.getState());
  }

  public async approveRecommendation(command: ApproveRecommendationCommand): Promise<AssessmentDetailsDto> {
    const state = await this.runtime.approveRecommendation(
      command.sessionId,
      command.recommendationId,
      command.operatorId
    );
    return this.toAssessmentDetailsDto(state);
  }

  public async rejectRecommendation(command: RejectRecommendationCommand): Promise<AssessmentDetailsDto> {
    const state = await this.runtime.rejectRecommendation(
      command.sessionId,
      command.recommendationId,
      command.operatorId,
      command.reason
    );
    return this.toAssessmentDetailsDto(state);
  }

  public async completeAssessment(command: CompleteAssessmentCommand): Promise<AssessmentSummaryDto> {
    const state = await this.runtime.completeSession(command.sessionId);
    return this.toAssessmentSummaryDto(state);
  }

  // ---------------------------------------------------------
  // Safe DTO Mappers
  // ---------------------------------------------------------

  private toAssessmentSummaryDto(state: AssessmentState): AssessmentSummaryDto {
    return {
      sessionId: state.sessionId,
      targetUri: state.targetUri,
      lifecycleStatus: state.lifecycleStatus,
      version: state.version,
      createdAt: state.timestamps.created,
      updatedAt: state.timestamps.lastUpdated,
      evidenceCount: state.evidenceCollections.length,
      pendingRecommendationCount: state.pendingRecommendations.length,
      approvedRequestCount: state.approvedRequestRecords.length,
      executionFailureCount: state.executionFailures.length,
      auditEntryCount: state.auditEntries.length,
    };
  }

  private toAssessmentDetailsDto(state: AssessmentState): AssessmentDetailsDto {
    const findings: SafeFindingSummaryDto[] = [];
    for (const ec of state.evidenceCollections) {
      for (const finding of ec.findings) {
        findings.push(this.toSafeFindingSummaryDto(finding));
      }
    }

    const pendingRecommendations: SafeRecommendationSummaryDto[] = state.pendingRecommendations.map(
      r => this.toSafeRecommendationSummaryDto(r)
    );

    return {
      ...this.toAssessmentSummaryDto(state),
      findings,
      pendingRecommendations,
      errors: [...state.errors]
    };
  }

  private toSafeFindingSummaryDto(finding: Finding): SafeFindingSummaryDto {
    return {
      id: finding.id,
      type: finding.type,
      severity: finding.severity,
      title: finding.title,
      target: finding.target,
      confidence: finding.confidence
    };
  }

  private toSafeRecommendationSummaryDto(recommendation: AttackRecommendation): SafeRecommendationSummaryDto {
    return {
      id: recommendation.id,
      capability: recommendation.capability,
      targetUri: recommendation.targetContext.uri,
      rationale: recommendation.rationale,
      riskLevel: recommendation.severity
    };
  }
}
