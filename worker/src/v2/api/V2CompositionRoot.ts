import type { AssessmentRepository } from '../storage/AssessmentRepository.js';
import { InMemoryAssessmentRepository } from '../storage/InMemoryAssessmentRepository.js';
import type { FormalFindingCandidateRepository } from '../finding-candidate-promotion/FindingCandidatePersistenceContracts.js';
import { InMemoryFormalFindingCandidateRepository } from '../finding-candidate-promotion/InMemoryFormalFindingCandidateRepository.js';
import { V2AssessmentRuntime } from '../runtime/V2AssessmentRuntime.js';
import { AssessmentApplicationService } from '../application/AssessmentApplicationService.js';
import { DefensiveReportReadinessService } from '../reporting-boundary/DefensiveReportReadinessService.js';
import type { MinimalOrchestrator } from '../core/MinimalOrchestrator.js';
import type { EvidenceDraftRepository } from '../finding-candidate-draft/EvidenceDraftPersistenceContracts.js';
import { InMemoryEvidenceDraftRepository } from '../finding-candidate-draft/InMemoryEvidenceDraftRepository.js';

export interface V2CompositionDependencies {
  readonly assessmentRepository?: AssessmentRepository;
  readonly candidateRepository?: FormalFindingCandidateRepository;
  readonly draftRepository?: EvidenceDraftRepository;
  readonly orchestrator?: MinimalOrchestrator;
  readonly runtime?: V2AssessmentRuntime;
  readonly assessmentService?: AssessmentApplicationService;
  readonly reportService?: DefensiveReportReadinessService;
}

/**
 * V2CompositionRoot manages static dependency injection for the V2 defensive core.
 *
 * Defaults to in-memory repositories to ensure 100% database-free conformance (ADR-011),
 * while supporting external injection of Postgres adapters (e.g. from M59).
 */
export class V2CompositionRoot {
  public readonly assessmentRepository: AssessmentRepository;
  public readonly candidateRepository: FormalFindingCandidateRepository;
  public readonly draftRepository: EvidenceDraftRepository;
  public readonly runtime: V2AssessmentRuntime;
  public readonly assessmentService: AssessmentApplicationService;
  public readonly reportService: DefensiveReportReadinessService;

  constructor(deps: V2CompositionDependencies = {}) {
    this.assessmentRepository = deps.assessmentRepository ?? new InMemoryAssessmentRepository();
    this.candidateRepository = deps.candidateRepository ?? new InMemoryFormalFindingCandidateRepository();
    this.draftRepository = deps.draftRepository ?? new InMemoryEvidenceDraftRepository();
    this.runtime = deps.runtime ?? new V2AssessmentRuntime(this.assessmentRepository, deps.orchestrator);
    this.assessmentService = deps.assessmentService ?? new AssessmentApplicationService(this.runtime);
    this.reportService = deps.reportService ?? new DefensiveReportReadinessService(this.candidateRepository);
  }

  public static createDefault(): V2CompositionRoot {
    return new V2CompositionRoot();
  }

  public static withDependencies(deps: V2CompositionDependencies): V2CompositionRoot {
    return new V2CompositionRoot(deps);
  }
}
