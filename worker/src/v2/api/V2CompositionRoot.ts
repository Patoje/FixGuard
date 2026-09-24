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
import type { OrchestratedAssessmentRepository } from '../application/OrchestratedAssessmentContracts.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import {
  OrchestratedAssessmentApplicationService,
  createAttackSurfaceQueryService,
} from '../application/OrchestratedAssessmentApplicationService.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import type { AttackSurfaceGraph } from '../attack-surface/AttackSurfaceContracts.js';
import type { AttackSurfaceQueryService } from '../attack-surface/AttackSurfaceQueryService.js';
import type { AttackPlanRepository } from '../attack-planning/AttackPlanRepository.js';
import { InMemoryAttackPlanRepository } from '../attack-planning/InMemoryAttackPlanRepository.js';
import { AttackPlanGeneratorService } from '../attack-planning/AttackPlanGeneratorService.js';
import { AttackAuthorizationService } from '../attack-authorization/AttackAuthorizationService.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import { AttackExecutionService } from '../attack-execution/AttackExecutionService.js';
import type { AttackChainRepository } from '../attack-chain/AttackChainRepository.js';
import { InMemoryAttackChainRepository } from '../attack-chain/InMemoryAttackChainRepository.js';
import { AttackChainService } from '../attack-chain/AttackChainService.js';
import type { PostExploitationRepository } from '../post-exploitation/PostExploitationRepository.js';
import { InMemoryPostExploitationRepository } from '../post-exploitation/InMemoryPostExploitationRepository.js';
import { CredentialVaultService } from '../post-exploitation/CredentialVaultService.js';
import { PostExploitationService } from '../post-exploitation/PostExploitationService.js';
import { LateralMovementService } from '../attack-planning/LateralMovementService.js';
import { ImpactAssessmentService } from '../reporting-boundary/ImpactAssessmentService.js';

export interface V2CompositionDependencies {
  readonly assessmentRepository?: AssessmentRepository;
  readonly candidateRepository?: FormalFindingCandidateRepository;
  readonly draftRepository?: EvidenceDraftRepository;
  readonly orchestrator?: MinimalOrchestrator;
  readonly runtime?: V2AssessmentRuntime;
  readonly assessmentService?: AssessmentApplicationService;
  readonly reportService?: DefensiveReportReadinessService;
  readonly orchestratedRepository?: OrchestratedAssessmentRepository;
  readonly orchestratedService?: OrchestratedAssessmentApplicationService;
  readonly availabilityService?: ReconToolAvailabilityService;
  readonly attackPlanRepository?: AttackPlanRepository;
  readonly attackPlanGenerator?: AttackPlanGeneratorService;
  readonly attackAuthorizationService?: AttackAuthorizationService;
  readonly attackCapabilityRegistry?: AttackCapabilityRegistry;
  readonly attackExecutionService?: AttackExecutionService;
  readonly attackChainRepository?: AttackChainRepository;
  readonly attackChainService?: AttackChainService;
  readonly postExploitationRepository?: PostExploitationRepository;
  readonly credentialVaultService?: CredentialVaultService;
  readonly postExploitationService?: PostExploitationService;
  readonly lateralMovementService?: LateralMovementService;
  readonly impactAssessmentService?: ImpactAssessmentService;
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
  public readonly orchestratedRepository: OrchestratedAssessmentRepository;
  public readonly orchestratedService: OrchestratedAssessmentApplicationService;
  public readonly availabilityService: ReconToolAvailabilityService;
  public readonly attackPlanRepository: AttackPlanRepository;
  public readonly attackPlanGenerator: AttackPlanGeneratorService;
  public readonly attackAuthorizationService: AttackAuthorizationService;
  public readonly attackCapabilityRegistry: AttackCapabilityRegistry;
  public readonly attackExecutionService: AttackExecutionService;
  public readonly attackChainRepository: AttackChainRepository;
  public readonly attackChainService: AttackChainService;
  public readonly postExploitationRepository: PostExploitationRepository;
  public readonly credentialVaultService: CredentialVaultService;
  public readonly postExploitationService: PostExploitationService;
  public readonly lateralMovementService: LateralMovementService;
  public readonly impactAssessmentService: ImpactAssessmentService;

  constructor(deps: V2CompositionDependencies = {}) {
    this.assessmentRepository = deps.assessmentRepository ?? new InMemoryAssessmentRepository();
    this.candidateRepository = deps.candidateRepository ?? new InMemoryFormalFindingCandidateRepository();
    this.draftRepository = deps.draftRepository ?? new InMemoryEvidenceDraftRepository();
    this.runtime = deps.runtime ?? new V2AssessmentRuntime(this.assessmentRepository, deps.orchestrator);
    this.assessmentService = deps.assessmentService ?? new AssessmentApplicationService(this.runtime);
    this.reportService = deps.reportService ?? new DefensiveReportReadinessService(this.candidateRepository);
    this.availabilityService = deps.availabilityService ?? new ReconToolAvailabilityService();
    this.attackPlanRepository = deps.attackPlanRepository ?? new InMemoryAttackPlanRepository();
    this.attackPlanGenerator = deps.attackPlanGenerator ?? new AttackPlanGeneratorService();
    this.attackAuthorizationService =
      deps.attackAuthorizationService ?? new AttackAuthorizationService(this.attackPlanRepository);
    this.attackCapabilityRegistry =
      deps.attackCapabilityRegistry ?? AttackCapabilityRegistry.createDefault();
    this.attackChainRepository = deps.attackChainRepository ?? new InMemoryAttackChainRepository();
    this.attackChainService =
      deps.attackChainService ?? new AttackChainService(this.attackChainRepository);
    this.postExploitationRepository =
      deps.postExploitationRepository ?? new InMemoryPostExploitationRepository();
    this.credentialVaultService =
      deps.credentialVaultService ?? new CredentialVaultService();
    this.postExploitationService =
      deps.postExploitationService ??
      new PostExploitationService(
        this.postExploitationRepository,
        this.credentialVaultService
      );
    this.attackExecutionService =
      deps.attackExecutionService ??
      new AttackExecutionService({
        planRepository: this.attackPlanRepository,
        capabilityRegistry: this.attackCapabilityRegistry,
        postExploitationService: this.postExploitationService,
      });
    this.lateralMovementService =
      deps.lateralMovementService ?? new LateralMovementService();
    this.impactAssessmentService =
      deps.impactAssessmentService ?? new ImpactAssessmentService();
    this.orchestratedRepository =
      deps.orchestratedRepository ?? new InMemoryOrchestratedAssessmentRepository();
    this.orchestratedService =
      deps.orchestratedService ??
      new OrchestratedAssessmentApplicationService({
        repository: this.orchestratedRepository,
        availabilityService: this.availabilityService,
        attackPlanRepository: this.attackPlanRepository,
        attackPlanGenerator: this.attackPlanGenerator,
        attackChainRepository: this.attackChainRepository,
        attackChainService: this.attackChainService,
        postExploitationRepository: this.postExploitationRepository,
        credentialVaultService: this.credentialVaultService,
        postExploitationService: this.postExploitationService,
        lateralMovementService: this.lateralMovementService,
        impactAssessmentService: this.impactAssessmentService,
      });
  }

  /** Milestone A2 — bind a query service to an immutable Attack Surface Graph. */
  public createAttackSurfaceQueryService(graph: AttackSurfaceGraph): AttackSurfaceQueryService {
    return createAttackSurfaceQueryService(graph);
  }

  public static createDefault(): V2CompositionRoot {
    return new V2CompositionRoot();
  }

  public static withDependencies(deps: V2CompositionDependencies): V2CompositionRoot {
    return new V2CompositionRoot(deps);
  }
}
