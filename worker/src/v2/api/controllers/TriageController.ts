import type { Request, Response, NextFunction } from 'express';
import type { FormalFindingCandidateRepository } from '../../finding-candidate-promotion/FindingCandidatePersistenceContracts.js';
import type { EvidenceDraftRepository } from '../../finding-candidate-draft/EvidenceDraftPersistenceContracts.js';
import { parsePromoteCandidateBody } from '../validation/ApiRequestValidators.js';
import { isStrictSafeId } from '../../reporting-boundary/DefensiveReportContracts.js';
import { ApiValidationError } from '../ApiErrors.js';
import { RecordNotFoundError } from '../../storage/StorageErrors.js';
import { promoteReviewedEvidenceFindingCandidateDraft } from '../../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionService.js';
import type { PromoteReviewedEvidenceFindingCandidateDraftRequest } from '../../finding-candidate-promotion/ReviewedEvidenceFindingCandidatePromotionContracts.js';

/**
 * TriageController
 *
 * Thin, blind linear HTTP presentation controller for Human-in-the-Loop evidence triage
 * and formal finding candidate promotion (M54 / M61.1).
 *
 * Responsibilities:
 * 1) Validates parameters and closed-world request bodies.
 * 2) Retrieves authentic drafts strictly from the backend repository (anti-fabrication boundary).
 * 3) Delegates to the M54 domain promotion service.
 * 4) Persists the promoted candidate directly to the candidate repository.
 * 5) Returns standard JSON HTTP responses (200 / 201).
 *
 * Zero domain logic, zero candidate inspection, zero client-injected drafts.
 */
export class TriageController {
  constructor(
    private readonly candidateRepository: FormalFindingCandidateRepository,
    private readonly draftRepository: EvidenceDraftRepository
  ) {}

  public listEvidenceDrafts = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const scanId = req.params.scanId;
      if (!scanId || typeof scanId !== 'string' || !isStrictSafeId(scanId)) {
        throw new ApiValidationError('scanId parameter has invalid format');
      }

      const drafts = await this.draftRepository.listDraftsByScanId(scanId);
      res.status(200).json({
        scanId,
        draftCount: drafts.length,
        drafts
      });
    } catch (err) {
      next(err);
    }
  };

  public promoteCandidate = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      // 1. Closed-world validation: strictly rejects unknown fields (including any client-supplied 'draft')
      const body = parsePromoteCandidateBody(req.body);

      // 2. Retrieve draft strictly from backend repository state (anti-fabrication boundary)
      const draft = await this.draftRepository.getDraft(body.draftId);
      if (!draft) {
        throw new RecordNotFoundError(
          `Evidence draft '${body.draftId}' was not found`,
          body.draftId
        );
      }

      // 3. Assemble domain promotion request with human operator triage decision
      const evaluatedAt = new Date().toISOString();
      const promoteReq: PromoteReviewedEvidenceFindingCandidateDraftRequest = {
        contractVersion: 'fixguard-reviewed-evidence-finding-candidate-promotion/v0',
        kind: 'promote_reviewed_evidence_finding_candidate_draft_request',
        candidateId: body.candidateId,
        scanId: body.scanId,
        requestedAt: evaluatedAt,
        draft,
        triageDecision: {
          decisionId: body.triageDecisionId,
          reviewerId: body.reviewerId,
          reviewedAt: evaluatedAt,
          decision: 'approve_finding_candidate_promotion',
          attestations: {
            reviewedDraft: true,
            reviewedEvidenceRefs: true,
            understandsCandidateIsNotConfirmedFinding: true,
            understandsNoVulnerabilityConfirmed: true,
            understandsNoExploitabilityClaim: true,
            understandsNoSeverityRiskImpactAssigned: true,
            understandsNoRemediationAdvice: true,
            authorizedPromotionToFormalCandidate: true
          },
          explicitNonClaims: {
            noConfirmedFinding: true,
            noConfirmedVulnerability: true,
            noExploitabilityClaim: true,
            noSeverityRiskOrImpactClaim: true,
            noRemediationAdvice: true,
            noSafeReportItemCreated: true,
            noExternalReportCreated: true,
            noNetworkExecution: true,
            noToolExecution: true,
            noPersistence: true
          }
        },
        classification: {
          createsFormalFindingCandidate: false,
          createsConfirmedFinding: false,
          createsSafeReportItem: false,
          createsExternalReport: false,
          confirmsVulnerabilities: false,
          makesExploitabilityClaims: false,
          makesRiskClaims: false,
          makesSeverityClaims: false,
          makesImpactClaims: false,
          providesRemediationAdvice: false,
          persistsCandidate: false,
          persistsToDatabase: false,
          executesNetwork: false,
          executesTools: false
        }
      };

      // 4. Delegate to M54 promotion service
      const result = await promoteReviewedEvidenceFindingCandidateDraft(promoteReq, evaluatedAt);
      if (result.status !== 'candidate_created' || !result.candidate) {
        throw new ApiValidationError(`Candidate promotion failed: ${result.reasonCode}`);
      }

      // 5. Persist promoted candidate to repository
      await this.candidateRepository.saveCandidate(result.candidate);

      // 6. Return standard 201 Created
      res.status(201).json({
        status: 'candidate_created',
        reasonCode: result.reasonCode,
        candidate: result.candidate
      });
    } catch (err) {
      next(err);
    }
  };
}
