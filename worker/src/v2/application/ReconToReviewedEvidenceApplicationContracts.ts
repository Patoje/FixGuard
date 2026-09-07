import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import type { ActiveReconRunRepository } from '../recon/active/ActiveReconOriginRunRepository.js';
import type { ReviewedEvidenceStoreRepository } from '../evidence-store/ReviewedEvidenceStoreContracts.js';

export const RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION = 'recon-to-reviewed-evidence/v1';

export interface ReconToReviewedEvidencePipelineCommand {
  contractVersion: typeof RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION;
  assessmentId: string;
  scanId: string;
  operatorId: string;
  targetOrigin: string; // e.g., 'https://example.com'
  evaluatedAt: string; // ISO-8601 UTC
  reviewDecision: {
    decision: 'approve_evidence' | 'reject' | 'needs_more_review';
    reviewerId: string;
    reviewedAt: string;
  };
}

export interface ReconToReviewedEvidencePipelineDependencies {
  reconAdapters?: ActiveReconDocumentProbeAdapters;
  reconRepository?: ActiveReconRunRepository;
  evidenceStoreRepository?: ReviewedEvidenceStoreRepository;
}

export interface ReconToReviewedEvidencePipelineResult {
  contractVersion: typeof RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION;
  assessmentId: string;
  scanId: string;
  status: 'completed' | 'rejected' | 'needs_more_review' | 'failed';
  reasonCode: string;
  authorizationDecisionId?: string;
  reconRunId?: string;
  validationId?: string;
  promotionStatus?: 'promoted' | 'rejected' | 'needs_more_review' | 'failed';
  storedRecordId?: string;
  evidenceId?: string;
  lineage?: {
    assessmentId: string;
    scanId: string;
    authorizationDecisionId: string;
    authorizationGrantId: string;
    actorId: string;
  };
  classification: {
    readonly createsRealFindings: false;
    readonly createsPersistedEvidence: boolean;
    readonly confirmsVulnerabilities: false;
    readonly makesRiskClaims: false;
    readonly makesSeverityClaims: false;
    readonly makesImpactClaims: false;
    readonly executesNetwork: false;
    readonly executesTools: false;
    readonly persistsData: boolean;
  };
  error?: {
    code: string;
    safeMessage: string;
  };
}
