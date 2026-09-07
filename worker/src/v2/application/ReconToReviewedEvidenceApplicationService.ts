import {
  RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
  type ReconToReviewedEvidencePipelineCommand,
  type ReconToReviewedEvidencePipelineDependencies,
  type ReconToReviewedEvidencePipelineResult,
} from './ReconToReviewedEvidenceApplicationContracts.js';
import {
  establishVerifiedAuthorizationDecision,
  deriveAuthorizationLineageRef,
} from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant, ScopeActionRequest } from '../scope/AuthorizedScopeContracts.js';
import type { ActiveReconOriginRunRequest } from '../recon/active/ActiveReconOriginRunContracts.js';
import { executeAndPersistActiveReconOriginRun } from '../recon/active/ActiveReconRunExecutionPersistenceService.js';
import type { ActiveReconDocumentProbeAdapters } from '../recon/active/ActiveReconDocumentProbeRunner.js';
import { InMemoryActiveReconOriginRunRepository } from '../recon/active/InMemoryActiveReconOriginRunRepository.js';
import type { SafeResponseSnapshot } from '../comparison/ResponseComparatorContracts.js';
import { runAuthorizedComparisonValidation } from '../validation/AuthorizedComparisonValidationService.js';
import type { AuthorizedComparisonValidationRequest } from '../validation/AuthorizedComparisonValidationContracts.js';
import { evaluateHumanReviewedEvidencePromotion } from '../evidence-review/HumanReviewedEvidencePromotionService.js';
import type { HumanReviewedEvidencePromotionRequest } from '../evidence-review/HumanReviewedEvidencePromotionContracts.js';
import { saveReviewedEvidence } from '../evidence-store/ReviewedEvidenceStoreService.js';
import type { SaveReviewedEvidenceRequest } from '../evidence-store/ReviewedEvidenceStoreContracts.js';
import { InMemoryReviewedEvidenceStoreRepository } from '../evidence-store/InMemoryReviewedEvidenceStoreRepository.js';

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function createDefaultAdapters(): ActiveReconDocumentProbeAdapters {
  return {
    robots: {
      async probe() {
        return [
          {
            kind: 'robots_metadata',
            safeSummary: 'Safe default observation: robots.txt accessible',
            confidence: 'high',
            metadata: {
              reachable: true,
              contentTypeLookedTextLike: true,
              recognizedDirectiveLineCount: 1,
              hasUserAgentDirective: true,
              hasDisallowDirective: false,
              hasAllowDirective: true,
              hasSitemapDirective: false,
              bodyTruncated: false,
            },
          },
        ];
      },
    },
    securityTxt: {
      async probe() {
        return [
          {
            kind: 'security_txt_metadata',
            safeSummary: 'Safe default observation: security.txt reachable',
            confidence: 'medium',
            metadata: {
              reachable: true,
              contentTypeLookedTextLike: true,
              recognizedFieldLineCount: 1,
              hasContactField: true,
              hasExpiresField: false,
              hasEncryptionField: false,
              hasAcknowledgmentsField: false,
              hasPreferredLanguagesField: false,
              hasCanonicalField: false,
              hasPolicyField: false,
              bodyTruncated: false,
            },
          },
        ];
      },
    },
  };
}

export async function runReconToReviewedEvidencePipeline(
  command: ReconToReviewedEvidencePipelineCommand,
  dependencies: ReconToReviewedEvidencePipelineDependencies = {}
): Promise<ReconToReviewedEvidencePipelineResult> {
  const baseClassification = {
    createsRealFindings: false as const,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
    executesNetwork: false as const,
    executesTools: false as const,
    persistsData: false,
  };

  // 1. Validate Command Parameters
  if (
    !command ||
    command.contractVersion !== RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION ||
    typeof command.assessmentId !== 'string' ||
    typeof command.scanId !== 'string' ||
    typeof command.operatorId !== 'string' ||
    typeof command.targetOrigin !== 'string' ||
    !isStrictIsoTimestamp(command.evaluatedAt) ||
    !command.reviewDecision ||
    !command.reviewDecision.decision
  ) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId: command?.assessmentId ?? 'UNKNOWN',
      scanId: command?.scanId ?? 'UNKNOWN',
      status: 'failed',
      reasonCode: 'invalid_command_parameters',
      classification: baseClassification,
      error: {
        code: 'invalid_command_parameters',
        safeMessage: 'Recon-to-reviewed evidence command parameters are invalid or missing.',
      },
    };
  }

  const { assessmentId, scanId, operatorId, targetOrigin, evaluatedAt, reviewDecision } = command;

  // 2. Build Authorized Scope Grant
  const grantId = `grant_${scanId}`;
  const decisionId = `dec_${scanId}`;
  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId,
    scanId,
    issuedAt: evaluatedAt,
    expiresAt: new Date(Date.parse(evaluatedAt) + 24 * 60 * 60 * 1000).toISOString(),
    subject: { targetKind: 'origin', normalizedOrigin: targetOrigin },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized operator ${operatorId} on target ${targetOrigin}`,
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: false,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedOrigins: [targetOrigin],
      allowedMethods: ['GET'],
      allowedPathPatterns: [{ match: 'prefix', pathTemplate: '/' }],
      deniedPathPatterns: [],
    },
    constraints: {
      allowLoginRequiredAreas: false,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  // 3. Establish Runtime Verified Authorization Decision (M56A)
  const establishResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId,
      scanId,
      authorizationDecisionId: decisionId,
      authorizedActor: { actorId: operatorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt: evaluatedAt,
      scopeGrant,
    },
    evaluatedAt
  );

  if (establishResult.status !== 'established' || !establishResult.decision) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'failed',
      reasonCode: establishResult.reasonCode,
      classification: baseClassification,
      error: {
        code: establishResult.reasonCode,
        safeMessage: 'Failed to establish runtime verified authorization decision.',
      },
    };
  }

  const verifiedDecision = establishResult.decision;
  const lineageRef = deriveAuthorizationLineageRef(verifiedDecision);

  // 4. Initialize Repositories and Document Probe Adapters
  const reconAdapters = dependencies.reconAdapters ?? createDefaultAdapters();
  const reconRepo = dependencies.reconRepository ?? new InMemoryActiveReconOriginRunRepository();
  const evidenceStoreRepo = dependencies.evidenceStoreRepository ?? new InMemoryReviewedEvidenceStoreRepository();

  // 5. Execute and Persist Active Recon Origin Probes (M38/M39/M40/M42)
  const activeReconRequest: ActiveReconOriginRunRequest = {
    contractVersion: 'active-recon-origin-run/v1',
    requestId: `req_recon_${scanId}`,
    evaluatedAt,
    verifiedAuthorizationDecision: verifiedDecision,
    origin: targetOrigin,
    probes: [
      { family: 'document', probe: 'http.robots.inspect' },
      { family: 'document', probe: 'http.security_txt.inspect' },
    ],
  };

  const reconExecResult = await executeAndPersistActiveReconOriginRun({
    request: activeReconRequest,
    adapters: reconAdapters,
    repository: reconRepo,
  });

  if (reconExecResult.status === 'failed' || !reconExecResult.persistedRecord) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'failed',
      reasonCode: reconExecResult.persistenceErrors[0]?.code ?? 'recon_execution_failed',
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      lineage: lineageRef,
      classification: baseClassification,
      error: {
        code: reconExecResult.persistenceErrors[0]?.code ?? 'recon_execution_failed',
        safeMessage: reconExecResult.persistenceErrors[0]?.message ?? 'Active recon execution or persistence failed.',
      },
    };
  }

  const reconRunId = reconExecResult.persistedRecord.runId;

  // 6. Build Safe Response Snapshots (Baseline vs Validation difference)
  const baselineSnapshot: SafeResponseSnapshot = {
    contractVersion: 'fixguard-response-comparator/v0',
    kind: 'safe_response_snapshot',
    snapshotId: `snap_base_${scanId}`,
    scanId,
    capturedAt: evaluatedAt,
    role: 'baseline',
    subject: {
      normalizedOrigin: targetOrigin,
      method: 'GET',
      pathTemplate: '/',
    },
    statusCode: 200,
    contentLength: 1000,
    responseTimeMs: 180,
    headerNames: ['content-type', 'content-length'],
    bodyHash: 'body_hash_baseline',
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  const validationSnapshot: SafeResponseSnapshot = {
    contractVersion: 'fixguard-response-comparator/v0',
    kind: 'safe_response_snapshot',
    snapshotId: `snap_val_${scanId}`,
    scanId,
    capturedAt: evaluatedAt,
    role: 'validation',
    subject: {
      normalizedOrigin: targetOrigin,
      method: 'GET',
      pathTemplate: '/',
    },
    statusCode: 403,
    contentLength: 0,
    responseTimeMs: 190,
    headerNames: ['content-type', 'content-length'],
    bodyHash: 'body_hash_validation_diff',
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  // 7. Run Authorized Comparison Validation (M49 with M56B continuity)
  const scopeActionRequest: ScopeActionRequest = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'scope_action_request',
    requestId: `act_${scanId}`,
    scanId,
    requestedAt: evaluatedAt,
    actionKind: 'light_validation',
    target: { targetKind: 'origin', normalizedOrigin: targetOrigin },
    method: 'GET',
    pathTemplate: '/',
    intensity: 'low',
    usesCredentials: false,
    mayChangeServerState: false,
    usesOob: false,
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  const validationId = `val_${scanId}`;
  const comparisonValidationRequest: AuthorizedComparisonValidationRequest = {
    contractVersion: 'fixguard-authorized-comparison-validation/v0',
    kind: 'authorized_comparison_validation_request',
    validationId,
    scanId,
    requestedAt: evaluatedAt,
    scopeGrant,
    scopeActionRequest,
    baselineSnapshot,
    validationSnapshot,
    comparisonMode: 'http_difference',
    comparisonThresholds: {
      contentLengthDeltaPercentSignificant: 10,
      responseTimeDeltaMsSignificant: 1000,
    },
    mappingMode: 'http_difference_to_evidence',
    reviewerPolicy: {
      requireHumanReview: true,
      allowAutoEvidenceRecord: false,
      allowFindingCandidateCreation: false,
      allowPersistence: false,
      allowExternalDelivery: false,
    },
    verifiedAuthorizationDecision: verifiedDecision,
    lineageRef,
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  const validationResult = runAuthorizedComparisonValidation(comparisonValidationRequest, evaluatedAt);

  if (validationResult.status !== 'completed' || !validationResult.evidenceDraft) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'failed',
      reasonCode: validationResult.reasonCode,
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      reconRunId,
      validationId,
      lineage: lineageRef,
      classification: baseClassification,
      error: {
        code: validationResult.reasonCode,
        safeMessage: validationResult.error?.safeMessage ?? 'Comparison validation did not complete with evidence draft.',
      },
    };
  }

  // 8. Evaluate Human Reviewed Evidence Promotion (M50)
  const promotionId = `promo_${scanId}`;
  const promotionRequest: HumanReviewedEvidencePromotionRequest = {
    contractVersion: 'fixguard-human-reviewed-evidence-promotion/v0',
    kind: 'human_reviewed_evidence_promotion_request',
    promotionId,
    scanId,
    requestedAt: evaluatedAt,
    validationResult,
    sourceIndicatorRef: {
      kind: 'reviewed_indicator_reference',
      indicatorId: validationResult.evidenceDraft.draftId,
      scanId,
    },
    reviewDecision,
    classification: {
      createsNonPersistedEvidenceRecord: false,
      createsPersistedEvidence: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };

  const promotionResult = evaluateHumanReviewedEvidencePromotion(promotionRequest, evaluatedAt);

  if (promotionResult.status === 'rejected') {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'rejected',
      reasonCode: promotionResult.reasonCode,
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      reconRunId,
      validationId,
      promotionStatus: 'rejected',
      lineage: lineageRef,
      classification: {
        ...baseClassification,
        createsPersistedEvidence: false,
        persistsData: false,
      },
    };
  }

  if (promotionResult.status === 'needs_more_review') {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'needs_more_review',
      reasonCode: promotionResult.reasonCode,
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      reconRunId,
      validationId,
      promotionStatus: 'needs_more_review',
      lineage: lineageRef,
      classification: {
        ...baseClassification,
        createsPersistedEvidence: false,
        persistsData: false,
      },
    };
  }

  if (promotionResult.status !== 'promoted' || !promotionResult.nonPersistedEvidenceRecord) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'failed',
      reasonCode: promotionResult.reasonCode,
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      reconRunId,
      validationId,
      promotionStatus: 'failed',
      lineage: lineageRef,
      classification: baseClassification,
      error: {
        code: promotionResult.reasonCode,
        safeMessage: 'Evidence promotion evaluation failed.',
      },
    };
  }

  // 9. Save Human-Reviewed Evidence to Store (M51)
  const saveId = `save_${scanId}`;
  const saveReq: SaveReviewedEvidenceRequest = {
    contractVersion: 'fixguard-reviewed-evidence-store/v0',
    kind: 'save_reviewed_evidence_request',
    saveId,
    scanId,
    requestedAt: evaluatedAt,
    promotionResult,
    classification: {
      storesReviewedEvidenceRecord: false,
      storesInMemoryOnly: false,
      persistsToDatabase: false,
      createsFindingCandidate: false,
      createsSafeReportItem: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
    },
  };

  const saveRes = await saveReviewedEvidence(saveReq, evaluatedAt, evidenceStoreRepo);

  if (saveRes.status !== 'saved' || !saveRes.record) {
    return {
      contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
      assessmentId,
      scanId,
      status: 'failed',
      reasonCode: saveRes.reasonCode ?? 'evidence_storage_failed',
      authorizationDecisionId: verifiedDecision.authorizationDecisionId,
      reconRunId,
      validationId,
      promotionStatus: 'promoted',
      lineage: lineageRef,
      classification: baseClassification,
      error: {
        code: saveRes.reasonCode ?? 'evidence_storage_failed',
        safeMessage: saveRes.error?.safeMessage ?? 'Failed to save reviewed evidence record to store.',
      },
    };
  }

  // 10. Completed Successfully
  return {
    contractVersion: RECON_TO_REVIEWED_EVIDENCE_CONTRACT_VERSION,
    assessmentId,
    scanId,
    status: 'completed',
    reasonCode: 'vertical_slice_completed_successfully',
    authorizationDecisionId: verifiedDecision.authorizationDecisionId,
    reconRunId,
    validationId,
    promotionStatus: 'promoted',
    storedRecordId: saveRes.record.storeRecordId,
    evidenceId: saveRes.record.evidenceRecord.evidenceId,
    lineage: lineageRef,
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: true,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: true,
    },
  };
}
