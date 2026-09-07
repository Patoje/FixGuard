import { deriveAuthorizationLineageRef } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import type { ActiveReconOriginRunRequest } from './ActiveReconOriginRunContracts.js';
import { runActiveReconOriginProbes } from './ActiveReconOriginRunService.js';
import type { ActiveReconDocumentProbeAdapters } from './ActiveReconDocumentProbeRunner.js';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';
import { constructActiveReconOriginRunRecord, validatePersistedActiveReconRecord } from './ActiveReconOriginRunPersistenceService.js';
import type { PersistedActiveReconRunRecord, PersistedDocumentProbeRunItem, PersistedActiveReconRunError } from './ActiveReconOriginRunPersistenceContracts.js';
import type { SafeActiveReconObservation, SafeRobotsTxtMetadata, SafeSecurityTxtMetadata } from './ActiveReconContracts.js';
import type {
  ActiveReconRunExecutionPersistenceResult,
  ActiveReconRunExecutionPersistenceError,
  ActiveReconReloadVerificationResult
} from './ActiveReconRunExecutionPersistenceContracts.js';

function verifyObservations(saved: SafeActiveReconObservation[], reloaded: SafeActiveReconObservation[]): boolean {
  if (saved.length !== reloaded.length) return false;
  for (let i = 0; i < saved.length; i++) {
    const s = saved[i];
    const r = reloaded[i];
    if (s.kind !== r.kind) return false;
    if (s.safeSummary !== r.safeSummary) return false;
    if (s.confidence !== r.confidence) return false;
    if (s.kind === 'robots_metadata' && r.kind === 'robots_metadata') {
      const sm = s.metadata as SafeRobotsTxtMetadata | undefined;
      const rm = r.metadata as SafeRobotsTxtMetadata | undefined;
      if (!!sm !== !!rm) return false;
      if (sm && rm) {
        if (sm.reachable !== rm.reachable) return false;
        if (sm.contentTypeLookedTextLike !== rm.contentTypeLookedTextLike) return false;
        if (sm.recognizedDirectiveLineCount !== rm.recognizedDirectiveLineCount) return false;
        if (sm.hasUserAgentDirective !== rm.hasUserAgentDirective) return false;
        if (sm.hasDisallowDirective !== rm.hasDisallowDirective) return false;
        if (sm.hasAllowDirective !== rm.hasAllowDirective) return false;
        if (sm.hasSitemapDirective !== rm.hasSitemapDirective) return false;
        if (sm.bodyTruncated !== rm.bodyTruncated) return false;
      }
    } else if (s.kind === 'security_txt_metadata' && r.kind === 'security_txt_metadata') {
      const sm = s.metadata as SafeSecurityTxtMetadata | undefined;
      const rm = r.metadata as SafeSecurityTxtMetadata | undefined;
      if (!!sm !== !!rm) return false;
      if (sm && rm) {
        if (sm.reachable !== rm.reachable) return false;
        if (sm.contentTypeLookedTextLike !== rm.contentTypeLookedTextLike) return false;
        if (sm.recognizedFieldLineCount !== rm.recognizedFieldLineCount) return false;
        if (sm.hasContactField !== rm.hasContactField) return false;
        if (sm.hasExpiresField !== rm.hasExpiresField) return false;
        if (sm.hasEncryptionField !== rm.hasEncryptionField) return false;
        if (sm.hasAcknowledgmentsField !== rm.hasAcknowledgmentsField) return false;
        if (sm.hasPreferredLanguagesField !== rm.hasPreferredLanguagesField) return false;
        if (sm.hasCanonicalField !== rm.hasCanonicalField) return false;
        if (sm.hasPolicyField !== rm.hasPolicyField) return false;
        if (sm.bodyTruncated !== rm.bodyTruncated) return false;
      }
    } else {
      return false; // Mismatched kinds
    }
  }
  return true;
}

function verifyErrors(saved: PersistedActiveReconRunError[], reloaded: PersistedActiveReconRunError[]): boolean {
  if (saved.length !== reloaded.length) return false;
  for (let i = 0; i < saved.length; i++) {
    if (saved[i].code !== reloaded[i].code) return false;
    if (saved[i].message !== reloaded[i].message) return false;
  }
  return true;
}

function verifyItems(saved: PersistedDocumentProbeRunItem[], reloaded: PersistedDocumentProbeRunItem[]): boolean {
  if (saved.length !== reloaded.length) return false;
  for (let i = 0; i < saved.length; i++) {
    const s = saved[i];
    const r = reloaded[i];
    if (s.itemVersion !== r.itemVersion) return false;
    if (s.family !== r.family) return false;
    if (s.safeProbeIndex !== r.safeProbeIndex) return false;
    if (s.safeKind !== r.safeKind) return false;
    if (s.status !== r.status) return false;
    if (s.target.normalizedOrigin !== r.target.normalizedOrigin) return false;
    if (s.target.safeDisplayUrl !== r.target.safeDisplayUrl) return false;
    if (!verifyObservations(s.observations, r.observations)) return false;
    if (!!s.error !== !!r.error) return false;
    if (s.error && r.error) {
      if (s.error.code !== r.error.code) return false;
      if (s.error.message !== r.error.message) return false;
    }
  }
  return true;
}

export function verifyReloadedActiveReconRecord(
  saved: PersistedActiveReconRunRecord,
  reloaded: PersistedActiveReconRunRecord
): ActiveReconReloadVerificationResult {
  if (saved.recordVersion !== reloaded.recordVersion) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.runId !== reloaded.runId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.recordKind !== reloaded.recordKind) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.status !== reloaded.status) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (saved.subject.kind !== reloaded.subject.kind) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.subject.normalizedOrigin !== reloaded.subject.normalizedOrigin) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (saved.counts.requested !== reloaded.counts.requested) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.counts.planned !== reloaded.counts.planned) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.counts.completed !== reloaded.counts.completed) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.counts.blocked !== reloaded.counts.blocked) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.counts.candidate !== reloaded.counts.candidate) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.counts.failed !== reloaded.counts.failed) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (saved.classification.finding !== reloaded.classification.finding) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.classification.evidence !== reloaded.classification.evidence) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.classification.vulnerability !== reloaded.classification.vulnerability) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.classification.riskClaim !== reloaded.classification.riskClaim) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (!verifyItems(saved.items as PersistedDocumentProbeRunItem[], reloaded.items as PersistedDocumentProbeRunItem[])) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (!verifyObservations(saved.observations, reloaded.observations)) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (!verifyErrors(saved.runErrors, reloaded.runErrors)) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (saved.createdAt !== reloaded.createdAt) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.updatedAt !== reloaded.updatedAt) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if (saved.provenance.sourceBoundary !== reloaded.provenance.sourceBoundary) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.provenance.sourceContractVersion !== reloaded.provenance.sourceContractVersion) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  if (saved.provenance.persistedBy !== reloaded.provenance.persistedBy) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };

  if ('authorizationSource' in saved.provenance) {
    if (!('authorizationSource' in reloaded.provenance)) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.authorizationSource !== reloaded.provenance.authorizationSource) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.assessmentId !== reloaded.provenance.assessmentId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.scanId !== reloaded.provenance.scanId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.authorizationGrantId !== reloaded.provenance.authorizationGrantId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.authorizationDecisionId !== reloaded.provenance.authorizationDecisionId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
    if (saved.provenance.actorId !== reloaded.provenance.actorId) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  } else {
    if ('authorizationSource' in reloaded.provenance) return { status: 'mismatch', reasonCode: 'repository_reload_mismatch' };
  }

  return { status: 'verified' };
}

export async function executeAndPersistActiveReconOriginRun({
  request,
  adapters,
  repository,
}: {
  request: ActiveReconOriginRunRequest;
  adapters: ActiveReconDocumentProbeAdapters;
  repository: ActiveReconRunRepository;
}): Promise<ActiveReconRunExecutionPersistenceResult> {
  try {
    const trustedRequest = request;

    let originRunResult;
    try {
      originRunResult = await runActiveReconOriginProbes(trustedRequest, adapters);
    } catch (error: unknown) {
      return {
        contractVersion: 'active-recon-run-execution-persistence/v0',
        status: 'failed',
        originRun: null,
        persistedRecord: null,
        reloadVerified: false,
        counts: { requested: 0, planned: 0, completed: 0, blocked: 0, candidate: 0, failed: 0 },
        runErrors: [],
        persistenceErrors: [{ code: 'origin_run_failed', message: 'Active recon origin run failed safely.' }],
        classification: { finding: false, evidence: false, vulnerability: false, riskClaim: false }
      };
    }

    const baseResult: ActiveReconRunExecutionPersistenceResult = {
      contractVersion: 'active-recon-run-execution-persistence/v0',
      status: 'failed',
      originRun: {
        runId: originRunResult.runId,
        normalizedOrigin: originRunResult.normalizedOrigin,
        status: originRunResult.status,
      },
      persistedRecord: null,
      reloadVerified: false,
      counts: {
        requested: originRunResult.requestedProbeCount,
        planned: originRunResult.plannedProbeCount,
        completed: originRunResult.completedProbeCount,
        blocked: originRunResult.blockedProbeCount,
        candidate: originRunResult.candidateProbeCount,
        failed: originRunResult.failedProbeCount,
      },
      runErrors: originRunResult.runErrors || [],
      persistenceErrors: [],
      classification: { finding: false, evidence: false, vulnerability: false, riskClaim: false }
    };

    if (originRunResult.disposition === 'authorization_denied' || originRunResult.disposition === 'preflight_denied') {
      baseResult.persistenceErrors.push({ code: 'preflight_denied_no_persistence', message: 'Run was denied during preflight; no persistence.' });
      return baseResult;
    }

    const verifiedDecision = trustedRequest.verifiedAuthorizationDecision;
    const authLineage = deriveAuthorizationLineageRef(verifiedDecision);
    const authorizationLineageProvenance = {
      authorizationDecisionId: authLineage.authorizationDecisionId,
      authorizationGrantId: authLineage.authorizationGrantId,
      assessmentId: authLineage.assessmentId,
      scanId: authLineage.scanId,
      actorId: authLineage.actorId,
    };

    let localRecord;

    try {
      localRecord = constructActiveReconOriginRunRecord(
        originRunResult,
        authorizationLineageProvenance
      );
    } catch (error: unknown) {
      baseResult.persistenceErrors.push({ code: 'persistence_failed', message: 'Active recon local record construction failed.' });
      return baseResult;
    }

    const localValidation = validatePersistedActiveReconRecord(localRecord);
    if (localValidation.status !== 'valid_v1' && localValidation.status !== 'valid_v0_legacy') {
      baseResult.persistenceErrors.push({ code: 'persistence_record_invalid', message: 'Active recon local persistence validation failed safely.' });
      return baseResult;
    }

    let savedRecord;
    try {
      savedRecord = await repository.saveRun(localRecord);
    } catch (error: unknown) {
      baseResult.persistenceErrors.push({ code: 'repository_save_failed', message: 'Active recon repository save failed safely.' });
      return baseResult;
    }

    if (!savedRecord) {
      baseResult.persistenceErrors.push({ code: 'repository_save_failed', message: 'Active recon repository save failed safely.' });
      return baseResult;
    }

    const savedValidation = validatePersistedActiveReconRecord(savedRecord);
    if (savedValidation.status === 'invalid') {
       baseResult.persistenceErrors.push({ code: 'repository_save_result_invalid', message: 'Repository returned invalid saved record.' });
       return baseResult;
    }

    const saveVerification = verifyReloadedActiveReconRecord(localRecord, savedValidation.record);
    if (saveVerification.status !== 'verified') {
      baseResult.persistenceErrors.push({ code: 'repository_save_result_mismatch', message: 'Repository save result mismatch.' });
      return baseResult;
    }

    let reloadedRecord;
    try {
      reloadedRecord = await repository.getRun(savedValidation.record.runId);
    } catch (error: unknown) {
      baseResult.persistenceErrors.push({ code: 'repository_reload_failed', message: 'Active recon repository returned an invalid record.' });
      return baseResult;
    }

    if (!reloadedRecord) {
      baseResult.persistenceErrors.push({ code: 'repository_reload_missing', message: 'Active recon repository reload failed safely (missing).' });
      return baseResult;
    }

    const reloadedValidation = validatePersistedActiveReconRecord(reloadedRecord);
    if (reloadedValidation.status === 'invalid') {
      baseResult.persistenceErrors.push({ code: 'repository_reload_invalid', message: 'Reloaded record failed runtime validation.' });
      return baseResult;
    }

    const verification = verifyReloadedActiveReconRecord(savedValidation.record, reloadedValidation.record);
    if (verification.status !== 'verified') {
      baseResult.persistenceErrors.push({ code: 'repository_reload_mismatch', message: 'Repository reload mismatch.' });
      return baseResult;
    }

    baseResult.status = savedValidation.record.status;
    baseResult.persistedRecord = reloadedValidation.record;
    baseResult.reloadVerified = true;

    return baseResult;
  } catch (error: unknown) {
    return {
      contractVersion: 'active-recon-run-execution-persistence/v0',
      status: 'failed',
      originRun: null,
      persistedRecord: null,
      reloadVerified: false,
      counts: { requested: 0, planned: 0, completed: 0, blocked: 0, candidate: 0, failed: 0 },
      runErrors: [],
      persistenceErrors: [{ code: 'unexpected_execution_persistence_failure', message: 'Unexpected active recon execution persistence failure.' }],
      classification: { finding: false, evidence: false, vulnerability: false, riskClaim: false }
    };
  }
}
