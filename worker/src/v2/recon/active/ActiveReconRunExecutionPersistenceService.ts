import type { ActiveReconOriginRunRequest } from './ActiveReconOriginRunContracts.js';
import { runActiveReconOriginProbes } from './ActiveReconOriginRunService.js';
import type { ActiveReconDocumentProbeAdapters } from './ActiveReconDocumentProbeRunner.js';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';
import { persistActiveReconOriginRunResult } from './ActiveReconOriginRunPersistenceService.js';
import type { 
  ActiveReconRunExecutionPersistenceResult,
  ActiveReconRunExecutionPersistenceError 
} from './ActiveReconRunExecutionPersistenceContracts.js';

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
    let originRunResult;
    try {
      originRunResult = await runActiveReconOriginProbes(request, adapters);
    } catch (err: any) {
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
      status: 'failed', // Default to failed, update on success
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

    let savedRecord;
    try {
      savedRecord = await persistActiveReconOriginRunResult(originRunResult, repository);
    } catch (err: any) {
      if (err.message?.includes('Duplicate runId')) {
         // Might be a repository save failure but let's treat any failure from persistActiveReconOriginRunResult as persistence_failed, unless it specifically happens inside the repository.saveRun call. Actually persistActiveReconOriginRunResult does call saveRun.
      }
      baseResult.persistenceErrors.push({ code: 'persistence_failed', message: 'Active recon persistence failed safely.' });
      return baseResult;
    }

    if (!savedRecord) {
      baseResult.persistenceErrors.push({ code: 'repository_save_failed', message: 'Active recon repository save failed safely.' });
      return baseResult;
    }

    let reloadedRecord;
    try {
      reloadedRecord = await repository.getRun(savedRecord.runId);
    } catch (err: any) {
      baseResult.persistenceErrors.push({ code: 'repository_reloaded_invalid_record', message: 'Active recon repository returned an invalid record.' });
      return baseResult;
    }

    if (!reloadedRecord) {
      baseResult.persistenceErrors.push({ code: 'repository_reload_failed', message: 'Active recon repository reload failed safely.' });
      return baseResult;
    }

    baseResult.status = savedRecord.status;
    baseResult.persistedRecord = reloadedRecord;
    baseResult.reloadVerified = true;

    return baseResult;
  } catch (err: any) {
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
