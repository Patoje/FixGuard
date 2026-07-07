import type { 
  StartAuthorizedActiveReconRunCommand,
  ListActiveReconRunSummariesQuery,
  GetActiveReconRunDetailQuery,
  BuildActiveReconRunSafeReportQuery,
  StartAuthorizedActiveReconRunResult,
  ListActiveReconRunSummariesResult,
  GetActiveReconRunDetailResult,
  BuildActiveReconRunSafeReportResult,
  ActiveReconApplicationUseCasesContractVersion
} from './ActiveReconApplicationUseCaseContracts.js';

import { executeAndPersistActiveReconOriginRun } from './ActiveReconRunExecutionPersistenceService.js';
import { listActiveReconRunSummaryViews, getActiveReconRunDetailView } from './ActiveReconRunReadModelService.js';
import { buildActiveReconRunSafeReportSnapshot } from './ActiveReconRunSafeReportService.js';

import type { ActiveReconDocumentProbeAdapters } from './ActiveReconDocumentProbeRunner.js';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';
import type { ActiveReconOriginRunRequest } from './ActiveReconOriginRunContracts.js';

export async function startAuthorizedActiveReconRun({
  command,
  adapters,
  repository
}: {
  command: StartAuthorizedActiveReconRunCommand;
  adapters: ActiveReconDocumentProbeAdapters;
  repository: ActiveReconRunRepository;
}): Promise<StartAuthorizedActiveReconRunResult> {
  const version: ActiveReconApplicationUseCasesContractVersion = 'active-recon-application-use-cases/v0';
  const baseResult = {
    contractVersion: version,
    createsFindings: false as const,
    createsEvidence: false as const,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
  };

  if (!command || command.contractVersion !== version || command.kind !== 'start_authorized_active_recon_run_command') {
    return { ...baseResult, status: 'failed', errorCode: 'invalid_command' };
  }

  try {
    const request: ActiveReconOriginRunRequest = {
      contractVersion: 'active-recon-origin-run/v0',
      requestId: command.runId, // correlation id
      authorization: {
        confirmed: true,
        scopeLabel: 'ApplicationUseCase'
      },
      authorizedScope: {
        allowedOrigins: [command.normalizedOrigin],
        allowSameHostPaths: true,
        allowSubdomains: false
      },
      origin: command.normalizedOrigin,
      probes: [
        { family: 'document', probe: 'http.robots.inspect' },
        { family: 'document', probe: 'http.security_txt.inspect' }
      ]
    };

    const res = await executeAndPersistActiveReconOriginRun({ request, adapters, repository });
    if (res.status === 'failed' || !res.originRun) {
       return { ...baseResult, status: 'failed', errorCode: 'execution_failed' };
    }

    return {
      ...baseResult,
      status: 'completed',
      runId: res.originRun.runId,
    };
  } catch (e) {
    return { ...baseResult, status: 'failed', errorCode: 'unexpected_application_use_case_failure' };
  }
}

export async function listActiveReconRunSummaries({
  query,
  repository
}: {
  query: ListActiveReconRunSummariesQuery;
  repository: ActiveReconRunRepository;
}): Promise<ListActiveReconRunSummariesResult> {
  const version: ActiveReconApplicationUseCasesContractVersion = 'active-recon-application-use-cases/v0';
  const baseResult = {
    contractVersion: version,
    createsFindings: false as const,
    createsEvidence: false as const,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
  };

  if (!query || query.contractVersion !== version || query.kind !== 'list_active_recon_run_summaries_query') {
    return { ...baseResult, status: 'failed', summaries: [], errorCode: 'invalid_query' };
  }

  try {
    const summaries = await listActiveReconRunSummaryViews({
      repository,
      filter: query.filter,
      limit: query.limit
    });
    return { ...baseResult, status: 'completed', summaries };
  } catch (e) {
    return { ...baseResult, status: 'failed', summaries: [], errorCode: 'read_failed' };
  }
}

export async function getActiveReconRunDetail({
  query,
  repository
}: {
  query: GetActiveReconRunDetailQuery;
  repository: ActiveReconRunRepository;
}): Promise<GetActiveReconRunDetailResult> {
  const version: ActiveReconApplicationUseCasesContractVersion = 'active-recon-application-use-cases/v0';
  const baseResult = {
    contractVersion: version,
    createsFindings: false as const,
    createsEvidence: false as const,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
  };

  if (!query || query.contractVersion !== version || query.kind !== 'get_active_recon_run_detail_query') {
    return { ...baseResult, status: 'failed', detail: null, errorCode: 'invalid_query' };
  }

  try {
    const detail = await getActiveReconRunDetailView({
      repository,
      runId: query.runId
    });
    if (!detail) {
      return { ...baseResult, status: 'not_found', detail: null, errorCode: 'run_not_found' };
    }
    return { ...baseResult, status: 'completed', detail };
  } catch (e) {
    return { ...baseResult, status: 'failed', detail: null, errorCode: 'read_failed' };
  }
}

export async function buildActiveReconRunSafeReport({
  query,
  repository
}: {
  query: BuildActiveReconRunSafeReportQuery;
  repository: ActiveReconRunRepository;
}): Promise<BuildActiveReconRunSafeReportResult> {
  const version: ActiveReconApplicationUseCasesContractVersion = 'active-recon-application-use-cases/v0';
  const baseResult = {
    contractVersion: version,
    createsFindings: false as const,
    createsEvidence: false as const,
    confirmsVulnerabilities: false as const,
    makesRiskClaims: false as const,
    makesSeverityClaims: false as const,
    makesImpactClaims: false as const,
  };

  if (!query || query.contractVersion !== version || query.kind !== 'build_active_recon_run_safe_report_query') {
    return { ...baseResult, status: 'failed', report: null, errorCode: 'invalid_query' };
  }

  try {
    const detail = await getActiveReconRunDetailView({
      repository,
      runId: query.runId
    });
    if (!detail) {
      return { ...baseResult, status: 'not_found', report: null, errorCode: 'run_not_found' };
    }
    const report = buildActiveReconRunSafeReportSnapshot(detail);
    return { ...baseResult, status: 'completed', report };
  } catch (e) {
    return { ...baseResult, status: 'failed', report: null, errorCode: 'report_failed' };
  }
}
