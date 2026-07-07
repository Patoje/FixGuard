import type { ActiveReconRunSummaryView, ActiveReconRunDetailView } from './ActiveReconRunReadModelContracts.js';
import type { ActiveReconRunSafeReportSnapshot } from './ActiveReconRunSafeReportContracts.js';

export type ActiveReconApplicationUseCasesContractVersion = 'active-recon-application-use-cases/v0';

export type StartAuthorizedActiveReconRunCommand = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  kind: 'start_authorized_active_recon_run_command';
  normalizedOrigin: string;
  runId?: string; // Optional correlation id
};

export type ListActiveReconRunSummariesQuery = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  kind: 'list_active_recon_run_summaries_query';
  filter?: {
    normalizedOrigin?: string;
    status?: 'completed' | 'partial' | 'failed';
  };
  limit?: number;
};

export type GetActiveReconRunDetailQuery = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  kind: 'get_active_recon_run_detail_query';
  runId: string;
};

export type BuildActiveReconRunSafeReportQuery = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  kind: 'build_active_recon_run_safe_report_query';
  runId: string;
};

export type ActiveReconApplicationUseCaseErrorCode =
  | 'invalid_command'
  | 'invalid_query'
  | 'execution_failed'
  | 'read_failed'
  | 'report_failed'
  | 'run_not_found'
  | 'unexpected_application_use_case_failure';

export type ActiveReconApplicationUseCaseStatus = 'completed' | 'not_found' | 'failed';

export type StartAuthorizedActiveReconRunResult = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  status: ActiveReconApplicationUseCaseStatus;
  runId?: string;
  errorCode?: ActiveReconApplicationUseCaseErrorCode;
  createsFindings: false;
  createsEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
};

export type ListActiveReconRunSummariesResult = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  status: ActiveReconApplicationUseCaseStatus;
  summaries: ActiveReconRunSummaryView[];
  errorCode?: ActiveReconApplicationUseCaseErrorCode;
  createsFindings: false;
  createsEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
};

export type GetActiveReconRunDetailResult = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  status: ActiveReconApplicationUseCaseStatus;
  detail: ActiveReconRunDetailView | null;
  errorCode?: ActiveReconApplicationUseCaseErrorCode;
  createsFindings: false;
  createsEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
};

export type BuildActiveReconRunSafeReportResult = {
  contractVersion: ActiveReconApplicationUseCasesContractVersion;
  status: ActiveReconApplicationUseCaseStatus;
  report: ActiveReconRunSafeReportSnapshot | null;
  errorCode?: ActiveReconApplicationUseCaseErrorCode;
  createsFindings: false;
  createsEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
};
