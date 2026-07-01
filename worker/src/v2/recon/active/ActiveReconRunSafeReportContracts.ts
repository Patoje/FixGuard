export type ActiveReconRunSafeReportContractVersion = 'active-recon-run-safe-report/v0';

export type ActiveReconRunSafeReportSection =
  | {
      kind: 'scope';
      title: 'Scope';
      entries: string[];
    }
  | {
      kind: 'probe_summary';
      title: 'Probe Summary';
      entries: string[];
    }
  | {
      kind: 'document_metadata';
      title: 'Document Metadata';
      entries: string[];
    }
  | {
      kind: 'run_errors';
      title: 'Run Errors';
      entries: string[];
    }
  | {
      kind: 'limitations';
      title: 'Limitations';
      entries: string[];
    };

export type ActiveReconRunSafeReportSnapshot = {
  contractVersion: 'active-recon-run-safe-report/v0';
  reportKind: 'active-recon.safe-run-report';
  title: 'Active Recon Safe Run Report';

  subject: {
    kind: 'origin';
    normalizedOrigin?: string;
  };

  run: {
    runId: string;
    status: 'completed' | 'partial' | 'failed';
    createdAt?: string;
    updatedAt?: string;
  };

  sections: ActiveReconRunSafeReportSection[];

  explicitNonClaims: {
    noFindingsGenerated: true;
    noEvidenceRecordsGenerated: true;
    noVulnerabilitiesConfirmed: true;
    noRiskSeverityOrImpactClaims: true;
    noRawHttpDataIncluded: true;
  };

  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
};
