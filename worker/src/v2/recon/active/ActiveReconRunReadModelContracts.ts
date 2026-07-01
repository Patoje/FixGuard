import type { PersistedActiveReconRunError } from './ActiveReconOriginRunPersistenceContracts.js';

export type ActiveReconRunSummaryViewContractVersion = 'active-recon-run-summary-view/v0';
export type ActiveReconRunDetailViewContractVersion = 'active-recon-run-detail-view/v0';

export type ActiveReconRunSafeObservationConfidence = 'low' | 'medium' | 'high';

export type RobotsMetadataView = {
  reachable?: boolean;
  contentTypeLookedTextLike?: boolean;
  recognizedDirectiveLineCount?: number;
  hasUserAgentDirective?: boolean;
  hasDisallowDirective?: boolean;
  hasAllowDirective?: boolean;
  hasSitemapDirective?: boolean;
  bodyTruncated?: boolean;
};

export type SecurityTxtMetadataView = {
  reachable?: boolean;
  contentTypeLookedTextLike?: boolean;
  recognizedFieldLineCount?: number;
  hasContactField?: boolean;
  hasExpiresField?: boolean;
  hasEncryptionField?: boolean;
  hasAcknowledgmentsField?: boolean;
  hasPreferredLanguagesField?: boolean;
  hasCanonicalField?: boolean;
  hasPolicyField?: boolean;
  bodyTruncated?: boolean;
};

export type SafeObservationView =
  | {
      kind: 'robots_metadata';
      safeSummary: string;
      confidence: ActiveReconRunSafeObservationConfidence;
      metadata: RobotsMetadataView;
    }
  | {
      kind: 'security_txt_metadata';
      safeSummary: string;
      confidence: ActiveReconRunSafeObservationConfidence;
      metadata: SecurityTxtMetadataView;
    };

export type ActiveReconRunSummaryView = {
  contractVersion: 'active-recon-run-summary-view/v0';

  runId: string;
  recordVersion: 'active-recon-origin-run-record/v0';
  recordKind: 'active-recon.origin-run';

  subject: {
    kind: 'origin';
    normalizedOrigin?: string;
  };

  status: 'completed' | 'partial' | 'failed';

  timestamps: {
    createdAt?: string;
    updatedAt?: string;
  };

  counts: {
    probesPlanned: number;
    probesCompleted: number;
    probesBlocked: number;
    probesCandidate: number;
    probesFailed: number;
    runErrors: number;
    observations: number;
  };

  documentProbeSummary: {
    robots: {
      present: boolean;
      reachable?: boolean;
      bodyTruncated?: boolean;
      recognizedDirectiveLineCount?: number;
      hasUserAgentDirective?: boolean;
      hasDisallowDirective?: boolean;
      hasAllowDirective?: boolean;
      hasSitemapDirective?: boolean;
    };

    securityTxt: {
      present: boolean;
      reachable?: boolean;
      bodyTruncated?: boolean;
      recognizedFieldLineCount?: number;
      hasContactField?: boolean;
      hasExpiresField?: boolean;
      hasEncryptionField?: boolean;
      hasAcknowledgmentsField?: boolean;
      hasPreferredLanguagesField?: boolean;
      hasCanonicalField?: boolean;
      hasPolicyField?: boolean;
    };
  };

  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
};

export type ActiveReconRunDetailView = {
  contractVersion: 'active-recon-run-detail-view/v0';

  summary: ActiveReconRunSummaryView;

  safeItems: Array<{
    family: 'document';
    kind: 'http.robots.inspect' | 'http.security_txt.inspect' | 'unknown';
    status: 'completed' | 'blocked' | 'candidate' | 'failed';
    policyDecision?: 'allow' | 'block' | 'candidate';
    observationCount: number;
    errorCode?: string;
  }>;

  safeObservations: SafeObservationView[];

  runErrors: PersistedActiveReconRunError[];

  classification: {
    finding: false;
    evidence: false;
    vulnerability: false;
    riskClaim: false;
  };
};
