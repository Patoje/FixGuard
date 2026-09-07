import type {
  ActiveReconRunRepository,
  ActiveReconRunListFilter
} from './ActiveReconOriginRunRepository.js';
import type { PersistedActiveReconRunRecord } from './ActiveReconOriginRunPersistenceContracts.js';
import type {
  ActiveReconRunSummaryView,
  ActiveReconRunDetailView,
  SafeObservationView,
  RobotsMetadataView,
  SecurityTxtMetadataView
} from './ActiveReconRunReadModelContracts.js';
import { validatePersistedActiveReconRecord } from './ActiveReconOriginRunPersistenceService.js';

export function toActiveReconRunSummaryView(record: PersistedActiveReconRunRecord): ActiveReconRunSummaryView {
  let robotsPresent = false;
  let robotsReachable: boolean | undefined;
  let robotsBodyTruncated: boolean | undefined;
  let robotsLineCount: number | undefined;
  let hasUserAgent: boolean | undefined;
  let hasDisallow: boolean | undefined;
  let hasAllow: boolean | undefined;
  let hasSitemap: boolean | undefined;

  let secTxtPresent = false;
  let secTxtReachable: boolean | undefined;
  let secTxtBodyTruncated: boolean | undefined;
  let secTxtLineCount: number | undefined;
  let hasContact: boolean | undefined;
  let hasExpires: boolean | undefined;
  let hasEncryption: boolean | undefined;
  let hasAcknowledgments: boolean | undefined;
  let hasLanguages: boolean | undefined;
  let hasCanonical: boolean | undefined;
  let hasPolicy: boolean | undefined;

  for (const obs of record.observations) {
    if (obs.kind === 'robots_metadata') {
      robotsPresent = true;
      robotsReachable = obs.metadata?.reachable;
      robotsBodyTruncated = obs.metadata?.bodyTruncated;
      robotsLineCount = obs.metadata?.recognizedDirectiveLineCount;
      hasUserAgent = obs.metadata?.hasUserAgentDirective;
      hasDisallow = obs.metadata?.hasDisallowDirective;
      hasAllow = obs.metadata?.hasAllowDirective;
      hasSitemap = obs.metadata?.hasSitemapDirective;
    } else if (obs.kind === 'security_txt_metadata') {
      secTxtPresent = true;
      secTxtReachable = obs.metadata?.reachable;
      secTxtBodyTruncated = obs.metadata?.bodyTruncated;
      secTxtLineCount = obs.metadata?.recognizedFieldLineCount;
      hasContact = obs.metadata?.hasContactField;
      hasExpires = obs.metadata?.hasExpiresField;
      hasEncryption = obs.metadata?.hasEncryptionField;
      hasAcknowledgments = obs.metadata?.hasAcknowledgmentsField;
      hasLanguages = obs.metadata?.hasPreferredLanguagesField;
      hasCanonical = obs.metadata?.hasCanonicalField;
      hasPolicy = obs.metadata?.hasPolicyField;
    }
  }

  return {
    contractVersion: 'active-recon-run-summary-view/v0',
    runId: record.runId,
    recordVersion: record.recordVersion,
    recordKind: record.recordKind,
    subject: {
      kind: record.subject.kind,
      normalizedOrigin: record.subject.normalizedOrigin
    },
    status: record.status,
    timestamps: {
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    },
    authorizationProvenance: record.provenance.sourceContractVersion === 'active-recon-origin-run/v1' ? {
      authorizationDecisionId: record.provenance.authorizationDecisionId,
      authorizationGrantId: record.provenance.authorizationGrantId,
      assessmentId: record.provenance.assessmentId,
      scanId: record.provenance.scanId,
      actorId: record.provenance.actorId,
    } : undefined,
    counts: {
      probesPlanned: record.counts.planned,
      probesCompleted: record.counts.completed,
      probesBlocked: record.counts.blocked,
      probesCandidate: record.counts.candidate,
      probesFailed: record.counts.failed,
      runErrors: record.runErrors.length,
      observations: record.observations.length
    },
    documentProbeSummary: {
      robots: {
        present: robotsPresent,
        reachable: robotsReachable,
        bodyTruncated: robotsBodyTruncated,
        recognizedDirectiveLineCount: robotsLineCount,
        hasUserAgentDirective: hasUserAgent,
        hasDisallowDirective: hasDisallow,
        hasAllowDirective: hasAllow,
        hasSitemapDirective: hasSitemap
      },
      securityTxt: {
        present: secTxtPresent,
        reachable: secTxtReachable,
        bodyTruncated: secTxtBodyTruncated,
        recognizedFieldLineCount: secTxtLineCount,
        hasContactField: hasContact,
        hasExpiresField: hasExpires,
        hasEncryptionField: hasEncryption,
        hasAcknowledgmentsField: hasAcknowledgments,
        hasPreferredLanguagesField: hasLanguages,
        hasCanonicalField: hasCanonical,
        hasPolicyField: hasPolicy
      }
    },
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false
    }
  };
}

export function toActiveReconRunDetailView(record: PersistedActiveReconRunRecord): ActiveReconRunDetailView {
  const summary = toActiveReconRunSummaryView(record);

  const safeItems = record.items.map(item => ({
    family: item.family,
    kind: item.safeKind,
    status: item.status,
    policyDecision: item.status === 'blocked' ? 'block' : item.status === 'candidate' ? 'candidate' : item.status === 'completed' ? 'allow' : undefined,
    observationCount: item.observations.length,
    errorCode: item.error?.code
  })) as ActiveReconRunDetailView['safeItems'];

  const safeObservations: SafeObservationView[] = record.observations.map(obs => {
    if (obs.kind === 'robots_metadata') {
      const mapped: SafeObservationView = {
        kind: 'robots_metadata',
        safeSummary: obs.safeSummary,
        confidence: obs.confidence,
        metadata: {
          reachable: obs.metadata?.reachable,
          contentTypeLookedTextLike: obs.metadata?.contentTypeLookedTextLike,
          recognizedDirectiveLineCount: obs.metadata?.recognizedDirectiveLineCount,
          hasUserAgentDirective: obs.metadata?.hasUserAgentDirective,
          hasDisallowDirective: obs.metadata?.hasDisallowDirective,
          hasAllowDirective: obs.metadata?.hasAllowDirective,
          hasSitemapDirective: obs.metadata?.hasSitemapDirective,
          bodyTruncated: obs.metadata?.bodyTruncated
        }
      };
      return mapped;
    } else {
      const mapped: SafeObservationView = {
        kind: 'security_txt_metadata',
        safeSummary: obs.safeSummary,
        confidence: obs.confidence,
        metadata: {
          reachable: obs.metadata?.reachable,
          contentTypeLookedTextLike: obs.metadata?.contentTypeLookedTextLike,
          recognizedFieldLineCount: obs.metadata?.recognizedFieldLineCount,
          hasContactField: obs.metadata?.hasContactField,
          hasExpiresField: obs.metadata?.hasExpiresField,
          hasEncryptionField: obs.metadata?.hasEncryptionField,
          hasAcknowledgmentsField: obs.metadata?.hasAcknowledgmentsField,
          hasPreferredLanguagesField: obs.metadata?.hasPreferredLanguagesField,
          hasCanonicalField: obs.metadata?.hasCanonicalField,
          hasPolicyField: obs.metadata?.hasPolicyField,
          bodyTruncated: obs.metadata?.bodyTruncated
        }
      };
      return mapped;
    }
  });

  return {
    contractVersion: 'active-recon-run-detail-view/v0',
    summary,
    safeItems,
    safeObservations,
    runErrors: record.runErrors,
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false
    }
  };
}

export async function listActiveReconRunSummaryViews({
  repository,
  filter,
  limit
}: {
  repository: ActiveReconRunRepository;
  filter?: ActiveReconRunListFilter;
  limit?: number;
}): Promise<ActiveReconRunSummaryView[]> {
  const records = await repository.listRuns(filter);
  
  let safeLimit = 100;
  if (limit !== undefined) {
    if (limit > 0 && limit <= 100) {
      safeLimit = limit;
    }
  }

  const validatedRecords: PersistedActiveReconRunRecord[] = [];
  for (const raw of records) {
    const val = validatePersistedActiveReconRecord(raw);
    if (val.status !== 'invalid') {
      validatedRecords.push(val.record);
    }
  }

  // Deterministic in-memory sort: createdAt DESC, runId ASC
  validatedRecords.sort((a, b) => {
    const tA = a.createdAt || '';
    const tB = b.createdAt || '';
    if (tA > tB) return -1;
    if (tA < tB) return 1;
    if (a.runId < b.runId) return -1;
    if (a.runId > b.runId) return 1;
    return 0;
  });

  const sliced = validatedRecords.slice(0, safeLimit);
  return sliced.map(toActiveReconRunSummaryView);
}

export async function getActiveReconRunDetailView({
  repository,
  runId
}: {
  repository: ActiveReconRunRepository;
  runId: string;
}): Promise<ActiveReconRunDetailView | null> {
  const rawRecord = await repository.getRun(runId);
  if (!rawRecord) return null;
  const val = validatePersistedActiveReconRecord(rawRecord);
  if (val.status === 'invalid') return null;
  return toActiveReconRunDetailView(val.record);
}
