/**
 * Supabase RLS / Data API abuse detection (Fase 2).
 *
 * Claims SUPABASE_RLS_WORLD_READABLE only when OBSERVED:
 * - anon GET returns 200
 * - body is JSON (not HTML)
 * - optional: auth returns same / also readable (strengthens claim)
 *
 * Never fabricates tables. Never embeds anon key / JWT in drafts or findings.
 */

import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { runPostgrestTableProbe } from './PostgrestTableProbeService.js';
import { POSTGREST_TABLE_PROBE_CONTRACT_VERSION } from './PostgrestTableProbeContracts.js';
import {
  SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
  type SupabaseRlsAbuseDetectionRequest,
  type SupabaseRlsAbuseDetectionResult,
  type SupabaseRlsAbuseObservation,
} from './SupabaseRlsAbuseDetectionContracts.js';
import { redactSupabaseKeyPreview } from './SupabaseCredentialMaterialContracts.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

function isWorldReadable(pair: {
  readonly anon: {
    readonly statusCode: number;
    readonly isJsonBody: boolean;
    readonly isHtmlBody: boolean;
    readonly rowCountHint: number | null;
  };
}): boolean {
  if (pair.anon.statusCode !== 200) return false;
  if (pair.anon.isHtmlBody) return false;
  if (!pair.anon.isJsonBody) return false;
  return true;
}

export async function runSupabaseRlsAbuseDetection(
  request: SupabaseRlsAbuseDetectionRequest
): Promise<SupabaseRlsAbuseDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const anonKey = request.anonApiKey.trim();
  if (anonKey.length === 0) {
    return {
      contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
      kind: 'supabase_rls_abuse_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'prerequisite_missing',
      reasonCode: 'anon_key_not_observed',
      lineage,
      restBaseUrl: request.restBaseUrl,
      observations: [],
      error: {
        code: 'anon_key_not_observed',
        safeMessage: 'OBSERVED Supabase anon key required for RLS Data API probes',
      },
    };
  }

  let pairs = request.probePairs;
  if (!pairs) {
    const probeResult = await runPostgrestTableProbe({
      contractVersion: POSTGREST_TABLE_PROBE_CONTRACT_VERSION,
      kind: 'postgrest_table_probe_request',
      probeId: `prb_rls_${sanitizeToSafeId(request.detectionId)}`,
      assessmentId: request.assessmentId,
      scanId: request.scanId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      scopeGrant: request.scopeGrant,
      restBaseUrl: request.restBaseUrl,
      tableNames: request.tableNames,
      anonApiKey: anonKey,
      authenticatedContext: request.authenticatedContext,
      transport: request.transport,
      dnsResolver: request.dnsResolver,
    });

    if (
      probeResult.status === 'preflight_denied' ||
      probeResult.status === 'batch_preflight_denied'
    ) {
      return {
        contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
        kind: 'supabase_rls_abuse_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'preflight_denied',
        reasonCode: probeResult.reasonCode,
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
        error: probeResult.error,
      };
    }

    if (probeResult.status !== 'probe_completed') {
      return {
        contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
        kind: 'supabase_rls_abuse_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'unexpected_failure',
        reasonCode: probeResult.reasonCode,
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
        error: probeResult.error,
      };
    }
    pairs = probeResult.pairs;
  }

  const observations: SupabaseRlsAbuseObservation[] = [];
  for (const pair of pairs) {
    if (!isWorldReadable(pair)) {
      continue;
    }
    // Abstain HTML / non-JSON already gated. Prefer cases with rows or schema keys.
    const hasSignal =
      (pair.anon.rowCountHint !== null && pair.anon.rowCountHint >= 0) ||
      pair.anon.topLevelJsonKeys.length > 0 ||
      pair.anon.isJsonBody;
    if (!hasSignal) continue;

    const auth = pair.authenticated;
    const anonEqualsAuth =
      auth !== undefined &&
      auth.statusCode === pair.anon.statusCode &&
      auth.bodyHash === pair.anon.bodyHash &&
      auth.isJsonBody === true;

    // Secure control: anon denied, auth allowed — not world-readable
    if (
      auth &&
      (pair.anon.statusCode === 401 || pair.anon.statusCode === 403) &&
      auth.statusCode === 200
    ) {
      continue;
    }

    observations.push({
      tableName: pair.tableName,
      tableUrl: pair.tableUrl,
      claimKind: 'SUPABASE_RLS_WORLD_READABLE',
      anonStatusCode: pair.anon.statusCode,
      ...(auth ? { authenticatedStatusCode: auth.statusCode } : {}),
      anonBodyHash: pair.anon.bodyHash,
      ...(auth ? { authenticatedBodyHash: auth.bodyHash } : {}),
      anonIsJson: pair.anon.isJsonBody,
      topLevelJsonKeys: pair.anon.topLevelJsonKeys,
      rowCountHint: pair.anon.rowCountHint,
      anonEqualsAuth,
    });
  }

  if (observations.length === 0) {
    const anyHtml = pairs.some((p) => p.anon.isHtmlBody);
    return {
      contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
      kind: 'supabase_rls_abuse_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: anyHtml ? 'not_data_api_html_body' : 'no_world_readable_tables',
      lineage,
      restBaseUrl: request.restBaseUrl,
      observations: [],
    };
  }

  const primary = observations[0]!;
  const safeSeed = sanitizeToSafeId(`${request.detectionId}_${primary.tableName}`);
  const draftId = `dft_sbrls_${safeSeed}`;
  const nowIso = new Date().toISOString();
  const keyPreview = redactSupabaseKeyPreview(anonKey);

  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: primary.anonEqualsAuth ? 'strong' : 'moderate',
    sourceComparisonId: `cmp_sbrls_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_sbrls_${safeSeed}_anon`,
      validationSnapshotId: `snp_sbrls_${safeSeed}_auth`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: sanitizeEvidenceFragment(
      `OBSERVED Supabase Data API table '${primary.tableName}' world-readable via anon role (status ${primary.anonStatusCode}, JSON). anonKey=${keyPreview}${
        primary.anonEqualsAuth ? '; anon≡auth body hash' : ''
      }`
    ),
  };

  // Unattended → draft for auto-promotion / HITL (no direct Finding without promotion path).
  return {
    contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
    kind: 'supabase_rls_abuse_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'supabase_rls_world_readable_observed',
    lineage,
    restBaseUrl: request.restBaseUrl,
    observations,
    evidenceDraft,
  };
}

/** Build a Finding from an approved observation (HITL or auto-promote service). */
export function buildSupabaseRlsWorldReadableFinding(input: {
  readonly observation: SupabaseRlsAbuseObservation;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly actorId: string;
  readonly observedAt: string;
  readonly draftId: string;
}): Finding {
  const { observation: obs } = input;
  const safeSeed = sanitizeToSafeId(`${input.draftId}_${obs.tableName}`);
  return {
    id: `fnd_sbrls_${safeSeed}`,
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: `Supabase RLS world-readable table '${obs.tableName}'`,
    description: sanitizeEvidenceFragment(
      `OBSERVED anon Data API GET returned HTTP ${obs.anonStatusCode} JSON on '${obs.tableName}'` +
        (obs.anonEqualsAuth
          ? ' with authenticated response matching anon (no RLS read boundary).'
          : ' (anon role can SELECT; auth differential optional).')
    ),
    target: obs.tableUrl,
    evidence: sanitizeEvidenceFragment(
      JSON.stringify({
        claimKind: obs.claimKind,
        tableName: obs.tableName,
        anonStatusCode: obs.anonStatusCode,
        authenticatedStatusCode: obs.authenticatedStatusCode,
        anonBodyHash: obs.anonBodyHash,
        authenticatedBodyHash: obs.authenticatedBodyHash,
        topLevelJsonKeys: obs.topLevelJsonKeys,
        rowCountHint: obs.rowCountHint,
        anonEqualsAuth: obs.anonEqualsAuth,
      })
    ),
    confidence: obs.anonEqualsAuth ? 0.95 : 0.88,
    verificationState: 'suspected_vulnerability',
    metadata: {
      kind: 'supabase_rls_abuse_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      claimKind: 'SUPABASE_RLS_WORLD_READABLE',
      tableName: obs.tableName,
      tableUrl: obs.tableUrl,
      anonStatusCode: obs.anonStatusCode,
      authenticatedStatusCode: obs.authenticatedStatusCode,
      anonBodyHash: obs.anonBodyHash,
      authenticatedBodyHash: obs.authenticatedBodyHash,
      topLevelJsonKeys: obs.topLevelJsonKeys,
      rowCountHint: obs.rowCountHint ?? undefined,
      anonEqualsAuth: obs.anonEqualsAuth,
      observedAt: input.observedAt,
      candidateId: `cnd_sbrls_${safeSeed}`,
      evidenceRecordId: `evd_sbrls_${safeSeed}`,
      lineage: `${input.assessmentId}:${input.scanId}:${input.actorId}`,
    },
  };
}

export class SupabaseRlsAbuseDetectionService {
  async detect(
    request: SupabaseRlsAbuseDetectionRequest
  ): Promise<SupabaseRlsAbuseDetectionResult> {
    return runSupabaseRlsAbuseDetection(request);
  }
}
