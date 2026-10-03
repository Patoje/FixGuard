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

function isAttributableToTarget(tableUrl: string, restBaseUrl: string): boolean {
  try {
    const tableHost = new URL(tableUrl).host.toLowerCase();
    const baseHost = new URL(restBaseUrl).host.toLowerCase();
    return tableHost === baseHost;
  } catch {
    return false;
  }
}

function hasObservedExposedData(anon: {
  readonly statusCode: number;
  readonly isJsonBody: boolean;
  readonly isHtmlBody: boolean;
  readonly rowCountHint: number | null;
  readonly topLevelJsonKeys: readonly string[];
  readonly bodySnippet?: string;
}): boolean {
  if (anon.statusCode !== 200) return false;
  if (anon.isHtmlBody) return false;
  if (!anon.isJsonBody) return false;

  // Explicit row count hint: must be > 0. Row count 0 means empty array ([]), NOT data exposure!
  if (anon.rowCountHint !== null) {
    return anon.rowCountHint > 0;
  }

  // Snippet check: empty array [] or empty object {} has no exposed records
  if (anon.bodySnippet) {
    const trimmed = anon.bodySnippet.trim();
    if (
      trimmed === '[]' ||
      trimmed === '{}' ||
      /^\s*\[\s*\]\s*$/.test(trimmed) ||
      /^\s*\{\s*\}\s*$/.test(trimmed)
    ) {
      return false;
    }
  }

  // If object without row count hint, must have non-error data properties
  if (anon.topLevelJsonKeys && anon.topLevelJsonKeys.length > 0) {
    const errorKeys = new Set(['code', 'message', 'details', 'hint', 'error']);
    const nonErrorKeys = anon.topLevelJsonKeys.filter((k) => !errorKeys.has(k.toLowerCase()));
    return nonErrorKeys.length > 0;
  }

  return false;
}

function isEmptyOrInconclusiveResponse(anon: {
  readonly statusCode: number;
  readonly isJsonBody: boolean;
  readonly isHtmlBody: boolean;
  readonly rowCountHint: number | null;
  readonly topLevelJsonKeys: readonly string[];
  readonly bodySnippet?: string;
}): boolean {
  if (anon.statusCode !== 200) return false;
  if (anon.isHtmlBody) return false;
  if (!anon.isJsonBody) return false;

  if (anon.rowCountHint === 0) return true;

  if (anon.bodySnippet) {
    const trimmed = anon.bodySnippet.trim();
    if (
      trimmed === '[]' ||
      trimmed === '{}' ||
      /^\s*\[\s*\]\s*$/.test(trimmed) ||
      /^\s*\{\s*\}\s*$/.test(trimmed)
    ) {
      return true;
    }
  }

  if (!anon.topLevelJsonKeys || anon.topLevelJsonKeys.length === 0) return true;

  const errorKeys = new Set(['code', 'message', 'details', 'hint', 'error']);
  const nonErrorKeys = anon.topLevelJsonKeys.filter((k) => !errorKeys.has(k.toLowerCase()));
  if (nonErrorKeys.length === 0) return true;

  return false;
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
  let sawEmptyOrInconclusive = false;
  let sawReadBoundaryEnforced = false;
  let sawHtmlBody = false;
  let sawUnattributed = false;
  let sawIncompleteEvidence = false;

  for (const pair of pairs) {
    // 1. Evidence completeness check
    if (
      !pair.tableName ||
      pair.tableName.trim().length === 0 ||
      !pair.tableUrl ||
      pair.tableUrl.trim().length === 0 ||
      !pair.anon ||
      typeof pair.anon.statusCode !== 'number' ||
      !pair.anon.bodyHash ||
      pair.anon.bodyHash.trim().length === 0
    ) {
      sawIncompleteEvidence = true;
      continue;
    }

    // 2. Attributability check: target URL must match restBaseUrl
    if (!isAttributableToTarget(pair.tableUrl, request.restBaseUrl)) {
      sawUnattributed = true;
      continue;
    }

    if (pair.anon.isHtmlBody || !pair.anon.isJsonBody) {
      sawHtmlBody = true;
      continue;
    }

    const auth = pair.authenticated;
    // 3. Secure control: anon denied (401/403)
    if (pair.anon.statusCode === 401 || pair.anon.statusCode === 403) {
      sawReadBoundaryEnforced = true;
      continue;
    }

    // 4. Confirmed data exposure: anon 200 + actual observed rows > 0 or qualifying data properties
    if (hasObservedExposedData(pair.anon)) {
      const anonEqualsAuth =
        auth !== undefined &&
        auth.statusCode === pair.anon.statusCode &&
        auth.bodyHash === pair.anon.bodyHash &&
        auth.isJsonBody === true;

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
        ...(pair.anon.bodySnippet ? { bodySnippet: pair.anon.bodySnippet } : {}),
      });
      continue;
    }

    // 5. Empty or inconclusive response (e.g. 200 with [], 0 rows, empty object)
    if (isEmptyOrInconclusiveResponse(pair.anon)) {
      sawEmptyOrInconclusive = true;
      continue;
    }

    // Otherwise unrecognized / contradictory response
    sawIncompleteEvidence = true;
  }

  if (observations.length === 0) {
    if (sawEmptyOrInconclusive) {
      return {
        contractVersion: SUPABASE_RLS_ABUSE_DETECTION_CONTRACT_VERSION,
        kind: 'supabase_rls_abuse_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'inconclusive_observation',
        reasonCode: 'inconclusive_empty_table',
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
      };
    }

    if (sawReadBoundaryEnforced) {
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
        reasonCode: 'read_boundary_enforced',
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
      };
    }

    if (sawHtmlBody) {
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
        reasonCode: 'not_data_api_html_body',
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
      };
    }

    if (sawUnattributed) {
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
        reasonCode: 'target_attribution_unverified',
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
      };
    }

    if (sawIncompleteEvidence) {
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
        reasonCode: 'incomplete_or_contradictory_evidence',
        lineage,
        restBaseUrl: request.restBaseUrl,
        observations: [],
      };
    }

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
      reasonCode: 'no_world_readable_tables',
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
  if (obs.claimKind !== 'SUPABASE_RLS_WORLD_READABLE') {
    throw new Error(`Cannot build world-readable finding for claimKind '${obs.claimKind}'`);
  }
  if (obs.anonStatusCode !== 200) {
    throw new Error(`Cannot build world-readable finding for non-200 status ${obs.anonStatusCode}`);
  }
  if (obs.rowCountHint !== null && obs.rowCountHint <= 0) {
    throw new Error('Cannot construct world-readable finding for observation without observed rows');
  }
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
