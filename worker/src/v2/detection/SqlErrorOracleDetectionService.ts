/**
 * Milestone P4-5 — SQL Error Oracle Detection Engine
 *
 * Targets backend data-access layers:
 * - Detects unhandled database error surfacing (INFORMATION_DISCLOSURE / potential_weakness).
 * - Tests candidate parameters with an inert syntax-testing canary token.
 * - Matches known error signatures across MySQL, MSSQL, PostgreSQL, Oracle, and SQLite.
 *
 * Strict Invariants:
 * - Strictly non-exploitative, non-timing, no database dumping.
 * - Sanitizes captured error excerpts with sanitizeEvidenceFragment() (max 128 chars).
 * - 7-pass SSRF preflight protection.
 * - Clean abstention (secure_target_abstained) when target sanitizes inputs or returns generic error pages.
 * - HITL Routing: Unattended runs produce pending_human_review with EvidenceDraftEnvelope.
 */

import type {
  SqlErrorOracleDetectionRequest,
  SqlErrorOracleDetectionResult,
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from './DetectionContracts.js';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { Finding } from '../core/Evidence.js';
import type { EvidenceDraftEnvelope } from '../evidence-mapping/ComparisonEvidenceMappingContracts.js';
import { defaultHttpProbeTransport } from './IdorDifferentialDetectionService.js';
import { sanitizeEvidenceFragment } from '../core/EvidenceSanitizer.js';

function sanitizeToSafeId(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9]/g, '').slice(0, 16);
  return cleaned.length > 0 ? cleaned : '001';
}

type DatabaseEngine = 'mysql' | 'mssql' | 'postgresql' | 'oracle' | 'sqlite' | 'unknown';

interface ErrorRule {
  readonly engine: DatabaseEngine;
  readonly patterns: readonly RegExp[];
}

const SQL_ERROR_RULES: readonly ErrorRule[] = [
  {
    engine: 'mysql',
    patterns: [
      /You have an error in your SQL syntax/i,
      /Warning: mysql_/i,
      /mysqli?::query/i,
      /check the manual that corresponds to your (MySQL|MariaDB) server version/i,
      /MySqlException/i,
      /com\.mysql\.jdbc\.exceptions/i,
    ],
  },
  {
    engine: 'mssql',
    patterns: [
      /Unclosed quotation mark after the character string/i,
      /Microsoft OLE DB Provider for SQL Server/i,
      /SQLServer JDBC Driver/i,
      /Procedure or function '.*' expects parameter/i,
      /SqlException/i,
      /System\.Data\.SqlClient\.SqlException/i,
    ],
  },
  {
    engine: 'postgresql',
    patterns: [
      /pg_query: Query failed/i,
      /syntax error at or near/i,
      /PostgreSQL query failed/i,
      /PSQLException/i,
      /org\.postgresql\.util\.PSQLException/i,
    ],
  },
  {
    engine: 'oracle',
    patterns: [
      /ORA-01756/i,
      /ORA-00933/i,
      /ORA-00921/i,
      /Oracle error/i,
      /Oracle\.DataAccess\.Client/i,
    ],
  },
  {
    engine: 'sqlite',
    patterns: [
      /SQLite3::prepare/i,
      /unrecognized token/i,
      /near ".*": syntax error/i,
      /SQLite error/i,
      /System\.Data\.SQLite\.SQLiteException/i,
    ],
  },
];

function matchSqlError(bodyText: string): { engine: DatabaseEngine; fragment: string } | null {
  for (const rule of SQL_ERROR_RULES) {
    for (const pattern of rule.patterns) {
      const match = pattern.exec(bodyText);
      if (match) {
        const startIdx = Math.max(0, match.index - 10);
        const endIdx = Math.min(bodyText.length, match.index + match[0].length + 80);
        const rawExcerpt = bodyText.substring(startIdx, endIdx).replace(/\s+/g, ' ').trim();
        const sanitized = sanitizeEvidenceFragment(rawExcerpt);
        const truncated = sanitized.length > 128 ? `${sanitized.slice(0, 125)}...` : sanitized;
        return { engine: rule.engine, fragment: truncated };
      }
    }
  }

  // Fallback generic SQL pattern
  const genericMatch = /(?:SQL syntax.*error|syntax error.*SQL|unhandled database query error)/i.exec(bodyText);
  if (genericMatch) {
    const startIdx = Math.max(0, genericMatch.index - 10);
    const endIdx = Math.min(bodyText.length, genericMatch.index + genericMatch[0].length + 80);
    const rawExcerpt = bodyText.substring(startIdx, endIdx).replace(/\s+/g, ' ').trim();
    const sanitized = sanitizeEvidenceFragment(rawExcerpt);
    const truncated = sanitized.length > 128 ? `${sanitized.slice(0, 125)}...` : sanitized;
    return { engine: 'unknown', fragment: truncated };
  }

  return null;
}

export async function runSqlErrorOracleDetection(
  request: SqlErrorOracleDetectionRequest
): Promise<SqlErrorOracleDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };

  const safeSeed = sanitizeToSafeId(request.detectionId);
  const nowIso = new Date().toISOString();
  const transport = request.transport ?? defaultHttpProbeTransport;
  const canaryToken = `'FixGuard_Oracle_${safeSeed}`;

  // 1. Construct Probe Request
  let targetProbeUrl = request.endpointUrl;
  let probeBody: string | undefined;
  const isPost = request.method === 'POST';

  if (isPost) {
    targetProbeUrl = request.endpointUrl;
    probeBody = `${encodeURIComponent(request.parameterName)}=${encodeURIComponent(canaryToken)}`;
  } else {
    try {
      const parsedUrl = new URL(request.endpointUrl);
      parsedUrl.searchParams.set(request.parameterName, canaryToken);
      targetProbeUrl = parsedUrl.toString();
    } catch {
      targetProbeUrl = `${request.endpointUrl}?${encodeURIComponent(request.parameterName)}=${encodeURIComponent(canaryToken)}`;
    }
  }

  // 2. SSRF Preflight
  const preflight = await runAdapterPreflight({
    target: targetProbeUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sql_error_oracle_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'preflight_denied',
      reasonCode: preflight.reasonCode,
      lineage,
      endpointUrl: targetProbeUrl,
      parameterName: request.parameterName,
      injectedProbe: canaryToken,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied for SQL Error Oracle: ${preflight.reasonCode}`,
      },
    };
  }

  // 3. Dispatch Probe Request
  const probeReq: HttpProbeRequest = {
    url: targetProbeUrl,
    method: isPost ? 'POST' : 'GET',
    headers: {
      accept: 'text/html, application/xhtml+xml, application/json, */*',
      'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
      ...(isPost ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
    },
    body: probeBody,
    timeoutMs: 5000,
  };

  let probeResp: HttpProbeResponse | undefined;
  try {
    probeResp = await transport(probeReq);
  } catch (err) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sql_error_oracle_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'unexpected_failure',
      reasonCode: 'probe_dispatch_failed',
      lineage,
      endpointUrl: targetProbeUrl,
      parameterName: request.parameterName,
      injectedProbe: canaryToken,
      error: {
        code: 'probe_dispatch_failed',
        safeMessage: err instanceof Error ? err.message : 'Probe request failed',
      },
    };
  }

  // 4. Analyze Response for SQL Error Signatures
  const errorMatch = matchSqlError(probeResp.bodyText);
  if (!errorMatch) {
    return {
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'sql_error_oracle_detection_result',
      detectionId: request.detectionId,
      scanId: request.scanId,
      assessmentId: request.assessmentId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
      status: 'secure_target_abstained',
      reasonCode: 'no_sql_error_oracle_disclosed',
      lineage,
      endpointUrl: targetProbeUrl,
      parameterName: request.parameterName,
      injectedProbe: canaryToken,
    };
  }

  const { engine: databaseEngine, fragment: errorFragment } = errorMatch;
  const draftId = `dft_sqlo_${safeSeed}`;
  const candidateId = `cnd_sqlo_${safeSeed}`;
  const evidenceRecordId = `evd_sqlo_${safeSeed}`;

  let parsedPath = '/';
  try {
    parsedPath = new URL(targetProbeUrl).pathname;
  } catch {
    // fallback
  }

  // 5. Human Review Routing & Finding Construction
  if (request.humanReviewDecision) {
    if (request.humanReviewDecision.decision === 'approve_evidence') {
      const finding: Finding = {
        id: `fnd_sqlo_${safeSeed}`,
        type: 'INFORMATION_DISCLOSURE',
        severity: 'medium',
        title: `Database Error Oracle (${databaseEngine.toUpperCase()}) on parameter '${request.parameterName}'`,
        description: `Target application surfaces database error messages (${databaseEngine}) on parameter '${request.parameterName}' at ${parsedPath}. Disclosed fragment: "${errorFragment}".`,
        target: targetProbeUrl,
        evidence: sanitizeEvidenceFragment(
          JSON.stringify({
            endpointUrl: targetProbeUrl,
            parameterName: request.parameterName,
            databaseEngine,
            injectedProbe: canaryToken,
            errorFragment,
            reviewedBy: request.humanReviewDecision.reviewerId,
            reviewedAt: request.humanReviewDecision.reviewedAt,
          })
        ),
        confidence: 0.95,
        metadata: {
          kind: 'sql_error_oracle_metadata',
          category: 'INFORMATION_DISCLOSURE',
          databaseEngine,
          parameterName: request.parameterName,
          injectedProbe: canaryToken,
          errorFragment,
          endpointUrl: targetProbeUrl,
          observedAt: nowIso,
          candidateId,
          evidenceRecordId,
          lineage: `${request.assessmentId}:${request.scanId}:${request.actorId}`,
        },
      };

      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'sql_error_oracle_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'potential_weakness',
        reasonCode: 'sql_error_oracle_confirmed',
        lineage,
        endpointUrl: targetProbeUrl,
        parameterName: request.parameterName,
        databaseEngine,
        injectedProbe: canaryToken,
        errorFragment,
        finding,
      };
    }

    if (request.humanReviewDecision.decision === 'reject') {
      return {
        contractVersion: DETECTION_CONTRACT_VERSION,
        kind: 'sql_error_oracle_detection_result',
        detectionId: request.detectionId,
        scanId: request.scanId,
        assessmentId: request.assessmentId,
        authorizationGrantId: request.authorizationGrantId,
        authorizationDecisionId: request.authorizationDecisionId,
        actorId: request.actorId,
        status: 'secure_target_abstained',
        reasonCode: 'human_review_rejected',
        lineage,
        endpointUrl: targetProbeUrl,
        parameterName: request.parameterName,
        databaseEngine,
        injectedProbe: canaryToken,
      };
    }
  }

  // 6. Unreviewed -> Produce Draft for HITL Triage
  const evidenceDraft: EvidenceDraftEnvelope = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'moderate',
    sourceComparisonId: `cmp_sqlo_${safeSeed}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_sqlo_${safeSeed}_base`,
      validationSnapshotId: `snp_sqlo_${safeSeed}_val`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `Target application surfaced ${databaseEngine.toUpperCase()} database error message on parameter '${request.parameterName}': "${errorFragment}"`,
  };

  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'sql_error_oracle_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: 'pending_human_review',
    reasonCode: 'sql_error_oracle_observed',
    lineage,
    endpointUrl: targetProbeUrl,
    parameterName: request.parameterName,
    databaseEngine,
    injectedProbe: canaryToken,
    errorFragment,
    evidenceDraft,
  };
}

export class SqlErrorOracleDetectionService {
  public async execute(
    request: SqlErrorOracleDetectionRequest
  ): Promise<SqlErrorOracleDetectionResult> {
    return runSqlErrorOracleDetection(request);
  }
}
