/**
 * Milestone A7 — SQL Oracle Advancement Capability
 *
 * Re-probes a suspected SQL error-oracle parameter with structured
 * error-provoking payloads ONLY (error-based validation).
 *
 * MUST NOT:
 * - use sleep / timing / blind techniques
 * - exfiltrate data (SELECT *, UNION dump, information_schema harvest)
 *
 * Blast-radius intent (authorization): read_authenticated.
 * Plan capabilityGained may be active_validation; never invent BlastRadiusClass values.
 *
 * On success, AttackExecutionService advances VerificationState one ordered step
 * (suspected_vulnerability → validated_vulnerability) via VerificationStateService.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport, HttpProbeRequest } from '../../detection/DetectionContracts.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';

/**
 * Closed allowlist of error-provoking payloads.
 * Syntax-breakers only — no sleep, no data-returning SELECT dumps.
 */
export const SQL_ERROR_PROVOCATION_PAYLOADS: readonly string[] = [
  "'",
  "''",
  "'\"",
  "')",
  "';",
  "' OR 'FixGuard'='FixGuardX",
  "1'",
] as const;

/** Patterns that MUST never appear in advancement payloads (fail-closed guard). */
const FORBIDDEN_PAYLOAD_MARKERS: readonly RegExp[] = [
  /\bSLEEP\s*\(/i,
  /\bWAITFOR\b/i,
  /\bBENCHMARK\s*\(/i,
  /\bPG_SLEEP\s*\(/i,
  /\bSELECT\s+\*/i,
  /\bINTO\s+(OUT|DUMP)FILE\b/i,
  /\bLOAD_FILE\s*\(/i,
  /\bINFORMATION_SCHEMA\b/i,
  /\bUNION\s+SELECT\b/i,
];

const EVIDENCE_MAX_CHARS = 128;

const SQL_ERROR_PATTERNS: readonly RegExp[] = [
  /You have an error in your SQL syntax/i,
  /Warning: mysql_/i,
  /mysqli?::query/i,
  /Unclosed quotation mark after the character string/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /SqlException/i,
  /pg_query: Query failed/i,
  /syntax error at or near/i,
  /PSQLException/i,
  /ORA-01756/i,
  /ORA-00933/i,
  /SQLite3::prepare/i,
  /near ".*": syntax error/i,
  /(?:SQL syntax.*error|syntax error.*SQL|unhandled database query error)/i,
];

function assertPayloadsSafe(payloads: readonly string[]): void {
  for (const payload of payloads) {
    for (const forbidden of FORBIDDEN_PAYLOAD_MARKERS) {
      if (forbidden.test(payload)) {
        throw new Error(
          `SQL oracle advancement invariant violated: forbidden payload pattern ${forbidden}`
        );
      }
    }
  }
}

assertPayloadsSafe(SQL_ERROR_PROVOCATION_PAYLOADS);

function truncateSanitized(raw: string): string {
  const sanitized = sanitizeEvidenceFragment(raw);
  return sanitized.length > EVIDENCE_MAX_CHARS ? sanitized.slice(0, EVIDENCE_MAX_CHARS) : sanitized;
}

function matchSqlErrorFragment(bodyText: string): string | null {
  for (const pattern of SQL_ERROR_PATTERNS) {
    const match = pattern.exec(bodyText);
    if (match) {
      const startIdx = Math.max(0, match.index - 10);
      const endIdx = Math.min(bodyText.length, match.index + match[0].length + 80);
      const rawExcerpt = bodyText.substring(startIdx, endIdx).replace(/\s+/g, ' ').trim();
      return truncateSanitized(rawExcerpt);
    }
  }
  return null;
}

function succeeded(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'succeeded',
    reasonCode,
    safeMessage,
    ...(evidenceId ? { evidenceId } : {}),
  };
}

function refuted(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'refuted', reasonCode, safeMessage };
}

function failed(reasonCode: string, safeMessage: string): AttackCapabilityExecutionResult {
  return { outcome: 'failed', reasonCode, safeMessage };
}

function resolveParameterName(ctx: AttackCapabilityInvocationContext): string | undefined {
  if (typeof ctx.plan.parameterName === 'string' && ctx.plan.parameterName.trim().length > 0) {
    return ctx.plan.parameterName.trim();
  }
  for (const finding of ctx.findings) {
    const meta = finding.metadata;
    if (meta.kind === 'sql_error_oracle_metadata' && typeof meta.parameterName === 'string') {
      return meta.parameterName;
    }
  }
  return undefined;
}

function buildProbeUrl(baseUrl: string, parameterName: string, payload: string): string {
  try {
    const parsed = new URL(baseUrl);
    parsed.searchParams.set(parameterName, payload);
    return parsed.toString();
  } catch {
    const sep = baseUrl.includes('?') ? '&' : '?';
    return `${baseUrl}${sep}${encodeURIComponent(parameterName)}=${encodeURIComponent(payload)}`;
  }
}

/**
 * Creates the SQL oracle advancement AttackCapabilityPort.
 * Injectable transport enables hermetic smoke tests.
 */
export function createSqlOracleAdvancementCapability(
  transport?: IdorHttpProbeTransport
): AttackCapabilityPort {
  const httpTransport = transport ?? defaultHttpProbeTransport;

  return {
    capability: 'sql_oracle_advancement',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('sql_adv_target_missing', 'SQL oracle advancement requires a target URL');
      }

      const parameterName = resolveParameterName(ctx);
      if (!parameterName) {
        return failed(
          'sql_adv_parameter_missing',
          'SQL oracle advancement requires an observed injectable parameter name'
        );
      }

      let lastEvidence = '';

      for (const payload of SQL_ERROR_PROVOCATION_PAYLOADS) {
        const probeUrl = buildProbeUrl(ctx.targetUrl, parameterName, payload);
        const probeReq: HttpProbeRequest = {
          url: probeUrl,
          method: 'GET',
          headers: {
            accept: 'text/html, application/xhtml+xml, application/json, */*',
            'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
          },
          timeoutMs: 5000,
        };

        let bodyText: string;
        try {
          const resp = await httpTransport(probeReq);
          bodyText = resp.bodyText ?? '';
        } catch {
          return failed('sql_adv_transport_failed', 'SQL oracle advancement probe transport failed');
        }

        lastEvidence = truncateSanitized(bodyText);
        const fragment = matchSqlErrorFragment(bodyText);
        if (fragment !== null) {
          return succeeded(
            'sql_oracle_error_confirmed',
            `SQL error oracle re-confirmed (error-based only); evidence=${fragment}`,
            `ev_sql_adv_${ctx.step.stepId}`
          );
        }
      }

      return refuted(
        'sql_oracle_not_reconfirmed',
        `No SQL error oracle signature on re-probe; evidence=${lastEvidence}`
      );
    },
  };
}
