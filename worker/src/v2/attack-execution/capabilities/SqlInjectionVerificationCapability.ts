/**
 * Milestone A9 — SQL Injection Verification Capability
 *
 * Authorized defensive error-based verification via sqlmap
 * (--technique=E only; no dump/shell/blind/time-based).
 *
 * AttackExecutionService already enforced 7 safety gates before invocation.
 * Safe CLI args are still built fail-closed before any process spawn.
 *
 * On succeeded (confirmed), VerificationState advances one ordered step:
 *   validated_vulnerability → exploitability_confirmed
 * On refuted, AttackExecutionService records REFUTED via VerificationStateService.
 *
 * Layering with A7:
 *   suspected_vulnerability → sql_oracle_advancement → validated_vulnerability (A7)
 *   validated_vulnerability → sql_injection_verification → exploitability_confirmed (A9)
 *
 * Plan capabilityGained: active_validation.
 * Authorization BlastRadiusClass: read_authenticated (existing; do not invent new classes).
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { LocalProcessRunner } from '../../core/ProcessRunner.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';
import { parseSqlmapStructuredOutput } from '../tools/SqlmapAdapter.js';
import {
  buildSafeSqlmapCliArgs,
  SQLMAP_DBMS_HINT_ALLOWLIST,
  SQLMAP_VERIFICATION_CONTRACT_VERSION,
  SQLMAP_VERIFICATION_NON_CLAIMS,
  type SqlmapDbmsHint,
  type SqlmapResult,
} from '../tools/SqlmapContracts.js';

const EVIDENCE_MAX_CHARS = 128;

export type SqlInjectionVerificationProvider = (args: {
  readonly targetUrl: string;
  readonly parameterName: string;
  readonly dbmsHint: SqlmapDbmsHint;
}) => Promise<SqlmapResult>;

function truncateSanitized(raw: string): string {
  const sanitized = sanitizeEvidenceFragment(raw);
  return sanitized.length > EVIDENCE_MAX_CHARS ? sanitized.slice(0, EVIDENCE_MAX_CHARS) : sanitized;
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

function isBinaryAbsentError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /Command not found/i.test(msg) || /ENOENT/i.test(msg) || /not found/i.test(msg);
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

function coerceDbmsHint(raw: string): SqlmapDbmsHint | null {
  const engine = raw.trim().toLowerCase();
  for (const hint of SQLMAP_DBMS_HINT_ALLOWLIST) {
    if (hint === engine) return hint;
  }
  if (engine.includes('postgres')) return 'postgresql';
  if (engine.includes('mysql') || engine.includes('maria')) return 'mysql';
  if (engine.includes('mssql') || engine.includes('sql server')) return 'mssql';
  if (engine.includes('oracle')) return 'oracle';
  if (engine.includes('sqlite')) return 'sqlite';
  return null;
}

function resolveDbmsHint(ctx: AttackCapabilityInvocationContext): SqlmapDbmsHint {
  for (const finding of ctx.findings) {
    const meta = finding.metadata;
    if (meta.kind === 'sql_error_oracle_metadata') {
      const coerced = coerceDbmsHint(meta.databaseEngine);
      if (coerced !== null) return coerced;
    }
  }
  return 'mysql';
}

/**
 * Creates sql_injection_verification AttackCapabilityPort.
 * Injectable resultProvider enables hermetic smoke without sqlmap binary.
 */
export function createSqlInjectionVerificationCapability(options?: {
  readonly resultProvider?: SqlInjectionVerificationProvider;
  readonly processRunner?: ProcessRunner;
}): AttackCapabilityPort {
  const runner = options?.processRunner ?? new LocalProcessRunner();

  const defaultProvider: SqlInjectionVerificationProvider = async ({
    targetUrl,
    parameterName,
    dbmsHint,
  }) => {
    const built = buildSafeSqlmapCliArgs({ targetUrl, parameterName, dbmsHint });
    if (!built.ok) {
      return {
        status: 'tool_error',
        contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
        targetUrl,
        parameterName,
        dbmsHint,
        technique: 'E',
        evidenceExcerpt: sanitizeEvidenceFragment(built.reason, EVIDENCE_MAX_CHARS),
        reasonCode: built.reasonCode,
        explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
        lineage: {
          assessmentId: 'capability',
          scanId: 'capability',
          authorizationGrantId: 'capability',
          authorizationDecisionId: 'capability',
          actorId: 'capability',
        },
      };
    }

    try {
      const output = await runner.execute({
        binary: 'sqlmap',
        args: [...built.args],
        timeoutMs: 60_000,
      });
      return parseSqlmapStructuredOutput({
        stdout: output.stdout,
        stderr: output.stderr,
        exitCode: output.exitCode,
        timedOut: output.timedOut,
        durationMs: output.durationMs,
        targetUrl,
        parameterName,
        dbmsHint,
        lineage: {
          assessmentId: 'capability',
          scanId: 'capability',
          authorizationGrantId: 'capability',
          authorizationDecisionId: 'capability',
          actorId: 'capability',
        },
      });
    } catch (err: unknown) {
      if (isBinaryAbsentError(err)) {
        return {
          status: 'tool_error',
          contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
          targetUrl,
          parameterName,
          dbmsHint,
          technique: 'E',
          evidenceExcerpt: 'sqlmap binary not found; hermetic fallback',
          reasonCode: 'sqlmap_binary_absent',
          explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
          lineage: {
            assessmentId: 'capability',
            scanId: 'capability',
            authorizationGrantId: 'capability',
            authorizationDecisionId: 'capability',
            actorId: 'capability',
          },
          hermeticFallback: true,
        };
      }
      throw err;
    }
  };

  const provider = options?.resultProvider ?? defaultProvider;

  return {
    capability: 'sql_injection_verification',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('sql_inj_target_missing', 'SQL injection verification requires a target URL');
      }

      const parameterName = resolveParameterName(ctx);
      if (!parameterName) {
        return failed(
          'sql_inj_parameter_missing',
          'SQL injection verification requires an observed injectable parameter name'
        );
      }

      const dbmsHint = resolveDbmsHint(ctx);

      let result: SqlmapResult;
      try {
        result = await provider({
          targetUrl: ctx.targetUrl,
          parameterName,
          dbmsHint,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        return failed('sql_inj_verification_failed', truncateSanitized(msg));
      }

      switch (result.status) {
        case 'confirmed':
          return succeeded(
            'sql_injection_error_based_confirmed',
            `Error-based SQL injection confirmed (technique=E); evidence=${truncateSanitized(result.evidenceExcerpt)}`,
            `ev_sql_inj_${ctx.step.stepId}`
          );
        case 'refuted':
          return refuted(
            'sql_injection_not_confirmed',
            `SQL injection not confirmed by error-based sqlmap; evidence=${truncateSanitized(result.evidenceExcerpt)}`
          );
        case 'timed_out':
          return failed(
            'sql_injection_timed_out',
            `Sqlmap verification timed out; evidence=${truncateSanitized(result.evidenceExcerpt)}`
          );
        case 'tool_error':
          return failed(
            result.reasonCode || 'sql_injection_tool_error',
            truncateSanitized(result.evidenceExcerpt || result.reasonCode)
          );
        default: {
          const _exhaustive: never = result.status;
          return failed('sql_inj_unexpected_status', `Unexpected status: ${String(_exhaustive)}`);
        }
      }
    },
  };
}
