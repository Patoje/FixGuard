/**
 * Milestone A9 — Sqlmap Adapter
 *
 * Authorized defensive error-based SQL injection verification via ProcessRunner
 * (shell: false). Hardcoded --technique=E only. Prohibited shell/dump/query
 * flags fail-closed BEFORE spawn. Never fabricates confirmed without parsed evidence.
 */

import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from '../../recon/adapters/AdapterPreflightPipeline.js';
import {
  SQLMAP_VERIFICATION_CONTRACT_VERSION,
  SQLMAP_VERIFICATION_NON_CLAIMS,
  buildSafeSqlmapCliArgs,
  validateSqlmapCliArgs,
  type SqlmapDbmsHint,
  type SqlmapRequest,
  type SqlmapResult,
  type SqlmapTool,
} from './SqlmapContracts.js';

const EVIDENCE_MAX_CHARS = 256;

const CONFIRMED_MARKERS: readonly RegExp[] = [
  /\bis vulnerable\b/i,
  /\bappears to be injectable\b/i,
];

const REFUTED_MARKERS: readonly RegExp[] = [
  /do not appear to be injectable/i,
  /all tested parameters do not appear to be injectable/i,
  /does not seem to be injectable/i,
  /parameter .+ is not injectable/i,
  /does not appear to be injectable/i,
];

/** Reject time-based / union / stacked signals even if somehow emitted. */
const FORBIDDEN_TECHNIQUE_MARKERS: readonly RegExp[] = [
  /\btime[- ]based\b/i,
  /\bbool(?:ean)?[- ]based\b/i,
  /\bunion[- ]based\b/i,
  /\bstacked queries\b/i,
  /\bSLEEP\s*\(/i,
  /\bWAITFOR\b/i,
  /\bBENCHMARK\s*\(/i,
];

function isBinaryAbsentError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    /Command not found/i.test(msg) ||
    /ENOENT/i.test(msg) ||
    /not found/i.test(msg)
  );
}

function baseResult(
  request: SqlmapRequest,
  status: SqlmapResult['status'],
  reasonCode: string,
  evidenceExcerpt: string,
  extras?: { readonly durationMs?: number; readonly hermeticFallback?: true }
): SqlmapResult {
  return {
    status,
    contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
    targetUrl: typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '',
    parameterName:
      typeof request.parameterName === 'string' ? request.parameterName.trim() : '',
    dbmsHint: request.dbmsHint,
    technique: 'E',
    evidenceExcerpt: sanitizeEvidenceFragment(evidenceExcerpt, EVIDENCE_MAX_CHARS),
    reasonCode,
    explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
    lineage: request.lineage,
    ...(extras?.durationMs !== undefined ? { durationMs: extras.durationMs } : {}),
    ...(extras?.hermeticFallback ? { hermeticFallback: true } : {}),
  };
}

/**
 * Parse sqlmap stdout/stderr into a closed SqlmapResult status.
 * Confirmed requires explicit injectable markers AND no forbidden technique markers.
 * Never auto-confirms on empty or hermetic output.
 */
export function parseSqlmapStructuredOutput(input: {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
  readonly timedOut: boolean;
  readonly durationMs: number;
  readonly targetUrl: string;
  readonly parameterName: string;
  readonly dbmsHint: SqlmapDbmsHint;
  readonly lineage: SqlmapRequest['lineage'];
}): SqlmapResult {
  const combined = `${input.stdout}\n${input.stderr}`;
  const excerpt = sanitizeEvidenceFragment(combined.trim() || 'empty_sqlmap_output', EVIDENCE_MAX_CHARS);

  if (input.timedOut) {
    return {
      status: 'timed_out',
      contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
      targetUrl: input.targetUrl,
      parameterName: input.parameterName,
      dbmsHint: input.dbmsHint,
      technique: 'E',
      evidenceExcerpt: excerpt,
      reasonCode: 'execution_timed_out',
      explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
      lineage: input.lineage,
      durationMs: input.durationMs,
    };
  }

  for (const forbidden of FORBIDDEN_TECHNIQUE_MARKERS) {
    if (forbidden.test(combined)) {
      return {
        status: 'tool_error',
        contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
        targetUrl: input.targetUrl,
        parameterName: input.parameterName,
        dbmsHint: input.dbmsHint,
        technique: 'E',
        evidenceExcerpt: excerpt,
        reasonCode: 'forbidden_technique_signal',
        explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
        lineage: input.lineage,
        durationMs: input.durationMs,
      };
    }
  }

  // Prefer structured JSON lines when present
  let jsonConfirmed = false;
  let jsonRefuted = false;
  for (const line of input.stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
      const rec = parsed as Record<string, unknown>;
      const statusField =
        (typeof rec.status === 'string' && rec.status) ||
        (typeof rec.result === 'string' && rec.result) ||
        '';
      const injectable =
        rec.injectable === true ||
        rec.vulnerable === true ||
        /^(vulnerable|injectable|confirmed)$/i.test(statusField);
      const notInjectable =
        rec.injectable === false ||
        rec.vulnerable === false ||
        /^(refuted|not.?injectable|clean)$/i.test(statusField);
      if (injectable) jsonConfirmed = true;
      if (notInjectable) jsonRefuted = true;
    } catch {
      continue;
    }
  }

  const textRefuted = REFUTED_MARKERS.some((re) => re.test(combined));
  const textConfirmed = CONFIRMED_MARKERS.some((re) => re.test(combined));

  // Explicit refutation wins over ambiguous wording
  if (jsonRefuted || textRefuted) {
    return {
      status: 'refuted',
      contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
      targetUrl: input.targetUrl,
      parameterName: input.parameterName,
      dbmsHint: input.dbmsHint,
      technique: 'E',
      evidenceExcerpt: excerpt,
      reasonCode: 'sql_injection_not_confirmed',
      explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
      lineage: input.lineage,
      durationMs: input.durationMs,
    };
  }

  if (jsonConfirmed || textConfirmed) {
    // Require error-based context when Type: lines are present
    if (/Type:\s+/i.test(combined)) {
      const hasErrorBased = /Type:\s*error-based/i.test(combined);
      if (!hasErrorBased) {
        return {
          status: 'tool_error',
          contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
          targetUrl: input.targetUrl,
          parameterName: input.parameterName,
          dbmsHint: input.dbmsHint,
          technique: 'E',
          evidenceExcerpt: excerpt,
          reasonCode: 'non_error_based_confirmation',
          explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
          lineage: input.lineage,
          durationMs: input.durationMs,
        };
      }
    }

    return {
      status: 'confirmed',
      contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
      targetUrl: input.targetUrl,
      parameterName: input.parameterName,
      dbmsHint: input.dbmsHint,
      technique: 'E',
      evidenceExcerpt: excerpt,
      reasonCode: 'sql_injection_error_based_confirmed',
      explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
      lineage: input.lineage,
      durationMs: input.durationMs,
    };
  }

  if (input.exitCode === 0) {
    return {
      status: 'refuted',
      contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
      targetUrl: input.targetUrl,
      parameterName: input.parameterName,
      dbmsHint: input.dbmsHint,
      technique: 'E',
      evidenceExcerpt: excerpt,
      reasonCode: 'sql_injection_not_confirmed',
      explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
      lineage: input.lineage,
      durationMs: input.durationMs,
    };
  }

  return {
    status: 'tool_error',
    contractVersion: SQLMAP_VERIFICATION_CONTRACT_VERSION,
    targetUrl: input.targetUrl,
    parameterName: input.parameterName,
    dbmsHint: input.dbmsHint,
    technique: 'E',
    evidenceExcerpt: excerpt,
    reasonCode: 'process_execution_failed',
    explicitNonClaims: SQLMAP_VERIFICATION_NON_CLAIMS,
    lineage: input.lineage,
    durationMs: input.durationMs,
  };
}

export class SqlmapAdapter implements SqlmapTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  /**
   * Builds the exact safe CLI argument array.
   * Exposed for hermetic smoke assertions (no process spawn).
   */
  public static buildCliArgs(
    targetUrl: string,
    parameterName: string,
    dbmsHint: SqlmapDbmsHint
  ): ReturnType<typeof buildSafeSqlmapCliArgs> {
    return buildSafeSqlmapCliArgs({ targetUrl, parameterName, dbmsHint });
  }

  async verify(request: SqlmapRequest): Promise<SqlmapResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';
    const rawParam =
      typeof request.parameterName === 'string' ? request.parameterName.trim() : '';

    // -------------------------------------------------------------------------
    // Gate 0: Closed DTO → safe args (blocks flag injection / prohibited flags)
    // -------------------------------------------------------------------------
    const built = buildSafeSqlmapCliArgs({
      targetUrl: rawTarget,
      parameterName: rawParam,
      dbmsHint: request.dbmsHint,
    });
    if (!built.ok) {
      return baseResult(request, 'tool_error', built.reasonCode, built.reason);
    }

    // Defense-in-depth: re-validate final argv before spawn
    const argCheck = validateSqlmapCliArgs(built.args);
    if (!argCheck.ok) {
      return baseResult(request, 'tool_error', argCheck.reasonCode, argCheck.reason);
    }

    // -------------------------------------------------------------------------
    // Unified Atomic Preflight Gate (SSRF / scope / auth / lineage)
    // -------------------------------------------------------------------------
    const preflight = await runAdapterPreflight({
      target: rawTarget,
      targetKind: 'url',
      unsupportedProtocolReasonCode: 'unsupported_url_protocol',
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      authorizedScopeGrant: request.authorizedScopeGrant,
      lineage: request.lineage,
      permissionCheck: (ps) =>
        Boolean(
          ps.activeValidation ||
            ps.lightValidation ||
            ps.endpointDiscovery ||
            ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason:
        'Scope grant does not permit active validation or sqlmap verification',
      targetOutOfScopeReason: 'Target URL host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return baseResult(request, 'tool_error', preflight.reasonCode, preflight.reason);
    }

    const args = [...built.args];
    const timeoutMs = request.timeoutMs ?? 60_000;

    // ProcessRunner / LocalProcessRunner always spawns with shell: false
    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'sqlmap',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      if (isBinaryAbsentError(err)) {
        // Hermetic fallback — never fabricate confirmed
        return baseResult(
          request,
          'tool_error',
          'sqlmap_binary_absent',
          'sqlmap binary not found; hermetic fallback (no confirmation fabricated)',
          { durationMs: 0, hermeticFallback: true }
        );
      }
      const msg = err instanceof Error ? err.message : String(err);
      return baseResult(request, 'tool_error', 'process_launch_failed', msg);
    }

    return parseSqlmapStructuredOutput({
      stdout: output.stdout,
      stderr: output.stderr,
      exitCode: output.exitCode,
      timedOut: output.timedOut,
      durationMs: output.durationMs,
      targetUrl: rawTarget,
      parameterName: rawParam,
      dbmsHint: request.dbmsHint,
      lineage: request.lineage,
    });
  }
}
