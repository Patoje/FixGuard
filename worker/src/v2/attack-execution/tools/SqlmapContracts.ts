/**
 * Milestone A9 — Sqlmap Adapter Contracts
 * Contract version: fixguard-sqlmap-verification/v0
 *
 * Error-based SQL injection verification ONLY (--technique=E).
 * Permanently prohibits shell, dump, and query-execution flags.
 * Caller DTOs cannot inject extra CLI flags.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type SqlmapVerificationContractVersion = 'fixguard-sqlmap-verification/v0';
export const SQLMAP_VERIFICATION_CONTRACT_VERSION: SqlmapVerificationContractVersion =
  'fixguard-sqlmap-verification/v0';

/**
 * Hardcoded safe sqlmap parameters (always appended; never caller-supplied).
 * --technique=E → error-based ONLY (no time-based sleep, no blind, no union).
 */
export const SQLMAP_HARDCODED_SAFE_FLAGS: readonly string[] = [
  '--batch',
  '--technique=E',
  '--level=1',
  '--risk=1',
  '--no-cast',
] as const;

/**
 * Permanently prohibited flags — fail-closed BEFORE process spawn.
 * Includes long-form and common short aliases that enable shell/dump/query abuse.
 */
export const SQLMAP_PROHIBITED_FLAGS: readonly string[] = [
  '--os-shell',
  '--os-cmd',
  '--os-pwn',
  '--file-read',
  '--file-write',
  '--dump',
  '--dump-all',
  '--sql-shell',
  '--sql-query',
] as const;

/** Closed DBMS hint allowlist — never pass arbitrary strings as --dbms. */
export type SqlmapDbmsHint =
  | 'mysql'
  | 'postgresql'
  | 'mssql'
  | 'oracle'
  | 'sqlite';

export const SQLMAP_DBMS_HINT_ALLOWLIST: readonly SqlmapDbmsHint[] = [
  'mysql',
  'postgresql',
  'mssql',
  'oracle',
  'sqlite',
] as const;

export interface SqlmapVerificationExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesOsCommands: false;
  readonly dumpsDatabase: false;
  readonly severity: 'info';
}

export const SQLMAP_VERIFICATION_NON_CLAIMS: SqlmapVerificationExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesOsCommands: false,
  dumpsDatabase: false,
  severity: 'info',
});

/**
 * Request DTO — closed fields only.
 * MUST NOT accept extraArgs / flags / technique overrides.
 */
export interface SqlmapRequest {
  readonly targetUrl: string;
  readonly parameterName: string;
  readonly dbmsHint: SqlmapDbmsHint;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type SqlmapResultStatus = 'confirmed' | 'refuted' | 'timed_out' | 'tool_error';

export interface SqlmapResult {
  readonly status: SqlmapResultStatus;
  readonly contractVersion: SqlmapVerificationContractVersion;
  readonly targetUrl: string;
  readonly parameterName: string;
  readonly dbmsHint: SqlmapDbmsHint;
  readonly technique: 'E';
  readonly evidenceExcerpt: string;
  readonly reasonCode: string;
  readonly explicitNonClaims: SqlmapVerificationExplicitNonClaims;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly durationMs?: number;
  /** True when sqlmap binary was absent — never fabricates confirmed. */
  readonly hermeticFallback?: true;
}

export interface SqlmapTool {
  verify(request: SqlmapRequest): Promise<SqlmapResult>;
}

export type SqlmapArgValidationResult =
  | { readonly ok: true; readonly args: readonly string[] }
  | { readonly ok: false; readonly reasonCode: string; readonly reason: string };

const PARAMETER_NAME_REGEX = /^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,127}$/;

function looksLikeCliFlag(token: string): boolean {
  const t = token.trim().toLowerCase();
  return t.startsWith('-') || t.includes('--');
}

/**
 * Fail-closed scan of a CLI argument array for permanently prohibited flags.
 * Also rejects any arg that embeds a prohibited flag as a prefix (`--dump=users`).
 */
export function findProhibitedSqlmapFlag(args: readonly string[]): string | null {
  for (const raw of args) {
    if (typeof raw !== 'string') continue;
    const token = raw.trim().toLowerCase();
    if (!token) continue;
    for (const prohibited of SQLMAP_PROHIBITED_FLAGS) {
      const p = prohibited.toLowerCase();
      if (token === p || token.startsWith(p + '=') || token.startsWith(p + ' ')) {
        return prohibited;
      }
    }
  }
  return null;
}

/**
 * Validates closed request fields and builds the exact safe CLI argument array.
 * Caller cannot inject technique/dump/shell flags via DTO fields.
 */
export function buildSafeSqlmapCliArgs(input: {
  readonly targetUrl: string;
  readonly parameterName: string;
  readonly dbmsHint: SqlmapDbmsHint;
}): SqlmapArgValidationResult {
  const targetUrl = typeof input.targetUrl === 'string' ? input.targetUrl.trim() : '';
  if (!targetUrl) {
    return {
      ok: false,
      reasonCode: 'target_url_missing',
      reason: 'Sqlmap verification requires a non-empty targetUrl',
    };
  }
  if (looksLikeCliFlag(targetUrl) || /\s--/.test(targetUrl)) {
    return {
      ok: false,
      reasonCode: 'target_url_flag_injection',
      reason: 'targetUrl must not embed CLI flags',
    };
  }

  const parameterName =
    typeof input.parameterName === 'string' ? input.parameterName.trim() : '';
  if (!parameterName || !PARAMETER_NAME_REGEX.test(parameterName)) {
    return {
      ok: false,
      reasonCode: 'invalid_parameter_name',
      reason: 'parameterName must be a closed alphanumeric identifier (no CLI flags)',
    };
  }
  if (looksLikeCliFlag(parameterName)) {
    return {
      ok: false,
      reasonCode: 'parameter_flag_injection',
      reason: 'parameterName must not look like a CLI flag',
    };
  }

  const dbmsHint = input.dbmsHint;
  let dbmsAllowed = false;
  if (typeof dbmsHint === 'string') {
    for (const allowed of SQLMAP_DBMS_HINT_ALLOWLIST) {
      if (allowed === dbmsHint) {
        dbmsAllowed = true;
        break;
      }
    }
  }
  if (!dbmsAllowed) {
    return {
      ok: false,
      reasonCode: 'invalid_dbms_hint',
      reason: 'dbmsHint must be one of the closed SqlmapDbmsHint allowlist values',
    };
  }

  const args: string[] = [
    '-u',
    targetUrl,
    '-p',
    parameterName,
    '--dbms',
    dbmsHint,
    ...SQLMAP_HARDCODED_SAFE_FLAGS,
  ];

  const prohibited = findProhibitedSqlmapFlag(args);
  if (prohibited !== null) {
    return {
      ok: false,
      reasonCode: 'prohibited_flag',
      reason: `Prohibited sqlmap flag "${prohibited}" is permanently blocked`,
    };
  }

  // Invariant: technique must remain error-based only
  if (!args.includes('--technique=E')) {
    return {
      ok: false,
      reasonCode: 'technique_invariant_violated',
      reason: 'Safe sqlmap args must hardcode --technique=E',
    };
  }
  if (args.some((a) => /^--technique=/.test(a) && a !== '--technique=E')) {
    return {
      ok: false,
      reasonCode: 'technique_invariant_violated',
      reason: 'Non-error-based sqlmap techniques are permanently prohibited',
    };
  }

  return { ok: true, args };
}

/**
 * Runtime gate for arbitrary argument arrays (smoke / defense-in-depth).
 * Rejects prohibited flags before any spawn.
 */
export function validateSqlmapCliArgs(args: readonly string[]): SqlmapArgValidationResult {
  if (!Array.isArray(args)) {
    return {
      ok: false,
      reasonCode: 'invalid_args',
      reason: 'CLI args must be a string array',
    };
  }
  const prohibited = findProhibitedSqlmapFlag(args);
  if (prohibited !== null) {
    return {
      ok: false,
      reasonCode: 'prohibited_flag',
      reason: `Prohibited sqlmap flag "${prohibited}" is permanently blocked before spawn`,
    };
  }
  return { ok: true, args: [...args] };
}
