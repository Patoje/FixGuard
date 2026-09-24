/**
 * Milestone A8 — Nuclei Adapter Contracts
 * Contract version: fixguard-nuclei-scan/v0
 *
 * Nuclei template hits are OBSERVED matcher events only.
 * They do NOT automatically confirm verified vulnerabilities.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedActiveReconRequestLineage } from '../../lineage/AuthorizedExecutionLineageContracts.js';

export type NucleiScanContractVersion = 'fixguard-nuclei-scan/v0';
export const NUCLEI_SCAN_CONTRACT_VERSION: NucleiScanContractVersion = 'fixguard-nuclei-scan/v0';

/** Allowlisted template path prefixes (exact prefix match). */
export const NUCLEI_TEMPLATE_ALLOWLIST_PREFIXES: readonly string[] = [
  'http/fuzzing/xss-',
  'http/miscellaneous/',
  'http/technologies/',
  'http/exposures/',
] as const;

/** Permanently prohibited template path prefixes — fail-closed before spawn. */
export const NUCLEI_TEMPLATE_PROHIBITED_PREFIXES: readonly string[] = [
  'network/',
  'headless/',
  'javascript/',
  'workflows/',
  'dns/',
  'file/',
  'code/',
] as const;

export interface NucleiScanExplicitNonClaims {
  readonly createsRealFindings: false;
  readonly createsPersistedEvidence: false;
  readonly confirmsVulnerabilities: false;
  readonly makesRiskClaims: false;
  readonly makesSeverityClaims: false;
  readonly makesImpactClaims: false;
  readonly executesNetworkPayloads: false;
  readonly severity: 'info';
}

export const NUCLEI_SCAN_NON_CLAIMS: NucleiScanExplicitNonClaims = Object.freeze({
  createsRealFindings: false,
  createsPersistedEvidence: false,
  confirmsVulnerabilities: false,
  makesRiskClaims: false,
  makesSeverityClaims: false,
  makesImpactClaims: false,
  executesNetworkPayloads: false,
  severity: 'info',
});

/**
 * Observed nuclei matcher hit. epistemicStatus is always OBSERVED —
 * template match ≠ verified vulnerability.
 */
export interface NucleiObservation {
  readonly templateId: string;
  readonly templatePath: string;
  readonly matchedAt: string;
  readonly host: string;
  readonly matcherName?: string;
  readonly evidenceExcerpt: string;
  readonly tags: readonly string[];
  readonly epistemicStatus: 'OBSERVED';
  readonly discoveredAt: string;
  readonly collectedAt: string;
  readonly freshness: 'live';
  readonly sourceReliability: 'direct_observation';
}

export interface NucleiRequest {
  readonly targetUrl: string;
  readonly templates: readonly string[];
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly authorizedScopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly timeoutMs?: number;
}

export type NucleiResult =
  | {
      readonly status: 'success';
      readonly contractVersion: NucleiScanContractVersion;
      readonly targetUrl: string;
      readonly templates: readonly string[];
      readonly observations: readonly NucleiObservation[];
      readonly explicitNonClaims: NucleiScanExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly durationMs: number;
      /** True when nuclei binary was absent and hermetic empty result was returned. */
      readonly hermeticFallback?: true;
    }
  | {
      readonly status: 'preflight_denied';
      readonly contractVersion: NucleiScanContractVersion;
      readonly targetUrl: string;
      readonly templates: readonly string[];
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: NucleiScanExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
    }
  | {
      readonly status: 'execution_failed';
      readonly contractVersion: NucleiScanContractVersion;
      readonly targetUrl: string;
      readonly templates: readonly string[];
      readonly reasonCode: string;
      readonly reason: string;
      readonly explicitNonClaims: NucleiScanExplicitNonClaims;
      readonly lineage: AuthorizedActiveReconRequestLineage;
      readonly exitCode?: number;
      readonly stderr?: string;
      readonly durationMs?: number;
    };

export interface NucleiTool {
  scan(request: NucleiRequest): Promise<NucleiResult>;
}

export type NucleiTemplateValidationResult =
  | { readonly ok: true; readonly normalizedTemplates: readonly string[] }
  | { readonly ok: false; readonly reasonCode: string; readonly reason: string };

/**
 * Fail-closed template selector validation.
 * Rejects prohibited categories, RCE tags, path traversal, and absolute/arbitrary paths
 * BEFORE any process spawn.
 */
export function validateNucleiTemplates(
  templates: readonly string[] | undefined
): NucleiTemplateValidationResult {
  if (!Array.isArray(templates) || templates.length === 0) {
    return {
      ok: false,
      reasonCode: 'templates_missing',
      reason: 'At least one nuclei template selector is required',
    };
  }

  const normalized: string[] = [];

  for (const raw of templates) {
    if (typeof raw !== 'string' || raw.trim().length === 0) {
      return {
        ok: false,
        reasonCode: 'invalid_template_selector',
        reason: 'Template selector must be a non-empty string',
      };
    }

    const trimmed = raw.trim();

    // Path traversal / arbitrary path injection
    if (
      trimmed.includes('..') ||
      trimmed.includes('\\') ||
      trimmed.includes('\0') ||
      trimmed.startsWith('/') ||
      trimmed.startsWith('~') ||
      /^[a-zA-Z]:[\\/]/.test(trimmed) ||
      trimmed.includes('://')
    ) {
      return {
        ok: false,
        reasonCode: 'unsafe_template_path',
        reason: 'Path traversal or absolute/arbitrary template paths are prohibited',
      };
    }

    const lower = trimmed.toLowerCase();

    // Permanently prohibited category prefixes
    for (const prohibited of NUCLEI_TEMPLATE_PROHIBITED_PREFIXES) {
      if (lower.startsWith(prohibited) || lower.includes('/' + prohibited)) {
        return {
          ok: false,
          reasonCode: 'prohibited_template_category',
          reason: `Template category "${prohibited}" is permanently prohibited`,
        };
      }
    }

    // RCE tag / path segment — fail-closed
    const segments = lower.split(/[/,_.-]+/);
    if (segments.includes('rce') || lower.includes('/rce') || lower.includes('rce-') || lower.endsWith('-rce')) {
      return {
        ok: false,
        reasonCode: 'prohibited_template_tag_rce',
        reason: 'Templates tagged or named with rce are permanently prohibited',
      };
    }

    // Must match allowlist prefix
    const allowed = NUCLEI_TEMPLATE_ALLOWLIST_PREFIXES.some((prefix) => lower.startsWith(prefix));
    if (!allowed) {
      return {
        ok: false,
        reasonCode: 'template_not_allowlisted',
        reason: `Template selector is outside the closed allowlist prefixes`,
      };
    }

    normalized.push(trimmed);
  }

  return { ok: true, normalizedTemplates: normalized };
}

/** Default allowlisted XSS template selector for nuclei_xss_scan capability. */
export const NUCLEI_XSS_DEFAULT_TEMPLATES: readonly string[] = [
  'http/fuzzing/xss-',
] as const;
