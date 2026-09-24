/**
 * Milestone A8 — Nuclei Adapter
 *
 * Authorized defensive template scanning via ProcessRunner (shell: false).
 * Fail-closed template allowlist BEFORE process spawn.
 * Always passes -no-interactsh. Observations are epistemicStatus OBSERVED only.
 */

import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';
import {
  runAdapterPreflight,
  type PreSpawnDnsResolver,
} from './AdapterPreflightPipeline.js';
import {
  NUCLEI_SCAN_CONTRACT_VERSION,
  NUCLEI_SCAN_NON_CLAIMS,
  validateNucleiTemplates,
  type NucleiObservation,
  type NucleiRequest,
  type NucleiResult,
  type NucleiTool,
} from './NucleiContracts.js';

const EVIDENCE_MAX_CHARS = 256;

const REQUIRED_FLAGS: readonly string[] = [
  '-json',
  '-silent',
  '-no-interactsh',
  '-rate-limit',
  '10',
  '-timeout',
  '10',
] as const;

function isBinaryAbsentError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    /Command not found/i.test(msg) ||
    /ENOENT/i.test(msg) ||
    /not found/i.test(msg)
  );
}

function buildNucleiArgs(targetUrl: string, templates: readonly string[]): string[] {
  const args: string[] = ['-u', targetUrl];
  for (const template of templates) {
    args.push('-t', template);
  }
  for (const flag of REQUIRED_FLAGS) {
    args.push(flag);
  }
  return args;
}

function parseTags(raw: unknown): readonly string[] {
  if (!Array.isArray(raw)) return [];
  const tags: string[] = [];
  for (const item of raw) {
    if (typeof item === 'string' && item.trim().length > 0) {
      tags.push(item.trim().toLowerCase());
    }
  }
  return tags;
}

function observationContainsRce(tags: readonly string[], templateId: string, templatePath: string): boolean {
  if (tags.includes('rce')) return true;
  const hay = `${templateId} ${templatePath}`.toLowerCase();
  return /(^|[/_-])rce([/_-]|$)/.test(hay);
}

function parseNucleiStdout(stdout: string, fallbackHost: string): readonly NucleiObservation[] {
  const observations: NucleiObservation[] = [];
  const seen = new Set<string>();
  const collectedAt = new Date().toISOString();

  const lines = stdout.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let rec: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        continue;
      }
      rec = parsed as Record<string, unknown>;
    } catch {
      continue;
    }

    const info =
      rec.info && typeof rec.info === 'object' && !Array.isArray(rec.info)
        ? (rec.info as Record<string, unknown>)
        : {};

    const templateId =
      (typeof rec['template-id'] === 'string' && rec['template-id'].trim()) ||
      (typeof rec.templateID === 'string' && rec.templateID.trim()) ||
      (typeof info.name === 'string' && info.name.trim()) ||
      'unknown';

    const templatePath =
      (typeof rec['template-path'] === 'string' && rec['template-path'].trim()) ||
      (typeof rec.template === 'string' && rec.template.trim()) ||
      (typeof rec['template-url'] === 'string' && rec['template-url'].trim()) ||
      templateId;

    const tags = parseTags(info.tags);
    if (observationContainsRce(tags, templateId, templatePath)) {
      // Drop RCE-tagged hits even if somehow emitted — fail-closed observation filter
      continue;
    }

    const matchedAt =
      (typeof rec['matched-at'] === 'string' && rec['matched-at'].trim()) ||
      (typeof rec.matched === 'string' && rec.matched.trim()) ||
      (typeof rec.host === 'string' && rec.host.trim()) ||
      fallbackHost;

    let host = fallbackHost;
    try {
      host = new URL(matchedAt.startsWith('http') ? matchedAt : `https://${matchedAt}`).hostname
        .toLowerCase()
        .replace(/\.$/, '');
    } catch {
      if (typeof rec.host === 'string' && rec.host.trim()) {
        host = rec.host.trim().toLowerCase().replace(/\.$/, '');
      }
    }

    const matcherName =
      typeof rec['matcher-name'] === 'string' && rec['matcher-name'].trim()
        ? rec['matcher-name'].trim()
        : undefined;

    const rawExcerptCandidates: string[] = [];
    if (typeof rec['extracted-results'] === 'string') {
      rawExcerptCandidates.push(rec['extracted-results']);
    } else if (Array.isArray(rec['extracted-results'])) {
      for (const er of rec['extracted-results']) {
        if (typeof er === 'string') rawExcerptCandidates.push(er);
      }
    }
    if (typeof rec['curl-command'] === 'string') {
      // Never persist curl-command (may contain secrets) — skip
    }
    if (typeof info.name === 'string') {
      rawExcerptCandidates.push(info.name);
    }
    if (matcherName) {
      rawExcerptCandidates.push(matcherName);
    }

    const evidenceExcerpt = sanitizeEvidenceFragment(
      rawExcerptCandidates.join(' | ') || `nuclei_match:${templateId}`,
      EVIDENCE_MAX_CHARS
    );

    const dedupKey = `${templateId}|${matchedAt}|${matcherName ?? ''}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const observation: NucleiObservation = {
      templateId,
      templatePath,
      matchedAt,
      host,
      ...(matcherName ? { matcherName } : {}),
      evidenceExcerpt,
      tags,
      epistemicStatus: 'OBSERVED',
      discoveredAt: collectedAt,
      collectedAt,
      freshness: 'live',
      sourceReliability: 'direct_observation',
    };
    observations.push(observation);
  }

  return observations;
}

export class NucleiAdapter implements NucleiTool {
  constructor(
    private readonly processRunner: ProcessRunner,
    private readonly dnsResolver?: PreSpawnDnsResolver
  ) {}

  /**
   * Builds the exact CLI argument array for an allowlisted request.
   * Exposed for hermetic smoke assertions (no process spawn).
   */
  public static buildCliArgs(targetUrl: string, templates: readonly string[]): string[] {
    return buildNucleiArgs(targetUrl, templates);
  }

  async scan(request: NucleiRequest): Promise<NucleiResult> {
    const rawTarget = typeof request.targetUrl === 'string' ? request.targetUrl.trim() : '';
    const rawTemplates = request.templates;

    // -------------------------------------------------------------------------
    // Gate 0: Template allowlist / prohibit — BEFORE any spawn or network
    // -------------------------------------------------------------------------
    const templateCheck = validateNucleiTemplates(rawTemplates);
    if (!templateCheck.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
        targetUrl: rawTarget,
        templates: Array.isArray(rawTemplates) ? [...rawTemplates] : [],
        reasonCode: templateCheck.reasonCode,
        reason: templateCheck.reason,
        explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const templates = templateCheck.normalizedTemplates;

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
            ps.technologyFingerprinting ||
            ps.activeCrawling ||
            ps.passiveRecon ||
            ('activeRecon' in ps && (ps as { activeRecon?: boolean }).activeRecon)
        ),
      missingPermissionReason: 'Scope grant does not permit active validation or nuclei scanning',
      targetOutOfScopeReason: 'Target URL host is outside authorized scope boundaries',
      dnsResolver: this.dnsResolver,
    });

    if (!preflight.ok) {
      return {
        status: 'preflight_denied',
        contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
        targetUrl: rawTarget,
        templates,
        reasonCode: preflight.reasonCode,
        reason: preflight.reason,
        explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    const args = buildNucleiArgs(rawTarget, templates);
    // ProcessRunner / LocalProcessRunner always spawns with shell: false
    const timeoutMs = request.timeoutMs ?? 60_000;

    let output;
    try {
      output = await this.processRunner.execute({
        binary: 'nuclei',
        args,
        timeoutMs,
      });
    } catch (err: unknown) {
      if (isBinaryAbsentError(err)) {
        // Hermetic fallback when nuclei binary is not installed — zero fabricated hits
        return {
          status: 'success',
          contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
          targetUrl: rawTarget,
          templates,
          observations: [],
          explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
          lineage: request.lineage,
          durationMs: 0,
          hermeticFallback: true,
        };
      }
      const msg = err instanceof Error ? err.message : String(err);
      return {
        status: 'execution_failed',
        contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
        targetUrl: rawTarget,
        templates,
        reasonCode: 'process_launch_failed',
        reason: msg,
        explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
        lineage: request.lineage,
      };
    }

    if (output.timedOut) {
      return {
        status: 'execution_failed',
        contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
        targetUrl: rawTarget,
        templates,
        reasonCode: 'execution_timed_out',
        reason: `nuclei execution timed out after ${timeoutMs}ms`,
        explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: sanitizeEvidenceFragment(output.stderr, EVIDENCE_MAX_CHARS),
        durationMs: output.durationMs,
      };
    }

    if (output.exitCode !== 0) {
      return {
        status: 'execution_failed',
        contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
        targetUrl: rawTarget,
        templates,
        reasonCode: 'process_execution_failed',
        reason:
          sanitizeEvidenceFragment(output.stderr.trim(), EVIDENCE_MAX_CHARS) ||
          `nuclei exited with non-zero exit code: ${output.exitCode}`,
        explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
        lineage: request.lineage,
        exitCode: output.exitCode,
        stderr: sanitizeEvidenceFragment(output.stderr, EVIDENCE_MAX_CHARS),
        durationMs: output.durationMs,
      };
    }

    const observations = parseNucleiStdout(output.stdout, preflight.targetHost);

    return {
      status: 'success',
      contractVersion: NUCLEI_SCAN_CONTRACT_VERSION,
      targetUrl: rawTarget,
      templates,
      observations,
      explicitNonClaims: NUCLEI_SCAN_NON_CLAIMS,
      lineage: request.lineage,
      durationMs: output.durationMs,
    };
  }
}
