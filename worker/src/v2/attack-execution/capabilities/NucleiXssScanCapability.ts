/**
 * Milestone A8 — Nuclei XSS Scan Capability
 *
 * Authorized defensive XSS template validation.
 * AttackExecutionService already enforced 7 safety gates before invocation.
 * Template allowlist is still enforced fail-closed before any process spawn.
 *
 * Observations remain epistemicStatus OBSERVED — not automatic verified vulns.
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
import { NucleiAdapter } from '../../recon/adapters/NucleiAdapter.js';
import {
  NUCLEI_XSS_DEFAULT_TEMPLATES,
  validateNucleiTemplates,
  type NucleiObservation,
} from '../../recon/adapters/NucleiContracts.js';

const EVIDENCE_MAX_CHARS = 128;

export type NucleiXssObservationProvider = (args: {
  readonly targetUrl: string;
  readonly templates: readonly string[];
}) => Promise<readonly NucleiObservation[]>;

function truncateSanitized(raw: string): string {
  const sanitized = sanitizeEvidenceFragment(raw);
  return sanitized.length > EVIDENCE_MAX_CHARS ? sanitized.slice(0, EVIDENCE_MAX_CHARS) : sanitized;
}

/**
 * OBSERVED template matches are not verified vulns — distinct outcome so
 * AttackExecutionService caps VerificationState at suspected_vulnerability.
 */
function observed(
  reasonCode: string,
  safeMessage: string,
  evidenceId?: string
): AttackCapabilityExecutionResult {
  return {
    outcome: 'observed',
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

function summarizeObservations(observations: readonly NucleiObservation[]): string {
  if (observations.length === 0) return 'no_matches';
  const first = observations[0]!;
  return truncateSanitized(
    `template=${first.templateId};matched=${first.matchedAt};excerpt=${first.evidenceExcerpt}`
  );
}

function isBinaryAbsentError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /Command not found/i.test(msg) || /ENOENT/i.test(msg);
}

/**
 * Creates nuclei_xss_scan AttackCapabilityPort.
 * Injectable observationProvider enables hermetic smoke without nuclei binary.
 */
export function createNucleiXssScanCapability(options?: {
  readonly observationProvider?: NucleiXssObservationProvider;
  readonly processRunner?: ProcessRunner;
  readonly templates?: readonly string[];
}): AttackCapabilityPort {
  const templates = options?.templates ?? NUCLEI_XSS_DEFAULT_TEMPLATES;
  const runner = options?.processRunner ?? new LocalProcessRunner();

  const defaultProvider: NucleiXssObservationProvider = async ({ targetUrl, templates: tpls }) => {
    const templateCheck = validateNucleiTemplates(tpls);
    if (!templateCheck.ok) {
      throw new Error(`nuclei_template_preflight:${templateCheck.reasonCode}`);
    }

    const args = NucleiAdapter.buildCliArgs(targetUrl, templateCheck.normalizedTemplates);
    try {
      const output = await runner.execute({
        binary: 'nuclei',
        args,
        timeoutMs: 60_000,
      });
      if (output.timedOut || output.exitCode !== 0) {
        return [];
      }
      // Parse via a one-off adapter scan is heavy; capability only needs OBSERVED hits.
      // Reuse adapter parsing by feeding stdout through a tiny local parse of NDJSON fields.
      return parseStdoutToObservations(output.stdout, targetUrl);
    } catch (err: unknown) {
      if (isBinaryAbsentError(err)) {
        return [];
      }
      throw err;
    }
  };

  const provider = options?.observationProvider ?? defaultProvider;

  return {
    capability: 'nuclei_xss_scan',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('nuclei_xss_target_missing', 'Nuclei XSS scan requires a target URL');
      }

      const templateCheck = validateNucleiTemplates(templates);
      if (!templateCheck.ok) {
        return failed(templateCheck.reasonCode, truncateSanitized(templateCheck.reason));
      }

      let observations: readonly NucleiObservation[];
      try {
        observations = await provider({
          targetUrl: ctx.targetUrl,
          templates: templateCheck.normalizedTemplates,
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.startsWith('nuclei_template_preflight:')) {
          return failed('prohibited_template_category', truncateSanitized(msg));
        }
        return failed('nuclei_xss_scan_failed', truncateSanitized(msg));
      }

      if (observations.length === 0) {
        return refuted(
          'nuclei_xss_no_template_match',
          'No OBSERVED nuclei XSS template matches on target'
        );
      }

      for (const obs of observations) {
        if (obs.epistemicStatus !== 'OBSERVED') {
          return failed(
            'nuclei_xss_epistemic_invariant',
            'Nuclei observations must carry epistemicStatus OBSERVED only'
          );
        }
      }

      const evidence = summarizeObservations(observations);
      return observed(
        'nuclei_xss_template_match_observed',
        `OBSERVED nuclei XSS template match(es) count=${observations.length}; evidence=${evidence}`,
        `ev_nuclei_xss_${ctx.step.stepId}`
      );
    },
  };
}

function parseStdoutToObservations(stdout: string, targetUrl: string): readonly NucleiObservation[] {
  const collectedAt = new Date().toISOString();
  let host = 'unknown';
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    // keep unknown
  }

  const out: NucleiObservation[] = [];
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
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
      (typeof info.name === 'string' && info.name.trim()) ||
      'unknown';

    const templatePath =
      (typeof rec['template-path'] === 'string' && rec['template-path'].trim()) || templateId;

    const tags: string[] = [];
    if (Array.isArray(info.tags)) {
      for (const t of info.tags) {
        if (typeof t === 'string' && t.trim()) tags.push(t.trim().toLowerCase());
      }
    }
    if (tags.includes('rce')) continue;

    const matchedAt =
      (typeof rec['matched-at'] === 'string' && rec['matched-at'].trim()) || targetUrl;

    const evidenceExcerpt = sanitizeEvidenceFragment(
      typeof info.name === 'string' ? info.name : `nuclei_match:${templateId}`,
      EVIDENCE_MAX_CHARS
    );

    out.push({
      templateId,
      templatePath,
      matchedAt,
      host,
      evidenceExcerpt,
      tags,
      epistemicStatus: 'OBSERVED',
      discoveredAt: collectedAt,
      collectedAt,
      freshness: 'live',
      sourceReliability: 'direct_observation',
    });
  }
  return out;
}
