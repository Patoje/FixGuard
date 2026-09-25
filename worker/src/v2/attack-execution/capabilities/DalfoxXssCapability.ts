/**
 * V2 Attack Capability — Dalfox XSS / parameter reflection probe.
 *
 * Migrates V1 dalfox usage into an authorize-gated AttackCapabilityPort for
 * `parameter_reflection_probe`. Observations remain epistemic OBSERVED —
 * never automatic verified vulns or severities.
 *
 * Stack policy (caller/recommendation layer): prefer legacy/reflection paths;
 * deprioritize SPA-primary. This capability itself is stack-agnostic and
 * fail-closed when dalfox is absent.
 *
 * AttackExecutionService already enforced 7 safety gates before invocation.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { ProcessRunner } from '../../core/ProcessRunner.js';
import { LocalProcessRunner } from '../../core/ProcessRunner.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';

const EVIDENCE_MAX_CHARS = 128;
const DALFOX_TIMEOUT_MS = 60_000;

export interface DalfoxObservation {
  readonly matchedAt: string;
  readonly evidenceExcerpt: string;
  readonly epistemicStatus: 'OBSERVED';
}

export type DalfoxObservationProvider = (args: {
  readonly targetUrl: string;
  readonly parameterName?: string;
  readonly headers?: Readonly<Record<string, string>>;
}) => Promise<readonly DalfoxObservation[]>;

function truncateSanitized(raw: string): string {
  const sanitized = sanitizeEvidenceFragment(raw);
  return sanitized.length > EVIDENCE_MAX_CHARS
    ? sanitized.slice(0, EVIDENCE_MAX_CHARS)
    : sanitized;
}

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

function isBinaryAbsentError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /Command not found/i.test(msg) || /ENOENT/i.test(msg);
}

/**
 * Build dalfox CLI args — defensive, non-interactive, JSON output.
 * Prefer reflection/legacy parameter paths; no blind mining spray.
 */
export function buildDalfoxCliArgs(args: {
  readonly targetUrl: string;
  readonly parameterName?: string;
  readonly cookieHeader?: string;
}): readonly string[] {
  const cli: string[] = ['url', args.targetUrl, '--silence', '--format', 'json'];
  if (args.parameterName && args.parameterName.trim().length > 0) {
    cli.push('-p', args.parameterName.trim());
  }
  // Skip mining / deep DOM for SPA-hostile noise; focus reflection confirmation.
  cli.push('--skip-mining-all', '--skip-bav');
  if (args.cookieHeader && args.cookieHeader.trim().length > 0) {
    cli.push('-C', args.cookieHeader.trim());
  }
  return Object.freeze(cli);
}

function extractCookieHeader(
  headers: Readonly<Record<string, string>> | undefined
): string | undefined {
  if (!headers) return undefined;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'cookie' && typeof v === 'string' && v.trim().length > 0) {
      return v.trim();
    }
  }
  return undefined;
}

function parseDalfoxStdout(stdout: string, targetUrl: string): readonly DalfoxObservation[] {
  const out: DalfoxObservation[] = [];
  const lines = stdout.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let rec: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) continue;
      rec = parsed as Record<string, unknown>;
    } catch {
      // dalfox may emit a single JSON array
      try {
        const parsed: unknown = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          for (const item of parsed) {
            if (!item || typeof item !== 'object' || Array.isArray(item)) continue;
            const row = item as Record<string, unknown>;
            const type =
              (typeof row.type === 'string' && row.type) ||
              (typeof row['poc_type'] === 'string' && row['poc_type']) ||
              '';
            if (!/xss|reflected|verify/i.test(type) && type.length > 0) {
              // Still accept rows with data/param evidence.
            }
            const excerpt = truncateSanitized(
              typeof row.data === 'string'
                ? row.data
                : typeof row.param === 'string'
                  ? `param=${row.param}`
                  : 'dalfox_match'
            );
            out.push({
              matchedAt: targetUrl,
              evidenceExcerpt: excerpt,
              epistemicStatus: 'OBSERVED',
            });
          }
        }
      } catch {
        // ignore non-JSON
      }
      continue;
    }

    const type =
      (typeof rec.type === 'string' && rec.type) ||
      (typeof rec['poc_type'] === 'string' && rec['poc_type']) ||
      '';
    if (type.length > 0 && !/xss|reflected|verify|vuln/i.test(type)) {
      continue;
    }
    const excerpt = truncateSanitized(
      typeof rec.data === 'string'
        ? rec.data
        : typeof rec.param === 'string'
          ? `param=${rec.param}`
          : typeof rec.message === 'string'
            ? rec.message
            : 'dalfox_match'
    );
    out.push({
      matchedAt:
        (typeof rec.url === 'string' && rec.url.trim()) ||
        (typeof rec['injected_url'] === 'string' && rec['injected_url'].trim()) ||
        targetUrl,
      evidenceExcerpt: excerpt,
      epistemicStatus: 'OBSERVED',
    });
  }
  return out;
}

/**
 * Creates parameter_reflection_probe AttackCapabilityPort backed by dalfox.
 */
export function createDalfoxParameterReflectionCapability(options?: {
  readonly observationProvider?: DalfoxObservationProvider;
  readonly processRunner?: ProcessRunner;
}): AttackCapabilityPort {
  const runner = options?.processRunner ?? new LocalProcessRunner();

  const defaultProvider: DalfoxObservationProvider = async ({
    targetUrl,
    parameterName,
    headers,
  }) => {
    const cookieHeader = extractCookieHeader(headers);
    const args = buildDalfoxCliArgs({
      targetUrl,
      ...(parameterName ? { parameterName } : {}),
      ...(cookieHeader ? { cookieHeader } : {}),
    });
    try {
      const output = await runner.execute({
        binary: 'dalfox',
        args: [...args],
        timeoutMs: DALFOX_TIMEOUT_MS,
      });
      if (output.timedOut) {
        return [];
      }
      // dalfox exits non-zero on some "no vuln" paths — still parse stdout.
      return parseDalfoxStdout(output.stdout, targetUrl);
    } catch (err: unknown) {
      if (isBinaryAbsentError(err)) {
        throw new Error('dalfox_binary_absent');
      }
      throw err;
    }
  };

  const provider = options?.observationProvider ?? defaultProvider;

  return {
    capability: 'parameter_reflection_probe',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed(
          'dalfox_target_missing',
          'Parameter reflection probe requires a target URL'
        );
      }

      const planParam =
        typeof ctx.plan.parameterName === 'string' && ctx.plan.parameterName.trim().length > 0
          ? ctx.plan.parameterName.trim()
          : undefined;

      let observations: readonly DalfoxObservation[];
      try {
        observations = await provider({
          targetUrl: ctx.targetUrl,
          ...(planParam ? { parameterName: planParam } : {}),
          ...(ctx.primaryIdentity?.headers
            ? { headers: ctx.primaryIdentity.headers }
            : {}),
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'dalfox_binary_absent' || /dalfox_binary_absent/.test(msg)) {
          return failed(
            'dalfox_binary_absent',
            'dalfox binary not found on PATH (degraded; install to enable reflection probe)'
          );
        }
        return failed('dalfox_probe_failed', truncateSanitized(msg));
      }

      if (observations.length === 0) {
        return refuted(
          'dalfox_no_reflection_observed',
          'No OBSERVED dalfox XSS/reflection PoC on target'
        );
      }

      for (const obs of observations) {
        if (obs.epistemicStatus !== 'OBSERVED') {
          return failed(
            'dalfox_epistemic_invariant',
            'Dalfox observations must carry epistemicStatus OBSERVED only'
          );
        }
      }

      const first = observations[0]!;
      return observed(
        'dalfox_reflection_observed',
        `OBSERVED dalfox reflection/XSS match count=${observations.length}; evidence=${first.evidenceExcerpt}`,
        `ev_dalfox_${ctx.step.stepId}`
      );
    },
  };
}
