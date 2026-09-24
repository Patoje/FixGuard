/**
 * Milestone A7 — LFI Path Traversal Capability
 *
 * Native HTTP probe for authorized defensive verification of path-traversal /
 * local-file inclusion candidates. Allowlisted canaries only; no CLI tools.
 *
 * Blast-radius intent (authorization): read_escalated.
 * Evidence: sanitizeEvidenceFragment() + hard truncates to 128 chars.
 */

import type {
  AttackCapabilityExecutionResult,
  AttackCapabilityInvocationContext,
  AttackCapabilityPort,
} from '../AttackExecutionContracts.js';
import type { IdorHttpProbeTransport, HttpProbeRequest } from '../../detection/DetectionContracts.js';
import { defaultHttpProbeTransport } from '../../detection/IdorDifferentialDetectionService.js';
import {
  INERT_PROBE_PATTERNS,
  detectStructuralLeak,
} from '../../detection/ParameterIntegrityDetectionService.js';
import { sanitizeEvidenceFragment } from '../../core/EvidenceSanitizer.js';

/** Allowlisted deterministic traversal canaries (safe well-known markers only). */
export const LFI_TRAVERSAL_CANARIES: readonly string[] = [...INERT_PROBE_PATTERNS];

const EVIDENCE_MAX_CHARS = 128;

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

function resolveParameterName(ctx: AttackCapabilityInvocationContext): string | undefined {
  if (typeof ctx.plan.parameterName === 'string' && ctx.plan.parameterName.trim().length > 0) {
    return ctx.plan.parameterName.trim();
  }
  for (const finding of ctx.findings) {
    const meta = finding.metadata;
    if (meta.kind === 'parameter_integrity_metadata' && typeof meta.parameterName === 'string') {
      return meta.parameterName;
    }
  }
  return undefined;
}

function buildProbeUrl(baseUrl: string, parameterName: string, canary: string): string {
  try {
    const parsed = new URL(baseUrl);
    parsed.searchParams.set(parameterName, canary);
    return parsed.toString();
  } catch {
    const sep = baseUrl.includes('?') ? '&' : '?';
    return `${baseUrl}${sep}${encodeURIComponent(parameterName)}=${encodeURIComponent(canary)}`;
  }
}

/**
 * Creates the LFI path-traversal AttackCapabilityPort.
 * Injectable transport enables hermetic smoke tests.
 */
export function createLfiPathTraversalCapability(
  transport?: IdorHttpProbeTransport
): AttackCapabilityPort {
  const httpTransport = transport ?? defaultHttpProbeTransport;

  return {
    capability: 'lfi_path_traversal',
    async execute(ctx: AttackCapabilityInvocationContext): Promise<AttackCapabilityExecutionResult> {
      if (!ctx.targetUrl || ctx.targetUrl.trim().length === 0) {
        return failed('lfi_target_missing', 'LFI path traversal capability requires a target URL');
      }

      const parameterName = resolveParameterName(ctx);
      if (!parameterName) {
        return failed(
          'lfi_parameter_missing',
          'LFI path traversal capability requires an observed resource/file parameter name'
        );
      }

      let lastStatus: number | undefined;
      let lastEvidence = '';

      for (const canary of LFI_TRAVERSAL_CANARIES) {
        const probeUrl = buildProbeUrl(ctx.targetUrl, parameterName, canary);
        const probeReq: HttpProbeRequest = {
          url: probeUrl,
          method: 'GET',
          headers: {
            accept: 'text/html, application/xhtml+xml, application/json, */*',
            'user-agent': 'Mozilla/5.0 (FixGuard Defensive Auditor)',
          },
          timeoutMs: 5000,
        };

        let statusCode: number;
        let bodyText: string;
        try {
          const resp = await httpTransport(probeReq);
          statusCode = resp.statusCode;
          bodyText = resp.bodyText ?? '';
        } catch {
          return failed('lfi_transport_failed', 'LFI path traversal probe transport failed');
        }

        lastStatus = statusCode;
        lastEvidence = truncateSanitized(bodyText);

        if (statusCode === 400 || statusCode === 403 || statusCode === 404) {
          return refuted(
            'lfi_boundary_enforced',
            `Target refused traversal probe with HTTP ${statusCode}; evidence=${lastEvidence}`
          );
        }

        const leak = detectStructuralLeak(bodyText);
        if (leak.leaked && leak.excerpt) {
          const evidence = truncateSanitized(leak.excerpt);
          return succeeded(
            'lfi_traversal_marker_matched',
            `Traversal marker matched (${leak.signatureKind ?? 'unknown'}); evidence=${evidence}`,
            `ev_lfi_${ctx.step.stepId}`
          );
        }
      }

      return refuted(
        'lfi_no_traversal_marker',
        `No traversal marker in responses (lastStatus=${lastStatus ?? 'n/a'}); evidence=${lastEvidence}`
      );
    },
  };
}
