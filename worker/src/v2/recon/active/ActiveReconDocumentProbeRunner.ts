import { isRuntimeEstablishedVerifiedAuthorizationDecision, validateVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateEgressPolicy } from '../policy/PassiveEgressPolicy.js';
import type { ActiveReconAdapter } from './ActiveReconAdapter.js';
import type { ActiveReconProbeRequest } from './ActiveReconContracts.js';
import type {
  ActiveReconDocumentProbeKind,
  ActiveReconDocumentProbeRunRequest,
  ActiveReconDocumentProbeRunResult,
  ActiveReconDocumentProbeRunProbeResult,
} from './ActiveReconDocumentProbeRunContracts.js';

/** Fixed adapter table — injected, not instantiated by runner */
export type ActiveReconDocumentProbeAdapters = {
  robots?: ActiveReconAdapter;
  securityTxt?: ActiveReconAdapter;
};

const SUPPORTED_PROBE_KINDS: ReadonlySet<ActiveReconDocumentProbeKind> = new Set([
  'http.robots.inspect',
  'http.security_txt.inspect',
]);

/** Generate a safe, runner-controlled run ID. Never echoes caller input. */
function makeRunId(): string {
  return `run_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

/**
 * Resolve the injected adapter for a given probe kind.
 * Returns undefined if no adapter is registered for that kind.
 */
function resolveAdapter(
  kind: ActiveReconDocumentProbeKind,
  adapters: ActiveReconDocumentProbeAdapters
): ActiveReconAdapter | undefined {
  if (kind === 'http.robots.inspect') return adapters.robots;
  if (kind === 'http.security_txt.inspect') return adapters.securityTxt;
  return undefined;
}

/**
 * Extract a safe-for-output target representation from a policy decision.
 * Never includes the raw targetUrl with query/fragment/tokens.
 */
function safeTargetFromDecision(decision: ReturnType<typeof evaluateEgressPolicy>): {
  normalizedOrigin?: string;
  safeDisplayUrl?: string;
} {
  if (decision.decision === 'allow') {
    const nt = decision.normalizedTarget;
    const scheme = nt.scheme.replace(':', '') as 'http' | 'https';
    const isDefault =
      (scheme === 'http' && nt.port === '80') ||
      (scheme === 'https' && nt.port === '443');
    const normalizedOrigin = `${scheme}://${nt.hostname}${isDefault ? '' : ':' + nt.port}`;
    return { normalizedOrigin, safeDisplayUrl: decision.safeDisplayUrl };
  }
  if ('safeDisplayUrl' in decision && decision.safeDisplayUrl) {
    return { safeDisplayUrl: decision.safeDisplayUrl };
  }
  return {};
}

/**
 * Runtime authorization guard. Enforced before any policy evaluation or adapter
 * invocation. TypeScript types alone are insufficient — this must be a runtime check.
 *
 * Only `request.authorization?.confirmed === true` (strict equality) may proceed.
 */
function isAuthorizationConfirmed(request: ActiveReconDocumentProbeRunRequest): boolean {
  if ('authorization' in request) return false;
  const decision = request.verifiedAuthorizationDecision;
  if (!decision) return false;
  if (!isRuntimeEstablishedVerifiedAuthorizationDecision(decision)) return false;
  const validationResult = validateVerifiedAuthorizationDecision(decision, request.evaluatedAt);
  if (validationResult.status === 'invalid') return false;
  return true;
}

/**
 * M38 — Active Recon Document Probe Runner
 *
 * Orchestrates explicit per-URL document probes (robots.txt, security.txt)
 * using injected adapters, M30 egress policy, and safe result shapes.
 *
 * The runner:
 * - Does NOT instantiate real adapters.
 * - Does NOT read process.env.
 * - Does NOT import node:http / node:https / node:dns.
 * - Does NOT create findings or evidence.
 * - Does NOT persist anything.
 * - Does NOT derive targets from origins.
 * - Does NOT add new probe kinds.
 * - Does NOT echo raw caller-supplied runId, probeId, or unsupported kind values.
 */
export async function runActiveReconDocumentProbes(
  request: ActiveReconDocumentProbeRunRequest,
  adapters: ActiveReconDocumentProbeAdapters
): Promise<ActiveReconDocumentProbeRunResult> {
  const probes = request.probes ?? [];

  // FINDING 1 FIX — Runtime authorization guard.
  // Must be checked BEFORE runId generation, egress policy evaluation, adapter
  // resolution, and any adapter invocation.
  if (!isAuthorizationConfirmed(request)) {
    const failedResults: ActiveReconDocumentProbeRunProbeResult[] = probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`,
      safeKind: 'unknown' as const,
      status: 'failed' as const,
      policyDecision: 'none' as const,
      target: {},
      observations: [],
      error: {
        code: 'authorization_not_confirmed' as const,
        message: 'Run authorization was not confirmed. No probes were executed.',
      },
    }));

    return {
      runId: makeRunId(),
      disposition: 'authorization_denied',
      requestedProbeCount: probes.length,
      completedProbeCount: 0,
      blockedProbeCount: 0,
      failedProbeCount: probes.length,
      candidateProbeCount: 0,
      probes: failedResults,
      observations: [],
      classification: {
        finding: false,
        evidence: false,
        vulnerability: false,
        riskClaim: false,
      },
    };
  }

  // FINDING 2 FIX — Runner-generated run ID. Caller-supplied runId is NEVER echoed.
  const runId = makeRunId();
  const scopeGrant = request.verifiedAuthorizationDecision!.scopeGrant;
  const authorizedScope = {
    allowedOrigins: scopeGrant.boundaries.allowedOrigins || [],
    allowSameHostPaths: true,
    allowSubdomains: scopeGrant.subject.targetKind === 'domain',
  };

  const probeResults: ActiveReconDocumentProbeRunProbeResult[] = [];

  for (let i = 0; i < probes.length; i++) {
    const probe = probes[i];
    const { kind, targetUrl } = probe;

    // FINDING 2 FIX — safe probe index only (probe-1, probe-2, …)
    // Caller-supplied probeId is NEVER echoed in output.
    const safeProbeIndex = `probe-${i + 1}`;

    // FINDING 3 FIX — Unsupported probe kind guard.
    // We must not echo the raw unsupported kind value.
    if (!SUPPORTED_PROBE_KINDS.has(kind)) {
      probeResults.push({
        safeProbeIndex,
        safeKind: 'unknown',   // never the raw unsupported kind
        status: 'failed',
        policyDecision: 'none',
        target: {},
        observations: [],
        error: {
          code: 'unsupported_probe',
          message: 'Unsupported document probe kind.',  // fixed message — no raw kind echoed
        },
      });
      continue;
    }

    // 2. Evaluate M30 egress policy — before any adapter invocation
    let decision: ReturnType<typeof evaluateEgressPolicy>;
    try {
      decision = evaluateEgressPolicy({ targetUrl, capabilityId: kind, authorizedScope });
    } catch {
      probeResults.push({
        safeProbeIndex,
        safeKind: kind,
        status: 'failed',
        policyDecision: 'none',
        target: {},
        observations: [],
        error: {
          code: 'invalid_target',
          message: 'Target URL could not be evaluated by the egress policy.',
        },
      });
      continue;
    }

    const safeTarget = safeTargetFromDecision(decision);

    // 3. Block — do not invoke adapter
    if (decision.decision === 'block') {
      probeResults.push({
        safeProbeIndex,
        safeKind: kind,
        status: 'blocked',
        policyDecision: 'block',
        target: safeTarget,
        observations: [],
        error: {
          code: 'policy_blocked',
          message: 'Target was blocked by egress policy before adapter invocation.',
        },
      });
      continue;
    }

    // 4. Candidate — do not invoke adapter
    if (decision.decision === 'candidate') {
      probeResults.push({
        safeProbeIndex,
        safeKind: kind,
        status: 'candidate',
        policyDecision: 'candidate',
        target: safeTarget,
        observations: [],
        error: {
          code: 'policy_candidate',
          message: 'Target is a scope candidate; explicit authorization required before probing.',
        },
      });
      continue;
    }

    // 5. Allow — resolve adapter, then invoke
    const adapter = resolveAdapter(kind, adapters);

    if (!adapter) {
      probeResults.push({
        safeProbeIndex,
        safeKind: kind,
        status: 'failed',
        policyDecision: 'allow',
        target: safeTarget,
        observations: [],
        error: {
          code: 'adapter_missing',
          message: 'No adapter is registered for the requested document probe kind.',
        },
      });
      continue;
    }

    // 6. Invoke adapter with request-bound probe request
    let observations;
    try {
      const probeRequest: ActiveReconProbeRequest = {
        capabilityId: kind,
        targetUrl,
        authorizedScope,
        requestedAtMs: Date.now(),
      };
      observations = await adapter.probe(probeRequest);
    } catch {
      // Do not include raw exception message — it may contain unsafe URL/body data
      probeResults.push({
        safeProbeIndex,
        safeKind: kind,
        status: 'failed',
        policyDecision: 'allow',
        target: safeTarget,
        observations: [],
        error: {
          code: 'adapter_failed',
          message: 'Adapter execution failed. No raw output is retained.',
        },
      });
      continue;
    }

    probeResults.push({
      safeProbeIndex,
      safeKind: kind,
      status: 'completed',
      policyDecision: 'allow',
      target: safeTarget,
      observations,
    });
  }

  // Aggregate counts
  let completedProbeCount = 0;
  let blockedProbeCount = 0;
  let failedProbeCount = 0;
  let candidateProbeCount = 0;
  const allObservations = [];

  for (const r of probeResults) {
    if (r.status === 'completed') {
      completedProbeCount++;
      allObservations.push(...r.observations);
    } else if (r.status === 'blocked') {
      blockedProbeCount++;
    } else if (r.status === 'failed') {
      failedProbeCount++;
    } else if (r.status === 'candidate') {
      candidateProbeCount++;
    }
  }

  return {
    runId,
    disposition: 'execution_completed',
    requestedProbeCount: probes.length,
    completedProbeCount,
    blockedProbeCount,
    failedProbeCount,
    candidateProbeCount,
    probes: probeResults,
    observations: allObservations,
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false,
    },
  };
}
