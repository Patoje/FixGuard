import { evaluateEgressPolicy, isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import { normalizeTargetUrl } from '../policy/TargetUrlNormalizer.js';
import { runActiveReconDocumentProbes, type ActiveReconDocumentProbeAdapters } from './ActiveReconDocumentProbeRunner.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision, validateVerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionService.js';
import type { ActiveReconDocumentProbeEntry } from './ActiveReconDocumentProbeRunContracts.js';
import {
  type ActiveReconOriginRunRequest,
  type ActiveReconOriginRunResult,
  type ActiveReconOriginProbeSelection,
  type ActiveReconOriginRunProbeResult,
  deriveActiveReconRunStatus
} from './ActiveReconOriginRunContracts.js';

const DOCUMENT_PROBE_DEFINITIONS = {
  'http.robots.inspect': {
    family: 'document',
    path: '/robots.txt',
  },
  'http.security_txt.inspect': {
    family: 'document',
    path: '/.well-known/security.txt',
  },
} as const;

function makeRunId(): string {
  return `origin_run_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

export async function runActiveReconOriginProbes(
  request: ActiveReconOriginRunRequest,
  adapters: ActiveReconDocumentProbeAdapters
): Promise<ActiveReconOriginRunResult> {
  const probes = request.probes ?? [];
  const requestedProbeCount = probes.length;

  const baseResult: ActiveReconOriginRunResult = {
    contractVersion: 'active-recon-origin-run-result/v0',
    runId: makeRunId(),
    status: 'failed',
    disposition: 'execution_failed',
    requestedProbeCount,
    plannedProbeCount: 0,
    completedProbeCount: 0,
    blockedProbeCount: 0,
    candidateProbeCount: 0,
    failedProbeCount: 0,
    runErrors: [],
    probes: [],
    observations: [],
    classification: {
      finding: false,
      evidence: false,
      vulnerability: false,
      riskClaim: false,
    },
  };

  // 1. Validate authorization (M56A)
  const authError = (function(req: any) {
    const d = req.verifiedAuthorizationDecision;
    if (
      !d ||
      typeof d !== 'object' ||
      !('contractVersion' in d) ||
      d.contractVersion !== 'fixguard-verified-authorization-decision/v0' ||
      d.decision !== 'authorized' ||
      !('verification' in d) ||
      !isRuntimeEstablishedVerifiedAuthorizationDecision(d)
    ) {
      return 'invalid';
    }
    return null;
  })(request);

  if (authError !== null) {
    return {
      ...baseResult,
      disposition: 'authorization_denied',
      failedProbeCount: requestedProbeCount,
      runErrors: [{ code: 'authorization_not_confirmed', message: 'Run authorization was not confirmed.' }],
      probes: probes.map((_, i) => ({
        safeProbeIndex: `probe-${i + 1}`,
        family: 'document',
        safeKind: 'unknown',
        status: 'failed',
        target: {},
        observations: [],
        error: { code: 'authorization_not_confirmed', message: 'Run authorization was not confirmed.' },
      })),
    };
  }

  // 2. Validate Origin Shape
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(request.origin);
  } catch {
    return {
      ...baseResult,
      disposition: 'preflight_denied',
      failedProbeCount: requestedProbeCount,
      runErrors: [{ code: 'invalid_origin', message: 'Origin is not a valid URL.' }],
      probes: probes.map((_, i) => ({
        safeProbeIndex: `probe-${i + 1}`,
        family: 'document',
        safeKind: 'unknown',
        status: 'failed',
        target: {},
        observations: [],
        error: { code: 'invalid_origin', message: 'Origin is not a valid URL.' },
      })),
    };
  }

  if (parsedOrigin.protocol !== 'http:' && parsedOrigin.protocol !== 'https:') {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin protocol must be http or https.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin protocol must be http or https.' },
    }))};
  }

  if (parsedOrigin.origin !== request.origin) {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must be strictly canonical.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must be strictly canonical.' },
    }))};
  }

  if (parsedOrigin.pathname !== '' && parsedOrigin.pathname !== '/') {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain a path.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain a path.' },
    }))};
  }

  if (parsedOrigin.search || parsedOrigin.hash) {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain query or fragment.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain query or fragment.' },
    }))};
  }

  if (parsedOrigin.username || parsedOrigin.password) {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain credentials.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain credentials.' },
    }))};
  }

  if (isInternalOrSsrfTarget(parsedOrigin.hostname)) {
    return { ...baseResult, disposition: 'preflight_denied', failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin resolves to an unsafe internal IP.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin resolves to an unsafe internal IP.' },
    }))};
  }

  const normalizedOrigin = `${parsedOrigin.protocol}//${parsedOrigin.host}`;
  baseResult.normalizedOrigin = normalizedOrigin;

  // 3. Deduplicate probes & reject empty/unsupported
  if (probes.length === 0) {
    return {
      ...baseResult,
      status: 'failed',
      runErrors: [{ code: 'empty_probe_set', message: 'At least one supported origin probe must be requested.' }],
      probes: [],
    };
  }

  // 3. M39/M56A atomic batch preflight: normalize and validate every probe selection before any execution.
  //    If any selection is invalid, blocked, or missing an adapter, abort entire batch without side effects.
  type SupportedDocumentProbeKind = 'http.robots.inspect' | 'http.security_txt.inspect';
  const SUPPORTED_DOCUMENT_PROBES = new Set<SupportedDocumentProbeKind>(['http.robots.inspect', 'http.security_txt.inspect']);

  type NormalizedOriginProbeSelection =
    | Readonly<{
        status: 'valid_document_probe';
        originalIndex: number;
        safeProbeIndex: string;
        probe: SupportedDocumentProbeKind;
      }>
    | Readonly<{
        status: 'invalid_selection';
        originalIndex: number;
        safeProbeIndex: string;
        safeFamily: string;
        safeProbe: string;
        probeStatus: 'failed' | 'blocked' | 'candidate';
        reasonCode: any;
        message: string;
      }>;

  const scopeGrant = request.verifiedAuthorizationDecision?.scopeGrant as Record<string, any> | undefined;

  const normalizedSelections: NormalizedOriginProbeSelection[] = probes.map((probeReq, i): NormalizedOriginProbeSelection => {
    const safeProbeIndex = `probe-${i + 1}`;
    const raw = probeReq as Record<string, unknown>;
    const rawFamily = typeof raw?.family === 'string' ? raw.family : 'unknown';
    const rawProbe = typeof raw?.probe === 'string' ? raw.probe : 'unknown';

    // 1. Family check
    if (!probeReq || rawFamily !== 'document') {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: rawFamily.slice(0, 64),
        safeProbe: rawProbe.slice(0, 64),
        probeStatus: 'failed',
        reasonCode: 'unsupported_probe',
        message: 'Unsupported origin probe selection.',
      };
    }

    // 2. Supported probe check
    if (!SUPPORTED_DOCUMENT_PROBES.has(rawProbe as SupportedDocumentProbeKind)) {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: 'document',
        safeProbe: rawProbe.slice(0, 64),
        probeStatus: 'failed',
        reasonCode: 'unsupported_probe',
        message: 'Unsupported origin probe selection.',
      };
    }

    const probeKind = rawProbe as SupportedDocumentProbeKind;
    const def = DOCUMENT_PROBE_DEFINITIONS[probeKind];
    const targetUrl = `${normalizedOrigin}${def.path}`;

    // 3. Scope grant checks
    if (scopeGrant) {
      // 3a. Permission check (endpointDiscovery)
      if (scopeGrant.permissionSet?.endpointDiscovery === false) {
        return {
          status: 'invalid_selection',
          originalIndex: i,
          safeProbeIndex,
          safeFamily: 'document',
          safeProbe: probeKind,
          probeStatus: 'blocked',
          reasonCode: 'policy_blocked',
          message: 'Endpoint discovery permission is not granted.',
        };
      }

      // 3b. Origin / host matching
      let originMatched = false;
      const boundaries = scopeGrant.boundaries;
      if (boundaries?.allowedOrigins && Array.isArray(boundaries.allowedOrigins) && boundaries.allowedOrigins.length > 0) {
        if (boundaries.allowedOrigins.includes(normalizedOrigin)) {
          originMatched = true;
        }
      } else if (scopeGrant.subject?.targetKind === 'origin' && scopeGrant.subject.normalizedOrigin === normalizedOrigin) {
        originMatched = true;
      } else if (scopeGrant.subject?.targetKind === 'host' && scopeGrant.subject.host === parsedOrigin.host) {
        originMatched = true;
      } else if (scopeGrant.subject?.targetKind === 'domain' && scopeGrant.subject.domain === parsedOrigin.hostname) {
        originMatched = true;
      }

      if (!originMatched) {
        return {
          status: 'invalid_selection',
          originalIndex: i,
          safeProbeIndex,
          safeFamily: 'document',
          safeProbe: probeKind,
          probeStatus: 'blocked',
          reasonCode: 'policy_blocked',
          message: 'Target origin is not within authorized scope.',
        };
      }

      // 3c. Denied path patterns
      if (boundaries?.deniedPathPatterns && Array.isArray(boundaries.deniedPathPatterns)) {
        for (const pattern of boundaries.deniedPathPatterns) {
          const p = pattern.pathTemplate;
          const isExact = pattern.match === 'exact';
          const matched = isExact
            ? def.path === p
            : (def.path === p || def.path.startsWith(p.endsWith('/') ? p : `${p}/`));
          if (matched) {
            return {
              status: 'invalid_selection',
              originalIndex: i,
              safeProbeIndex,
              safeFamily: 'document',
              safeProbe: probeKind,
              probeStatus: 'blocked',
              reasonCode: 'policy_blocked',
              message: 'Target path is explicitly denied by scope.',
            };
          }
        }
      }

      // 3d. Allowed path patterns (if specified, must match)
      if (boundaries?.allowedPathPatterns && Array.isArray(boundaries.allowedPathPatterns) && boundaries.allowedPathPatterns.length > 0) {
        let pathAllowed = false;
        for (const pattern of boundaries.allowedPathPatterns) {
          const p = pattern.pathTemplate;
          const isExact = pattern.match === 'exact';
          const matched = isExact
            ? def.path === p
            : (def.path === p || def.path.startsWith(p.endsWith('/') ? p : `${p}/`));
          if (matched) {
            pathAllowed = true;
            break;
          }
        }
        if (!pathAllowed) {
          return {
            status: 'invalid_selection',
            originalIndex: i,
            safeProbeIndex,
            safeFamily: 'document',
            safeProbe: probeKind,
            probeStatus: 'blocked',
            reasonCode: 'policy_blocked',
            message: 'Target path is not within allowed path patterns.',
          };
        }
      }

      // 3e. Denied methods
      if (boundaries?.deniedMethods && Array.isArray(boundaries.deniedMethods) && boundaries.deniedMethods.includes('GET')) {
        return {
          status: 'invalid_selection',
          originalIndex: i,
          safeProbeIndex,
          safeFamily: 'document',
          safeProbe: probeKind,
          probeStatus: 'blocked',
          reasonCode: 'policy_blocked',
          message: 'Method GET is explicitly denied by scope.',
        };
      }

      // 3f. Allowed methods
      if (boundaries?.allowedMethods && Array.isArray(boundaries.allowedMethods) && boundaries.allowedMethods.length > 0) {
        if (!boundaries.allowedMethods.includes('GET')) {
          return {
            status: 'invalid_selection',
            originalIndex: i,
            safeProbeIndex,
            safeFamily: 'document',
            safeProbe: probeKind,
            probeStatus: 'blocked',
            reasonCode: 'policy_blocked',
            message: 'Method GET is not within allowed methods.',
          };
        }
      }
    }

    // 4. Egress policy check
    const authorizedScope = {
      allowedOrigins: scopeGrant?.boundaries?.allowedOrigins || [],
      allowSameHostPaths: true,
      allowSubdomains: scopeGrant?.subject?.targetKind === 'domain',
    };
    let egressDecision: ReturnType<typeof evaluateEgressPolicy>;
    try {
      egressDecision = evaluateEgressPolicy({
        targetUrl,
        capabilityId: probeKind,
        authorizedScope,
      });
    } catch {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: 'document',
        safeProbe: probeKind,
        probeStatus: 'failed',
        reasonCode: 'policy_blocked',
        message: 'Target URL could not be evaluated by the egress policy.',
      };
    }

    if (egressDecision.decision === 'block') {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: 'document',
        safeProbe: probeKind,
        probeStatus: 'blocked',
        reasonCode: 'policy_blocked',
        message: 'Target was blocked by egress policy before adapter invocation.',
      };
    }
    if (egressDecision.decision === 'candidate') {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: 'document',
        safeProbe: probeKind,
        probeStatus: 'candidate',
        reasonCode: 'policy_candidate',
        message: 'Target is a scope candidate; explicit authorization required before probing.',
      };
    }

    // 5. Adapter availability check
    const adapter = probeKind === 'http.robots.inspect' ? adapters?.robots : adapters?.securityTxt;
    if (!adapter) {
      return {
        status: 'invalid_selection',
        originalIndex: i,
        safeProbeIndex,
        safeFamily: 'document',
        safeProbe: probeKind,
        probeStatus: 'failed',
        reasonCode: 'adapter_missing',
        message: 'No adapter is registered for the requested document probe kind.',
      };
    }

    return {
      status: 'valid_document_probe',
      originalIndex: i,
      safeProbeIndex,
      probe: probeKind,
    };
  });

  const invalidSelections = normalizedSelections.filter(s => s.status === 'invalid_selection');
  const validSelections = normalizedSelections.filter(s => s.status === 'valid_document_probe');

  // If any selection is invalid, abort the entire batch atomically
  if (invalidSelections.length > 0) {
    const batchResult: ActiveReconOriginRunProbeResult[] = normalizedSelections.map(s => {
      if (s.status === 'invalid_selection') {
        const safeKind = s.safeProbe in DOCUMENT_PROBE_DEFINITIONS ? (s.safeProbe as SupportedDocumentProbeKind) : 'unknown';
        return {
          safeProbeIndex: s.safeProbeIndex,
          family: 'document',
          safeKind,
          status: s.probeStatus,
          target: { normalizedOrigin },
          observations: [],
          error: { code: s.reasonCode, message: s.message },
        };
      } else {
        return {
          safeProbeIndex: s.safeProbeIndex,
          family: 'document',
          safeKind: s.probe,
          status: 'failed',
          target: { normalizedOrigin },
          observations: [],
          error: { code: 'batch_preflight_aborted', message: 'Batch aborted due to invalid probe selection in batch.' },
        };
      }
    });
    return {
      ...baseResult,
      disposition: 'preflight_denied',
      status: 'failed',
      failedProbeCount: batchResult.filter(p => p.status === 'failed').length,
      blockedProbeCount: batchResult.filter(p => p.status === 'blocked').length,
      candidateProbeCount: batchResult.filter(p => p.status === 'candidate').length,
      completedProbeCount: 0,
      probes: batchResult,
      runErrors: [{ code: invalidSelections[0].reasonCode, message: invalidSelections[0].message }],
    };
  }

  const plannedTargets: { safeProbeIndex: string; kind: SupportedDocumentProbeKind; targetUrl: string }[] = [];
  const originProbesResult: ActiveReconOriginRunProbeResult[] = [];
  const seenKinds = new Set<string>();

  for (const sel of validSelections) {
    if (sel.status !== 'valid_document_probe') continue; // type narrowing
    const { safeProbeIndex, probe } = sel;

    if (seenKinds.has(probe)) {
      continue;
    }
    seenKinds.add(probe);

    const def = DOCUMENT_PROBE_DEFINITIONS[probe];
    const targetUrl = `${normalizedOrigin}${def.path}`;

    plannedTargets.push({
      safeProbeIndex,
      kind: probe,
      targetUrl,
    });
  }

  baseResult.plannedProbeCount = plannedTargets.length;
  baseResult.failedProbeCount = originProbesResult.length; // Unsupported ones

  // 4. Build M38 Runner Request & Execute
  if (plannedTargets.length > 0) {
    const m38Probes: ActiveReconDocumentProbeEntry[] = plannedTargets.map(pt => ({
      probeId: pt.safeProbeIndex, // Passing our safe index as the runner's probeId
      kind: pt.kind,
      targetUrl: pt.targetUrl,
    }));

    const runnerRequest: import('./ActiveReconDocumentProbeRunContracts.js').ActiveReconDocumentProbeRunRequest = {
      contractVersion: 'active-recon-document-probe-run/v1',
      evaluatedAt: request.evaluatedAt,
      verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
      probes: m38Probes,
    };

    let runnerResult;
    try {
      runnerResult = await runActiveReconDocumentProbes(runnerRequest, adapters);
    } catch {
      // Runner threw an exception completely
      for (const pt of plannedTargets) {
        originProbesResult.push({
          safeProbeIndex: pt.safeProbeIndex,
          family: 'document',
          safeKind: pt.kind,
          status: 'failed',
          target: { normalizedOrigin },
          observations: [],
          error: { code: 'runner_failed', message: 'Document probe runner execution failed.' },
        });
        baseResult.failedProbeCount++;
      }
      baseResult.status = 'failed';
      baseResult.probes = originProbesResult;
      return baseResult;
    }

    // 5. Map M38 Results to M39 Results
    baseResult.disposition = runnerResult.disposition;
    for (const rProbe of runnerResult.probes) {
      // The M38 runner now returns `safeProbeIndex` instead of `probeId`.
      // We mapped our `pt.safeProbeIndex` into `probeId` in the request,
      // but M38 runner ignores it and generates its own `probe-1`, `probe-2` based on index.
      // So we map by index:
      const m38Index = runnerResult.probes.indexOf(rProbe);
      const plannedTarget = plannedTargets[m38Index];
      if (!plannedTarget) continue;

      const safeKind = rProbe.safeKind === 'unknown' ? 'unknown' : rProbe.safeKind;

      originProbesResult.push({
        safeProbeIndex: plannedTarget.safeProbeIndex,
        family: 'document',
        safeKind,
        status: rProbe.status,
        target: rProbe.target,
        observations: rProbe.observations,
        error: rProbe.error ? { code: rProbe.error.code as any, message: rProbe.error.message } : undefined,
      });

      if (rProbe.status === 'completed') baseResult.completedProbeCount++;
      else if (rProbe.status === 'blocked') baseResult.blockedProbeCount++;
      else if (rProbe.status === 'candidate') baseResult.candidateProbeCount++;
      else if (rProbe.status === 'failed') baseResult.failedProbeCount++;

      baseResult.observations.push(...rProbe.observations);
    }
  }

  // Finalize counts & status
  baseResult.probes = originProbesResult.sort((a, b) => a.safeProbeIndex.localeCompare(b.safeProbeIndex));
  baseResult.plannedProbeCount = plannedTargets.length;
  baseResult.requestedProbeCount = request.probes.length;

  baseResult.status = deriveActiveReconRunStatus(
    baseResult.plannedProbeCount,
    baseResult.completedProbeCount
  );

  return baseResult;
}
