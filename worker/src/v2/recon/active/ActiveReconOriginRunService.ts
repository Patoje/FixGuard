import { evaluateEgressPolicy, isInternalOrSsrfTarget } from '../policy/PassiveEgressPolicy.js';
import { normalizeTargetUrl } from '../policy/TargetUrlNormalizer.js';
import { runActiveReconDocumentProbes, type ActiveReconDocumentProbeAdapters } from './ActiveReconDocumentProbeRunner.js';
import type { ActiveReconDocumentProbeEntry, ActiveReconDocumentProbeRunRequest } from './ActiveReconDocumentProbeRunContracts.js';
import type {
  ActiveReconOriginRunRequest,
  ActiveReconOriginRunResult,
  ActiveReconOriginRunProbeResult,
  ActiveReconOriginProbeSelection,
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

function isAuthorizationConfirmed(request: ActiveReconOriginRunRequest): boolean {
  return (request as any).authorization?.confirmed === true;
}

export async function runActiveReconOriginProbes(
  request: ActiveReconOriginRunRequest,
  adapters: ActiveReconDocumentProbeAdapters
): Promise<ActiveReconOriginRunResult> {
  const probes = request.probes ?? [];
  const requestedProbeCount = probes.length;

  const baseResult: ActiveReconOriginRunResult = {
    contractVersion: 'active-recon-origin-run/v0',
    runId: makeRunId(),
    status: 'failed',
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

  // 1. Validate authorization
  if (!isAuthorizationConfirmed(request)) {
    return {
      ...baseResult,
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
    return { ...baseResult, failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin protocol must be http or https.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin protocol must be http or https.' },
    }))};
  }

  if (parsedOrigin.pathname !== '' && parsedOrigin.pathname !== '/') {
    return { ...baseResult, failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain a path.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain a path.' },
    }))};
  }

  if (parsedOrigin.search || parsedOrigin.hash) {
    return { ...baseResult, failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain query or fragment.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain query or fragment.' },
    }))};
  }

  if (parsedOrigin.username || parsedOrigin.password) {
    return { ...baseResult, failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin must not contain credentials.' }], probes: probes.map((_, i) => ({
      safeProbeIndex: `probe-${i + 1}`, family: 'document', safeKind: 'unknown', status: 'failed', target: {}, observations: [],
      error: { code: 'invalid_origin', message: 'Origin must not contain credentials.' },
    }))};
  }

  if (isInternalOrSsrfTarget(parsedOrigin.hostname)) {
    return { ...baseResult, failedProbeCount: requestedProbeCount, runErrors: [{ code: 'invalid_origin', message: 'Origin resolves to an unsafe internal IP.' }], probes: probes.map((_, i) => ({
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

  const plannedTargets: { safeProbeIndex: string; kind: 'http.robots.inspect' | 'http.security_txt.inspect'; targetUrl: string }[] = [];
  const originProbesResult: ActiveReconOriginRunProbeResult[] = [];
  const seenKinds = new Set<string>();

  for (let i = 0; i < probes.length; i++) {
    const probeReq = probes[i];
    const safeProbeIndex = `probe-${i + 1}`;

    if (!probeReq || probeReq.family !== 'document' || !(probeReq.probe in DOCUMENT_PROBE_DEFINITIONS)) {
      originProbesResult.push({
        safeProbeIndex,
        family: 'document',
        safeKind: 'unknown',
        status: 'failed',
        target: { normalizedOrigin },
        observations: [],
        error: { code: 'unsupported_probe', message: 'Unsupported origin probe selection.' },
      });
      continue;
    }

    if (seenKinds.has(probeReq.probe)) {
      // deduplicate safely
      continue;
    }
    seenKinds.add(probeReq.probe);

    const def = DOCUMENT_PROBE_DEFINITIONS[probeReq.probe as keyof typeof DOCUMENT_PROBE_DEFINITIONS];
    const targetUrl = `${normalizedOrigin}${def.path}`;

    plannedTargets.push({
      safeProbeIndex,
      kind: probeReq.probe as 'http.robots.inspect' | 'http.security_txt.inspect',
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

    const runnerRequest: ActiveReconDocumentProbeRunRequest = {
      authorizedScope: request.authorizedScope,
      authorization: request.authorization,
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

  if (baseResult.completedProbeCount === baseResult.plannedProbeCount && baseResult.plannedProbeCount > 0) {
    baseResult.status = 'completed';
  } else if (baseResult.completedProbeCount > 0) {
    baseResult.status = 'partial';
  } else {
    baseResult.status = 'failed';
  }

  return baseResult;
}
