/**
 * Milestone M1 — Auth Boundary Differential Detection
 *
 * GET-only A / anon (/ optional B) comparable probes on an OBSERVED account/order path.
 * Distinguishes auth boundary (A 200 / anon 302-login) from BOLA/IDOR (object cross-user).
 *
 * Soft-404, WAF, expired session → interfered/inconclusive — never false secure/refuted.
 * Does not invent object IDs. Does not auto-promote High findings (HITL remains separate).
 */

import { createHash } from 'node:crypto';
import { DETECTION_CONTRACT_VERSION } from './DetectionContracts.js';
import type {
  HttpProbeRequest,
  HttpProbeResponse,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from './DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import { validateSessionHealth } from '../core/SessionLifecycleService.js';
import {
  evaluateTestValidity,
} from '../test-validity/TestValidityService.js';
import type {
  AuthBoundaryDifferentialDetectionRequest,
  AuthBoundaryDifferentialDetectionResult,
  AuthBoundaryInvestigationOutcome,
  AuthBoundaryProbeFacet,
} from './AuthBoundaryDifferentialContracts.js';
import { isHtmlShellBodySignal } from './DetectionTargetBridge.js';

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function analyzeBodyShape(
  bodyText: string,
  contentType: string | undefined
): AuthBoundaryProbeFacet['bodyShapeKind'] {
  const trimmed = bodyText.trim();
  const ct = (contentType ?? '').toLowerCase();
  if (trimmed.length === 0) return 'empty';
  if (ct.includes('text/html') || /<html|<!doctype html/i.test(trimmed)) {
    return 'html';
  }
  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return 'json_array';
      if (parsed !== null && typeof parsed === 'object') return 'json_object';
    } catch {
      // fall through
    }
  }
  return 'text';
}

function buildHeaders(identity: ProbeAuthContext): Record<string, string> {
  const headers: Record<string, string> = { ...(identity.headers ?? {}) };
  if (identity.cookies && Object.keys(identity.cookies).length > 0) {
    headers['cookie'] = Object.entries(identity.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  return headers;
}

function safeRedirectHostPath(headers: Readonly<Record<string, string>>): string | undefined {
  const loc = headers['location'];
  if (typeof loc !== 'string' || loc.trim().length === 0) return undefined;
  try {
    if (loc.startsWith('http://') || loc.startsWith('https://')) {
      const u = new URL(loc);
      return `${u.host}${u.pathname}`.slice(0, 160);
    }
    return loc.split('?')[0]?.slice(0, 160);
  } catch {
    return loc.split('?')[0]?.slice(0, 160);
  }
}

function toFacet(
  role: AuthBoundaryProbeFacet['identityRole'],
  identityId: string,
  response: HttpProbeResponse
): AuthBoundaryProbeFacet {
  const contentType = response.headers['content-type'];
  return {
    identityRole: role,
    identityId,
    statusCode: response.statusCode,
    ...(safeRedirectHostPath(response.headers)
      ? { redirectLocationHostPath: safeRedirectHostPath(response.headers) }
      : {}),
    ...(contentType ? { contentType: contentType.slice(0, 80) } : {}),
    bodyHash: sha256(response.bodyText),
    bodyLength: response.bodyText.length,
    bodyShapeKind: analyzeBodyShape(response.bodyText, contentType),
  };
}

function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (a.length === 0 || b.length === 0) return 0;
  if (sha256(a) === sha256(b)) return 1;
  try {
    const aObj = JSON.parse(a) as Record<string, unknown>;
    const bObj = JSON.parse(b) as Record<string, unknown>;
    if (
      typeof aObj === 'object' &&
      aObj !== null &&
      typeof bObj === 'object' &&
      bObj !== null &&
      !Array.isArray(aObj) &&
      !Array.isArray(bObj)
    ) {
      const aKeys = Object.keys(aObj);
      const bKeys = new Set(Object.keys(bObj));
      if (aKeys.length > 0) {
        let match = 0;
        for (const k of aKeys) {
          if (bKeys.has(k)) match++;
        }
        return match / aKeys.length;
      }
    }
  } catch {
    // text fallback
  }
  const lenDiff = Math.abs(a.length - b.length);
  const maxLen = Math.max(a.length, b.length);
  return maxLen > 0 ? Math.max(0, (maxLen - lenDiff) / maxLen) : 0;
}

function isLoginRedirect(statusCode: number, location: string | undefined): boolean {
  if (statusCode < 300 || statusCode >= 400) return false;
  const loc = (location ?? '').toLowerCase();
  return /login|signin|sign-in|auth|sso|oauth|account\/login/.test(loc);
}

function isAuthDenied(statusCode: number, location: string | undefined): boolean {
  if (statusCode === 401 || statusCode === 403) return true;
  return isLoginRedirect(statusCode, location);
}

function looksExpiredOrUnauthedBaseline(facet: AuthBoundaryProbeFacet): boolean {
  return isAuthDenied(facet.statusCode, facet.redirectLocationHostPath);
}

function looksWafOrChallenge(response: HttpProbeResponse, targetHost: string): boolean {
  const headerNames = Object.keys(response.headers).map((h) => h.toLowerCase());
  const headerValues: Record<string, string> = {};
  for (const [k, v] of Object.entries(response.headers)) {
    headerValues[k.toLowerCase()] = v.slice(0, 80);
  }
  const validity = evaluateTestValidity({
    probe: {
      statusCode: response.statusCode,
      headerNames,
      headerValues,
      bodyExcerpt: response.bodyText.slice(0, 400),
      responseTimeMs: response.responseTimeMs,
      targetHost,
    },
  });
  return validity.verdict === 'interfered';
}

function isSoft404OrHtmlNoise(
  endpointUrl: string,
  a: AuthBoundaryProbeFacet,
  anon: AuthBoundaryProbeFacet
): boolean {
  const aHtml = isHtmlShellBodySignal({
    contentType: a.contentType,
    bodyShapeKind: a.bodyShapeKind,
  });
  const anonHtml = isHtmlShellBodySignal({
    contentType: anon.contentType,
    bodyShapeKind: anon.bodyShapeKind,
  });
  if (aHtml && anonHtml) return true;
  if (aHtml && a.statusCode === 200) return true;
  // Both client errors with identical body → not a measurement of auth boundary
  if (
    a.statusCode === anon.statusCode &&
    a.statusCode >= 400 &&
    a.statusCode < 500 &&
    a.bodyHash === anon.bodyHash
  ) {
    return true;
  }
  void endpointUrl;
  return false;
}

function defaultTransport(): IdorHttpProbeTransport {
  return async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), req.timeoutMs ?? 5000);
    try {
      const res = await fetch(req.url, {
        method: req.method,
        headers: req.headers,
        redirect: 'manual',
        signal: controller.signal,
      });
      const bodyText = await res.text();
      const headers: Record<string, string> = {};
      res.headers.forEach((val, key) => {
        headers[key.toLowerCase()] = val;
      });
      return {
        statusCode: res.status,
        headers,
        bodyText,
        responseTimeMs: Date.now() - start,
      };
    } finally {
      clearTimeout(timeout);
    }
  };
}

function resultBase(
  request: AuthBoundaryDifferentialDetectionRequest,
  args: {
    readonly status: AuthBoundaryDifferentialDetectionResult['status'];
    readonly investigationOutcome: AuthBoundaryInvestigationOutcome;
    readonly reasonCode: string;
    readonly safeMessage: string;
    readonly facets?: readonly AuthBoundaryProbeFacet[];
    readonly bodySimilarityRatio?: number;
    readonly error?: { readonly code: string; readonly safeMessage: string };
  }
): AuthBoundaryDifferentialDetectionResult {
  return {
    contractVersion: DETECTION_CONTRACT_VERSION,
    kind: 'auth_boundary_differential_detection_result',
    detectionId: request.detectionId,
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
    status: args.status,
    investigationOutcome: args.investigationOutcome,
    reasonCode: args.reasonCode,
    safeMessage: args.safeMessage,
    lineage: {
      assessmentId: request.assessmentId,
      scanId: request.scanId,
      authorizationGrantId: request.authorizationGrantId,
      authorizationDecisionId: request.authorizationDecisionId,
      actorId: request.actorId,
    },
    endpointUrl: request.endpointUrl,
    ...(args.facets ? { facets: args.facets } : {}),
    ...(args.bodySimilarityRatio !== undefined
      ? { bodySimilarityRatio: args.bodySimilarityRatio }
      : {}),
    ...(args.error ? { error: args.error } : {}),
  };
}

export async function runAuthBoundaryDifferentialDetection(
  request: AuthBoundaryDifferentialDetectionRequest
): Promise<AuthBoundaryDifferentialDetectionResult> {
  const lineage = {
    scanId: request.scanId,
    assessmentId: request.assessmentId,
    authorizationGrantId: request.authorizationGrantId,
    authorizationDecisionId: request.authorizationDecisionId,
    actorId: request.actorId,
  };
  const nowIso = new Date().toISOString();

  const preflight = await runAdapterPreflight({
    target: request.endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: request.verifiedAuthorizationDecision,
    authorizedScopeGrant: request.scopeGrant,
    lineage,
    permissionCheck: (ps) =>
      Boolean(ps.endpointDiscovery || ps.lightValidation || ps.activeValidation),
    dnsResolver: request.dnsResolver,
  });

  if (!preflight.ok) {
    return resultBase(request, {
      status: 'preflight_denied',
      investigationOutcome: 'inconclusive',
      reasonCode: preflight.reasonCode,
      safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      error: {
        code: preflight.reasonCode,
        safeMessage: `Preflight denied: ${preflight.reasonCode}`,
      },
    });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(request.endpointUrl);
  } catch {
    return resultBase(request, {
      status: 'preflight_denied',
      investigationOutcome: 'inconclusive',
      reasonCode: 'malformed_target_url',
      safeMessage: 'Invalid endpoint URL format',
      error: { code: 'malformed_target_url', safeMessage: 'Invalid endpoint URL format' },
    });
  }

  const targetHost = parsedUrl.hostname;
  let identityAHeaders = buildHeaders(request.identityA);

  if (request.identityA.sessionState) {
    const sessionCheck = await validateSessionHealth(request.identityA.sessionState, nowIso);
    if (!sessionCheck.ok) {
      return resultBase(request, {
        status: 'measurement_inconclusive',
        investigationOutcome: 'inconclusive',
        reasonCode: sessionCheck.reasonCode ?? 'session_expired',
        safeMessage: 'Identity A session expired or unhealthy — cannot judge auth boundary',
        error: {
          code: sessionCheck.reasonCode ?? 'session_expired',
          safeMessage: 'Identity A session expired',
        },
      });
    }
    if (sessionCheck.updatedHeaders) {
      identityAHeaders = { ...identityAHeaders, ...sessionCheck.updatedHeaders };
    }
  }

  const transport = request.transport ?? defaultTransport();

  async function probe(
    headers: Readonly<Record<string, string>>
  ): Promise<HttpProbeResponse> {
    return transport({
      url: request.endpointUrl,
      method: 'GET',
      headers: { Accept: '*/*', ...headers },
      timeoutMs: 5000,
    });
  }

  let responseA: HttpProbeResponse;
  let responseAnon: HttpProbeResponse;
  try {
    responseA = await probe(identityAHeaders);
    responseAnon = await probe({});
  } catch (err: unknown) {
    return resultBase(request, {
      status: 'unexpected_failure',
      investigationOutcome: 'inconclusive',
      reasonCode: 'probe_dispatch_failed',
      safeMessage: err instanceof Error ? err.message : 'Auth boundary probe failed',
      error: {
        code: 'probe_dispatch_failed',
        safeMessage: err instanceof Error ? err.message : 'Auth boundary probe failed',
      },
    });
  }

  const facets: AuthBoundaryProbeFacet[] = [
    toFacet('authenticated_a', request.identityA.identityId, responseA),
    toFacet('anonymous', 'anonymous', responseAnon),
  ];

  let responseB: HttpProbeResponse | undefined;
  if (request.identityB) {
    try {
      responseB = await probe(buildHeaders(request.identityB));
      facets.push(toFacet('authenticated_b', request.identityB.identityId, responseB));
    } catch {
      // Optional B probe failure does not abort A vs anon classification
    }
  }

  const facetA = facets[0]!;
  const facetAnon = facets[1]!;

  if (looksWafOrChallenge(responseA, targetHost) || looksWafOrChallenge(responseAnon, targetHost)) {
    return resultBase(request, {
      status: 'measurement_interfered',
      investigationOutcome: 'interfered',
      reasonCode: 'waf_or_challenge_interfered',
      safeMessage:
        'WAF/challenge/rate-limit signals observed — auth boundary measurement interfered (not secure, not validated)',
      facets,
    });
  }

  if (looksExpiredOrUnauthedBaseline(facetA)) {
    return resultBase(request, {
      status: 'measurement_inconclusive',
      investigationOutcome: 'inconclusive',
      reasonCode: 'session_expired_or_unauthenticated_baseline',
      safeMessage:
        'Identity A did not receive an authenticated resource (401/403/login redirect) — expired session or wrong identity; inconclusive',
      facets,
    });
  }

  if (facetA.statusCode === 404 && facetAnon.statusCode === 404) {
    return resultBase(request, {
      status: 'measurement_inconclusive',
      investigationOutcome: 'inconclusive',
      reasonCode: 'both_404_inconclusive',
      safeMessage: 'Both authenticated and anonymous probes returned 404 — inconclusive',
      facets,
    });
  }

  if (isSoft404OrHtmlNoise(request.endpointUrl, facetA, facetAnon)) {
    return resultBase(request, {
      status: 'measurement_inconclusive',
      investigationOutcome: 'inconclusive',
      reasonCode: 'soft_404_or_html_shell_inconclusive',
      safeMessage:
        'HTML soft-404 / SPA shell responses — cannot honestly judge auth boundary (inconclusive)',
      facets,
    });
  }

  const similarity = bodySimilarity(responseA.bodyText, responseAnon.bodyText);
  const anonDenied = isAuthDenied(
    facetAnon.statusCode,
    facetAnon.redirectLocationHostPath
  );
  const aSuccess =
    facetA.statusCode >= 200 &&
    facetA.statusCode < 300 &&
    facetA.bodyLength > 0 &&
    facetA.bodyShapeKind !== 'html';
  const anonSuccess =
    facetAnon.statusCode >= 200 && facetAnon.statusCode < 300 && facetAnon.bodyLength > 0;

  // Secure: A gets resource, anon denied / login redirect
  if (aSuccess && anonDenied) {
    return resultBase(request, {
      status: 'boundary_secure',
      investigationOutcome: 'secure',
      reasonCode: 'auth_boundary_enforced_a200_anon_denied',
      safeMessage:
        'Auth boundary appears enforced: authenticated GET succeeded; anonymous probe denied or redirected to login',
      facets,
      bodySimilarityRatio: similarity,
    });
  }

  // Also treat anon 404 with distinct body while A has resource as secure-ish boundary
  if (aSuccess && facetAnon.statusCode === 404 && facetA.bodyHash !== facetAnon.bodyHash) {
    return resultBase(request, {
      status: 'boundary_secure',
      investigationOutcome: 'secure',
      reasonCode: 'auth_boundary_enforced_a200_anon_404',
      safeMessage:
        'Auth boundary appears enforced: authenticated GET succeeded; anonymous probe returned distinct 404',
      facets,
      bodySimilarityRatio: similarity,
    });
  }

  // Validated broken boundary: both succeed with high structural similarity, non-HTML
  if (
    aSuccess &&
    anonSuccess &&
    similarity >= 0.85 &&
    facetAnon.bodyShapeKind !== 'html'
  ) {
    return resultBase(request, {
      status: 'boundary_validated',
      investigationOutcome: 'validated',
      reasonCode: 'auth_boundary_broken_anon_parity',
      safeMessage:
        'Anonymous GET returned comparable authenticated resource content — auth boundary differential validated (not BOLA/object-ID swap)',
      facets,
      bodySimilarityRatio: similarity,
    });
  }

  // Suspicious: both success with moderate similarity, or anon success without clear deny
  if (aSuccess && anonSuccess) {
    return resultBase(request, {
      status: 'boundary_suspicious',
      investigationOutcome: 'suspicious',
      reasonCode: 'auth_boundary_anon_success_suspicious',
      safeMessage:
        'Anonymous GET returned success on account/order path without clear auth denial — suspicious; needs human review',
      facets,
      bodySimilarityRatio: similarity,
    });
  }

  // Optional A↔B same-path high similarity note (still not IDOR without object IDs)
  if (
    responseB &&
    facetA.statusCode >= 200 &&
    facetA.statusCode < 300 &&
    responseB.statusCode >= 200 &&
    responseB.statusCode < 300
  ) {
    const abSim = bodySimilarity(responseA.bodyText, responseB.bodyText);
    if (abSim >= 0.95 && facetA.bodyShapeKind !== 'html') {
      return resultBase(request, {
        status: 'boundary_suspicious',
        investigationOutcome: 'suspicious',
        reasonCode: 'auth_boundary_ab_identical_suspicious',
        safeMessage:
          'Identities A and B received near-identical account-path bodies — suspicious shared-boundary signal (not object-level IDOR without resource IDs)',
        facets,
        bodySimilarityRatio: abSim,
      });
    }
  }

  // A success but anon neither clearly denied nor clearly leaking
  if (aSuccess) {
    return resultBase(request, {
      status: 'measurement_inconclusive',
      investigationOutcome: 'inconclusive',
      reasonCode: 'auth_boundary_inconclusive_anon_status',
      safeMessage: `Authenticated probe succeeded; anonymous status ${facetAnon.statusCode} is not a clear deny or leak — inconclusive`,
      facets,
      bodySimilarityRatio: similarity,
    });
  }

  // Baseline not a protected resource
  return resultBase(request, {
    status: 'boundary_refuted',
    investigationOutcome: 'refuted',
    reasonCode: 'baseline_not_protected_resource',
    safeMessage:
      'Authenticated baseline did not return a protected resource representation — broken-boundary hypothesis refuted for this path',
    facets,
    bodySimilarityRatio: similarity,
  });
}

export class AuthBoundaryDifferentialDetectionService {
  public async execute(
    request: AuthBoundaryDifferentialDetectionRequest
  ): Promise<AuthBoundaryDifferentialDetectionResult> {
    return runAuthBoundaryDifferentialDetection(request);
  }
}
