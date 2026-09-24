/**
 * Phase D1 — Discovery → Detection bridge (minimal).
 *
 * Feeds OBSERVED app endpoints from recon into detection probes, excluding
 * pure static bundles (/_next/static) from heavy probing. Tech-aware gates
 * suppress irrelevant PHP-session probes on Next.js / non-PHP stacks with an
 * explicit abstain/suppress reason (never a silent drop).
 *
 * Non-goals: new detectors, Attack Mode breadth, DetectionRegistry rewrite.
 */

import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { TechnologyFingerprintService } from '../recon/analysis/TechnologyFingerprintService.js';
import type { DetectedTechnology, TechEcosystemProfile } from '../core/TechnologyContracts.js';

export const DETECTION_TARGET_BRIDGE_MAX_PRIMARY = 8;
export const DETECTION_TARGET_BRIDGE_MAX_IDOR = 5;

const REJECTED_MEDIA_EXTENSIONS = Object.freeze([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.svg',
  '.woff',
  '.woff2',
  '.ttf',
  '.css',
  '.ico',
  '.map',
] as const);

const IDOR_PARAM_NAMES = Object.freeze([
  'id',
  'user_id',
  'userid',
  'account_id',
  'order_id',
  'doc_id',
  'item_id',
] as const);

const REST_ID_PATH =
  /\/(users|orders|accounts|items|documents|api\/users|api\/orders|api\/accounts)\/([0-9a-zA-Z_-]+)$/i;

export type DetectionEndpointKind = 'app_endpoint' | 'static_bundle';

export interface DetectionAppEndpointTarget {
  readonly url: string;
  readonly path: string;
  readonly kind: 'app_endpoint';
  readonly epistemicStatus: 'OBSERVED';
  readonly parameters: readonly string[];
}

export interface DetectionIdorCandidate {
  readonly endpointUrl: string;
  readonly resourceParamName: string;
  readonly baselineResourceId: string;
  readonly source: 'parameter_observation' | 'rest_path' | 'observed_endpoint_query_probe';
}

export interface DetectionSuppressionRecord {
  readonly detectorKind: string;
  readonly reasonCode: string;
  readonly rationale: string;
  readonly url?: string;
}

export interface DetectionTargetBridgeInput {
  readonly targetDomain: string;
  readonly aggregatedObservations: AggregatedReconObservations;
  readonly maxPrimaryProbeUrls?: number;
  readonly maxIdorCandidates?: number;
}

export interface DetectionTargetBridgeResult {
  readonly ecosystemProfile: TechEcosystemProfile;
  readonly detectedTechnologies: readonly DetectedTechnology[];
  readonly appEndpoints: readonly DetectionAppEndpointTarget[];
  readonly staticBundleUrls: readonly string[];
  /** App endpoints preferred for heavy surface probes (CORS, headers, reflection, …). */
  readonly primaryProbeUrls: readonly string[];
  readonly idorCandidates: readonly DetectionIdorCandidate[];
  readonly suppressions: readonly DetectionSuppressionRecord[];
  readonly phpSessionFixationGate: PhpSessionFixationTechGate;
}

export interface PhpSessionFixationTechGate {
  readonly suppress: boolean;
  readonly reasonCode: string;
  readonly rationale: string;
}

function normalizeDomain(targetDomain: string): string {
  return targetDomain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '');
}

export function isStaticBundlePath(pathname: string): boolean {
  return pathname.toLowerCase().includes('/_next/static/');
}

function isRejectedMediaPath(pathname: string): boolean {
  const lower = pathname.toLowerCase();
  if (isStaticBundlePath(lower)) {
    return false;
  }
  return REJECTED_MEDIA_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

function classifyPath(pathname: string): DetectionEndpointKind {
  return isStaticBundlePath(pathname) ? 'static_bundle' : 'app_endpoint';
}

function extractQueryParamNames(url: string): string[] {
  try {
    const parsed = new URL(url);
    return Array.from(parsed.searchParams.keys()).sort();
  } catch {
    return [];
  }
}

function fingerprintFromObservations(
  aggregated: AggregatedReconObservations
): { technologies: readonly DetectedTechnology[]; ecosystemProfile: TechEcosystemProfile } {
  const fingerprintService = new TechnologyFingerprintService();
  const rawObservations: unknown[] = [
    ...aggregated.webObservations,
    ...aggregated.urls,
  ];

  // Prefer the richest web observation body/headers when present.
  let bestUrl = '';
  let bestHeaders: Readonly<Record<string, string | string[] | undefined>> | undefined;
  let bestBody = '';
  for (const web of aggregated.webObservations) {
    const body = typeof web.bodyText === 'string' ? web.bodyText : '';
    if (body.length >= bestBody.length) {
      bestBody = body;
      bestUrl = web.url;
      bestHeaders = web.headers;
    }
  }

  return fingerprintService.analyze({
    url: bestUrl,
    headers: bestHeaders,
    bodyText: bestBody,
    rawObservations,
  });
}

/**
 * Tech-aware gate: PHPSESSID-style session fixation is irrelevant on Next.js /
 * non-PHP SPA stacks. Suppression is explicit (reasonCode), not silent.
 */
export function evaluatePhpSessionFixationTechGate(
  ecosystem: TechEcosystemProfile,
  technologies: readonly DetectedTechnology[]
): PhpSessionFixationTechGate {
  const spa = ecosystem.spaFramework;
  if (spa === 'nextjs' || spa === 'nuxtjs') {
    return {
      suppress: true,
      reasonCode: 'php_session_probe_suppressed_spa_framework',
      rationale: `spaFramework=${spa}: PHPSESSID session-fixation probe abstained (non-PHP session model)`,
    };
  }

  const nextHigh = technologies.some(
    (t) =>
      t.name.toLowerCase().includes('next.js') &&
      t.confidence === 'high'
  );
  if (nextHigh) {
    return {
      suppress: true,
      reasonCode: 'php_session_probe_suppressed_nextjs_high',
      rationale:
        'Next.js detected at high confidence: PHPSESSID session-fixation probe abstained',
    };
  }

  const hasPhp = technologies.some((t) => t.name.toLowerCase() === 'php');
  if (ecosystem.hasSpa && !hasPhp && !ecosystem.hasPhpLegacy) {
    return {
      suppress: true,
      reasonCode: 'php_session_probe_suppressed_non_php_spa',
      rationale:
        'SPA without PHP signals: PHPSESSID session-fixation probe abstained',
    };
  }

  return {
    suppress: false,
    reasonCode: 'php_session_probe_applicable',
    rationale: 'PHPSESSID session-fixation probe allowed by tech gate',
  };
}

/**
 * Identical error-page differentials (e.g. both identities 404 + same body hash)
 * are not access-control evidence. Callers should abstain with this reason.
 */
export function isIdenticalErrorDifferential(input: {
  readonly baselineStatusCode: number;
  readonly validationStatusCode: number;
  readonly baselineBodyHash: string;
  readonly validationBodyHash: string;
}): boolean {
  const { baselineStatusCode, validationStatusCode, baselineBodyHash, validationBodyHash } =
    input;
  if (baselineBodyHash.length === 0 || validationBodyHash.length === 0) {
    return false;
  }
  if (baselineBodyHash !== validationBodyHash) {
    return false;
  }
  if (baselineStatusCode !== validationStatusCode) {
    return false;
  }
  // Identical client/server errors or empty auth failures with no body delta.
  return (
    baselineStatusCode === 404 ||
    baselineStatusCode === 400 ||
    baselineStatusCode === 401 ||
    baselineStatusCode === 403 ||
    baselineStatusCode === 410 ||
    baselineStatusCode === 502 ||
    baselineStatusCode === 503
  );
}

/**
 * True when dual-identity probes observed identical HTTP substance and the
 * probe pair is an anonymous orchestrator fallback (identity_anon_*).
 * Identity-label authStateHash churn alone must not mint IDOR drafts.
 *
 * Labeled BYOT identities (even without injected headers yet) and credentialed
 * probes keep the differential pipeline — identical error pages still abstain.
 */
export function shouldAbstainIdorWithoutAccessDifferential(input: {
  readonly baselineStatusCode: number;
  readonly validationStatusCode: number;
  readonly baselineBodyHash: string;
  readonly validationBodyHash: string;
  readonly identityAHasCredentials: boolean;
  readonly identityBHasCredentials: boolean;
  readonly identityAId?: string;
  readonly identityBId?: string;
}): boolean {
  if (isIdenticalErrorDifferential(input)) {
    return true;
  }

  const bothAnonymousFallbacks =
    isAnonymousIdentityId(input.identityAId) && isAnonymousIdentityId(input.identityBId);

  if (!bothAnonymousFallbacks) {
    return false;
  }

  if (input.identityAHasCredentials || input.identityBHasCredentials) {
    return false;
  }

  return (
    input.baselineStatusCode === input.validationStatusCode &&
    input.baselineBodyHash.length > 0 &&
    input.baselineBodyHash === input.validationBodyHash
  );
}

export function isAnonymousIdentityId(identityId: string | undefined): boolean {
  if (!identityId) return false;
  const id = identityId.toLowerCase();
  return (
    id === 'anonymous' ||
    id.startsWith('anonymous') ||
    id.startsWith('identity_anon') ||
    id.startsWith('anonymous_probe')
  );
}

export function probeAuthContextHasCredentials(input: {
  readonly headers?: Readonly<Record<string, string>>;
  readonly cookies?: Readonly<Record<string, string>>;
  readonly sessionState?: unknown;
}): boolean {
  if (input.sessionState !== undefined && input.sessionState !== null) {
    return true;
  }
  if (input.cookies && Object.keys(input.cookies).length > 0) {
    return true;
  }
  if (!input.headers) {
    return false;
  }
  // Any non-empty injected header differentiates the probe (BYOT identity material).
  return Object.values(input.headers).some((v) => v.trim().length > 0);
}

function collectObservedUrls(
  targetDomain: string,
  aggregated: AggregatedReconObservations
): Map<string, { url: string; path: string; parameters: Set<string> }> {
  const domain = normalizeDomain(targetDomain);
  const byPath = new Map<string, { url: string; path: string; parameters: Set<string> }>();

  const ingest = (rawUrl: string): void => {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return;
    }
    const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
    if (host !== domain && !host.endsWith(`.${domain}`)) {
      return;
    }
    const path = parsed.pathname || '/';
    if (isRejectedMediaPath(path)) {
      return;
    }
    const kind = classifyPath(path);
    if (kind === 'static_bundle') {
      return; // handled separately for sourcemap; excluded from heavy probes
    }
    const params = extractQueryParamNames(rawUrl);
    const existing = byPath.get(path);
    if (!existing) {
      byPath.set(path, {
        url: `${parsed.origin}${path}`,
        path,
        parameters: new Set(params),
      });
    } else {
      for (const p of params) {
        existing.parameters.add(p);
      }
    }
  };

  for (const u of aggregated.urls) {
    ingest(u.url);
  }
  for (const w of aggregated.webObservations) {
    ingest(w.url);
  }
  for (const c of aggregated.content) {
    if (typeof c.url === 'string') {
      ingest(c.url);
    }
  }

  // Do NOT invent synthetic origin root `/` as OBSERVED when recon never produced it.
  return byPath;
}

function collectStaticBundles(aggregated: AggregatedReconObservations): string[] {
  const out = new Set<string>();
  const consider = (rawUrl: string): void => {
    try {
      const parsed = new URL(rawUrl);
      if (isStaticBundlePath(parsed.pathname)) {
        out.add(rawUrl.split('#')[0] ?? rawUrl);
      }
    } catch {
      // ignore
    }
  };
  for (const u of aggregated.urls) {
    consider(u.url);
  }
  for (const w of aggregated.webObservations) {
    consider(w.url);
  }
  return Array.from(out).sort();
}

function buildIdorCandidates(
  aggregated: AggregatedReconObservations,
  appEndpoints: readonly DetectionAppEndpointTarget[],
  maxIdor: number,
  suppressions: DetectionSuppressionRecord[]
): DetectionIdorCandidate[] {
  const candidates: DetectionIdorCandidate[] = [];
  const seen = new Set<string>();

  const push = (c: DetectionIdorCandidate): void => {
    const key = `${c.endpointUrl}|${c.resourceParamName}|${c.baselineResourceId}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push(c);
  };

  for (const paramObs of aggregated.parameters) {
    const pName = paramObs.parameterName.toLowerCase();
    if ((IDOR_PARAM_NAMES as readonly string[]).includes(pName)) {
      push({
        endpointUrl: paramObs.url,
        resourceParamName: paramObs.parameterName,
        baselineResourceId: '1',
        source: 'parameter_observation',
      });
    }
  }

  for (const urlObs of aggregated.urls) {
    const match = urlObs.url.match(REST_ID_PATH);
    if (match && match[1] && match[2]) {
      push({
        endpointUrl: urlObs.url,
        resourceParamName: match[1],
        baselineResourceId: match[2],
        source: 'rest_path',
      });
    }
  }

  // Prefer real OBSERVED app endpoints over fabricated /api/user/1.
  if (candidates.length === 0 && appEndpoints.length > 0) {
    for (const ep of appEndpoints) {
      if (ep.path === '/') continue;
      if (isStaticBundlePath(ep.path)) continue;
      push({
        endpointUrl: ep.url,
        resourceParamName: 'id',
        baselineResourceId: '1',
        source: 'observed_endpoint_query_probe',
      });
      if (candidates.length >= maxIdor) break;
    }
  }

  if (candidates.length === 0) {
    suppressions.push({
      detectorKind: 'idor_access_control',
      reasonCode: 'idor_no_observed_resource_candidates',
      rationale:
        'No OBSERVED resource-parameter or app-endpoint candidates for differential IDOR; fabricated /api/user/1 fallback suppressed',
    });
  }

  return candidates.slice(0, maxIdor);
}

/**
 * Build detection targets from recon observations (pre-profile).
 */
export function buildDetectionTargetsFromRecon(
  input: DetectionTargetBridgeInput
): DetectionTargetBridgeResult {
  const maxPrimary = input.maxPrimaryProbeUrls ?? DETECTION_TARGET_BRIDGE_MAX_PRIMARY;
  const maxIdor = input.maxIdorCandidates ?? DETECTION_TARGET_BRIDGE_MAX_IDOR;
  const suppressions: DetectionSuppressionRecord[] = [];

  const { technologies, ecosystemProfile } = fingerprintFromObservations(
    input.aggregatedObservations
  );

  const byPath = collectObservedUrls(input.targetDomain, input.aggregatedObservations);
  const staticBundleUrls = collectStaticBundles(input.aggregatedObservations);

  if (staticBundleUrls.length > 0) {
    suppressions.push({
      detectorKind: 'heavy_surface_probe',
      reasonCode: 'static_bundle_excluded_from_heavy_probe',
      rationale: `${staticBundleUrls.length} static bundle URL(s) excluded from heavy detection probing (e.g. /_next/static)`,
    });
  }

  const appEndpoints: DetectionAppEndpointTarget[] = Array.from(byPath.values())
    .map((e) => ({
      url: e.url,
      path: e.path,
      kind: 'app_endpoint' as const,
      epistemicStatus: 'OBSERVED' as const,
      parameters: Array.from(e.parameters).sort(),
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

  // Prefer non-root app routes first, then root — still capped.
  const ranked = [
    ...appEndpoints.filter((e) => e.path !== '/'),
    ...appEndpoints.filter((e) => e.path === '/'),
  ];
  const primaryProbeUrls = ranked.slice(0, maxPrimary).map((e) => e.url);

  const idorCandidates = buildIdorCandidates(
    input.aggregatedObservations,
    appEndpoints,
    maxIdor,
    suppressions
  );

  const phpSessionFixationGate = evaluatePhpSessionFixationTechGate(
    ecosystemProfile,
    technologies
  );
  if (phpSessionFixationGate.suppress) {
    suppressions.push({
      detectorKind: 'session_fixation',
      reasonCode: phpSessionFixationGate.reasonCode,
      rationale: phpSessionFixationGate.rationale,
    });
  }

  return {
    ecosystemProfile,
    detectedTechnologies: technologies,
    appEndpoints,
    staticBundleUrls,
    primaryProbeUrls,
    idorCandidates,
    suppressions,
    phpSessionFixationGate,
  };
}
