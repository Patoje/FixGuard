/**
 * Pure probe inventory. Reads aggregated recon observations and the
 * assessment's existing AuthorizedScopeGrant. Does not execute HTTP,
 * spawn processes, call detectors, or mint authorization.
 */

import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION } from '../scope/AuthorizedScopeContracts.js';
import {
  evaluateScopePolicy,
  getSafeClassification,
  isPathAllowedByScopeBoundaries,
} from '../scope/AuthorizedScopePolicyService.js';
import type { AuthorizedActiveReconRequestLineage } from '../lineage/AuthorizedExecutionLineageContracts.js';
import {
  PROBE_INVENTORY_CONTRACT_VERSION,
  type ProbeInventory,
  type ProbeInventoryEntry,
} from './ProbeInventoryContracts.js';

const INVENTORY_KEYS = [
  'contractVersion',
  'kind',
  'assessmentId',
  'scanId',
  'authorizationGrantId',
  'authorizationDecisionId',
  'actorId',
  'entries',
] as const;

const ENTRY_KEYS = ['origin', 'path', 'method', 'parameters', 'sources'] as const;

const METHOD_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,15}$/;
const SOURCE_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

const URL_DISCOVERY_SOURCE = 'url_discovery';
const WEB_INSPECTION_SOURCE = 'web_inspection';
const CONTENT_DISCOVERY_SOURCE = 'content_discovery';
const PARAMETER_DISCOVERY_SOURCE = 'parameter_discovery';
const SPA_DISCOVERY_SOURCE = 'spa_discovery';

export interface BuildProbeInventoryInput {
  readonly observations: AggregatedReconObservations;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedActiveReconRequestLineage;
  readonly evaluatedAt: string;
}

interface MutableEntry {
  origin: string;
  path: string;
  method: string;
  explicit: boolean;
  parameters: Set<string>;
  sources: Set<string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[]
): boolean {
  const keys = Object.keys(value);
  if (keys.length !== allowed.length) {
    return false;
  }
  for (const key of allowed) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      return false;
    }
  }
  return true;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isStringArray(value: unknown): value is readonly string[] {
  if (!Array.isArray(value)) {
    return false;
  }
  return value.every((item) => typeof item === 'string');
}

function pathKey(origin: string, path: string): string {
  return `${origin}\n${path}`;
}

function probeKey(origin: string, path: string, method: string): string {
  return `${origin}\n${path}\n${method}`;
}

function rememberParameter(target: Set<string>, name: unknown): void {
  if (typeof name !== 'string') {
    return;
  }
  const trimmed = name.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return;
  }
  if (/[\r\n\0]/.test(trimmed)) {
    return;
  }
  target.add(trimmed);
}

function rememberSource(target: Set<string>, source: string): void {
  const trimmed = source.trim();
  if (!SOURCE_PATTERN.test(trimmed)) {
    return;
  }
  target.add(trimmed);
}

function rememberSources(target: Set<string>, sources: readonly string[], fallback: string): void {
  for (const source of sources) {
    rememberSource(target, source);
  }
  if (target.size === 0) {
    rememberSource(target, fallback);
  }
}

/**
 * Method carried by the raw observation. Absent or blank means the
 * observation did not record a method (URL and content discovery).
 * A present method is kept; it is not replaced with GET.
 * Returns null when a present method is not a token we can store.
 */
function readObservedMethod(
  value: string | undefined
): { method: string; explicit: boolean } | null {
  if (value === undefined) {
    return { method: 'GET', explicit: false };
  }
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return { method: 'GET', explicit: false };
  }
  if (!METHOD_PATTERN.test(trimmed)) {
    return null;
  }
  return { method: trimmed.toUpperCase(), explicit: true };
}

function queryParameterNames(parsed: URL, target: Set<string>): void {
  parsed.searchParams.forEach((_value, key) => {
    rememberParameter(target, key);
  });
}

/**
 * URL is inside the sealed grant. Uses evaluateScopePolicy the same way
 * seed validation does (endpoint discovery, no state change) plus the
 * shared path-boundary check. The observed method is not submitted as a
 * state-changing request: this catalog does not execute the URL.
 */
function urlIsInAuthorizedScope(
  grant: AuthorizedScopeGrant,
  parsed: URL,
  evaluatedAt: string,
  index: number
): boolean {
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return false;
  }
  const pathname = parsed.pathname.length > 0 ? parsed.pathname : '/';
  if (!isPathAllowedByScopeBoundaries(pathname, grant)) {
    return false;
  }
  const hostname = parsed.hostname.trim().toLowerCase().replace(/\.$/, '');
  if (hostname.length === 0) {
    return false;
  }
  const decision = evaluateScopePolicy({
    grant,
    request: {
      contractVersion: AUTHORIZED_SCOPE_POLICY_CONTRACT_VERSION,
      kind: 'scope_action_request',
      requestId: `probe_req_${index}`,
      scanId: grant.scanId,
      requestedAt: evaluatedAt,
      actionKind: 'endpoint_discovery',
      target: {
        targetKind: 'origin',
        normalizedOrigin: parsed.origin,
        host: hostname,
        domain: hostname,
      },
      method: 'GET',
      pathTemplate: pathname,
      intensity: 'passive',
      usesCredentials: false,
      mayChangeServerState: false,
      usesOob: false,
      classification: getSafeClassification(),
    },
    decisionId: `probe_scope_${index}`,
    evaluatedAt,
  });
  return decision.decision === 'allowed';
}

/** Same sealed-grant check the inventory uses when accepting an observed URL. */
export function isUrlInsideAuthorizedScope(
  grant: AuthorizedScopeGrant,
  rawUrl: string,
  evaluatedAt: string
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  return urlIsInAuthorizedScope(grant, parsed, evaluatedAt, 0);
}

function addCandidate(
  bucket: Map<string, MutableEntry>,
  input: {
    readonly parsed: URL;
    readonly method: string;
    readonly explicit: boolean;
    readonly parameters: readonly string[];
    readonly sources: readonly string[];
    readonly fallbackSource: string;
  }
): void {
  const origin = input.parsed.origin;
  const path = input.parsed.pathname.length > 0 ? input.parsed.pathname : '/';
  const key = probeKey(origin, path, input.method);
  let entry = bucket.get(key);
  if (!entry) {
    entry = {
      origin,
      path,
      method: input.method,
      explicit: input.explicit,
      parameters: new Set<string>(),
      sources: new Set<string>(),
    };
    bucket.set(key, entry);
  }
  if (input.explicit) {
    entry.explicit = true;
  }
  queryParameterNames(input.parsed, entry.parameters);
  for (const name of input.parameters) {
    rememberParameter(entry.parameters, name);
  }
  const sourceBucket = new Set<string>();
  rememberSources(sourceBucket, input.sources, input.fallbackSource);
  for (const source of sourceBucket) {
    entry.sources.add(source);
  }
}

function considerUrl(
  bucket: Map<string, MutableEntry>,
  grant: AuthorizedScopeGrant,
  evaluatedAt: string,
  index: { value: number },
  rawUrl: string,
  methodValue: string | undefined,
  parameters: readonly string[],
  sources: readonly string[],
  fallbackSource: string
): void {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return;
  }
  const method = readObservedMethod(methodValue);
  if (!method) {
    return;
  }
  const current = index.value;
  index.value += 1;
  if (!urlIsInAuthorizedScope(grant, parsed, evaluatedAt, current)) {
    return;
  }
  addCandidate(bucket, {
    parsed,
    method: method.method,
    explicit: method.explicit,
    parameters,
    sources,
    fallbackSource,
  });
}

/**
 * Method-less observations must not invent a GET row when the same
 * origin and path was observed with a real method (POST, PUT, …).
 */
function dropSyntheticGetWhenMethodObserved(bucket: Map<string, MutableEntry>): void {
  const explicitPaths = new Set<string>();
  for (const entry of bucket.values()) {
    if (entry.explicit) {
      explicitPaths.add(pathKey(entry.origin, entry.path));
    }
  }
  const syntheticKeys: string[] = [];
  for (const [key, entry] of bucket) {
    if (entry.explicit) {
      continue;
    }
    if (!explicitPaths.has(pathKey(entry.origin, entry.path))) {
      continue;
    }
    syntheticKeys.push(key);
  }
  for (const key of syntheticKeys) {
    const synthetic = bucket.get(key);
    bucket.delete(key);
    if (!synthetic) {
      continue;
    }
    for (const entry of bucket.values()) {
      if (pathKey(entry.origin, entry.path) !== pathKey(synthetic.origin, synthetic.path)) {
        continue;
      }
      if (!entry.explicit) {
        continue;
      }
      for (const parameter of synthetic.parameters) {
        entry.parameters.add(parameter);
      }
      for (const source of synthetic.sources) {
        entry.sources.add(source);
      }
    }
  }
}

function freezeInventory(
  lineage: AuthorizedActiveReconRequestLineage,
  bucket: Map<string, MutableEntry>
): ProbeInventory {
  const entries: ProbeInventoryEntry[] = Array.from(bucket.values())
    .map((entry) => ({
      origin: entry.origin,
      path: entry.path,
      method: entry.method,
      parameters: Object.freeze(Array.from(entry.parameters).sort()),
      sources: Object.freeze(Array.from(entry.sources).sort()),
    }))
    .sort((left, right) => {
      const originOrder = left.origin.localeCompare(right.origin);
      if (originOrder !== 0) {
        return originOrder;
      }
      const pathOrder = left.path.localeCompare(right.path);
      if (pathOrder !== 0) {
        return pathOrder;
      }
      return left.method.localeCompare(right.method);
    });

  return Object.freeze({
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
    entries: Object.freeze(entries),
  });
}

export function buildProbeInventory(input: BuildProbeInventoryInput): ProbeInventory {
  const bucket = new Map<string, MutableEntry>();
  const index = { value: 0 };
  const observations = input.observations;

  for (const urlObs of observations.urls) {
    considerUrl(
      bucket,
      input.scopeGrant,
      input.evaluatedAt,
      index,
      urlObs.url,
      undefined,
      [],
      urlObs.sources,
      URL_DISCOVERY_SOURCE
    );
  }

  for (const webObs of observations.webObservations) {
    considerUrl(
      bucket,
      input.scopeGrant,
      input.evaluatedAt,
      index,
      webObs.url,
      webObs.method,
      [],
      [],
      WEB_INSPECTION_SOURCE
    );
  }

  for (const contentObs of observations.content) {
    considerUrl(
      bucket,
      input.scopeGrant,
      input.evaluatedAt,
      index,
      contentObs.url,
      undefined,
      [],
      [],
      CONTENT_DISCOVERY_SOURCE
    );
  }

  for (const parameterObs of observations.parameters) {
    considerUrl(
      bucket,
      input.scopeGrant,
      input.evaluatedAt,
      index,
      parameterObs.url,
      parameterObs.method,
      [parameterObs.parameterName],
      [],
      PARAMETER_DISCOVERY_SOURCE
    );
  }

  for (const spaObs of observations.spaObservations ?? []) {
    for (const route of spaObs.routes) {
      const sources = route.source.length > 0 ? [route.source] : [];
      considerUrl(
        bucket,
        input.scopeGrant,
        input.evaluatedAt,
        index,
        route.url,
        route.method,
        [],
        sources,
        SPA_DISCOVERY_SOURCE
      );
    }
  }

  dropSyntheticGetWhenMethodObserved(bucket);
  return freezeInventory(input.lineage, bucket);
}

export interface ProbeCandidate {
  readonly url: string;
  readonly parameterName?: string;
  readonly source?: string;
}

export interface AppendProbeCandidatesResult {
  readonly inventory: ProbeInventory;
  readonly acceptedUrls: readonly string[];
  readonly rejectedUrls: readonly string[];
}

const READ_STEP_SOURCE = 'read_step';

function lineageFromInventory(inventory: ProbeInventory): AuthorizedActiveReconRequestLineage {
  return {
    assessmentId: inventory.assessmentId,
    scanId: inventory.scanId,
    authorizationGrantId: inventory.authorizationGrantId,
    authorizationDecisionId: inventory.authorizationDecisionId,
    actorId: inventory.actorId,
  };
}

function bucketFromInventory(inventory: ProbeInventory): Map<string, MutableEntry> {
  const bucket = new Map<string, MutableEntry>();
  for (const entry of inventory.entries) {
    const parameters = new Set<string>();
    for (const name of entry.parameters) {
      rememberParameter(parameters, name);
    }
    const sources = new Set<string>();
    for (const source of entry.sources) {
      rememberSource(sources, source);
    }
    bucket.set(probeKey(entry.origin, entry.path, entry.method), {
      origin: entry.origin,
      path: entry.path,
      method: entry.method,
      explicit: true,
      parameters,
      sources,
    });
  }
  return bucket;
}

/**
 * Copy-on-write append. A candidate is stored only when the same scope
 * filter as buildProbeInventory accepts it. Hosts outside that grant are
 * returned as rejected and are not inserted.
 */
export function appendProbeCandidates(
  inventory: ProbeInventory,
  scopeGrant: AuthorizedScopeGrant,
  evaluatedAt: string,
  candidates: readonly ProbeCandidate[]
): AppendProbeCandidatesResult {
  const bucket = bucketFromInventory(inventory);
  const accepted: string[] = [];
  const rejected: string[] = [];
  let index = inventory.entries.length;

  for (const candidate of candidates) {
    let parsed: URL;
    try {
      parsed = new URL(candidate.url);
    } catch {
      rejected.push(candidate.url);
      continue;
    }
    const current = index;
    index += 1;
    if (!urlIsInAuthorizedScope(scopeGrant, parsed, evaluatedAt, current)) {
      rejected.push(parsed.toString());
      continue;
    }
    const origin = parsed.origin;
    const path = parsed.pathname.length > 0 ? parsed.pathname : '/';
    const method = readObservedMethod(undefined);
    if (!method) {
      rejected.push(parsed.toString());
      continue;
    }
    const key = probeKey(origin, path, method.method);
    const before = bucket.get(key);
    const beforeParameters = before ? before.parameters.size : 0;
    const source = candidate.source ?? READ_STEP_SOURCE;
    addCandidate(bucket, {
      parsed,
      method: method.method,
      explicit: false,
      parameters: candidate.parameterName ? [candidate.parameterName] : [],
      sources: [source],
      fallbackSource: READ_STEP_SOURCE,
    });
    const after = bucket.get(key);
    const grew =
      !before ||
      (after !== undefined && after.parameters.size > beforeParameters);
    if (grew) {
      accepted.push(parsed.toString());
    }
  }

  return {
    inventory: freezeInventory(lineageFromInventory(inventory), bucket),
    acceptedUrls: Object.freeze(accepted),
    rejectedUrls: Object.freeze(rejected),
  };
}

function parseEntry(value: unknown): ProbeInventoryEntry | null {
  if (!isRecord(value) || !hasExactKeys(value, ENTRY_KEYS)) {
    return null;
  }
  if (
    !isNonEmptyString(value.origin) ||
    !isNonEmptyString(value.path) ||
    !isNonEmptyString(value.method) ||
    !isStringArray(value.parameters) ||
    !isStringArray(value.sources)
  ) {
    return null;
  }
  if (value.sources.length === 0) {
    return null;
  }
  return {
    origin: value.origin,
    path: value.path,
    method: value.method,
    parameters: value.parameters,
    sources: value.sources,
  };
}

/**
 * Closed-world parse of a persisted probe inventory.
 * Unknown keys, missing keys, and malformed entries fail closed.
 */
export function parseProbeInventory(value: unknown): ProbeInventory | null {
  if (!isRecord(value) || !hasExactKeys(value, INVENTORY_KEYS)) {
    return null;
  }
  if (
    value.contractVersion !== PROBE_INVENTORY_CONTRACT_VERSION ||
    value.kind !== 'probe_inventory' ||
    !isNonEmptyString(value.assessmentId) ||
    !isNonEmptyString(value.scanId) ||
    !isNonEmptyString(value.authorizationGrantId) ||
    !isNonEmptyString(value.authorizationDecisionId) ||
    !isNonEmptyString(value.actorId) ||
    !Array.isArray(value.entries)
  ) {
    return null;
  }
  const entries: ProbeInventoryEntry[] = [];
  for (const raw of value.entries) {
    const entry = parseEntry(raw);
    if (!entry) {
      return null;
    }
    entries.push(entry);
  }
  return {
    contractVersion: PROBE_INVENTORY_CONTRACT_VERSION,
    kind: 'probe_inventory',
    assessmentId: value.assessmentId,
    scanId: value.scanId,
    authorizationGrantId: value.authorizationGrantId,
    authorizationDecisionId: value.authorizationDecisionId,
    actorId: value.actorId,
    entries,
  };
}
