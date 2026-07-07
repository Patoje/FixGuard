/**
 * M47 — Response Comparator Service (DB-free)
 *
 * Pure functions with no network, no tools, no DB, no side effects.
 * Completely independent of M45 EvidenceBoundary.
 *
 * Public API:
 *   validateSafeResponseSnapshot(snapshot): ValidationResult
 *   validateResponseComparisonRequest(request): ValidationResult
 *   compareResponses(request, comparedAt): ResponseComparisonResult
 *
 * Internal helpers (exported for testing):
 *   buildResponseDifference(baseline, validation, thresholds): ResponseDifference
 *   deriveComparisonSignificance(difference, mode): ComparisonSignificance
 *   deriveEvidenceMappingHint(difference, significance, mode): EvidenceMappingHint
 */

import type {
  SafeResponseSnapshot,
  ResponseComparisonRequest,
  ResponseComparisonResult,
  ResponseDifference,
  ComparisonSignificance,
  EvidenceMappingHint,
  ValidationResult,
  ResponseComparatorClassificationFlags,
  SnapshotSubject,
  ComparisonThresholds,
  ComparatorErrorCode,
  ExplicitNonClaims
} from './ResponseComparatorContracts.js';

import {
  RESPONSE_COMPARATOR_CONTRACT_VERSION,
  ALLOWED_HTTP_METHODS,
  ALLOWED_SNAPSHOT_ROLES,
  ALLOWED_SHAPE_KINDS,
  ALLOWED_AUTH_STATE_SIGNALS,
  ALLOWED_ERROR_SIGNAL_NAMES,
  ALLOWED_EXCERPT_SOURCES,
  ALLOWED_COMPARISON_MODES,
  ALLOWED_SIGNAL_SUMMARY_ITEMS,
  ALLOWED_STRONGEST_SIGNALS,
  ALLOWED_SIGNAL_STRENGTHS,
  ALLOWED_SUGGESTED_EVIDENCE_TYPES,
  ALLOWED_SUGGESTED_SIGNAL_STRENGTHS,
  ALLOWED_COMPARATOR_ERROR_CODES
} from './ResponseComparatorContracts.js';

// ---------------------------------------------------------------------------
// Safe sentinel constants
// ---------------------------------------------------------------------------

const SENTINEL_COMPARISON_ID = 'invalid_comparison_id';
const SENTINEL_SNAPSHOT_ID = 'invalid_snapshot_id';
const SENTINEL_SCAN_ID = 'invalid_scan_id';
const SENTINEL_EVALUATED_AT = '1970-01-01T00:00:00.000Z';

// ---------------------------------------------------------------------------
// Classification helper
// ---------------------------------------------------------------------------

export function getSafeClassification(): ResponseComparatorClassificationFlags {
  return {
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetwork: false,
    executesTools: false,
    persistsData: false
  };
}

// ---------------------------------------------------------------------------
// Explicit non-claims
// ---------------------------------------------------------------------------

function getSafeNonClaims(): ExplicitNonClaims {
  return {
    noConfirmedVulnerability: true,
    noFindingCreated: true,
    noPersistedEvidenceCreated: true,
    noSeverityRiskOrImpactClaim: true,
    noRawSensitiveDataIncluded: true
  };
}

// ---------------------------------------------------------------------------
// Generic validators
// ---------------------------------------------------------------------------

const CLASSIFICATION_KEYS = [
  'createsRealFindings', 'createsPersistedEvidence', 'confirmsVulnerabilities',
  'makesRiskClaims', 'makesSeverityClaims', 'makesImpactClaims',
  'executesNetwork', 'executesTools', 'persistsData'
] as const;

function validateAllowedKeys(value: any, allowed: readonly string[]): ValidationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Value must be a plain object' };
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Unknown/forbidden field: ${key}` };
    }
  }
  return { isValid: true };
}

// Sensitive header names to reject
const SENSITIVE_HEADER_NAMES = new Set([
  'authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key',
  'bearer', 'token', 'secret', 'password', 'api-key', 'apikey', 'access-token', 'refresh-token'
]);

function forbiddenContentScan(str: string): boolean {
  if (!str) return false;
  const lower = str.toLowerCase();
  const forbidden = [
    'authorization', 'bearer', 'cookie', 'set-cookie',
    'password', 'secret', 'token', 'api_key', 'apikey',
    'access_token', 'refresh_token',
    'raw_request', 'raw request', 'raw_response', 'raw response',
    'raw_body', 'raw body', 'raw_headers', 'raw headers',
    'raw payload', 'raw command', 'raw output', 'raw tool output',
    'stack trace', 'error:',
    'confirmed vulnerability', 'critical severity',
    'target is vulnerable'
  ];
  return forbidden.some(f => lower.includes(f));
}

function validateSafeId(id: any): ValidationResult {
  if (!id || typeof id !== 'string' || id.length === 0)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID missing or empty' };
  if (id.length > 128)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID exceeds max 128' };
  if (!/^[a-zA-Z0-9_\-.:]+$/.test(id))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains invalid characters' };
  if (forbiddenContentScan(id))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'ID contains forbidden content' };
  return { isValid: true };
}

function validateSafeHash(hash: any): ValidationResult {
  if (!hash || typeof hash !== 'string' || hash.length === 0)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash missing or empty' };
  if (hash.length > 128)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash exceeds max 128' };
  if (!/^[a-zA-Z0-9_\-=+/.:]+$/.test(hash))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash contains invalid characters' };
  if (forbiddenContentScan(hash))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Hash contains forbidden content' };
  return { isValid: true };
}

function validateIsoTimestamp(ts: any): ValidationResult {
  if (typeof ts !== 'string')
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Timestamp missing or invalid type' };

  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(ts)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Timestamp is not strict ISO 8601' };
  }

  const parsed = new Date(ts);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== ts) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid ISO timestamp' };
  }

  return { isValid: true };
}

function validateSafeText(text: any, maxLength: number): ValidationResult {
  if (text === undefined || typeof text !== 'string')
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text missing or invalid type' };
  if (text.length > maxLength)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Text exceeds max length ${maxLength}` };
  if (forbiddenContentScan(text))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Text contains forbidden content' };
  return { isValid: true };
}

function validateNormalizedOrigin(origin: any): ValidationResult {
  if (!origin || typeof origin !== 'string')
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin missing' };
  if (origin.length > 253)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin too long' };
  let url: URL;
  try { url = new URL(origin); } catch {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin is not a valid URL' };
  }
  if (!['http:', 'https:'].includes(url.protocol))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must be http or https' };
  if (url.username || url.password)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain credentials' };
  if (url.pathname !== '/')
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain path' };
  if (url.search || url.hash)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin must not contain query or fragment' };
  if (forbiddenContentScan(origin))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'normalizedOrigin contains forbidden content' };
  return { isValid: true };
}

function validatePathTemplate(pt: any): ValidationResult {
  if (!pt || typeof pt !== 'string')
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate missing' };
  if (pt.length > 300)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate too long' };
  if (!pt.startsWith('/'))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must start with /' };
  if (pt.includes('?') || pt.includes('#'))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate must not contain query or fragment' };
  if (forbiddenContentScan(pt))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'pathTemplate contains forbidden content' };
  return { isValid: true };
}

function validateClassification(cls: any): ValidationResult {
  const keysVal = validateAllowedKeys(cls, CLASSIFICATION_KEYS);
  if (!keysVal.isValid) return keysVal;
  for (const key of CLASSIFICATION_KEYS) {
    if ((cls as any)[key] !== false)
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Classification flag ${key} must be false` };
  }
  return { isValid: true };
}

function safeIdOrSentinel(raw: any, sentinel: string): string {
  if (!raw || typeof raw !== 'string') return sentinel;
  return validateSafeId(raw).isValid ? raw : sentinel;
}

// ---------------------------------------------------------------------------
// Subject validator
// ---------------------------------------------------------------------------

function validateSnapshotSubject(subject: any): ValidationResult {
  if (!subject || typeof subject !== 'object' || Array.isArray(subject))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'subject missing or invalid' };

  const keysVal = validateAllowedKeys(subject, ['normalizedOrigin', 'method', 'pathTemplate', 'routeId']);
  if (!keysVal.isValid) return keysVal;

  // Must include routeId OR (normalizedOrigin + method + pathTemplate)
  const hasRouteId = typeof subject.routeId === 'string' && subject.routeId.length > 0;
  const hasFullOriginSubject =
    subject.normalizedOrigin !== undefined &&
    subject.method !== undefined &&
    subject.pathTemplate !== undefined;

  if (!hasRouteId && !hasFullOriginSubject) {
    return {
      isValid: false, errorCode: 'unsafe_content_rejected',
      message: 'subject must include routeId OR (normalizedOrigin + method + pathTemplate)'
    };
  }

  if (subject.normalizedOrigin !== undefined) {
    const v = validateNormalizedOrigin(subject.normalizedOrigin);
    if (!v.isValid) return v;
  }
  if (subject.method !== undefined && !ALLOWED_HTTP_METHODS.includes(subject.method)) {
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Invalid method' };
  }
  if (subject.pathTemplate !== undefined) {
    const v = validatePathTemplate(subject.pathTemplate);
    if (!v.isValid) return v;
  }
  if (subject.routeId !== undefined) {
    const v = validateSafeId(subject.routeId);
    if (!v.isValid) return v;
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// Subject equality check
// ---------------------------------------------------------------------------

function subjectsEqual(a: SnapshotSubject, b: SnapshotSubject): boolean {
  return (
    a.normalizedOrigin === b.normalizedOrigin &&
    a.method === b.method &&
    a.pathTemplate === b.pathTemplate &&
    a.routeId === b.routeId
  );
}

// ---------------------------------------------------------------------------
// headerNames validator
// ---------------------------------------------------------------------------

const SAFE_HEADER_NAME_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/;

function validateHeaderNames(headerNames: any): ValidationResult {
  if (!Array.isArray(headerNames))
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerNames must be an array' };
  if (headerNames.length > 100)
    return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'headerNames exceeds cap of 100' };
  for (const name of headerNames) {
    if (typeof name !== 'string' || name.length === 0 || name.length > 100)
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name invalid length' };
    if (!SAFE_HEADER_NAME_RE.test(name))
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name contains invalid characters' };
    if (SENSITIVE_HEADER_NAMES.has(name.toLowerCase()))
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: `Sensitive header name rejected: ${name}` };
    if (forbiddenContentScan(name))
      return { isValid: false, errorCode: 'unsafe_content_rejected', message: 'Header name contains forbidden content' };
  }
  return { isValid: true };
}

// ---------------------------------------------------------------------------
// SafeResponseSnapshot validator
// ---------------------------------------------------------------------------

const SNAPSHOT_KEYS = [
  'contractVersion', 'kind', 'snapshotId', 'scanId', 'capturedAt', 'role',
  'subject', 'statusCode', 'contentLength', 'responseTimeMs',
  'headerNames', 'bodyHash', 'normalizedBodyShape', 'redirect',
  'authState', 'errorSignals', 'safeExcerpt', 'classification'
] as const;

export function validateSafeResponseSnapshot(snapshot: any): ValidationResult {
  if (!snapshot || snapshot.kind !== 'safe_response_snapshot')
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid kind' };
  if (snapshot.contractVersion !== RESPONSE_COMPARATOR_CONTRACT_VERSION)
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(snapshot, SNAPSHOT_KEYS);
  if (!keysVal.isValid) return { ...keysVal, errorCode: 'invalid_baseline_snapshot' };

  const idVal = validateSafeId(snapshot.snapshotId);
  if (!idVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: idVal.message };

  const scanIdVal = validateSafeId(snapshot.scanId);
  if (!scanIdVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: scanIdVal.message };

  const tsVal = validateIsoTimestamp(snapshot.capturedAt);
  if (!tsVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: tsVal.message };

  if (!ALLOWED_SNAPSHOT_ROLES.includes(snapshot.role))
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid role' };

  const subjectVal = validateSnapshotSubject(snapshot.subject);
  if (!subjectVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: subjectVal.message };

  // statusCode
  if (!Number.isInteger(snapshot.statusCode) || snapshot.statusCode < 100 || snapshot.statusCode > 599)
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'statusCode must be 100..599' };

  // contentLength
  if (!Number.isFinite(snapshot.contentLength) || snapshot.contentLength < 0 || snapshot.contentLength > 100_000_000)
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'contentLength must be 0..100_000_000' };

  // responseTimeMs
  if (!Number.isFinite(snapshot.responseTimeMs) || snapshot.responseTimeMs < 0 || snapshot.responseTimeMs > 300_000)
    return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'responseTimeMs must be 0..300_000' };

  // headerNames
  const headerVal = validateHeaderNames(snapshot.headerNames);
  if (!headerVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: headerVal.message };

  // bodyHash
  const hashVal = validateSafeHash(snapshot.bodyHash);
  if (!hashVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: hashVal.message };

  // normalizedBodyShape (optional)
  if (snapshot.normalizedBodyShape !== undefined) {
    const nbs = snapshot.normalizedBodyShape;
    const nbsKeysVal = validateAllowedKeys(nbs, ['shapeKind', 'topLevelJsonKeys', 'normalizedSchemaHash']);
    if (!nbsKeysVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: nbsKeysVal.message };
    if (!ALLOWED_SHAPE_KINDS.includes(nbs.shapeKind))
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid shapeKind' };
    if (nbs.topLevelJsonKeys !== undefined) {
      if (!Array.isArray(nbs.topLevelJsonKeys))
        return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'topLevelJsonKeys must be an array' };
      if (nbs.topLevelJsonKeys.length > 200)
        return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'topLevelJsonKeys exceeds cap of 200' };
      for (const k of nbs.topLevelJsonKeys) {
        const kv = validateSafeText(k, 100);
        if (!kv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: kv.message };
      }
    }
    if (nbs.normalizedSchemaHash !== undefined) {
      const shv = validateSafeHash(nbs.normalizedSchemaHash);
      if (!shv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: shv.message };
    }
  }

  // redirect (optional)
  if (snapshot.redirect !== undefined) {
    const r = snapshot.redirect;
    const rKeysVal = validateAllowedKeys(r, ['redirected', 'locationOriginHash', 'locationPathTemplate']);
    if (!rKeysVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: rKeysVal.message };
    if (typeof r.redirected !== 'boolean')
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'redirect.redirected must be boolean' };
    if (r.locationOriginHash !== undefined) {
      const lhv = validateSafeHash(r.locationOriginHash);
      if (!lhv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: lhv.message };
    }
    if (r.locationPathTemplate !== undefined) {
      const lpv = validatePathTemplate(r.locationPathTemplate);
      if (!lpv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: lpv.message };
    }
  }

  // authState (optional)
  if (snapshot.authState !== undefined) {
    const as = snapshot.authState;
    const asKeysVal = validateAllowedKeys(as, ['authenticatedSignal', 'authStateHash']);
    if (!asKeysVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: asKeysVal.message };
    if (!ALLOWED_AUTH_STATE_SIGNALS.includes(as.authenticatedSignal))
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid authenticatedSignal' };
    if (as.authStateHash !== undefined) {
      const ahv = validateSafeHash(as.authStateHash);
      if (!ahv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: ahv.message };
    }
  }

  // errorSignals (optional)
  if (snapshot.errorSignals !== undefined) {
    const es = snapshot.errorSignals;
    const esKeysVal = validateAllowedKeys(es, [
      'hasSqlErrorSignal', 'hasStackTraceSignal', 'hasAuthErrorSignal',
      'hasServerErrorSignal', 'signalNames'
    ]);
    if (!esKeysVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: esKeysVal.message };
    for (const boolKey of ['hasSqlErrorSignal', 'hasStackTraceSignal', 'hasAuthErrorSignal', 'hasServerErrorSignal'] as const) {
      if (typeof es[boolKey] !== 'boolean')
        return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: `errorSignals.${boolKey} must be boolean` };
    }
    if (!Array.isArray(es.signalNames))
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'errorSignals.signalNames must be an array' };
    if (es.signalNames.length > 100)
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'signalNames exceeds cap of 100' };
    for (const sn of es.signalNames) {
      if (!ALLOWED_ERROR_SIGNAL_NAMES.includes(sn))
        return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: `Invalid signalName: ${sn}` };
    }
  }

  // safeExcerpt (optional)
  if (snapshot.safeExcerpt !== undefined) {
    const se = snapshot.safeExcerpt;
    const seKeysVal = validateAllowedKeys(se, ['text', 'source', 'redacted']);
    if (!seKeysVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: seKeysVal.message };
    const tv = validateSafeText(se.text, 300);
    if (!tv.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: tv.message };
    if (!ALLOWED_EXCERPT_SOURCES.includes(se.source))
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'Invalid excerpt source' };
    if (se.redacted !== true)
      return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: 'safeExcerpt.redacted must be true' };
  }

  // classification
  const clsVal = validateClassification(snapshot.classification);
  if (!clsVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: clsVal.message };

  return { isValid: true };
}

// ---------------------------------------------------------------------------
// ResponseComparisonRequest validator
// ---------------------------------------------------------------------------

const REQUEST_KEYS = [
  'contractVersion', 'kind', 'comparisonId', 'scanId', 'requestedAt',
  'baseline', 'validation', 'comparisonMode', 'thresholds', 'classification'
] as const;

const THRESHOLD_KEYS = ['contentLengthDeltaPercentSignificant', 'responseTimeDeltaMsSignificant'] as const;

export function validateResponseComparisonRequest(request: any): ValidationResult {
  if (!request || request.kind !== 'response_comparison_request')
    return { isValid: false, errorCode: 'invalid_comparison_request', message: 'Invalid kind' };
  if (request.contractVersion !== RESPONSE_COMPARATOR_CONTRACT_VERSION)
    return { isValid: false, errorCode: 'invalid_comparison_request', message: 'Invalid contractVersion' };

  const keysVal = validateAllowedKeys(request, REQUEST_KEYS);
  if (!keysVal.isValid) return { ...keysVal, errorCode: 'invalid_comparison_request' };

  const idVal = validateSafeId(request.comparisonId);
  if (!idVal.isValid) return { isValid: false, errorCode: 'invalid_comparison_request', message: idVal.message };

  const scanIdVal = validateSafeId(request.scanId);
  if (!scanIdVal.isValid) return { isValid: false, errorCode: 'invalid_comparison_request', message: scanIdVal.message };

  const tsVal = validateIsoTimestamp(request.requestedAt);
  if (!tsVal.isValid) return { isValid: false, errorCode: 'invalid_comparison_request', message: tsVal.message };

  if (!ALLOWED_COMPARISON_MODES.includes(request.comparisonMode))
    return { isValid: false, errorCode: 'invalid_comparison_request', message: 'Invalid comparisonMode' };

  // thresholds
  const thresholdsKeysVal = validateAllowedKeys(request.thresholds, THRESHOLD_KEYS);
  if (!thresholdsKeysVal.isValid)
    return { isValid: false, errorCode: 'invalid_comparison_request', message: thresholdsKeysVal.message };
  const { contentLengthDeltaPercentSignificant: clThresh, responseTimeDeltaMsSignificant: rtThresh } = request.thresholds;
  if (!Number.isFinite(clThresh) || clThresh < 0 || clThresh > 10000)
    return { isValid: false, errorCode: 'invalid_comparison_request', message: 'contentLengthDeltaPercentSignificant must be 0..10000' };
  if (!Number.isFinite(rtThresh) || rtThresh < 0 || rtThresh > 300000)
    return { isValid: false, errorCode: 'invalid_comparison_request', message: 'responseTimeDeltaMsSignificant must be 0..300000' };

  // classification
  const clsVal = validateClassification(request.classification);
  if (!clsVal.isValid) return { isValid: false, errorCode: 'invalid_comparison_request', message: clsVal.message };

  // baseline and validation snapshots
  const baseVal = validateSafeResponseSnapshot(request.baseline);
  if (!baseVal.isValid) return { isValid: false, errorCode: 'invalid_baseline_snapshot', message: baseVal.message };

  const valVal = validateSafeResponseSnapshot(request.validation);
  if (!valVal.isValid) return { isValid: false, errorCode: 'invalid_validation_snapshot', message: valVal.message };

  // role checks
  if (request.baseline.role !== 'baseline')
    return { isValid: false, errorCode: 'snapshot_role_mismatch', message: 'baseline.role must be "baseline"' };
  if (request.validation.role !== 'validation')
    return { isValid: false, errorCode: 'snapshot_role_mismatch', message: 'validation.role must be "validation"' };

  // scanId must match across request/baseline/validation
  if (request.baseline.scanId !== request.scanId || request.validation.scanId !== request.scanId)
    return { isValid: false, errorCode: 'scan_mismatch', message: 'baseline/validation scanId must match request scanId' };

  // subjects must be exactly equal
  if (!subjectsEqual(request.baseline.subject, request.validation.subject))
    return { isValid: false, errorCode: 'subject_mismatch', message: 'baseline and validation subjects must be exactly equal' };

  return { isValid: true };
}

// ---------------------------------------------------------------------------
// Safe array diff helpers
// ---------------------------------------------------------------------------

function safeStringArrayDiff(base: string[], val: string[]): { added: string[]; removed: string[] } {
  const baseSet = new Set(base);
  const valSet = new Set(val);
  const added = [...valSet].filter(s => !baseSet.has(s));
  const removed = [...baseSet].filter(s => !valSet.has(s));
  return { added, removed };
}

// ---------------------------------------------------------------------------
// buildResponseDifference
// ---------------------------------------------------------------------------

export function buildResponseDifference(
  baseline: SafeResponseSnapshot,
  validation: SafeResponseSnapshot,
  thresholds: ComparisonThresholds
): ResponseDifference {
  const statusCodeChanged = baseline.statusCode !== validation.statusCode;

  const clDelta = validation.contentLength - baseline.contentLength;
  const clDeltaPercent = baseline.contentLength === 0
    ? (validation.contentLength === 0 ? 0 : 100)
    : Math.abs(clDelta / baseline.contentLength) * 100;
  const contentLengthChanged = clDelta !== 0;
  const contentLengthSignificant = clDeltaPercent >= thresholds.contentLengthDeltaPercentSignificant;

  const rtDelta = validation.responseTimeMs - baseline.responseTimeMs;
  const responseTimeChanged = rtDelta !== 0;
  const responseTimeSignificant = Math.abs(rtDelta) >= thresholds.responseTimeDeltaMsSignificant;

  const bodyHashChanged = baseline.bodyHash !== validation.bodyHash;

  // headerNames diff
  const headerDiff = safeStringArrayDiff(baseline.headerNames, validation.headerNames);
  const headerNamesAdded = headerDiff.added.slice(0, 100);
  const headerNamesRemoved = headerDiff.removed.slice(0, 100);
  const headersChanged = headerNamesAdded.length > 0 || headerNamesRemoved.length > 0;

  // json keys diff
  const baseJsonKeys = baseline.normalizedBodyShape?.topLevelJsonKeys ?? [];
  const valJsonKeys = validation.normalizedBodyShape?.topLevelJsonKeys ?? [];
  const jsonDiff = safeStringArrayDiff(baseJsonKeys, valJsonKeys);
  const jsonKeysAdded = jsonDiff.added.slice(0, 200);
  const jsonKeysRemoved = jsonDiff.removed.slice(0, 200);
  const jsonShapeChanged =
    jsonKeysAdded.length > 0 || jsonKeysRemoved.length > 0 ||
    (baseline.normalizedBodyShape?.shapeKind !== validation.normalizedBodyShape?.shapeKind);

  // redirect changed
  const redirectChanged = JSON.stringify(baseline.redirect ?? null) !== JSON.stringify(validation.redirect ?? null);

  // authState changed
  const authStateChanged =
    (baseline.authState?.authenticatedSignal ?? 'unknown') !==
    (validation.authState?.authenticatedSignal ?? 'unknown') ||
    (baseline.authState?.authStateHash ?? '') !== (validation.authState?.authStateHash ?? '');

  // error signal observed
  const errorSignalObserved =
    (validation.errorSignals?.hasSqlErrorSignal === true) ||
    (validation.errorSignals?.hasStackTraceSignal === true) ||
    (validation.errorSignals?.hasAuthErrorSignal === true) ||
    (validation.errorSignals?.hasServerErrorSignal === true);

  // signal summary (closed enum only)
  const signalSummary: ResponseDifference['signalSummary'] = [];
  if (statusCodeChanged) signalSummary.push('status_code_changed');
  if (contentLengthChanged) signalSummary.push('content_length_changed');
  if (responseTimeChanged) signalSummary.push('response_time_changed');
  if (bodyHashChanged) signalSummary.push('body_hash_changed');
  if (headersChanged) signalSummary.push('headers_changed');
  if (jsonShapeChanged) signalSummary.push('json_shape_changed');
  if (redirectChanged) signalSummary.push('redirect_changed');
  if (authStateChanged) signalSummary.push('auth_state_changed');
  if (errorSignalObserved) signalSummary.push('error_signal_observed');

  return {
    statusCodeChanged,
    baselineStatusCode: baseline.statusCode,
    validationStatusCode: validation.statusCode,
    contentLengthChanged,
    contentLengthDelta: clDelta,
    contentLengthDeltaPercent: clDeltaPercent,
    contentLengthSignificant,
    responseTimeChanged,
    responseTimeDeltaMs: rtDelta,
    responseTimeSignificant,
    bodyHashChanged,
    headerNamesAdded,
    headerNamesRemoved,
    jsonKeysAdded,
    jsonKeysRemoved,
    redirectChanged,
    authStateChanged,
    errorSignalObserved,
    signalSummary
  };
}

// ---------------------------------------------------------------------------
// deriveComparisonSignificance
// ---------------------------------------------------------------------------

export function deriveComparisonSignificance(
  diff: ResponseDifference,
  mode: string
): ComparisonSignificance {
  const hasAnyDifference = diff.signalSummary.length > 0;

  // Determine strongest signal and signal strength
  // This is comparison signal strength, NOT severity/risk/impact.
  let strongestSignal: ComparisonSignificance['strongestSignal'] = 'none';
  let comparisonSignalStrength: ComparisonSignificance['comparisonSignalStrength'] = 'none';
  let rationale = 'No differences observed.';

  const baseCode = diff.baselineStatusCode ?? 0;
  const valCode = diff.validationStatusCode ?? 0;
  const isAuthBoundary = diff.statusCodeChanged && (
    ((baseCode === 401 || baseCode === 403) && valCode >= 200 && valCode < 300) ||
    ((valCode === 401 || valCode === 403) && baseCode >= 200 && baseCode < 300)
  );

  // Strong signals
  if (diff.authStateChanged) {
    strongestSignal = 'auth_state';
    comparisonSignalStrength = 'strong';
    rationale = 'Authentication state changed between baseline and validation responses.';
  } else if (isAuthBoundary) {
    strongestSignal = 'status_code';
    comparisonSignalStrength = 'strong';
    rationale = 'Status code changed across an authentication boundary.';
  } else if (diff.errorSignalObserved && (valCode >= 500 || diff.signalSummary.includes('error_signal_observed'))) {
    strongestSignal = 'error_signal';
    comparisonSignalStrength = 'strong';
    rationale = 'Error signals observed in validation response.';
  } else if (diff.responseTimeSignificant && mode === 'time_based_difference') {
    strongestSignal = 'response_time';
    comparisonSignalStrength = 'moderate';
    rationale = 'Significant response time difference observed.';
  } else if (diff.statusCodeChanged) {
    strongestSignal = 'status_code';
    comparisonSignalStrength = 'moderate';
    rationale = 'Status code differs between baseline and validation responses.';
  } else if (diff.redirectChanged) {
    strongestSignal = 'redirect';
    comparisonSignalStrength = 'moderate';
    rationale = 'Redirect behavior changed between responses.';
  } else if (diff.bodyHashChanged && diff.contentLengthSignificant) {
    strongestSignal = 'body_hash';
    comparisonSignalStrength = 'moderate';
    rationale = 'Body content and length differ significantly.';
  } else if (diff.jsonKeysAdded.length > 0 || diff.jsonKeysRemoved.length > 0) {
    strongestSignal = 'json_shape';
    comparisonSignalStrength = 'moderate';
    rationale = 'JSON structure differs between responses.';
  } else if (diff.responseTimeSignificant) {
    // time significant but not time_based mode -> weak
    strongestSignal = 'response_time';
    comparisonSignalStrength = 'weak';
    rationale = 'Response time difference observed.';
  } else if (diff.bodyHashChanged) {
    strongestSignal = 'body_hash';
    comparisonSignalStrength = 'weak';
    rationale = 'Body hash differs; content length difference is not significant.';
  } else if (diff.headerNamesAdded.length > 0 || diff.headerNamesRemoved.length > 0) {
    strongestSignal = 'headers';
    comparisonSignalStrength = 'weak';
    rationale = 'Header names differ between responses.';
  } else if (diff.contentLengthChanged) {
    strongestSignal = 'content_length';
    comparisonSignalStrength = 'weak';
    rationale = 'Content length differs between responses.';
  }

  const hasSignificantDifference = comparisonSignalStrength === 'strong' || comparisonSignalStrength === 'moderate';

  return {
    hasAnyDifference,
    hasSignificantDifference,
    strongestSignal,
    comparisonSignalStrength,
    rationale
  };
}

// ---------------------------------------------------------------------------
// deriveEvidenceMappingHint
// ---------------------------------------------------------------------------

export function deriveEvidenceMappingHint(
  diff: ResponseDifference,
  significance: ComparisonSignificance,
  mode: string
): EvidenceMappingHint {
  let suggestedEvidenceType: EvidenceMappingHint['suggestedEvidenceType'];

  // authorization_difference: mode OR authStateChanged
  if (mode === 'authorization_difference' || diff.authStateChanged) {
    suggestedEvidenceType = 'authorization_difference';
  } else if (mode === 'time_based_difference' && diff.responseTimeSignificant) {
    // time_based_difference ONLY when explicitly in time mode AND responseTimeSignificant
    // Generic http mode + responseTimeSignificant -> http_difference (not time_based_difference)
    suggestedEvidenceType = 'time_based_difference';
  } else {
    suggestedEvidenceType = 'http_difference';
  }

  const suggestedSignalStrength: EvidenceMappingHint['suggestedSignalStrength'] =
    significance.comparisonSignalStrength === 'strong' ? 'strong'
    : significance.comparisonSignalStrength === 'moderate' ? 'moderate'
    : 'weak';

  return {
    suggestedEvidenceType,
    suggestedSignalStrength,
    requiresHumanReview: true,
    notPersistedEvidence: true
  };
}

// ---------------------------------------------------------------------------
// Safe failed result builder
// ---------------------------------------------------------------------------

function buildFailedResult(
  safeComparisonId: string,
  safeScanId: string,
  safeComparedAt: string,
  safeBaselineSnapshotId: string,
  safeValidationSnapshotId: string,
  errorCode: ComparatorErrorCode,
  safeMessage: string
): ResponseComparisonResult {
  return {
    contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
    kind: 'response_comparison_result',
    comparisonId: safeComparisonId,
    scanId: safeScanId,
    comparedAt: safeComparedAt,
    status: 'failed',
    baselineSnapshotId: safeBaselineSnapshotId,
    validationSnapshotId: safeValidationSnapshotId,
    difference: null,
    significance: null,
    evidenceMappingHint: null,
    explicitNonClaims: getSafeNonClaims(),
    classification: getSafeClassification(),
    error: { code: errorCode, safeMessage }
  };
}

// ---------------------------------------------------------------------------
// compareResponses
// ---------------------------------------------------------------------------

export function compareResponses(
  request: any,
  comparedAt: string
): ResponseComparisonResult {
  // Sanitize metadata before anything else — never echo unsafe values
  const safeComparedAt = validateIsoTimestamp(comparedAt).isValid ? comparedAt : SENTINEL_EVALUATED_AT;
  const safeComparisonId = safeIdOrSentinel(request?.comparisonId, SENTINEL_COMPARISON_ID);
  const safeScanId = safeIdOrSentinel(request?.scanId, SENTINEL_SCAN_ID);
  const safeBaselineSnapshotId = safeIdOrSentinel(request?.baseline?.snapshotId, SENTINEL_SNAPSHOT_ID);
  const safeValidationSnapshotId = safeIdOrSentinel(request?.validation?.snapshotId, SENTINEL_SNAPSHOT_ID);

  // If core metadata is invalid, fail immediately
  if (safeComparedAt === SENTINEL_EVALUATED_AT) {
    return buildFailedResult(
      safeComparisonId, safeScanId, SENTINEL_EVALUATED_AT,
      safeBaselineSnapshotId, safeValidationSnapshotId,
      'invalid_comparison_metadata',
      'comparedAt is not a valid ISO timestamp.'
    );
  }
  if (safeComparisonId === SENTINEL_COMPARISON_ID) {
    return buildFailedResult(
      SENTINEL_COMPARISON_ID, safeScanId, safeComparedAt,
      safeBaselineSnapshotId, safeValidationSnapshotId,
      'invalid_comparison_metadata',
      'comparisonId is invalid or contains unsafe content.'
    );
  }

  // Validate full request
  const reqVal = validateResponseComparisonRequest(request);
  if (!reqVal.isValid) {
    const errorCode = (ALLOWED_COMPARATOR_ERROR_CODES.includes(reqVal.errorCode as any)
      ? reqVal.errorCode
      : 'invalid_comparison_request') as ComparatorErrorCode;
    return buildFailedResult(
      safeComparisonId, safeScanId, safeComparedAt,
      safeBaselineSnapshotId, safeValidationSnapshotId,
      errorCode,
      'Request validation failed.'
    );
  }

  // All validated — compute comparison
  try {
    const diff = buildResponseDifference(request.baseline, request.validation, request.thresholds);
    const significance = deriveComparisonSignificance(diff, request.comparisonMode);
    const hint = deriveEvidenceMappingHint(diff, significance, request.comparisonMode);

    return {
      contractVersion: RESPONSE_COMPARATOR_CONTRACT_VERSION,
      kind: 'response_comparison_result',
      comparisonId: safeComparisonId,
      scanId: safeScanId,
      comparedAt: safeComparedAt,
      status: 'completed',
      baselineSnapshotId: safeBaselineSnapshotId,
      validationSnapshotId: safeValidationSnapshotId,
      difference: diff,
      significance,
      evidenceMappingHint: hint,
      explicitNonClaims: getSafeNonClaims(),
      classification: getSafeClassification()
    };
  } catch {
    return buildFailedResult(
      safeComparisonId, safeScanId, safeComparedAt,
      safeBaselineSnapshotId, safeValidationSnapshotId,
      'unexpected_comparator_failure',
      'An unexpected error occurred during comparison.'
    );
  }
}
