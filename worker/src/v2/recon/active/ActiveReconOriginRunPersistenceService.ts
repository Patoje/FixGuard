import {
  type ActiveReconOriginRunResult,
  deriveActiveReconRunStatus
} from './ActiveReconOriginRunContracts.js';
import type {
  PersistedActiveReconRunRecord,
  PersistedActiveReconRunItem,
  PersistedActiveReconRunError,
  PersistedDocumentProbeRunItem,
  PersistedActiveReconRecordValidationResult,
  ActiveReconPersistedRecordVersion,
  ActiveReconPersistedRecordKind
} from './ActiveReconOriginRunPersistenceContracts.js';
import type { SafeActiveReconObservation, SafeRobotsTxtMetadata, SafeSecurityTxtMetadata } from './ActiveReconContracts.js';
import type { ActiveReconRunRepository } from './ActiveReconOriginRunRepository.js';

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expectedKeys: readonly string[]): boolean {
  const actualKeys = Object.keys(value);
  if (actualKeys.length !== expectedKeys.length) return false;
  for (const key of actualKeys) {
    if (!expectedKeys.includes(key)) return false;
  }
  return true;
}

function validateSafeId(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed !== value) return null;
  if (trimmed.length > 255) return null; // Safe max length
  return trimmed;
}

function validateCanonicalIsoTimestamp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  const canonical = new Date(milliseconds).toISOString();
  if (canonical !== value) return null;
  return value;
}

function validateError(value: unknown): PersistedActiveReconRunError | null {
  if (!isRecord(value)) return null;
  if (!hasExactKeys(value, ['code', 'message'])) return null;

  if (typeof value.code !== 'string') return null;

  const ALLOWED_ERROR_CODES = [
    'authorization_not_confirmed',
    'invalid_origin',
    'origin_out_of_scope',
    'unsupported_probe',
    'empty_probe_set',
    'planning_failed',
    'runner_failed',
    'adapter_missing',
    'adapter_failed',
    'policy_blocked',
    'policy_candidate',
    'persistence_validation_failed'
  ] as const;

  if (!(ALLOWED_ERROR_CODES as readonly string[]).includes(value.code)) return null;
  if (typeof value.message !== 'string') return null;

  return {
    code: value.code as PersistedActiveReconRunError['code'],
    message: value.message
  };
}

function validateRunErrors(value: unknown): PersistedActiveReconRunError[] | null {
  if (!Array.isArray(value)) return null;
  const validated: PersistedActiveReconRunError[] = [];
  for (const err of value) {
    const v = validateError(err);
    if (!v) return null;
    validated.push(v);
  }
  return validated;
}

function validateCanonicalHttpOrigin(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  if (parsed.username !== '' || parsed.password !== '') return null;
  if (parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== '') return null;
  if (parsed.origin !== value) return null;
  return value;
}

function validateSubject(value: unknown): { kind: 'origin'; normalizedOrigin?: string } | null {
  if (!isRecord(value)) return null;
  const keys = Object.keys(value);
  if (keys.length < 1 || keys.length > 2) return null;
  if (!keys.includes('kind')) return null;

  if (value.kind !== 'origin') return null;
  if (keys.length === 2 && !keys.includes('normalizedOrigin')) return null;

  if ('normalizedOrigin' in value) {
    const origin = validateCanonicalHttpOrigin(value.normalizedOrigin);
    if (!origin) return null;
    return { kind: 'origin', normalizedOrigin: origin };
  }

  return { kind: 'origin' };
}

function derivePersistedCountsFromItems(
  items: readonly PersistedDocumentProbeRunItem[]
): {
  planned: number;
  completed: number;
  blocked: number;
  candidate: number;
  failed: number;
} {
  let planned = items.length;
  let completed = 0;
  let blocked = 0;
  let candidate = 0;
  let failed = 0;

  for (const item of items) {
    if (item.status === 'completed') completed++;
    else if (item.status === 'blocked') blocked++;
    else if (item.status === 'candidate') candidate++;
    else if (item.status === 'failed') failed++;
  }

  return { planned, completed, blocked, candidate, failed };
}

function validatePersistedRunSemantics(
  status: 'completed' | 'partial' | 'failed',
  counts: {
    requested: number;
    planned: number;
    completed: number;
    blocked: number;
    candidate: number;
    failed: number;
  },
  items: readonly PersistedDocumentProbeRunItem[],
  observations: readonly SafeActiveReconObservation[],
  runErrors: readonly PersistedActiveReconRunError[]
): { valid: boolean; message?: string } {
  // 1. requested count is consistent with item count
  if (counts.requested < counts.planned) return { valid: false, message: 'requested count is less than planned count' };

  // 2. Derive expected counts
  const derived = derivePersistedCountsFromItems(items);
  if (counts.planned !== items.length) return { valid: false, message: 'planned count differs from item count' };
  if (counts.planned !== derived.planned) return { valid: false, message: 'planned count differs from derived planned count' };
  if (counts.completed !== derived.completed) return { valid: false, message: 'completed count differs from completed items' };
  if (counts.blocked !== derived.blocked) return { valid: false, message: 'blocked count differs from blocked items' };
  if (counts.candidate !== derived.candidate) return { valid: false, message: 'candidate count differs from candidate items' };
  if (counts.failed !== derived.failed) return { valid: false, message: 'failed count differs from failed items' };

  // 3. Observations exactly equal ordered aggregation
  const aggregatedObservations: SafeActiveReconObservation[] = [];
  for (const item of items) {
    aggregatedObservations.push(...item.observations);
  }

  if (observations.length !== aggregatedObservations.length) return { valid: false, message: 'top-level observations count differs from aggregated item observations' };

  // Note: we'll do a simple deep equality string check for the ordered observations array since we already validated them structurally
  if (JSON.stringify(observations) !== JSON.stringify(aggregatedObservations)) {
    return { valid: false, message: 'top-level observations differ from ordered aggregated item observations' };
  }

  // 4. Overall status compatibility matches M39 derivation exactly
  const expectedStatus = deriveActiveReconRunStatus(counts.planned, counts.completed);
  if (status !== expectedStatus) {
    return { valid: false, message: `derived status ${expectedStatus} does not match provided status ${status}` };
  }

  // If status is completed, there should be no failed items or run errors
  if (status === 'completed') {
    if (counts.blocked > 0 || counts.candidate > 0 || counts.failed > 0 || runErrors.length > 0) return { valid: false, message: 'completed run with incompatible failed items/errors' };
  }
  // If status is failed, there must be failed items or run errors, or it was completely blocked
  if (status === 'failed') {
    if (counts.failed === 0 && runErrors.length === 0 && counts.blocked === 0 && counts.candidate === 0) return { valid: false, message: 'failed run with semantically contradictory terminal counts' };
  }

  return { valid: true };
}

function validateCountsShape(value: unknown): {
  requested: number;
  planned: number;
  completed: number;
  blocked: number;
  candidate: number;
  failed: number;
} | null {
  if (!isRecord(value)) return null;
  if (!hasExactKeys(value, ['requested', 'planned', 'completed', 'blocked', 'candidate', 'failed'])) return null;

  const fields = ['requested', 'planned', 'completed', 'blocked', 'candidate', 'failed'] as const;
  for (const field of fields) {
    if (typeof value[field] !== 'number' || !Number.isInteger(value[field]) || (value[field] as number) < 0) return null;
  }

  return {
    requested: value.requested as number,
    planned: value.planned as number,
    completed: value.completed as number,
    blocked: value.blocked as number,
    candidate: value.candidate as number,
    failed: value.failed as number,
  };
}

function validateClassification(value: unknown): { finding: false; evidence: false; vulnerability: false; riskClaim: false } | null {
  if (!isRecord(value)) return null;
  if (!hasExactKeys(value, ['finding', 'evidence', 'vulnerability', 'riskClaim'])) return null;

  if (value.finding !== false) return null;
  if (value.evidence !== false) return null;
  if (value.vulnerability !== false) return null;
  if (value.riskClaim !== false) return null;

  return { finding: false, evidence: false, vulnerability: false, riskClaim: false };
}

function validateRobotsMetadata(value: unknown): SafeRobotsTxtMetadata | null {
  if (!isRecord(value)) return null;
  const allowed = ['reachable', 'contentTypeLookedTextLike', 'recognizedDirectiveLineCount', 'hasUserAgentDirective', 'hasDisallowDirective', 'hasAllowDirective', 'hasSitemapDirective', 'bodyTruncated'];
  const actual = Object.keys(value);
  for (const k of actual) {
    if (!allowed.includes(k)) return null;
  }

  const m: SafeRobotsTxtMetadata = {};
  if ('reachable' in value) { if (typeof value.reachable !== 'boolean') return null; m.reachable = value.reachable; }
  if ('contentTypeLookedTextLike' in value) { if (typeof value.contentTypeLookedTextLike !== 'boolean') return null; m.contentTypeLookedTextLike = value.contentTypeLookedTextLike; }
  if ('recognizedDirectiveLineCount' in value) { if (typeof value.recognizedDirectiveLineCount !== 'number') return null; m.recognizedDirectiveLineCount = value.recognizedDirectiveLineCount; }
  if ('hasUserAgentDirective' in value) { if (typeof value.hasUserAgentDirective !== 'boolean') return null; m.hasUserAgentDirective = value.hasUserAgentDirective; }
  if ('hasDisallowDirective' in value) { if (typeof value.hasDisallowDirective !== 'boolean') return null; m.hasDisallowDirective = value.hasDisallowDirective; }
  if ('hasAllowDirective' in value) { if (typeof value.hasAllowDirective !== 'boolean') return null; m.hasAllowDirective = value.hasAllowDirective; }
  if ('hasSitemapDirective' in value) { if (typeof value.hasSitemapDirective !== 'boolean') return null; m.hasSitemapDirective = value.hasSitemapDirective; }
  if ('bodyTruncated' in value) { if (typeof value.bodyTruncated !== 'boolean') return null; m.bodyTruncated = value.bodyTruncated; }

  return m;
}

function validateSecurityTxtMetadata(value: unknown): SafeSecurityTxtMetadata | null {
  if (!isRecord(value)) return null;
  const allowed = ['reachable', 'contentTypeLookedTextLike', 'recognizedFieldLineCount', 'hasContactField', 'hasExpiresField', 'hasEncryptionField', 'hasAcknowledgmentsField', 'hasPreferredLanguagesField', 'hasCanonicalField', 'hasPolicyField', 'bodyTruncated'];
  const actual = Object.keys(value);
  for (const k of actual) {
    if (!allowed.includes(k)) return null;
  }

  const m: SafeSecurityTxtMetadata = {};
  if ('reachable' in value) { if (typeof value.reachable !== 'boolean') return null; m.reachable = value.reachable; }
  if ('contentTypeLookedTextLike' in value) { if (typeof value.contentTypeLookedTextLike !== 'boolean') return null; m.contentTypeLookedTextLike = value.contentTypeLookedTextLike; }
  if ('recognizedFieldLineCount' in value) { if (typeof value.recognizedFieldLineCount !== 'number') return null; m.recognizedFieldLineCount = value.recognizedFieldLineCount; }
  if ('hasContactField' in value) { if (typeof value.hasContactField !== 'boolean') return null; m.hasContactField = value.hasContactField; }
  if ('hasExpiresField' in value) { if (typeof value.hasExpiresField !== 'boolean') return null; m.hasExpiresField = value.hasExpiresField; }
  if ('hasEncryptionField' in value) { if (typeof value.hasEncryptionField !== 'boolean') return null; m.hasEncryptionField = value.hasEncryptionField; }
  if ('hasAcknowledgmentsField' in value) { if (typeof value.hasAcknowledgmentsField !== 'boolean') return null; m.hasAcknowledgmentsField = value.hasAcknowledgmentsField; }
  if ('hasPreferredLanguagesField' in value) { if (typeof value.hasPreferredLanguagesField !== 'boolean') return null; m.hasPreferredLanguagesField = value.hasPreferredLanguagesField; }
  if ('hasCanonicalField' in value) { if (typeof value.hasCanonicalField !== 'boolean') return null; m.hasCanonicalField = value.hasCanonicalField; }
  if ('hasPolicyField' in value) { if (typeof value.hasPolicyField !== 'boolean') return null; m.hasPolicyField = value.hasPolicyField; }
  if ('bodyTruncated' in value) { if (typeof value.bodyTruncated !== 'boolean') return null; m.bodyTruncated = value.bodyTruncated; }

  return m;
}

function validateObservation(value: unknown): SafeActiveReconObservation | null {
  if (!isRecord(value)) return null;

  const hasMeta = 'metadata' in value;
  if (hasMeta) {
    if (!hasExactKeys(value, ['kind', 'safeSummary', 'confidence', 'metadata'])) return null;
  } else {
    if (!hasExactKeys(value, ['kind', 'safeSummary', 'confidence'])) return null;
  }

  if (value.kind !== 'robots_metadata' && value.kind !== 'security_txt_metadata') return null;
  if (typeof value.safeSummary !== 'string') return null;
  if (value.confidence !== 'low' && value.confidence !== 'medium' && value.confidence !== 'high') return null;

  if (value.kind === 'robots_metadata') {
    const meta = hasMeta ? validateRobotsMetadata(value.metadata) : undefined;
    if (hasMeta && !meta) return null;
    if (hasMeta && meta) {
      return {
        kind: 'robots_metadata',
        safeSummary: value.safeSummary,
        confidence: value.confidence,
        metadata: meta
      };
    }
    return {
      kind: 'robots_metadata',
      safeSummary: value.safeSummary,
      confidence: value.confidence
    };
  } else {
    const meta = hasMeta ? validateSecurityTxtMetadata(value.metadata) : undefined;
    if (hasMeta && !meta) return null;
    if (hasMeta && meta) {
      return {
        kind: 'security_txt_metadata',
        safeSummary: value.safeSummary,
        confidence: value.confidence,
        metadata: meta
      };
    }
    return {
      kind: 'security_txt_metadata',
      safeSummary: value.safeSummary,
      confidence: value.confidence
    };
  }
}

function validateObservations(value: unknown): SafeActiveReconObservation[] | null {
  if (!Array.isArray(value)) return null;
  const validated: SafeActiveReconObservation[] = [];
  for (const obs of value) {
    const v = validateObservation(obs);
    if (!v) return null;
    validated.push(v);
  }
  return validated;
}
function validateItemTarget(value: unknown): { normalizedOrigin?: string; safeDisplayUrl?: string } | null {
  if (!isRecord(value)) return null;
  const actual = Object.keys(value);
  for (const k of actual) {
    if (k !== 'normalizedOrigin' && k !== 'safeDisplayUrl') return null;
  }
  const t: { normalizedOrigin?: string; safeDisplayUrl?: string } = {};
  if ('normalizedOrigin' in value && value.normalizedOrigin !== undefined) {
    if (typeof value.normalizedOrigin !== 'string') return null;
    t.normalizedOrigin = value.normalizedOrigin;
  }
  if ('safeDisplayUrl' in value && value.safeDisplayUrl !== undefined) {
    if (typeof value.safeDisplayUrl !== 'string') return null;
    t.safeDisplayUrl = value.safeDisplayUrl;
  }
  return t;
}
function validateItem(value: unknown): PersistedDocumentProbeRunItem | null {
  if (!isRecord(value)) return null;

  const hasError = 'error' in value;
  const expectedKeys = ['itemVersion', 'family', 'safeProbeIndex', 'safeKind', 'status', 'target', 'observations'];
  if (hasError) expectedKeys.push('error');

  if (!hasExactKeys(value, expectedKeys)) return null;

  if (value.itemVersion !== 'active-recon-document-probe-item/v0') return null;
  if (value.family !== 'document') return null;

  const safeProbeIndex = validateSafeId(value.safeProbeIndex);
  if (!safeProbeIndex) return null;

  if (value.safeKind !== 'http.robots.inspect' && value.safeKind !== 'http.security_txt.inspect' && value.safeKind !== 'unknown') return null;
  if (value.status !== 'completed' && value.status !== 'blocked' && value.status !== 'candidate' && value.status !== 'failed') return null;

  const target = validateItemTarget(value.target);
  if (!target) return null;

  const observations = validateObservations(value.observations);
  if (!observations) return null;

  let error: PersistedActiveReconRunError | undefined = undefined;
  if (hasError) {
    const err = validateError(value.error);
    if (!err) return null;
    error = err;
  }

  return {
    itemVersion: 'active-recon-document-probe-item/v0',
    family: 'document',
    safeProbeIndex,
    safeKind: value.safeKind,
    status: value.status,
    target,
    observations,
    ...(hasError ? { error } : {})
  };
}

function validateItems(value: unknown): PersistedDocumentProbeRunItem[] | null {
  if (!Array.isArray(value)) return null;
  const validated: PersistedDocumentProbeRunItem[] = [];
  for (const item of value) {
    const v = validateItem(item);
    if (!v) return null;
    validated.push(v);
  }
  return validated;
}

const UNSAFE_KEYS = [
  '"targetUrl"', '"raw"', '"headers"', '"body"', '"request"', '"response"', '"payload"',
  '"cookie"', '"authorization"', '"password"', '"api_key"', '"apikey"', '"secret"',
  '"token"', '"severity"', '"impact"', '"exploit"',
  '"finding":true', '"evidence":true', '"riskClaim":true', '"vulnerability":true',
];

const DENY_PATTERNS = [
  'SECRET', 'SUPER_SECRET', 'token=', 'api_key=', 'apikey=', 'password=', 'passwd=',
  'authorization:', 'authorization=', 'bearer ', 'cookie:', 'cookie=', 'set-cookie:',
  'x-api-key', 'private_key', 'access_token', 'refresh_token', 'client_secret',
  '?token=', '&token=', '?api_key=', '&api_key=', '?apikey=', '&apikey=', '?password=', '&password='
];

function checkStringSafety(value: unknown): boolean {
  let hasUnsafeString = false;
  function walk(obj: unknown) {
    if (hasUnsafeString) return;
    if (typeof obj === 'string') {
      const lower = obj.toLowerCase();
      for (const pattern of DENY_PATTERNS) {
        if (lower.includes(pattern.toLowerCase())) {
          hasUnsafeString = true;
          return;
        }
      }
    } else if (Array.isArray(obj)) {
      obj.forEach(walk);
    } else if (obj && typeof obj === 'object') {
      for (const key of Object.keys(obj as Record<string, unknown>)) {
        walk((obj as Record<string, unknown>)[key]);
      }
    }
  }
  walk(value);
  return !hasUnsafeString;
}

export function validatePersistedActiveReconRecord(value: unknown): PersistedActiveReconRecordValidationResult {
  if (!isRecord(value)) {
    return { status: 'invalid', reasonCode: 'unknown_record_format', message: 'Not an object' };
  }

  const expectedCommon = [
    'recordVersion', 'recordKind', 'runId', 'subject', 'status', 'counts',
    'items', 'observations', 'runErrors', 'classification', 'provenance',
    'createdAt', 'updatedAt'
  ];

  if (!hasExactKeys(value, expectedCommon)) {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Unknown or missing top-level keys' };
  }

  const serialized = JSON.stringify(value);
  for (const key of UNSAFE_KEYS) {
    if (key.includes(':true')) {
      if (serialized.includes(key)) {
        return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Unsafe active recon classification claim' };
      }
    } else if (serialized.includes(`"${key.replace(/"/g, '')}"`)) {
      return { status: 'invalid', reasonCode: 'invalid_record_structure', message: `contains unsafe key ${key.replace(/"/g, '')}` };
    }
  }

  if (serialized.includes('requestId') || serialized.includes('planId') || serialized.includes('probeId')) {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Contains forbidden ID field' };
  }

  if (!checkStringSafety(value)) {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Unsafe string value rejected before persistence.' };
  }

  const recordVersion = value.recordVersion;
  if (recordVersion !== 'active-recon-origin-run-record/v0' && recordVersion !== 'active-recon-origin-run-record/v1') {
    return { status: 'invalid', reasonCode: 'unknown_record_format', message: 'Unknown recordVersion' };
  }

  if (value.recordKind !== 'active-recon.origin-run') {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid recordKind' };
  }

  const runId = validateSafeId(value.runId);
  if (!runId) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid runId' };

  const status = value.status;
  if (status !== 'completed' && status !== 'partial' && status !== 'failed') {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid status' };
  }

  const subject = validateSubject(value.subject);
  if (!subject) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid subject' };

  const items = validateItems(value.items);
  if (!items) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid items or unsupported item family/error code' };

  const counts = validateCountsShape(value.counts);
  if (!counts) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid counts' };

  const observations = validateObservations(value.observations);
  if (!observations) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid observations' };

  const runErrors = validateRunErrors(value.runErrors);
  if (!runErrors) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid run errors' };

  const semanticCheck = validatePersistedRunSemantics(status as 'completed' | 'partial' | 'failed', counts, items, observations, runErrors);
  if (!semanticCheck.valid) {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: semanticCheck.message || 'Semantic mismatch' };
  }

  const classification = validateClassification(value.classification);
  if (!classification) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid classification' };

  const createdAt = validateCanonicalIsoTimestamp(value.createdAt);
  const updatedAt = validateCanonicalIsoTimestamp(value.updatedAt);
  if (!createdAt || !updatedAt) return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'Invalid timestamps' };

  if (new Date(createdAt).getTime() > new Date(updatedAt).getTime()) {
    return { status: 'invalid', reasonCode: 'invalid_record_structure', message: 'createdAt after updatedAt' };
  }

  const provenance = value.provenance;
  if (!isRecord(provenance)) {
    return { status: 'invalid', reasonCode: 'missing_provenance', message: 'Missing provenance object' };
  }

  if (recordVersion === 'active-recon-origin-run-record/v0') {
    if (!hasExactKeys(provenance, ['sourceBoundary', 'sourceContractVersion', 'persistedBy'])) {
      if ('authorizationSource' in provenance || 'assessmentId' in provenance || 'scanId' in provenance || 'authorizationGrantId' in provenance || 'authorizationDecisionId' in provenance || 'actorId' in provenance) {
        return { status: 'invalid', reasonCode: 'v1_provenance_on_v0', message: 'V0 record must not contain V1 provenance fields' };
      }
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid V0 provenance shape' };
    }
    if (provenance.sourceBoundary !== 'M39' || provenance.persistedBy !== 'M40') {
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid sourceBoundary or persistedBy' };
    }
    if (provenance.sourceContractVersion === 'active-recon-origin-run/v1') {
      return { status: 'invalid', reasonCode: 'v1_provenance_on_v0', message: 'V0 record cannot have V1 provenance' };
    }
    if (provenance.sourceContractVersion !== 'active-recon-origin-run/v0') {
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid provenance version' };
    }

    const validatedV0Record: PersistedActiveReconRunRecord = {
      recordVersion: 'active-recon-origin-run-record/v0',
      recordKind: 'active-recon.origin-run',
      runId,
      subject,
      status: status as 'completed' | 'partial' | 'failed',
      counts,
      items,
      observations,
      runErrors,
      classification,
      provenance: {
        sourceBoundary: 'M39',
        sourceContractVersion: 'active-recon-origin-run/v0',
        persistedBy: 'M40'
      },
      createdAt,
      updatedAt
    };
    return { status: 'valid_v0_legacy', record: validatedV0Record };
  }

  if (recordVersion === 'active-recon-origin-run-record/v1') {
    if (!hasExactKeys(provenance, ['sourceBoundary', 'sourceContractVersion', 'persistedBy', 'authorizationSource', 'authorizationDecisionId', 'authorizationGrantId', 'assessmentId', 'scanId', 'actorId'])) {
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid V1 provenance shape' };
    }
    if (provenance.sourceBoundary !== 'M39' || provenance.persistedBy !== 'M40') {
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid sourceBoundary or persistedBy' };
    }
    if (provenance.sourceContractVersion === 'active-recon-origin-run/v0') {
      return { status: 'invalid', reasonCode: 'legacy_provenance_on_v1', message: 'V1 record cannot have V0 provenance' };
    }
    if (provenance.sourceContractVersion !== 'active-recon-origin-run/v1') {
      return { status: 'invalid', reasonCode: 'invalid_provenance_shape', message: 'Invalid provenance version' };
    }
    if (provenance.authorizationSource !== 'fixguard-verified-authorization-decision/v0') {
      return { status: 'invalid', reasonCode: 'wrong_authorization_source', message: 'Invalid authorizationSource' };
    }

    const requiredIds = ['assessmentId', 'scanId', 'authorizationGrantId', 'authorizationDecisionId', 'actorId'] as const;
    const validatedIds: Record<string, string> = {};
    for (const idField of requiredIds) {
      const val = validateSafeId(provenance[idField]);
      if (!val) {
        if (!provenance[idField]) {
           if (idField === 'scanId') return { status: 'invalid', reasonCode: 'missing_scan_id', message: 'V1 provenance missing scanId' };
        }
        return { status: 'invalid', reasonCode: 'empty_provenance_id', message: `Missing or empty ID: ${idField}` };
      }
      validatedIds[idField] = val;
    }

    const validatedV1Record: PersistedActiveReconRunRecord = {
      recordVersion: 'active-recon-origin-run-record/v1',
      recordKind: 'active-recon.origin-run',
      runId,
      subject,
      status: status as 'completed' | 'partial' | 'failed',
      counts,
      items,
      observations,
      runErrors,
      classification,
      provenance: {
        sourceBoundary: 'M39',
        sourceContractVersion: 'active-recon-origin-run/v1',
        persistedBy: 'M40',
        authorizationSource: 'fixguard-verified-authorization-decision/v0',
        authorizationDecisionId: validatedIds.authorizationDecisionId,
        authorizationGrantId: validatedIds.authorizationGrantId,
        assessmentId: validatedIds.assessmentId,
        scanId: validatedIds.scanId,
        actorId: validatedIds.actorId
      },
      createdAt,
      updatedAt
    };
    return { status: 'valid_v1', record: validatedV1Record };
  }

  return { status: 'invalid', reasonCode: 'unknown_record_format', message: 'Unknown recordVersion' };
}

export function constructActiveReconOriginRunRecord(
  result: ActiveReconOriginRunResult,
  authorizationLineageProvenance?: {
    authorizationDecisionId: string;
    authorizationGrantId: string;
    assessmentId: string;
    scanId: string;
    actorId: string;
  }
): PersistedActiveReconRunRecord {
  if (
    result.classification?.finding !== false ||
    result.classification?.evidence !== false ||
    result.classification?.vulnerability !== false ||
    result.classification?.riskClaim !== false
  ) {
    throw new Error('Unsafe active recon classification claim.');
  }
  const now = new Date().toISOString();

  const items: PersistedActiveReconRunItem[] = result.probes.map(p => {
    let error: PersistedActiveReconRunError | undefined = undefined;
    if (p.error) {
      const v = validateError(p.error);
      if (!v) throw new Error('Invalid error code');
      error = v;
    }

    return {
      itemVersion: 'active-recon-document-probe-item/v0',
      family: p.family as 'document',
      safeProbeIndex: p.safeProbeIndex,
      safeKind: p.safeKind,
      status: p.status === 'planned' ? 'failed' : p.status,
      target: {
        ...(p.target?.normalizedOrigin ? { normalizedOrigin: p.target.normalizedOrigin } : {}),
        ...(p.target?.safeDisplayUrl ? { safeDisplayUrl: p.target.safeDisplayUrl } : {}),
      },
      observations: p.observations,
      ...(error ? { error } : {})
    };
  });

  const provenance = authorizationLineageProvenance
    ? {
        sourceBoundary: 'M39' as const,
        sourceContractVersion: 'active-recon-origin-run/v1' as const,
        persistedBy: 'M40' as const,
        authorizationSource: 'fixguard-verified-authorization-decision/v0' as const,
        authorizationDecisionId: authorizationLineageProvenance.authorizationDecisionId,
        authorizationGrantId: authorizationLineageProvenance.authorizationGrantId,
        assessmentId: authorizationLineageProvenance.assessmentId,
        scanId: authorizationLineageProvenance.scanId,
        actorId: authorizationLineageProvenance.actorId,
      }
    : {
        sourceBoundary: 'M39' as const,
        sourceContractVersion: 'active-recon-origin-run/v0' as const,
        persistedBy: 'M40' as const,
      };

  const recordVersion = authorizationLineageProvenance
    ? 'active-recon-origin-run-record/v1' as const
    : 'active-recon-origin-run-record/v0' as const;

  const record = {
    recordVersion,
    recordKind: 'active-recon.origin-run' as const,
    runId: result.runId,
    subject: {
      kind: 'origin' as const,
      ...(result.normalizedOrigin ? { normalizedOrigin: result.normalizedOrigin } : {}),
    },
    status: result.status,
    counts: {
      requested: result.requestedProbeCount,
      planned: result.plannedProbeCount,
      completed: result.completedProbeCount,
      blocked: result.blockedProbeCount,
      candidate: result.candidateProbeCount,
      failed: result.failedProbeCount,
    },
    items,
    observations: result.observations,
    runErrors: (result.runErrors || []).map(e => {
      const v = validateError(e);
      if (!v) throw new Error('Invalid error code');
      return v;
    }),
    classification: { finding: false as const, evidence: false as const, vulnerability: false as const, riskClaim: false as const },
    provenance,
    createdAt: now,
    updatedAt: now,
  };

  if (!checkStringSafety(record)) {
    throw new Error('Unsafe string value rejected before persistence.');
  }

  const validationResult = validatePersistedActiveReconRecord(record);
  if (validationResult.status === 'invalid') {
    throw new Error(`Persistence validation failed: ${validationResult.message}`);
  }

  return validationResult.record;
}

/**
 * @deprecated Use validatePersistedActiveReconRecord instead. This exists solely to satisfy unmodified Postgres repositories.
 */
export function validatePersistedActiveReconRunRecord(record: PersistedActiveReconRunRecord): void {
  const result = validatePersistedActiveReconRecord(record);
  if (result.status === 'invalid') {
    if (result.message.includes('Unsafe string value rejected before persistence') ||
        result.message.includes('Invalid error code') ||
        result.message.includes('Unsafe active recon classification claim') ||
        result.message.includes('contains unsafe key') ||
        result.message.includes('unsupported item family')) {
      throw new Error(result.message);
    }
    throw new Error(`Persistence validation failed: ${result.message}`);
  }
}
