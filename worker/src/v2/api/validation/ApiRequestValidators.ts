import { ApiValidationError } from '../ApiErrors.js';
import type { CreateAssessmentCommand } from '../../application/ApplicationDtos.js';
import {
  type GenerateDefensiveReportCommand,
  isStrictSafeId
} from '../../reporting-boundary/DefensiveReportContracts.js';

function assertExactKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  contextName: string
): void {
  const keys = Object.keys(record);
  for (const k of keys) {
    if (!allowedKeys.includes(k)) {
      throw new ApiValidationError(
        `Closed-world validation failed: unexpected field '${k}' in ${contextName}`
      );
    }
  }
  for (const required of allowedKeys) {
    if (!(required in record)) {
      throw new ApiValidationError(
        `Closed-world validation failed: missing required field '${required}' in ${contextName}`
      );
    }
  }
}

export function parseCreateAssessmentBody(body: unknown): CreateAssessmentCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  assertExactKeys(record, ['targetUri'], 'CreateAssessmentRequest');

  const { targetUri } = record;
  if (typeof targetUri !== 'string' || targetUri.trim().length === 0) {
    throw new ApiValidationError('Field targetUri must be a non-empty string');
  }

  // Ensure reasonable URI scheme
  try {
    const parsed = new URL(targetUri);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new ApiValidationError('targetUri must have http: or https: scheme');
    }
  } catch (err: unknown) {
    if (err instanceof ApiValidationError) throw err;
    throw new ApiValidationError('targetUri must be a valid URL');
  }

  return { targetUri };
}

export function parseGenerateReportBody(body: unknown): GenerateDefensiveReportCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = [
    'reportId',
    'sessionId',
    'scanId',
    'requestedAt',
    'operatorSignatureId',
    'operatorVerifiedAt',
    'operatorAttestationText'
  ] as const;

  assertExactKeys(record, allowedKeys, 'GenerateReportRequest');

  for (const key of allowedKeys) {
    const val = record[key];
    if (typeof val !== 'string') {
      throw new ApiValidationError(`Field '${key}' must be a string`);
    }
  }

  return {
    reportId: record.reportId as string,
    sessionId: record.sessionId as string,
    scanId: record.scanId as string,
    requestedAt: record.requestedAt as string,
    operatorSignatureId: record.operatorSignatureId as string,
    operatorVerifiedAt: record.operatorVerifiedAt as string,
    operatorAttestationText: record.operatorAttestationText as string
  };
}

export interface PromoteCandidateHttpCommand {
  readonly candidateId: string;
  readonly scanId: string;
  readonly draftId: string;
  readonly reviewerId: string;
  readonly triageDecisionId: string;
}

export function parsePromoteCandidateBody(body: unknown): PromoteCandidateHttpCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = [
    'candidateId',
    'scanId',
    'draftId',
    'reviewerId',
    'triageDecisionId'
  ] as const;

  // Exact-key closed-world check: strictly rejects unknown keys (including any injected 'draft' object)
  assertExactKeys(record, allowedKeys, 'PromoteCandidateRequest');

  for (const key of allowedKeys) {
    const val = record[key];
    if (typeof val !== 'string' || val.trim().length === 0) {
      throw new ApiValidationError(`Field '${key}' must be a non-empty string`);
    }
    if (!isStrictSafeId(val)) {
      throw new ApiValidationError(`Field '${key}' must satisfy strict identifier format`);
    }
  }

  return {
    candidateId: record.candidateId as string,
    scanId: record.scanId as string,
    draftId: record.draftId as string,
    reviewerId: record.reviewerId as string,
    triageDecisionId: record.triageDecisionId as string
  };
}

export interface ApproveRecommendationHttpCommand {
  readonly recommendationId: string;
  readonly operatorId: string;
}

export function parseApproveRecommendationBody(body: unknown): ApproveRecommendationHttpCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = ['recommendationId', 'operatorId'] as const;

  assertExactKeys(record, allowedKeys, 'ApproveRecommendationRequest');

  for (const key of allowedKeys) {
    const val = record[key];
    if (typeof val !== 'string' || val.trim().length === 0) {
      throw new ApiValidationError(`Field '${key}' must be a non-empty string`);
    }
    if (!isStrictSafeId(val)) {
      throw new ApiValidationError(`Field '${key}' must satisfy strict identifier format`);
    }
  }

  return {
    recommendationId: record.recommendationId as string,
    operatorId: record.operatorId as string
  };
}

import type { ByotIdentity, ByotSessionIdentityBundle } from '../../detection/DetectionContracts.js';

export function parseByotIdentity(raw: unknown, identityLabel: string = 'ByotIdentity'): ByotIdentity {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ApiValidationError(`${identityLabel} must be a non-empty object`);
  }

  const record = raw as Record<string, unknown>;
  const allowedKeys = ['identityId', 'injectHeaders', 'injectCookies'] as const;
  for (const k of Object.keys(record)) {
    if (!allowedKeys.includes(k as typeof allowedKeys[number])) {
      throw new ApiValidationError(
        `Closed-world validation failed: unexpected field '${k}' in ${identityLabel}`
      );
    }
  }

  if (!('identityId' in record)) {
    throw new ApiValidationError(
      `Closed-world validation failed: missing required field 'identityId' in ${identityLabel}`
    );
  }

  const { identityId, injectHeaders, injectCookies } = record;

  if (typeof identityId !== 'string' || !isStrictSafeId(identityId)) {
    throw new ApiValidationError(
      `Field 'identityId' in ${identityLabel} must satisfy strict identifier format`
    );
  }

  let parsedHeaders: Record<string, string> | undefined;
  if (injectHeaders !== undefined) {
    if (typeof injectHeaders !== 'object' || injectHeaders === null || Array.isArray(injectHeaders)) {
      throw new ApiValidationError(
        `Field 'injectHeaders' in ${identityLabel} must be an object if provided`
      );
    }
    const headerEntries = Object.entries(injectHeaders);
    if (headerEntries.length > 20) {
      throw new ApiValidationError(
        `Field 'injectHeaders' in ${identityLabel} cannot contain more than 20 entries`
      );
    }
    parsedHeaders = {};
    for (const [k, v] of headerEntries) {
      if (typeof k !== 'string' || k.trim().length === 0 || !/^[a-zA-Z0-9_-]+$/.test(k)) {
        throw new ApiValidationError(
          `Invalid header name '${k}' in ${identityLabel}. Must be alphanumeric with hyphens/underscores.`
        );
      }
      if (typeof v !== 'string') {
        throw new ApiValidationError(
          `Value for header '${k}' in ${identityLabel} must be a string`
        );
      }
      if (v.length > 4096) {
        throw new ApiValidationError(
          `Value for header '${k}' in ${identityLabel} exceeds maximum allowed length (4096 chars)`
        );
      }
      parsedHeaders[k] = v;
    }
  }

  let parsedCookies: Record<string, string> | undefined;
  if (injectCookies !== undefined) {
    if (typeof injectCookies !== 'object' || injectCookies === null || Array.isArray(injectCookies)) {
      throw new ApiValidationError(
        `Field 'injectCookies' in ${identityLabel} must be an object if provided`
      );
    }
    const cookieEntries = Object.entries(injectCookies);
    if (cookieEntries.length > 20) {
      throw new ApiValidationError(
        `Field 'injectCookies' in ${identityLabel} cannot contain more than 20 entries`
      );
    }
    parsedCookies = {};
    for (const [k, v] of cookieEntries) {
      if (typeof k !== 'string' || k.trim().length === 0 || !/^[a-zA-Z0-9_.-]+$/.test(k)) {
        throw new ApiValidationError(
          `Invalid cookie name '${k}' in ${identityLabel}. Must be alphanumeric with hyphens/underscores/dots.`
        );
      }
      if (typeof v !== 'string') {
        throw new ApiValidationError(
          `Value for cookie '${k}' in ${identityLabel} must be a string`
        );
      }
      if (v.length > 4096) {
        throw new ApiValidationError(
          `Value for cookie '${k}' in ${identityLabel} exceeds maximum allowed length (4096 chars)`
        );
      }
      parsedCookies[k] = v;
    }
  }

  return {
    identityId: identityId.trim(),
    ...(parsedHeaders ? { injectHeaders: Object.freeze(parsedHeaders) } : {}),
    ...(parsedCookies ? { injectCookies: Object.freeze(parsedCookies) } : {}),
  };
}

export function parseByotSessionIdentityBundle(raw: unknown): ByotSessionIdentityBundle {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ApiValidationError('sessionIdentities must be a non-empty object');
  }

  const record = raw as Record<string, unknown>;
  const allowedKeys = ['identityA', 'identityB'] as const;
  for (const k of Object.keys(record)) {
    if (!allowedKeys.includes(k as typeof allowedKeys[number])) {
      throw new ApiValidationError(
        `Closed-world validation failed: unexpected field '${k}' in sessionIdentities`
      );
    }
  }

  if (!('identityA' in record)) {
    throw new ApiValidationError(
      "Closed-world validation failed: missing required field 'identityA' in sessionIdentities"
    );
  }

  const identityA = parseByotIdentity(record.identityA, 'identityA');
  const identityB =
    record.identityB !== undefined ? parseByotIdentity(record.identityB, 'identityB') : undefined;

  return {
    identityA,
    ...(identityB ? { identityB } : {}),
  };
}

function parseOptionalStringArray(
  value: unknown,
  fieldName: string
): readonly string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Array.isArray(value)) {
    throw new ApiValidationError(`Field ${fieldName} must be an array of strings when provided`);
  }
  if (value.length > 100) {
    throw new ApiValidationError(`Field ${fieldName} exceeds maximum of 100 entries`);
  }
  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.trim().length === 0) {
      throw new ApiValidationError(`Field ${fieldName} entries must be non-empty strings`);
    }
    if (item.length > 2048) {
      throw new ApiValidationError(`Field ${fieldName} entry exceeds maximum length of 2048`);
    }
    out.push(item.trim());
  }
  return Object.freeze(out);
}

export function parseStartOrchestratedAssessmentBody(
  body: unknown
): {
  targetDomain: string;
  actorId?: string;
  config?: Record<string, unknown>;
  sessionIdentities?: ByotSessionIdentityBundle;
  seedUrls?: readonly string[];
  seedPaths?: readonly string[];
} {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = [
    'targetDomain',
    'actorId',
    'config',
    'sessionIdentities',
    'seedUrls',
    'seedPaths',
  ] as const;
  for (const k of Object.keys(record)) {
    if (!allowedKeys.includes(k as typeof allowedKeys[number])) {
      throw new ApiValidationError(
        `Closed-world validation failed: unexpected field '${k}' in StartOrchestratedAssessmentRequest`
      );
    }
  }

  if (!('targetDomain' in record)) {
    throw new ApiValidationError(
      "Closed-world validation failed: missing required field 'targetDomain' in StartOrchestratedAssessmentRequest"
    );
  }

  const { targetDomain, actorId, config, sessionIdentities, seedUrls, seedPaths } = record;
  if (typeof targetDomain !== 'string' || targetDomain.trim().length === 0) {
    throw new ApiValidationError('Field targetDomain must be a non-empty string');
  }

  if (actorId !== undefined && (typeof actorId !== 'string' || !isStrictSafeId(actorId))) {
    throw new ApiValidationError('Field actorId must satisfy strict identifier format');
  }

  if (config !== undefined && (typeof config !== 'object' || config === null || Array.isArray(config))) {
    throw new ApiValidationError('Field config must be an object if provided');
  }

  let parsedSessionIdentities: ByotSessionIdentityBundle | undefined;
  if (sessionIdentities !== undefined) {
    parsedSessionIdentities = parseByotSessionIdentityBundle(sessionIdentities);
  }

  const parsedSeedUrls = parseOptionalStringArray(seedUrls, 'seedUrls');
  const parsedSeedPaths = parseOptionalStringArray(seedPaths, 'seedPaths');

  return {
    targetDomain: targetDomain.trim(),
    ...(actorId ? { actorId } : {}),
    ...(config ? { config: config as Record<string, unknown> } : {}),
    ...(parsedSessionIdentities ? { sessionIdentities: parsedSessionIdentities } : {}),
    ...(parsedSeedUrls ? { seedUrls: parsedSeedUrls } : {}),
    ...(parsedSeedPaths ? { seedPaths: parsedSeedPaths } : {}),
  };
}

export interface ReviewEvidenceDraftHttpCommand {
  readonly decision: 'approve_evidence' | 'reject_evidence';
  readonly reviewerId: string;
  readonly reviewedAt: string;
  readonly notes?: string;
}

const BANNED_SYNTHETIC_REVIEWERS = new Set([
  'reviewer_lead_sec',
  'synthetic_reviewer',
  'mock_reviewer',
  'auto_reviewer',
  'bot_reviewer',
  'system_auto',
]);

export function isForbiddenSyntheticReviewerId(reviewerId: string): boolean {
  if (!reviewerId || typeof reviewerId !== 'string') return true;
  const lower = reviewerId.trim().toLowerCase();
  if (BANNED_SYNTHETIC_REVIEWERS.has(lower)) return true;
  if (
    lower.startsWith('synthetic_') ||
    lower.startsWith('mock_') ||
    lower.startsWith('auto_') ||
    lower.startsWith('bot_')
  ) {
    return true;
  }
  return false;
}

export function parseReviewEvidenceDraftBody(body: unknown): ReviewEvidenceDraftHttpCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = ['decision', 'reviewerId', 'reviewedAt', 'notes'] as const;
  for (const k of Object.keys(record)) {
    if (!allowedKeys.includes(k as typeof allowedKeys[number])) {
      throw new ApiValidationError(
        `Closed-world validation failed: unexpected field '${k}' in ReviewEvidenceDraftRequest`
      );
    }
  }

  if (!('decision' in record) || !('reviewerId' in record) || !('reviewedAt' in record)) {
    throw new ApiValidationError(
      "Closed-world validation failed: missing required fields 'decision', 'reviewerId', and/or 'reviewedAt'"
    );
  }

  const { decision, reviewerId, reviewedAt, notes } = record;

  if (decision !== 'approve_evidence' && decision !== 'reject_evidence') {
    throw new ApiValidationError(
      "Field 'decision' must be either 'approve_evidence' or 'reject_evidence'"
    );
  }

  if (typeof reviewerId !== 'string' || !isStrictSafeId(reviewerId)) {
    throw new ApiValidationError("Field 'reviewerId' must satisfy strict identifier format");
  }

  if (isForbiddenSyntheticReviewerId(reviewerId)) {
    throw new ApiValidationError(
      `Field 'reviewerId' contains forbidden synthetic or unauthenticated reviewer pattern '${reviewerId}'`
    );
  }

  if (
    typeof reviewedAt !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(reviewedAt) ||
    Number.isNaN(Date.parse(reviewedAt))
  ) {
    throw new ApiValidationError("Field 'reviewedAt' must be a valid ISO 8601 timestamp string");
  }

  if (notes !== undefined && typeof notes !== 'string') {
    throw new ApiValidationError("Field 'notes' must be a string if provided");
  }

  return {
    decision,
    reviewerId,
    reviewedAt,
    ...(notes ? { notes } : {}),
  };
}

export interface GenerateHtmlReportHttpCommand {
  readonly operatorId: string;
  readonly attestationText: string;
}

export function parseGenerateHtmlReportHttpBody(body: unknown): GenerateHtmlReportHttpCommand {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ApiValidationError('Request body must be a non-empty object');
  }

  const record = body as Record<string, unknown>;
  const allowedKeys = ['operatorId', 'attestationText'] as const;

  assertExactKeys(record, allowedKeys, 'GenerateHtmlReportRequest');

  const { operatorId, attestationText } = record;

  if (typeof operatorId !== 'string' || operatorId.trim().length === 0) {
    throw new ApiValidationError("Field 'operatorId' must be a non-empty string");
  }

  if (!isStrictSafeId(operatorId)) {
    throw new ApiValidationError("Field 'operatorId' must satisfy strict identifier format");
  }

  if (typeof attestationText !== 'string' || attestationText.trim().length < 10) {
    throw new ApiValidationError(
      "Field 'attestationText' must be a string containing at least 10 characters"
    );
  }

  return {
    operatorId: operatorId.trim(),
    attestationText: attestationText.trim(),
  };
}

