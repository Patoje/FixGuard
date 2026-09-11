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
