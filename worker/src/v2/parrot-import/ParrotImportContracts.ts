/**
 * R4 — Parrot Import Boundary Contracts (recon-first pivot, v0).
 *
 * Versioned, file-based import of manual (Parrot) validation results back
 * into FixGuard. The imported file is UNTRUSTED INPUT: exact-key
 * closed-world validated, forbidden-content scanned, and fail-closed on
 * anything unexpected. Importing a result never creates a Finding and
 * never auto-confirms anything — it produces a provenance-tagged
 * ParrotImportedObservation that still requires separate human review
 * before it can feed any later promotion pipeline. No VM bridge, no
 * remote execution — this boundary only parses and validates a file the
 * operator explicitly supplies.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

export type ParrotImportContractVersion = 'fixguard-parrot-import/v0';
export const PARROT_IMPORT_CONTRACT_VERSION: ParrotImportContractVersion =
  'fixguard-parrot-import/v0';

export type ParrotImportOutcome = 'confirmed' | 'not_confirmed' | 'inconclusive';

const ALLOWED_OUTCOMES: ReadonlySet<string> = new Set([
  'confirmed',
  'not_confirmed',
  'inconclusive',
]);

/** Forbidden terms in free-text import fields — blocks attempts to smuggle
 * severity/exploit claims or sensitive raw material through an import. */
const FORBIDDEN_IMPORT_TERMS: readonly string[] = [
  'severity',
  'cvss',
  'risk_score',
  'riskscore',
  'critical severity',
  'bearer',
  'cookie',
  'set-cookie',
  'password',
  'secret',
  'api_key',
  'apikey',
  'access_token',
  'refresh_token',
  'raw_request',
  'raw_response',
  'raw_body',
  'raw_headers',
  'autoapprove',
  'auto_approve',
  'confirmed: true',
];

const MAX_OBSERVATIONS_PER_IMPORT = 200;
const MAX_NOTE_LENGTH = 2000;

function isStrictSafeId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
}

function isStrictIsoTimestamp(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value)) &&
    new Date(value).toISOString() === value
  );
}

function isSafeFreeText(value: unknown, maxLength: number): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0 || value.length > maxLength) return false;
  const lower = value.toLowerCase();
  return !FORBIDDEN_IMPORT_TERMS.some((term) => lower.includes(term));
}

/** Raw, untrusted shape an operator-supplied Parrot export file is expected
 * to have. Nothing here is trusted until validateParrotImportFile() passes. */
export interface RawParrotImportObservation {
  readonly hypothesisId?: unknown;
  readonly outcome?: unknown;
  readonly operatorNote?: unknown;
  readonly evidenceExcerpt?: unknown;
}

export interface RawParrotImportFile {
  readonly formatVersion?: unknown;
  readonly dossierId?: unknown;
  readonly assessmentId?: unknown;
  readonly scanId?: unknown;
  readonly importedBy?: unknown;
  readonly generatedAt?: unknown;
  readonly observations?: unknown;
}

/** Validated, safe view of a single imported observation. */
export interface ParrotImportedObservation {
  readonly contractVersion: ParrotImportContractVersion;
  readonly kind: 'parrot_imported_observation';
  readonly observationId: string;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly dossierId: string;
  readonly hypothesisId: string;
  readonly outcome: ParrotImportOutcome;
  readonly operatorNote: string;
  readonly evidenceExcerpt?: string;
  readonly importedBy: string;
  /** Server-assigned at import time — never trusted from the file itself. */
  readonly importedAt: string;
  readonly sourceKind: 'parrot_file_import';
  readonly requiresHumanReview: true;
  readonly nonClaims: {
    readonly noFindingCreated: true;
    readonly noSeverityClaim: true;
    readonly noAutoConfirmation: true;
    readonly treatedAsUntrustedInput: true;
  };
}

export type ParrotImportRejectionReason =
  | 'invalid_shape'
  | 'unsupported_format_version'
  | 'invalid_identifier'
  | 'invalid_timestamp'
  | 'too_many_observations'
  | 'empty_observations'
  | 'invalid_observation_shape'
  | 'invalid_outcome'
  | 'unsafe_content_rejected';

export interface ParrotImportResult {
  readonly contractVersion: ParrotImportContractVersion;
  readonly kind: 'parrot_import_result';
  readonly status: 'accepted' | 'rejected';
  readonly reasonCode?: ParrotImportRejectionReason;
  readonly rejectionDetail?: string;
  readonly observations: readonly ParrotImportedObservation[];
  readonly importedCount: number;
}

const ALLOWED_TOP_LEVEL_KEYS = new Set([
  'formatVersion',
  'dossierId',
  'assessmentId',
  'scanId',
  'importedBy',
  'generatedAt',
  'observations',
]);

const ALLOWED_OBSERVATION_KEYS = new Set([
  'hypothesisId',
  'outcome',
  'operatorNote',
  'evidenceExcerpt',
]);

function rejected(
  reasonCode: ParrotImportRejectionReason,
  detail: string
): ParrotImportResult {
  return {
    contractVersion: PARROT_IMPORT_CONTRACT_VERSION,
    kind: 'parrot_import_result',
    status: 'rejected',
    reasonCode,
    rejectionDetail: detail,
    observations: Object.freeze([]),
    importedCount: 0,
  };
}

/**
 * Two-pass atomic validation (ADR-002 philosophy applied to file import):
 * the whole import is rejected if ANY observation fails — never a partial
 * accept. Exact-key closed-world at both the file and observation level
 * (ADR-003). All free-text fields are forbidden-content scanned (ADR-008
 * spirit extended to inbound, not just outbound, content).
 */
export function validateAndParseParrotImportFile(
  raw: unknown,
  args: {
    readonly expectedAssessmentId: string;
    readonly expectedScanId: string;
    readonly importedBy: string;
    readonly importedAt: string;
  }
): ParrotImportResult {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return rejected('invalid_shape', 'Import file must be a single JSON object');
  }
  const file = raw as RawParrotImportFile;

  const topKeys = Object.keys(file);
  for (const k of topKeys) {
    if (!ALLOWED_TOP_LEVEL_KEYS.has(k)) {
      return rejected('invalid_shape', `Unexpected top-level key '${k}'`);
    }
  }

  if (file.formatVersion !== PARROT_IMPORT_CONTRACT_VERSION) {
    return rejected(
      'unsupported_format_version',
      `Expected formatVersion '${PARROT_IMPORT_CONTRACT_VERSION}'`
    );
  }

  if (
    !isStrictSafeId(file.dossierId) ||
    !isStrictSafeId(file.assessmentId) ||
    !isStrictSafeId(file.scanId)
  ) {
    return rejected('invalid_identifier', 'dossierId/assessmentId/scanId must be strict-safe ids');
  }
  if (file.assessmentId !== args.expectedAssessmentId || file.scanId !== args.expectedScanId) {
    return rejected(
      'invalid_identifier',
      'Import assessmentId/scanId must match the assessment this import targets'
    );
  }
  if (!isStrictSafeId(file.importedBy)) {
    return rejected('invalid_identifier', 'importedBy must be a strict-safe id');
  }
  if (!isStrictIsoTimestamp(file.generatedAt)) {
    return rejected('invalid_timestamp', 'generatedAt must be a strict ISO-8601 timestamp');
  }

  if (!Array.isArray(file.observations)) {
    return rejected('invalid_shape', 'observations must be an array');
  }
  if (file.observations.length === 0) {
    return rejected('empty_observations', 'observations must contain at least one entry');
  }
  if (file.observations.length > MAX_OBSERVATIONS_PER_IMPORT) {
    return rejected(
      'too_many_observations',
      `observations exceeds max of ${MAX_OBSERVATIONS_PER_IMPORT}`
    );
  }

  const parsed: ParrotImportedObservation[] = [];
  for (let i = 0; i < file.observations.length; i += 1) {
    const raw0 = file.observations[i];
    if (!raw0 || typeof raw0 !== 'object' || Array.isArray(raw0)) {
      return rejected('invalid_observation_shape', `observations[${i}] must be an object`);
    }
    const obs = raw0 as RawParrotImportObservation;
    const obsKeys = Object.keys(obs);
    for (const k of obsKeys) {
      if (!ALLOWED_OBSERVATION_KEYS.has(k)) {
        return rejected(
          'invalid_observation_shape',
          `observations[${i}] has unexpected key '${k}'`
        );
      }
    }
    if (!isStrictSafeId(obs.hypothesisId)) {
      return rejected('invalid_identifier', `observations[${i}].hypothesisId is invalid`);
    }
    if (typeof obs.outcome !== 'string' || !ALLOWED_OUTCOMES.has(obs.outcome)) {
      return rejected(
        'invalid_outcome',
        `observations[${i}].outcome must be one of: confirmed, not_confirmed, inconclusive`
      );
    }
    if (!isSafeFreeText(obs.operatorNote, MAX_NOTE_LENGTH)) {
      return rejected(
        'unsafe_content_rejected',
        `observations[${i}].operatorNote is missing, too long, or contains a forbidden term`
      );
    }
    if (obs.evidenceExcerpt !== undefined && !isSafeFreeText(obs.evidenceExcerpt, MAX_NOTE_LENGTH)) {
      return rejected(
        'unsafe_content_rejected',
        `observations[${i}].evidenceExcerpt contains a forbidden term or exceeds max length`
      );
    }

    parsed.push({
      contractVersion: PARROT_IMPORT_CONTRACT_VERSION,
      kind: 'parrot_imported_observation',
      observationId: `pimp_${args.expectedAssessmentId}_${i}`.slice(0, 64),
      assessmentId: file.assessmentId,
      scanId: file.scanId,
      dossierId: file.dossierId,
      hypothesisId: obs.hypothesisId,
      outcome: obs.outcome as ParrotImportOutcome,
      operatorNote: obs.operatorNote,
      ...(obs.evidenceExcerpt !== undefined ? { evidenceExcerpt: obs.evidenceExcerpt } : {}),
      importedBy: args.importedBy,
      importedAt: args.importedAt,
      sourceKind: 'parrot_file_import',
      requiresHumanReview: true,
      nonClaims: {
        noFindingCreated: true,
        noSeverityClaim: true,
        noAutoConfirmation: true,
        treatedAsUntrustedInput: true,
      },
    });
  }

  return {
    contractVersion: PARROT_IMPORT_CONTRACT_VERSION,
    kind: 'parrot_import_result',
    status: 'accepted',
    observations: Object.freeze(parsed),
    importedCount: parsed.length,
  };
}
