/**
 * F0.1 — Record and persist observed facts.
 * Fail-closed: object/action identifiers that are not substrings of the
 * supplied observation text are rejected and never stored.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import {
  OBSERVED_FACT_CONTRACT_VERSION,
  isObservedFactKind,
  isObservedFactObservationKind,
  type ObservedFact,
  type ObservedFactKind,
  type RecordObservedFactInput,
} from './ObservedFactContracts.js';

const FACT_REQUIRED_KEYS = Object.freeze([
  'contractVersion',
  'kind',
  'factId',
  'factKind',
  'assessmentId',
  'scanId',
  'epistemicStatus',
  'value',
  'sourceUrl',
  'observationKind',
  'lineage',
  'observedAt',
] as const);

const FACT_OPTIONAL_KEYS = Object.freeze(['sourceLabel'] as const);

const LINEAGE_KEYS = Object.freeze([
  'assessmentId',
  'scanId',
  'authorizationGrantId',
  'authorizationDecisionId',
  'actorId',
] as const);

const OBSERVED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const OBJECT_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const ACTION_ID_RE = /^[A-Za-z0-9_+\/=.-]{8,128}$/;
const PARAM_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SCHEMA_SIDE_RE = /^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$/;
const SCHEMA_RELATION_RE =
  /^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*->[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$/;
const DELTA_SHAPE = 'empty|json_object|json_array|html|text';
const DELTA_TOKEN_RE = new RegExp(
  `^anon=\\d{3};session=\\d{3};anon_hash=[a-f0-9]{16,64};session_hash=[a-f0-9]{16,64}(?:;anon_shape=(?:${DELTA_SHAPE});session_shape=(?:${DELTA_SHAPE}))?;interfered=(?:true|false)$`
);
const BUILD_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const ROUTE_MANIFEST_RE = /^\/_next\/static\/[A-Za-z0-9._-]+\/_(?:build|ssg)Manifest\.js$/;
const TECH_VERSION_RE = /^(?:Next\.js|React) v?\d+\.\d+\.\d+$/;
const ASN_RE = /^AS\d{1,10}$/;
const CDN_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const COOKIE_FLAGS_RE =
  /^[A-Za-z0-9_-]{1,64}(?:;Secure)?(?:;HttpOnly)?(?:;SameSite=(?:Lax|Strict|None))?$/;
const SEARCH_URL_RE = /^https:\/\/[A-Za-z0-9._:-]+\/[^\s]*$/;
const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const SOURCE_LABEL_RE = /^[a-z0-9_]{1,64}$/;

export type RecordObservedFactResult =
  | { readonly status: 'persisted'; readonly fact: ObservedFact }
  | { readonly status: 'rejected'; readonly reasonCode: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const allowed = new Set<string>([...required, ...optional]);
  const keys = Object.keys(value);
  for (const key of keys) {
    if (!allowed.has(key)) return false;
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
  }
  return true;
}

function readString(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  if (typeof value !== 'string' || value.length === 0) return null;
  return value;
}

function stableFactId(parts: readonly string[]): string {
  let hash = 2166136261;
  const text = parts.join('\u001f');
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return `fact_${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

function copyLineage(
  lineage: AuthorizedExecutionLineageTuple
): AuthorizedExecutionLineageTuple {
  return {
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    authorizationGrantId: lineage.authorizationGrantId,
    authorizationDecisionId: lineage.authorizationDecisionId,
    actorId: lineage.actorId,
  };
}

function parseLineage(value: unknown): AuthorizedExecutionLineageTuple | null {
  if (!isRecord(value) || !exactKeys(value, LINEAGE_KEYS)) return null;
  const assessmentId = readString(value, 'assessmentId');
  const scanId = readString(value, 'scanId');
  const authorizationGrantId = readString(value, 'authorizationGrantId');
  const authorizationDecisionId = readString(value, 'authorizationDecisionId');
  const actorId = readString(value, 'actorId');
  if (
    !assessmentId ||
    !scanId ||
    !authorizationGrantId ||
    !authorizationDecisionId ||
    !actorId
  ) {
    return null;
  }
  return {
    assessmentId,
    scanId,
    authorizationGrantId,
    authorizationDecisionId,
    actorId,
  };
}

function tokensGrounded(value: string, observationText: string): boolean {
  const tokens = value.split(';');
  return tokens.every((token) => token.length > 0 && observationText.includes(token));
}

function htmlFieldGrounded(value: string, observationText: string): boolean {
  const parts = value.split(';');
  if (parts.length === 0) return false;
  return parts.every((part) => {
    const splitAt = part.indexOf('=');
    if (splitAt <= 0) return false;
    const token = part.slice(splitAt + 1);
    return token.length > 0 && observationText.includes(token);
  });
}

function cookieSecretLeak(value: string, observationText: string): boolean {
  const pair = observationText.match(/\b([A-Za-z0-9_-]+)=([^;\s,]+)/);
  const secret = pair?.[2] ?? '';
  if (secret.length === 0) return false;
  if (secret === 'Lax' || secret === 'Strict' || secret === 'None' || secret === 'true' || secret === 'false') {
    return false;
  }
  return value.includes(secret);
}

function valueGroundedInObservation(
  factKind: ObservedFactKind,
  value: string,
  observationText: string
): boolean {
  if (observationText.length === 0) return false;
  if (factKind === 'schema_relation') {
    const sides = value.split('->');
    if (sides.length !== 2) return false;
    const left = sides[0] ?? '';
    const right = sides[1] ?? '';
    return left.length > 0 && right.length > 0 && observationText.includes(left) && observationText.includes(right);
  }
  if (factKind === 'anon_session_get_delta' || factKind === 'graphql_auth_delta') {
    if (!DELTA_TOKEN_RE.test(value)) return false;
    return tokensGrounded(value, observationText);
  }
  if (
    factKind === 'observed_cookie_flags' ||
    factKind === 'observed_well_known' ||
    factKind === 'observed_registration' ||
    factKind === 'observed_published_index' ||
    factKind === 'observed_document_metadata' ||
    factKind === 'observed_public_advisory'
  ) {
    if (factKind === 'observed_cookie_flags' && cookieSecretLeak(value, observationText)) {
      return false;
    }
    return tokensGrounded(value, observationText);
  }
  if (factKind === 'observed_html_field') {
    return htmlFieldGrounded(value, observationText);
  }
  return observationText.includes(value);
}

function identifierShapeAllowed(factKind: ObservedFactKind, value: string): boolean {
  if (JWT_SHAPE_RE.test(value)) return false;
  if (factKind === 'observed_object_id') return OBJECT_ID_RE.test(value);
  if (factKind === 'observed_action_id') return ACTION_ID_RE.test(value);
  if (factKind === 'observed_param') return PARAM_NAME_RE.test(value);
  if (factKind === 'schema_relation') {
    if (!SCHEMA_RELATION_RE.test(value)) return false;
    const sides = value.split('->');
    return SCHEMA_SIDE_RE.test(sides[0] ?? '') && SCHEMA_SIDE_RE.test(sides[1] ?? '');
  }
  if (factKind === 'anon_session_get_delta' || factKind === 'graphql_auth_delta') {
    return DELTA_TOKEN_RE.test(value);
  }
  if (factKind === 'observed_build_id') return BUILD_ID_RE.test(value);
  if (factKind === 'observed_route_manifest_path') return ROUTE_MANIFEST_RE.test(value);
  if (factKind === 'observed_tech_version') return TECH_VERSION_RE.test(value);
  if (factKind === 'observed_asn') return ASN_RE.test(value);
  if (factKind === 'observed_cdn') return CDN_RE.test(value);
  if (factKind === 'observed_related_host') return HOST_RE.test(value);
  if (factKind === 'observed_cookie_flags') return COOKIE_FLAGS_RE.test(value);
  if (factKind === 'observed_well_known') {
    return value.startsWith('path=/.well-known/') && value.includes(';reachable=');
  }
  if (factKind === 'observed_search_index_url') return SEARCH_URL_RE.test(value);
  if (
    factKind === 'observed_registration' ||
    factKind === 'observed_published_index' ||
    factKind === 'observed_document_metadata' ||
    factKind === 'observed_public_advisory'
  ) {
    return value.length > 0 && value.length <= 512 && !/[\r\n]/.test(value);
  }
  if (factKind === 'observed_html_field') {
    return /^[a-z]+=[^;\r\n]+(?:;[a-z]+=[^;\r\n]+)*$/.test(value) && value.length <= 512;
  }
  return false;
}

function rejectionForInput(input: RecordObservedFactInput): string | null {
  if (!isObservedFactKind(input.factKind)) return 'invalid_fact_kind';
  if (!isObservedFactObservationKind(input.observationKind)) return 'invalid_observation_kind';
  if (!OBSERVED_AT_RE.test(input.observedAt)) return 'invalid_observed_at';
  if (input.sourceUrl.trim().length === 0) return 'invalid_source_url';
  if (input.sourceLabel !== undefined && !SOURCE_LABEL_RE.test(input.sourceLabel)) {
    return 'invalid_source_label';
  }
  const lineage = input.lineage;
  if (
    lineage.assessmentId.trim().length === 0 ||
    lineage.scanId.trim().length === 0 ||
    lineage.authorizationGrantId.trim().length === 0 ||
    lineage.authorizationDecisionId.trim().length === 0 ||
    lineage.actorId.trim().length === 0
  ) {
    return 'invalid_lineage';
  }
  if (!identifierShapeAllowed(input.factKind, input.value)) return 'invalid_identifier_shape';
  if (!valueGroundedInObservation(input.factKind, input.value, input.observationText)) {
    return 'identifier_not_in_observation';
  }
  return null;
}

function buildFact(input: RecordObservedFactInput): ObservedFact {
  const lineage = copyLineage(input.lineage);
  const fact: ObservedFact = {
    contractVersion: OBSERVED_FACT_CONTRACT_VERSION,
    kind: 'observed_fact',
    factId: stableFactId([
      lineage.assessmentId,
      lineage.scanId,
      input.factKind,
      input.value,
      input.sourceUrl,
    ]),
    factKind: input.factKind,
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    epistemicStatus: 'OBSERVED',
    value: input.value,
    sourceUrl: input.sourceUrl,
    observationKind: input.observationKind,
    lineage,
    observedAt: input.observedAt,
    ...(input.sourceLabel !== undefined ? { sourceLabel: input.sourceLabel } : {}),
  };
  return fact;
}

export function tryBuildObservedFact(input: RecordObservedFactInput): ObservedFact | null {
  if (rejectionForInput(input)) return null;
  return buildFact(input);
}

export function parseObservedFact(value: unknown): ObservedFact | null {
  if (!isRecord(value) || !exactKeys(value, FACT_REQUIRED_KEYS, FACT_OPTIONAL_KEYS)) {
    return null;
  }
  if (value.contractVersion !== OBSERVED_FACT_CONTRACT_VERSION) return null;
  if (value.kind !== 'observed_fact') return null;
  if (value.epistemicStatus !== 'OBSERVED') return null;
  const factId = readString(value, 'factId');
  const factKindRaw = value.factKind;
  const assessmentId = readString(value, 'assessmentId');
  const scanId = readString(value, 'scanId');
  const factValue = readString(value, 'value');
  const sourceUrl = readString(value, 'sourceUrl');
  const observationKindRaw = value.observationKind;
  const observedAt = readString(value, 'observedAt');
  const lineage = parseLineage(value.lineage);
  if (
    !factId ||
    !factId.startsWith('fact_') ||
    !isObservedFactKind(factKindRaw) ||
    !assessmentId ||
    !scanId ||
    !factValue ||
    !sourceUrl ||
    !isObservedFactObservationKind(observationKindRaw) ||
    !observedAt ||
    !OBSERVED_AT_RE.test(observedAt) ||
    !lineage ||
    lineage.assessmentId !== assessmentId ||
    lineage.scanId !== scanId ||
    !identifierShapeAllowed(factKindRaw, factValue)
  ) {
    return null;
  }
  let sourceLabel: string | undefined;
  if (value.sourceLabel !== undefined) {
    if (typeof value.sourceLabel !== 'string' || !SOURCE_LABEL_RE.test(value.sourceLabel)) {
      return null;
    }
    sourceLabel = value.sourceLabel;
  }
  const fact: ObservedFact = {
    contractVersion: OBSERVED_FACT_CONTRACT_VERSION,
    kind: 'observed_fact',
    factId,
    factKind: factKindRaw,
    assessmentId,
    scanId,
    epistemicStatus: 'OBSERVED',
    value: factValue,
    sourceUrl,
    observationKind: observationKindRaw,
    lineage,
    observedAt,
    ...(sourceLabel !== undefined ? { sourceLabel } : {}),
  };
  return fact;
}

export function isObservedFactRecord(value: unknown): value is ObservedFact {
  return parseObservedFact(value) !== null;
}

export function acceptObservedFacts(facts: readonly unknown[]): readonly ObservedFact[] {
  const out: ObservedFact[] = [];
  const seen = new Set<string>();
  for (const fact of facts) {
    const parsed = parseObservedFact(fact);
    if (!parsed || seen.has(parsed.factId)) continue;
    seen.add(parsed.factId);
    out.push(parsed);
  }
  return Object.freeze(out);
}

/**
 * Build facts for identifiers that already appear in the source URL.
 * Callers must pass object ids extracted from that URL, not placeholders.
 */
export function collectGroundedSurfaceFacts(input: {
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
  readonly objectIds: readonly { readonly sourceUrl: string; readonly objectId: string }[];
  readonly parameters: readonly { readonly sourceUrl: string; readonly parameterName: string }[];
}): readonly ObservedFact[] {
  const drafts: RecordObservedFactInput[] = [];
  for (const item of input.objectIds) {
    drafts.push({
      factKind: 'observed_object_id',
      value: item.objectId,
      observationText: item.sourceUrl,
      sourceUrl: item.sourceUrl,
      observationKind: 'url',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'rest_path',
    });
  }
  for (const item of input.parameters) {
    drafts.push({
      factKind: 'observed_param',
      value: item.parameterName,
      observationText: item.sourceUrl,
      sourceUrl: item.sourceUrl,
      observationKind: 'url',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'query_param',
    });
  }
  const built: ObservedFact[] = [];
  const seen = new Set<string>();
  for (const draft of drafts) {
    if (rejectionForInput(draft)) continue;
    const fact = buildFact(draft);
    if (seen.has(fact.factId)) continue;
    seen.add(fact.factId);
    built.push(fact);
  }
  return Object.freeze(built);
}

export class InMemoryObservedFactRepository {
  private readonly facts = new Map<string, ObservedFact>();

  record(input: RecordObservedFactInput): RecordObservedFactResult {
    const reasonCode = rejectionForInput(input);
    if (reasonCode) {
      return { status: 'rejected', reasonCode };
    }
    const fact = buildFact(input);
    if (this.facts.has(fact.factId)) {
      return { status: 'rejected', reasonCode: 'duplicate_fact_id' };
    }
    const stored = parseObservedFact(fact);
    if (!stored) {
      return { status: 'rejected', reasonCode: 'fact_failed_exact_key_validation' };
    }
    this.facts.set(stored.factId, stored);
    const readBack = this.get(stored.factId);
    if (!readBack) {
      return { status: 'rejected', reasonCode: 'fact_failed_exact_key_validation' };
    }
    return { status: 'persisted', fact: readBack };
  }

  /**
   * Reject unknown objects (extra keys such as severity) before any write.
   */
  recordUnknown(value: unknown): RecordObservedFactResult {
    if (!isRecord(value)) {
      return { status: 'rejected', reasonCode: 'invalid_fact_object' };
    }
    if (!exactKeys(value, [
      'factKind',
      'value',
      'observationText',
      'sourceUrl',
      'observationKind',
      'lineage',
      'observedAt',
    ], ['sourceLabel'])) {
      return { status: 'rejected', reasonCode: 'exact_key_rejected' };
    }
    const factKind = value.factKind;
    const factValue = readString(value, 'value');
    const observationText = value.observationText;
    const sourceUrl = readString(value, 'sourceUrl');
    const observationKind = value.observationKind;
    const lineage = parseLineage(value.lineage);
    const observedAt = readString(value, 'observedAt');
    if (
      !isObservedFactKind(factKind) ||
      !factValue ||
      typeof observationText !== 'string' ||
      !sourceUrl ||
      !isObservedFactObservationKind(observationKind) ||
      !lineage ||
      !observedAt
    ) {
      return { status: 'rejected', reasonCode: 'invalid_fact_object' };
    }
    let sourceLabel: string | undefined;
    if (value.sourceLabel !== undefined) {
      if (typeof value.sourceLabel !== 'string') {
        return { status: 'rejected', reasonCode: 'invalid_source_label' };
      }
      sourceLabel = value.sourceLabel;
    }
    return this.record({
      factKind,
      value: factValue,
      observationText,
      sourceUrl,
      observationKind,
      lineage,
      observedAt,
      ...(sourceLabel !== undefined ? { sourceLabel } : {}),
    });
  }

  get(factId: string): ObservedFact | null {
    const stored = this.facts.get(factId);
    if (!stored) return null;
    return parseObservedFact(stored);
  }

  listByAssessmentId(assessmentId: string): readonly ObservedFact[] {
    const matched: ObservedFact[] = [];
    for (const fact of this.facts.values()) {
      if (fact.assessmentId !== assessmentId) continue;
      const copy = parseObservedFact(fact);
      if (copy) matched.push(copy);
    }
    matched.sort((a, b) => a.factId.localeCompare(b.factId));
    return Object.freeze(matched);
  }

  has(factId: string): boolean {
    return this.facts.has(factId);
  }
}

export function parameterNameAppearsInUrl(url: string, parameterName: string): boolean {
  try {
    return new URL(url).searchParams.has(parameterName);
  } catch {
    return false;
  }
}
