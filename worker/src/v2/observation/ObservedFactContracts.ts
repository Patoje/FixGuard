/**
 * F0.1 — Observed fact catalog.
 *
 * Typed OBSERVED facts only. No severity, no impact, no vulnerability claim.
 * Object and action identifiers are accepted only when they appear in the
 * observation text that produced them.
 */

import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';

export const OBSERVED_FACT_CONTRACT_VERSION = 'fixguard-observed-fact/v0' as const;
export type ObservedFactContractVersion = typeof OBSERVED_FACT_CONTRACT_VERSION;

export const OBSERVED_FACT_KINDS = Object.freeze([
  'observed_object_id',
  'observed_action_id',
  'observed_param',
  'schema_relation',
  'anon_session_get_delta',
  'observed_build_id',
  'observed_route_manifest_path',
  'observed_tech_version',
  'observed_asn',
  'observed_cdn',
  'observed_related_host',
  'observed_cookie_flags',
  'observed_well_known',
  'observed_registration',
  'observed_published_index',
  'observed_document_metadata',
  'observed_search_index_url',
  'graphql_auth_delta',
  'observed_public_advisory',
  'observed_html_field',
] as const);

export type ObservedFactKind = (typeof OBSERVED_FACT_KINDS)[number];

export type ObservedFactObservationKind =
  | 'url'
  | 'http_body'
  | 'http_header'
  | 'schema_document'
  | 'differential_get'
  | 'dns_json'
  | 'sourcemap_comment'
  | 'tls_certificate'
  | 'published_record'
  | 'document_bytes';

const OBSERVED_FACT_OBSERVATION_KINDS: readonly ObservedFactObservationKind[] = Object.freeze([
  'url',
  'http_body',
  'http_header',
  'schema_document',
  'differential_get',
  'dns_json',
  'sourcemap_comment',
  'tls_certificate',
  'published_record',
  'document_bytes',
]);

export function isObservedFactKind(value: unknown): value is ObservedFactKind {
  return typeof value === 'string' && (OBSERVED_FACT_KINDS as readonly string[]).includes(value);
}

export function isObservedFactObservationKind(
  value: unknown
): value is ObservedFactObservationKind {
  return (
    typeof value === 'string' &&
    (OBSERVED_FACT_OBSERVATION_KINDS as readonly string[]).includes(value)
  );
}

/**
 * Canonical anon-vs-session GET delta value.
 * Every `;`-separated token must also appear in the observation text.
 */
export function formatAnonSessionGetDeltaValue(input: {
  readonly anonStatus: number;
  readonly sessionStatus: number;
  readonly anonBodyHash: string;
  readonly sessionBodyHash: string;
  readonly interfered: boolean;
  readonly anonBodyShape?: 'empty' | 'json_object' | 'json_array' | 'html' | 'text';
  readonly sessionBodyShape?: 'empty' | 'json_object' | 'json_array' | 'html' | 'text';
}): string {
  const interfered = input.interfered ? 'true' : 'false';
  const shapes =
    input.anonBodyShape && input.sessionBodyShape
      ? `;anon_shape=${input.anonBodyShape};session_shape=${input.sessionBodyShape}`
      : '';
  return `anon=${input.anonStatus};session=${input.sessionStatus};anon_hash=${input.anonBodyHash};session_hash=${input.sessionBodyHash}${shapes};interfered=${interfered}`;
}

export interface ObservedFact {
  readonly contractVersion: ObservedFactContractVersion;
  readonly kind: 'observed_fact';
  readonly factId: string;
  readonly factKind: ObservedFactKind;
  readonly assessmentId: string;
  readonly scanId: string;
  readonly epistemicStatus: 'OBSERVED';
  readonly value: string;
  readonly sourceUrl: string;
  readonly observationKind: ObservedFactObservationKind;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
  readonly sourceLabel?: string;
}

export interface RecordObservedFactInput {
  readonly factKind: ObservedFactKind;
  readonly value: string;
  readonly observationText: string;
  readonly sourceUrl: string;
  readonly observationKind: ObservedFactObservationKind;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
  readonly sourceLabel?: string;
}
