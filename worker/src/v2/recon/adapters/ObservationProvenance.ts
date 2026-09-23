/**
 * Shared freshness / provenance vocabulary for recon observation DTOs.
 * collectedAt is ISO-8601 UTC collection time; it does NOT prove underlying data is current.
 */

export type ObservationFreshness = 'live' | 'historical' | 'unknown';

export type ObservationSourceReliability =
  | 'direct_observation'
  | 'historical_archive'
  | 'inferred_relationship';

export interface ObservationProvenanceFields {
  readonly collectedAt: string;
  readonly freshness: ObservationFreshness;
  readonly sourceReliability: ObservationSourceReliability;
}

export function liveDirectProvenance(collectedAt: string): ObservationProvenanceFields {
  return {
    collectedAt,
    freshness: 'live',
    sourceReliability: 'direct_observation',
  };
}

export function historicalArchiveProvenance(collectedAt: string): ObservationProvenanceFields {
  return {
    collectedAt,
    freshness: 'historical',
    sourceReliability: 'historical_archive',
  };
}

export function unknownInferredProvenance(collectedAt: string): ObservationProvenanceFields {
  return {
    collectedAt,
    freshness: 'unknown',
    sourceReliability: 'inferred_relationship',
  };
}
