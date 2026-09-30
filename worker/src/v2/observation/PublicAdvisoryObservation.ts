/**
 * F6.6 — public advisory observation for a version already left by F4.3.
 * No version means no advisory. The advisory id must be in the supplied record.
 */

import { tryBuildObservedFact } from './ObservedFactCatalogService.js';
import type { AuthorizedExecutionLineageTuple } from '../detection/DetectionContracts.js';
import type { ObservedFact } from './ObservedFactContracts.js';

export interface PublicAdvisoryRecord {
  readonly product: string;
  readonly version: string;
  readonly advisoryId: string;
}

/** Local identifier list. A match requires the same product and version already observed. */
export const LOCAL_PUBLIC_ADVISORIES: readonly PublicAdvisoryRecord[] = Object.freeze([
  Object.freeze({
    product: 'Next.js',
    version: '14.2.5',
    advisoryId: 'ADV-FIXTURE-1',
  }),
]);

export function observePublicAdvisory(input: {
  readonly product: string;
  readonly version: string | undefined;
  readonly advisories: readonly PublicAdvisoryRecord[];
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly sourceUrl: string;
  readonly observedAt: string;
}): ObservedFact | null {
  const version = input.version?.trim() ?? '';
  if (version.length === 0) return null;
  const product = input.product.trim();
  const match = input.advisories.find(
    (record) => record.product === product && record.version === version && record.advisoryId.trim().length > 0
  );
  if (!match) return null;
  const observationText = `${match.product} ${match.version} ${match.advisoryId}`;
  const value = `${match.product};${match.version};${match.advisoryId}`;
  return tryBuildObservedFact({
    factKind: 'observed_public_advisory',
    value,
    observationText,
    sourceUrl: input.sourceUrl,
    observationKind: 'published_record',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'public_advisory',
  });
}
