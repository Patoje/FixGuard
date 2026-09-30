/**
 * F4.2 — at most two in-scope GETs for Next route manifests.
 * Runs only when buildId was already captured. Preflight denial issues zero GETs.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../../detection/DetectionContracts.js';
import type { IdorHttpProbeTransport } from '../../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';
import {
  defaultDocumentCopyDirectory,
  observeDownloadedDocument,
} from '../../observation/DocumentMetadataReader.js';

const MANIFEST_NAMES = Object.freeze(['_buildManifest.js', '_ssgManifest.js'] as const);

export async function probeNextRouteManifests(input: {
  readonly originUrl: string;
  readonly buildId: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
}): Promise<{
  readonly facts: readonly ObservedFact[];
  readonly requestCount: number;
  readonly status: 'observed' | 'preflight_denied' | 'skipped';
}> {
  if (input.buildId.trim().length === 0) {
    return { facts: [], requestCount: 0, status: 'skipped' };
  }
  let origin = '';
  try {
    const parsed = new URL(input.originUrl);
    origin = parsed.origin;
  } catch {
    return { facts: [], requestCount: 0, status: 'skipped' };
  }

  const facts: ObservedFact[] = [];
  let requestCount = 0;
  for (const name of MANIFEST_NAMES) {
    const path = `/_next/static/${input.buildId}/${name}`;
    const url = `${origin}${path}`;
    const preflight = await runAdapterPreflight({
      target: url,
      targetKind: 'url',
      verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
      authorizedScopeGrant: input.scopeGrant,
      lineage: input.lineage,
      requiredPermissions: ['endpointDiscovery', 'passiveRecon', 'technologyFingerprinting'],
      missingPermissionReason: 'Scope grant does not permit Next route manifest GET',
      dnsResolver: input.dnsResolver,
    });
    if (!preflight.ok) {
      return { facts: [], requestCount: 0, status: 'preflight_denied' };
    }
    requestCount += 1;
    const response = await input.transport({
      url,
      method: 'GET',
      headers: {},
      timeoutMs: 8000,
    });
    const retained = observeDownloadedDocument({
      downloaded: true,
      url,
      method: 'GET',
      statusCode: response.statusCode,
      contentType: response.headers['content-type'],
      body: response.bodyText,
      scopeGrant: input.scopeGrant,
      lineage: input.lineage,
      observedAt: input.observedAt,
      directory: defaultDocumentCopyDirectory(),
    });
    if (retained.fact) facts.push(retained.fact);
    if (response.statusCode < 200 || response.statusCode >= 300) continue;
    if (!response.bodyText.includes(path)) continue;
    const fact = tryBuildObservedFact({
      factKind: 'observed_route_manifest_path',
      value: path,
      observationText: response.bodyText,
      sourceUrl: url,
      observationKind: 'http_body',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'next_route_manifest',
    });
    if (fact) facts.push(fact);
  }
  return { facts: Object.freeze(facts), requestCount, status: 'observed' };
}
