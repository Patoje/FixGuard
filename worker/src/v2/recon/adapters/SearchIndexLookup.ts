/**
 * F6.4 — one bounded search-index query for the authorized site.
 * gau is not this step. URLs whose host is outside the grant are discarded.
 * Missing endpoint or key performs zero calls.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../../detection/DetectionContracts.js';
import { runAdapterPreflight } from './AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from './AdapterPreflightPipeline.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';

export interface SearchIndexLookupResult {
  readonly status: 'observed' | 'preflight_denied' | 'credentials_absent' | 'empty' | 'execution_failed';
  readonly facts: readonly ObservedFact[];
  readonly fetchCount: number;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function lookupAuthorizedSearchIndex(input: {
  readonly siteHost: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly fetchImpl?: typeof fetch;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
  readonly endpointUrl?: string;
  readonly apiKey?: string;
}): Promise<SearchIndexLookupResult> {
  const siteHost = input.siteHost.trim().toLowerCase();
  const preflight = await runAdapterPreflight({
    target: siteHost,
    targetKind: 'fqdn',
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    authorizedScopeGrant: input.scopeGrant,
    lineage: input.lineage,
    permissionCheck: (ps) => Boolean(ps.passiveRecon || ps.endpointDiscovery),
    missingPermissionReason: 'Scope grant does not permit search index lookup',
    dnsResolver: input.dnsResolver,
  });
  if (!preflight.ok) {
    return { status: 'preflight_denied', facts: [], fetchCount: 0 };
  }
  const endpointUrl = input.endpointUrl ?? process.env.FIXGUARD_SEARCH_INDEX_URL?.trim() ?? '';
  const apiKey = input.apiKey ?? process.env.FIXGUARD_SEARCH_INDEX_KEY?.trim() ?? '';
  if (endpointUrl.length === 0 || apiKey.length === 0) {
    return { status: 'credentials_absent', facts: [], fetchCount: 0 };
  }
  const fetchImpl = input.fetchImpl ?? fetch;
  const requestUrl = new URL(endpointUrl);
  requestUrl.searchParams.set('site', siteHost);
  let body = '';
  try {
    const response = await fetchImpl(requestUrl.toString(), {
      headers: { accept: 'application/json', authorization: `Bearer ${apiKey}` },
    });
    body = await response.text();
    if (!response.ok) return { status: 'execution_failed', facts: [], fetchCount: 1 };
  } catch {
    return { status: 'execution_failed', facts: [], fetchCount: 1 };
  }
  const allowed = new Set((input.scopeGrant.boundaries.allowedHosts ?? []).map((host) => host.toLowerCase()));
  const facts: ObservedFact[] = [];
  const seen = new Set<string>();
  for (const match of body.matchAll(/https:\/\/[A-Za-z0-9._:-]+\/[^\s"'<>]*/g)) {
    const url = match[0];
    if (!url || seen.has(url) || !body.includes(url)) continue;
    const host = hostOf(url);
    if (!host || !allowed.has(host)) continue;
    seen.add(url);
    const fact = tryBuildObservedFact({
      factKind: 'observed_search_index_url',
      value: url,
      observationText: body,
      sourceUrl: `https://${siteHost}/`,
      observationKind: 'url',
      lineage: input.lineage,
      observedAt: input.observedAt,
      sourceLabel: 'search_index',
    });
    if (fact) facts.push(fact);
    if (facts.length >= 20) break;
  }
  return {
    status: facts.length > 0 ? 'observed' : 'empty',
    facts: Object.freeze(facts),
    fetchCount: 1,
  };
}
