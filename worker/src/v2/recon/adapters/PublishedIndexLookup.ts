/**
 * F6.2 — published host index (Shodan or Censys).
 * No API key means zero calls. No on-demand scan and no other organizations.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../../detection/DetectionContracts.js';
import { runAdapterPreflight } from './AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from './AdapterPreflightPipeline.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';

export interface PublishedIndexLookupResult {
  readonly status: 'observed' | 'preflight_denied' | 'credentials_absent' | 'empty' | 'execution_failed';
  readonly fact: ObservedFact | null;
  readonly fetchCount: number;
}

function readKey(): { readonly vendor: 'shodan' | 'censys'; readonly key: string } | null {
  const shodan = process.env.SHODAN_API_KEY?.trim() ?? '';
  if (shodan.length > 0) return { vendor: 'shodan', key: shodan };
  const censysId = process.env.CENSYS_API_ID?.trim() ?? '';
  const censysSecret = process.env.CENSYS_API_SECRET?.trim() ?? '';
  if (censysId.length > 0 && censysSecret.length > 0) {
    return { vendor: 'censys', key: `${censysId}:${censysSecret}` };
  }
  return null;
}

export async function lookupPublishedHostIndex(input: {
  readonly host: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly fetchImpl?: typeof fetch;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
  readonly apiKey?: string;
  readonly vendor?: 'shodan' | 'censys';
}): Promise<PublishedIndexLookupResult> {
  const host = input.host.trim().toLowerCase();
  const preflight = await runAdapterPreflight({
    target: host,
    targetKind: 'fqdn',
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    authorizedScopeGrant: input.scopeGrant,
    lineage: input.lineage,
    permissionCheck: (ps) => Boolean(ps.passiveRecon || ps.endpointDiscovery),
    missingPermissionReason: 'Scope grant does not permit published index lookup',
    dnsResolver: input.dnsResolver,
  });
  if (!preflight.ok) {
    return { status: 'preflight_denied', fact: null, fetchCount: 0 };
  }
  const fromEnv = readKey();
  const vendor = input.vendor ?? fromEnv?.vendor;
  const apiKey = input.apiKey ?? fromEnv?.key;
  if (!vendor || !apiKey) {
    return { status: 'credentials_absent', fact: null, fetchCount: 0 };
  }
  const fetchImpl = input.fetchImpl ?? fetch;
  const url =
    vendor === 'shodan'
      ? `https://api.shodan.io/dns/domain/${encodeURIComponent(host)}?key=${encodeURIComponent(apiKey)}`
      : `https://search.censys.io/api/v2/hosts/search?q=${encodeURIComponent(host)}`;
  let body = '';
  try {
    const headers: Record<string, string> = { accept: 'application/json' };
    if (vendor === 'censys') {
      headers.authorization = `Basic ${Buffer.from(apiKey).toString('base64')}`;
    }
    const response = await fetchImpl(url, { headers });
    body = await response.text();
    if (!response.ok) return { status: 'execution_failed', fact: null, fetchCount: 1 };
  } catch {
    return { status: 'execution_failed', fact: null, fetchCount: 1 };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { status: 'execution_failed', fact: null, fetchCount: 1 };
  }
  const parts: string[] = [];
  const ports = new Set<string>();
  const products = new Set<string>();
  const visit = (value: unknown, inForeignHost: boolean): void => {
    if (inForeignHost || value === null || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, false);
      return;
    }
    const record = value as Record<string, unknown>;
    const otherHost =
      typeof record.ip_str === 'string'
        ? record.ip_str
        : typeof record.hostname === 'string'
          ? record.hostname
          : typeof record.domain === 'string'
            ? record.domain
            : '';
    if (otherHost.length > 0 && otherHost.toLowerCase() !== host && !host.endsWith(otherHost.toLowerCase())) {
      return;
    }
    if (typeof record.port === 'number' && body.includes(String(record.port))) {
      ports.add(String(record.port));
    }
    if (typeof record.product === 'string' && body.includes(record.product)) {
      products.add(record.product);
    }
    for (const nested of Object.values(record)) visit(nested, false);
  };
  visit(parsed, false);
  for (const port of ports) parts.push(port);
  for (const product of products) {
    if (!product.includes(';')) parts.push(product);
  }
  if (parts.length === 0) return { status: 'empty', fact: null, fetchCount: 1 };
  const value = parts.join(';');
  const fact = tryBuildObservedFact({
    factKind: 'observed_published_index',
    value,
    observationText: body,
    sourceUrl: `https://${host}/`,
    observationKind: 'published_record',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: vendor,
  });
  return { status: fact ? 'observed' : 'empty', fact, fetchCount: 1 };
}
