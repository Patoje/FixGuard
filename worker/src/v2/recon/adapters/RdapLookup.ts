/**
 * F6.1 — one RDAP query for the authorized domain.
 * Preflight denial performs zero fetches. Other domains in the payload are ignored.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple } from '../../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';

export interface RdapLookupResult {
  readonly status: 'observed' | 'preflight_denied' | 'execution_failed' | 'empty';
  readonly fact: ObservedFact | null;
  readonly fetchCount: number;
}

function stringField(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

export async function lookupAuthorizedDomainRdap(input: {
  readonly domain: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly fetchImpl?: typeof fetch;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
}): Promise<RdapLookupResult> {
  const domain = input.domain.trim().toLowerCase().replace(/\.$/, '');
  const preflight = await runAdapterPreflight({
    target: domain,
    targetKind: 'fqdn',
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    authorizedScopeGrant: input.scopeGrant,
    lineage: input.lineage,
    permissionCheck: (ps) => Boolean(ps.endpointDiscovery || ps.passiveRecon),
    missingPermissionReason: 'Scope grant does not permit RDAP lookup',
    dnsResolver: input.dnsResolver,
  });
  if (!preflight.ok) {
    return { status: 'preflight_denied', fact: null, fetchCount: 0 };
  }
  const fetchImpl = input.fetchImpl ?? fetch;
  const url = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  let body = '';
  try {
    const response = await fetchImpl(url, { headers: { accept: 'application/rdap+json, application/json' } });
    body = await response.text();
    if (!response.ok) {
      return { status: 'execution_failed', fact: null, fetchCount: 1 };
    }
  } catch {
    return { status: 'execution_failed', fact: null, fetchCount: 1 };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { status: 'execution_failed', fact: null, fetchCount: 1 };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { status: 'empty', fact: null, fetchCount: 1 };
  }
  const record = parsed as Record<string, unknown>;
  const ldh = stringField(record.ldhName)?.toLowerCase();
  if (ldh && ldh !== domain) {
    return { status: 'empty', fact: null, fetchCount: 1 };
  }
  const parts: string[] = [];
  const entities = Array.isArray(record.entities) ? record.entities : [];
  for (const entity of entities) {
    if (entity === null || typeof entity !== 'object') continue;
    const roles = (entity as { roles?: unknown }).roles;
    if (!Array.isArray(roles) || !roles.includes('registrar')) continue;
    const vcard = (entity as { vcardArray?: unknown }).vcardArray;
    if (!Array.isArray(vcard)) continue;
    for (const row of vcard) {
      if (!Array.isArray(row) || row[0] !== 'fn') continue;
      const name = stringField(row[3]);
      if (name && body.includes(name)) parts.push(name);
    }
  }
  const events = Array.isArray(record.events) ? record.events : [];
  for (const event of events) {
    if (event === null || typeof event !== 'object') continue;
    const action = stringField((event as { eventAction?: unknown }).eventAction);
    const date = stringField((event as { eventDate?: unknown }).eventDate);
    if (!action || !date || !body.includes(date)) continue;
    if (action === 'registration' || action === 'expiration') parts.push(date);
  }
  const nameservers = Array.isArray(record.nameservers) ? record.nameservers : [];
  for (const ns of nameservers) {
    if (ns === null || typeof ns !== 'object') continue;
    const name = stringField((ns as { ldhName?: unknown }).ldhName)?.toLowerCase();
    if (!name || !body.toLowerCase().includes(name)) continue;
    if (name === domain) continue;
    parts.push(name);
  }
  if (parts.length === 0) {
    return { status: 'empty', fact: null, fetchCount: 1 };
  }
  const value = parts.join(';');
  const fact = tryBuildObservedFact({
    factKind: 'observed_registration',
    value,
    observationText: body,
    sourceUrl: url,
    observationKind: 'published_record',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'rdap',
  });
  return { status: fact ? 'observed' : 'empty', fact, fetchCount: 1 };
}
