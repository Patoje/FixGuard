/**
 * F5.3 / F5.4 — exact-path well-known GETs.
 * No redirect follow. Preflight denial issues zero GETs.
 * security.txt records presence only. OpenID/OAuth records issuer or
 * authorization_endpoint only when that string is in the JSON and the host
 * is in allowedHosts.
 */

import type { VerifiedAuthorizationDecision } from '../../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
} from '../../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../adapters/AdapterPreflightPipeline.js';
import { tryBuildObservedFact } from '../../observation/ObservedFactCatalogService.js';
import type { ObservedFact } from '../../observation/ObservedFactContracts.js';
import {
  defaultDocumentCopyDirectory,
  observeDownloadedDocument,
} from '../../observation/DocumentMetadataReader.js';

const SECURITY_TXT_PATH = '/.well-known/security.txt';
const OPENID_PATH = '/.well-known/openid-configuration';
const OAUTH_PATH = '/.well-known/oauth-authorization-server';

function hostAllowed(host: string, grant: AuthorizedScopeGrant): boolean {
  const allowed = grant.boundaries.allowedHosts ?? [];
  const normalized = host.toLowerCase();
  return allowed.some((entry) => entry.toLowerCase() === normalized);
}

async function getExact(input: {
  readonly url: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
}): Promise<{
  readonly denied: boolean;
  readonly statusCode: number;
  readonly bodyText: string;
  readonly contentType?: string;
  readonly fetched: boolean;
}> {
  const parsed = new URL(input.url);
  if (parsed.search !== '' || parsed.hash !== '') {
    return { denied: true, statusCode: 0, bodyText: '', fetched: false };
  }
  const preflight = await runAdapterPreflight({
    target: input.url,
    targetKind: 'url',
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    authorizedScopeGrant: input.scopeGrant,
    lineage: input.lineage,
    requiredPermissions: ['endpointDiscovery', 'passiveRecon'],
    missingPermissionReason: 'Scope grant does not permit well-known GET',
    dnsResolver: input.dnsResolver,
  });
  if (!preflight.ok) {
    return { denied: true, statusCode: 0, bodyText: '', fetched: false };
  }
  const response = await input.transport({
    url: input.url,
    method: 'GET',
    headers: { accept: 'application/json, text/plain' },
    timeoutMs: 8000,
  });
  if (response.statusCode >= 300 && response.statusCode < 400) {
    return {
      denied: false,
      statusCode: response.statusCode,
      bodyText: '',
      contentType: response.headers['content-type'],
      fetched: true,
    };
  }
  return {
    denied: false,
    statusCode: response.statusCode,
    bodyText: response.bodyText,
    contentType: response.headers['content-type'],
    fetched: true,
  };
}

function retainGetDocument(input: {
  readonly url: string;
  readonly statusCode: number;
  readonly contentType?: string;
  readonly body: string;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly observedAt: string;
}): { readonly fact: ObservedFact | null; readonly filePath: string | null } {
  return observeDownloadedDocument({
    downloaded: true,
    url: input.url,
    method: 'GET',
    statusCode: input.statusCode,
    contentType: input.contentType,
    body: input.body,
    scopeGrant: input.scopeGrant,
    lineage: input.lineage,
    observedAt: input.observedAt,
    directory: defaultDocumentCopyDirectory(),
  });
}

export async function inspectSecurityTxt(input: {
  readonly originUrl: string;
  readonly verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
}): Promise<{
  readonly fact: ObservedFact | null;
  readonly documentFact: ObservedFact | null;
  readonly documentFilePath: string | null;
  readonly requestCount: number;
  readonly status: 'observed' | 'preflight_denied' | 'skipped';
}> {
  let origin = '';
  try {
    origin = new URL(input.originUrl).origin;
  } catch {
    return { fact: null, documentFact: null, documentFilePath: null, requestCount: 0, status: 'skipped' };
  }
  const url = `${origin}${SECURITY_TXT_PATH}`;
  const response = await getExact({ ...input, url });
  if (response.denied) {
    return { fact: null, documentFact: null, documentFilePath: null, requestCount: 0, status: 'preflight_denied' };
  }
  const retained = retainGetDocument({
    url,
    statusCode: response.statusCode,
    contentType: response.contentType,
    body: response.bodyText,
    scopeGrant: input.scopeGrant,
    lineage: input.lineage,
    observedAt: input.observedAt,
  });
  const reachable = response.statusCode >= 200 && response.statusCode < 300;
  const contact = reachable && /(?:^|\n)\s*Contact\s*:/i.test(response.bodyText);
  const value = `path=${SECURITY_TXT_PATH};reachable=${reachable ? 'true' : 'false'};contact=${contact ? 'true' : 'false'}`;
  const observationText = `${url}\n${value}`;
  const fact = tryBuildObservedFact({
    factKind: 'observed_well_known',
    value,
    observationText,
    sourceUrl: url,
    observationKind: 'http_body',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'security_txt',
  });
  return {
    fact,
    documentFact: retained.fact,
    documentFilePath: retained.filePath,
    requestCount: 1,
    status: 'observed',
  };
}

function scopedEndpoint(jsonText: string, key: 'issuer' | 'authorization_endpoint', grant: AuthorizedScopeGrant): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonText);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const raw = (parsed as Record<string, unknown>)[key];
  if (typeof raw !== 'string' || !jsonText.includes(raw)) return null;
  let host = '';
  try {
    host = new URL(raw).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!hostAllowed(host, grant)) return null;
  return raw;
}

export async function inspectOpenIdAndOAuth(input: {
  readonly originUrl: string;
  readonly authHosts?: readonly string[];
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
  let originHost = '';
  let origin = '';
  try {
    const parsed = new URL(input.originUrl);
    origin = parsed.origin;
    originHost = parsed.hostname.toLowerCase();
  } catch {
    return { facts: [], requestCount: 0, status: 'skipped' };
  }
  const hosts = [originHost];
  for (const host of input.authHosts ?? []) {
    const normalized = host.toLowerCase();
    if (!hostAllowed(normalized, input.scopeGrant)) continue;
    if (!hosts.includes(normalized)) hosts.push(normalized);
  }
  const facts: ObservedFact[] = [];
  let requestCount = 0;
  let denied = false;
  for (const host of hosts) {
    let hostGets = 0;
    for (const path of [OPENID_PATH, OAUTH_PATH] as const) {
      if (hostGets >= 2) break;
      const url = `https://${host}${path}`;
      if (host === originHost) {
        const originUrl = `${origin}${path}`;
        const response = await getExact({ ...input, url: originUrl });
        if (response.denied) {
          denied = true;
          continue;
        }
        requestCount += 1;
        hostGets += 1;
        const fact = wellKnownFact(originUrl, path, response, input);
        if (fact) facts.push(fact);
        const retained = retainGetDocument({
          url: originUrl,
          statusCode: response.statusCode,
          contentType: response.contentType,
          body: response.bodyText,
          scopeGrant: input.scopeGrant,
          lineage: input.lineage,
          observedAt: input.observedAt,
        });
        if (retained.fact) facts.push(retained.fact);
        continue;
      }
      const response = await getExact({ ...input, url });
      if (response.denied) {
        denied = true;
        continue;
      }
      requestCount += 1;
      hostGets += 1;
      const fact = wellKnownFact(url, path, response, input);
      if (fact) facts.push(fact);
      const retained = retainGetDocument({
        url,
        statusCode: response.statusCode,
        contentType: response.contentType,
        body: response.bodyText,
        scopeGrant: input.scopeGrant,
        lineage: input.lineage,
        observedAt: input.observedAt,
      });
      if (retained.fact) facts.push(retained.fact);
    }
  }
  if (requestCount === 0 && denied) {
    return { facts: [], requestCount: 0, status: 'preflight_denied' };
  }
  return { facts: Object.freeze(facts), requestCount, status: 'observed' };
}

function wellKnownFact(
  url: string,
  path: string,
  response: { readonly statusCode: number; readonly bodyText: string },
  input: {
    readonly scopeGrant: AuthorizedScopeGrant;
    readonly lineage: AuthorizedExecutionLineageTuple;
    readonly observedAt: string;
  }
): ObservedFact | null {
  const reachable = response.statusCode >= 200 && response.statusCode < 300 && response.statusCode !== 301 && response.statusCode !== 302 && response.statusCode !== 303 && response.statusCode !== 307 && response.statusCode !== 308;
  const parts = [`path=${path}`, `reachable=${reachable ? 'true' : 'false'}`];
  if (reachable && path === OPENID_PATH) {
    const issuer = scopedEndpoint(response.bodyText, 'issuer', input.scopeGrant);
    if (issuer) parts.push(`issuer=${issuer}`);
  }
  if (reachable && path === OAUTH_PATH) {
    const endpoint = scopedEndpoint(response.bodyText, 'authorization_endpoint', input.scopeGrant);
    if (endpoint) parts.push(`authorization_endpoint=${endpoint}`);
  }
  const value = parts.join(';');
  return tryBuildObservedFact({
    factKind: 'observed_well_known',
    value,
    observationText: `${url}\n${value}`,
    sourceUrl: url,
    observationKind: 'http_body',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'well_known',
  });
}
