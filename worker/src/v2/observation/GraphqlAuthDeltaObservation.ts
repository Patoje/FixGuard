/**
 * F6.5 — read-only GraphQL auth delta.
 * Already-observed endpoint. Anon vs identity A. Identity B is optional.
 * No mutation, no introspection, no severity.
 */

import { createHash } from 'node:crypto';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type {
  AuthorizedExecutionLineageTuple,
  IdorHttpProbeTransport,
  ProbeAuthContext,
} from '../detection/DetectionContracts.js';
import { runAdapterPreflight } from '../recon/adapters/AdapterPreflightPipeline.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import {
  formatAnonSessionGetDeltaValue,
  type ObservedFact,
} from './ObservedFactContracts.js';
import { tryBuildObservedFact } from './ObservedFactCatalogService.js';

function bodyHash(body: string): string {
  return createHash('sha256').update(body).digest('hex').slice(0, 16);
}

const OPERATION_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,80}$/;

function readQuery(operationName: string): string {
  return `{ ${operationName} }`;
}

async function readGet(input: {
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly transport: IdorHttpProbeTransport;
}): Promise<{ readonly statusCode: number; readonly bodyHash: string }> {
  const response = await input.transport({
    url: input.url,
    method: 'GET',
    headers: input.headers,
    timeoutMs: 8000,
  });
  return { statusCode: response.statusCode, bodyHash: bodyHash(response.bodyText) };
}

export async function observeGraphqlAuthDelta(input: {
  readonly endpointUrl: string;
  readonly operationName?: string;
  readonly identityA?: ProbeAuthContext;
  readonly identityB?: ProbeAuthContext;
  readonly verifiedAuthorizationDecision?: VerifiedAuthorizationDecision;
  readonly scopeGrant: AuthorizedScopeGrant;
  readonly lineage: AuthorizedExecutionLineageTuple;
  readonly transport: IdorHttpProbeTransport;
  readonly dnsResolver?: PreSpawnDnsResolver;
  readonly observedAt: string;
}): Promise<{
  readonly fact: ObservedFact | null;
  readonly requestCount: number;
  readonly reasonCode: string;
  readonly createsFinding: false;
  readonly severity: undefined;
}> {
  const none = {
    fact: null,
    requestCount: 0,
    createsFinding: false as const,
    severity: undefined,
  };
  const operationName = input.operationName?.trim() ?? '';
  if (!OPERATION_NAME_RE.test(operationName)) {
    return { ...none, reasonCode: 'operation_missing' };
  }
  const queryUrl = new URL(input.endpointUrl);
  queryUrl.searchParams.set('query', readQuery(operationName));
  if (!input.verifiedAuthorizationDecision || !input.identityA) {
    return { ...none, reasonCode: 'authorization_missing' };
  }
  const preflight = await runAdapterPreflight({
    target: input.endpointUrl,
    targetKind: 'url',
    verifiedAuthorizationDecision: input.verifiedAuthorizationDecision,
    authorizedScopeGrant: input.scopeGrant,
    lineage: input.lineage,
    requiredPermissions: ['activeValidation', 'authenticatedTesting', 'lightValidation'],
    missingPermissionReason: 'Scope grant does not permit GraphQL auth delta',
    dnsResolver: input.dnsResolver,
  });
  if (!preflight.ok) {
    return { ...none, reasonCode: preflight.reasonCode ?? 'preflight_denied' };
  }
  const anon = await readGet({
    url: queryUrl.toString(),
    headers: {},
    transport: input.transport,
  });
  const session = await readGet({
    url: queryUrl.toString(),
    headers: input.identityA.headers ?? {},
    transport: input.transport,
  });
  let requestCount = 2;
  if (input.identityB) {
    await readGet({
      url: queryUrl.toString(),
      headers: input.identityB.headers ?? {},
      transport: input.transport,
    });
    requestCount += 1;
  }
  const value = formatAnonSessionGetDeltaValue({
    anonStatus: anon.statusCode,
    sessionStatus: session.statusCode,
    anonBodyHash: anon.bodyHash,
    sessionBodyHash: session.bodyHash,
    interfered: false,
  });
  const fact = tryBuildObservedFact({
    factKind: 'graphql_auth_delta',
    value,
    observationText: `${input.endpointUrl} ${value}`,
    sourceUrl: input.endpointUrl,
    observationKind: 'differential_get',
    lineage: input.lineage,
    observedAt: input.observedAt,
    sourceLabel: 'graphql_auth_delta',
  });
  return {
    fact,
    requestCount,
    reasonCode: 'graphql_auth_delta_observed',
    createsFinding: false,
    severity: undefined,
  };
}
