/**
 * F6 — published data and the read-only test gap.
 * External lookups fail closed without a key. The document reader opens no socket.
 */

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { Socket, type SocketConnectOpts } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { AuthorizedExecutionLineageTuple, IdorHttpProbeTransport } from '../detection/DetectionContracts.js';
import { lookupAuthorizedDomainRdap } from '../recon/adapters/RdapLookup.js';
import { lookupPublishedHostIndex } from '../recon/adapters/PublishedIndexLookup.js';
import { lookupAuthorizedSearchIndex } from '../recon/adapters/SearchIndexLookup.js';
import {
  MAX_RETAINED_DOCUMENT_BYTES,
  observeDownloadedDocument,
  readLocalDocumentMetadata,
  retainBoundedDocumentCopy,
} from '../observation/DocumentMetadataReader.js';
import { LOCAL_PUBLIC_ADVISORIES, observePublicAdvisory } from '../observation/PublicAdvisoryObservation.js';
import { inspectSecurityTxt } from '../recon/deep/WellKnownInspectService.js';
import { observeGraphqlAuthDelta } from '../observation/GraphqlAuthDeltaObservation.js';
import { createGraphqlAuthDeltaCapability } from '../attack-execution/capabilities/GraphqlAuthDeltaCapability.js';
import { AttackCapabilityRegistry } from '../attack-execution/AttackCapabilityRegistry.js';
import type { AttackCapabilityInvocationContext } from '../attack-execution/AttackExecutionContracts.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import { ATTACK_PLANNING_CONTRACT_VERSION } from '../attack-planning/AttackPlanContracts.js';

const DOMAIN = 'published.example.com';
const OBSERVED_AT = '2026-09-28T12:00:00.000Z';
const ENDPOINT = `https://${DOMAIN}/graphql`;

function lineage(): AuthorizedExecutionLineageTuple {
  return {
    assessmentId: 'asm_f6_001',
    scanId: 'scn_f6_001',
    authorizationGrantId: 'grnt_f6_001',
    authorizationDecisionId: 'dec_f6_001',
    actorId: 'act_f6_001',
  };
}

function scopeGrant(discover = true): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grnt_f6_001',
    scanId: 'scn_f6_001',
    issuedAt: '2026-09-28T11:00:00.000Z',
    expiresAt: '2026-09-29T11:00:00.000Z',
    subject: { targetKind: 'domain', domain: DOMAIN },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: `Authorized scope for ${DOMAIN}`,
    },
    permissionSet: {
      passiveRecon: discover,
      technologyFingerprinting: discover,
      endpointDiscovery: discover,
      activeCrawling: false,
      authenticatedTesting: discover,
      lightValidation: discover,
      activeValidation: discover,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: [DOMAIN],
      allowedHosts: [DOMAIN, '93.184.216.34'],
      allowedOrigins: [`https://${DOMAIN}`],
      allowedMethods: ['GET', 'HEAD'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: {
      createsRealFindings: false,
      createsPersistedEvidence: false,
      confirmsVulnerabilities: false,
      makesRiskClaims: false,
      makesSeverityClaims: false,
      makesImpactClaims: false,
      executesNetwork: false,
      executesTools: false,
      persistsData: false,
    },
  };
}

function establish(grant: AuthorizedScopeGrant) {
  const authRes = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asm_f6_001',
      scanId: grant.scanId,
      authorizationDecisionId: 'dec_f6_001',
      authorizedActor: { actorId: 'act_f6_001', actorType: 'human' },
      decision: 'authorized',
      decidedAt: OBSERVED_AT,
      scopeGrant: grant,
    },
    OBSERVED_AT
  );
  if (authRes.status !== 'established') {
    throw new Error(`auth not established: ${authRes.reasonCode}`);
  }
  return authRes.decision;
}

async function rdapOneQuery(): Promise<void> {
  let fetches = 0;
  const denied = await lookupAuthorizedDomainRdap({
    domain: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant(false)),
    scopeGrant: scopeGrant(false),
    lineage: lineage(),
    fetchImpl: async () => {
      fetches += 1;
      throw new Error('fetch must not run');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(denied.status, 'preflight_denied');
  assert.equal(denied.fetchCount, 0);
  assert.equal(fetches, 0);

  const foreign = await lookupAuthorizedDomainRdap({
    domain: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    fetchImpl: async () => {
      fetches += 1;
      return new Response(JSON.stringify({ ldhName: 'other.example.net', nameservers: [{ ldhName: 'ns1.other.example.net' }] }), { status: 200 });
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(foreign.fact, null);
  assert.equal(foreign.fetchCount, 1);

  const body = JSON.stringify({
    ldhName: DOMAIN,
    entities: [{ roles: ['registrar'], vcardArray: ['vcard', ['fn', {}, 'text', 'Example Registrar']] }],
    events: [{ eventAction: 'registration', eventDate: '2010-01-02T00:00:00Z' }],
    nameservers: [{ ldhName: `ns1.${DOMAIN}` }],
    remarks: [{ description: ['other.example.net'] }],
  });
  const observed = await lookupAuthorizedDomainRdap({
    domain: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    fetchImpl: async (input) => {
      fetches += 1;
      assert.equal(String(input), `https://rdap.org/domain/${DOMAIN}`);
      return new Response(body, { status: 200 });
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(observed.fetchCount, 1);
  assert.ok(observed.fact);
  assert.equal(observed.fact.value.includes('Example Registrar'), true);
  assert.equal(observed.fact.value.includes('2010-01-02T00:00:00Z'), true);
  assert.equal(observed.fact.value.includes(`ns1.${DOMAIN}`), true);
  assert.equal(observed.fact.value.includes('other.example.net'), false);
}

async function publishedIndexFailClosed(): Promise<void> {
  let fetches = 0;
  const absent = await lookupPublishedHostIndex({
    host: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    apiKey: '',
    vendor: 'shodan',
    fetchImpl: async () => {
      fetches += 1;
      throw new Error('API must not be called');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(absent.status, 'credentials_absent');
  assert.equal(absent.fetchCount, 0);
  assert.equal(fetches, 0);

  const denied = await lookupPublishedHostIndex({
    host: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant(false)),
    scopeGrant: scopeGrant(false),
    lineage: lineage(),
    apiKey: 'present-for-deny',
    vendor: 'shodan',
    fetchImpl: async () => {
      fetches += 1;
      throw new Error('API must not be called');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(denied.status, 'preflight_denied');
  assert.equal(denied.fetchCount, 0);
  assert.equal(fetches, 0);

  const index = JSON.stringify({
    ports: [
      { port: 443, product: 'nginx' },
      { port: 22, product: 'openssh', hostname: 'other.example.net' },
    ],
  });
  const observed = await lookupPublishedHostIndex({
    host: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    apiKey: 'index-key',
    vendor: 'shodan',
    fetchImpl: async () => {
      fetches += 1;
      return new Response(index, { status: 200 });
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(fetches, 1);
  assert.ok(observed.fact);
  assert.equal(observed.fact.value.includes('443'), true);
  assert.equal(observed.fact.value.includes('nginx'), true);
  assert.equal(observed.fact.value.includes('openssh'), false);
  assert.equal(JSON.stringify(observed.fact).includes('index-key'), false);
}

function assertNoSocket(run: () => void): void {
  const original = Socket.prototype.connect;
  let opened = 0;
  function countingConnect(this: Socket, options: SocketConnectOpts, connectionListener?: () => void): Socket;
  function countingConnect(this: Socket, port: number, host: string, connectionListener?: () => void): Socket;
  function countingConnect(this: Socket, port: number, connectionListener?: () => void): Socket;
  function countingConnect(this: Socket, path: string, connectionListener?: () => void): Socket;
  function countingConnect(this: Socket): Socket {
    opened += 1;
    return this;
  }
  Socket.prototype.connect = countingConnect;
  try {
    run();
  } finally {
    Socket.prototype.connect = original;
  }
  assert.equal(opened, 0);
}

function documentMetadataFromLocalBytes(): void {
  assert.equal(retainBoundedDocumentCopy({ downloaded: false, url: `https://${DOMAIN}/doc`, bytes: null }), null);
  const dir = mkdtempSync(join(tmpdir(), 'fixguard-f6-'));
  const filePath = join(dir, 'note.txt');
  writeFileSync(filePath, 'Title: Quarterly Review\nAuthor: Ada\n');
  const read = readLocalDocumentMetadata({
    filePath,
    sourceUrl: `https://${DOMAIN}/note.txt`,
    lineage: lineage(),
    observedAt: OBSERVED_AT,
  });
  assert.ok(read.fact);
  assert.equal(read.fact.value.includes('Title: Quarterly Review'), true);
  assert.equal(read.fact.value.includes('Author: Ada'), true);
  assert.equal(read.fact.value.includes('Producer'), false);
}

function inScopeDownloadedDocumentRetainsCopy(): void {
  const dir = mkdtempSync(join(tmpdir(), 'fixguard-f6-doc-'));
  const url = `https://${DOMAIN}/files/quarterly.pdf`;
  const body = 'Title: Quarterly Review\nAuthor: Ada\n';
  const retained = observeDownloadedDocument({
    downloaded: true,
    url,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: dir,
  });
  assert.ok(retained.filePath);
  assert.equal(existsSync(retained.filePath), true);
  const stored = readFileSync(retained.filePath, 'utf8');
  assert.equal(stored.includes('Title: Quarterly Review'), true);
  assert.ok(retained.fact);
  assert.equal(retained.fact.factKind, 'observed_document_metadata');
  assert.equal(retained.fact.value.includes('Title: Quarterly Review'), true);
  assert.equal(retained.fact.value.includes('Author: Ada'), true);
  assert.equal(stored.includes('Title: Quarterly Review'), true);

  const image = observeDownloadedDocument({
    downloaded: true,
    url: `https://${DOMAIN}/scan.png`,
    method: 'GET',
    statusCode: 200,
    contentType: 'image/png',
    body: 'Title: Floor Plan\nAuthor: Ada\n',
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: dir,
  });
  assert.ok(image.filePath);
  assert.ok(image.fact);
  assert.equal(image.fact.value.includes('Title: Floor Plan'), true);
  assert.equal(readFileSync(image.filePath, 'utf8').includes('Title: Floor Plan'), true);

  const htmlDir = mkdtempSync(join(tmpdir(), 'fixguard-f6-html-'));
  const html = observeDownloadedDocument({
    downloaded: true,
    url: `https://${DOMAIN}/`,
    method: 'GET',
    statusCode: 200,
    contentType: 'text/html; charset=utf-8',
    body: '<html>Title: Quarterly Review\nAuthor: Ada\n',
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: htmlDir,
  });
  assert.equal(html.fact, null);
  assert.equal(html.filePath, null);
  assert.equal(readdirSync(htmlDir).length, 0);

  const shell = observeDownloadedDocument({
    downloaded: true,
    url,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body: '<html>Title: Quarterly Review\nAuthor: Ada\n',
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: htmlDir,
  });
  assert.equal(shell.fact, null);
  assert.equal(shell.filePath, null);
  assert.equal(readdirSync(htmlDir).length, 0);

  const cookie = observeDownloadedDocument({
    downloaded: true,
    url,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body: 'Set-Cookie: session=secret\nTitle: Quarterly Review\n',
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: htmlDir,
  });
  assert.equal(cookie.filePath, null);
  assert.equal(readdirSync(htmlDir).length, 0);

  const missingDir = mkdtempSync(join(tmpdir(), 'fixguard-f6-miss-'));
  const missing = observeDownloadedDocument({
    downloaded: true,
    url,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body: null,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: missingDir,
  });
  assert.equal(missing.fact, null);
  assert.equal(missing.filePath, null);
  assert.equal(readdirSync(missingDir).length, 0);

  const absent = observeDownloadedDocument({
    downloaded: false,
    url,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: missingDir,
  });
  assert.equal(absent.fact, null);
  assert.equal(absent.filePath, null);
  assert.equal(readdirSync(missingDir).length, 0);

  const foreignDir = mkdtempSync(join(tmpdir(), 'fixguard-f6-foreign-'));
  const foreign = observeDownloadedDocument({
    downloaded: true,
    url: 'https://other.example.net/secret.pdf',
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: foreignDir,
  });
  assert.equal(foreign.fact, null);
  assert.equal(foreign.filePath, null);
  assert.equal(readdirSync(foreignDir).length, 0);

  const oversized = new Uint8Array(MAX_RETAINED_DOCUMENT_BYTES + 32);
  const prefix = new TextEncoder().encode('Title: Cap Check\nAuthor: Ada\n');
  oversized.set(prefix, 0);
  const capped = observeDownloadedDocument({
    downloaded: true,
    url: `https://${DOMAIN}/files/large.pdf`,
    method: 'GET',
    statusCode: 200,
    contentType: 'application/pdf',
    body: oversized,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    observedAt: OBSERVED_AT,
    directory: dir,
  });
  assert.ok(capped.filePath);
  assert.equal(statSync(capped.filePath).size, MAX_RETAINED_DOCUMENT_BYTES);
  assert.ok(capped.fact);
  assert.equal(capped.fact.value.includes('Title: Cap Check'), true);
  assert.equal(readFileSync(capped.filePath).includes(Buffer.from('Title: Cap Check')), true);
}

async function searchIndexDropsForeignHosts(): Promise<void> {
  let fetches = 0;
  const absent = await lookupAuthorizedSearchIndex({
    siteHost: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    endpointUrl: '',
    apiKey: '',
    fetchImpl: async () => {
      fetches += 1;
      throw new Error('search must not be called');
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(absent.status, 'credentials_absent');
  assert.equal(absent.fetchCount, 0);
  assert.equal(fetches, 0);

  const body = `https://${DOMAIN}/docs/guide https://other.example.net/stolen`;
  const observed = await lookupAuthorizedSearchIndex({
    siteHost: DOMAIN,
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    endpointUrl: 'https://search.example/index',
    apiKey: 'search-key',
    fetchImpl: async () => {
      fetches += 1;
      return new Response(body, { status: 200 });
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(fetches, 1);
  assert.equal(observed.facts.length, 1);
  assert.equal(observed.facts[0]?.value, `https://${DOMAIN}/docs/guide`);
  assert.equal(JSON.stringify(observed.facts).includes('other.example.net'), false);
}

function graphqlPlan(): AttackPlan {
  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: 'pln_f6_gql',
    assessmentId: 'asm_f6_001',
    scanId: 'scn_f6_001',
    title: 'GraphQL auth delta',
    reasoning: 'already observed endpoint',
    capability: 'graphql_auth_delta',
    blastRadius: 'user_scoped',
    capabilityGained: 'read_authenticated',
    status: 'ready_for_authorization',
    sourceFindingIds: [],
    sourceFindingTypes: [],
    prerequisites: [],
    steps: [
      {
        stepId: 'step_f6_gql',
        ordinal: 1,
        title: 'GET delta',
        description: 'anon versus identity A',
        status: 'ready',
        requiredPermissions: ['active_http_get'],
      },
    ],
    executable: false,
    planOrigin: 'observed_surface',
    targetUrl: ENDPOINT,
    lineage: lineage(),
    createdAt: OBSERVED_AT,
  };
}

async function graphqlDeltaReadOnly(): Promise<void> {
  const registry = AttackCapabilityRegistry.createDefault();
  assert.ok(registry.get('graphql_auth_delta'));
  assert.ok(registry.get('auth_boundary_differential'));
  let calls = 0;
  const transport: IdorHttpProbeTransport = async (request) => {
    calls += 1;
    assert.equal(request.method, 'GET');
    assert.equal(request.url.includes('introspection'), false);
    assert.equal(request.url.includes('mutation'), false);
    assert.equal(new URL(request.url).searchParams.get('query'), '{ orders }');
    return {
      statusCode: calls === 1 ? 401 : 200,
      headers: {},
      bodyText: calls === 1 ? '{}' : '{"data":1}',
      responseTimeMs: 1,
    };
  };
  const missing = await observeGraphqlAuthDelta({
    endpointUrl: ENDPOINT,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport,
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(missing.requestCount, 0);
  assert.equal(missing.fact, null);
  assert.equal(missing.severity, undefined);
  assert.equal(calls, 0);

  const plan = graphqlPlan();
  const token = Object.freeze({
    contractVersion: ATTACK_AUTHORIZATION_CONTRACT_VERSION,
    kind: 'attack_authorization_token' as const,
    planId: plan.planId,
    assessmentId: plan.assessmentId,
    blastRadiusClass: 'read_escalated' as const,
    authorizationLevel: 'hitl_plan_approval' as const,
    authorizedBy: 'act_f6_001',
    authorizedAt: OBSERVED_AT,
    [Symbol.toStringTag]: 'AttackAuthorizationToken',
  }) as AttackAuthorizationToken;
  const ctx: AttackCapabilityInvocationContext = {
    plan,
    step: { ...plan.steps[0]!, blastRadiusClass: 'read_escalated' },
    token,
    targetHost: DOMAIN,
    targetUrl: ENDPOINT,
    scopeGrant: scopeGrant(),
    findings: [],
    primaryIdentity: { identityId: 'id_a', headers: { authorization: 'Bearer operator_a' } },
    transport,
    dnsResolver: async () => ['93.184.216.34'],
  };
  const blocked = await createGraphqlAuthDeltaCapability().execute(ctx);
  assert.equal(blocked.outcome, 'failed');
  assert.equal(calls, 0);

  const observed = await observeGraphqlAuthDelta({
    endpointUrl: ENDPOINT,
    operationName: 'orders',
    identityA: { identityId: 'id_a', headers: { authorization: 'Bearer operator_a' } },
    verifiedAuthorizationDecision: establish(scopeGrant()),
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport,
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(observed.requestCount, 2);
  assert.equal(observed.createsFinding, false);
  assert.equal(observed.severity, undefined);
  assert.ok(observed.fact);
  assert.equal(observed.fact.value.includes('anon=401'), true);
  assert.equal(observed.fact.value.includes('session=200'), true);
  assert.equal(observed.fact.value.includes('anon_hash='), true);
  assert.equal(observed.fact.value.includes('session_hash='), true);
  assert.equal(JSON.stringify(observed).includes('severity'), false);
}

function advisoryFacts(input: {
  readonly product: string;
  readonly version: string | undefined;
  readonly advisories: readonly { product: string; version: string; advisoryId: string }[];
}): readonly { readonly factKind: string; readonly value: string }[] {
  const fact = observePublicAdvisory({
    product: input.product,
    version: input.version,
    advisories: input.advisories,
    lineage: lineage(),
    sourceUrl: `https://${DOMAIN}/`,
    observedAt: OBSERVED_AT,
  });
  return fact ? [fact] : [];
}

function advisoryOnlyForSeenVersion(): void {
  const listed = LOCAL_PUBLIC_ADVISORIES[0];
  assert.ok(listed);
  const none = advisoryFacts({
    product: listed.product,
    version: undefined,
    advisories: LOCAL_PUBLIC_ADVISORIES,
  });
  assert.equal(none.length, 0);
  const emptyList = advisoryFacts({
    product: listed.product,
    version: listed.version,
    advisories: [],
  });
  assert.equal(emptyList.filter((fact) => fact.factKind === 'observed_public_advisory').length, 0);
  const otherVersion = advisoryFacts({
    product: listed.product,
    version: '9.9.9',
    advisories: LOCAL_PUBLIC_ADVISORIES,
  });
  assert.equal(otherVersion.filter((fact) => fact.factKind === 'observed_public_advisory').length, 0);
  const matched = advisoryFacts({
    product: listed.product,
    version: listed.version,
    advisories: LOCAL_PUBLIC_ADVISORIES,
  });
  assert.equal(matched.length, 1);
  assert.equal(matched[0]?.factKind, 'observed_public_advisory');
  assert.equal(matched[0]?.value.includes(listed.advisoryId), true);
  const encoded = JSON.stringify(matched).toLowerCase();
  assert.equal(encoded.includes('metasploit'), false);
  assert.equal(encoded.includes('exploit-db'), false);
}

async function securityTxtGetRetainsPdfAlreadyInBody(): Promise<void> {
  const decision = establish(scopeGrant());
  const pdfBody = 'Title: Quarterly Review\nAuthor: Ada\n';
  let pdfCalls = 0;
  const pdf = await inspectSecurityTxt({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: decision,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: async () => {
      pdfCalls += 1;
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/pdf' },
        bodyText: pdfBody,
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(pdfCalls, 1);
  assert.equal(pdf.requestCount, 1);
  assert.ok(pdf.documentFilePath);
  assert.equal(existsSync(pdf.documentFilePath), true);
  assert.ok(pdf.documentFact);
  assert.equal(pdf.documentFact.factKind, 'observed_document_metadata');
  assert.equal(pdf.documentFact.value.includes('Title: Quarterly Review'), true);

  let htmlCalls = 0;
  const html = await inspectSecurityTxt({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: decision,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: async () => {
      htmlCalls += 1;
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html>Title: Quarterly Review\nAuthor: Ada\n',
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(htmlCalls, 1);
  assert.equal(html.documentFilePath, null);
  assert.equal(html.documentFact, null);

  let emptyCalls = 0;
  const empty = await inspectSecurityTxt({
    originUrl: `https://${DOMAIN}/`,
    verifiedAuthorizationDecision: decision,
    scopeGrant: scopeGrant(),
    lineage: lineage(),
    transport: async () => {
      emptyCalls += 1;
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/pdf' },
        bodyText: '',
        responseTimeMs: 1,
      };
    },
    dnsResolver: async () => ['93.184.216.34'],
    observedAt: OBSERVED_AT,
  });
  assert.equal(emptyCalls, 1);
  assert.equal(empty.documentFilePath, null);
  assert.equal(empty.documentFact, null);
}

async function main(): Promise<void> {
  await rdapOneQuery();
  await publishedIndexFailClosed();
  assertNoSocket(() => {
    documentMetadataFromLocalBytes();
    inScopeDownloadedDocumentRetainsCopy();
    advisoryOnlyForSeenVersion();
  });
  await securityTxtGetRetainsPdfAlreadyInBody();
  await searchIndexDropsForeignHosts();
  await graphqlDeltaReadOnly();
  console.log('[milestone_f6_published_osint_gap_smoke] ALL PASSED');
}

main().catch((err: unknown) => {
  console.error('[milestone_f6_published_osint_gap_smoke] FATAL', err);
  process.exit(1);
});
