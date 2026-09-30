/**
 * Phase 1 — probe inventory smoke.
 * Dedupes in-scope URLs, keeps the observed method, drops out-of-scope URLs,
 * and rejects malformed inventories. No network.
 */
import assert from 'node:assert/strict';
import process from 'node:process';
import {
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
  type OrchestratedAssessmentRecord,
} from '../application/OrchestratedAssessmentContracts.js';
import {
  buildProbeInventory,
  parseProbeInventory,
} from '../investigation/ProbeInventory.js';
import type { ProbeInventory } from '../investigation/ProbeInventoryContracts.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { getSafeClassification } from '../scope/AuthorizedScopePolicyService.js';
import { validateOrchestratedAssessmentRecord } from '../storage/OrchestratedAssessmentPersistenceValidation.js';

const lineage = {
  assessmentId: 'asmt_probe_inv_001',
  scanId: 'scan_probe_inv_001',
  authorizationGrantId: 'grant_probe_inv_001',
  authorizationDecisionId: 'dec_probe_inv_001',
  actorId: 'act_probe_inv_op',
} as const;

const observedAt = '2026-09-30T15:00:00.000Z';
const evaluatedAt = '2026-09-30T15:05:00.000Z';

function emptyObservations(): AggregatedReconObservations {
  return {
    subdomains: [],
    dnsRecords: [],
    ports: [],
    webObservations: [],
    tlsCertificates: [],
    urls: [],
    content: [],
    parameters: [],
    secrets: [],
  };
}

function scopeGrant(): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: '2026-09-30T15:00:00.000Z',
    expiresAt: '2026-09-30T16:00:00.000Z',
    subject: {
      targetKind: 'domain',
      domain: 'app.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized probe inventory smoke for app.example.com',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: false,
      activeValidation: false,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedOrigins: ['https://app.example.com'],
      allowedHosts: ['app.example.com'],
      allowedDomains: ['app.example.com'],
      allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
      deniedPathPatterns: [{ match: 'exact', pathTemplate: '/admin' }],
    },
    constraints: {
      allowLoginRequiredAreas: false,
      allowStateChangingRequests: false,
      allowCredentialUse: false,
      allowOobCallbacks: false,
      allowThirdPartyTargets: false,
    },
    classification: getSafeClassification(),
  };
}

function minimalRecord(probeInventory?: ProbeInventory): OrchestratedAssessmentRecord {
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    targetDomain: 'app.example.com',
    status: 'completed',
    lineage,
    stages: [],
    timing: { startedAt: observedAt },
    errorCount: 0,
    warningCount: 0,
    findings: [],
    recommendations: [],
  };
  if (probeInventory) {
    return { ...record, probeInventory };
  }
  return record;
}

function fail(error: unknown): never {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function main(): void {
  const grant = scopeGrant();
  const observations: AggregatedReconObservations = {
    ...emptyObservations(),
    urls: [
      {
        url: 'https://app.example.com/orders?id=1',
        host: 'app.example.com',
        path: '/orders',
        query: 'id=1',
        sources: ['gau'],
        discoveredAt: observedAt,
      },
      {
        url: 'https://app.example.com/orders?status=open',
        host: 'app.example.com',
        path: '/orders',
        query: 'status=open',
        sources: ['katana'],
        discoveredAt: observedAt,
      },
      {
        url: 'https://app.example.com/login',
        host: 'app.example.com',
        path: '/login',
        sources: ['katana'],
        discoveredAt: observedAt,
      },
      {
        url: 'https://evil.example/steal',
        host: 'evil.example',
        path: '/steal',
        sources: ['gau'],
        discoveredAt: observedAt,
      },
      {
        url: 'https://app.example.com/admin',
        host: 'app.example.com',
        path: '/admin',
        sources: ['gau'],
        discoveredAt: observedAt,
      },
      {
        url: 'https://cdn.app.example.com/asset',
        host: 'cdn.app.example.com',
        path: '/asset',
        sources: ['gau'],
        discoveredAt: observedAt,
      },
    ],
    webObservations: [
      {
        url: 'https://app.example.com/login',
        method: 'POST',
        statusCode: 200,
        technologies: [],
        discoveredAt: observedAt,
      },
    ],
    content: [
      {
        url: 'https://app.example.com/health',
        path: '/health',
        statusCode: 200,
        discoveredAt: observedAt,
      },
    ],
    parameters: [
      {
        url: 'https://app.example.com/login',
        method: 'POST',
        parameterName: 'username',
        discoveredAt: observedAt,
      },
    ],
    spaObservations: [
      {
        url: 'https://app.example.com/',
        targetHost: 'app.example.com',
        frameworks: [],
        routes: [
          {
            url: 'https://app.example.com/checkout',
            path: '/checkout',
            method: 'PUT',
            routeType: 'api_fetch',
            source: 'playwright_spa',
            discoveredAt: observedAt,
          },
        ],
        inputs: [],
        technologies: [],
        discoveredAt: observedAt,
      },
    ],
  };

  const inventory = buildProbeInventory({
    observations,
    scopeGrant: grant,
    lineage,
    evaluatedAt,
  });

  assert.equal(observations.urls.length, 6);
  assert.equal(inventory.entries.length, 4);
  assert.equal(inventory.assessmentId, lineage.assessmentId);
  assert.equal(inventory.scanId, lineage.scanId);
  assert.equal(inventory.authorizationGrantId, lineage.authorizationGrantId);
  assert.equal(inventory.authorizationDecisionId, lineage.authorizationDecisionId);
  assert.equal(inventory.actorId, lineage.actorId);

  const orders = inventory.entries.find((entry) => entry.path === '/orders');
  assert.ok(orders);
  assert.equal(orders.method, 'GET');
  assert.deepEqual(orders.parameters, ['id', 'status']);
  assert.deepEqual(orders.sources, ['gau', 'katana']);
  assert.equal(orders.origin, 'https://app.example.com');

  const login = inventory.entries.find((entry) => entry.path === '/login');
  assert.ok(login);
  assert.equal(login.method, 'POST');
  assert.equal(
    inventory.entries.some((entry) => entry.path === '/login' && entry.method === 'GET'),
    false
  );
  assert.deepEqual(login.parameters, ['username']);
  assert.deepEqual(login.sources, ['katana', 'parameter_discovery', 'web_inspection']);

  const health = inventory.entries.find((entry) => entry.path === '/health');
  assert.ok(health);
  assert.equal(health.method, 'GET');
  assert.deepEqual(health.sources, ['content_discovery']);

  const checkout = inventory.entries.find((entry) => entry.path === '/checkout');
  assert.ok(checkout);
  assert.equal(checkout.method, 'PUT');
  assert.deepEqual(checkout.sources, ['playwright_spa']);

  assert.equal(
    inventory.entries.some((entry) => entry.origin === 'https://evil.example'),
    false
  );
  assert.equal(
    inventory.entries.some((entry) => entry.path === '/admin'),
    false
  );
  assert.equal(
    inventory.entries.some((entry) => entry.origin === 'https://cdn.app.example.com'),
    false
  );

  const roundTrip = parseProbeInventory(inventory);
  assert.ok(roundTrip);
  assert.equal(roundTrip.entries.length, inventory.entries.length);

  const empty = buildProbeInventory({
    observations: emptyObservations(),
    scopeGrant: grant,
    lineage,
    evaluatedAt,
  });
  assert.deepEqual(empty.entries, []);
  assert.equal(parseProbeInventory(empty)?.entries.length, 0);

  assert.equal(
    parseProbeInventory({ ...inventory, confirmed: true }),
    null
  );
  const [first, ...rest] = inventory.entries;
  assert.ok(first);
  assert.equal(
    parseProbeInventory({
      ...inventory,
      entries: [{ ...first, note: 'extra' }, ...rest],
    }),
    null
  );
  assert.equal(
    parseProbeInventory({
      ...inventory,
      entries: [{ ...first, parameters: 'username' }, ...rest],
    }),
    null
  );

  assert.equal(validateOrchestratedAssessmentRecord(minimalRecord()), true);
  assert.equal(validateOrchestratedAssessmentRecord(minimalRecord(inventory)), true);
  assert.equal(
    validateOrchestratedAssessmentRecord({
      ...minimalRecord(),
      probeInventory: { ...inventory, confirmed: true },
    }),
    false
  );
  assert.equal(
    validateOrchestratedAssessmentRecord(
      minimalRecord({ ...inventory, assessmentId: 'asmt_other' })
    ),
    false
  );
}

try {
  main();
} catch (error) {
  fail(error);
}
process.exit(0);
