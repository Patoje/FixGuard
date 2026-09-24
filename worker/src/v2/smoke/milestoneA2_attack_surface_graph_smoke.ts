/**
 * Milestone A2 Smoke Suite — Attack Surface Graph (ASG)
 *
 * Verifies:
 * 1. Builder produces ASG from sample assessment output with correct node/edge counts
 * 2. Every edge carries mandatory EpistemicStatus
 * 3. QueryService accurate matches (endpoints with finding types, identities, uncovered, reachable)
 * 4. Epistemic honesty: validated findings → VERIFIED edges; recon → OBSERVED (not overclaimed)
 */

import assert from 'node:assert/strict';
import type { Finding } from '../core/Evidence.js';
import type { TargetProfile } from '../intelligence/IntelligenceContracts.js';
import type { AggregatedReconObservations } from '../recon/orchestration/ActiveReconOrchestrationContracts.js';
import { AttackSurfaceGraphBuilder } from '../attack-surface/AttackSurfaceGraphBuilder.js';
import { AttackSurfaceQueryService } from '../attack-surface/AttackSurfaceQueryService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION } from '../application/OrchestratedAssessmentContracts.js';
import type { OrchestratedAssessmentRecord } from '../application/OrchestratedAssessmentContracts.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { V2CompositionRoot } from '../api/V2CompositionRoot.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

async function runSmokeTests(): Promise<void> {
  console.log('=== Milestone A2: Attack Surface Graph Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_a2_001';
  const scanId = 'scn_smoke_a2_001';
  const actorId = 'act_smoke_a2_operator';
  const targetHost = 'app.example.com';

  const lineage = {
    assessmentId,
    scanId,
    authorizationGrantId: 'grn_smoke_a2_001',
    authorizationDecisionId: 'dec_smoke_a2_001',
    actorId,
  };

  const findings: Finding[] = [
    {
      id: 'fnd_cors_a2_001',
      type: 'CORS_MISCONFIGURATION',
      severity: 'high',
      title: 'CORS reflects arbitrary origin',
      description: 'Observed ACAO reflection with credentials.',
      target: 'https://app.example.com/api/user',
      evidence: 'ACAO: https://evil.example',
      confidence: 0.92,
      metadata: {
        kind: 'security_misconfiguration_metadata',
        category: 'CORS_MISCONFIGURATION',
        reflectedOrigin: 'https://evil.example',
        allowCredentials: true,
        endpointUrl: 'https://app.example.com/api/user',
        candidateId: 'cand_cors_a2',
        evidenceRecordId: 'evr_cors_a2',
        lineage: { assessmentId, scanId, actorId },
      },
      verificationState: 'validated_vulnerability',
    },
    {
      id: 'fnd_headers_a2_001',
      type: 'MISSING_SECURITY_HEADERS',
      severity: 'low',
      title: 'Missing CSP header',
      description: 'CSP header absent on root.',
      target: 'https://app.example.com/',
      evidence: 'header CSP missing',
      confidence: 0.7,
      metadata: {
        kind: 'missing_security_headers_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        missingHeaders: ['content-security-policy'],
        presentHeaders: [],
        observedAt: nowIso,
        endpointUrl: 'https://app.example.com/',
        candidateId: 'cand_hdr_a2',
        evidenceRecordId: 'evr_hdr_a2',
        lineage: { assessmentId, scanId, actorId },
      },
      verificationState: 'observed_anomaly',
    },
  ];

  const profile: TargetProfile = {
    contractVersion: 'fixguard-intelligence/v0',
    kind: 'target_profile',
    profileId: 'prf_smoke_a2_001',
    targetHost,
    normalizedOrigin: `https://${targetHost}`,
    updatedAt: nowIso,
    technologies: ['Nginx', 'Express'],
    lineage,
    endpoints: [
      {
        url: 'https://app.example.com/',
        path: '/',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: ['MISSING_SECURITY_HEADERS'],
      },
      {
        url: 'https://app.example.com/api/user',
        path: '/api/user',
        method: 'GET',
        parameters: ['id'],
        authRequirement: 'authenticated',
        flawCategories: ['CORS_MISCONFIGURATION'],
      },
      {
        url: 'https://app.example.com/about',
        path: '/about',
        method: 'GET',
        parameters: [],
        authRequirement: 'none',
        flawCategories: [],
      },
    ],
    knownFindings: findings,
    discoveredHosts: [],
    authSurface: {
      loginPaths: [],
      oauthPaths: [],
      ssoPaths: [],
      registrationPaths: [],
      passwordResetPaths: [],
      otherAuthPaths: [],
    },
    historicalAssets: [],
    externalDependencies: [],
  };

  const observations: AggregatedReconObservations = {
    subdomains: [
      {
        subdomain: 'api.example.com',
        parentDomain: 'example.com',
        ipAddresses: ['203.0.113.10'],
        sources: ['crt.sh'],
        discoveredAt: nowIso,
        confidence: 0.9,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    dnsRecords: [
      {
        domain: targetHost,
        recordType: 'A',
        values: ['203.0.113.50'],
        discoveredAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    ports: [
      {
        host: targetHost,
        ip: '203.0.113.50',
        port: 443,
        protocol: 'tcp',
        state: 'open',
        discoveredAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    webObservations: [
      {
        url: 'https://app.example.com/',
        method: 'GET',
        statusCode: 200,
        title: 'App',
        webServer: 'nginx',
        technologies: ['Nginx'],
        resolvedIp: '203.0.113.50',
        discoveredAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    tlsCertificates: [],
    urls: [],
    content: [],
    parameters: [
      {
        url: 'https://app.example.com/api/user',
        method: 'GET',
        parameterName: 'id',
        discoveredAt: nowIso,
        freshness: 'live',
        sourceReliability: 'direct_observation',
      },
    ],
    secrets: [],
  };

  // --- Test 1: Builder node/edge counts ---
  const graph = AttackSurfaceGraphBuilder.buildFromAssessmentResults({
    profile,
    findings,
    observations,
    builtAt: nowIso,
    authContexts: [
      {
        identityId: 'identity_alice_a2',
        sessionTokenRef: 'byot://identity/identity_alice_a2',
        createdAt: nowIso,
      },
    ],
  });

  assert.equal(graph.kind, 'attack_surface_graph');
  assert.equal(graph.assessmentId, assessmentId);
  assert.equal(graph.scanId, scanId);
  assert.equal(graph.targetHost, targetHost);
  assert.ok(graph.nodes.length >= 10, `expected >=10 nodes, got ${graph.nodes.length}`);
  assert.ok(graph.edges.length >= 10, `expected >=10 edges, got ${graph.edges.length}`);

  const kindCounts = graph.nodes.reduce<Record<string, number>>((acc, n) => {
    acc[n.kind] = (acc[n.kind] ?? 0) + 1;
    return acc;
  }, {});

  assert.ok((kindCounts['domain'] ?? 0) >= 1, 'missing domain node');
  assert.ok((kindCounts['endpoint'] ?? 0) >= 3, 'expected >=3 endpoint nodes');
  assert.ok((kindCounts['vulnerability'] ?? 0) === 2, 'expected 2 vulnerability nodes');
  assert.ok((kindCounts['ip_address'] ?? 0) >= 1, 'missing ip nodes');
  assert.ok((kindCounts['port'] ?? 0) >= 1, 'missing port node');
  assert.ok((kindCounts['parameter'] ?? 0) >= 1, 'missing parameter node');
  assert.ok((kindCounts['identity'] ?? 0) >= 1, 'missing identity node');
  assert.ok((kindCounts['session'] ?? 0) >= 1, 'missing SessionNode from authContexts');

  const sessionEdges = graph.edges.filter((e) => e.kind === 'observed_as_accessible_by');
  assert.ok(sessionEdges.length >= 1, 'expected observed_as_accessible_by edges for SessionNode');
  for (const e of sessionEdges) {
    assert.equal(e.epistemicStatus, 'OBSERVED');
  }

  console.log(
    `✓ Test 1 Passed: ASG built with ${graph.nodes.length} nodes / ${graph.edges.length} edges`,
    kindCounts
  );

  // --- Test 2: All edges carry EpistemicStatus ---
  for (const edge of graph.edges) {
    assert.ok(
      edge.epistemicStatus === 'OBSERVED' ||
        edge.epistemicStatus === 'INFERRED' ||
        edge.epistemicStatus === 'VERIFIED' ||
        edge.epistemicStatus === 'REFUTED',
      `edge ${edge.id} missing EpistemicStatus`
    );
  }

  const corsVuln = graph.nodes.find(
    (n) => n.kind === 'vulnerability' && n.metadata.findingType === 'CORS_MISCONFIGURATION'
  );
  assert.ok(corsVuln, 'CORS vulnerability node missing');
  assert.equal(corsVuln.epistemicStatus, 'VERIFIED');

  const corsEdge = graph.edges.find(
    (e) => e.toNodeId === corsVuln.id && e.kind === 'has_vulnerability'
  );
  assert.ok(corsEdge, 'CORS has_vulnerability edge missing');
  assert.equal(corsEdge.epistemicStatus, 'VERIFIED');

  const headerVuln = graph.nodes.find(
    (n) => n.kind === 'vulnerability' && n.metadata.findingType === 'MISSING_SECURITY_HEADERS'
  );
  assert.ok(headerVuln);
  assert.equal(headerVuln.epistemicStatus, 'OBSERVED');

  const dnsResolveEdges = graph.edges.filter((e) => e.kind === 'resolves_to');
  assert.ok(dnsResolveEdges.length >= 1);
  for (const e of dnsResolveEdges) {
    assert.notEqual(e.epistemicStatus, 'VERIFIED', 'must not overclaim VERIFIED on DNS edges');
  }

  console.log('✓ Test 2 Passed: All edges carry EpistemicStatus; VERIFIED only where warranted');

  // --- Test 3: QueryService accuracy ---
  const query = new AttackSurfaceQueryService(graph);

  const corsEndpoints = query.findEndpointsWithFinding('CORS_MISCONFIGURATION');
  assert.equal(corsEndpoints.length, 1);
  assert.equal(corsEndpoints[0]?.node.metadata.url, 'https://app.example.com/api/user');
  assert.equal(corsEndpoints[0]?.epistemicStatus, 'VERIFIED');
  assert.ok(corsEndpoints[0]?.relatedEdges.every((e) => Boolean(e.epistemicStatus)));

  const identities = query.findIdentitiesForEndpoint('https://app.example.com/api/user');
  assert.ok(identities.length >= 1, 'expected identity for authenticated endpoint');
  assert.equal(identities[0]?.node.kind, 'identity');
  assert.ok(identities[0]?.relatedEdges.every((e) => Boolean(e.epistemicStatus)));

  const uncovered = query.findUncoveredEndpoints();
  const uncoveredUrls = uncovered.map((m) => m.node.metadata.url);
  assert.ok(uncoveredUrls.includes('https://app.example.com/about'), 'about should be uncovered');
  assert.ok(
    !uncoveredUrls.includes('https://app.example.com/api/user'),
    'api/user has CORS finding — must not be uncovered'
  );

  const reachable = query.findReachableHosts();
  assert.ok(reachable.length >= 1, 'expected reachable IP hosts');
  assert.ok(reachable.every((m) => m.node.kind === 'ip_address'));
  assert.ok(reachable.every((m) => Boolean(m.epistemicStatus)));

  console.log('✓ Test 3 Passed: QueryService matches are accurate and preserve epistemic status');

  // --- Test 4: Persistence + application getAttackSurface + composition wiring ---
  const repository = new InMemoryOrchestratedAssessmentRepository();
  const record: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId,
    scanId,
    targetDomain: targetHost,
    status: 'completed',
    lineage,
    stages: [],
    timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 1 },
    errorCount: 0,
    warningCount: 0,
    profile,
    findings,
    recommendations: [],
    attackSurfaceGraph: graph,
  };
  await repository.save(record);

  const service = new OrchestratedAssessmentApplicationService({ repository });
  const asgResult = await service.getAttackSurface(assessmentId);
  assert.equal(asgResult.assessmentId, assessmentId);
  assert.ok(asgResult.attackSurfaceGraph);
  assert.equal(asgResult.attackSurfaceGraph?.graphId, graph.graphId);
  assert.equal(asgResult.lineage.assessmentId, assessmentId);

  const root = V2CompositionRoot.withDependencies({
    orchestratedRepository: repository,
    orchestratedService: service,
  });
  const composedQuery = root.createAttackSurfaceQueryService(graph);
  assert.equal(composedQuery.findEndpointsWithFinding('CORS_MISCONFIGURATION').length, 1);

  console.log('✓ Test 4 Passed: getAttackSurface + CompositionRoot query wiring');

  console.log('=== Milestone A2 Attack Surface Graph: ALL TESTS PASSED ===');
}

runSmokeTests().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
});
