/**
 * Milestone P4-6 Smoke Test Suite
 * GraphQL Surface Mapper (Milestone P4-6)
 *
 * Verifies:
 * 1. Detects enabled introspection, extracts root types, and constructs GraphQLSurfaceMetadata.
 * 2. Detects batching capabilities and field suggestion disclosures.
 * 3. Cleanly abstains (secure_target_abstained) when GraphQL endpoints are disabled, hardened, or not present.
 * 4. Preflight and egress gates block internal/SSRF addresses.
 * 5. Full HITL triage lifecycle promotes drafts to formal Findings.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { runGraphQLSurfaceDetection } from '../detection/GraphQLSurfaceDetectionService.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { evaluateScopePolicy } from '../scope/AuthorizedScopePolicyService.js';
import { DETECTION_CONTRACT_VERSION } from '../detection/DetectionContracts.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { Finding, GraphQLSurfaceMetadata } from '../core/Evidence.js';

console.log('[milestoneP4_6_graphql_surface_smoke] Starting Milestone P4-6 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p46_001',
    scanId: 'scn_test_p46_001',
    authorizationGrantId: 'grnt_test_p46_001',
    authorizationDecisionId: 'dec_test_p46_001',
    actorId: 'usr_secops_lead',
  };

  const decidedAt = new Date().toISOString();

  const scopeGrant: AuthorizedScopeGrant = {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: lineage.authorizationGrantId,
    scanId: lineage.scanId,
    issuedAt: new Date(Date.now() - 3600_000).toISOString(),
    expiresAt: new Date(Date.now() + 86400_000).toISOString(),
    subject: {
      targetKind: 'origin',
      normalizedOrigin: 'https://api.example.com',
    },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized for Milestone P4-6 GraphQL Surface smoke testing',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: false,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['api.example.com'],
      allowedHosts: ['api.example.com'],
      allowedOrigins: ['https://api.example.com'],
      allowedMethods: ['GET', 'HEAD', 'POST'],
    },
    constraints: {
      allowLoginRequiredAreas: false,
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

  const authDecisionResult = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
      decision: 'authorized',
      decidedAt,
      scopeGrant,
    },
    decidedAt
  );

  if (authDecisionResult.status !== 'established' || !authDecisionResult.decision) {
    throw new Error('Failed to establish verified authorization decision for smoke test');
  }

  const authDecision = authDecisionResult.decision;

  // -------------------------------------------------------------------------
  // Test 1: Detects enabled introspection, extracts root types, and constructs GraphQLSurfaceMetadata
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Detects enabled introspection and extracts root types ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const bodyStr = typeof req.body === 'string' ? req.body : '';
      if (bodyStr.includes('__schema')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({
            data: {
              __schema: {
                types: [
                  { name: 'Query' },
                  { name: 'Mutation' },
                  { name: 'User' },
                  { name: 'Account' },
                  { name: 'Payment' },
                  { name: '__Schema' },
                  { name: '__Type' },
                ],
              },
            },
          }),
          responseTimeMs: 20,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ data: { __typename: 'Query' } }),
        responseTimeMs: 20,
      };
    };

    const result = await runGraphQLSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'graphql_surface_detection_request',
      detectionId: 'det_test_p46_introspection',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/graphql',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.status !== 'graphql_surface_detected') {
      throw new Error(`Test 1 Failed: Expected status 'graphql_surface_detected', got '${result.status}'`);
    }
    if (!result.introspectionEnabled) {
      throw new Error('Test 1 Failed: Expected introspectionEnabled to be true');
    }
    if (!result.discoveredRootTypes || !result.discoveredRootTypes.includes('User')) {
      throw new Error(`Test 1 Failed: Expected discoveredRootTypes to contain 'User', got: ${JSON.stringify(result.discoveredRootTypes)}`);
    }
    if (!result.finding) {
      throw new Error('Test 1 Failed: Expected finding to be constructed');
    }
    const meta = result.finding.metadata as GraphQLSurfaceMetadata;
    if (meta.kind !== 'graphql_surface_metadata' || meta.category !== 'INFORMATION_DISCLOSURE') {
      throw new Error(`Test 1 Failed: Invalid finding metadata: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 1 Passed: Enabled introspection detected and root types extracted');
  }

  // -------------------------------------------------------------------------
  // Test 2: Detects batching capabilities and field suggestion disclosures
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Detects batching capabilities and field suggestion disclosures ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const bodyStr = typeof req.body === 'string' ? req.body : '';
      if (bodyStr.includes('fixguard_invalid_probe')) {
        return {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({
            errors: [
              {
                message: 'Cannot query field "fixguard_invalid_probe" on type "Query". Did you mean "userProfile" or "accounts"?',
              },
            ],
          }),
          responseTimeMs: 20,
        };
      }
      if (bodyStr.startsWith('[')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify([
            { data: { __typename: 'Query' } },
            { data: { __typename: 'Query' } },
          ]),
          responseTimeMs: 20,
        };
      }
      // Introspection disabled
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        bodyText: JSON.stringify({ errors: [{ message: 'GraphQL introspection is disabled.' }] }),
        responseTimeMs: 20,
      };
    };

    const result = await runGraphQLSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'graphql_surface_detection_request',
      detectionId: 'det_test_p46_batch_suggest',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/graphql',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.status !== 'graphql_surface_detected') {
      throw new Error(`Test 2 Failed: Expected status 'graphql_surface_detected', got '${result.status}'`);
    }
    if (!result.batchingEnabled) {
      throw new Error('Test 2 Failed: Expected batchingEnabled to be true');
    }
    if (!result.fieldSuggestionsEnabled) {
      throw new Error('Test 2 Failed: Expected fieldSuggestionsEnabled to be true');
    }
    if (!result.suggestionLeak || !result.suggestionLeak.includes('Did you mean')) {
      throw new Error(`Test 2 Failed: Expected suggestionLeak containing 'Did you mean', got: ${result.suggestionLeak}`);
    }
    if (result.introspectionEnabled) {
      throw new Error('Test 2 Failed: Expected introspectionEnabled to be false');
    }

    console.log('✓ Test 2 Passed: Batching capability and field suggestion disclosures accurately detected');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly abstains on hardened, non-existent, or non-GraphQL targets
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly abstains on hardened or non-GraphQL targets ---');
  {
    const mockTransport: IdorHttpProbeTransport = async (): Promise<HttpProbeResponse> => {
      return {
        statusCode: 404,
        headers: { 'content-type': 'text/html' },
        bodyText: '<html><body>404 Not Found</body></html>',
        responseTimeMs: 20,
      };
    };

    const result = await runGraphQLSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'graphql_surface_detection_request',
      detectionId: 'det_test_p46_abstain',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'https://api.example.com/graphql',
      verifiedAuthorizationDecision: authDecision,
      scopeGrant,
      transport: mockTransport,
    });

    if (result.status !== 'secure_target_abstained') {
      throw new Error(`Test 3 Failed: Expected status 'secure_target_abstained', got '${result.status}'`);
    }
    if (result.introspectionEnabled || result.batchingEnabled || result.fieldSuggestionsEnabled) {
      throw new Error('Test 3 Failed: Capabilities should all be false on abstention');
    }

    console.log('✓ Test 3 Passed: Hardened endpoint cleanly abstained');
  }

  // -------------------------------------------------------------------------
  // Test 4: Preflight and egress gates block internal/SSRF addresses
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Preflight and egress gates block internal/SSRF addresses ---');
  {
    const ssrfScopeGrant: AuthorizedScopeGrant = {
      ...scopeGrant,
      boundaries: {
        allowedDomains: ['127.0.0.1'],
        allowedHosts: ['127.0.0.1'],
        allowedOrigins: ['http://127.0.0.1'],
        allowedMethods: ['GET', 'POST'],
      },
    };

    const ssrfAuthDecision = establishVerifiedAuthorizationDecision(
      {
        contractVersion: 'fixguard-verified-authorization-decision/v0',
        kind: 'establish_verified_authorization_decision_request',
        assessmentId: lineage.assessmentId,
        scanId: lineage.scanId,
        authorizationDecisionId: lineage.authorizationDecisionId,
        authorizedActor: { actorId: lineage.actorId, actorType: 'human' },
        decision: 'authorized',
        decidedAt,
        scopeGrant: ssrfScopeGrant,
      },
      decidedAt
    );

    if (ssrfAuthDecision.status !== 'established' || !ssrfAuthDecision.decision) {
      throw new Error('Failed to set up SSRF test decision');
    }

    const result = await runGraphQLSurfaceDetection({
      contractVersion: DETECTION_CONTRACT_VERSION,
      kind: 'graphql_surface_detection_request',
      detectionId: 'det_test_p46_ssrf',
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      authorizationGrantId: lineage.authorizationGrantId,
      authorizationDecisionId: lineage.authorizationDecisionId,
      actorId: lineage.actorId,
      endpointUrl: 'http://127.0.0.1:8080/graphql',
      verifiedAuthorizationDecision: ssrfAuthDecision.decision,
      scopeGrant: ssrfScopeGrant,
    });

    if (result.status !== 'preflight_denied') {
      throw new Error(`Test 4 Failed: Expected 'preflight_denied' for SSRF target, got '${result.status}'`);
    }

    console.log('✓ Test 4 Passed: SSRF target safely blocked at preflight boundary');
  }

  // -------------------------------------------------------------------------
  // Test 5: Full HITL triage lifecycle promotes drafts to formal Findings
  // -------------------------------------------------------------------------
  console.log('--- Test 5: Full HITL triage lifecycle promotes drafts to formal Findings ---');
  {
    const repository = new InMemoryOrchestratedAssessmentRepository();
    const availabilityService = new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    });

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const bodyStr = typeof req.body === 'string' ? req.body : '';
      if (bodyStr.includes('__schema')) {
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          bodyText: JSON.stringify({
            data: {
              __schema: {
                types: [{ name: 'Query' }, { name: 'UserProfile' }, { name: 'Orders' }],
              },
            },
          }),
          responseTimeMs: 25,
        };
      }
      return {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        bodyText: '<!DOCTYPE html><html><body>Web Application</body></html>',
        responseTimeMs: 20,
      };
    };

    const mockDnsResolver = async (_host: string): Promise<string[]> => ['93.184.216.34'];

    const appService = new OrchestratedAssessmentApplicationService({
      repository,
      availabilityService,
      httpTransport: mockTransport,
      dnsResolver: mockDnsResolver,
    });

    const startRes = await appService.startAssessment({
      targetDomain: 'api.example.com',
      actorId: 'usr_secops_lead',
    });

    if (startRes.status !== 'running') {
      throw new Error(`Test 5 Failed: Assessment did not start with running status: ${startRes.status}`);
    }

    let attempts = 0;
    let status = await appService.getStatus(startRes.assessmentId);
    while (status.status === 'running' && attempts < 100) {
      await new Promise((r) => setTimeout(r, 100));
      status = await appService.getStatus(startRes.assessmentId);
      attempts++;
    }

    const draftsResponse = await appService.getEvidenceDrafts(startRes.assessmentId);
    const gqlDraft = draftsResponse.drafts.find(
      (d) => d.differentialContext?.detectionKind === 'graphql_surface'
    );

    if (!gqlDraft) {
      throw new Error(`Test 5 Failed: Expected pending GraphQL surface draft, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    if (!gqlDraft.differentialContext?.introspectionEnabled) {
      throw new Error('Test 5 Failed: Expected draft introspectionEnabled to be true');
    }

    // Perform HITL review promotion
    const reviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: gqlDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Confirmed exposed GraphQL introspection in staging environment.',
    });

    if (reviewResult.decision !== 'approve_evidence' || !reviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Review promotion failed: ${JSON.stringify(reviewResult)}`);
    }

    const promotedFinding = reviewResult.findingCreated;
    if (promotedFinding.type !== 'INFORMATION_DISCLOSURE') {
      throw new Error(`Test 5 Failed: Expected finding type 'INFORMATION_DISCLOSURE', got '${promotedFinding.type}'`);
    }

    const findingMeta = promotedFinding.metadata as GraphQLSurfaceMetadata;
    if (findingMeta.kind !== 'graphql_surface_metadata' || !findingMeta.introspectionEnabled) {
      throw new Error(`Test 5 Failed: Invalid promoted finding metadata: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'graphql_surface_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted GraphQL surface finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted GraphQL surface draft to formal Finding');
  }

  console.log('\n[milestoneP4_6_graphql_surface_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP4_6_graphql_surface_smoke] FATAL ERROR:', err);
  process.exit(1);
});
