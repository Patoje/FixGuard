/**
 * Milestone P5-1 Smoke Test Suite
 * CORS + IDOR Compound Chain Correlator (Milestone P5-1)
 *
 * Verifies:
 * 1. Correlates confirmed Credentialed CORS finding + confirmed IDOR finding on matching origin into a compound chain draft.
 * 2. Cleanly ignores/abstains when CORS and IDOR are on different origins.
 * 3. Cleanly ignores/abstains when CORS finding lacks credentials (allowCredentialsHeader: false).
 * 4. Operates purely in-memory with zero network overhead.
 * 5. Full HITL triage lifecycle promotes compound draft to formal Critical Finding.
 */

import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { correlateCorsIdorChains } from '../intelligence/correlation/CorsIdorChainCorrelator.js';
import type {
  IdorHttpProbeTransport,
  HttpProbeRequest,
  HttpProbeResponse,
} from '../detection/DetectionContracts.js';
import type { Finding, CompoundChainMetadata } from '../core/Evidence.js';

console.log('[milestoneP5_1_cors_idor_chain_smoke] Starting Milestone P5-1 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_p51_001',
    scanId: 'scn_test_p51_001',
    authorizationGrantId: 'grnt_test_p51_001',
    authorizationDecisionId: 'dec_test_p51_001',
    actorId: 'usr_secops_lead',
  };

  const decidedAt = new Date().toISOString();

  // -------------------------------------------------------------------------
  // Test 1: Correlates confirmed Credentialed CORS + confirmed IDOR on matching origin
  // -------------------------------------------------------------------------
  console.log('--- Test 1: Correlates confirmed Credentialed CORS + IDOR on matching origin ---');
  {
    const corsFinding: Finding = {
      id: 'fnd_cors_test_001',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'high',
      title: 'Credentialed CORS Misconfiguration on /api/user',
      description: 'Reflects arbitrary origin with credentials true',
      target: 'https://app.example.com/api/user',
      evidence: '{"acao":"https://canary.fixguard.internal","acac":true}',
      confidence: 0.95,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'credentialed_cors_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        endpointUrl: 'https://app.example.com/api/user',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: true,
        acaoHeader: 'https://canary.fixguard.internal',
        observedAt: decidedAt,
      },
    };

    const idorFinding: Finding = {
      id: 'fnd_idor_test_001',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'Differential IDOR on /api/tenant/documents/42',
      description: 'Identity A accessed Identity B tenant document',
      target: 'https://app.example.com/api/tenant/documents/42',
      evidence: '{"statusDiff":200}',
      confidence: 0.95,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'broken_access_control_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        candidateId: 'cnd_idor_001',
        evidenceRecordId: 'evd_idor_001',
        lineage: { assessmentId: lineage.assessmentId },
        endpointUrl: 'https://app.example.com/api/tenant/documents/42',
        resourceParamName: 'docId',
        baselineResourceId: '41',
        unauthorizedActorId: 'usr_tenant_a',
      },
    };

    const result = correlateCorsIdorChains({
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      actorId: lineage.actorId,
      findings: [corsFinding, idorFinding],
    });

    if (result.chainsFound !== 1) {
      throw new Error(`Test 1 Failed: Expected 1 chain, got ${result.chainsFound}`);
    }
    if (result.compoundDrafts.length !== 1) {
      throw new Error('Test 1 Failed: Expected 1 compound draft');
    }

    const draft = result.compoundDrafts[0]!;
    if (draft.differentialContext?.detectionKind !== 'cors_idor_compound') {
      throw new Error(`Test 1 Failed: Expected detectionKind 'cors_idor_compound', got '${draft.differentialContext?.detectionKind}'`);
    }
    if (draft.differentialContext?.primaryFindingId !== 'fnd_cors_test_001') {
      throw new Error(`Test 1 Failed: Expected primaryFindingId 'fnd_cors_test_001', got '${draft.differentialContext?.primaryFindingId}'`);
    }
    if (draft.differentialContext?.secondaryFindingId !== 'fnd_idor_test_001') {
      throw new Error(`Test 1 Failed: Expected secondaryFindingId 'fnd_idor_test_001', got '${draft.differentialContext?.secondaryFindingId}'`);
    }
    if (draft.differentialContext?.sharedOrigin !== 'https://app.example.com') {
      throw new Error(`Test 1 Failed: Expected sharedOrigin 'https://app.example.com', got '${draft.differentialContext?.sharedOrigin}'`);
    }

    console.log('✓ Test 1 Passed: Compound chain draft correctly synthesized');
  }

  // -------------------------------------------------------------------------
  // Test 2: Cleanly ignores when CORS and IDOR are on different origins
  // -------------------------------------------------------------------------
  console.log('--- Test 2: Cleanly ignores when CORS and IDOR are on different origins ---');
  {
    const corsFinding: Finding = {
      id: 'fnd_cors_diff_origin',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'high',
      title: 'Credentialed CORS on app.example.com',
      description: 'CORS on app domain',
      target: 'https://app.example.com/api/user',
      evidence: '{"acac":true}',
      confidence: 0.9,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'credentialed_cors_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        endpointUrl: 'https://app.example.com/api/user',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: true,
        acaoHeader: 'https://canary.fixguard.internal',
        observedAt: decidedAt,
      },
    };

    const idorFinding: Finding = {
      id: 'fnd_idor_diff_origin',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'IDOR on completely different origin',
      description: 'IDOR on other host',
      target: 'https://api.partner.net/documents/100',
      evidence: '{"statusDiff":200}',
      confidence: 0.9,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'broken_access_control_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        candidateId: 'cnd_idor_002',
        evidenceRecordId: 'evd_idor_002',
        lineage: { assessmentId: lineage.assessmentId },
        endpointUrl: 'https://api.partner.net/documents/100',
        resourceParamName: 'docId',
        baselineResourceId: '99',
        unauthorizedActorId: 'usr_tenant_a',
      },
    };

    const result = correlateCorsIdorChains({
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      actorId: lineage.actorId,
      findings: [corsFinding, idorFinding],
    });

    if (result.chainsFound !== 0) {
      throw new Error(`Test 2 Failed: Expected 0 chains for mismatched origins, got ${result.chainsFound}`);
    }

    console.log('✓ Test 2 Passed: Mismatched origins cleanly ignored');
  }

  // -------------------------------------------------------------------------
  // Test 3: Cleanly ignores when CORS finding lacks allowCredentialsHeader: true
  // -------------------------------------------------------------------------
  console.log('--- Test 3: Cleanly ignores when CORS finding lacks credentials flag ---');
  {
    const corsNoCredFinding: Finding = {
      id: 'fnd_cors_no_cred',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'medium',
      title: 'Public CORS on app.example.com without credentials',
      description: 'Public reflection only',
      target: 'https://app.example.com/api/public',
      evidence: '{"acac":false}',
      confidence: 0.8,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'credentialed_cors_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        endpointUrl: 'https://app.example.com/api/public',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: false,
        acaoHeader: 'https://canary.fixguard.internal',
        observedAt: decidedAt,
      },
    };

    const idorFinding: Finding = {
      id: 'fnd_idor_002',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'IDOR on app.example.com',
      description: 'IDOR target',
      target: 'https://app.example.com/api/tenant/42',
      evidence: '{"statusDiff":200}',
      confidence: 0.9,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'broken_access_control_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        candidateId: 'cnd_idor_003',
        evidenceRecordId: 'evd_idor_003',
        lineage: { assessmentId: lineage.assessmentId },
        endpointUrl: 'https://app.example.com/api/tenant/42',
        resourceParamName: 'tenantId',
        baselineResourceId: '41',
        unauthorizedActorId: 'usr_tenant_a',
      },
    };

    const result = correlateCorsIdorChains({
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      actorId: lineage.actorId,
      findings: [corsNoCredFinding, idorFinding],
    });

    if (result.chainsFound !== 0) {
      throw new Error(`Test 3 Failed: Expected 0 chains when allowCredentials is false, got ${result.chainsFound}`);
    }

    console.log('✓ Test 3 Passed: Non-credentialed CORS finding correctly excluded from chain');
  }

  // -------------------------------------------------------------------------
  // Test 4: Direct approval promotion returns formal Critical Finding
  // -------------------------------------------------------------------------
  console.log('--- Test 4: Direct approval promotion returns formal Critical Finding ---');
  {
    const corsFinding: Finding = {
      id: 'fnd_cors_test_004',
      type: 'SECURITY_MISCONFIGURATION',
      severity: 'high',
      title: 'Credentialed CORS Misconfiguration',
      description: 'CORS on target',
      target: 'https://app.example.com/api/account',
      evidence: '{"acac":true}',
      confidence: 0.95,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'credentialed_cors_metadata',
        category: 'SECURITY_MISCONFIGURATION',
        endpointUrl: 'https://app.example.com/api/account',
        httpMethod: 'GET',
        suppliedOrigin: 'https://canary.fixguard.internal',
        reflectedOrigin: 'https://canary.fixguard.internal',
        allowCredentialsHeader: true,
        acaoHeader: 'https://canary.fixguard.internal',
        observedAt: decidedAt,
      },
    };

    const idorFinding: Finding = {
      id: 'fnd_idor_test_004',
      type: 'BROKEN_ACCESS_CONTROL',
      severity: 'high',
      title: 'Differential IDOR on Account Data',
      description: 'IDOR on account endpoint',
      target: 'https://app.example.com/api/account/data/99',
      evidence: '{"statusDiff":200}',
      confidence: 0.95,
      verificationState: 'validated_vulnerability',
      metadata: {
        kind: 'broken_access_control_metadata',
        category: 'BROKEN_ACCESS_CONTROL',
        candidateId: 'cnd_idor_004',
        evidenceRecordId: 'evd_idor_004',
        lineage: { assessmentId: lineage.assessmentId },
        endpointUrl: 'https://app.example.com/api/account/data/99',
        resourceParamName: 'accountId',
        baselineResourceId: '98',
        unauthorizedActorId: 'usr_tenant_a',
      },
    };

    const result = correlateCorsIdorChains({
      assessmentId: lineage.assessmentId,
      scanId: lineage.scanId,
      actorId: lineage.actorId,
      findings: [corsFinding, idorFinding],
      humanReviewDecision: {
        reviewerId: 'usr_secops_lead',
        reviewedAt: new Date().toISOString(),
        decision: 'approve_evidence',
      },
    });

    if (result.compoundFindings.length !== 1) {
      throw new Error(`Test 4 Failed: Expected 1 promoted compound finding, got ${result.compoundFindings.length}`);
    }

    const finding = result.compoundFindings[0]!;
    if (finding.severity !== 'critical' || finding.type !== 'BROKEN_ACCESS_CONTROL') {
      throw new Error(`Test 4 Failed: Invalid severity or type on compound finding: ${finding.severity} / ${finding.type}`);
    }

    const meta = finding.metadata as CompoundChainMetadata;
    if (meta.kind !== 'compound_chain_metadata' || meta.chainKind !== 'cors_idor_compound') {
      throw new Error(`Test 4 Failed: Invalid metadata kind on compound finding: ${JSON.stringify(meta)}`);
    }

    console.log('✓ Test 4 Passed: Direct human approval promoted compound chain finding');
  }

  // -------------------------------------------------------------------------
  // Test 5: Full HITL triage lifecycle in OrchestratedAssessmentApplicationService
  // -------------------------------------------------------------------------
  console.log('--- Test 5: Full HITL triage lifecycle in Application Service ---');
  {
    const repository = new InMemoryOrchestratedAssessmentRepository();
    const availabilityService = new ReconToolAvailabilityService({
      async execute() {
        return { stdout: '1.0.0\n', stderr: '', exitCode: 0, durationMs: 1, timedOut: false };
      },
    });

    const mockTransport: IdorHttpProbeTransport = async (req: HttpProbeRequest): Promise<HttpProbeResponse> => {
      const origin = req.headers['Origin'] ?? req.headers['origin'] ?? 'https://canary.fixguard.internal';
      return {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': origin,
          'access-control-allow-credentials': 'true',
        },
        bodyText: JSON.stringify({ sensitive: 'user_profile', tenantId: 42 }),
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
      targetDomain: 'app.example.com',
      actorId: 'usr_secops_lead',
      sessionIdentities: {
        identityA: {
          identityId: 'usr_tenant_a',
          injectHeaders: { 'x-user-id': 'tenant_a' },
        },
        identityB: {
          identityId: 'usr_tenant_b',
          injectHeaders: { 'x-user-id': 'tenant_b' },
        },
      },
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
    const corsDraft = draftsResponse.drafts.find((d) => d.differentialContext?.detectionKind === 'credentialed_cors');
    const idorDraft = draftsResponse.drafts.find((d) => d.differentialContext?.detectionKind === 'idor_access_control');

    if (!corsDraft || !idorDraft) {
      throw new Error(`Test 5 Failed: Expected both CORS and IDOR drafts in assessment, found: ${JSON.stringify(draftsResponse.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    // 1. Promote CORS draft
    await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: corsDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Approved CORS vulnerability.',
    });

    // 2. Promote IDOR draft -> triggers auto compound chain synthesis!
    const reviewResultIdor = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: idorDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Approved IDOR vulnerability.',
    });

    if (!reviewResultIdor.findingCreated) {
      throw new Error('Test 5 Failed: IDOR promotion failed');
    }

    // Check that a new compound chain draft was automatically synthesized
    const draftsAfterPromotion = await appService.getEvidenceDrafts(startRes.assessmentId);
    const chainDraft = draftsAfterPromotion.drafts.find((d) => d.differentialContext?.detectionKind === 'cors_idor_compound');

    if (!chainDraft) {
      throw new Error(`Test 5 Failed: Expected synthesized cors_idor_compound draft after both findings promoted, found: ${JSON.stringify(draftsAfterPromotion.drafts.map((d) => d.differentialContext?.detectionKind))}`);
    }

    // 3. Promote the synthesized compound chain draft
    const chainReviewResult = await appService.reviewEvidenceDraft({
      assessmentId: startRes.assessmentId,
      draftId: chainDraft.draftId,
      decision: 'approve_evidence',
      reviewerId: 'usr_secops_lead',
      reviewedAt: new Date().toISOString(),
      notes: 'Approved synthesized CORS + IDOR compound exploit chain.',
    });

    if (chainReviewResult.decision !== 'approve_evidence' || !chainReviewResult.findingCreated) {
      throw new Error(`Test 5 Failed: Compound chain review promotion failed: ${JSON.stringify(chainReviewResult)}`);
    }

    const promotedChainFinding = chainReviewResult.findingCreated;
    if (promotedChainFinding.severity !== 'critical') {
      throw new Error(`Test 5 Failed: Expected severity 'critical', got '${promotedChainFinding.severity}'`);
    }

    const findingMeta = promotedChainFinding.metadata as CompoundChainMetadata;
    if (findingMeta.kind !== 'compound_chain_metadata' || findingMeta.chainKind !== 'cors_idor_compound') {
      throw new Error(`Test 5 Failed: Invalid metadata on promoted chain finding: ${JSON.stringify(findingMeta)}`);
    }

    const summary = await appService.getSummary(startRes.assessmentId);
    const summaryFinding = summary.findings.find((f: Finding) => f.metadata?.kind === 'compound_chain_metadata');
    if (!summaryFinding) {
      throw new Error('Test 5 Failed: Promoted compound chain finding not found in assessment summary');
    }

    console.log('✓ Test 5 Passed: HITL review approved and promoted compound chain draft to formal Critical Finding');
  }

  console.log('\n[milestoneP5_1_cors_idor_chain_smoke] ALL 5 TESTS PASSED SUCCESSFULLY! (100% compliant)');
}

runTests().catch((err) => {
  console.error('[milestoneP5_1_cors_idor_chain_smoke] FATAL ERROR:', err);
  process.exit(1);
});
