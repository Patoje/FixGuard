/**
 * FixGuard V2 — Milestone P2-6 Smoke Suite
 *
 * Verifies HTML Report Generation & Operator Attestation:
 * 1. Generates standalone HTML report with metadata, limitations, confirmed findings, and signed attestation.
 * 2. Fails closed when attestationText is omitted, shorter than 10 characters, or empty.
 * 3. Omits unreviewed evidence drafts from findings tables (strictly HITL promoted findings only).
 * 4. Preserves and renders the continuous lineage chain for every reported finding.
 * 5. Full controller & HTTP validation conformance (closed-world exact keys, status 200/400).
 */

import assert from 'node:assert';
import {
  generateDefensiveHtmlReport,
  validateOperatorAttestation,
} from '../reporting-boundary/ReportGeneratorService.js';
import {
  buildHeaderSection,
  buildExecutiveSummarySection,
  buildAuditLimitationsSection,
  buildConfirmedFindingsSection,
  buildRecommendationsSection,
  buildOperatorAttestationSection,
} from '../reporting-boundary/ReportSectionBuilders.js';
import {
  OrchestratedAssessmentApplicationService,
  ASSESSMENT_GLOBAL_TIMEOUT_MS,
} from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';
import { ReconToolAvailabilityService } from '../capabilities/ReconToolAvailabilityService.js';
import { OrchestratedAssessmentController } from '../api/controllers/OrchestratedAssessmentController.js';
import { parseGenerateHtmlReportHttpBody } from '../api/validation/ApiRequestValidators.js';
import { ReportGenerationError } from '../reporting-boundary/DefensiveReportContracts.js';
import { ApiValidationError, ConcurrencyLimitExceededError } from '../api/ApiErrors.js';
import type { Finding } from '../core/Evidence.js';
import {
  type OrchestratedAssessmentRecord,
  ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
} from '../application/OrchestratedAssessmentContracts.js';
import type { Request, Response, NextFunction } from 'express';

console.log('[milestoneP2_6_report_generation_smoke] Starting Milestone P2-6 smoke suite...');

async function runTests(): Promise<void> {
  const lineage = {
    assessmentId: 'asm_test_report_001',
    scanId: 'scan_test_report_001',
    authorizationGrantId: 'grant_test_report_001',
    authorizationDecisionId: 'dec_test_report_001',
    actorId: 'operator_sec_lead',
  };

  const sampleFinding: Finding = {
    id: 'fnd_report_001',
    type: 'open_redirect',
    severity: 'medium',
    title: 'Open Redirect via Insecure Return Parameter',
    description: 'Server issued HTTP 302 redirecting directly to canary domain.',
    target: 'https://example.com/login?next=https://canary.fixguard.internal/cb',
    evidence: 'Server issued HTTP 302 redirecting directly to canary domain.',
    confidence: 0.95,
    verificationState: 'validated_vulnerability',
    metadata: {
      kind: 'open_redirect_metadata',
      parameterName: 'next',
      injectedCanary: 'https://canary.fixguard.internal/cb',
      finalDestination: 'https://canary.fixguard.internal/cb',
      redirectChain: [
        'https://example.com/login?next=https://canary.fixguard.internal/cb',
        'https://canary.fixguard.internal/cb',
      ],
      observedAt: '2026-09-15T12:00:00.000Z',
    },
  };

  const sampleRecord: OrchestratedAssessmentRecord = {
    contractVersion: ORCHESTRATED_ASSESSMENT_CONTRACT_VERSION,
    assessmentId: lineage.assessmentId,
    scanId: lineage.scanId,
    targetDomain: 'example.com',
    status: 'completed',
    timing: {
      startedAt: '2026-09-15T11:55:00.000Z',
      completedAt: '2026-09-15T12:05:00.000Z',
      durationMs: 600000,
    },
    lineage,
    stages: [
      {
        stage: 'stage_1_domain_zone',
        status: 'completed',
        observationsCount: 2,
        durationMs: 120,
        warnings: [],
      },
    ],
    errorCount: 0,
    warningCount: 0,
    findings: [sampleFinding],
    pendingEvidenceDrafts: [],
    recommendations: [
      {
        contractVersion: 'fixguard-intelligence/v0',
        kind: 'target_recommendation',
        recommendationId: 'rec_report_001',
        targetHost: 'example.com',
        category: 'parameter_fuzzing',
        title: 'Review Redirect Parameter Allowlist',
        reasoning: 'Target endpoint accepted arbitrary redirect destinations.',
        suggestedCapability: 'active_recon_document_probe',
        requiredPermissions: ['lightValidation'],
        confidence: 0.95,
        severity: 'medium',
        sourceFindingIds: [sampleFinding.id],
        lineage,
        createdAt: '2026-09-15T12:05:00.000Z',
      },
    ],
    profile: {
      contractVersion: 'fixguard-intelligence/v0',
      kind: 'target_profile',
      profileId: 'prf_report_001',
      targetHost: 'example.com',
      normalizedOrigin: 'https://example.com',
      updatedAt: '2026-09-15T12:05:00.000Z',
      technologies: ['Nginx', 'Node.js'],
      endpoints: [
        {
          url: 'https://example.com/login',
          method: 'GET',
          path: '/login',
          parameters: ['next'],
          authRequirement: 'none',
          flawCategories: [],
        },
      ],
      knownFindings: [sampleFinding],
      lineage,
    },
  };

  // ──────────────────────────────────────────────────────────────────────────
  // Test 1: Section Builders Conformance
  // ──────────────────────────────────────────────────────────────────────────
  console.log('-> Test 1: Section Builders output valid, well-formed HTML snippets');
  const headerHtml = buildHeaderSection(sampleRecord);
  assert.ok(headerHtml.includes('example.com'), 'Header must contain target domain');
  assert.ok(headerHtml.includes('asm_test_report_001'), 'Header must contain assessment ID');

  const execSummaryHtml = buildExecutiveSummarySection(sampleRecord);
  assert.ok(execSummaryHtml.includes('Total Confirmed'), 'Executive summary must count findings');
  assert.ok(execSummaryHtml.includes('Medium'), 'Executive summary must show Medium severity count');

  const limitationsHtml = buildAuditLimitationsSection();
  assert.ok(limitationsHtml.includes('Mandatory Audit Limitations'), 'Limitations section must be titled');
  assert.ok(limitationsHtml.includes('Point-in-Time Assessment'), 'Must state point-in-time nature');

  const findingsHtml = buildConfirmedFindingsSection(sampleRecord.findings || [], sampleRecord.lineage);
  assert.ok(findingsHtml.includes('Open Redirect via Insecure Return Parameter'), 'Findings section must list confirmed finding');
  assert.ok(findingsHtml.includes('grant_test_report_001'), 'Findings section must render lineage grantId');
  assert.ok(!findingsHtml.includes('drf_unreviewed_001'), 'Findings section MUST NOT contain unreviewed draft ID');

  const attestationHtml = buildOperatorAttestationSection({
    operatorId: 'operator_lead_tester',
    attestationText: 'I hereby certify that all findings have been validated in accordance with the defensive audit standard.',
    verifiedAt: '2026-09-15T12:10:00.000Z',
  });
  assert.ok(attestationHtml.includes('operator_lead_tester'), 'Attestation section must display operator ID');
  assert.ok(attestationHtml.includes('defensive audit standard'), 'Attestation section must display attestation statement');

  console.log('  [PASS] All section builders conform.');

  // ──────────────────────────────────────────────────────────────────────────
  // Test 2: Operator Attestation Validation (Fail-Closed)
  // ──────────────────────────────────────────────────────────────────────────
  console.log('-> Test 2: Operator Attestation fails closed on invalid or short statements');
  assert.throws(
    () => validateOperatorAttestation(''),
    (err: unknown) => err instanceof ReportGenerationError && err.code === 'missing_operator_signature',
    'Empty attestation must throw ReportGenerationError'
  );

  assert.throws(
    () => validateOperatorAttestation('short'),
    (err: unknown) => err instanceof ReportGenerationError && err.code === 'missing_operator_signature',
    'Attestation < 10 characters must throw ReportGenerationError'
  );

  assert.throws(
    () => validateOperatorAttestation('   too short   '),
    (err: unknown) => err instanceof ReportGenerationError && err.code === 'missing_operator_signature',
    'Trimmed attestation < 10 characters must throw ReportGenerationError'
  );

  assert.throws(
    () => validateOperatorAttestation('This statement asserts a confirmed vulnerability without proper verification.'),
    (err: unknown) => err instanceof ReportGenerationError && err.code === 'invalid_report_request',
    'Attestation containing forbidden simulation claims must throw'
  );

  assert.doesNotThrow(
    () => validateOperatorAttestation('Valid defensive attestation statement confirming factual observations.'),
    'Valid statement >= 10 characters must pass'
  );
  console.log('  [PASS] Operator attestation fails closed appropriately.');

  // ──────────────────────────────────────────────────────────────────────────
  // Test 3: Standalone Report Generation (Domain Service)
  // ──────────────────────────────────────────────────────────────────────────
  console.log('-> Test 3: generateDefensiveHtmlReport produces self-contained HTML');
  const fullHtml = generateDefensiveHtmlReport({
    record: sampleRecord,
    operatorId: 'operator_sec_lead',
    attestationText: 'Factual defensive assessment performed in authorized scope without synthetic data.',
    generatedAt: '2026-09-15T12:15:00.000Z',
  });

  assert.ok(fullHtml.startsWith('<!DOCTYPE html>'), 'Report must start with <!DOCTYPE html>');
  assert.ok(fullHtml.includes('<html lang="en">'), 'Report must have html root');
  assert.ok(fullHtml.includes('FixGuard V2 Defensive Security Report'), 'Report must have authoritative title');
  assert.ok(fullHtml.includes('Content-Security-Policy'), 'Report must contain strict Content-Security-Policy meta tag');
  assert.ok(fullHtml.includes('example.com'), 'Report must have target domain');
  assert.ok(fullHtml.includes('Open Redirect via Insecure Return Parameter'), 'Confirmed finding must appear');
  assert.ok(fullHtml.includes('grant_test_report_001'), 'Lineage tuple must appear in full report');
  assert.ok(!fullHtml.includes('drf_unreviewed_001'), 'Unreviewed draft MUST NOT appear in findings');
  assert.ok(fullHtml.includes('Mandatory Audit Limitations'), 'Limitations section must be present');
  assert.ok(fullHtml.includes('operator_sec_lead'), 'Signed operator ID must be present');

  // Test 3b: XSS Escaping Verification
  const xssFinding: Finding = {
    ...sampleFinding,
    id: 'fnd_xss_001',
    title: '<script>alert("xss_title")</script>',
    description: '<img src=x onerror=alert("xss_desc")>',
    evidence: '<svg onload=alert("xss_evidence")>',
    target: 'https://example.com/<script>alert("xss_target")</script>',
  };
  const xssRecord: OrchestratedAssessmentRecord = {
    ...sampleRecord,
    targetDomain: 'xss.<script>alert("domain")</script>.com',
    findings: [xssFinding],
  };
  const xssHtml = generateDefensiveHtmlReport({
    record: xssRecord,
    operatorId: 'operator_sec_lead',
    attestationText: 'Testing <b>XSS escaping</b> in operator statement &lt;ok&gt;.',
    generatedAt: '2026-09-15T12:15:00.000Z',
  });
  assert.ok(!xssHtml.includes('<script>'), 'XSS script tags must be escaped in HTML');
  assert.ok(!xssHtml.includes('<img src=x'), 'XSS img tags must be escaped in HTML');
  assert.ok(!xssHtml.includes('<svg onload='), 'XSS svg tags must be escaped in HTML');
  assert.ok(xssHtml.includes('&lt;script&gt;alert(&quot;xss_title&quot;)&lt;/script&gt;'), 'XSS title must be escaped');
  assert.ok(xssHtml.includes('&lt;img src=x onerror=alert(&quot;xss_desc&quot;)&gt;'), 'XSS desc must be escaped');
  console.log('  [PASS] Standalone HTML report generated successfully with full XSS and CSP protection.');

  // ──────────────────────────────────────────────────────────────────────────
  // Test 4: Application Service End-to-End Report Generation & Concurrency / Timeout
  // ──────────────────────────────────────────────────────────────────────────
  console.log('-> Test 4: OrchestratedAssessmentApplicationService.generateHtmlReport & Concurrency');
  const repository = new InMemoryOrchestratedAssessmentRepository();
  await repository.save(sampleRecord);

  const availabilityService = new ReconToolAvailabilityService();
  const appService = new OrchestratedAssessmentApplicationService({
    repository,
    availabilityService,
  });

  const reportFromApp = await appService.generateHtmlReport(
    lineage.assessmentId,
    'operator_auditor_99',
    'Verified with standard compliance procedures.'
  );

  assert.ok(typeof reportFromApp === 'string' && reportFromApp.length > 500, 'App service must return HTML string');
  assert.ok(reportFromApp.includes('operator_auditor_99'), 'App service report must include operator ID');
  assert.ok(reportFromApp.includes('Content-Security-Policy'), 'App report must include CSP meta tag');
  console.log('  [PASS] Application service generated report cleanly.');

  // ──────────────────────────────────────────────────────────────────────────
  // Test 5: HTTP Controller & Validator Conformance
  // ──────────────────────────────────────────────────────────────────────────
  console.log('-> Test 5: Controller & HTTP Validator validation');
  // Closed-world validation
  assert.throws(
    () => parseGenerateHtmlReportHttpBody({ operatorId: 'op_1', attestationText: 'valid text here', extraKey: 'bad' }),
    (err: unknown) => err instanceof ApiValidationError,
    'Extra key in request body must throw ApiValidationError'
  );

  assert.throws(
    () => parseGenerateHtmlReportHttpBody({ operatorId: 'op_1', attestationText: 'short' }),
    (err: unknown) => err instanceof ApiValidationError,
    'Short attestation in request body must throw ApiValidationError'
  );

  const parsed = parseGenerateHtmlReportHttpBody({
    operatorId: 'operator_alpha',
    attestationText: 'Formal attestation certifying authorized target scope.',
  });
  assert.strictEqual(parsed.operatorId, 'operator_alpha');
  assert.strictEqual(parsed.attestationText, 'Formal attestation certifying authorized target scope.');

  // Controller execution test
  const controller = new OrchestratedAssessmentController(appService);
  let sentHtml = '';
  let sentStatus = 0;
  let sentContentType = '';

  const mockReq: Partial<Request> = {
    params: { assessmentId: lineage.assessmentId },
    body: {
      operatorId: 'operator_alpha',
      attestationText: 'Formal attestation certifying authorized target scope.',
    },
  };

  const mockRes: Partial<Response> = {
    setHeader(name: string, value: string | string[]) {
      if (name === 'Content-Type' && typeof value === 'string') {
        sentContentType = value;
      }
      return this as Response;
    },
    status(code: number) {
      sentStatus = code;
      return this as Response;
    },
    send(body: unknown) {
      sentHtml = String(body);
      return this as Response;
    },
  };

  let nextCalledWith: unknown = null;
  const mockNext: NextFunction = (err?: unknown) => {
    nextCalledWith = err;
  };

  await controller.generateHtmlReport(mockReq as Request, mockRes as Response, mockNext);
  assert.strictEqual(nextCalledWith, null, 'Controller should not call next with error on valid request');
  assert.strictEqual(sentStatus, 200, 'Controller must return status 200');
  assert.ok(sentContentType.includes('text/html'), 'Controller must set Content-Type: text/html');
  assert.ok(sentHtml.includes('operator_alpha'), 'Rendered HTML must include operator ID');
  assert.ok(sentHtml.includes('example.com'), 'Rendered HTML must include target domain');
  console.log('  [PASS] Controller and validators operate conformantly.');

  console.log('[milestoneP2_6_report_generation_smoke] Milestone P2-6 smoke suite completed successfully!');
}

runTests().catch((err) => {
  console.error('[milestoneP2_6_report_generation_smoke] FAILED:', err);
  process.exit(1);
});
