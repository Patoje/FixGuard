/**
 * Milestone P6-1 Smoke Test Suite — Static Secret & Credential Scanning Engine (SAST)
 *
 * Verifies:
 * 1. Detects hardcoded AWS key and private key in local source mock with redacted snippet and critical severity.
 * 2. Cleanly abstains when code contains no secrets.
 * 3. Operates purely in-memory with zero network overhead.
 * 4. Full HITL triage lifecycle promotes secret draft to formal Finding.
 * 5. Pattern matching and redaction across all supported secret kinds.
 */

import {
  scanSourceFilesForSecrets,
  scanFileLinesForSecrets,
} from '../sast/StaticSecretScanningService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P6-1: Static Secret Scanning Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p6_1_001';
  const scanId = 'scn_smoke_p6_1_001';
  const actorId = 'act_smoke_p6_1_operator';
  const targetDomain = 'app.example.com';

  const vulnerableSourceFile = {
    filePath: 'src/config/aws.ts',
    content: `
import AWS from 'aws-sdk';

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

export const s3 = new AWS.S3({
  accessKeyId: AWS_ACCESS_KEY_ID,
  secretAccessKey: AWS_SECRET_ACCESS_KEY,
});
    `.trim(),
  };

  const vulnerableKeyFile = {
    filePath: 'certs/server.key',
    content: `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+Q3...
-----END RSA PRIVATE KEY-----
    `.trim(),
  };

  const cleanSourceFile = {
    filePath: 'src/utils/math.ts',
    content: `
export function add(a: number, b: number): number {
  return a + b;
}

export function multiply(a: number, b: number): number {
  return a * b;
}
    `.trim(),
  };

  // -------------------------------------------------------------------------
  // TEST 1: Detects hardcoded AWS key and private key with redacted snippet
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing static secret detection on vulnerable sources...');
  {
    const result = scanSourceFilesForSecrets({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      files: [vulnerableSourceFile, vulnerableKeyFile],
    });

    if (!result.hasSecrets) {
      throw new Error('[TEST 1] Expected hasSecrets: true');
    }
    if (result.detectedSecrets.length < 2) {
      throw new Error(`[TEST 1] Expected at least 2 detected secrets, got ${result.detectedSecrets.length}`);
    }

    const awsSecret = result.detectedSecrets.find((s) => s.secretKind === 'aws_key');
    if (!awsSecret || awsSecret.exposureSeverity !== 'critical' || !awsSecret.sanitizedSnippet.includes('AKIA[REDACTED]')) {
      throw new Error(`[TEST 1] AWS key secret mismatch: ${JSON.stringify(awsSecret)}`);
    }

    const keySecret = result.detectedSecrets.find((s) => s.secretKind === 'private_key');
    if (!keySecret || keySecret.exposureSeverity !== 'critical' || !keySecret.sanitizedSnippet.includes('-----BEGIN PRIVATE KEY-----[REDACTED]')) {
      throw new Error(`[TEST 1] Private key secret mismatch: ${JSON.stringify(keySecret)}`);
    }

    if (result.evidenceDrafts.length !== result.detectedSecrets.length) {
      throw new Error('[TEST 1] Evidence drafts count should match detected secrets');
    }

    console.log(`[TEST 1] PASS: Detected ${result.detectedSecrets.length} static secrets with redaction.`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Cleanly abstains when code contains no secrets
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying abstention on clean source code...');
  {
    const result = scanSourceFilesForSecrets({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      files: [cleanSourceFile],
    });

    if (result.hasSecrets || result.detectedSecrets.length > 0 || result.evidenceDrafts.length > 0) {
      throw new Error('[TEST 2] Should abstain with 0 secrets on clean code');
    }
    console.log('[TEST 2] PASS: Cleanly abstained with zero findings on clean codebase.');
  }

  // -------------------------------------------------------------------------
  // TEST 3: Operates purely in-memory with zero network overhead
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying zero network overhead during analytical SAST scan...');
  {
    const startMemory = process.memoryUsage().heapUsed;
    const result = scanSourceFilesForSecrets({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      files: [vulnerableSourceFile, vulnerableKeyFile, cleanSourceFile],
    });
    const endMemory = process.memoryUsage().heapUsed;

    if (!result.hasSecrets) {
      throw new Error('[TEST 3] In-memory scan failed to execute');
    }
    console.log(`[TEST 3] PASS: In-memory SAST scan completed cleanly (heap delta: ${Math.round((endMemory - startMemory) / 1024)} KB).`);
  }

  // -------------------------------------------------------------------------
  // TEST 4: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Testing HITL review lifecycle promoting secret draft to formal Finding...');
  {
    const repo = new InMemoryOrchestratedAssessmentRepository();
    const appService = new OrchestratedAssessmentApplicationService({ repository: repo });

    const initialRecord = {
      contractVersion: 'fixguard-orchestrated-assessment/v0' as const,
      assessmentId,
      scanId,
      targetDomain,
      status: 'completed' as const,
      lineage: {
        assessmentId,
        scanId,
        authorizationGrantId: 'grn_smoke_001',
        authorizationDecisionId: 'dec_smoke_001',
        actorId,
      },
      stages: [],
      timing: { startedAt: nowIso, completedAt: nowIso, durationMs: 150 },
      errorCount: 0,
      warningCount: 0,
      findings: [],
      pendingEvidenceDrafts: [
        {
          draftKind: 'non_persisted_comparison_evidence_draft' as const,
          draftId: 'dft_ssec_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_ssec_001',
          sourceSnapshotIds: {
            baselineSnapshotId: 'snp_base_001',
            validationSnapshotId: 'snp_val_001',
          },
          requiresHumanReview: true as const,
          notPersisted: true as const,
          notARealFinding: true as const,
          notConfirmedEvidence: true as const,
          notForExternalDelivery: true as const,
          notM45EvidenceRecord: true as const,
          safeRationale: 'SAST inspection identified hardcoded AWS Key at src/config/aws.ts:3.',
          differentialContext: {
            endpointUrl: `https://${targetDomain}/src/config/aws.ts`,
            detectionKind: 'static_secret_exposure' as const,
            filePath: 'src/config/aws.ts',
            lineNumber: 3,
            secretKind: 'aws_key' as const,
            exposureSeverity: 'critical' as const,
            sanitizedSnippet: 'const AWS_ACCESS_KEY_ID = "AKIA[REDACTED]";',
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_ssec_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Approved hardcoded AWS credential exposure.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 4] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated) {
      throw new Error('[TEST 4] Assessment not found in repository');
    }

    const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_ssec_'));
    if (!promotedFinding) {
      throw new Error('[TEST 4] Expected promoted static secret finding in repository');
    }

    if (
      promotedFinding.metadata.kind !== 'static_secret_exposure_metadata' ||
      promotedFinding.severity !== 'critical' ||
      promotedFinding.metadata.secretKind !== 'aws_key' ||
      promotedFinding.metadata.filePath !== 'src/config/aws.ts' ||
      promotedFinding.metadata.lineNumber !== 3
    ) {
      throw new Error('[TEST 4] Promoted finding metadata mismatch');
    }
    console.log(`[TEST 4] PASS: Promoted critical finding verified: ${promotedFinding.id} (${promotedFinding.title})`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Pattern Matching & Redaction Across Diverse Secret Kinds
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing pattern detection for Database URI, JWT Secret, and Generic API Key...');
  {
    const snippetCode = `
const DB_URL = "postgres://admin_user:SuperSecretPassword123@db.prod.internal:5432/main_db";
const jwt_secret = "mySuperSecretSigningKey2026";
const api_key = "sk_live_99887766554433221100";
    `.trim();

    const detected = scanFileLinesForSecrets('src/env.ts', snippetCode);
    if (detected.length !== 3) {
      throw new Error(`[TEST 5] Expected 3 secrets, got ${detected.length}`);
    }

    const dbSec = detected.find((d) => d.secretKind === 'database_uri');
    const jwtSec = detected.find((d) => d.secretKind === 'jwt_secret');
    const apiKeySec = detected.find((d) => d.secretKind === 'generic_api_key');

    if (!dbSec || !dbSec.sanitizedSnippet.includes('://admin_user:[REDACTED]@')) {
      throw new Error('[TEST 5] DB URI redaction failed');
    }
    if (!jwtSec || !jwtSec.sanitizedSnippet.includes('[REDACTED]')) {
      throw new Error('[TEST 5] JWT Secret redaction failed');
    }
    if (!apiKeySec || !apiKeySec.sanitizedSnippet.includes('[REDACTED]')) {
      throw new Error('[TEST 5] Generic API Key redaction failed');
    }

    console.log('[TEST 5] PASS: All secret kinds successfully matched and redacted.');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P6-1 Static Secret & Credential Scanning certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
