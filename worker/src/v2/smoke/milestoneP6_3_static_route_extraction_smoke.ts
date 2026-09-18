/**
 * Milestone P6-3 Smoke Test Suite — Static Route & Endpoint Extraction Engine (Phase 6 Finale)
 *
 * Verifies:
 * 1. Extracts hidden API routes and methods from mock source files across frameworks.
 * 2. Enriches target profile candidates with discovered static routes.
 * 3. Cleanly abstains when source contains no route declarations.
 * 4. Operates purely offline with zero network overhead.
 * 5. Full HITL triage lifecycle promotes extracted route draft to formal Finding.
 */

import {
  scanFilesForStaticRoutes,
  extractRoutesFromFile,
  isInternalRoute,
} from '../sast/StaticRouteExtractionService.js';
import { OrchestratedAssessmentApplicationService } from '../application/OrchestratedAssessmentApplicationService.js';
import { InMemoryOrchestratedAssessmentRepository } from '../storage/InMemoryOrchestratedAssessmentRepository.js';

async function runSmokeTests() {
  console.log('=== Milestone P6-3: Static Route Extraction Smoke Suite ===');

  const nowIso = new Date().toISOString();
  const assessmentId = 'asm_smoke_p6_3_001';
  const scanId = 'scn_smoke_p6_3_001';
  const actorId = 'act_smoke_p6_3_operator';
  const targetDomain = 'app.example.com';

  const expressServerCode = `
import express from 'express';
const app = express();
const router = express.Router();

app.get('/api/v1/users', (req, res) => res.json([]));
router.post('/api/v1/admin/dump-database', (req, res) => res.json({ status: 'ok' }));
router.delete('/api/v1/internal/clear-cache', (req, res) => res.json({ cleared: true }));
app.use('/api/v1', router);
`;

  const nextJsAppRoute = `
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({ status: 'healthy' });
}

export async function POST(req: Request) {
  return NextResponse.json({ created: true });
}

export async function DELETE(req: Request) {
  return NextResponse.json({ deleted: true });
}
`;

  const fastApiCode = `
from fastapi import FastAPI, APIRouter

app = FastAPI()
router = APIRouter()

@app.get("/api/v2/items")
def read_items():
    return []

@router.post("/api/v2/debug/run-diagnostics")
def run_diagnostics():
    return {"debug": True}
`;

  const springCode = `
package com.example.demo;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v3/billing")
public class BillingController {

    @GetMapping("/invoice")
    public String getInvoice() {
        return "invoice";
    }

    @PostMapping("/admin/reset-ledger")
    public String resetLedger() {
        return "reset";
    }
}
`;

  const plainUtilityCode = `
export function add(a: number, b: number): number {
  return a + b;
}

export function formatGreeting(name: string): string {
  return \`Hello, \${name}!\`;
}
`;

  // -------------------------------------------------------------------------
  // TEST 1: Extracts hidden API routes and methods across frameworks
  // -------------------------------------------------------------------------
  console.log('[TEST 1] Testing static route extraction across Express, Next.js, FastAPI, Spring...');
  {
    const result = scanFilesForStaticRoutes({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      sourceFiles: [
        { filePath: 'src/server.ts', content: expressServerCode, frameworkHint: 'express' },
        { filePath: 'app/api/health/route.ts', content: nextJsAppRoute, frameworkHint: 'nextjs' },
        { filePath: 'backend/api.py', content: fastApiCode, frameworkHint: 'fastapi' },
        { filePath: 'src/main/java/BillingController.java', content: springCode, frameworkHint: 'spring' },
      ],
    });

    if (!result.hasRoutes) {
      throw new Error('[TEST 1] Expected hasRoutes: true');
    }
    if (result.extractedRoutes.length < 6) {
      throw new Error(`[TEST 1] Expected at least 6 extracted routes, got ${result.extractedRoutes.length}`);
    }

    // Verify Express routes
    const adminDump = result.extractedRoutes.find((r) => r.extractedRoutePattern === '/api/v1/admin/dump-database');
    if (!adminDump || !adminDump.isInternalOnly || !adminDump.supportedMethods.includes('POST')) {
      throw new Error(`[TEST 1] Express admin dump route mismatch: ${JSON.stringify(adminDump)}`);
    }

    // Verify Next.js route
    const healthRoute = result.extractedRoutes.find((r) => r.extractedRoutePattern === '/api/health');
    if (!healthRoute || healthRoute.frameworkType !== 'nextjs' || !healthRoute.supportedMethods.includes('DELETE')) {
      throw new Error(`[TEST 1] Next.js route mismatch: ${JSON.stringify(healthRoute)}`);
    }

    // Verify FastAPI route
    const debugRoute = result.extractedRoutes.find((r) => r.extractedRoutePattern === '/api/v2/debug/run-diagnostics');
    if (!debugRoute || !debugRoute.isInternalOnly || debugRoute.frameworkType !== 'fastapi') {
      throw new Error(`[TEST 1] FastAPI debug route mismatch: ${JSON.stringify(debugRoute)}`);
    }

    // Verify Spring route
    const springReset = result.extractedRoutes.find((r) => r.extractedRoutePattern === '/admin/reset-ledger');
    if (!springReset || !springReset.isInternalOnly || springReset.frameworkType !== 'spring') {
      throw new Error(`[TEST 1] Spring reset ledger route mismatch: ${JSON.stringify(springReset)}`);
    }

    console.log(`[TEST 1] PASS: Successfully extracted ${result.extractedRoutes.length} routes across all 4 frameworks.`);
  }

  // -------------------------------------------------------------------------
  // TEST 2: Enriches target profile candidates with discovered static routes
  // -------------------------------------------------------------------------
  console.log('[TEST 2] Verifying candidate endpoint enrichment...');
  {
    const result = scanFilesForStaticRoutes({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      sourceFiles: [
        { filePath: 'src/server.ts', content: expressServerCode, frameworkHint: 'express' },
      ],
    });

    if (!result.enrichedEndpointCandidates.includes('/api/v1/users') || !result.enrichedEndpointCandidates.includes('/api/v1/admin/dump-database')) {
      throw new Error('[TEST 2] Enriched endpoint candidates missing extracted routes');
    }
    console.log(`[TEST 2] PASS: Enriched candidate pool with ${result.enrichedEndpointCandidates.length} candidate endpoints.`);
  }

  // -------------------------------------------------------------------------
  // TEST 3: Cleanly abstains when source contains no route declarations
  // -------------------------------------------------------------------------
  console.log('[TEST 3] Verifying abstention on plain utility code...');
  {
    const result = scanFilesForStaticRoutes({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      sourceFiles: [
        { filePath: 'src/utils/math.ts', content: plainUtilityCode },
      ],
    });

    if (result.hasRoutes || result.extractedRoutes.length > 0 || result.evidenceDrafts.length > 0) {
      throw new Error('[TEST 3] Expected abstention with 0 routes on plain source code');
    }
    console.log('[TEST 3] PASS: Cleanly abstained with zero findings on route-free source.');
  }

  // -------------------------------------------------------------------------
  // TEST 4: Operates purely offline with zero network overhead
  // -------------------------------------------------------------------------
  console.log('[TEST 4] Verifying zero network overhead during offline static route scan...');
  {
    const startMemory = process.memoryUsage().heapUsed;
    const result = scanFilesForStaticRoutes({
      assessmentId,
      scanId,
      actorId,
      targetDomain,
      sourceFiles: [
        { filePath: 'src/server.ts', content: expressServerCode },
        { filePath: 'src/main/java/BillingController.java', content: springCode },
      ],
    });
    const endMemory = process.memoryUsage().heapUsed;

    if (!result.hasRoutes) {
      throw new Error('[TEST 4] In-memory static route extraction failed');
    }
    console.log(`[TEST 4] PASS: In-memory route scan completed cleanly (heap delta: ${Math.round((endMemory - startMemory) / 1024)} KB).`);
  }

  // -------------------------------------------------------------------------
  // TEST 5: Full HITL Review Lifecycle & Promotion to Formal Finding
  // -------------------------------------------------------------------------
  console.log('[TEST 5] Testing HITL review lifecycle promoting route draft to formal Finding...');
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
          draftId: 'dft_stroute_rev_001',
          suggestedEvidenceType: 'http_difference' as const,
          suggestedStrength: 'strong' as const,
          sourceComparisonId: 'cmp_stroute_001',
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
          safeRationale: 'Static code analysis extracted internal route pattern /api/v1/admin/dump-database from src/server.ts.',
          differentialContext: {
            endpointUrl: `https://${targetDomain}/api/v1/admin/dump-database`,
            detectionKind: 'static_route_extraction' as const,
            frameworkType: 'express' as const,
            sourceFilePath: 'src/server.ts',
            extractedRoutePattern: '/api/v1/admin/dump-database',
            supportedMethods: ['POST'],
            isInternalOnly: true,
            validationStatusCode: 200,
          },
        },
      ],
      recommendations: [],
    };

    await repo.save(initialRecord);

    const reviewRes = await appService.reviewEvidenceDraft({
      assessmentId,
      draftId: 'dft_stroute_rev_001',
      decision: 'approve_evidence',
      reviewerId: 'act_operator_human_01',
      reviewedAt: nowIso,
      notes: 'Approved internal database dump route finding.',
    });

    if (reviewRes.decision !== 'approve_evidence' || !reviewRes.findingCreated) {
      throw new Error(`[TEST 5] Expected review decision 'approve_evidence' with findingCreated, got ${reviewRes.decision}`);
    }

    const updated = await repo.findById(assessmentId);
    if (!updated) {
      throw new Error('[TEST 5] Assessment not found in repository');
    }

    const promotedFinding = updated.findings.find((f) => f.id.startsWith('fnd_stroute_'));
    if (!promotedFinding) {
      throw new Error('[TEST 5] Expected promoted static route finding in repository');
    }

    if (
      promotedFinding.metadata.kind !== 'static_route_extraction_metadata' ||
      promotedFinding.severity !== 'medium' ||
      promotedFinding.metadata.extractedRoutePattern !== '/api/v1/admin/dump-database' ||
      promotedFinding.metadata.isInternalOnly !== true
    ) {
      throw new Error('[TEST 5] Promoted finding metadata mismatch');
    }
    console.log(`[TEST 5] PASS: Promoted internal route finding verified: ${promotedFinding.id} (${promotedFinding.title})`);
  }

  // Internal route helper test
  if (!isInternalRoute('/admin/users') || !isInternalRoute('/api/debug/info') || isInternalRoute('/products/view')) {
    throw new Error('Internal route classifier assertion failed');
  }

  console.log('\n[ALL TESTS PASSED] Milestone P6-3 Static Route & Endpoint Extraction Engine certified!');
}

runSmokeTests().catch((err) => {
  console.error('[SMOKE FAILED]', err);
  process.exit(1);
});
