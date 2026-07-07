import assert from 'node:assert';
import process from 'node:process';
import type {
  ObservationRecord,
  IndicatorRecord,
  EvidenceRecord,
  EvidenceBoundaryContractVersion,
  EvidenceBoundaryClassificationFlags
} from '../evidence/EvidenceBoundaryContracts.js';
import {
  validateObservationRecord,
  validateIndicatorRecord,
  validateEvidenceRecord,
  validateFindingCandidateRecord,
  validateSafeReportItemSnapshot,
  evaluateFindingPromotion,
  buildFindingCandidateFromPromotion,
  buildSafeReportItemSnapshot,
  getSafeClassification,
  validateSafeHash,
  forbiddenContentScan
} from '../evidence/EvidenceBoundaryService.js';

function checkClassificationFlags(obj: any, label: string) {
  assert.strictEqual(obj.classification.createsRealFindings, false, `${label}: createsRealFindings`);
  assert.strictEqual(obj.classification.createsPersistedEvidence, false, `${label}: createsPersistedEvidence`);
  assert.strictEqual(obj.classification.confirmsVulnerabilities, false, `${label}: confirmsVulnerabilities`);
  assert.strictEqual(obj.classification.makesRiskClaims, false, `${label}: makesRiskClaims`);
  assert.strictEqual(obj.classification.makesSeverityClaims, false, `${label}: makesSeverityClaims`);
  assert.strictEqual(obj.classification.makesImpactClaims, false, `${label}: makesImpactClaims`);
}

async function runTests() {
  console.log('--- V2 Evidence Boundary DB-Free Smoke Test ---');

  const baseClassification = getSafeClassification();

  const validObservation: ObservationRecord = {
    contractVersion: 'fixguard-evidence-boundary/v0',
    kind: 'observation_record',
    observationId: 'obs_1',
    scanId: 'scan_1',
    observedAt: new Date().toISOString(),
    sourceKind: 'tool_adapter',
    observationType: 'raw_tool_output_observed',
    subject: { pathTemplate: '/api/v1/users' },
    provenance: { description: 'From mock adapter' },
    safeData: { rawOutputHash: 'abc123safehash' },
    classification: baseClassification
  };

  const validIndicator: IndicatorRecord = {
    contractVersion: 'fixguard-evidence-boundary/v0',
    kind: 'indicator_record',
    indicatorId: 'ind_1',
    scanId: 'scan_1',
    derivedFromObservationIds: ['obs_1'],
    indicatorType: 'misconfiguration_candidate',
    target: { pathTemplate: '/api/v1/users' },
    confidence: 0.8,
    rationale: 'Header detected',
    suggestedValidation: 'Perform manual check',
    requiresHumanApproval: true,
    approvalLevelRequired: 'none',
    classification: baseClassification
  };

  const validEvidence: EvidenceRecord = {
    contractVersion: 'fixguard-evidence-boundary/v0',
    kind: 'evidence_record',
    evidenceId: 'ev_1',
    scanId: 'scan_1',
    indicatorId: 'ind_1',
    collectedAt: new Date().toISOString(),
    collectedBy: 'response_comparator',
    evidenceType: 'http_difference',
    redaction: { isRedacted: true, redactionMethod: 'omitted' },
    strength: 'strong',
    classification: baseClassification
  };

  console.log('[*] Testing valid records...');
  assert.strictEqual(validateObservationRecord(validObservation).isValid, true);
  assert.strictEqual(validateIndicatorRecord(validIndicator).isValid, true);
  assert.strictEqual(validateEvidenceRecord(validEvidence).isValid, true);
  console.log('[+] Valid records pass validation.');

  console.log('[*] Testing "No direct finding from tool output"...');
  const invalidPromotion = buildFindingCandidateFromPromotion({
    indicator: validIndicator,
    evidenceRecords: [],
    candidateId: 'cand_1',
    now: new Date().toISOString()
  });
  assert.strictEqual(invalidPromotion.status, 'failed');
  assert.strictEqual(invalidPromotion.error?.code, 'insufficient_evidence');
  console.log('[+] Raw tool output requires Indicator + Evidence to become Candidate.');

  console.log('[*] Testing wrong contractVersion...');
  assert.strictEqual(validateObservationRecord({ ...validObservation, contractVersion: 'wrong' as any }).isValid, false);
  assert.strictEqual(validateIndicatorRecord({ ...validIndicator, contractVersion: 'wrong' as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, contractVersion: 'wrong' as any }).isValid, false);

  console.log('[*] Testing classification flags true...');
  const badClass: EvidenceBoundaryClassificationFlags = { ...baseClassification, createsRealFindings: true as any };
  assert.strictEqual(validateObservationRecord({ ...validObservation, classification: badClass }).isValid, false);

  console.log('[*] Testing unknown fields on classification flags...');
  const unknownClass = { ...baseClassification, extraClaim: true };
  assert.strictEqual(validateObservationRecord({ ...validObservation, classification: unknownClass }).isValid, false);

  console.log('[*] Testing invalid enum values...');
  assert.strictEqual(validateObservationRecord({ ...validObservation, sourceKind: 'scanner' as any }).isValid, false);
  assert.strictEqual(validateIndicatorRecord({ ...validIndicator, indicatorType: 'confirmed_vulnerability' as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, strength: 'critical' as any }).isValid, false);

  console.log('[*] Testing redaction.isRedacted false and unsafe redactionMethod...');
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, redaction: { isRedacted: false as any, redactionMethod: 'none' } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, redaction: { isRedacted: true, redactionMethod: 'this is a secret_token_123' } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, redaction: { isRedacted: true, redactionMethod: 'none', secret: true } as any }).isValid, false);

  console.log('[*] Testing unsafe snapshot internals...');
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, baseline: { method: 'INVALID' as any } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, baseline: { pathTemplate: '/api?query=1' } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, baseline: { headerNames: ['Authorization'] } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, difference: { newJsonKeys: ['secret_token_123'] } }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, baseline: { contentLength: -10 } }).isValid, false);
  
  // Extra unknown fields
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, baseline: { rawBody: 'unsafe' } as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, attackOrValidation: { rawPayload: 'unsafe' } as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, difference: { risk: 'high' } as any }).isValid, false);

  console.log('[*] Testing invalid/unsafe hashes...');
  assert.strictEqual(validateSafeHash('hash with space').isValid, false);
  assert.strictEqual(validateSafeHash('hash/with/slash').isValid, false);
  assert.strictEqual(validateSafeHash('hash?with=query').isValid, false);
  assert.strictEqual(validateSafeHash('hash_secret_token').isValid, false);

  console.log('[*] Testing forbidden content scan...');
  const forbiddenTerms = ['raw request', 'raw response', 'raw payload', 'raw tool output', 'secret', 'cookie', 'authorization', 'bearer', 'confirmed vulnerability', 'target is vulnerable', 'critical severity'];
  for (const term of forbiddenTerms) {
    assert.strictEqual(forbiddenContentScan(term), true, `Term failed forbidden check: ${term}`);
  }
  console.log('[+] Forbidden content scanner works.');

  console.log('[*] Testing Promotion rules (auth, oob, sqli, mismatches)...');
  const authInd = { ...validIndicator, indicatorType: 'idor_candidate' as const };
  assert.strictEqual(evaluateFindingPromotion({ indicator: authInd, evidenceRecords: [validEvidence] }).status, 'needs_more_evidence'); // generic diff not enough
  assert.strictEqual(evaluateFindingPromotion({ indicator: authInd, evidenceRecords: [{ ...validEvidence, evidenceType: 'authorization_difference' }] }).status, 'eligible_for_candidate');
  assert.strictEqual(evaluateFindingPromotion({ indicator: authInd, evidenceRecords: [{ ...validEvidence, difference: { authStateChanged: true } }] }).status, 'eligible_for_candidate');

  const oobInd = { ...validIndicator, indicatorType: 'oob_validation_candidate' as const };
  assert.strictEqual(evaluateFindingPromotion({ indicator: oobInd, evidenceRecords: [validEvidence] }).status, 'needs_more_evidence'); // moderate generic diff
  assert.strictEqual(evaluateFindingPromotion({ indicator: oobInd, evidenceRecords: [{ ...validEvidence, evidenceType: 'oob_callback', strength: 'weak' }] }).status, 'needs_more_evidence'); // weak oob
  assert.strictEqual(evaluateFindingPromotion({ indicator: oobInd, evidenceRecords: [{ ...validEvidence, evidenceType: 'oob_callback', strength: 'strong' }] }).status, 'eligible_for_candidate');

  const sqliInd = { ...validIndicator, indicatorType: 'potential_sqli' as const };
  assert.strictEqual(evaluateFindingPromotion({ indicator: sqliInd, evidenceRecords: [validEvidence] }).status, 'needs_more_evidence');
  assert.strictEqual(evaluateFindingPromotion({ indicator: sqliInd, evidenceRecords: [{ ...validEvidence, evidenceType: 'time_based_difference', strength: 'strong' }] }).status, 'eligible_for_candidate');

  console.log('[*] Testing FindingCandidate building...');
  const buildRes = buildFindingCandidateFromPromotion({
    indicator: validIndicator,
    evidenceRecords: [validEvidence],
    candidateId: 'cand_1',
    now: new Date().toISOString()
  });
  assert.strictEqual(buildRes.status, 'completed');
  const candidate = buildRes.candidate!;

  console.log('[*] Testing FindingCandidate extra unknown fields (strict allowed-keys)...');
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, severity: 'critical' }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, risk: 'high' }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, impact: 'data exposure' }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, rawToolOutput: '...' }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, severityGate: { status: 'not_assessed', reason: 'a', severity: 'critical' } }).isValid, false);
  console.log('[+] Unknown fields safely rejected from FindingCandidate.');
  
  console.log('[*] Testing invalid array strings vs real arrays...');
  assert.strictEqual(validateObservationRecord({ ...validObservation, safeData: { headerNames: "Authorization" } as any }).isValid, false);
  assert.strictEqual(validateIndicatorRecord({ ...validIndicator, derivedFromObservationIds: "obs_1" as any }).isValid, false);
  assert.strictEqual(validateIndicatorRecord({ ...validIndicator, derivedFromObservationIds: [] as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, difference: { newJsonKeys: "secret_token_123" } as any }).isValid, false);
  assert.strictEqual(validateEvidenceRecord({ ...validEvidence, difference: { missingJsonKeys: "secret_token_123" } as any }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, derivedFromIndicatorIds: "ind_1" as any }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, evidenceIds: "ev_1" as any }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, derivedFromIndicatorIds: [] as any }).isValid, false);
  assert.strictEqual(validateFindingCandidateRecord({ ...candidate, evidenceIds: [] as any }).isValid, false);
  console.log('[+] Arrays are strictly validated.');
  
  console.log('[*] Testing Severity safety...');
  assert.strictEqual((candidate as any).severity, undefined);
  assert.strictEqual(candidate.severityGate.status, 'not_assessed');
  console.log('[+] FindingCandidate uses severityGate, no real severity assigned.');

  console.log('[*] Testing FindingCandidate non-real flags...');
  assert.strictEqual(candidate.isRealFinding, false);
  assert.strictEqual(candidate.requiresHumanReview, true);
  assert.strictEqual(candidate.notForExternalDelivery, true);
  console.log('[+] Candidate safely flagged as non-real and requires review.');

  console.log('[*] Testing Safe Report Item Snapshot...');
  const reportRes = buildSafeReportItemSnapshot({ candidate, evidenceRecords: [validEvidence] });
  assert.strictEqual(reportRes.status, 'completed');
  const report = reportRes.reportItem!;

  console.log('[*] Testing Report extra unknown fields (strict allowed-keys)...');
  assert.strictEqual(validateSafeReportItemSnapshot({ ...report, severity: 'critical' }).isValid, false);
  assert.strictEqual(validateSafeReportItemSnapshot({ ...report, externalDeliveryReady: true }).isValid, false);
  assert.strictEqual(validateSafeReportItemSnapshot({ ...report, rawResponse: 'unsafe' }).isValid, false);
  assert.strictEqual(validateSafeReportItemSnapshot({ ...report, reportReadiness: { ...report.reportReadiness, finalReport: true } }).isValid, false);
  assert.strictEqual(validateSafeReportItemSnapshot({ ...report, explicitNonClaims: { ...report.explicitNonClaims, confirmed: true } }).isValid, false);
  console.log('[+] Unknown fields safely rejected from Safe Report Snapshot.');

  console.log('[*] Testing Report readiness / non-claims...');
  assert.strictEqual(report.reportReadiness.externalDeliveryReady, false);
  assert.strictEqual(report.reportReadiness.requiresHumanReview, true);
  assert.strictEqual(report.reportReadiness.notAFinalVulnerabilityReport, true);
  assert.strictEqual(report.explicitNonClaims.noConfirmedVulnerability, true);
  assert.strictEqual(report.explicitNonClaims.noRealFindingCreated, true);
  assert.strictEqual(report.explicitNonClaims.noPersistedEvidenceCreated, true);
  assert.strictEqual(report.explicitNonClaims.noRiskSeverityOrImpactClaim, true);
  assert.strictEqual(report.explicitNonClaims.noRawSensitiveDataIncluded, true);
  console.log('[+] Report readiness and non-claims are correct.');

  console.log('[*] Testing Classification flags...');
  checkClassificationFlags(validObservation, 'Observation');
  checkClassificationFlags(validIndicator, 'Indicator');
  checkClassificationFlags(validEvidence, 'Evidence');
  checkClassificationFlags(candidate, 'Candidate');
  checkClassificationFlags(report, 'Report');
  console.log('[+] Classification flags safely assert no claims.');

  console.log('[*] Testing Safe report item content for forbidden terms...');
  const reportStr = JSON.stringify(report).toLowerCase();
  for (const term of forbiddenTerms) {
    if (reportStr.includes(term.toLowerCase())) {
      assert.fail(`Forbidden term leaked in report snapshot: ${term}`);
    }
  }
  console.log('[+] Safe report item contains no forbidden terms.');

  console.log('--- M45 Evidence Boundary DB-Free Smoke Completed Successfully ---');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
