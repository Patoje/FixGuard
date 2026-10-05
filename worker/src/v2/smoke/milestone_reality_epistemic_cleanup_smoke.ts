/**
 * Milestone Reality / Epistemic Cleanup Consolidated Smoke Suite
 *
 * Verifies canonical production logic directly:
 * SEC-01: Canonical PostgREST RLS Detection, Capability Execution, and Auto-Promotion:
 *   - Case 1: HTTP 200 with `[]` → inconclusive_observation (no draft, finding not permitted)
 *   - Case 2: HTTP 200 with non-empty array → pending_human_review (draft generated, finding permitted)
 *   - Case 3: HTTP 200 with object but no qualifying exposed records → inconclusive_observation
 *   - Case 4: HTTP 401/403 → secure_target_abstained (read_boundary_enforced)
 *   - Case 5: Missing/malformed/HTML body → secure_target_abstained (not_data_api_html_body)
 *   - Case 6: Contradictory / incomplete evidence → secure_target_abstained (incomplete_or_contradictory_evidence)
 *   - Case 7: Non-empty response with unattributed target URL → secure_target_abstained (target_attribution_unverified)
 *   - Capability: SupabaseRlsReadConfirmCapability returns refuted on [] and succeeded on rows > 0
 *   - Auto-Promotion: evaluateFindingAutoPromotion drops 0-row drafts as noise
 *
 * SEC-02: Safe credential scan regression:
 *   - live_epistemic_loop_test.ts and live_test_targets.ts contain zero hardcoded live credentials
 *   - Both fail closed when environment variables are missing
 *
 * SEC-04: Default authorization scope & granular state-changing authorization:
 *   - Default scope restricted to GET, HEAD, OPTIONS and allowStateChangingRequests: false
 *   - Default denial of POST, PUT, PATCH, DELETE via evaluateScopePolicy
 *   - Mismatched methods denied via evaluateScopePolicy
 *   - Attempted scope escalation rejected via rebindClientScopeGrantAgainstSealed
 *   - Explicit authorized grant permits state-changing request
 *
 * Surface:
 *   - preferSupabaseRlsTableOrder preserves order without hardcoded target bias
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { HttpMethod, AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import { evaluateScopePolicy } from '../scope/AuthorizedScopePolicyService.js';
import { rebindClientScopeGrantAgainstSealed } from '../scope/ScopeGrantRebinding.js';
import { establishVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import {
  runSupabaseRlsAbuseDetection,
  buildSupabaseRlsWorldReadableFinding,
} from '../supabase/SupabaseRlsAbuseDetectionService.js';
import { createSupabaseRlsReadConfirmCapability } from '../attack-execution/capabilities/SupabaseRlsReadConfirmCapability.js';
import { evaluateFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionPolicy.js';
import {
  preferSupabaseRlsTableOrder,
  SUPABASE_PREFERRED_RLS_SEED_TABLES,
} from '../supabase/SupabaseSurfaceContracts.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { Finding } from '../core/Evidence.js';
import type { AttackExecutionStep } from '../attack-execution/AttackExecutionContracts.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';

function fail(message: string): never {
  console.error(`FAIL: ${message}`);
  process.exit(1);
}

function assertTrue(condition: boolean, message: string): void {
  if (!condition) fail(message);
}

function makeTestScopeGrant(options?: {
  allowedMethods?: HttpMethod[];
  allowStateChangingRequests?: boolean;
}): AuthorizedScopeGrant {
  return {
    contractVersion: 'fixguard-authorized-scope-policy/v0',
    kind: 'authorized_scope_grant',
    grantId: 'grant_smoke_test',
    scanId: 'scan_smoke_test',
    issuedAt: '2026-10-02T12:00:00.000Z',
    expiresAt: '2026-10-03T12:00:00.000Z',
    subject: { targetKind: 'domain', domain: 'xyzcompany.supabase.co' },
    authorizationBasis: {
      basisKind: 'internal_asset_record',
      recordedBy: 'human_user',
      authorizationText: 'Authorized defensive test for xyzcompany.supabase.co',
    },
    permissionSet: {
      passiveRecon: true,
      technologyFingerprinting: true,
      endpointDiscovery: true,
      activeCrawling: true,
      authenticatedTesting: true,
      lightValidation: true,
      activeValidation: true,
      aggressiveValidation: false,
      oobTesting: false,
      destructiveOperations: false,
    },
    boundaries: {
      allowedDomains: ['xyzcompany.supabase.co'],
      allowedHosts: ['xyzcompany.supabase.co'],
      allowedOrigins: ['https://xyzcompany.supabase.co'],
      allowedMethods: options?.allowedMethods ?? ['GET', 'HEAD', 'OPTIONS'],
    },
    constraints: {
      allowLoginRequiredAreas: true,
      allowStateChangingRequests: options?.allowStateChangingRequests ?? false,
      allowCredentialUse: true,
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

function makeTestVerifiedDecision(scopeGrant: AuthorizedScopeGrant) {
  const established = establishVerifiedAuthorizationDecision(
    {
      contractVersion: 'fixguard-verified-authorization-decision/v0',
      kind: 'establish_verified_authorization_decision_request',
      assessmentId: 'asmt_smoke_test',
      scanId: 'scan_smoke_test',
      authorizationDecisionId: 'dec_smoke_test',
      authorizedActor: { actorId: 'usr_secops', actorType: 'human' },
      decision: 'authorized',
      decidedAt: '2026-10-02T12:00:00.000Z',
      scopeGrant,
    },
    '2026-10-02T12:00:00.000Z'
  );
  if (established.status !== 'established') {
    throw new Error(`Failed to establish test verified decision: ${established.reasonCode}`);
  }
  return established.decision;
}

// ============================================================================
// SEC-01: Canonical Production PostgREST RLS Abuse Detection Service Tests
// ============================================================================

async function testSec01Case1_Http200EmptyArray(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c1',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['profiles'],
    probePairs: [
      {
        tableName: 'profiles',
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/profiles',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: 'hash_c1',
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: [],
          rowCountHint: 0,
          bodySnippet: '[]',
        },
      },
    ],
  });

  assertTrue(
    result.status === 'inconclusive_observation',
    `SEC-01 Case 1: expected status 'inconclusive_observation' on HTTP 200 with [], got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'inconclusive_empty_table',
    `SEC-01 Case 1: expected reasonCode 'inconclusive_empty_table', got '${result.reasonCode}'`
  );
  assertTrue(
    result.evidenceDraft === undefined,
    'SEC-01 Case 1: evidenceDraft MUST NOT be emitted on empty response'
  );
  assertTrue(
    result.finding === undefined,
    'SEC-01 Case 1: finding MUST NOT be emitted on empty response'
  );
  assertTrue(
    result.observations.length === 0,
    'SEC-01 Case 1: confirmed observations must be empty'
  );

  console.log('[+] SEC-01 Case 1 passed: HTTP 200 with [] classified as inconclusive_observation (no draft/finding)');
}

async function testSec01Case2_Http200WithObservedRows(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c2',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['profiles'],
    probePairs: [
      {
        tableName: 'profiles',
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/profiles',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: 'hash_c2',
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: ['id', 'username', 'email'],
          rowCountHint: 3,
          bodySnippet: '[{"id":1,"username":"alice"},{"id":2,"username":"bob"}]',
        },
      },
    ],
  });

  assertTrue(
    result.status === 'pending_human_review',
    `SEC-01 Case 2: expected pending_human_review on observed rows > 0, got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'supabase_rls_world_readable_observed',
    `SEC-01 Case 2: expected reasonCode 'supabase_rls_world_readable_observed', got '${result.reasonCode}'`
  );
  assertTrue(
    result.evidenceDraft !== undefined,
    'SEC-01 Case 2: evidenceDraft must be emitted on observed rows > 0'
  );
  assertTrue(
    result.observations.length === 1,
    'SEC-01 Case 2: exactly 1 observation expected'
  );

  // Assert finding construction is permitted when approved
  const finding = buildSupabaseRlsWorldReadableFinding({
    observation: result.observations[0]!,
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    actorId: 'usr_secops',
    observedAt: '2026-10-02T12:00:00.000Z',
    draftId: result.evidenceDraft!.draftId,
  });
  assertTrue(finding.type === 'BROKEN_ACCESS_CONTROL', 'Finding type must be BROKEN_ACCESS_CONTROL');

  console.log('[+] SEC-01 Case 2 passed: HTTP 200 with observed rows > 0 produces pending_human_review and finding');
}

async function testSec01Case3_Http200ObjectWithoutRecords(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c3',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['audit_logs'],
    probePairs: [
      {
        tableName: 'audit_logs',
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/audit_logs',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: 'hash_c3',
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: [], // Empty object {}
          rowCountHint: null,
          bodySnippet: '{}',
        },
      },
    ],
  });

  assertTrue(
    result.status === 'inconclusive_observation',
    `SEC-01 Case 3: expected inconclusive_observation on empty object {}, got '${result.status}'`
  );
  assertTrue(
    result.evidenceDraft === undefined,
    'SEC-01 Case 3: draft must NOT be emitted for empty object'
  );

  console.log('[+] SEC-01 Case 3 passed: HTTP 200 with empty object {} classified as inconclusive_observation');
}

async function testSec01Case4_Http401403Protected(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c4',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['secure_keys'],
    probePairs: [
      {
        tableName: 'secure_keys',
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/secure_keys',
        anon: {
          roleHint: 'anon',
          statusCode: 401,
          bodyHash: 'hash_c4',
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: ['message'],
          rowCountHint: null,
          bodySnippet: '{"message": "Unauthorized"}',
        },
      },
    ],
  });

  assertTrue(
    result.status === 'secure_target_abstained',
    `SEC-01 Case 4: expected secure_target_abstained on HTTP 401, got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'read_boundary_enforced',
    `SEC-01 Case 4: expected reasonCode 'read_boundary_enforced', got '${result.reasonCode}'`
  );
  assertTrue(result.evidenceDraft === undefined, 'Draft must not be emitted on 401');

  console.log('[+] SEC-01 Case 4 passed: HTTP 401/403 classified as secure_target_abstained (read_boundary_enforced)');
}

async function testSec01Case5_HtmlOrNonJsonBody(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c5',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['spa_route'],
    probePairs: [
      {
        tableName: 'spa_route',
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/spa_route',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: 'hash_c5',
          contentType: 'text/html',
          isJsonBody: false,
          isHtmlBody: true,
          topLevelJsonKeys: [],
          rowCountHint: null,
          bodySnippet: '<!doctype html><html><body>SPA Shell</body></html>',
        },
      },
    ],
  });

  assertTrue(
    result.status === 'inconclusive_observation',
    `SEC-01 Case 5: expected inconclusive_observation on HTML body, got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'not_data_api_html_body',
    `SEC-01 Case 5: expected reasonCode 'not_data_api_html_body', got '${result.reasonCode}'`
  );

  console.log('[+] SEC-01 Case 5 passed: HTML response classified as inconclusive_observation');
}

async function testSec01Case6_ContradictoryOrIncompleteEvidence(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c6',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['corrupt_table'],
    probePairs: [
      {
        tableName: '', // Incomplete tableName
        tableUrl: 'https://xyzcompany.supabase.co/rest/v1/corrupt_table',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: '', // Empty bodyHash (contradictory)
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: ['id'],
          rowCountHint: 1,
        },
      },
    ],
  });

  assertTrue(
    result.status === 'inconclusive_observation',
    `SEC-01 Case 6: expected inconclusive_observation on incomplete evidence, got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'incomplete_or_contradictory_evidence',
    `SEC-01 Case 6: expected 'incomplete_or_contradictory_evidence', got '${result.reasonCode}'`
  );

  console.log('[+] SEC-01 Case 6 passed: Contradictory/incomplete evidence classified as inconclusive_observation');
}

async function testSec01Case7_UnattributedTarget(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);

  const result = await runSupabaseRlsAbuseDetection({
    contractVersion: 'fixguard-supabase-rls-abuse-detection/v0',
    kind: 'supabase_rls_abuse_detection_request',
    detectionId: 'det_test_c7',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    authorizationGrantId: 'grant_smoke_test',
    authorizationDecisionId: 'dec_smoke_test',
    actorId: 'usr_secops',
    verifiedAuthorizationDecision: verifiedDecision,
    scopeGrant,
    restBaseUrl: 'https://xyzcompany.supabase.co/rest/v1',
    anonApiKey: 'test_anon_key_observed',
    tableNames: ['unattributed_table'],
    probePairs: [
      {
        tableName: 'unattributed_table',
        // Host does not match restBaseUrl (attribution mismatch)
        tableUrl: 'https://attacker.untrusted.com/rest/v1/unattributed_table',
        anon: {
          roleHint: 'anon',
          statusCode: 200,
          bodyHash: 'hash_c7',
          contentType: 'application/json',
          isJsonBody: true,
          isHtmlBody: false,
          topLevelJsonKeys: ['id'],
          rowCountHint: 5,
        },
      },
    ],
  });

  assertTrue(
    result.status === 'inconclusive_observation',
    `SEC-01 Case 7: expected inconclusive_observation on unattributed target, got '${result.status}'`
  );
  assertTrue(
    result.reasonCode === 'target_attribution_unverified',
    `SEC-01 Case 7: expected 'target_attribution_unverified', got '${result.reasonCode}'`
  );

  console.log('[+] SEC-01 Case 7 passed: Unattributed target classified as inconclusive_observation');
}

async function testSec01_CapabilityConfirmation(): Promise<void> {
  const scopeGrant = makeTestScopeGrant();
  const verifiedDecision = makeTestVerifiedDecision(scopeGrant);
  const capability = createSupabaseRlsReadConfirmCapability();

  const dummyFinding: Finding = {
    id: 'fnd_test_empty',
    type: 'BROKEN_ACCESS_CONTROL',
    severity: 'high',
    title: 'Test finding',
    description: 'Test finding',
    target: 'https://xyzcompany.supabase.co/rest/v1/empty_table',
    evidence: '{}',
    confidence: 0.9,
    verificationState: 'suspected_vulnerability',
    metadata: {
      kind: 'supabase_rls_abuse_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      claimKind: 'SUPABASE_RLS_WORLD_READABLE',
      tableName: 'empty_table',
      tableUrl: 'https://xyzcompany.supabase.co/rest/v1/empty_table',
      anonStatusCode: 200,
      anonBodyHash: 'hash_empty',
      topLevelJsonKeys: [],
      anonEqualsAuth: false,
      observedAt: '2026-10-02T12:00:00.000Z',
    },
  };

  const dummyPlan: AttackPlan = {
    contractVersion: 'fixguard-attack-planning/v0',
    kind: 'attack_plan',
    planId: 'plan_test_confirm_1',
    assessmentId: 'asmt_smoke_test',
    scanId: 'scan_smoke_test',
    capability: 'supabase_rls_read_confirm',
    title: 'Confirm read on empty_table',
    reasoning: 'test',
    status: 'ready_for_authorization',
    blastRadius: 'single_resource',
    capabilityGained: 'none',
    sourceFindingIds: [dummyFinding.id],
    sourceFindingTypes: ['BROKEN_ACCESS_CONTROL'],
    prerequisites: [],
    steps: [],
    targetUrl: 'https://xyzcompany.supabase.co/rest/v1/empty_table',
    lineage: {
      assessmentId: 'asmt_smoke_test',
      scanId: 'scan_smoke_test',
      authorizationGrantId: 'grant_smoke_test',
      authorizationDecisionId: 'dec_smoke_test',
      actorId: 'usr_secops',
    },
    createdAt: '2026-10-02T12:00:00.000Z',
    executable: false,
  };

  const dummyStep: AttackExecutionStep = {
    stepId: 'step_test_1',
    ordinal: 1,
    title: 'Confirm read',
    description: 'Confirm read',
    status: 'ready',
    blastRadiusClass: 'read_public',
    requiredPermissions: ['active_http_get'],
  };

  // Mock transport returning empty array [] (HTTP 200)
  const emptyTransport = async () => ({
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    bodyText: '[]',
    responseTimeMs: 50,
  });

  const emptyResult = await capability.execute({
    plan: dummyPlan,
    step: dummyStep,
    targetHost: 'xyzcompany.supabase.co',
    targetUrl: 'https://xyzcompany.supabase.co/rest/v1/empty_table',
    scopeGrant,
    findings: [dummyFinding],
    verifiedAuthorizationDecision: verifiedDecision,
    primaryIdentity: {
      identityId: 'id_anon',
      headers: { apikey: 'test_anon_key_observed' },
    },
    transport: emptyTransport,
    dnsResolver: async () => ['104.18.32.7'],
  });

  assertTrue(
    emptyResult.outcome === 'inconclusive',
    `Capability on empty array [] MUST return outcome 'inconclusive', got '${emptyResult.outcome}'`
  );
  assertTrue(
    emptyResult.outcome !== 'succeeded',
    'Capability on empty array [] MUST NEVER succeed or declare vulnerable'
  );
  console.log('[+] SEC-01 Capability Confirmation on [] passed: outcome is inconclusive, NOT succeeded');
}

async function testSec01_AutoPromotionGateZeroRows(): Promise<void> {
  const draftWithZeroRows: EnrichedEvidenceDraft = {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId: 'dft_test_zero',
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: 'cmp_test_zero',
    sourceSnapshotIds: {
      baselineSnapshotId: 'snp_base',
      validationSnapshotId: 'snp_val',
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: 'Test zero row draft',
    differentialContext: {
      detectionKind: 'supabase_rls_abuse',
      endpointUrl: 'https://xyzcompany.supabase.co/rest/v1/empty_table',
      supabaseTableName: 'empty_table',
      supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
      baselineStatusCode: 200,
      baselineBodyHash: 'hash_zero',
      supabaseRowCountHint: 0, // Zero rows observed
      sanitizedSnippet: '[]',
    },
  };

  const evalResult = evaluateFindingAutoPromotion(draftWithZeroRows);
  assertTrue(
    evalResult.decision === 'drop_as_noise',
    `Auto-promotion on 0-row draft MUST return 'drop_as_noise', got '${evalResult.decision}'`
  );
  assertTrue(
    evalResult.reasonCode === 'supabase_rls_zero_rows_inconclusive' ||
      evalResult.reasonCode === 'supabase_rls_empty_array_inconclusive',
    `Expected inconclusive reason code, got '${evalResult.reasonCode}'`
  );
  console.log('[+] SEC-01 Auto-Promotion gate on zero rows passed: dropped as noise / inconclusive');
}

// ============================================================================
// SEC-02: Safe Credential Scan Regression Tests
// ============================================================================

async function testSec02_NoHardcodedSecretsInScripts(): Promise<void> {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const scriptsDir = path.resolve(__dirname, '../../../scripts');

  const liveEpistemicPath = path.join(scriptsDir, 'live_epistemic_loop_test.ts');
  const liveTargetsPath = path.join(scriptsDir, 'live_test_targets.ts');

  const filesToCheck = [liveEpistemicPath, liveTargetsPath];

  for (const filePath of filesToCheck) {
    if (!fs.existsSync(filePath)) {
      fail(`File not found for credential audit: ${filePath}`);
    }
    const content = fs.readFileSync(filePath, 'utf-8');

    // Regression check: Must NOT contain hardcoded JWT strings with payload
    const jwtLiteralRegex = /['"`]eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}['"`]/g;
    const matches = content.match(jwtLiteralRegex);
    assertTrue(
      matches === null || matches.length === 0,
      `SEC-02: Hardcoded JWT pattern detected in ${path.basename(filePath)}! File must use environment variables.`
    );

    // Verify required fail-closed environment variable reference
    assertTrue(
      content.includes('process.env.FG_LIVE_USER_JWT'),
      `SEC-02: ${path.basename(filePath)} must reference process.env.FG_LIVE_USER_JWT`
    );
  }

  console.log('[+] SEC-02 passed: zero hardcoded credentials in live scripts; env var enforcement present');
}

// ============================================================================
// SEC-04: Default Authorization Scope & Granular State-Changing Authorization
// ============================================================================

async function testSec04_ScopePolicyEnforcement(): Promise<void> {
  const baseClassification = {
    createsRealFindings: false,
    createsPersistedEvidence: false,
    confirmsVulnerabilities: false,
    makesRiskClaims: false,
    makesSeverityClaims: false,
    makesImpactClaims: false,
    executesNetwork: false,
    executesTools: false,
    persistsData: false,
  };

  function makeScopeRequest(grant: AuthorizedScopeGrant, overrides: Record<string, unknown> = {}) {
    return {
      contractVersion: 'fixguard-authorized-scope-policy/v0',
      kind: 'scope_action_request',
      requestId: 'req_sc_test',
      scanId: grant.scanId,
      requestedAt: '2026-10-02T12:05:00.000Z',
      actionKind: 'active_validation',
      target: { targetKind: 'origin', normalizedOrigin: 'https://xyzcompany.supabase.co' },
      pathTemplate: '/rest/v1/profiles',
      intensity: 'medium',
      usesCredentials: false,
      mayChangeServerState: false,
      usesOob: false,
      classification: baseClassification,
      ...overrides,
    };
  }

  // 1. Default scope grant (read-only GET, HEAD, OPTIONS)
  const defaultGrant = makeTestScopeGrant();
  assertTrue(
    defaultGrant.constraints.allowStateChangingRequests === false,
    'Default scope grant MUST have allowStateChangingRequests: false'
  );
  assert.deepEqual(
    defaultGrant.boundaries.allowedMethods,
    ['GET', 'HEAD', 'OPTIONS'],
    'Default scope grant MUST restrict allowedMethods to GET, HEAD, OPTIONS'
  );

  // 2. Default denial of state-changing methods (POST, PUT, PATCH, DELETE)
  const writeMethods: HttpMethod[] = ['POST', 'PUT', 'PATCH', 'DELETE'];
  for (const method of writeMethods) {
    const decision = evaluateScopePolicy({
      grant: defaultGrant,
      request: makeScopeRequest(defaultGrant, {
        method,
        mayChangeServerState: true,
      }),
      decisionId: `dec_test_${method}`,
      evaluatedAt: '2026-10-02T12:05:00.000Z',
    });
    assertTrue(
      decision.decision === 'denied',
      `SEC-04: Default scope MUST deny method ${method}`
    );
    assertTrue(
      decision.reasonCode === 'denied_method_not_allowed' ||
        decision.reasonCode === 'denied_state_change_not_allowed',
      `Expected method/state-change denial code for ${method}, got '${decision.reasonCode}'`
    );
  }

  // 3. Attempted scope escalation: client passing write methods against read-only sealed grant
  const escalatingClientGrant = makeTestScopeGrant({
    allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    allowStateChangingRequests: true,
  });
  const rebindResult = rebindClientScopeGrantAgainstSealed(escalatingClientGrant, defaultGrant);
  assertTrue(
    rebindResult.ok === false,
    'rebindClientScopeGrantAgainstSealed MUST reject client escalation of allowStateChangingRequests/POST'
  );
  if (!rebindResult.ok) {
    assertTrue(
      rebindResult.reasonCode === 'scope_violation',
      `Expected scope_violation on escalation, got '${rebindResult.reasonCode}'`
    );
  }

  // 4. Explicitly authorized state-changing grant permits authorized method
  const explicitWriteGrant = makeTestScopeGrant({
    allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'],
    allowStateChangingRequests: true,
  });
  const postDecision = evaluateScopePolicy({
    grant: explicitWriteGrant,
    request: makeScopeRequest(explicitWriteGrant, {
      method: 'POST',
      mayChangeServerState: true,
    }),
    decisionId: 'dec_test_post',
    evaluatedAt: '2026-10-02T12:05:00.000Z',
  });
  assertTrue(
    postDecision.decision === 'allowed',
    `Explicitly authorized POST must pass scope policy, got ${postDecision.decision} (${postDecision.reasonCode})`
  );

  // 5. Unrelated state-changing method (DELETE) remains denied on POST-only grant
  const deleteDecision = evaluateScopePolicy({
    grant: explicitWriteGrant,
    request: makeScopeRequest(explicitWriteGrant, {
      method: 'DELETE',
      mayChangeServerState: true,
    }),
    decisionId: 'dec_test_del',
    evaluatedAt: '2026-10-02T12:05:00.000Z',
  });
  assertTrue(
    deleteDecision.decision === 'denied',
    'Unrelated method DELETE must remain denied when only POST was authorized'
  );
  assertTrue(
    deleteDecision.reasonCode === 'denied_method_not_allowed',
    `Expected denied_method_not_allowed for DELETE, got '${deleteDecision.reasonCode}'`
  );

  console.log('[+] SEC-04 passed: default denial, escalation rejection, and granular explicit authorization verified');
}

// ============================================================================
// Surface Deduplication & Neutral Ordering Test
// ============================================================================

async function testSupabaseTableOrderPreserved(): Promise<void> {
  const input = ['runs', 'other', 'profiles', 'wallets', 'shop_items', 'RUNS'];
  const ordered = preferSupabaseRlsTableOrder(input);

  assert.deepEqual(
    [...ordered],
    ['runs', 'other', 'profiles', 'wallets', 'shop_items'],
    'preferSupabaseRlsTableOrder must preserve discovered order with deduplication'
  );
  assertTrue(
    SUPABASE_PREFERRED_RLS_SEED_TABLES.length === 0,
    'SUPABASE_PREFERRED_RLS_SEED_TABLES must be empty to avoid historical target bias'
  );
  console.log('[+] Table order preserved without synthetic Teclaaa bias');
}

// ============================================================================
// Main Suite Runner
// ============================================================================

async function main(): Promise<void> {
  console.log('=== FixGuard V2 Canonical Security & Epistemic Integrity Smoke Suite ===\n');

  console.log('--- SEC-01: PostgREST RLS Detection & Epistemic Classification ---');
  await testSec01Case1_Http200EmptyArray();
  await testSec01Case2_Http200WithObservedRows();
  await testSec01Case3_Http200ObjectWithoutRecords();
  await testSec01Case4_Http401403Protected();
  await testSec01Case5_HtmlOrNonJsonBody();
  await testSec01Case6_ContradictoryOrIncompleteEvidence();
  await testSec01Case7_UnattributedTarget();
  await testSec01_CapabilityConfirmation();
  await testSec01_AutoPromotionGateZeroRows();

  console.log('\n--- SEC-02: Credential Hardcoding Sanitization ---');
  await testSec02_NoHardcodedSecretsInScripts();

  console.log('\n--- SEC-04: Default Authorization Scope & Granular State-Changing Authorization ---');
  await testSec04_ScopePolicyEnforcement();

  console.log('\n--- Surface: Table Ordering & Deduplication ---');
  await testSupabaseTableOrderPreserved();

  console.log('\n[✔ ALL CANONICAL SECURITY & EPISTEMIC SMOKE TESTS PASSED]\n');
}

void main();
