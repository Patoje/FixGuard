/**
 * Finding auto-promotion policy smoke — confirmed attack-relevant signals → Finding;
 * discovery/cosmetic noise stays draft or drops; no invented vulns.
 */
import assert from 'node:assert/strict';
import { evaluateFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionPolicy.js';
import { applyFindingAutoPromotion } from '../finding-auto-promotion/FindingAutoPromotionService.js';
import type { EnrichedEvidenceDraft } from '../application/OrchestratedAssessmentContracts.js';
import { generateAttackPlans } from '../attack-planning/AttackPlanGeneratorService.js';

function fail(msg: string): never {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}

function baseDraft(
  draftId: string,
  detectionKind: EnrichedEvidenceDraft['differentialContext'] extends infer T
    ? T extends { detectionKind: infer K }
      ? K
      : never
    : never,
  extras: Record<string, unknown> = {}
): EnrichedEvidenceDraft {
  return {
    draftKind: 'non_persisted_comparison_evidence_draft',
    draftId,
    suggestedEvidenceType: 'http_difference',
    suggestedStrength: 'strong',
    sourceComparisonId: `cmp_${draftId}`,
    sourceSnapshotIds: {
      baselineSnapshotId: `snp_${draftId}_base`,
      validationSnapshotId: `snp_${draftId}_val`,
    },
    requiresHumanReview: true,
    notPersisted: true,
    notARealFinding: true,
    notConfirmedEvidence: true,
    notForExternalDelivery: true,
    notM45EvidenceRecord: true,
    safeRationale: `test draft ${detectionKind}`,
    differentialContext: {
      endpointUrl: 'https://app.example.com/api/resource',
      detectionKind,
      ...extras,
    },
  };
}

function runSmokeTests(): void {
  console.log('=== Finding Auto-Promotion Policy Smoke ===');

  // 1. IDOR with real differential → auto_promote
  const idorOk = baseDraft('dft_idor_ok', 'idor_access_control', {
    resourceParamName: 'id',
    baselineResourceId: '1',
    baselineStatusCode: 200,
    validationStatusCode: 200,
    baselineBodyHash: 'aaa111',
    validationBodyHash: 'bbb222',
  });
  assert.equal(evaluateFindingAutoPromotion(idorOk).decision, 'auto_promote');

  // 2. IDOR identical error pages → keep_as_draft; identical success bodies → auto_promote (BOLA)
  const idorNoise = baseDraft('dft_idor_noise', 'idor_access_control', {
    resourceParamName: 'id',
    baselineStatusCode: 404,
    validationStatusCode: 404,
    baselineBodyHash: 'samehash',
    validationBodyHash: 'samehash',
  });
  assert.equal(evaluateFindingAutoPromotion(idorNoise).decision, 'keep_as_draft');

  const idorBolaSameBody = baseDraft('dft_idor_bola', 'idor_access_control', {
    resourceParamName: 'id',
    baselineResourceId: '1',
    baselineStatusCode: 200,
    validationStatusCode: 200,
    baselineBodyHash: 'same_privileged_payload',
    validationBodyHash: 'same_privileged_payload',
  });
  assert.equal(
    evaluateFindingAutoPromotion(idorBolaSameBody).decision,
    'auto_promote',
    'Identical successful bodies across identities is BOLA — auto-promote'
  );

  // 2b. Soft-404 / SPA HTML shell on /a/b and /cart → keep_as_draft (never High)
  const idorSoft404Ab = baseDraft('dft_idor_soft404_ab', 'idor_access_control', {
    endpointUrl: 'https://shop.example.com/a/b',
    resourceParamName: 'b',
    baselineResourceId: 'b',
    baselineStatusCode: 200,
    validationStatusCode: 404,
    baselineBodyHash: 'html_shell_a',
    validationBodyHash: 'html_shell_b',
    baselineContentType: 'text/html; charset=utf-8',
    validationContentType: 'text/html',
    baselineBodyShapeKind: 'html',
    validationBodyShapeKind: 'html',
  });
  const soft404AbEval = evaluateFindingAutoPromotion(idorSoft404Ab);
  assert.equal(soft404AbEval.decision, 'keep_as_draft');
  assert.equal(soft404AbEval.reasonCode, 'idor_soft_404_or_html_shell');

  const idorSoft404Cart = baseDraft('dft_idor_soft404_cart', 'idor_access_control', {
    endpointUrl: 'https://shop.example.com/cart',
    resourceParamName: 'cart',
    baselineStatusCode: 200,
    validationStatusCode: 200,
    baselineBodyHash: 'cart_html_a',
    validationBodyHash: 'cart_html_b',
    sanitizedSnippet: '<!DOCTYPE html><html><body>Cart shell</body></html>',
  });
  const soft404CartEval = evaluateFindingAutoPromotion(idorSoft404Cart);
  assert.equal(soft404CartEval.decision, 'keep_as_draft');
  assert.equal(soft404CartEval.reasonCode, 'idor_soft_404_or_html_shell');

  // Opaque path without content-type still fail-closed (Sodimac-class draft)
  const idorOpaquePathOnly = baseDraft('dft_idor_opaque', 'idor_access_control', {
    endpointUrl: 'https://shop.example.com/a/i',
    resourceParamName: 'i',
    baselineStatusCode: 404,
    validationStatusCode: 200,
    baselineBodyHash: 'hash_a',
    validationBodyHash: 'hash_b',
  });
  assert.equal(
    evaluateFindingAutoPromotion(idorOpaquePathOnly).decision,
    'keep_as_draft',
    'Opaque /a/i without JSON shape must not auto-promote'
  );

  // Real API JSON differential still promotes (control)
  const idorApiJson = baseDraft('dft_idor_api_json', 'idor_access_control', {
    endpointUrl: 'https://app.example.com/api/orders/42',
    resourceParamName: 'id',
    baselineResourceId: '42',
    baselineStatusCode: 200,
    validationStatusCode: 200,
    baselineBodyHash: 'order_payload_a',
    validationBodyHash: 'order_payload_b',
    baselineBodyShapeKind: 'json_object',
    validationBodyShapeKind: 'json_object',
    baselineContentType: 'application/json',
    validationContentType: 'application/json',
  });
  assert.equal(evaluateFindingAutoPromotion(idorApiJson).decision, 'auto_promote');

  // 3. Missing security headers → keep_as_draft (cosmetic)
  const headers = baseDraft('dft_headers', 'missing_security_headers', {
    missingHeaders: ['content-security-policy'],
    presentHeaders: [],
  });
  assert.equal(evaluateFindingAutoPromotion(headers).decision, 'keep_as_draft');

  // 4. Static route extraction → drop_as_noise
  const routes = baseDraft('dft_routes', 'static_route_extraction', {
    extractedRoutePattern: '/dashboard',
    frameworkType: 'nextjs',
  });
  assert.equal(evaluateFindingAutoPromotion(routes).decision, 'drop_as_noise');

  // 5. Parameter reflection without canary → keep; with canary → promote
  const reflWeak = baseDraft('dft_refl_weak', 'parameter_reflection', {
    parameterName: 'q',
  });
  assert.equal(evaluateFindingAutoPromotion(reflWeak).decision, 'keep_as_draft');
  const reflOk = baseDraft('dft_refl_ok', 'parameter_reflection', {
    parameterName: 'q',
    reflectedCanary: 'FixGuard_Canary_ABC',
  });
  assert.equal(evaluateFindingAutoPromotion(reflOk).decision, 'auto_promote');

  // 6. Blind XSS without interaction → keep; confirmed → promote
  const bxssWeak = baseDraft('dft_bxss_weak', 'blind_xss', {
    parameterName: 'comment',
    interactionConfirmed: false,
  });
  assert.equal(evaluateFindingAutoPromotion(bxssWeak).decision, 'keep_as_draft');
  const bxssOk = baseDraft('dft_bxss_ok', 'blind_xss', {
    parameterName: 'comment',
    interactionConfirmed: true,
    canaryToken: 'tok_1',
  });
  assert.equal(evaluateFindingAutoPromotion(bxssOk).decision, 'auto_promote');

  // 6b. Supabase RLS: empty array, empty object {}, missing body, HTML -> dropped as noise
  const rlsEmptyArray = baseDraft('dft_rls_empty_arr', 'supabase_rls_abuse', {
    endpointUrl: 'https://app.example.com/rest/v1/users',
    supabaseTableName: 'users',
    supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
    baselineStatusCode: 200,
    baselineBodyHash: 'hash_arr',
    sanitizedSnippet: '[]',
  });
  assert.equal(evaluateFindingAutoPromotion(rlsEmptyArray).decision, 'drop_as_noise');

  const rlsEmptyObj = baseDraft('dft_rls_empty_obj', 'supabase_rls_abuse', {
    endpointUrl: 'https://app.example.com/rest/v1/users',
    supabaseTableName: 'users',
    supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
    baselineStatusCode: 200,
    baselineBodyHash: 'hash_obj',
    sanitizedSnippet: '{}',
  });
  assert.equal(evaluateFindingAutoPromotion(rlsEmptyObj).decision, 'drop_as_noise');

  const rlsMissingBody = baseDraft('dft_rls_no_body', 'supabase_rls_abuse', {
    endpointUrl: 'https://app.example.com/rest/v1/users',
    supabaseTableName: 'users',
    supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
    baselineStatusCode: 200,
    baselineBodyHash: 'hash_nobody',
    sanitizedSnippet: '   ',
  });
  assert.equal(evaluateFindingAutoPromotion(rlsMissingBody).decision, 'drop_as_noise');

  const rlsHtml = baseDraft('dft_rls_html', 'supabase_rls_abuse', {
    endpointUrl: 'https://app.example.com/rest/v1/users',
    supabaseTableName: 'users',
    supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
    baselineStatusCode: 200,
    baselineBodyHash: 'hash_html',
    sanitizedSnippet: '<!doctype html><html><body>Error</body></html>',
  });
  assert.equal(evaluateFindingAutoPromotion(rlsHtml).decision, 'drop_as_noise');

  const rlsRealRows = baseDraft('dft_rls_real_rows', 'supabase_rls_abuse', {
    endpointUrl: 'https://app.example.com/rest/v1/users',
    supabaseTableName: 'users',
    supabaseClaimKind: 'SUPABASE_RLS_WORLD_READABLE',
    baselineStatusCode: 200,
    baselineBodyHash: 'hash_real',
    supabaseRowCountHint: 3,
    sanitizedSnippet: '[{"id":1,"email":"admin@example.com"}]',
  });
  assert.equal(evaluateFindingAutoPromotion(rlsRealRows).decision, 'auto_promote');

  // 6b. Static secret exposure signal gate: missing/empty snippet or filePath -> keep_as_draft; complete -> auto_promote
  const secretMissingSnippet = baseDraft('dft_secret_no_snip', 'static_secret_exposure', {
    filePath: '/static/js/bundle.js',
    sanitizedSnippet: '   ',
  });
  assert.equal(
    evaluateFindingAutoPromotion(secretMissingSnippet).decision,
    'keep_as_draft',
    'Blank sanitizedSnippet must keep static_secret_exposure as draft'
  );

  const secretMissingPath = baseDraft('dft_secret_no_path', 'static_secret_exposure', {
    sanitizedSnippet: 'ghp_xxxx1234567890',
  });
  assert.equal(
    evaluateFindingAutoPromotion(secretMissingPath).decision,
    'keep_as_draft',
    'Missing filePath must keep static_secret_exposure as draft'
  );

  const secretValid = baseDraft('dft_secret_valid', 'static_secret_exposure', {
    filePath: '/static/js/bundle.js',
    sanitizedSnippet: 'ghp_xxxx1234567890',
  });
  assert.equal(
    evaluateFindingAutoPromotion(secretValid).decision,
    'auto_promote',
    'Valid static secret exposure with filePath and snippet must auto_promote'
  );

  // 6c. Hito 2 (ADR-005 gap closure) — the 7 detectionKinds that previously had
  // no case in evaluateSignalGate (fell to `default: return null` → unconditional
  // auto_promote). Each must now require the real evidence its own
  // buildAutoFinding conversion depends on.

  const jwtIncomplete = baseDraft('dft_jwt_incomplete', 'jwt_algorithm_confusion', {
    originalAlgorithm: 'HS256',
  });
  assert.equal(evaluateFindingAutoPromotion(jwtIncomplete).decision, 'keep_as_draft');
  assert.equal(evaluateFindingAutoPromotion(jwtIncomplete).reasonCode, 'jwt_confusion_signal_incomplete');
  const jwtComplete = baseDraft('dft_jwt_complete', 'jwt_algorithm_confusion', {
    originalAlgorithm: 'HS256',
    manipulatedAlgorithm: 'none',
    jwtProbeMechanism: 'alg_none_header',
  });
  assert.equal(evaluateFindingAutoPromotion(jwtComplete).decision, 'auto_promote');

  const sqlOracleIncomplete = baseDraft('dft_sqlo_incomplete', 'sql_error_oracle', {
    databaseEngine: 'postgresql',
  });
  assert.equal(evaluateFindingAutoPromotion(sqlOracleIncomplete).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(sqlOracleIncomplete).reasonCode,
    'sql_error_oracle_signal_incomplete'
  );
  const sqlOracleComplete = baseDraft('dft_sqlo_complete', 'sql_error_oracle', {
    databaseEngine: 'postgresql',
    sqlErrorFragment: 'syntax error at or near',
    injectedProbe: "' OR '1'='1",
  });
  assert.equal(evaluateFindingAutoPromotion(sqlOracleComplete).decision, 'auto_promote');

  const takeoverIncomplete = baseDraft('dft_takeover_incomplete', 'subdomain_takeover', {
    subdomain: 'old.example.com',
  });
  assert.equal(evaluateFindingAutoPromotion(takeoverIncomplete).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(takeoverIncomplete).reasonCode,
    'subdomain_takeover_fingerprint_missing'
  );
  const takeoverComplete = baseDraft('dft_takeover_complete', 'subdomain_takeover', {
    subdomain: 'old.example.com',
    cnameTarget: 'ghost-bucket.s3.amazonaws.com',
    hostingProvider: 'aws_s3',
    fingerprintMatch: 'NoSuchBucket',
  });
  assert.equal(evaluateFindingAutoPromotion(takeoverComplete).decision, 'auto_promote');

  const sessionFixationMissing = baseDraft('dft_sf_missing', 'session_fixation', {
    sessionCookieName: 'sid',
  });
  assert.equal(evaluateFindingAutoPromotion(sessionFixationMissing).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(sessionFixationMissing).reasonCode,
    'session_fixation_regeneration_unconfirmed'
  );
  // Semantic case, not just presence: server DID regenerate → no vuln to claim.
  const sessionFixationRegenerated = baseDraft('dft_sf_regenerated', 'session_fixation', {
    sessionCookieName: 'sid',
    fixedSessionId: 'abc123',
    serverRegeneratedSession: true,
  });
  assert.equal(evaluateFindingAutoPromotion(sessionFixationRegenerated).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(sessionFixationRegenerated).reasonCode,
    'session_fixation_regeneration_unconfirmed',
    'serverRegeneratedSession=true must never auto-promote, even with other fields present'
  );
  const sessionFixationComplete = baseDraft('dft_sf_complete', 'session_fixation', {
    sessionCookieName: 'sid',
    fixedSessionId: 'abc123',
    serverRegeneratedSession: false,
  });
  assert.equal(evaluateFindingAutoPromotion(sessionFixationComplete).decision, 'auto_promote');

  const corsIdorIncomplete = baseDraft('dft_cic_incomplete', 'cors_idor_compound', {
    primaryFindingId: 'fnd_cors_1',
  });
  assert.equal(evaluateFindingAutoPromotion(corsIdorIncomplete).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(corsIdorIncomplete).reasonCode,
    'cors_idor_compound_context_missing'
  );
  const corsIdorComplete = baseDraft('dft_cic_complete', 'cors_idor_compound', {
    primaryFindingId: 'fnd_cors_1',
    secondaryFindingId: 'fnd_idor_1',
    sharedOrigin: 'https://app.example.com',
  });
  assert.equal(evaluateFindingAutoPromotion(corsIdorComplete).decision, 'auto_promote');

  const crossChainIncomplete = baseDraft('dft_xc_incomplete', 'cross_finding_chain', {
    constituentFindingIds: ['fnd_1'],
  });
  assert.equal(evaluateFindingAutoPromotion(crossChainIncomplete).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(crossChainIncomplete).reasonCode,
    'cross_finding_chain_context_missing'
  );
  const crossChainComplete = baseDraft('dft_xc_complete', 'cross_finding_chain', {
    constituentFindingIds: ['fnd_1', 'fnd_2'],
    primaryVector: 'cors_misconfiguration',
    secondaryVector: 'information_disclosure',
  });
  assert.equal(evaluateFindingAutoPromotion(crossChainComplete).decision, 'auto_promote');

  const depVulnIncomplete = baseDraft('dft_dv_incomplete', 'dependency_vulnerability', {
    packageName: 'left-pad',
  });
  assert.equal(evaluateFindingAutoPromotion(depVulnIncomplete).decision, 'keep_as_draft');
  assert.equal(
    evaluateFindingAutoPromotion(depVulnIncomplete).reasonCode,
    'dependency_vulnerability_advisory_missing'
  );
  const depVulnComplete = baseDraft('dft_dv_complete', 'dependency_vulnerability', {
    packageName: 'left-pad',
    installedVersion: '1.3.0',
    vulnerableRange: '<1.3.1',
    advisoryId: 'GHSA-xxxx-yyyy-zzzz',
  });
  assert.equal(evaluateFindingAutoPromotion(depVulnComplete).decision, 'auto_promote');

  console.log('[+] Hito 2: all 7 previously-ungated kinds now require real evidence before auto_promote');

  // 7. applyFindingAutoPromotion partitions correctly
  const result = applyFindingAutoPromotion({
    drafts: [idorOk, idorNoise, idorBolaSameBody, headers, routes, reflOk],
    assessmentId: 'asm_auto_promo',
    scanId: 'scn_auto_promo',
    targetDomain: 'app.example.com',
    actorId: 'actor_test',
    evaluatedAt: new Date().toISOString(),
  });
  assert.equal(result.findings.length, 3, 'idor diff + idor bola + reflection must become findings');
  assert.ok(result.findings.filter((f) => f.type === 'BROKEN_ACCESS_CONTROL').length >= 2);
  assert.ok(result.findings.some((f) => f.type === 'INPUT_VALIDATION_FLAW'));
  assert.ok(
    result.findings.every((f) => f.verificationState !== 'exploitability_confirmed'),
    'auto findings must not claim exploitability_confirmed'
  );
  assert.ok(result.remainingDrafts.some((d) => d.draftId === 'dft_idor_noise'));
  assert.ok(result.remainingDrafts.some((d) => d.draftId === 'dft_headers'));
  assert.ok(result.droppedDraftIds.includes('dft_routes'));

  // 8. Attack plans prefer findings; header drafts mint no plans
  const plans = generateAttackPlans({
    assessmentId: 'asm_auto_promo',
    scanId: 'scn_auto_promo',
    findings: [...result.findings],
    identities: [
      { identityId: 'id_a', hasJwt: false },
      { identityId: 'id_b', hasJwt: false },
    ],
    lineage: {
      assessmentId: 'asm_auto_promo',
      scanId: 'scn_auto_promo',
      authorizationGrantId: 'grn_test',
      authorizationDecisionId: 'dec_test',
      actorId: 'actor_test',
    },
    draftSignals: [
      {
        draftId: 'dft_headers',
        detectionKind: 'missing_security_headers',
        endpointUrl: 'https://app.example.com/',
      },
    ],
    generatedAt: new Date().toISOString(),
  });
  assert.ok(
    plans.plans.some((p) => p.capability === 'idor_read_differential'),
    'auto IDOR finding must feed AttackPlan'
  );
  assert.ok(
    plans.plans.every((p) => !p.reasoning.includes('missing_security_headers')),
    'header cosmetics must not feed AttackPlan'
  );
  assert.ok(
    plans.plans.every((p) => p.executable === false),
    'plans remain non-executable (human auth for execute)'
  );

  console.log('=== Finding Auto-Promotion: ALL TESTS PASSED ===');
}

try {
  runSmokeTests();
} catch (err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  fail(message);
}
