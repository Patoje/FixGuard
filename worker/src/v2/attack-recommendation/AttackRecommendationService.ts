/**
 * Deterministic AttackRecommendationService — operator A/B ranking.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 * No ML / no magic: closed rule table over finding type + stack + preconditions + registry.
 */

import { createHash } from 'node:crypto';
import type { Finding, FindingMetadata } from '../core/Evidence.js';
import type { AttackCapabilityKind, AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import {
  ATTACK_OPERATOR_RECOMMENDATION_CONTRACT_VERSION,
  type AttackRecommendationServiceInput,
  type AttackRecommendationServiceResult,
  type OperatorAttackRecommendation,
  type OperatorPreconditions,
  type OperatorStackHints,
  type OperatorSuggestedFlags,
  type OperatorRecommendationReasonKind,
} from './AttackOperatorRecommendationContracts.js';
import { isBlockingDefense } from '../test-validity/DefenseObservationService.js';
import type { DefenseObservation } from '../test-validity/TestValidityContracts.js';

/** Spray-style capabilities that WAF/bot defenses often invalidate. */
const DEFENSE_SENSITIVE_CAPABILITIES: ReadonlySet<AttackCapabilityKind> = new Set([
  'nuclei_xss_scan',
  'parameter_reflection_probe',
  'sql_injection_verification',
  'sql_error_oracle_probe',
  'sql_oracle_advancement',
]);

function applyDefenseSoftPenalty(
  candidates: Candidate[],
  defenses: readonly DefenseObservation[] | undefined,
  rulesApplied: string[]
): Candidate[] {
  if (!defenses || defenses.length === 0) return candidates;
  const blocking = defenses.filter(isBlockingDefense);
  if (blocking.length === 0) return candidates;

  rulesApplied.push('rule_defense_observation_soft_penalty');
  return candidates.map((c) => {
    if (!DEFENSE_SENSITIVE_CAPABILITIES.has(c.capabilityKind)) return c;
    const penalized = Math.max(5, c.score - 25);
    return {
      ...c,
      score: penalized,
      reason: `${c.reason} [defense soft-penalty: ${blocking[0]!.controlKind}]`,
    };
  });
}

interface Candidate {
  readonly capabilityKind: AttackCapabilityKind;
  readonly humanLabel: string;
  readonly score: number;
  readonly reasonKind: OperatorRecommendationReasonKind;
  readonly reason: string;
  readonly ruleId: string;
  readonly suggestedFlags: OperatorSuggestedFlags;
  readonly commandSummary: string;
  readonly executable: boolean;
  readonly disabilityReason?: string;
  readonly sourceFindingId?: string;
  readonly sourceFindingType?: string;
  readonly planId?: string;
}

const CAPABILITY_LABELS: Readonly<Record<AttackCapabilityKind, string>> = {
  idor_read_differential: 'IDOR / BOLA differential read (BYOT A↔B)',
  cors_chain_exploit: 'Credentialed CORS chain exploit',
  auth_bypass_probe: 'Authentication bypass probe',
  jwt_alg_none_probe: 'JWT alg=none confusion probe',
  sql_error_oracle_probe: 'SQL error-oracle probe (advisory)',
  parameter_reflection_probe: 'Parameter reflection probe (advisory)',
  session_fixation_probe: 'Session fixation probe',
  method_manipulation_probe: 'HTTP method manipulation probe',
  lfi_path_traversal: 'LFI / path traversal verification',
  sql_oracle_advancement: 'SQL oracle advancement',
  nuclei_xss_scan: 'Nuclei XSS template scan',
  sql_injection_verification: 'sqlmap technique=E verification',
  credential_reuse: 'Credential reuse (lateral)',
  supabase_rls_read_confirm: 'Supabase RLS world-readable read confirm',
  supabase_rls_write_probe: 'Supabase RLS write canary (HITL mutation)',
  supabase_authz_write_matrix: 'Supabase authz write matrix BOLA/BFLA (HITL)',
  next_server_action_diff: 'Next.js Server Action differential (unauth↔BYOT)',
};

function sha16(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function normalizeStack(hints: OperatorStackHints | undefined): Required<
  Pick<OperatorStackHints, 'hasSpa' | 'hasPhpLegacy' | 'hasCms' | 'hasVercel' | 'hasNextJs'>
> & {
  spaFramework?: OperatorStackHints['spaFramework'];
  cmsType?: OperatorStackHints['cmsType'];
  technologyNames: readonly string[];
} {
  const names = (hints?.technologyNames ?? []).map((n) => n.toLowerCase());
  const hasName = (re: RegExp): boolean => names.some((n) => re.test(n));

  const hasNextJs =
    hints?.hasNextJs === true ||
    hints?.spaFramework === 'nextjs' ||
    hasName(/next\.?js|nextjs/);
  const hasVercel = hints?.hasVercel === true || hasName(/vercel/);
  const hasSpa =
    hints?.hasSpa === true ||
    hasNextJs ||
    hints?.spaFramework === 'react' ||
    hints?.spaFramework === 'vue' ||
    hints?.spaFramework === 'angular' ||
    hints?.spaFramework === 'nuxtjs' ||
    hasName(/react|vue|angular|nuxt|spa/);
  const hasPhpLegacy =
    hints?.hasPhpLegacy === true || hasName(/\bphp\b|wordpress|joomla|drupal|laravel/);
  const hasCms =
    hints?.hasCms === true ||
    hints?.cmsType === 'wordpress' ||
    hints?.cmsType === 'joomla' ||
    hints?.cmsType === 'drupal' ||
    hasName(/wordpress|joomla|drupal/);

  return {
    hasSpa,
    hasPhpLegacy,
    hasCms,
    hasVercel,
    hasNextJs,
    ...(hints?.spaFramework ? { spaFramework: hints.spaFramework } : {}),
    ...(hints?.cmsType ? { cmsType: hints.cmsType } : {}),
    technologyNames: names,
  };
}

function isCredentialedCors(finding: Finding): boolean {
  const meta = finding.metadata;
  if (meta.kind === 'credentialed_cors_metadata') {
    return meta.allowCredentialsHeader === true;
  }
  if (
    meta.kind === 'security_misconfiguration_metadata' &&
    meta.category === 'CORS_MISCONFIGURATION'
  ) {
    return meta.allowCredentials === true;
  }
  return finding.type === 'CORS_MISCONFIGURATION';
}

function isIdorFinding(finding: Finding): boolean {
  return (
    finding.type === 'BROKEN_ACCESS_CONTROL' ||
    finding.metadata.kind === 'broken_access_control_metadata'
  );
}

function isJwtFinding(finding: Finding): boolean {
  return (
    finding.type === 'BROKEN_AUTHENTICATION' &&
    finding.metadata.kind === 'jwt_algorithm_confusion_metadata'
  );
}

function isAuthBypassFinding(finding: Finding): boolean {
  return finding.type === 'BROKEN_AUTHENTICATION' && finding.metadata.kind === 'auth_bypass_metadata';
}

function isSqlOracleFinding(finding: Finding): boolean {
  return (
    finding.type === 'INFORMATION_DISCLOSURE' &&
    finding.metadata.kind === 'sql_error_oracle_metadata'
  );
}

function isReflectionOrXss(finding: Finding): boolean {
  if (finding.metadata.kind === 'blind_xss_detection_metadata') return true;
  if (finding.type === 'CROSS_SITE_SCRIPTING' || finding.type === 'PARAMETER_REFLECTION') return true;
  if (finding.type === 'INPUT_VALIDATION_FLAW' && finding.metadata.kind === 'input_validation_flaw_metadata') {
    return (
      finding.metadata.category === 'PARAMETER_REFLECTION' ||
      finding.metadata.category === 'INPUT_VALIDATION_FLAW' ||
      typeof finding.metadata.parameterName === 'string'
    );
  }
  return false;
}

function isLfiFinding(finding: Finding): boolean {
  return finding.metadata.kind === 'parameter_integrity_metadata';
}

function targetFromFinding(finding: Finding): string {
  const meta = finding.metadata as FindingMetadata & { endpointUrl?: string };
  if (typeof meta.endpointUrl === 'string' && meta.endpointUrl.length > 0) {
    return meta.endpointUrl;
  }
  return finding.target;
}

function parameterFromFinding(finding: Finding): string | undefined {
  const meta = finding.metadata;
  if ('parameterName' in meta && typeof meta.parameterName === 'string') {
    return meta.parameterName;
  }
  if (meta.kind === 'broken_access_control_metadata' && typeof meta.resourceParamName === 'string') {
    return meta.resourceParamName;
  }
  return undefined;
}

function planForCapability(
  plans: readonly AttackPlan[] | undefined,
  capability: AttackCapabilityKind,
  findingId?: string
): AttackPlan | undefined {
  if (!plans || plans.length === 0) return undefined;
  const matched = plans.filter((p) => p.capability === capability);
  if (findingId) {
    const byFinding = matched.find((p) => p.sourceFindingIds.includes(findingId));
    if (byFinding) return byFinding;
  }
  return matched[0];
}

function withRegistryGate(
  candidate: Candidate,
  registered: ReadonlySet<AttackCapabilityKind>
): Candidate {
  if (!registered.has(candidate.capabilityKind)) {
    return {
      ...candidate,
      executable: false,
      disabilityReason:
        candidate.disabilityReason ??
        `capability_not_implemented: ${candidate.capabilityKind} is not registered in AttackCapabilityRegistry`,
      score: Math.min(candidate.score, 40),
    };
  }
  return candidate;
}

function buildCandidatesForFinding(args: {
  finding: Finding;
  stack: ReturnType<typeof normalizeStack>;
  preconditions: OperatorPreconditions;
  registered: ReadonlySet<AttackCapabilityKind>;
  plans?: readonly AttackPlan[];
}): { candidates: Candidate[]; rulesApplied: string[] } {
  const { finding, stack, preconditions, registered, plans } = args;
  const rulesApplied: string[] = [];
  const raw: Candidate[] = [];
  const target = targetFromFinding(finding);
  const param = parameterFromFinding(finding);
  const findingId = finding.id;
  const findingType = finding.type;
  const vercelNext = stack.hasVercel && stack.hasNextJs;

  const push = (
    c: Omit<Candidate, 'ruleId' | 'sourceFindingId' | 'sourceFindingType' | 'planId'>,
    ruleId: string
  ): void => {
    rulesApplied.push(ruleId);
    raw.push(
      withRegistryGate(
        {
          ...c,
          ruleId,
          sourceFindingId: findingId,
          sourceFindingType: findingType,
          planId: planForCapability(plans, c.capabilityKind, findingId)?.planId,
        },
        registered
      )
    );
  };

  // --- IDOR / BOLA ---
  if (isIdorFinding(finding)) {
    const byotOk = preconditions.identityCount >= 2;
    const isSupabaseRls = finding.metadata.kind === 'supabase_rls_abuse_metadata';

    if (isSupabaseRls) {
      push(
        {
          capabilityKind: 'supabase_rls_read_confirm',
          humanLabel: CAPABILITY_LABELS.supabase_rls_read_confirm,
          score: 99,
          reasonKind: 'OBSERVED',
          reason: 'Supabase RLS world-readable table — prefer read confirm over generic IDOR',
          suggestedFlags: { method: 'GET', mode: 'rls_read_confirm', limit: 1 },
          commandSummary: `supabase_rls_read_confirm GET ${target}?select=*&limit=1`,
          executable: registered.has('supabase_rls_read_confirm'),
        },
        'rule_supabase_rls_read'
      );
      push(
        {
          capabilityKind: 'supabase_rls_write_probe',
          humanLabel: CAPABILITY_LABELS.supabase_rls_write_probe,
          score: 70,
          reasonKind: 'INFERRED',
          reason:
            'Advisory canary write — executable only after HITL mutation scope (state_change_benign)',
          suggestedFlags: { method: 'POST', mode: 'rls_write_canary', mutation: true },
          commandSummary: `supabase_rls_write_probe POST ${target} (HITL mutation)`,
          executable: false,
          disabilityReason: 'requires_hitl_mutation_scope: allowStateChangingRequests',
        },
        'rule_supabase_rls_write'
      );
      push(
        {
          capabilityKind: 'supabase_authz_write_matrix',
          humanLabel: CAPABILITY_LABELS.supabase_authz_write_matrix,
          score: byotOk ? 85 : 50,
          reasonKind: 'INFERRED',
          reason: byotOk
            ? 'Authz write matrix applicable with BYOT A+B — still requires mutation scope at execute'
            : 'Authz write matrix requires BYOT A+B and HITL mutation scope',
          suggestedFlags: { method: 'POST', differential: true, mutation: true },
          commandSummary: `supabase_authz_write_matrix POST ${target} identities=${preconditions.identityCount}`,
          executable: false,
          disabilityReason: byotOk
            ? 'requires_hitl_mutation_scope: allowStateChangingRequests'
            : 'prerequisite_missing: identity_count_at_least_2 (BYOT A+B) + mutation scope',
        },
        'rule_supabase_authz_write_matrix'
      );
    } else {
      push(
        {
          capabilityKind: 'idor_read_differential',
          humanLabel: CAPABILITY_LABELS.idor_read_differential,
          score: byotOk ? 100 : 55,
          reasonKind: 'OBSERVED',
          reason: byotOk
            ? 'BROKEN_ACCESS_CONTROL observed with BYOT A+B identities available'
            : 'BROKEN_ACCESS_CONTROL observed but BYOT requires ≥2 identities',
          suggestedFlags: {
            method: 'GET',
            differential: true,
            identityCount: preconditions.identityCount,
            ...(param ? { resourceParam: param } : {}),
          },
          commandSummary: `idor_read_differential GET ${target} identities=${preconditions.identityCount}`,
          executable: byotOk,
          ...(byotOk
            ? {}
            : { disabilityReason: 'prerequisite_missing: identity_count_at_least_2 (BYOT A+B)' }),
        },
        'rule_idor_byot'
      );
    }
  }

  // --- CORS + creds ---
  if (isCredentialedCors(finding) || preconditions.hasCredentialedCorsSignal) {
    if (isCredentialedCors(finding) || finding.type === 'CORS_MISCONFIGURATION') {
      push(
        {
          capabilityKind: 'cors_chain_exploit',
          humanLabel: CAPABILITY_LABELS.cors_chain_exploit,
          score: 95,
          reasonKind: 'OBSERVED',
          reason: 'Credentialed CORS misconfiguration signal present',
          suggestedFlags: { allowCredentials: true, mode: 'chain_exploit' },
          commandSummary: `cors_chain_exploit ${target} allowCredentials=true`,
          executable: true,
        },
        'rule_cors_creds'
      );
    }
  }

  // --- JWT ---
  if (isJwtFinding(finding) || preconditions.hasJwtIdentity) {
    if (isJwtFinding(finding) || finding.type === 'BROKEN_AUTHENTICATION') {
      const jwtObserved = isJwtFinding(finding);
      push(
        {
          capabilityKind: 'jwt_alg_none_probe',
          humanLabel: CAPABILITY_LABELS.jwt_alg_none_probe,
          score: jwtObserved ? 98 : preconditions.hasJwtIdentity ? 80 : 50,
          reasonKind: jwtObserved ? 'OBSERVED' : 'INFERRED',
          reason: jwtObserved
            ? 'JWT algorithm confusion metadata observed'
            : 'JWT-bearing identity present — alg=none probe is applicable',
          suggestedFlags: { alg: 'none', probe: 'alg_confusion' },
          commandSummary: `jwt_alg_none_probe ${target} alg=none`,
          executable: jwtObserved || preconditions.hasJwtIdentity,
          ...(!jwtObserved && !preconditions.hasJwtIdentity
            ? { disabilityReason: 'prerequisite_missing: identity_with_jwt' }
            : {}),
        },
        'rule_jwt_alg_none'
      );
    }
  }

  // --- Auth bypass ---
  if (isAuthBypassFinding(finding)) {
    push(
      {
        capabilityKind: 'auth_bypass_probe',
        humanLabel: CAPABILITY_LABELS.auth_bypass_probe,
        score: 92,
        reasonKind: 'OBSERVED',
        reason: 'Auth bypass metadata observed on BROKEN_AUTHENTICATION finding',
        suggestedFlags: { mode: 'bypass_probe' },
        commandSummary: `auth_bypass_probe ${target}`,
        executable: true,
      },
      'rule_auth_bypass'
    );
  }

  // --- SQLi oracle ladder ---
  if (isSqlOracleFinding(finding)) {
    if (finding.verificationState === 'validated_vulnerability') {
      push(
        {
          capabilityKind: 'sql_injection_verification',
          humanLabel: CAPABILITY_LABELS.sql_injection_verification,
          score: 97,
          reasonKind: 'OBSERVED',
          reason: 'SQL error oracle at validated_vulnerability — sqlmap technique=E only',
          suggestedFlags: {
            technique: 'E',
            ...(param ? { parameter: param } : {}),
            level: 1,
            risk: 1,
          },
          commandSummary: `sqlmap -u ${target}${param ? ` -p ${param}` : ''} --technique=E --batch`,
          executable: true,
        },
        'rule_sqli_sqlmap_e'
      );
    } else if (finding.verificationState === 'suspected_vulnerability') {
      push(
        {
          capabilityKind: 'sql_oracle_advancement',
          humanLabel: CAPABILITY_LABELS.sql_oracle_advancement,
          score: 94,
          reasonKind: 'OBSERVED',
          reason: 'SQL error oracle at suspected_vulnerability — advance one verification step',
          suggestedFlags: {
            mode: 'oracle_advancement',
            ...(param ? { parameter: param } : {}),
          },
          commandSummary: `sql_oracle_advancement ${target}${param ? ` param=${param}` : ''}`,
          executable: true,
        },
        'rule_sqli_oracle_advance'
      );
    } else {
      push(
        {
          capabilityKind: 'sql_error_oracle_probe',
          humanLabel: CAPABILITY_LABELS.sql_error_oracle_probe,
          score: 70,
          reasonKind: 'OBSERVED',
          reason: 'SQL error oracle observed — advisory probe (may be capability_not_implemented)',
          suggestedFlags: {
            mode: 'error_oracle',
            ...(param ? { parameter: param } : {}),
          },
          commandSummary: `sql_error_oracle_probe ${target}${param ? ` param=${param}` : ''}`,
          executable: registered.has('sql_error_oracle_probe'),
        },
        'rule_sqli_oracle_probe'
      );
    }
  }

  // --- XSS / reflection (stack-aware) ---
  if (isReflectionOrXss(finding)) {
    const legacyPhp = stack.hasPhpLegacy || stack.hasCms;
    const spaStack = stack.hasSpa || stack.hasNextJs;

    if (legacyPhp && !vercelNext) {
      push(
        {
          capabilityKind: 'nuclei_xss_scan',
          humanLabel: CAPABILITY_LABELS.nuclei_xss_scan,
          score: 70,
          reasonKind: 'OBSERVED',
          reason: 'Reflection/XSS on legacy/PHP/CMS stack — nuclei XSS templates',
          suggestedFlags: {
            templates: 'xss',
            ...(param ? { parameter: param } : {}),
          },
          commandSummary: `nuclei -t xss/ -u ${target}${param ? ` -V param=${param}` : ''}`,
          executable: true,
        },
        'rule_xss_legacy_nuclei'
      );
      push(
        {
          capabilityKind: 'parameter_reflection_probe',
          humanLabel: CAPABILITY_LABELS.parameter_reflection_probe,
          score: 88,
          reasonKind: 'OBSERVED',
          reason:
            'Legacy/PHP/CMS reflection path — prefer dalfox parameter_reflection_probe under human authorize',
          suggestedFlags: { ...(param ? { parameter: param } : {}), tool: 'dalfox' },
          commandSummary: `dalfox url ${target}${param ? ` -p ${param}` : ''} --silence --format json`,
          executable: registered.has('parameter_reflection_probe'),
          ...(!registered.has('parameter_reflection_probe')
            ? { disabilityReason: 'capability_not_implemented: parameter_reflection_probe' }
            : {}),
        },
        'rule_xss_legacy_dalfox'
      );
    } else if (spaStack || vercelNext) {
      push(
        {
          capabilityKind: 'nuclei_xss_scan',
          humanLabel: CAPABILITY_LABELS.nuclei_xss_scan,
          score: 35,
          reasonKind: 'INFERRED',
          reason:
            'SPA/Next/Vercel stack — classic XSS spray deprioritized (DOM/framework escaping common)',
          suggestedFlags: { templates: 'xss', deprioritized: true },
          commandSummary: `nuclei -t xss/ -u ${target} # deprioritized on SPA/Next`,
          executable: true,
        },
        'rule_xss_spa_deprioritize'
      );
      push(
        {
          capabilityKind: 'parameter_reflection_probe',
          humanLabel: CAPABILITY_LABELS.parameter_reflection_probe,
          score: 20,
          reasonKind: 'INFERRED',
          reason:
            'SPA-primary stack — dalfox/reflection probe deprioritized (prefer authz differentials)',
          suggestedFlags: { deprioritized: true, ...(param ? { parameter: param } : {}) },
          commandSummary: `dalfox url ${target} # deprioritized on SPA/Next`,
          executable: false,
          disabilityReason: 'stack_policy: deprioritize dalfox reflection on SPA-primary',
        },
        'rule_xss_spa_dalfox_deprioritize'
      );
      // Prefer authz if BYOT available as alternate on SPA
      if (preconditions.identityCount >= 2) {
        push(
          {
            capabilityKind: 'idor_read_differential',
            humanLabel: CAPABILITY_LABELS.idor_read_differential,
            score: 72,
            reasonKind: 'INFERRED',
            reason:
              'On SPA/Next, prefer authz/IDOR differential over classic XSS when BYOT A+B present',
            suggestedFlags: {
              method: 'GET',
              differential: true,
              identityCount: preconditions.identityCount,
            },
            commandSummary: `idor_read_differential GET ${target} identities=${preconditions.identityCount}`,
            executable: true,
          },
          'rule_spa_prefer_authz'
        );
      }
    } else {
      push(
        {
          capabilityKind: 'nuclei_xss_scan',
          humanLabel: CAPABILITY_LABELS.nuclei_xss_scan,
          score: 75,
          reasonKind: 'OBSERVED',
          reason: 'Reflection/XSS anomaly — nuclei XSS scan',
          suggestedFlags: {
            templates: 'xss',
            ...(param ? { parameter: param } : {}),
          },
          commandSummary: `nuclei -t xss/ -u ${target}`,
          executable: true,
        },
        'rule_xss_default_nuclei'
      );
    }
  }

  // --- LFI (stack-aware: never primary on Vercel+Next) ---
  if (isLfiFinding(finding)) {
    if (vercelNext) {
      push(
        {
          capabilityKind: 'lfi_path_traversal',
          humanLabel: CAPABILITY_LABELS.lfi_path_traversal,
          score: 15,
          reasonKind: 'INFERRED',
          reason: 'Vercel+Next stack — LFI/path traversal is not a primary validation path',
          suggestedFlags: { deprioritized: true, ...(param ? { parameter: param } : {}) },
          commandSummary: `lfi_path_traversal ${target} # not primary on Vercel+Next`,
          executable: false,
          disabilityReason: 'stack_policy: do not recommend LFI as primary on Vercel+Next',
        },
        'rule_lfi_vercel_block'
      );
    } else if (stack.hasPhpLegacy) {
      push(
        {
          capabilityKind: 'lfi_path_traversal',
          humanLabel: CAPABILITY_LABELS.lfi_path_traversal,
          score: 88,
          reasonKind: 'OBSERVED',
          reason: 'Parameter integrity / LFI signal on PHP-legacy stack',
          suggestedFlags: { mode: 'path_traversal', ...(param ? { parameter: param } : {}) },
          commandSummary: `lfi_path_traversal ${target}${param ? ` param=${param}` : ''}`,
          executable: true,
        },
        'rule_lfi_php'
      );
    } else {
      push(
        {
          capabilityKind: 'lfi_path_traversal',
          humanLabel: CAPABILITY_LABELS.lfi_path_traversal,
          score: 60,
          reasonKind: 'OBSERVED',
          reason: 'Parameter integrity signal — LFI verification candidate',
          suggestedFlags: { mode: 'path_traversal', ...(param ? { parameter: param } : {}) },
          commandSummary: `lfi_path_traversal ${target}${param ? ` param=${param}` : ''}`,
          executable: true,
        },
        'rule_lfi_default'
      );
    }
  }

  // Deduplicate by capability (keep highest score)
  const byCap = new Map<AttackCapabilityKind, Candidate>();
  for (const c of raw) {
    const prev = byCap.get(c.capabilityKind);
    if (!prev || c.score > prev.score) {
      byCap.set(c.capabilityKind, c);
    }
  }

  return {
    candidates: [...byCap.values()],
    rulesApplied: [...new Set(rulesApplied)],
  };
}

function buildCandidatesFromPlan(args: {
  plan: AttackPlan;
  stack: ReturnType<typeof normalizeStack>;
  preconditions: OperatorPreconditions;
  registered: ReadonlySet<AttackCapabilityKind>;
  finding?: Finding;
}): { candidates: Candidate[]; rulesApplied: string[] } {
  const { plan, registered, finding, preconditions, stack } = args;
  if (finding) {
    return buildCandidatesForFinding({
      finding,
      stack,
      preconditions,
      registered,
      plans: [plan],
    });
  }

  // Plan-only: rank primary capability as A, suggest a sensible alternate as B
  const rulesApplied = ['rule_plan_primary'];
  const primary = withRegistryGate(
    {
      capabilityKind: plan.capability,
      humanLabel: CAPABILITY_LABELS[plan.capability],
      score: 90,
      reasonKind: 'OBSERVED',
      reason: `Advisory plan ${plan.planId} recommends ${plan.capability}`,
      ruleId: 'rule_plan_primary',
      suggestedFlags: {
        planId: plan.planId,
        ...(plan.parameterName ? { parameter: plan.parameterName } : {}),
      },
      commandSummary: `${plan.capability} ${plan.targetUrl ?? '(no targetUrl)'}`,
      executable:
        registered.has(plan.capability) && plan.status !== 'prerequisite_missing',
      ...(plan.status === 'prerequisite_missing'
        ? { disabilityReason: 'plan status prerequisite_missing' }
        : {}),
      planId: plan.planId,
      sourceFindingId: plan.sourceFindingIds[0],
      sourceFindingType: plan.sourceFindingTypes[0],
    },
    registered
  );

  const alternateKind: AttackCapabilityKind | null =
    plan.capability === 'nuclei_xss_scan' && preconditions.identityCount >= 2
      ? 'idor_read_differential'
      : plan.capability === 'idor_read_differential' && preconditions.hasJwtIdentity
        ? 'jwt_alg_none_probe'
        : plan.capability === 'sql_oracle_advancement'
          ? 'sql_injection_verification'
          : null;

  const candidates = [primary];
  if (alternateKind) {
    rulesApplied.push('rule_plan_alternate');
    candidates.push(
      withRegistryGate(
        {
          capabilityKind: alternateKind,
          humanLabel: CAPABILITY_LABELS[alternateKind],
          score: 50,
          reasonKind: 'INFERRED',
          reason: `Alternate validation path relative to plan capability ${plan.capability}`,
          ruleId: 'rule_plan_alternate',
          suggestedFlags: { alternateTo: plan.capability },
          commandSummary: `${alternateKind} (alternate to ${plan.capability})`,
          executable: registered.has(alternateKind),
          planId: plan.planId,
        },
        registered
      )
    );
  }

  return { candidates, rulesApplied };
}

function rankTopTwo(
  candidates: Candidate[],
  assessmentId: string
): OperatorAttackRecommendation[] {
  const sorted = [...candidates].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.capabilityKind.localeCompare(b.capabilityKind);
  });

  const top = sorted.slice(0, 2);
  if (top.length === 0) return [];

  const out: OperatorAttackRecommendation[] = [];
  for (let i = 0; i < top.length; i++) {
    const c = top[i]!;
    const rank = i === 0 ? 'A' : 'B';
    const other = top[1 - i];
    let whyPreferred: string;
    if (i === 0) {
      whyPreferred = other
        ? `Higher deterministic score (${c.score} > ${other.score}) via ${c.ruleId}` +
          (c.executable && !other.executable ? '; also executable while alternate is not' : '')
        : `Sole ranked candidate via ${c.ruleId} (score ${c.score})`;
    } else {
      whyPreferred = `Secondary candidate (score ${c.score}) after A=${top[0]!.capabilityKind} (${top[0]!.score}) via ${c.ruleId}`;
    }

    out.push({
      recommendationId: `orec_${sha16([assessmentId, rank, c.capabilityKind, c.sourceFindingId ?? ''].join('|'))}`,
      rank,
      capabilityKind: c.capabilityKind,
      humanLabel: c.humanLabel,
      suggestedFlags: c.suggestedFlags,
      commandSummary: c.commandSummary,
      executable: c.executable,
      reasonKind: c.reasonKind,
      reason: c.reason,
      whyPreferred,
      ...(c.disabilityReason ? { disabilityReason: c.disabilityReason } : {}),
      ...(c.planId ? { planId: c.planId } : {}),
      ...(c.sourceFindingId ? { sourceFindingId: c.sourceFindingId } : {}),
      ...(c.sourceFindingType ? { sourceFindingType: c.sourceFindingType } : {}),
      score: c.score,
    });
  }
  return out;
}

export class AttackRecommendationService {
  public recommend(input: AttackRecommendationServiceInput): AttackRecommendationServiceResult {
    const generatedAt = input.generatedAt ?? new Date().toISOString();
    const stack = normalizeStack(input.stackHints);
    const registered = input.registeredCapabilities;

    let candidates: Candidate[] = [];
    let rulesApplied: string[] = [];

    if (input.finding) {
      const built = buildCandidatesForFinding({
        finding: input.finding,
        stack,
        preconditions: input.preconditions,
        registered,
        plans: input.plans,
      });
      candidates = built.candidates;
      rulesApplied = built.rulesApplied;
    } else if (input.plan) {
      const finding =
        input.findings?.find((f) => input.plan!.sourceFindingIds.includes(f.id)) ??
        undefined;
      const built = buildCandidatesFromPlan({
        plan: input.plan,
        stack,
        preconditions: input.preconditions,
        registered,
        ...(finding ? { finding } : {}),
      });
      candidates = built.candidates;
      rulesApplied = built.rulesApplied;
    } else if (input.findings && input.findings.length > 0) {
      // Assessment-wide: use highest-signal finding
      const ordered = [...input.findings].sort((a, b) => a.id.localeCompare(b.id));
      const allRules: string[] = [];
      const merged = new Map<AttackCapabilityKind, Candidate>();
      for (const finding of ordered) {
        const built = buildCandidatesForFinding({
          finding,
          stack,
          preconditions: input.preconditions,
          registered,
          plans: input.plans,
        });
        allRules.push(...built.rulesApplied);
        for (const c of built.candidates) {
          const prev = merged.get(c.capabilityKind);
          if (!prev || c.score > prev.score) merged.set(c.capabilityKind, c);
        }
      }
      candidates = [...merged.values()];
      rulesApplied = [...new Set(allRules)];
    } else {
      rulesApplied = ['rule_no_subject'];
    }

    candidates = applyDefenseSoftPenalty(
      candidates,
      input.defenseObservations,
      rulesApplied
    );

    const recommendations = rankTopTwo(candidates, input.assessmentId);

    return {
      contractVersion: ATTACK_OPERATOR_RECOMMENDATION_CONTRACT_VERSION,
      kind: 'attack_operator_recommendation_set',
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      ...(input.finding ? { subjectFindingId: input.finding.id } : {}),
      ...(input.plan ? { subjectPlanId: input.plan.planId } : {}),
      ...(input.investigationId ? { investigationId: input.investigationId } : {}),
      recommendations,
      rulesApplied,
      lineage: input.lineage,
      generatedAt,
    };
  }
}
