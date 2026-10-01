/**
 * FixGuard V2 — Demonstration of Operator Attack Recommendations & 1-Click Commands
 *
 * Simulates real-world findings detected on targets (Supabase RLS, IDOR/BOLA, SQLi)
 * and runs them through AttackRecommendationService to show:
 * - Deterministic A/B tool ranking
 * - Exact flags generated for each tool
 * - Ready-to-execute command line
 * - Authorization status & prerequisites
 */

import { AttackRecommendationService } from '../src/v2/attack-recommendation/AttackRecommendationService.js';
import { AttackCapabilityRegistry } from '../src/v2/attack-execution/AttackCapabilityRegistry.js';
import type { Finding } from '../src/v2/core/Evidence.js';
import type { AttackCapabilityKind } from '../src/v2/attack-planning/AttackPlanContracts.js';

const LINEAGE = {
  assessmentId: 'asmt_live_demo',
  scanId: 'scan_live_demo',
  authorizationGrantId: 'grant_live_demo',
  authorizationDecisionId: 'dec_live_demo',
  actorId: 'operator_demo',
} as const;

function getRegisteredCapabilities(): ReadonlySet<AttackCapabilityKind> {
  const registry = AttackCapabilityRegistry.createDefault();
  const allKinds: readonly AttackCapabilityKind[] = [
    'idor_read_differential',
    'cors_chain_exploit',
    'auth_bypass_probe',
    'auth_boundary_differential',
    'jwt_alg_none_probe',
    'sql_error_oracle_probe',
    'parameter_reflection_probe',
    'session_fixation_probe',
    'method_manipulation_probe',
    'lfi_path_traversal',
    'sql_oracle_advancement',
    'nuclei_xss_scan',
    'sql_injection_verification',
    'credential_reuse',
    'supabase_rls_read_confirm',
    'supabase_rls_write_probe',
    'supabase_authz_write_matrix',
    'next_server_action_diff',
  ];
  return new Set(allKinds.filter((k) => registry.get(k) !== null));
}

async function runDemo() {
  console.log('======================================================================');
  console.log('   FIXGUARD V2 — DEMO DE RECOMENDACIÓN DE ATAQUES Y FLAGS AL OPERADOR');
  console.log('   "Tools execute. Intelligence decides. Humans authorize."');
  console.log('======================================================================\n');

  const recommendationService = new AttackRecommendationService();
  const registeredCaps = getRegisteredCapabilities();

  // Caso 1: Hallazgo Supabase RLS World-Readable (como el encontrado en teclaaa.vercel.app)
  const findingSupabase: Finding = {
    id: 'fnd_supabase_rls_01',
    type: 'BROKEN_ACCESS_CONTROL',
    title: 'Supabase RLS World-Readable Table: public.profiles',
    target: 'https://vawrzoncszqauzxwqide.supabase.co/rest/v1/profiles',
    severity: 'high',
    evidence: 'observed',
    confidence: 0.95,
    verificationState: 'suspected_vulnerability',
    description: 'Tabla profiles accesible con anon key sin restricción RLS',
    metadata: {
      kind: 'supabase_rls_abuse_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_supa_1',
      evidenceRecordId: 'evr_supa_1',
      lineage: {},
      endpointUrl: 'https://vawrzoncszqauzxwqide.supabase.co/rest/v1/profiles',
      tableName: 'profiles',
    },
  };

  // Caso 2: Hallazgo IDOR / BOLA en API REST (con 2 identidades BYOT disponibles)
  const findingIdor: Finding = {
    id: 'fnd_idor_02',
    type: 'BROKEN_ACCESS_CONTROL',
    title: 'IDOR / BOLA on User Account Resource',
    target: 'https://api.target.com/v1/users/42/settings',
    severity: 'high',
    evidence: 'observed',
    confidence: 0.88,
    verificationState: 'observed_anomaly',
    description: 'Endpoint REST susceptible a lectura cruzada entre tenants',
    metadata: {
      kind: 'broken_access_control_metadata',
      category: 'BROKEN_ACCESS_CONTROL',
      candidateId: 'cand_idor_2',
      evidenceRecordId: 'evr_idor_2',
      lineage: {},
      endpointUrl: 'https://api.target.com/v1/users/42/settings',
      resourceParamName: 'id',
    },
  };

  // Caso 3: Hallazgo de Inyección SQL (Error Oracle / Parameter reflection)
  const findingSqli: Finding = {
    id: 'fnd_sqli_03',
    type: 'INFORMATION_DISCLOSURE',
    title: 'SQL Database Error Syntax Leaked in HTTP Response',
    target: 'https://target.com/catalog/search?q=test',
    severity: 'medium',
    evidence: 'observed',
    confidence: 0.92,
    verificationState: 'validated_vulnerability',
    description: 'Error de sintaxis Postgres expuesto en parámetro q',
    metadata: {
      kind: 'sql_error_oracle_metadata',
      category: 'SQL_ERROR_ORACLE',
      candidateId: 'cand_sqli_3',
      evidenceRecordId: 'evr_sqli_3',
      lineage: {},
      endpointUrl: 'https://target.com/catalog/search?q=test',
      parameterName: 'q',
    },
  };

  const scenarios = [
    {
      name: 'CASO 1: Hallazgo Supabase RLS (Stack Vercel + Next.js + Supabase)',
      finding: findingSupabase,
      stackHints: { hasVercel: true, hasNextJs: true, hasSupabase: true },
      preconditions: {
        identityCount: 1,
        hasJwtIdentity: true,
        hasCredentialedCorsSignal: false,
        hasObservedParameter: false,
        hasCredentialReference: false,
      },
    },
    {
      name: 'CASO 2: Hallazgo IDOR / BOLA con 2 identidades de prueba (BYOT A y B)',
      finding: findingIdor,
      stackHints: { hasSpa: true },
      preconditions: {
        identityCount: 2,
        hasJwtIdentity: true,
        hasCredentialedCorsSignal: false,
        hasObservedParameter: true,
        hasCredentialReference: false,
      },
    },
    {
      name: 'CASO 3: Inyección SQL confirmada (Error Oracle en parámetro "q")',
      finding: findingSqli,
      stackHints: {},
      preconditions: {
        identityCount: 0,
        hasJwtIdentity: false,
        hasCredentialedCorsSignal: false,
        hasObservedParameter: true,
        hasCredentialReference: false,
      },
    },
  ];

  for (const scenario of scenarios) {
    console.log(`\n----------------------------------------------------------------------`);
    console.log(`📌 ${scenario.name}`);
    console.log(`Objetivo: ${scenario.finding.target}`);
    console.log(`Tipo:     ${scenario.finding.type} | Confianza: ${scenario.finding.confidence * 100}%`);
    console.log(`----------------------------------------------------------------------`);

    const result = recommendationService.recommend({
      assessmentId: LINEAGE.assessmentId,
      scanId: LINEAGE.scanId,
      finding: scenario.finding,
      stackHints: scenario.stackHints,
      preconditions: scenario.preconditions,
      registeredCapabilities: registeredCaps,
      lineage: LINEAGE,
    });

    const recA = result.recommendations.find((r) => r.rank === 'A');
    const recB = result.recommendations.find((r) => r.rank === 'B');

    if (recA) {
      console.log(`\n🔹 OPCIÓN A (Recomendación Principal - Score: ${recA.score}/100):`);
      console.log(`   Herramienta / Capacidad:  ${recA.humanLabel}`);
      console.log(`   Comando Sugerido:         \x1b[32m${recA.commandSummary}\x1b[0m`);
      console.log(`   Flags Exactos (JSON):     ${JSON.stringify(recA.suggestedFlags)}`);
      console.log(`   ¿Listo para 1-Click?:    ${recA.executable ? '✅ SÍ (Precondiciones cumplidas)' : '⏸ NO (' + recA.disabilityReason + ')'}`);
      console.log(`   Justificación:            ${recA.reason}`);
      console.log(`   Por qué se prefiere:      ${recA.whyPreferred}`);
    }

    if (recB) {
      console.log(`\n🔸 OPCIÓN B (Alternativa Secundaria - Score: ${recB.score}/100):`);
      console.log(`   Herramienta / Capacidad:  ${recB.humanLabel}`);
      console.log(`   Comando Sugerido:         \x1b[33m${recB.commandSummary}\x1b[0m`);
      console.log(`   Flags Exactos (JSON):     ${JSON.stringify(recB.suggestedFlags)}`);
      console.log(`   ¿Listo para 1-Click?:    ${recB.executable ? '✅ SÍ' : '⏸ NO (' + recB.disabilityReason + ')'}`);
      console.log(`   Justificación:            ${recB.reason}`);
    }
  }

  console.log('\n======================================================================');
  console.log('   FIN DE LA DEMOSTRACIÓN');
  console.log('======================================================================\n');
}

runDemo().catch((err) => {
  console.error(err);
  process.exit(1);
});
