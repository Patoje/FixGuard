/**
 * Milestone A3 — AttackPlanGeneratorService
 *
 * Pure advisory plan generation from Findings + identity context.
 * Zero network calls. Plans with unsatisfied prerequisites are retained
 * with status `prerequisite_missing` (never discarded, never thrown).
 *
 * Finding vocabulary mapping (existing closed types — no parallel taxonomy):
 * 1. BROKEN_ACCESS_CONTROL (+ broken_access_control_metadata) → idor_read_differential
 * 2. CORS_MISCONFIGURATION credentialed OR credentialed_cors_metadata → cors_chain_exploit
 * 3. BROKEN_AUTHENTICATION + auth_bypass_metadata → auth_bypass_probe
 * 4. BROKEN_AUTHENTICATION + jwt_algorithm_confusion_metadata → jwt_alg_none_probe
 * 5. INFORMATION_DISCLOSURE + sql_error_oracle_metadata → sql_error_oracle_probe
 * 6. INPUT_VALIDATION_FLAW reflection (+ input_validation_flaw_metadata) → parameter_reflection_probe
 * 7. parameter_integrity_metadata (LFI/path traversal candidates) → lfi_path_traversal
 * 8. sql_error_oracle_metadata @ suspected_vulnerability → sql_oracle_advancement
 */

import { createHash } from 'node:crypto';
import type { Finding, FindingMetadata } from '../core/Evidence.js';
import {
  ATTACK_PLANNING_CONTRACT_VERSION,
  type AttackCapabilityKind,
  type AttackPlan,
  type AttackPlanGeneratorInput,
  type AttackPlanGeneratorResult,
  type AttackPlanIdentityContext,
  type AttackPlanStatus,
  type AttackPrerequisite,
  type AttackStep,
  type AttackPlanScopeClass,
  type CapabilityGained,
} from './AttackPlanContracts.js';

function sha256Short(content: string): string {
  return createHash('sha256').update(content).digest('hex').slice(0, 16);
}

function stablePlanId(assessmentId: string, capability: AttackCapabilityKind, findingId: string): string {
  return `apl_${sha256Short([assessmentId, capability, findingId].join('|'))}`;
}

function allPrerequisitesSatisfied(prereqs: readonly AttackPrerequisite[]): boolean {
  return prereqs.every((p) => p.satisfied);
}

function resolveStatus(prereqs: readonly AttackPrerequisite[]): AttackPlanStatus {
  return allPrerequisitesSatisfied(prereqs) ? 'ready_for_authorization' : 'prerequisite_missing';
}

function stepStatus(planStatus: AttackPlanStatus): AttackStep['status'] {
  return planStatus === 'ready_for_authorization' ? 'ready' : 'blocked';
}

function isCredentialedCors(finding: Finding): boolean {
  const meta = finding.metadata;
  if (meta.kind === 'credentialed_cors_metadata') {
    return meta.allowCredentialsHeader === true;
  }
  if (
    (finding.type === 'CORS_MISCONFIGURATION' || meta.kind === 'security_misconfiguration_metadata') &&
    meta.kind === 'security_misconfiguration_metadata' &&
    meta.category === 'CORS_MISCONFIGURATION'
  ) {
    return meta.allowCredentials === true;
  }
  return false;
}

function isAuthBypass(finding: Finding): boolean {
  return finding.type === 'BROKEN_AUTHENTICATION' && finding.metadata.kind === 'auth_bypass_metadata';
}

function isJwtConfusion(finding: Finding): boolean {
  return (
    finding.type === 'BROKEN_AUTHENTICATION' && finding.metadata.kind === 'jwt_algorithm_confusion_metadata'
  );
}

function isSqlErrorOracle(finding: Finding): boolean {
  return finding.type === 'INFORMATION_DISCLOSURE' && finding.metadata.kind === 'sql_error_oracle_metadata';
}

function isParameterReflection(finding: Finding): boolean {
  if (finding.type !== 'INPUT_VALIDATION_FLAW' && finding.type !== 'PARAMETER_REFLECTION') {
    return false;
  }
  const meta = finding.metadata;
  if (meta.kind !== 'input_validation_flaw_metadata') {
    return false;
  }
  return (
    meta.category === 'PARAMETER_REFLECTION' ||
    meta.category === 'INPUT_VALIDATION_FLAW' ||
    typeof meta.parameterName === 'string'
  );
}

/** Parameter integrity / LFI boundary findings (P5-6) → native LFI advancement plan. */
function isParameterIntegrity(finding: Finding): boolean {
  return finding.metadata.kind === 'parameter_integrity_metadata';
}

/**
 * SQL oracle advancement applies when an oracle finding is already at
 * suspected_vulnerability (one ordered step away from validated_vulnerability).
 * observed_anomaly findings keep the A3 sql_error_oracle_probe plan only.
 */
function isSqlOracleAdvancementCandidate(finding: Finding): boolean {
  return isSqlErrorOracle(finding) && finding.verificationState === 'suspected_vulnerability';
}

function targetFromFinding(finding: Finding): string | undefined {
  const meta = finding.metadata as FindingMetadata & { endpointUrl?: string };
  if (typeof meta.endpointUrl === 'string' && meta.endpointUrl.length > 0) {
    return meta.endpointUrl;
  }
  return finding.target;
}

function parameterFromFinding(finding: Finding): string | undefined {
  const meta = finding.metadata;
  if (meta.kind === 'sql_error_oracle_metadata' && typeof meta.parameterName === 'string') {
    return meta.parameterName;
  }
  if (meta.kind === 'input_validation_flaw_metadata' && typeof meta.parameterName === 'string') {
    return meta.parameterName;
  }
  if (meta.kind === 'parameter_integrity_metadata' && typeof meta.parameterName === 'string') {
    return meta.parameterName;
  }
  if (meta.kind === 'broken_access_control_metadata' && typeof meta.resourceParamName === 'string') {
    return meta.resourceParamName;
  }
  return undefined;
}

function buildPlan(args: {
  assessmentId: string;
  scanId: string;
  capability: AttackCapabilityKind;
  title: string;
  reasoning: string;
  blastRadius: AttackPlanScopeClass;
  capabilityGained: CapabilityGained;
  finding: Finding;
  prerequisites: readonly AttackPrerequisite[];
  steps: readonly Omit<AttackStep, 'status'>[];
  lineage: AttackPlanGeneratorInput['lineage'];
  createdAt: string;
  targetUrl?: string;
  parameterName?: string;
}): AttackPlan {
  const status = resolveStatus(args.prerequisites);
  const steps: AttackStep[] = args.steps.map((s) => ({
    ...s,
    status: stepStatus(status),
  }));

  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan',
    planId: stablePlanId(args.assessmentId, args.capability, args.finding.id),
    assessmentId: args.assessmentId,
    scanId: args.scanId,
    capability: args.capability,
    title: args.title,
    reasoning: args.reasoning,
    status,
    blastRadius: args.blastRadius,
    capabilityGained: args.capabilityGained,
    sourceFindingIds: [args.finding.id],
    sourceFindingTypes: [args.finding.type],
    prerequisites: [...args.prerequisites],
    steps,
    ...(args.targetUrl ? { targetUrl: args.targetUrl } : {}),
    ...(args.parameterName ? { parameterName: args.parameterName } : {}),
    lineage: { ...args.lineage },
    createdAt: args.createdAt,
    executable: false,
  };
}

function identityCountPrereq(identities: readonly AttackPlanIdentityContext[]): AttackPrerequisite {
  const count = identities.length;
  return {
    kind: 'identity_count_at_least_2',
    description: 'Requires at least two distinct operator-provided identities for differential comparison',
    satisfied: count >= 2,
    detail: `identity_count=${count}`,
  };
}

function identityPresentPrereq(identities: readonly AttackPlanIdentityContext[]): AttackPrerequisite {
  return {
    kind: 'identity_present',
    description: 'Requires at least one authenticated identity context',
    satisfied: identities.length >= 1,
    detail: `identity_count=${identities.length}`,
  };
}

function identityWithJwtPrereq(identities: readonly AttackPlanIdentityContext[]): AttackPrerequisite {
  const withJwt = identities.filter((i) => i.hasJwt);
  return {
    kind: 'identity_with_jwt',
    description: 'Requires an identity that carries a JWT-like bearer or cookie token',
    satisfied: withJwt.length >= 1,
    detail: `jwt_identity_count=${withJwt.length}`,
  };
}

function parameterPresentPrereq(parameterName: string | undefined): AttackPrerequisite {
  const present = typeof parameterName === 'string' && parameterName.trim().length > 0;
  return {
    kind: 'parameter_present',
    description: 'Requires an observed injectable/reflective parameter name',
    satisfied: present,
    detail: present ? `parameter=${parameterName}` : 'parameter=missing',
  };
}

function credentialedCorsPrereq(finding: Finding): AttackPrerequisite {
  return {
    kind: 'credentialed_cors',
    description: 'Requires credentialed CORS misconfiguration evidence (ACAO + credentials)',
    satisfied: isCredentialedCors(finding),
  };
}

function findingPresentPrereq(finding: Finding, expectedType: string): AttackPrerequisite {
  return {
    kind: 'finding_present',
    description: `Requires a finding of type ${expectedType}`,
    satisfied: finding.type === expectedType || finding.metadata !== undefined,
    detail: `findingId=${finding.id};type=${finding.type}`,
  };
}

/**
 * Infer whether an identity context carries a JWT-like credential (analytical only).
 */
export function identityHasJwtHeuristic(identity: {
  readonly injectHeaders?: Readonly<Record<string, string>>;
  readonly injectCookies?: Readonly<Record<string, string>>;
}): boolean {
  const headers = identity.injectHeaders ?? {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'authorization' && /\bbearer\s+eyj/i.test(value)) {
      return true;
    }
    if (lower.includes('jwt') && value.trim().startsWith('eyJ')) {
      return true;
    }
  }
  const cookies = identity.injectCookies ?? {};
  for (const [key, value] of Object.entries(cookies)) {
    if (key.toLowerCase().includes('jwt') || key.toLowerCase().includes('token')) {
      if (value.trim().startsWith('eyJ')) {
        return true;
      }
    }
  }
  return false;
}

export function generateAttackPlans(input: AttackPlanGeneratorInput): AttackPlanGeneratorResult {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const plans: AttackPlan[] = [];
  const identities = input.identities;

  for (const finding of input.findings) {
    // Rule 1: BROKEN_ACCESS_CONTROL + 2 identities → idor_read_differential
    if (finding.type === 'BROKEN_ACCESS_CONTROL') {
      const prereqs = [
        findingPresentPrereq(finding, 'BROKEN_ACCESS_CONTROL'),
        identityCountPrereq(identities),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'idor_read_differential',
          title: 'IDOR differential read validation',
          reasoning:
            'Observed broken access control evidence. Recommend dual-identity differential read validation after human authorization.',
          blastRadius: 'single_resource',
          capabilityGained: 'read_escalated',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_idor_step_1`,
              ordinal: 1,
              title: 'Authorize dual-identity differential read',
              description:
                'Human-authorized comparison of resource reads across two identities. Advisory only until authorized.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
          parameterName: parameterFromFinding(finding),
        })
      );
    }

    // Rule 2: CORS_MISCONFIGURATION (credentialed) + identity → cors_chain_exploit
    if (isCredentialedCors(finding) || finding.type === 'CORS_MISCONFIGURATION') {
      const prereqs = [
        findingPresentPrereq(finding, 'CORS_MISCONFIGURATION'),
        credentialedCorsPrereq(finding),
        identityPresentPrereq(identities),
      ];
      // Only emit a CORS plan when finding is CORS-typed or credentialed_cors metadata
      if (finding.type === 'CORS_MISCONFIGURATION' || finding.metadata.kind === 'credentialed_cors_metadata') {
        plans.push(
          buildPlan({
            assessmentId: input.assessmentId,
            scanId: input.scanId,
            capability: 'cors_chain_exploit',
            title: 'Credentialed CORS chain validation',
            reasoning:
              'Observed credentialed CORS reflection. Recommend cross-origin chain validation after human authorization.',
            blastRadius: 'cross_origin_third_party',
            capabilityGained: 'read_escalated',
            finding,
            prerequisites: prereqs,
            steps: [
              {
                stepId: `${finding.id}_cors_step_1`,
                ordinal: 1,
                title: 'Authorize credentialed CORS chain probe',
                description:
                  'Human-authorized cross-origin credentialed request validation. Advisory plan only.',
                requiredPermissions: ['active_http_get', 'cross_origin_probe'],
              },
            ],
            lineage: input.lineage,
            createdAt: generatedAt,
            targetUrl: targetFromFinding(finding),
          })
        );
      }
    }

    // Rule 3: BROKEN_AUTHENTICATION (bypass) + identity → auth_bypass_probe
    if (isAuthBypass(finding)) {
      const prereqs = [
        findingPresentPrereq(finding, 'BROKEN_AUTHENTICATION'),
        identityPresentPrereq(identities),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'auth_bypass_probe',
          title: 'Authentication bypass validation',
          reasoning:
            'Observed authentication bypass evidence. Recommend controlled bypass re-validation after human authorization.',
          blastRadius: 'single_endpoint',
          capabilityGained: 'read_authenticated',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_auth_bypass_step_1`,
              ordinal: 1,
              title: 'Authorize auth bypass probe',
              description: 'Human-authorized comparison of authenticated vs stripped-auth responses.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
        })
      );
    }

    // Rule 4: BROKEN_AUTHENTICATION (JWT) + identity with JWT → jwt_alg_none_probe
    if (isJwtConfusion(finding)) {
      const prereqs = [
        findingPresentPrereq(finding, 'BROKEN_AUTHENTICATION'),
        identityWithJwtPrereq(identities),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'jwt_alg_none_probe',
          title: 'JWT alg=none confusion validation',
          reasoning:
            'Observed JWT algorithm confusion evidence. Recommend alg=none defensive re-validation after human authorization.',
          blastRadius: 'user_scoped',
          capabilityGained: 'read_escalated',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_jwt_step_1`,
              ordinal: 1,
              title: 'Authorize JWT alg=none probe',
              description: 'Human-authorized JWT header algorithm confusion validation. Advisory only.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
        })
      );
    }

    // Rule 5: INFORMATION_DISCLOSURE (SQL error) + parameter → sql_error_oracle_probe
    if (isSqlErrorOracle(finding)) {
      const parameterName = parameterFromFinding(finding);
      const prereqs = [
        findingPresentPrereq(finding, 'INFORMATION_DISCLOSURE'),
        parameterPresentPrereq(parameterName),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'sql_error_oracle_probe',
          title: 'SQL error oracle validation',
          reasoning:
            'Observed SQL error disclosure on a parameter. Recommend controlled oracle validation after human authorization.',
          blastRadius: 'single_parameter',
          capabilityGained: 'read_authenticated',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_sql_step_1`,
              ordinal: 1,
              title: 'Authorize SQL error oracle probe',
              description: 'Human-authorized inert probe confirming SQL error oracle behavior.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
          parameterName,
        })
      );
    }

    // Rule 6: INPUT_VALIDATION_FLAW (reflection) + parameter → parameter_reflection_probe
    if (isParameterReflection(finding)) {
      const parameterName = parameterFromFinding(finding);
      const prereqs = [
        findingPresentPrereq(finding, 'INPUT_VALIDATION_FLAW'),
        parameterPresentPrereq(parameterName),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'parameter_reflection_probe',
          title: 'Parameter reflection validation',
          reasoning:
            'Observed parameter reflection. Recommend active reflection re-validation after human authorization.',
          blastRadius: 'single_parameter',
          capabilityGained: 'active_validation',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_reflect_step_1`,
              ordinal: 1,
              title: 'Authorize parameter reflection probe',
              description: 'Human-authorized canary reflection validation on the observed parameter.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
          parameterName,
        })
      );
    }

    // Rule 7 (A7): parameter_integrity_metadata → lfi_path_traversal
    // Authorization blast-radius intent: read_escalated (HITL plan approval).
    if (isParameterIntegrity(finding)) {
      const parameterName = parameterFromFinding(finding);
      const prereqs = [
        findingPresentPrereq(finding, finding.type),
        parameterPresentPrereq(parameterName),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'lfi_path_traversal',
          title: 'LFI path traversal validation',
          reasoning:
            'Observed parameter integrity / path-boundary anomaly. Recommend allowlisted LFI canary re-validation after human authorization.',
          blastRadius: 'single_parameter',
          capabilityGained: 'read_escalated',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_lfi_step_1`,
              ordinal: 1,
              title: 'Authorize LFI path traversal probe',
              description:
                'Human-authorized allowlisted traversal canary probe against a resource/file parameter. Advisory only.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
          parameterName,
        })
      );
    }

    // Rule 8 (A7): sql_error_oracle @ suspected_vulnerability → sql_oracle_advancement
    // Authorization blast-radius intent: read_authenticated (assessment authorization).
    // capabilityGained active_validation describes plan scope intent, not a BlastRadiusClass.
    if (isSqlOracleAdvancementCandidate(finding)) {
      const parameterName = parameterFromFinding(finding);
      const prereqs = [
        findingPresentPrereq(finding, 'INFORMATION_DISCLOSURE'),
        parameterPresentPrereq(parameterName),
      ];
      plans.push(
        buildPlan({
          assessmentId: input.assessmentId,
          scanId: input.scanId,
          capability: 'sql_oracle_advancement',
          title: 'SQL error oracle advancement',
          reasoning:
            'Suspected SQL error oracle. Recommend error-based re-probe (no blind/sleep, no data dump) to advance verification state after human authorization.',
          blastRadius: 'single_parameter',
          capabilityGained: 'active_validation',
          finding,
          prerequisites: prereqs,
          steps: [
            {
              stepId: `${finding.id}_sql_adv_step_1`,
              ordinal: 1,
              title: 'Authorize SQL oracle advancement probe',
              description:
                'Human-authorized error-provoking re-probe to advance suspected_vulnerability → validated_vulnerability.',
              requiredPermissions: ['active_http_get'],
            },
          ],
          lineage: input.lineage,
          createdAt: generatedAt,
          targetUrl: targetFromFinding(finding),
          parameterName,
        })
      );
    }
  }

  plans.sort((a, b) => a.planId.localeCompare(b.planId));

  return {
    contractVersion: ATTACK_PLANNING_CONTRACT_VERSION,
    kind: 'attack_plan_generator_result',
    assessmentId: input.assessmentId,
    scanId: input.scanId,
    plans,
    generatedAt,
    lineage: { ...input.lineage },
  };
}

export class AttackPlanGeneratorService {
  public generate(input: AttackPlanGeneratorInput): AttackPlanGeneratorResult {
    return generateAttackPlans(input);
  }
}
