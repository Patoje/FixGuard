/**
 * Milestone A5 — Attack Execution Service
 *
 * Executes authorized attack-plan steps under 7 mandatory safety gates
 * (exact order, fail-closed, no skipping). Requires WeakSet-branded A4 token.
 *
 * Tools execute. Intelligence decides. Humans authorize.
 */

import type { Finding } from '../core/Evidence.js';
import { nextVerificationState } from '../core/VerificationStateContracts.js';
import { VerificationStateService } from '../core/VerificationStateService.js';
import type { AttackPlan } from '../attack-planning/AttackPlanContracts.js';
import type { AttackPlanRepository } from '../attack-planning/AttackPlanRepository.js';
import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import { ATTACK_AUTHORIZATION_CONTRACT_VERSION } from '../attack-authorization/AttackAuthorizationContracts.js';
import { isRuntimeAuthorizedForBlastRadius } from '../attack-authorization/AttackAuthorizationService.js';
import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';
import type { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import type { PreSpawnDnsResolver } from '../recon/adapters/AdapterPreflightPipeline.js';
import { isInternalOrSsrfTarget } from '../recon/policy/PassiveEgressPolicy.js';
import { validateDnsRebinding } from '../recon/adapters/AdapterPreflightPipeline.js';
import {
  ATTACK_EXECUTION_CONTRACT_VERSION,
  isScopeAllowed,
  type AttackCapabilityIdentityRef,
  type AttackExecutionGateFailureCode,
  type AttackExecutionRecord,
  type AttackExecutionRequest,
  type AttackExecutionResult,
  type AttackExecutionStep,
  type AttackStepExecutionRecord,
} from './AttackExecutionContracts.js';
import type { AttackCapabilityRegistry } from './AttackCapabilityRegistry.js';

function isSafeId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  return /^[a-zA-Z0-9_\-.:]+$/.test(value);
}

function isCapabilityIdentityRef(value: unknown): value is AttackCapabilityIdentityRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const identityId = Reflect.get(value, 'identityId');
  if (typeof identityId !== 'string' || identityId.trim().length === 0) return false;
  if (!Reflect.has(value, 'headers')) return true;
  const headers = Reflect.get(value, 'headers');
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return false;
  for (const hv of Object.values(headers as Record<string, unknown>)) {
    if (typeof hv !== 'string') return false;
  }
  return true;
}

function extractTargetHost(
  planTargetUrl: string | undefined,
  scopeFallbackHost: string | undefined
): string | null {
  if (planTargetUrl && typeof planTargetUrl === 'string') {
    try {
      const u = new URL(planTargetUrl);
      if (u.hostname.length > 0) return u.hostname.toLowerCase();
    } catch {
      // fall through
    }
  }
  if (scopeFallbackHost && scopeFallbackHost.length > 0) return scopeFallbackHost.toLowerCase();
  return null;
}

function resolveTargetUrl(planTargetUrl: string | undefined, host: string): string {
  if (planTargetUrl && typeof planTargetUrl === 'string' && planTargetUrl.length > 0) {
    return planTargetUrl;
  }
  return `https://${host}/`;
}

function deny(
  reasonCode: AttackExecutionGateFailureCode,
  safeMessage: string,
  record?: AttackExecutionRecord
): AttackExecutionResult {
  return {
    status: 'preflight_denied',
    reasonCode,
    safeMessage,
    ...(record ? { record } : {}),
  };
}

/**
 * Structural check that preserves the original object reference (WeakSet brand).
 */
function isAttackAuthorizationToken(token: object): token is AttackAuthorizationToken {
  const contractVersion = Reflect.get(token, 'contractVersion');
  const kind = Reflect.get(token, 'kind');
  const planId = Reflect.get(token, 'planId');
  const assessmentId = Reflect.get(token, 'assessmentId');
  const blastRadiusClass = Reflect.get(token, 'blastRadiusClass');
  const authorizationLevel = Reflect.get(token, 'authorizationLevel');
  const authorizedBy = Reflect.get(token, 'authorizedBy');
  const authorizedAt = Reflect.get(token, 'authorizedAt');

  if (contractVersion !== ATTACK_AUTHORIZATION_CONTRACT_VERSION) return false;
  if (kind !== 'attack_authorization_token') return false;
  if (typeof planId !== 'string' || !isSafeId(planId)) return false;
  if (typeof assessmentId !== 'string' || !isSafeId(assessmentId)) return false;
  if (typeof blastRadiusClass !== 'string') return false;
  if (
    blastRadiusClass !== 'read_public' &&
    blastRadiusClass !== 'read_authenticated' &&
    blastRadiusClass !== 'read_escalated' &&
    blastRadiusClass !== 'sensitive_data_access' &&
    blastRadiusClass !== 'credential_use' &&
    blastRadiusClass !== 'privilege_escalation' &&
    blastRadiusClass !== 'lateral_movement' &&
    blastRadiusClass !== 'state_change_benign' &&
    blastRadiusClass !== 'state_change_impact'
  ) {
    return false;
  }
  if (typeof authorizationLevel !== 'string') return false;
  if (typeof authorizedBy !== 'string' || !isSafeId(authorizedBy)) return false;
  if (typeof authorizedAt !== 'string') return false;
  return true;
}

function isAuthorizedScopeGrant(value: object): value is AuthorizedScopeGrant {
  return (
    Reflect.get(value, 'contractVersion') === 'fixguard-authorized-scope-policy/v0' &&
    Reflect.get(value, 'kind') === 'authorized_scope_grant' &&
    typeof Reflect.get(value, 'grantId') === 'string' &&
    typeof Reflect.get(value, 'scanId') === 'string' &&
    typeof Reflect.get(value, 'boundaries') === 'object' &&
    Reflect.get(value, 'boundaries') !== null
  );
}

function isTargetExecutionCoordinator(value: object): value is TargetExecutionCoordinator {
  return typeof Reflect.get(value, 'isCircuitOpen') === 'function';
}

function isFindingArray(value: unknown): value is Finding[] {
  if (!Array.isArray(value)) return false;
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
    if (typeof Reflect.get(item, 'id') !== 'string') return false;
    if (typeof Reflect.get(item, 'verificationState') !== 'string') return false;
  }
  return true;
}

function isPreSpawnDnsResolver(value: unknown): value is PreSpawnDnsResolver {
  return typeof value === 'function';
}

export interface AttackExecutionServiceDependencies {
  readonly planRepository: AttackPlanRepository;
  readonly capabilityRegistry: AttackCapabilityRegistry;
}

export class AttackExecutionService {
  private readonly planRepository: AttackPlanRepository;
  private readonly capabilityRegistry: AttackCapabilityRegistry;

  constructor(deps: AttackExecutionServiceDependencies) {
    this.planRepository = deps.planRepository;
    this.capabilityRegistry = deps.capabilityRegistry;
  }

  public async execute(request: unknown): Promise<AttackExecutionResult> {
    const parsed = this.parseRequest(request);
    if (parsed.status === 'invalid') {
      return deny(parsed.reasonCode, parsed.safeMessage);
    }
    const req = parsed.request;
    const startedAt = req.executedAt ?? new Date().toISOString();

    const plan = await this.planRepository.getPlan(req.planId);
    if (!plan || plan.assessmentId !== req.assessmentId) {
      return deny('plan_not_found', 'Attack plan does not exist for the given assessment');
    }

    // Token must be the runtime-branded object (WeakSet) — JSON/plain objects fail closed.
    if (
      !isRuntimeAuthorizedForBlastRadius(
        req.token,
        req.token.blastRadiusClass,
        plan.planId,
        plan.assessmentId
      )
    ) {
      return deny('token_not_branded', 'Attack authorization token is missing or not runtime-branded');
    }

    const scopeHost =
      req.scopeGrant.boundaries.allowedHosts?.[0] ??
      (req.scopeGrant.subject.targetKind === 'host' ? req.scopeGrant.subject.host : undefined) ??
      (req.scopeGrant.subject.targetKind === 'domain' ? req.scopeGrant.subject.domain : undefined);

    const targetHost = extractTargetHost(plan.targetUrl, scopeHost);
    if (!targetHost) {
      return deny('target_host_invalid', 'Unable to resolve a safe target host for execution');
    }

    const targetUrl = resolveTargetUrl(plan.targetUrl, targetHost);
    const port = this.capabilityRegistry.get(plan.capability);
    if (!port) {
      return deny(
        'capability_not_registered',
        `Capability "${plan.capability}" is not registered for execution`
      );
    }

    const executionId = `aex_${plan.planId}_${Date.now().toString(36)}`;
    const stepRecords: AttackStepExecutionRecord[] = [];
    let findings: Finding[] = req.findings.map((f) => Object.freeze({ ...f }));

    for (const advisoryStep of plan.steps) {
      const step: AttackExecutionStep = {
        ...advisoryStep,
        blastRadiusClass: req.token.blastRadiusClass,
      };

      // ------------------------------------------------------------------
      // 7 Safety Gates — EXACT ORDER — fail closed, no skipping
      // ------------------------------------------------------------------

      // Gate 1: WeakSet brand + exact blast-radius class
      if (
        !isRuntimeAuthorizedForBlastRadius(
          req.token,
          step.blastRadiusClass,
          plan.planId,
          plan.assessmentId
        )
      ) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_authorization_brand',
          'Safety gate 1 failed: runtime authorization brand / blast-radius class'
        );
      }

      // Gate 2: plan binding
      if (req.token.planId !== plan.planId) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_plan_binding',
          'Safety gate 2 failed: token.planId does not match plan.planId'
        );
      }

      // Gate 3: assessment isolation
      if (req.token.assessmentId !== plan.assessmentId) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_assessment_binding',
          'Safety gate 3 failed: token.assessmentId does not match plan.assessmentId'
        );
      }

      // Gate 4: SSRF egress
      if (isInternalOrSsrfTarget(targetHost)) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_ssrf_egress',
          'Safety gate 4 failed: target host is internal or SSRF-blocked'
        );
      }

      // Gate 5: DNS rebinding
      const dnsCheck = await validateDnsRebinding(targetHost, req.dnsResolver);
      if (!dnsCheck.ok) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_dns_rebinding',
          'Safety gate 5 failed: DNS rebinding / private IP resolution blocked'
        );
      }

      // Gate 6: scope boundary
      if (!isScopeAllowed(targetHost, req.scopeGrant)) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_scope',
          'Safety gate 6 failed: target host is outside authorized scope'
        );
      }

      // Gate 7: circuit breaker
      if (req.coordinator.isCircuitOpen(targetHost)) {
        return this.gateFail(
          executionId,
          plan,
          req,
          startedAt,
          stepRecords,
          findings,
          step,
          targetHost,
          'gate_circuit_open',
          'Safety gate 7 failed: circuit breaker is OPEN for target host'
        );
      }

      // ------------------------------------------------------------------
      // Capability invocation (only after all 7 gates pass)
      // ------------------------------------------------------------------
      const capabilityResult = await port.execute({
        plan,
        step,
        token: req.token,
        targetHost,
        targetUrl,
        scopeGrant: req.scopeGrant,
        findings,
        ...(req.primaryIdentity ? { primaryIdentity: req.primaryIdentity } : {}),
        ...(req.secondaryIdentity ? { secondaryIdentity: req.secondaryIdentity } : {}),
      });

      const completedAt = new Date().toISOString();
      let verificationStateBefore: AttackStepExecutionRecord['verificationStateBefore'];
      let verificationStateAfter: AttackStepExecutionRecord['verificationStateAfter'];

      const sourceFindingId = plan.sourceFindingIds[0];
      const findingIdx = sourceFindingId
        ? findings.findIndex((f) => f.id === sourceFindingId)
        : -1;

      if (capabilityResult.outcome === 'succeeded' && findingIdx >= 0) {
        const finding = findings[findingIdx]!;
        verificationStateBefore = finding.verificationState;
        const nextState = nextVerificationState(finding.verificationState);
        if (nextState !== null) {
          const advanced = VerificationStateService.advanceState(finding, nextState, {
            evidenceId: capabilityResult.evidenceId ?? `ev_a5_${step.stepId}`,
            reasonCode: 'attack_execution_step_succeeded',
          });
          findings = [
            ...findings.slice(0, findingIdx),
            advanced.updatedFinding,
            ...findings.slice(findingIdx + 1),
          ];
          verificationStateAfter = advanced.updatedFinding.verificationState;
        } else {
          verificationStateAfter = finding.verificationState;
        }
      } else if (
        (capabilityResult.outcome === 'refuted' || capabilityResult.outcome === 'failed') &&
        findingIdx >= 0
      ) {
        const finding = findings[findingIdx]!;
        verificationStateBefore = finding.verificationState;
        // Record REFUTED via transition reason — VerificationState taxonomy has no REFUTED label.
        const refutedResult = VerificationStateService.refuteState(
          finding,
          finding.verificationState,
          {
            evidenceId: capabilityResult.evidenceId ?? `ev_a5_refute_${step.stepId}`,
            reasonCode: 'REFUTED',
          }
        );
        findings = [
          ...findings.slice(0, findingIdx),
          refutedResult.updatedFinding,
          ...findings.slice(findingIdx + 1),
        ];
        verificationStateAfter = refutedResult.updatedFinding.verificationState;
      }

      stepRecords.push({
        stepId: step.stepId,
        ordinal: step.ordinal,
        capability: plan.capability,
        blastRadiusClass: step.blastRadiusClass,
        targetHost,
        outcome: capabilityResult.outcome,
        reasonCode: capabilityResult.reasonCode,
        safeMessage: capabilityResult.safeMessage,
        gatesPassed: true,
        ...(verificationStateBefore ? { verificationStateBefore } : {}),
        ...(verificationStateAfter ? { verificationStateAfter } : {}),
        ...(capabilityResult.evidenceId ? { evidenceId: capabilityResult.evidenceId } : {}),
        completedAt,
      });

      if (capabilityResult.outcome === 'capability_not_implemented') {
        const completedAtFail = new Date().toISOString();
        return {
          status: 'failed',
          reasonCode: 'capability_not_registered',
          safeMessage: capabilityResult.safeMessage,
          record: this.buildRecord(
            executionId,
            plan,
            req,
            startedAt,
            completedAtFail,
            'failed',
            stepRecords,
            findings
          ),
        };
      }
    }

    const completedAt = new Date().toISOString();
    return {
      status: 'completed',
      reasonCode: 'attack_execution_completed',
      record: this.buildRecord(
        executionId,
        plan,
        req,
        startedAt,
        completedAt,
        'completed',
        stepRecords,
        findings
      ),
    };
  }

  private gateFail(
    executionId: string,
    plan: AttackPlan,
    req: AttackExecutionRequest,
    startedAt: string,
    priorSteps: readonly AttackStepExecutionRecord[],
    findings: readonly Finding[],
    step: AttackExecutionStep,
    targetHost: string,
    reasonCode: AttackExecutionGateFailureCode,
    safeMessage: string
  ): AttackExecutionResult {
    const completedAt = new Date().toISOString();
    const stepRecord: AttackStepExecutionRecord = {
      stepId: step.stepId,
      ordinal: step.ordinal,
      capability: plan.capability,
      blastRadiusClass: step.blastRadiusClass,
      targetHost,
      outcome: 'preflight_denied',
      reasonCode,
      safeMessage,
      gatesPassed: reasonCode,
      completedAt,
    };
    const record = this.buildRecord(
      executionId,
      plan,
      req,
      startedAt,
      completedAt,
      'preflight_denied',
      [...priorSteps, stepRecord],
      findings
    );
    return deny(reasonCode, safeMessage, record);
  }

  private buildRecord(
    executionId: string,
    plan: AttackPlan,
    req: AttackExecutionRequest,
    startedAt: string,
    completedAt: string,
    status: AttackExecutionRecord['status'],
    stepRecords: readonly AttackStepExecutionRecord[],
    findings: readonly Finding[]
  ): AttackExecutionRecord {
    return {
      contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
      kind: 'attack_execution_record',
      executionId,
      planId: plan.planId,
      assessmentId: plan.assessmentId,
      capability: plan.capability,
      operatorId: req.operatorId,
      startedAt,
      completedAt,
      status,
      stepRecords,
      updatedFindings: findings,
    };
  }

  private parseRequest(
    request: unknown
  ):
    | { status: 'ok'; request: AttackExecutionRequest }
    | { status: 'invalid'; reasonCode: AttackExecutionGateFailureCode; safeMessage: string } {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'Execution request must be a plain object',
      };
    }
    const req: Record<string, unknown> = {};
    for (const key of Object.keys(request)) {
      req[key] = Reflect.get(request, key);
    }

    const allowedKeys = [
      'contractVersion',
      'kind',
      'planId',
      'assessmentId',
      'token',
      'scopeGrant',
      'coordinator',
      'dnsResolver',
      'findings',
      'operatorId',
      'executedAt',
      'primaryIdentity',
      'secondaryIdentity',
    ];
    for (const k of Object.keys(req)) {
      if (!allowedKeys.includes(k)) {
        return {
          status: 'invalid',
          reasonCode: 'request_invalid',
          safeMessage: 'Execution request contains unknown or forbidden field',
        };
      }
    }

    if (req.contractVersion !== ATTACK_EXECUTION_CONTRACT_VERSION) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid contractVersion',
      };
    }
    if (req.kind !== 'attack_execution_request') {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid kind',
      };
    }
    if (!isSafeId(req.planId) || !isSafeId(req.assessmentId) || !isSafeId(req.operatorId)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'planId, assessmentId, or operatorId is invalid',
      };
    }
    if (!req.token || typeof req.token !== 'object' || Array.isArray(req.token)) {
      return {
        status: 'invalid',
        reasonCode: 'token_missing',
        safeMessage: 'Runtime attack authorization token is required',
      };
    }
    if (!isAttackAuthorizationToken(req.token)) {
      return {
        status: 'invalid',
        reasonCode: 'token_missing',
        safeMessage: 'Attack authorization token shape is invalid',
      };
    }
    if (!req.scopeGrant || typeof req.scopeGrant !== 'object' || Array.isArray(req.scopeGrant)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'scopeGrant is required',
      };
    }
    if (!isAuthorizedScopeGrant(req.scopeGrant)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'scopeGrant shape is invalid',
      };
    }
    if (!req.coordinator || typeof req.coordinator !== 'object' || Array.isArray(req.coordinator)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'coordinator is required',
      };
    }
    if (!isTargetExecutionCoordinator(req.coordinator)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'coordinator must expose isCircuitOpen',
      };
    }
    if (!isPreSpawnDnsResolver(req.dnsResolver)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'dnsResolver is required',
      };
    }
    if (!isFindingArray(req.findings)) {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'findings must be an array of Finding objects',
      };
    }

    let primaryIdentity: AttackCapabilityIdentityRef | undefined;
    if (req.primaryIdentity !== undefined) {
      if (!isCapabilityIdentityRef(req.primaryIdentity)) {
        return {
          status: 'invalid',
          reasonCode: 'request_invalid',
          safeMessage: 'primaryIdentity shape is invalid',
        };
      }
      primaryIdentity = req.primaryIdentity;
    }

    let secondaryIdentity: AttackCapabilityIdentityRef | undefined;
    if (req.secondaryIdentity !== undefined) {
      if (!isCapabilityIdentityRef(req.secondaryIdentity)) {
        return {
          status: 'invalid',
          reasonCode: 'request_invalid',
          safeMessage: 'secondaryIdentity shape is invalid',
        };
      }
      secondaryIdentity = req.secondaryIdentity;
    }

    // Narrowed ids — already validated by isSafeId above.
    const planId = req.planId;
    const assessmentId = req.assessmentId;
    const operatorId = req.operatorId;
    if (typeof planId !== 'string' || typeof assessmentId !== 'string' || typeof operatorId !== 'string') {
      return {
        status: 'invalid',
        reasonCode: 'request_invalid',
        safeMessage: 'planId, assessmentId, or operatorId is invalid',
      };
    }

    const built: AttackExecutionRequest = {
      contractVersion: ATTACK_EXECUTION_CONTRACT_VERSION,
      kind: 'attack_execution_request',
      planId,
      assessmentId,
      token: req.token,
      scopeGrant: req.scopeGrant,
      coordinator: req.coordinator,
      dnsResolver: req.dnsResolver,
      findings: req.findings,
      operatorId,
      ...(typeof req.executedAt === 'string' ? { executedAt: req.executedAt } : {}),
      ...(primaryIdentity ? { primaryIdentity } : {}),
      ...(secondaryIdentity ? { secondaryIdentity } : {}),
    };

    return { status: 'ok', request: built };
  }
}
