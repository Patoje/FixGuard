/**
 * Etapa 2 · F1 — ActiveInvestigationRuntimeService
 *
 * Tracks investigation runs with:
 * - execution state / working memory
 * - request budget + investigation-level timeout
 * - kill-switch / cancel
 * - InvestigationAuthorizationBundle binding existing WeakSet auth brands
 * - TargetExecutionCoordinator ceiling wiring from InvestigationBudget
 *
 * Does NOT execute AttackPlans. Gate-only — humans authorize execute separately.
 */

import type { AttackAuthorizationToken } from '../attack-authorization/AttackAuthorizationContracts.js';
import {
  ATTACK_AUTHORIZATION_CONTRACT_VERSION,
  isAuthorizableBlastRadiusClass,
} from '../attack-authorization/AttackAuthorizationContracts.js';
import { isRuntimeAuthorizedForBlastRadius } from '../attack-authorization/AttackAuthorizationService.js';
import type { VerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionContracts.js';
import { isRuntimeEstablishedVerifiedAuthorizationDecision } from '../authorization/VerifiedAuthorizationDecisionService.js';
import { TargetExecutionCoordinator } from '../runtime/TargetExecutionCoordinator.js';
import {
  ACTIVE_INVESTIGATION_CONTRACT_VERSION,
  DEFAULT_INVESTIGATION_BUDGET,
  type ActiveInvestigationLineage,
  type ActiveInvestigationSnapshot,
  type ActiveInvestigationStatus,
  type ActiveInvestigationWorkingMemory,
  type BindAttackAuthorizationRequest,
  type BindAttackAuthorizationResult,
  type BindCoordinatorCeilingsRequest,
  type CancelActiveInvestigationRequest,
  type CancelActiveInvestigationResult,
  type GateAuthorizedStepRequest,
  type GateAuthorizedStepResult,
  type InvestigationAuthorizationBundle,
  type InvestigationBudget,
  type InvestigationBudgetConsumption,
  type RecordInvestigationStepRequest,
  type RecordInvestigationStepResult,
  type StartActiveInvestigationRequest,
  type StartActiveInvestigationResult,
} from './ActiveInvestigationContracts.js';

const BUNDLE_TO_STRING_TAG = 'InvestigationAuthorizationBundle';

/** Module-private brand — only objects sealed in this module are authorized. */
const _authorizationBundleBrand = new WeakSet<object>();

interface MutableWorkingMemory {
  confirmedFactIds: string[];
  openHypothesisRefs: string[];
  executedStepIds: string[];
}

interface InternalInvestigation {
  readonly investigationId: string;
  readonly lineage: ActiveInvestigationLineage;
  readonly budget: InvestigationBudget;
  status: ActiveInvestigationStatus;
  cancelRequested: boolean;
  killSwitchEngaged: boolean;
  denialReasonCode?: string;
  completedAt?: string;
  consumption: {
    requestsConsumed: number;
    stepsRecorded: number;
    startedAt: string;
    lastActivityAt: string;
  };
  workingMemory: MutableWorkingMemory;
  authorizationBundle: InvestigationAuthorizationBundle;
  verifiedAuthorizationDecision: VerifiedAuthorizationDecision;
  attackAuthorizationToken: AttackAuthorizationToken | undefined;
  activeStepCount: number;
}

function isSafeId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  return /^[a-zA-Z0-9_\-.:]+$/.test(value);
}

function isSafeIsoTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const d = Date.parse(value);
  return !Number.isNaN(d);
}

function freezeBudget(budget: InvestigationBudget): InvestigationBudget {
  return Object.freeze({
    maxRequests: budget.maxRequests,
    maxDurationMs: budget.maxDurationMs,
    ...(budget.maxConcurrentSteps !== undefined
      ? { maxConcurrentSteps: budget.maxConcurrentSteps }
      : {}),
    ...(budget.requestsPerSecondCeiling !== undefined
      ? { requestsPerSecondCeiling: budget.requestsPerSecondCeiling }
      : {}),
    ...(budget.maxConcurrencyCeiling !== undefined
      ? { maxConcurrencyCeiling: budget.maxConcurrencyCeiling }
      : {}),
  });
}

function parseBudget(raw: unknown): InvestigationBudget | null {
  if (raw === undefined || raw === null) {
    return freezeBudget(DEFAULT_INVESTIGATION_BUDGET);
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const maxRequests = Reflect.get(raw, 'maxRequests');
  const maxDurationMs = Reflect.get(raw, 'maxDurationMs');
  if (typeof maxRequests !== 'number' || !Number.isInteger(maxRequests) || maxRequests < 1) {
    return null;
  }
  if (typeof maxDurationMs !== 'number' || !Number.isInteger(maxDurationMs) || maxDurationMs < 1) {
    return null;
  }
  const maxConcurrentSteps = Reflect.get(raw, 'maxConcurrentSteps');
  if (
    maxConcurrentSteps !== undefined &&
    (typeof maxConcurrentSteps !== 'number' ||
      !Number.isInteger(maxConcurrentSteps) ||
      maxConcurrentSteps < 1)
  ) {
    return null;
  }
  const requestsPerSecondCeiling = Reflect.get(raw, 'requestsPerSecondCeiling');
  if (
    requestsPerSecondCeiling !== undefined &&
    (typeof requestsPerSecondCeiling !== 'number' ||
      !Number.isFinite(requestsPerSecondCeiling) ||
      requestsPerSecondCeiling <= 0)
  ) {
    return null;
  }
  const maxConcurrencyCeiling = Reflect.get(raw, 'maxConcurrencyCeiling');
  if (
    maxConcurrencyCeiling !== undefined &&
    (typeof maxConcurrencyCeiling !== 'number' ||
      !Number.isInteger(maxConcurrencyCeiling) ||
      maxConcurrencyCeiling < 1)
  ) {
    return null;
  }
  return freezeBudget({
    maxRequests,
    maxDurationMs,
    ...(typeof maxConcurrentSteps === 'number' ? { maxConcurrentSteps } : {}),
    ...(typeof requestsPerSecondCeiling === 'number' ? { requestsPerSecondCeiling } : {}),
    ...(typeof maxConcurrencyCeiling === 'number' ? { maxConcurrencyCeiling } : {}),
  });
}

function parseLineage(raw: unknown): ActiveInvestigationLineage | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const assessmentId = Reflect.get(raw, 'assessmentId');
  const scanId = Reflect.get(raw, 'scanId');
  const authorizationGrantId = Reflect.get(raw, 'authorizationGrantId');
  const authorizationDecisionId = Reflect.get(raw, 'authorizationDecisionId');
  const actorId = Reflect.get(raw, 'actorId');
  if (!isSafeId(assessmentId)) return null;
  if (!isSafeId(scanId)) return null;
  if (!isSafeId(authorizationGrantId)) return null;
  if (!isSafeId(authorizationDecisionId)) return null;
  if (!isSafeId(actorId)) return null;
  return Object.freeze({
    assessmentId,
    scanId,
    authorizationGrantId,
    authorizationDecisionId,
    actorId,
  });
}

function isStructuralAttackToken(value: object): value is AttackAuthorizationToken {
  const contractVersion = Reflect.get(value, 'contractVersion');
  const kind = Reflect.get(value, 'kind');
  const planId = Reflect.get(value, 'planId');
  const assessmentId = Reflect.get(value, 'assessmentId');
  const blastRadiusClass = Reflect.get(value, 'blastRadiusClass');
  const authorizedBy = Reflect.get(value, 'authorizedBy');
  const authorizedAt = Reflect.get(value, 'authorizedAt');
  if (contractVersion !== ATTACK_AUTHORIZATION_CONTRACT_VERSION) return false;
  if (kind !== 'attack_authorization_token') return false;
  if (!isSafeId(planId) || !isSafeId(assessmentId) || !isSafeId(authorizedBy)) return false;
  if (!isSafeIsoTimestamp(authorizedAt)) return false;
  if (!isAuthorizableBlastRadiusClass(blastRadiusClass)) return false;
  return true;
}

function isRuntimeAttackToken(value: unknown): value is AttackAuthorizationToken {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  if (!isStructuralAttackToken(value)) return false;
  return isRuntimeAuthorizedForBlastRadius(
    value,
    value.blastRadiusClass,
    value.planId,
    value.assessmentId
  );
}

function freezeWorkingMemory(memory: MutableWorkingMemory): ActiveInvestigationWorkingMemory {
  return Object.freeze({
    confirmedFactIds: Object.freeze([...memory.confirmedFactIds]),
    openHypothesisRefs: Object.freeze([...memory.openHypothesisRefs]),
    executedStepIds: Object.freeze([...memory.executedStepIds]),
  });
}

function freezeConsumption(
  consumption: InternalInvestigation['consumption']
): InvestigationBudgetConsumption {
  return Object.freeze({
    requestsConsumed: consumption.requestsConsumed,
    stepsRecorded: consumption.stepsRecorded,
    startedAt: consumption.startedAt,
    lastActivityAt: consumption.lastActivityAt,
  });
}

function toSnapshot(inv: InternalInvestigation): ActiveInvestigationSnapshot {
  return Object.freeze({
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'active_investigation_snapshot' as const,
    investigationId: inv.investigationId,
    status: inv.status,
    lineage: inv.lineage,
    budget: inv.budget,
    consumption: freezeConsumption(inv.consumption),
    workingMemory: freezeWorkingMemory(inv.workingMemory),
    cancelRequested: inv.cancelRequested,
    killSwitchEngaged: inv.killSwitchEngaged,
    ...(inv.denialReasonCode ? { denialReasonCode: inv.denialReasonCode } : {}),
    ...(inv.completedAt ? { completedAt: inv.completedAt } : {}),
  });
}

function sealAuthorizationBundle(args: {
  readonly investigationId: string;
  readonly assessmentId: string;
  readonly sealedAt: string;
  readonly hasAttackAuthorizationToken: boolean;
}): InvestigationAuthorizationBundle {
  const bundle: InvestigationAuthorizationBundle = {
    contractVersion: ACTIVE_INVESTIGATION_CONTRACT_VERSION,
    kind: 'investigation_authorization_bundle',
    investigationId: args.investigationId,
    assessmentId: args.assessmentId,
    sealedAt: args.sealedAt,
    hasVerifiedAuthorizationDecision: true,
    hasAttackAuthorizationToken: args.hasAttackAuthorizationToken,
    [Symbol.toStringTag]: BUNDLE_TO_STRING_TAG,
  };
  Object.freeze(bundle);
  _authorizationBundleBrand.add(bundle);
  return bundle;
}

export function isRuntimeInvestigationAuthorizationBundle(
  value: unknown
): value is InvestigationAuthorizationBundle {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    _authorizationBundleBrand.has(value)
  );
}

function elapsedMs(startedAt: string, nowIso: string): number {
  return Date.parse(nowIso) - Date.parse(startedAt);
}

export class ActiveInvestigationRuntimeService {
  private readonly investigations = new Map<string, InternalInvestigation>();

  public startInvestigation(request: unknown): StartActiveInvestigationResult {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Start investigation request must be a non-empty object',
      };
    }

    const contractVersion = Reflect.get(request, 'contractVersion');
    const kind = Reflect.get(request, 'kind');
    if (contractVersion !== ACTIVE_INVESTIGATION_CONTRACT_VERSION) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Unsupported active investigation contract version',
      };
    }
    if (kind !== 'start_active_investigation_request') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid start investigation request kind',
      };
    }

    const investigationId = Reflect.get(request, 'investigationId');
    if (!isSafeId(investigationId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field investigationId must satisfy strict identifier format',
      };
    }
    if (this.investigations.has(investigationId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Investigation id already exists',
      };
    }

    const lineage = parseLineage(Reflect.get(request, 'lineage'));
    if (!lineage) {
      return {
        status: 'denied',
        reasonCode: 'lineage_invalid',
        safeMessage: 'Investigation lineage is missing or invalid',
      };
    }

    const decision = Reflect.get(request, 'verifiedAuthorizationDecision');
    if (decision === undefined || decision === null) {
      return {
        status: 'denied',
        reasonCode: 'authorization_brand_missing',
        safeMessage: 'Verified authorization decision is required to start an investigation',
      };
    }
    if (!isRuntimeEstablishedVerifiedAuthorizationDecision(decision)) {
      return {
        status: 'denied',
        reasonCode: 'authorization_brand_invalid',
        safeMessage: 'Verified authorization decision is not runtime-branded',
      };
    }

    const budget = parseBudget(Reflect.get(request, 'budget'));
    if (!budget) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Investigation budget is invalid',
      };
    }

    const startedAtRaw = Reflect.get(request, 'startedAt');
    const startedAt =
      startedAtRaw === undefined
        ? new Date().toISOString()
        : isSafeIsoTimestamp(startedAtRaw)
          ? startedAtRaw
          : null;
    if (startedAt === null) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field startedAt must be a valid ISO timestamp',
      };
    }

    let attackToken: AttackAuthorizationToken | undefined;
    const rawAttackToken = Reflect.get(request, 'attackAuthorizationToken');
    if (rawAttackToken !== undefined) {
      if (!isRuntimeAttackToken(rawAttackToken)) {
        return {
          status: 'denied',
          reasonCode: 'authorization_brand_invalid',
          safeMessage: 'Attack authorization token is not runtime-branded',
        };
      }
      if (rawAttackToken.assessmentId !== lineage.assessmentId) {
        return {
          status: 'denied',
          reasonCode: 'authorization_brand_invalid',
          safeMessage: 'Attack authorization token assessment binding mismatch',
        };
      }
      attackToken = rawAttackToken;
    }

    const openHypothesisRefsRaw = Reflect.get(request, 'openHypothesisRefs');
    const openHypothesisRefs: string[] = [];
    if (openHypothesisRefsRaw !== undefined) {
      if (!Array.isArray(openHypothesisRefsRaw)) {
        return {
          status: 'denied',
          reasonCode: 'request_invalid',
          safeMessage: 'Field openHypothesisRefs must be an array of identifiers',
        };
      }
      for (const ref of openHypothesisRefsRaw) {
        if (!isSafeId(ref)) {
          return {
            status: 'denied',
            reasonCode: 'request_invalid',
            safeMessage: 'openHypothesisRefs contains an invalid identifier',
          };
        }
        openHypothesisRefs.push(ref);
      }
    }

    const typedRequest = request as StartActiveInvestigationRequest;
    void typedRequest;

    const authorizationBundle = sealAuthorizationBundle({
      investigationId,
      assessmentId: lineage.assessmentId,
      sealedAt: startedAt,
      hasAttackAuthorizationToken: attackToken !== undefined,
    });

    const inv: InternalInvestigation = {
      investigationId,
      lineage,
      budget,
      status: 'running',
      cancelRequested: false,
      killSwitchEngaged: false,
      consumption: {
        requestsConsumed: 0,
        stepsRecorded: 0,
        startedAt,
        lastActivityAt: startedAt,
      },
      workingMemory: {
        confirmedFactIds: [],
        openHypothesisRefs,
        executedStepIds: [],
      },
      authorizationBundle,
      verifiedAuthorizationDecision: decision,
      attackAuthorizationToken: attackToken,
      activeStepCount: 0,
    };
    this.investigations.set(investigationId, inv);

    return {
      status: 'started',
      reasonCode: 'investigation_started',
      snapshot: toSnapshot(inv),
      authorizationBundle,
    };
  }

  public cancelInvestigation(request: unknown): CancelActiveInvestigationResult {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Cancel investigation request must be a non-empty object',
      };
    }
    if (Reflect.get(request, 'contractVersion') !== ACTIVE_INVESTIGATION_CONTRACT_VERSION) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Unsupported active investigation contract version',
      };
    }
    if (Reflect.get(request, 'kind') !== 'cancel_active_investigation_request') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid cancel investigation request kind',
      };
    }

    const investigationId = Reflect.get(request, 'investigationId');
    const operatorId = Reflect.get(request, 'operatorId');
    const mode = Reflect.get(request, 'mode');
    if (!isSafeId(investigationId) || !isSafeId(operatorId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'investigationId and operatorId must satisfy strict identifier format',
      };
    }
    if (mode !== 'cancel' && mode !== 'kill_switch') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Cancel mode must be cancel or kill_switch',
      };
    }

    const cancelledAtRaw = Reflect.get(request, 'cancelledAt');
    const cancelledAt =
      cancelledAtRaw === undefined
        ? new Date().toISOString()
        : isSafeIsoTimestamp(cancelledAtRaw)
          ? cancelledAtRaw
          : null;
    if (cancelledAt === null) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field cancelledAt must be a valid ISO timestamp',
      };
    }

    void (request as CancelActiveInvestigationRequest);

    const inv = this.investigations.get(investigationId);
    if (!inv) {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_found',
        safeMessage: 'Investigation was not found',
      };
    }
    if (inv.status !== 'running') {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_running',
        safeMessage: 'Investigation is not running',
      };
    }

    inv.cancelRequested = true;
    inv.killSwitchEngaged = mode === 'kill_switch';
    inv.status = 'cancelled';
    inv.denialReasonCode = mode === 'kill_switch' ? 'kill_switch_engaged' : 'cancel_requested';
    inv.completedAt = cancelledAt;
    inv.consumption.lastActivityAt = cancelledAt;
    inv.activeStepCount = 0;

    return {
      status: 'cancelled',
      reasonCode: mode === 'kill_switch' ? 'kill_switch_engaged' : 'investigation_cancelled',
      snapshot: toSnapshot(inv),
    };
  }

  public bindAttackAuthorization(request: unknown): BindAttackAuthorizationResult {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Bind attack authorization request must be a non-empty object',
      };
    }
    if (Reflect.get(request, 'contractVersion') !== ACTIVE_INVESTIGATION_CONTRACT_VERSION) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Unsupported active investigation contract version',
      };
    }
    if (Reflect.get(request, 'kind') !== 'bind_attack_authorization_request') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid bind attack authorization request kind',
      };
    }

    const investigationId = Reflect.get(request, 'investigationId');
    if (!isSafeId(investigationId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field investigationId must satisfy strict identifier format',
      };
    }

    const token = Reflect.get(request, 'attackAuthorizationToken');
    if (!isRuntimeAttackToken(token)) {
      return {
        status: 'denied',
        reasonCode: 'attack_authorization_invalid',
        safeMessage: 'Attack authorization token is not runtime-branded',
      };
    }

    void (request as BindAttackAuthorizationRequest);

    const inv = this.investigations.get(investigationId);
    if (!inv) {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_found',
        safeMessage: 'Investigation was not found',
      };
    }
    if (inv.status !== 'running') {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_running',
        safeMessage: 'Investigation is not running',
      };
    }
    if (token.assessmentId !== inv.lineage.assessmentId) {
      return {
        status: 'denied',
        reasonCode: 'assessment_mismatch',
        safeMessage: 'Attack authorization token assessment binding mismatch',
      };
    }

    inv.attackAuthorizationToken = token;
    inv.authorizationBundle = sealAuthorizationBundle({
      investigationId: inv.investigationId,
      assessmentId: inv.lineage.assessmentId,
      sealedAt: new Date().toISOString(),
      hasAttackAuthorizationToken: true,
    });

    return {
      status: 'bound',
      reasonCode: 'attack_authorization_bound',
      authorizationBundle: inv.authorizationBundle,
    };
  }

  /**
   * Apply investigation budget rate/concurrency ceilings onto a coordinator host quota.
   * Fail-closed: unknown / non-running investigation → false.
   */
  public bindCoordinatorCeilings(args: BindCoordinatorCeilingsRequest): boolean {
    if (!args || typeof args !== 'object') return false;
    if (!isSafeId(args.investigationId)) return false;
    if (typeof args.host !== 'string' || args.host.trim().length === 0) return false;
    if (!args.coordinator || typeof args.coordinator !== 'object') return false;
    if (typeof Reflect.get(args.coordinator, 'setHostQuota') !== 'function') return false;

    const inv = this.investigations.get(args.investigationId);
    if (!inv || inv.status !== 'running') return false;

    const rps =
      inv.budget.requestsPerSecondCeiling ??
      DEFAULT_INVESTIGATION_BUDGET.requestsPerSecondCeiling ??
      5;
    const maxConcurrency =
      inv.budget.maxConcurrencyCeiling ??
      DEFAULT_INVESTIGATION_BUDGET.maxConcurrencyCeiling ??
      2;

    (args.coordinator as TargetExecutionCoordinator).setHostQuota(args.host.trim().toLowerCase(), {
      requestsPerSecond: rps,
      maxConcurrency,
      maxQueueDepth: 100,
    });
    return true;
  }

  public createCoordinatorForInvestigation(
    investigationId: string,
    host?: string
  ): TargetExecutionCoordinator | null {
    const inv = this.investigations.get(investigationId);
    if (!inv || inv.status !== 'running') return null;

    const rps =
      inv.budget.requestsPerSecondCeiling ??
      DEFAULT_INVESTIGATION_BUDGET.requestsPerSecondCeiling ??
      5;
    const maxConcurrency =
      inv.budget.maxConcurrencyCeiling ??
      DEFAULT_INVESTIGATION_BUDGET.maxConcurrencyCeiling ??
      2;

    const coordinator = new TargetExecutionCoordinator({
      requestsPerSecond: rps,
      maxConcurrency,
      maxQueueDepth: 100,
    });
    if (host && host.trim().length > 0) {
      this.bindCoordinatorCeilings({ investigationId, coordinator, host });
    }
    return coordinator;
  }

  public gateAuthorizedStep(request: unknown): GateAuthorizedStepResult {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Gate authorized step request must be a non-empty object',
      };
    }
    if (Reflect.get(request, 'contractVersion') !== ACTIVE_INVESTIGATION_CONTRACT_VERSION) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Unsupported active investigation contract version',
      };
    }
    if (Reflect.get(request, 'kind') !== 'gate_authorized_step_request') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid gate authorized step request kind',
      };
    }

    const investigationId = Reflect.get(request, 'investigationId');
    const assessmentId = Reflect.get(request, 'assessmentId');
    if (!isSafeId(investigationId) || !isSafeId(assessmentId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'investigationId and assessmentId must satisfy strict identifier format',
      };
    }

    const expectedRequestCostRaw = Reflect.get(request, 'expectedRequestCost');
    const expectedRequestCost =
      expectedRequestCostRaw === undefined ? 1 : expectedRequestCostRaw;
    if (
      typeof expectedRequestCost !== 'number' ||
      !Number.isInteger(expectedRequestCost) ||
      expectedRequestCost < 0
    ) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'expectedRequestCost must be a non-negative integer',
      };
    }

    const gatedAtRaw = Reflect.get(request, 'gatedAt');
    const gatedAt =
      gatedAtRaw === undefined
        ? new Date().toISOString()
        : isSafeIsoTimestamp(gatedAtRaw)
          ? gatedAtRaw
          : null;
    if (gatedAt === null) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field gatedAt must be a valid ISO timestamp',
      };
    }

    const requireAttackAuthorization = Reflect.get(request, 'requireAttackAuthorization') === true;
    void (request as GateAuthorizedStepRequest);

    const inv = this.investigations.get(investigationId);
    if (!inv) {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_found',
        safeMessage: 'Investigation was not found',
      };
    }

    if (inv.lineage.assessmentId !== assessmentId) {
      return {
        status: 'denied',
        reasonCode: 'assessment_mismatch',
        safeMessage: 'Investigation assessment binding mismatch',
        snapshot: toSnapshot(inv),
      };
    }

    const terminal = this.refreshTerminalState(inv, gatedAt);
    if (terminal) {
      return terminal;
    }

    if (!isRuntimeInvestigationAuthorizationBundle(inv.authorizationBundle)) {
      return {
        status: 'denied',
        reasonCode: 'authorization_bundle_invalid',
        safeMessage: 'Investigation authorization bundle is not runtime-branded',
        snapshot: toSnapshot(inv),
      };
    }
    if (!isRuntimeEstablishedVerifiedAuthorizationDecision(inv.verifiedAuthorizationDecision)) {
      return {
        status: 'denied',
        reasonCode: 'verified_authorization_missing',
        safeMessage: 'Verified authorization decision brand is no longer valid',
        snapshot: toSnapshot(inv),
      };
    }

    if (requireAttackAuthorization) {
      if (!inv.attackAuthorizationToken) {
        return {
          status: 'denied',
          reasonCode: 'attack_authorization_required',
          safeMessage: 'Human-authorized attack token is required for this investigation step',
          snapshot: toSnapshot(inv),
        };
      }
      if (!isRuntimeAttackToken(inv.attackAuthorizationToken)) {
        return {
          status: 'denied',
          reasonCode: 'attack_authorization_invalid',
          safeMessage: 'Bound attack authorization token is not runtime-branded',
          snapshot: toSnapshot(inv),
        };
      }
      const planId = Reflect.get(request, 'planId');
      if (planId !== undefined) {
        if (!isSafeId(planId) || inv.attackAuthorizationToken.planId !== planId) {
          return {
            status: 'denied',
            reasonCode: 'attack_authorization_invalid',
            safeMessage: 'Attack authorization token plan binding mismatch',
            snapshot: toSnapshot(inv),
          };
        }
      }
    }

    const maxConcurrent = inv.budget.maxConcurrentSteps ?? 1;
    if (inv.activeStepCount >= maxConcurrent) {
      return {
        status: 'denied',
        reasonCode: 'concurrent_step_limit',
        safeMessage: 'Investigation concurrent step ceiling exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    if (inv.consumption.requestsConsumed + expectedRequestCost > inv.budget.maxRequests) {
      inv.status = 'budget_exceeded';
      inv.denialReasonCode = 'budget_exceeded';
      inv.completedAt = gatedAt;
      inv.consumption.lastActivityAt = gatedAt;
      return {
        status: 'denied',
        reasonCode: 'budget_exceeded',
        safeMessage: 'Investigation request budget would be exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    inv.activeStepCount += 1;
    inv.consumption.lastActivityAt = gatedAt;

    return {
      status: 'authorized',
      reasonCode: 'step_authorized',
      snapshot: toSnapshot(inv),
      authorizationBundle: inv.authorizationBundle,
      verifiedAuthorizationDecision: inv.verifiedAuthorizationDecision,
      ...(inv.attackAuthorizationToken
        ? { attackAuthorizationToken: inv.attackAuthorizationToken }
        : {}),
    };
  }

  /**
   * Release concurrent-step slot after a gated step finishes (success or fail).
   * Optionally consumes request budget and appends working-memory step id.
   */
  public recordStepOutcome(request: unknown): RecordInvestigationStepResult {
    if (!request || typeof request !== 'object' || Array.isArray(request)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Record investigation step request must be a non-empty object',
      };
    }
    if (Reflect.get(request, 'contractVersion') !== ACTIVE_INVESTIGATION_CONTRACT_VERSION) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Unsupported active investigation contract version',
      };
    }
    if (Reflect.get(request, 'kind') !== 'record_investigation_step_request') {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Invalid record investigation step request kind',
      };
    }

    const investigationId = Reflect.get(request, 'investigationId');
    const stepId = Reflect.get(request, 'stepId');
    if (!isSafeId(investigationId) || !isSafeId(stepId)) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'investigationId and stepId must satisfy strict identifier format',
      };
    }

    const requestCostRaw = Reflect.get(request, 'requestCost');
    const requestCost = requestCostRaw === undefined ? 1 : requestCostRaw;
    if (typeof requestCost !== 'number' || !Number.isInteger(requestCost) || requestCost < 0) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'requestCost must be a non-negative integer',
      };
    }

    const recordedAtRaw = Reflect.get(request, 'recordedAt');
    const recordedAt =
      recordedAtRaw === undefined
        ? new Date().toISOString()
        : isSafeIsoTimestamp(recordedAtRaw)
          ? recordedAtRaw
          : null;
    if (recordedAt === null) {
      return {
        status: 'denied',
        reasonCode: 'request_invalid',
        safeMessage: 'Field recordedAt must be a valid ISO timestamp',
      };
    }

    const producedFactIdsRaw = Reflect.get(request, 'producedFactIds');
    const producedFactIds: string[] = [];
    if (producedFactIdsRaw !== undefined) {
      if (!Array.isArray(producedFactIdsRaw)) {
        return {
          status: 'denied',
          reasonCode: 'request_invalid',
          safeMessage: 'producedFactIds must be an array of identifiers',
        };
      }
      for (const id of producedFactIdsRaw) {
        if (!isSafeId(id)) {
          return {
            status: 'denied',
            reasonCode: 'request_invalid',
            safeMessage: 'producedFactIds contains an invalid identifier',
          };
        }
        producedFactIds.push(id);
      }
    }

    void (request as RecordInvestigationStepRequest);

    const inv = this.investigations.get(investigationId);
    if (!inv) {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_found',
        safeMessage: 'Investigation was not found',
      };
    }

    if (inv.activeStepCount > 0) {
      inv.activeStepCount -= 1;
    }

    const terminal = this.refreshTerminalState(inv, recordedAt);
    if (terminal) {
      return {
        status: 'recorded',
        reasonCode:
          terminal.reasonCode === 'budget_exceeded'
            ? 'budget_exceeded'
            : terminal.reasonCode === 'timed_out'
              ? 'timed_out'
              : 'cancelled',
        snapshot: toSnapshot(inv),
      };
    }

    if (inv.consumption.requestsConsumed + requestCost > inv.budget.maxRequests) {
      inv.status = 'budget_exceeded';
      inv.denialReasonCode = 'budget_exceeded';
      inv.completedAt = recordedAt;
      inv.consumption.lastActivityAt = recordedAt;
      return {
        status: 'recorded',
        reasonCode: 'budget_exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    inv.consumption.requestsConsumed += requestCost;
    inv.consumption.stepsRecorded += 1;
    inv.consumption.lastActivityAt = recordedAt;
    if (!inv.workingMemory.executedStepIds.includes(stepId)) {
      inv.workingMemory.executedStepIds.push(stepId);
    }
    for (const factId of producedFactIds) {
      if (!inv.workingMemory.confirmedFactIds.includes(factId)) {
        inv.workingMemory.confirmedFactIds.push(factId);
      }
    }

    return {
      status: 'recorded',
      reasonCode: 'step_recorded',
      snapshot: toSnapshot(inv),
    };
  }

  public completeInvestigation(
    investigationId: string,
    completedAt?: string
  ): ActiveInvestigationSnapshot | null {
    if (!isSafeId(investigationId)) return null;
    const inv = this.investigations.get(investigationId);
    if (!inv || inv.status !== 'running') return null;
    const at =
      completedAt && isSafeIsoTimestamp(completedAt) ? completedAt : new Date().toISOString();
    inv.status = 'completed';
    inv.completedAt = at;
    inv.consumption.lastActivityAt = at;
    inv.activeStepCount = 0;
    return toSnapshot(inv);
  }

  public getSnapshot(investigationId: string): ActiveInvestigationSnapshot | null {
    if (!isSafeId(investigationId)) return null;
    const inv = this.investigations.get(investigationId);
    if (!inv) return null;
    this.refreshTerminalState(inv, new Date().toISOString());
    return toSnapshot(inv);
  }

  public getRuntimeAuthorizationBundle(
    investigationId: string
  ): InvestigationAuthorizationBundle | null {
    if (!isSafeId(investigationId)) return null;
    const inv = this.investigations.get(investigationId);
    if (!inv) return null;
    if (!isRuntimeInvestigationAuthorizationBundle(inv.authorizationBundle)) return null;
    return inv.authorizationBundle;
  }

  public findRunningInvestigationIdForAssessment(assessmentId: string): string | null {
    if (!isSafeId(assessmentId)) return null;
    for (const inv of this.investigations.values()) {
      if (inv.lineage.assessmentId === assessmentId && inv.status === 'running') {
        return inv.investigationId;
      }
    }
    return null;
  }

  private refreshTerminalState(
    inv: InternalInvestigation,
    nowIso: string
  ): GateAuthorizedStepResult | null {
    if (inv.status === 'cancelled' || inv.killSwitchEngaged || inv.cancelRequested) {
      if (inv.status === 'running') {
        inv.status = 'cancelled';
        inv.completedAt = nowIso;
        inv.denialReasonCode = inv.killSwitchEngaged ? 'kill_switch_engaged' : 'cancel_requested';
      }
      return {
        status: 'denied',
        reasonCode: inv.killSwitchEngaged ? 'kill_switch_engaged' : 'cancel_requested',
        safeMessage: inv.killSwitchEngaged
          ? 'Investigation kill-switch is engaged'
          : 'Investigation cancel was requested',
        snapshot: toSnapshot(inv),
      };
    }

    if (inv.status === 'budget_exceeded') {
      return {
        status: 'denied',
        reasonCode: 'budget_exceeded',
        safeMessage: 'Investigation request budget has been exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    if (inv.status === 'timed_out') {
      return {
        status: 'denied',
        reasonCode: 'timed_out',
        safeMessage: 'Investigation timeout has been exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    if (inv.status !== 'running') {
      return {
        status: 'denied',
        reasonCode: 'investigation_not_running',
        safeMessage: 'Investigation is not running',
        snapshot: toSnapshot(inv),
      };
    }

    if (elapsedMs(inv.consumption.startedAt, nowIso) > inv.budget.maxDurationMs) {
      inv.status = 'timed_out';
      inv.denialReasonCode = 'timed_out';
      inv.completedAt = nowIso;
      inv.consumption.lastActivityAt = nowIso;
      return {
        status: 'denied',
        reasonCode: 'timed_out',
        safeMessage: 'Investigation timeout has been exceeded',
        snapshot: toSnapshot(inv),
      };
    }

    return null;
  }
}
