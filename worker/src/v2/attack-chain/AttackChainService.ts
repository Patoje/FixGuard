/**
 * Milestone A6 — AttackChainService
 *
 * Tracks attack-chain hypotheses and aggregates executed-step evidence.
 * Pure recalculation only — no network, no fabricated steps, no epistemic inflation.
 *
 * Invariants enforced:
 * 1. overallEpistemicStatus = min(steps) — any INFERRED → chain INFERRED;
 *    any REFUTED → chain REFUTED (REFUTED never treated as VERIFIED)
 * 2. fully_validated only when every step succeeded and ≥2 steps exist;
 *    failed/refuted steps are retained and block fully_validated
 * 3. assessmentId + scanId isolation — cross-assessment step injection fails closed
 */

import { isStrictSafeId } from '../reporting-boundary/DefensiveReportContracts.js';
import {
  ATTACK_CHAIN_CONTRACT_VERSION,
  recalculateAttackChain,
  type AppendAttackChainStepInput,
  type AttackChain,
  type AttackChainStep,
  type InitAttackChainHypothesisInput,
  type RecordAttackChainStepOutcomeInput,
} from './AttackChainContracts.js';
import type { AttackChainRepository } from './AttackChainRepository.js';

export class AttackChainIsolationError extends Error {
  readonly reasonCode = 'attack_chain_isolation_violation' as const;

  constructor(message: string) {
    super(message);
    this.name = 'AttackChainIsolationError';
  }
}

export class AttackChainNotFoundError extends Error {
  readonly reasonCode = 'attack_chain_not_found' as const;

  constructor(message: string) {
    super(message);
    this.name = 'AttackChainNotFoundError';
  }
}

export class AttackChainValidationError extends Error {
  readonly reasonCode = 'attack_chain_validation_error' as const;

  constructor(message: string) {
    super(message);
    this.name = 'AttackChainValidationError';
  }
}

function assertStrictId(field: string, value: string): void {
  if (!value || typeof value !== 'string' || !isStrictSafeId(value)) {
    throw new AttackChainValidationError(
      `Field ${field} must satisfy strict identifier format`
    );
  }
}

function assertLineageMatches(
  chain: AttackChain,
  assessmentId: string,
  scanId: string
): void {
  if (chain.assessmentId !== assessmentId || chain.scanId !== scanId) {
    throw new AttackChainIsolationError(
      'Cross-assessment/scan attack-chain step injection rejected (fail-closed)'
    );
  }
  if (
    chain.lineage.assessmentId !== assessmentId ||
    chain.lineage.scanId !== scanId
  ) {
    throw new AttackChainIsolationError(
      'Attack-chain lineage isolation violation (fail-closed)'
    );
  }
}

function omitCompletedAt(chain: AttackChain): AttackChain {
  if (chain.completedAt === undefined) {
    const { completedAt: _dropped, ...rest } = chain;
    void _dropped;
    return rest;
  }
  return chain;
}

export class AttackChainService {
  constructor(private readonly repository: AttackChainRepository) {}

  /**
   * Initialize a chain hypothesis with zero steps.
   * overallEpistemicStatus starts as INFERRED (no observed evidence yet).
   */
  async initHypothesis(input: InitAttackChainHypothesisInput): Promise<AttackChain> {
    assertStrictId('chainId', input.chainId);
    assertStrictId('assessmentId', input.assessmentId);
    assertStrictId('scanId', input.scanId);

    if (
      input.lineage.assessmentId !== input.assessmentId ||
      input.lineage.scanId !== input.scanId
    ) {
      throw new AttackChainIsolationError(
        'Hypothesis lineage must match assessmentId/scanId (fail-closed)'
      );
    }

    if (typeof input.hypothesis !== 'string' || input.hypothesis.trim().length === 0) {
      throw new AttackChainValidationError('hypothesis must be a non-empty string');
    }

    const createdAt = input.createdAt ?? new Date().toISOString();

    const chain: AttackChain = {
      contractVersion: ATTACK_CHAIN_CONTRACT_VERSION,
      kind: 'attack_chain',
      chainId: input.chainId,
      assessmentId: input.assessmentId,
      scanId: input.scanId,
      hypothesis: input.hypothesis.trim(),
      objectiveKind: input.objectiveKind,
      steps: [],
      overallEpistemicStatus: 'INFERRED',
      status: 'hypothesis',
      impactLevel: input.impactLevel,
      lineage: {
        assessmentId: input.lineage.assessmentId,
        scanId: input.lineage.scanId,
        authorizationGrantId: input.lineage.authorizationGrantId,
        authorizationDecisionId: input.lineage.authorizationDecisionId,
        actorId: input.lineage.actorId,
      },
      createdAt,
    };

    return this.repository.saveChain(chain);
  }

  /**
   * Append an executed step with evidence. Recalculates status + epistemic min.
   * Cross-assessment injection fails closed.
   */
  async appendExecutedStep(input: AppendAttackChainStepInput): Promise<AttackChain> {
    assertStrictId('chainId', input.chainId);
    assertStrictId('assessmentId', input.assessmentId);
    assertStrictId('scanId', input.scanId);
    assertStrictId('stepId', input.stepId);
    if (input.sourceStepId !== undefined) {
      assertStrictId('sourceStepId', input.sourceStepId);
    }

    const existing = await this.repository.getChain(input.chainId);
    if (!existing) {
      throw new AttackChainNotFoundError(`AttackChain not found: ${input.chainId}`);
    }

    assertLineageMatches(existing, input.assessmentId, input.scanId);

    if (existing.status === 'abandoned') {
      throw new AttackChainValidationError('Cannot append steps to an abandoned chain');
    }

    if (existing.steps.some((s) => s.stepId === input.stepId)) {
      throw new AttackChainValidationError(`Duplicate stepId: ${input.stepId}`);
    }

    if (input.sourceStepId !== undefined) {
      const source = existing.steps.find((s) => s.stepId === input.sourceStepId);
      if (!source) {
        throw new AttackChainValidationError(
          `sourceStepId '${input.sourceStepId}' does not exist on this chain`
        );
      }
    }

    const recordedAt = input.recordedAt ?? input.evidence.recordedAt ?? new Date().toISOString();
    const sequence = existing.steps.length + 1;

    const step: AttackChainStep = {
      stepId: input.stepId,
      sequence,
      capabilityKind: input.capabilityKind,
      epistemicStatus: input.epistemicStatus,
      evidence: {
        ...(input.evidence.evidenceId !== undefined
          ? { evidenceId: input.evidence.evidenceId }
          : {}),
        reasonCode: input.evidence.reasonCode,
        safeMessage: input.evidence.safeMessage,
        recordedAt,
      },
      capabilityGained: input.capabilityGained,
      outcome: input.outcome,
      ...(input.sourceStepId !== undefined ? { sourceStepId: input.sourceStepId } : {}),
    };

    const withStep: AttackChain = {
      ...existing,
      steps: [...existing.steps, step],
    };

    const recalculated = omitCompletedAt(recalculateAttackChain(withStep, recordedAt));
    return this.repository.updateChain(recalculated);
  }

  /**
   * Record / update an outcome on an existing step and recalculate aggregates.
   * Failed/refuted outcomes are preserved — never discarded to force fully_validated.
   */
  async recordOutcome(input: RecordAttackChainStepOutcomeInput): Promise<AttackChain> {
    assertStrictId('chainId', input.chainId);
    assertStrictId('assessmentId', input.assessmentId);
    assertStrictId('scanId', input.scanId);
    assertStrictId('stepId', input.stepId);

    const existing = await this.repository.getChain(input.chainId);
    if (!existing) {
      throw new AttackChainNotFoundError(`AttackChain not found: ${input.chainId}`);
    }

    assertLineageMatches(existing, input.assessmentId, input.scanId);

    if (existing.status === 'abandoned') {
      throw new AttackChainValidationError('Cannot record outcome on an abandoned chain');
    }

    const idx = existing.steps.findIndex((s) => s.stepId === input.stepId);
    if (idx < 0) {
      throw new AttackChainValidationError(`Step not found: ${input.stepId}`);
    }

    const nowIso = input.recordedAt ?? new Date().toISOString();
    const prev = existing.steps[idx]!;
    const updatedStep: AttackChainStep = {
      ...prev,
      outcome: input.outcome,
      ...(input.epistemicStatus !== undefined
        ? { epistemicStatus: input.epistemicStatus }
        : {}),
      ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
    };

    const steps = existing.steps.map((s, i) => (i === idx ? updatedStep : s));
    const withSteps: AttackChain = { ...existing, steps };
    const recalculated = omitCompletedAt(recalculateAttackChain(withSteps, nowIso));
    return this.repository.updateChain(recalculated);
  }

  async getChain(chainId: string): Promise<AttackChain | null> {
    assertStrictId('chainId', chainId);
    return this.repository.getChain(chainId);
  }

  async listByAssessmentId(assessmentId: string): Promise<readonly AttackChain[]> {
    assertStrictId('assessmentId', assessmentId);
    return this.repository.listByAssessmentId(assessmentId);
  }

  async abandonChain(
    chainId: string,
    assessmentId: string,
    scanId: string,
    abandonedAt?: string
  ): Promise<AttackChain> {
    assertStrictId('chainId', chainId);
    assertStrictId('assessmentId', assessmentId);
    assertStrictId('scanId', scanId);

    const existing = await this.repository.getChain(chainId);
    if (!existing) {
      throw new AttackChainNotFoundError(`AttackChain not found: ${chainId}`);
    }
    assertLineageMatches(existing, assessmentId, scanId);

    const nowIso = abandonedAt ?? new Date().toISOString();
    const abandoned: AttackChain = {
      ...existing,
      status: 'abandoned',
      completedAt: nowIso,
    };
    return this.repository.updateChain(abandoned);
  }
}
