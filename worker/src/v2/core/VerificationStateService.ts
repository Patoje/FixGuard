/**
 * VerificationStateService.ts
 * FixGuard V2 - Verification State Machine Service
 * Enforces strict transitions and state immutability.
 */

import type { Finding } from './Evidence';
import type { VerificationState, VerificationStateTransition } from './VerificationStateContracts';

export class VerificationStateService {
  /**
   * Advances or transitions the verification state of a Finding.
   * Invariant: A transition MUST carry either an evidenceId or a reviewerId.
   */
  public static advanceState(
    finding: Finding,
    targetState: VerificationState,
    transition: {
      readonly evidenceId?: string;
      readonly reviewerId?: string;
      readonly reasonCode: string;
    }
  ): { updatedFinding: Finding; transitionRecord: VerificationStateTransition } {
    if (!transition.evidenceId && !transition.reviewerId) {
      throw new Error('Verification state transition invariant violated: Must specify either evidenceId or reviewerId.');
    }

    if (!transition.reasonCode || transition.reasonCode.trim().length === 0) {
      throw new Error('Verification state transition invariant violated: Reason code is required.');
    }

    const currentState = finding.verificationState;

    const transitionRecord: VerificationStateTransition = {
      fromState: currentState,
      toState: targetState,
      transitionedAt: new Date().toISOString(),
      ...(transition.evidenceId ? { evidenceId: transition.evidenceId } : {}),
      ...(transition.reviewerId ? { reviewerId: transition.reviewerId } : {}),
      reasonCode: transition.reasonCode,
    };

    const updatedFinding: Finding = Object.freeze({
      ...finding,
      verificationState: targetState,
    });

    return { updatedFinding, transitionRecord };
  }

  /**
   * Refutes or downgrades a verification state with evidence or human reviewer authorization.
   */
  public static refuteState(
    finding: Finding,
    targetState: VerificationState,
    transition: {
      readonly evidenceId?: string;
      readonly reviewerId?: string;
      readonly reasonCode: string;
    }
  ): { updatedFinding: Finding; transitionRecord: VerificationStateTransition } {
    return this.advanceState(finding, targetState, transition);
  }
}
