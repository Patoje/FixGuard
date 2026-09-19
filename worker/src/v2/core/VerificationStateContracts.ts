/**
 * VerificationStateContracts.ts
 * FixGuard V2 - 5-State Verification Lifecycle Contracts
 */

export type VerificationState =
  | 'observed_anomaly'
  | 'suspected_vulnerability'
  | 'validated_vulnerability'
  | 'exploitability_confirmed'
  | 'impact_confirmed';

export interface VerificationStateTransition {
  readonly fromState: VerificationState;
  readonly toState: VerificationState;
  readonly transitionedAt: string;
  readonly evidenceId?: string;
  readonly reviewerId?: string;
  readonly reasonCode: string;
}
