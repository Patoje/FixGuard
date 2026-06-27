import type { LifecycleState } from './AssessmentState';

export class RuntimeLifecycleError extends Error {
  constructor(
    public readonly sessionId: string,
    public readonly action: string,
    public readonly lifecycleStatus: LifecycleState,
    message?: string
  ) {
    super(message || `Invalid lifecycle transition: Cannot perform action '${action}' in state '${lifecycleStatus}' for session '${sessionId}'`);
    this.name = 'RuntimeLifecycleError';
  }
}
