import type { AssessmentState } from './AssessmentState';

export class V2AssessmentSession {
  private state: AssessmentState;

  constructor(targetUri: string, sessionId?: string) {
    this.state = {
      sessionId: sessionId || `session_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      targetUri,
      lifecycleStatus: 'initialized',
      evidenceCollections: [],
      currentProfile: null,
      pendingRecommendations: [],
      approvedRequestRecords: [],
      executionFailures: [],
      auditEntries: [],
      errors: [],
      timestamps: {
        created: Date.now(),
        lastUpdated: Date.now()
      },
      version: 1
    };
  }

  public getState(): AssessmentState {
    return JSON.parse(JSON.stringify(this.state));
  }

  /**
   * Internal/runtime use only. Replaces internal state with a versioned clone.
   */
  public update(updater: (state: AssessmentState) => Partial<AssessmentState>): void {
    const currentStateClone = JSON.parse(JSON.stringify(this.state));
    const changes = updater(currentStateClone);
    
    this.state = {
      ...currentStateClone,
      ...changes,
      timestamps: {
        ...currentStateClone.timestamps,
        lastUpdated: Date.now()
      },
      version: currentStateClone.version + 1
    };
  }
}
