export class StaleStateError extends Error {
  constructor(
    public readonly sessionId: string,
    public readonly expectedVersion: number,
    public readonly actualVersion: number,
    public readonly message: string
  ) {
    super(message);
    this.name = 'StaleStateError';
  }
}
