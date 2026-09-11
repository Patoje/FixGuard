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

export class PersistenceConflictError extends Error {
  constructor(
    message: string,
    public readonly conflictKey?: string
  ) {
    super(message);
    this.name = 'PersistenceConflictError';
  }
}

export class SessionNotFoundError extends Error {
  constructor(
    message: string,
    public readonly sessionId?: string
  ) {
    super(message);
    this.name = 'SessionNotFoundError';
  }
}

export class RecordCorruptedError extends Error {
  constructor(
    message: string,
    public readonly recordId?: string
  ) {
    super(message);
    this.name = 'RecordCorruptedError';
  }
}

export class RecordNotFoundError extends Error {
  constructor(
    message: string,
    public readonly recordId?: string
  ) {
    super(message);
    this.name = 'RecordNotFoundError';
  }
}

