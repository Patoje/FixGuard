/**
 * Process-local BYOT session store.
 *
 * Secrets never persist to DB / reports / JSON read-models.
 * Only identity metadata is exposed for recommendation preconditions.
 * Full header/cookie material is available solely for in-process execute injection.
 */

export interface EphemeralByotIdentityMaterial {
  readonly identityId: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface EphemeralByotSessionMeta {
  readonly assessmentId: string;
  readonly identityCount: number;
  readonly identityAId: string;
  readonly identityBId?: string;
  readonly hasJwtA: boolean;
  readonly hasJwtB: boolean;
  readonly registeredAt: string;
}

interface InternalSession {
  readonly meta: EphemeralByotSessionMeta;
  readonly identityA: EphemeralByotIdentityMaterial;
  readonly identityB?: EphemeralByotIdentityMaterial;
}

function isSafeId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) return false;
  return /^[a-zA-Z0-9_\-.:]+$/.test(value);
}

function looksLikeJwt(headers: Readonly<Record<string, string>> | undefined): boolean {
  if (!headers) return false;
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() !== 'authorization') continue;
    if (/^bearer\s+eyJ[A-Za-z0-9_-]+\./i.test(v.trim())) return true;
  }
  return false;
}

function freezeHeaders(
  headers: Readonly<Record<string, string>> | undefined
): Readonly<Record<string, string>> | undefined {
  if (!headers) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (typeof k !== 'string' || typeof v !== 'string') continue;
    out[k] = v;
  }
  return Object.freeze(out);
}

export class EphemeralByotSessionStore {
  private readonly sessions = new Map<string, InternalSession>();

  public register(args: {
    readonly assessmentId: string;
    readonly identityA: EphemeralByotIdentityMaterial;
    readonly identityB?: EphemeralByotIdentityMaterial;
    readonly registeredAt?: string;
  }): EphemeralByotSessionMeta | null {
    if (!isSafeId(args.assessmentId)) return null;
    if (!isSafeId(args.identityA.identityId)) return null;
    if (args.identityB && !isSafeId(args.identityB.identityId)) return null;

    const hasJwtA = looksLikeJwt(args.identityA.headers);
    const hasJwtB = looksLikeJwt(args.identityB?.headers);
    const identityCount = args.identityB ? 2 : 1;
    const meta: EphemeralByotSessionMeta = Object.freeze({
      assessmentId: args.assessmentId,
      identityCount,
      identityAId: args.identityA.identityId,
      ...(args.identityB ? { identityBId: args.identityB.identityId } : {}),
      hasJwtA,
      hasJwtB,
      registeredAt: args.registeredAt ?? new Date().toISOString(),
    });

    this.sessions.set(args.assessmentId, {
      meta,
      identityA: Object.freeze({
        identityId: args.identityA.identityId,
        ...(args.identityA.headers
          ? { headers: freezeHeaders(args.identityA.headers) }
          : {}),
      }),
      ...(args.identityB
        ? {
            identityB: Object.freeze({
              identityId: args.identityB.identityId,
              ...(args.identityB.headers
                ? { headers: freezeHeaders(args.identityB.headers) }
                : {}),
            }),
          }
        : {}),
    });

    return meta;
  }

  public getMeta(assessmentId: string): EphemeralByotSessionMeta | null {
    if (!isSafeId(assessmentId)) return null;
    return this.sessions.get(assessmentId)?.meta ?? null;
  }

  /**
   * Returns identity material for execute injection. Caller must not serialize to clients.
   */
  public getExecuteIdentities(assessmentId: string): {
    readonly primaryIdentity: EphemeralByotIdentityMaterial;
    readonly secondaryIdentity?: EphemeralByotIdentityMaterial;
  } | null {
    if (!isSafeId(assessmentId)) return null;
    const session = this.sessions.get(assessmentId);
    if (!session) return null;
    return {
      primaryIdentity: session.identityA,
      ...(session.identityB ? { secondaryIdentity: session.identityB } : {}),
    };
  }

  public clear(assessmentId: string): boolean {
    if (!isSafeId(assessmentId)) return false;
    return this.sessions.delete(assessmentId);
  }
}

/** Shared process-local store for orchestrated assessment BYOT sessions. */
export const ephemeralByotSessionStore = new EphemeralByotSessionStore();
