/**
 * M56A — Authorized Execution Lineage Contracts (DB-free)
 *
 * Defines stage-specific immutable lineage references for authorized active-recon
 * execution. These carry provenance identities — not mutable state.
 *
 * Design:
 * - No optional bags. Each reference carries only identities that actually exist
 *   at that specific pipeline stage.
 * - All fields are readonly and the types are Readonly<...>.
 * - References do NOT carry scope grant content — that lives in the decision.
 *
 * Scope:
 * - M56A defines request-level and run-level recon lineage.
 * - M56B will add comparison/validation lineage (separate slice).
 */

// ---------------------------------------------------------------------------
// Base authorization lineage reference
// ---------------------------------------------------------------------------

/**
 * The minimal common authorization identity reference.
 * Composed into stage-specific lineage types.
 */
export type AuthorizationLineageRef = Readonly<{
  assessmentId: string;
  scanId: string;
  authorizationGrantId: string;
  authorizationDecisionId: string;
}>;

// ---------------------------------------------------------------------------
// M38/M39 stage: active recon request lineage
// ---------------------------------------------------------------------------

/**
 * Lineage ref attached to an authorized active-recon execution request.
 * Present before a run ID is generated.
 */
export type AuthorizedActiveReconRequestLineage = Readonly<
  AuthorizationLineageRef & {
    /** 
     * actorId from the VerifiedAuthorizationDecision.authorizedActor.
     * Carried for audit/provenance purposes — not authenticated by M56A.
     */
    actorId: string;
  }
>;

// ---------------------------------------------------------------------------
// M40 stage: active recon run lineage (after runId is generated)
// ---------------------------------------------------------------------------

/**
 * Lineage ref attached to a persisted active-recon run record.
 * Adds the generated runId which is only available after execution begins.
 */
export type AuthorizedActiveReconRunLineage = Readonly<
  AuthorizationLineageRef & {
    actorId: string;
    /** The service-generated runId — never caller-supplied. */
    runId: string;
  }
>;

// ---------------------------------------------------------------------------
// Provenance marker for persistence (M40 contract extension)
// ---------------------------------------------------------------------------

/**
 * Embedded in persisted records to identify the authorization source contract.
 * This does NOT store the full decision — only provenance references.
 */
export type ActiveReconAuthorizationProvenance = Readonly<{
  /** Source contract that established authorization. */
  authorizationSource: 'fixguard-verified-authorization-decision/v0';
  authorizationDecisionId: string;
  authorizationGrantId: string;
  assessmentId: string;
  scanId: string;
  actorId: string;
}>;
