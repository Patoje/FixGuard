/**
 * M56A — Verified Authorization Decision Contracts (DB-free)
 *
 * Contract version: fixguard-verified-authorization-decision/v0
 *
 * This module defines contracts for a runtime-established authorization decision
 * that cannot be constructed by callers via plain object literal.
 *
 * IMPORTANT LIMITATIONS — what this module does NOT do:
 *
 * - Does NOT implement authentication, login, or session validation.
 * - Does NOT integrate with any identity provider.
 * - Does NOT use cryptographic signatures.
 * - Does NOT persist decisions.
 * - Does NOT make network calls.
 * - The runtime brand proves the object passed through the trusted DB-free service
 *   in the current runtime instance. It is NOT cryptographic verification.
 * - The human actor identity is modeled but not cryptographically authenticated
 *   by M56A itself.
 *
 * The decision embeds the canonical M46 AuthorizedScopeGrant for all scope/
 * permission semantics. Do not duplicate scope fields here.
 */

import type { AuthorizedScopeGrant } from '../scope/AuthorizedScopeContracts.js';

// ---------------------------------------------------------------------------
// Contract Version
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecisionContractVersion =
  'fixguard-verified-authorization-decision/v0';

export const VERIFIED_AUTHORIZATION_DECISION_CONTRACT_VERSION: VerifiedAuthorizationDecisionContractVersion =
  'fixguard-verified-authorization-decision/v0';

// ---------------------------------------------------------------------------
// Authorized Actor
// ---------------------------------------------------------------------------

export type VerifiedAuthorizedActor = Readonly<{
  /** A stable application-level actor identifier — not a cryptographic token. */
  actorId: string;
  /** Only 'human' actors may authorize promotion. */
  actorType: 'human';
}>;

// ---------------------------------------------------------------------------
// Verification Provenance
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecisionVerification = Readonly<{
  verifiedAt: string;
  /**
   * 'trusted_application_boundary' — means the decision was established by
   * the VerifiedAuthorizationDecisionService within the trusted application
   * boundary. It does NOT mean cryptographic verification occurred.
   */
  method: 'trusted_application_boundary';
}>;

// ---------------------------------------------------------------------------
// VerifiedAuthorizationDecision
//
// The actual branded runtime artifact. Callers receive this via the service.
// A plain object with the same fields is rejected by the validator.
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecision = Readonly<{
  contractVersion: VerifiedAuthorizationDecisionContractVersion;
  kind: 'verified_authorization_decision';

  assessmentId: string;
  scanId: string;
  authorizationGrantId: string;
  authorizationDecisionId: string;

  authorizedActor: VerifiedAuthorizedActor;

  /** Only 'authorized' decisions produce a verified artifact. */
  decision: 'authorized';
  decidedAt: string;

  /**
   * Embeds the canonical M46 AuthorizedScopeGrant.
   * All scope/permission semantics derive from here.
   * Required invariant: authorizationGrantId === scopeGrant.grantId
   * Required invariant: scanId === scopeGrant.scanId
   */
  scopeGrant: AuthorizedScopeGrant;

  verification: VerifiedAuthorizationDecisionVerification;
}>;

// ---------------------------------------------------------------------------
// Establishment Request
//
// The closed input type supplied to the establishment service.
// Contains the raw trusted-boundary decision inputs.
// ---------------------------------------------------------------------------

export type EstablishVerifiedAuthorizationDecisionRequest = Readonly<{
  contractVersion: VerifiedAuthorizationDecisionContractVersion;
  kind: 'establish_verified_authorization_decision_request';

  assessmentId: string;
  scanId: string;
  authorizationDecisionId: string;
  authorizedActor: VerifiedAuthorizedActor;

  /** Only 'authorized' decisions may establish a verified artifact. */
  decision: 'authorized';
  decidedAt: string;

  /** The canonical M46 scope grant that embeds all permissions and boundaries. */
  scopeGrant: AuthorizedScopeGrant;
}>;

// ---------------------------------------------------------------------------
// Establishment Result
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecisionEstablishmentReasonCode =
  | 'verified_authorization_decision_established'
  | 'establishment_request_invalid'
  | 'actor_invalid'
  | 'scope_grant_invalid'
  | 'temporal_invariant_violated'
  | 'decision_not_authorized'
  | 'id_invariant_violated'
  | 'unexpected_establishment_failure';

export type EstablishVerifiedAuthorizationDecisionResult =
  | {
      status: 'established';
      reasonCode: 'verified_authorization_decision_established';
      decision: VerifiedAuthorizationDecision;
    }
  | {
      status: 'failed';
      reasonCode: Exclude<
        VerifiedAuthorizationDecisionEstablishmentReasonCode,
        'verified_authorization_decision_established'
      >;
      /** Safe reason message — never echoes unsafe caller input. */
      safeMessage: string;
    };

// ---------------------------------------------------------------------------
// Validation Result
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecisionValidationReasonCode =
  | 'valid_verified_authorization_decision'
  | 'not_runtime_established'
  | 'decision_invalid'
  | 'temporal_invariant_violated'
  | 'scope_grant_invalid'
  | 'unexpected_validation_failure';

export type ValidateVerifiedAuthorizationDecisionResult =
  | { status: 'valid'; reasonCode: 'valid_verified_authorization_decision' }
  | {
      status: 'invalid';
      reasonCode: Exclude<
        VerifiedAuthorizationDecisionValidationReasonCode,
        'valid_verified_authorization_decision'
      >;
      safeMessage: string;
    };

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

export type VerifiedAuthorizationDecisionClassification = Readonly<{
  createsRealFindings: false;
  createsPersistedEvidence: false;
  confirmsVulnerabilities: false;
  makesRiskClaims: false;
  makesSeverityClaims: false;
  makesImpactClaims: false;
  executesNetwork: false;
  executesTools: false;
  persistsData: false;
}>;
