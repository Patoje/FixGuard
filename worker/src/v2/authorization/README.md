# Verified Authorization (M37)

Provides structural and semantic validation for Verified Authorization Decisions, which act as the unforgeable root of trust for all active scanning operations in V2.

## Key Properties
- **Recursive Immutability**: All decisions returned by `establishVerifiedAuthorizationDecision` are deeply frozen to prevent runtime tampering.
- **Forgery Resistance**: M37 enforces strict shape contracts and prevents unauthorized modifications to scope grants or actor identities.
- **Strict Lineage**: The returned decision perfectly matches the evaluation lineage and is bound securely to the scope grant.

## M56A Enhancements
- Completed strict closed-key validation for all nested objects.
- Removed generic type omissions and implemented rigid contract adherence.
- Unified classification validation with the M46 Authorized Scope Policy.
