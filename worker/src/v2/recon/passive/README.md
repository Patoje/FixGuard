# Passive Recon Boundary

This directory (`worker/src/v2/recon/passive/`) contains the passive recon adapters/executors for FixGuard V2.

## Milestone 31 Rules
*   **Guarded Adapter Path**: M31 adds a guarded `http.header.inspect` real adapter path.
*   **Opt-In Real Egress**: Real egress is explicit opt-in only via `RealHttpHeaderInspectTransport`.
*   **Default Hermetic Validation**: Default smokes and checks (`smoke:v2:recon`) use `FakeHttpHeaderInspectTransport` and remain network-free and DB-free.
*   **Policy Enforced Before Transport**: M30 policy must be evaluated before the transport is called.
*   **IP Guard**: Real transport validates DNS resolution against SSRF constraints before initiating an HTTP request.
*   **Bounded Collection**: M31 is not a crawler, scanner integration, or vulnerability validator. It performs a bounded `HEAD` request, never reads or persists response bodies, does not follow redirects, and strictly redacts credentials (cookies/auth) from headers.

## Milestone 32 Rules
*   **Explicit Opt-In Only**: M32 introduces an explicit, opt-in-only real egress validation script.
*   **Excluded from Defaults**: The M32 validation script (`smoke:v2:recon:real`) is intentionally excluded from `check:v2`, `smoke:v2`, and `smoke:v2:recon` to preserve the DB-free and external-network-free guarantees of default test paths.
*   **No Production Readiness Claims**: M32 proves that one bounded `HEAD` request can be executed securely. It does not validate production readiness or scanner integration.
*   **No Reusable Composition**: The smoke test constructs the real transport directly; no real egress executors are added to the application default composition yet.
