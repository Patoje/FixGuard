# Passive Recon Boundary

This directory (`worker/src/v2/recon/passive/`) contains the passive recon adapters/executors for FixGuard V2.

## Milestone 31 Rules
*   **Guarded Adapter Path**: M31 adds a guarded `http.header.inspect` real adapter path.
*   **Opt-In Real Egress**: Real egress is explicit opt-in only via `RealHttpHeaderInspectTransport`.
*   **Default Hermetic Validation**: Default smokes and checks (`smoke:v2:recon`) use `FakeHttpHeaderInspectTransport` and remain network-free and DB-free.
*   **Policy Enforced Before Transport**: M30 policy must be evaluated before the transport is called.
*   **IP Guard**: Real transport validates DNS resolution against SSRF constraints before initiating an HTTP request.
*   **Bounded Collection**: M31 is not a crawler, scanner integration, or vulnerability validator. It performs a bounded `HEAD` request, never reads or persists response bodies, does not follow redirects, and strictly redacts credentials (cookies/auth) from headers.
