# FixGuard V2 Passive Recon Vertical Flow Plan

## Context
Milestone 29 introduces the first passive recon vertical flow: `http.header.inspect`. 
This capability operates passively by observing HTTP header metadata.

## Implementation Details
1. **Fixture-Backed Only**: M29 relies strictly on deterministic fixture execution. Real network fetch is deferred to a future milestone after a separate scope/egress policy boundary exists.
2. **No Scanners**: M29 forbids real scanners, shell execution, or child processes to ensure this capability operates cleanly as a metadata-only passive executor.
3. **Capability**: The `http.header.inspect` capability is registered in the `DefaultCapabilityRegistry`.
4. **Executor Boundary**: A new `PassiveCapabilityExecutor` contract is established under `worker/src/v2/recon/passive/`, providing a clean injection boundary for deterministic observation generation.
5. **Runtime Injection**: `V2AssessmentRuntime` accepts an optional `passiveExecutor`. V2AssessmentRuntime routes only explicit approved http.header.inspect requests through the injected passive executor. It does not broadly dispatch every capability with category passive. Future passive capabilities require their own explicit contract, routing decision, and smoke coverage before execution. startInitialRecon does not trigger the passive executor. http.header.inspect requires explicit human approval.
6. **Approval Boundary**: The M28 capability registry validation rules strictly apply. Unsafe overrides are rejected before execution.

## Evidence Strategy
* **Evidence-Only**: M29 creates evidence, not vulnerability findings.
* **Separation of Facts**: Observed facts (like status code and header values) are explicitly separated from inferred signals (like potential framework hints).
* **Forbidden Fields**: The evidence omits the response body, auth headers, cookies, tokens, and any executable parameters.

## Production Status
This milestone establishes the boundary and flow but intentionally avoids real network requests. It makes no production-readiness claims.
