# FixGuard V2 Real HTTP Header Inspect Plan (M31)

## Overview
Milestone 31 introduces the guarded, real network-backed passive adapter for the `http.header.inspect` capability.

## Architecture Boundaries
1. **Adapter Enforces Policy**: Before calling the transport, the `GuardedHttpHeaderInspectAdapter` evaluates the target URL against the M30 Egress Policy. If the decision is `block` or `candidate`, it throws a controlled policy error and NEVER invokes the transport.
2. **Real vs Fake Transport**: `HttpHeaderInspectTransport` abstraction separates the policy/sanitization logic from the actual network fetch. `FakeHttpHeaderInspectTransport` is used for default smoke testing (DB-free, network-free). `RealHttpHeaderInspectTransport` handles actual outbound HEAD requests.
3. **Resolved-IP Guard**: The `RealHttpHeaderInspectTransport` executes DNS resolution explicitly before making an HTTP connection. If the resolved IPs are internal, private, loopback, multicast, or otherwise SSRF-risky, it drops the connection.
4. **Header Sanitization**: The adapter preserves only safe metadata (such as `Server`, `Content-Type`) and aggressively redacts credentials (`Set-Cookie`, `Authorization`, `token`). Only the first 50 headers or 4096 bytes are consumed to prevent denial of service. Response bodies are never read.

## Non-Default Egress
M31 real egress is explicit and opt-in. The default execution environment (`check:v2`, `smoke:v2`) explicitly uses the fake transport, maintaining hermetic validation. `V2AssessmentRuntime` does not read environment variables to magically switch to real egress.

## No Vulnerability Claims
The evidence produced by M31 always contains `findings: []`. It gathers defensive reconnaissance observations but does not simulate an active attack or produce inflated risk scores.

## Opt-in Real Validation (M32)
M32 introduces a formal, explicit, opt-in validation path for the real HTTP header inspect adapter.
* **Opt-in Only**: M32 requires exact environment variables to run.
* **Validation Only**: M32 proves real egress works but does not add real egress executors to the production composition.
* **Hermetic Defaults**: M32 validation (`smoke:v2:recon:real`) is intentionally excluded from `check:v2` and `smoke:v2`.
* **Bounded Output**: M32 performs exactly one bounded `HEAD` request and produces no vulnerability claims or findings.
