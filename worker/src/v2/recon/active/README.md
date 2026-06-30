# FixGuard V2 Active Recon Boundary

This boundary models the contracts and adapter interfaces for active target interactions.

## Core Rules
- **No exploitation:** Active Recon is not exploitation.
- **No vulnerabilities:** Active Recon does not perform vulnerability validation.
- **No scanners:** Active Recon does not orchestrate scanner binaries.
- **M35 Real Probe:** M35 introduces explicit opt-in real execution for `http.robots.inspect` only.
- **No crawler:** The real adapter performs exactly one bounded GET request (timeout 3000ms, max 16 KiB, no redirects).
- **Safe Metadata Only:** No raw bodies, headers, URLs, or directive paths are emitted or persisted.
- **No findings:** Probes do not create findings.
- **No persisted evidence:** Observations are modeled purely in-memory and are not persisted as product evidence.
- **Policy-gated:** All probes are gated by the M30 egress policy before execution.
- **Resolved-IP guard:** Real adapters use the M31-style DNS resolution guard to block internal/SSRF targets at the socket level.
- **Audit-safe:** All decisions map safely to the M33 control-plane audit model in smoke tests.

- **M36 DB-Free Sanitizers:** M36 introduces DB-free, network-free metadata sanitizers for document-like probes (robots.txt, security.txt).
- **No Real security.txt Network:** M36 does not execute real network requests for security.txt. The real adapter remains completely untouched from M35.
- **Fixed Shapes:** Sanitizers emit strictly fixed shapes. No raw payload values or generic metadata containers (`[key: string]: unknown`) exist.
- **Fake Fixtures:** Fake active recon adapter responses are strictly mock behavior to prove fixed shapes. They do not represent real target evidence.

`security.txt` real network (M37) is explicit opt-in only behind `FIXGUARD_V2_REAL_ACTIVE_RECON_CONFIRM_AUTHORIZED=I_CONFIRM_AUTHORIZED_SECURITY_TXT_TARGET`. Scanners remain future milestones. M35 is explicit opt-in only. No production-readiness claims are made.

- **M38 Runner Boundary:** M38 introduces a controlled DB-free active recon document probe runner (`ActiveReconDocumentProbeRunner.ts`) that orchestrates `http.robots.inspect` and `http.security_txt.inspect` only.
- **Explicit URLs Only:** M38 uses explicit per-probe target URLs. It does not derive paths from origins (`/robots.txt` or `/.well-known/security.txt` are not auto-generated). Origin-derived planning is deferred to M39.
- **Dependency Injection:** The runner accepts a fixed injected adapter table (`ActiveReconDocumentProbeAdapters`). It does not instantiate real adapters by default.
- **Policy-First:** M38 evaluates M30 egress policy per-target before any adapter invocation. Blocked/candidate decisions never reach adapters.
- **No New Probe Kinds:** M38 does not add probe kinds beyond `http.robots.inspect` and `http.security_txt.inspect`.
- **No Modifications to Real Adapters:** `RealActiveReconHttpProbeAdapter.ts` and `RealActiveReconSecurityTxtProbeAdapter.ts` are untouched.
- **No Persistence:** The runner does not persist anything, create findings, or create evidence.
- **No Runtime/Storage/API/UI:** M38 does not integrate runtime, storage, Postgres, API, or UI.
- **Safe Result Shape:** Result never includes raw targetUrl, raw bodies, raw headers, raw request/response, or any finding/evidence/risk/severity/impact/exploit claims.
- **Real Opt-in Combined Smoke:** M38 may inject real adapters via an explicit opt-in combined smoke (`smoke:v2:recon:active:runner:real`), excluded from all defaults.
