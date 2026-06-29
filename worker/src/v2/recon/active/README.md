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

`security.txt` real network and scanners are future milestones. M35 is explicit opt-in only. No production-readiness claims are made.
