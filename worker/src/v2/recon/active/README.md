# FixGuard V2 Active Recon Boundary

This boundary models the contracts and adapter interfaces for active target interactions.

## Core Rules
- **No exploitation:** Active Recon is not exploitation.
- **No vulnerabilities:** Active Recon does not perform vulnerability validation.
- **No scanners:** Active Recon does not orchestrate scanner binaries.
- **M34 is network-free:** The current milestone utilizes a fake adapter only.
- **No findings:** Probes do not create findings.
- **No persisted evidence:** Observations are modeled purely in-memory and are not persisted as product evidence.
- **Policy-gated:** All probes are gated by the M30 egress policy before execution.
- **Audit-safe:** All decisions map safely to the M33 control-plane audit model in smoke tests.

Real active probe adapters wait for M35. Scanner integrations require separate milestones.
No production-readiness claims are made for active recon in M34.
