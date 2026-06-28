# FixGuard V2 Application Service Boundary

This directory (`worker/src/v2/application`) contains the **AssessmentApplicationService**, which serves as the narrow, safe facade for future external entry points like API routes, UI controllers, or background workers.

## Purpose

* **Facade:** Exposes domain operations in terms of use-case commands instead of raw internal objects.
* **Safety:** Prevents external callers from reaching directly into runtime, storage, or execution internals.
* **DTO Mapping:** Transforms internal state into safe, plain-data Command/Result Data Transfer Objects (DTOs).

## Core Rules

* **No Executable Keys:** DTOs strictly omit executable fields (e.g., `binary`, `args`, `env`, `command`, `shell`, `stdin`) to ensure they cannot leak or be injected from external sources.
* **No Internal Leakage:** DTOs do not expose raw `CapabilityRequest`, `ExecutionRequest`, `V2AssessmentSession`, or DB/storage internals.
* **No Composition Ownership:** The Application Service receives the `V2AssessmentRuntime` via dependency injection. It does not instantiate runtimes, DB clients, repositories, or read env vars.
* **Future Flow:**
  * Bootstrap/Composition constructs Runtime and AssessmentApplicationService.
  * API/UI/Worker -> AssessmentApplicationService -> V2AssessmentRuntime -> Repository/Tools
