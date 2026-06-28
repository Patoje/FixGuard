# FixGuard V2 Application Service Boundary Plan (Milestone 24)

## Purpose
Introduce a narrow, safe facade layer (`AssessmentApplicationService`) that future API/UI/Queue elements can call safely. This guarantees that external entrypoints cannot reach directly into execution internals, storage repositories, runtime objects, or dangerous payload structures.

## Core Characteristics

### Allowed Responsibilities
* Map incoming commands to safe runtime methods.
* Map complex internal state (`AssessmentState`, `V2AssessmentSession`) out to clean, flat Data Transfer Objects (DTOs).
* Receive the `V2AssessmentRuntime` strictly via constructor dependency injection.
* Preserve the established Approval Boundary. All human approval operations must pass through the `V2AssessmentRuntime` to ensure proper audit logging and intent translation.

### Forbidden Responsibilities
* **No Database/Environment Logic:** It must not create connection pools, repositories, or runtimes. It remains fully agnostic of the composition layer (e.g., Postgres boundaries).
* **No Internal Exposure:** It must never expose `CapabilityRequest`, `ExecutionRequest`, `V2AssessmentSession`, or DB handles.
* **No Executable Payload Exposure:** It must rigorously strip or avoid exposing `binary`, `args`, `env`, `command`, `shell`, or `stdin`.

## Intended Call Chain (Future)
* Bootstrap/Composition constructs Runtime and AssessmentApplicationService.
* API/UI/Worker -> AssessmentApplicationService -> V2AssessmentRuntime -> Repository/Tools

## Safety Notes
This milestone does not integrate with any real API or worker layer yet. It merely establishes the application boundary. Furthermore, Postgres remains an explicit opt-in composition detail, and is not elevated to a default. This milestone focuses entirely on interface safety.
