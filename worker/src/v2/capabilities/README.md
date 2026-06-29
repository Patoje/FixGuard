# FixGuard V2 Capability Contract Boundary

A capability is a typed defensive intent, not a command.

The capabilities directory establishes a strict metadata boundary to define what FixGuard is allowed to do, validating safe capability metadata and capability input *before* V2 starts adding real scanner and recon flows.

## What is a Capability?

* A capability is a **defensive intent metadata** definition.
* A capability is **not a command**.
* A capability is **not** an `ExecutionRequest`.
* A capability is **not** a persisted executable payload.

## Responsibilities of CapabilityRegistry

* Registers safe `CapabilityDefinition`.
* Rejects definitions containing forbidden executable keys recursively.
* Rejects duplicate IDs.
* Resolves definitions by ID.
* Lists definitions as cloned/plain objects.
* Validates safe inputs for a registered capability.

## Non-Responsibilities (What it explicitly does not do)

* No real scanner execution.
* No process spawning or shell execution.
* No adapter selection.
* No SQLMap/Nuclei/FFUF/Katana/HTTPX execution.
* No API/UI/queues/workers.
* No DB access.
* No approval decisions.
* No persistence or runtime orchestration.

## Execution and Production Readiness

Real scanner execution remains future work. V1 is only a source of concepts, not code to patch or import blindly. Default validation remains DB-free. This module does **not** claim production readiness; it simply defines the boundaries and validation structures for future integrations.

### Milestone 28 updates
In M28, the registry was integrated into the approval translation path.
- Approval now requires a registered safe capability id.
- The registry validates the final safe config before transient CapabilityRequest creation.
- The registry is strictly metadata/validation, not a runner. No real scanner execution added.
- CapabilityRequest remains transient, and ExecutionRequest is never persisted.
- There are no production readiness claims.

### Milestone 29 updates
In M29, http.header.inspect was registered as a passive capability. 
It supports deterministic, fixture-backed observation of safe HTTP header metadata without any real network fetch.
