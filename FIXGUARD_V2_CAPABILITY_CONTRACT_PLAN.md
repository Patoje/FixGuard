# FixGuard V2 Capability Contract Plan

## Goal
Add a standalone safe capability contract boundary that defines and validates safe capability metadata and safe capability inputs before V2 adds real scanner or recon flows.

## What is a Capability?
A capability is a **defensive intent metadata definition**. It is NOT an `ExecutionRequest`, nor is it a command. It is not persisted. The goal is to explicitly separate intention/metadata from operational execution (e.g., shell, process spawn).

## Responsibilities
- **Safe Definition**: Provide static TypeScript definitions (`CapabilityDefinition`) to document the purpose, risks, and shapes of a capability (e.g. `http_probe`, `subdomain_discovery`).
- **Safe Input Validation**: Enforce that capability inputs (`SafeCapabilityInput`) do not leak shell/process-level executable key mappings (like `binary`, `command`, `spawn`). Inputs are strictly limited in depth and forbid functions, symbols, and `undefined` to maintain strict JSON serialization safety.
- **Capability Registry**: Register definitions and validate capability inputs against those definitions.

## Boundaries and Limitations
- The `CapabilityRegistry` does **not** execute tools, spawn processes, or resolve commands.
- It does not interact with the Postgres database.
- It is entirely decoupled from the runtime execution orchestrator. Real scanner execution remains future work.
- Existing `CapabilityRequest` remains untouched to prevent scope creep into persisted layers.

## Validation
A deterministic, database-free smoke test validates:
- Registration of safe capabilities.
- Rejection of duplicate IDs and capabilities containing forbidden executable keywords (`binary`, `args`, `env`, `command`, `shell`, `stdin`, `spawn`, `exec`, `process`, etc.) at both top and nested levels.
- Input validations against forbidden shapes and keywords.
