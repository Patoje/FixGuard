# FixGuard V2 Capability Registry Integration Plan

## Context
Milestone 28 integrates the Capability Registry from M27 into the approval and runtime translation path. 
This enforces that human approval can only spawn transient `CapabilityRequest` objects for registered safe capabilities, and validates the final configuration.

## Requirements
* Approval translation must consult the `CapabilityRegistry`.
* Unknown capabilities must be rejected and throw `CapabilityValidationError` rather than a tool execution error.
* Unsafe configurations must be rejected and throw `CapabilityValidationError`.
* Rejections must abort the approval without mutating the session (no snapshots, no audit entries, no execution failure records, pending recommendation stays pending).
* `CapabilityRequest` remains transient and un-persisted.
* `ExecutionRequest` is never persisted.
* Registry remains strictly metadata and validation logic. It does not spawn or execute.
* Safe default capabilities (`subdomain_discovery`, `http_probe`) are provided in memory to allow existing smokes to pass.

## Outcome
By enforcing validation within `IntentTranslator` (and allowing the resulting `CapabilityValidationError` to reject smoothly in `V2AssessmentRuntime`), we guarantee that any unauthorized tools or injected executable parameters never reach the orchestrator or persistence layer.
