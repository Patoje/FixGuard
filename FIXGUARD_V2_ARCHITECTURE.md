# FixGuard V2 Architecture

> **Core Philosophy: "Tools execute. Intelligence decides. Humans authorize."**

This document is the primary architectural reference for the FixGuard V2 system.
It must be read by every developer or AI agent joining the project before making any changes.
It describes architectural boundaries, design intent, and inviolable rules.
It does not describe implementation details, APIs, or UI.

---

## 1. Project Vision

FixGuard is a **human-in-the-loop security assessment assistant**.

It is not an autonomous exploit engine.
It does not execute attacks without explicit human approval.
It does not chain exploitation steps automatically.
It does not maintain long-term memory across unrelated engagements.

### What FixGuard does:

1. **Discovers** — runs reconnaissance capabilities against an authorized target.
2. **Accumulates** — stores structured evidence from every tool execution.
3. **Analyzes** — correlates evidence to build a current understanding of the target.
4. **Recommends** — proposes specific attack actions based on what is known.
5. **Pauses** — waits for an authorized human operator to approve or reject each recommendation.
6. **Executes** — runs only approved actions through the execution core.
7. **Updates** — feeds new results back into intelligence, deepening understanding.

This cycle repeats until the operator ends the session.

### What FixGuard is not:

- It is not a one-click exploit framework.
- It is not a vulnerability scanner that runs autonomously.
- It is not a penetration testing autopilot.
- It is not an LLM-driven agent that dynamically writes exploits.

Every active exploitation step requires an explicit, deliberate human decision.
This is not a limitation of the current implementation. It is a permanent design principle.

---

## 2. High-Level Architecture

FixGuard V2 is composed of three independent layers separated by strict data contracts.
No layer may import or call another layer directly.
Data flows in one direction only.

### Complete System Flow

```
+-------------------------------------------------------------+
|                    EXECUTION CORE                           |
|                                                             |
|   CapabilityRequest                                         |
|         |                                                   |
|   ToolDefinition  (resolved by registry)                    |
|         |                                                   |
|   Adapter         (translates intent to command)            |
|         |                                                   |
|   ExecutionRunner (runs process, captures output)           |
|         |                                                   |
|   Parser          (transforms output to findings)           |
|         |                                                   |
|   EvidenceCollection                                        |
+-------------------------------------------------------------+
                          |
                          | EvidenceCollection
                          v
+-------------------------------------------------------------+
|                  INTELLIGENCE LAYER                         |
|                                                             |
|   EvidenceAccumulator  (collects all findings)              |
|         |                                                   |
|   CorrelationEngine    (deduplicates, combines signals)     |
|         |                                                   |
|   TargetProfileBuilder (builds target understanding)        |
|         |                                                   |
|   RecommendationEngine (applies rules, emits proposals)     |
|         |                                                   |
|   AttackRecommendation                                      |
+-------------------------------------------------------------+
                          |
                          | AttackRecommendation
                          v
+-------------------------------------------------------------+
|                  APPROVAL BOUNDARY                          |
|                                                             |
|   Recommendation Inbox   (holds pending proposals)          |
|         |                                                   |
|   Approval Gateway       (human operator interface)         |
|         |                                                   |
|   Intent Translator      (converts approval to request)     |
|         |                                                   |
|   CapabilityRequest  -->  back to Execution Core            |
+-------------------------------------------------------------+
```

### Why the Flow is Unidirectional

Each layer communicates with the next using only frozen data contracts.
No layer holds a reference to the layer before or after it.

- The **Execution Core** receives a `CapabilityRequest` and returns an `EvidenceCollection`. It does not know Intelligence exists.
- The **Intelligence Layer** receives an `EvidenceCollection` and emits an `AttackRecommendation`. It does not know the Execution Core exists.
- The **Approval Boundary** receives an `AttackRecommendation` and, after human approval, emits a new `CapabilityRequest`. It does not modify either layer.

This design guarantees that:
- Automated exploitation is structurally impossible.
- Layers can be independently tested, replaced, or evolved.
- The system is auditable at every transition point.

---

## 3. Architectural Boundaries

### Execution Core

**Role:** Executes. Nothing else.

- Accepts a `CapabilityRequest` specifying what capability is needed and against which target.
- Resolves the appropriate tool via the `ToolAdapterRegistry`.
- Translates the request into a safe, shell-free process execution command.
- Captures stdout, stderr, exit codes, and duration.
- Transforms raw output into structured `Finding` objects.
- Returns an `EvidenceCollection`.

**What the Execution Core does NOT do:**
- It does not decide what should be scanned.
- It does not prioritize or schedule its own runs.
- It does not interpret findings for security meaning.
- It does not know the Intelligence Layer exists.
- It does not contain business logic of any kind.

### Intelligence Layer

**Role:** Reasons. Nothing else.

- Receives `EvidenceCollections` and accumulates them over a session.
- Correlates findings across multiple tool executions.
- Maintains a `TargetProfile` representing the current understanding of the target.
- Applies declarative rules to the profile to generate `AttackRecommendations`.

**What the Intelligence Layer does NOT do:**
- It does not execute any tool or process.
- It does not directly communicate with the Execution Core.
- It does not name specific tools in its rules.
- It does not make decisions about human approval.
- It does not automatically chain attack steps.

### Approval Boundary

**Role:** Human authorization bridge. Nothing else.

- Holds `AttackRecommendations` in an inbox until a human acts.
- Exposes an interface for the operator to inspect, approve, or reject each recommendation.
- On approval, translates the immutable `AttackRecommendation` plus the operator's overrides into a valid `CapabilityRequest`.
- Records an immutable audit log of who authorized what and when.

**What the Approval Boundary does NOT do:**
- It does not modify `AttackRecommendations` internally.
- It does not call the Intelligence Layer.
- It does not call the Execution Core directly (it only emits a `CapabilityRequest` into the pipeline).
- It does not automatically approve anything.

---

## 4. Execution Core Contracts

The following data structures are **permanently frozen**.
They must not be changed without a formal architectural review.

### CapabilityRequest
The input to the Execution Core.

| Field | Type | Purpose |
|---|---|---|
| `capability` | `string` | The named capability being requested (e.g., `subdomain_discovery`) |
| `target` | `TargetContext` | The target this capability should be run against |
| `config` | `Record<string, unknown>` | Optional adapter-specific tuning parameters |

`capability` is always a semantic concept, never a tool name.

### TargetContext
Describes the target of an execution.

| Field | Type | Purpose |
|---|---|---|
| `uri` | `string` | The primary target URI or domain |
| `headers` | `Record<string, string>?` | Optional request headers (auth tokens, custom headers) |
| `env` | `string?` | Target environment label (e.g., `staging`, `production`) |

`TargetContext` is intentionally extensible. Future capabilities (gRPC, cloud, mobile) may require additional fields.

### ExecutionRequest
The instruction handed to the `ExecutionRunner`.

| Field | Type | Purpose |
|---|---|---|
| `binary` | `string` | The exact binary name to execute |
| `args` | `string[]` | Arguments as a strict array — never a concatenated string |
| `env` | `Record<string, string>?` | Environment variable overrides |
| `timeoutMs` | `number` | Hard execution timeout |

`binary` and `args` must always remain separate. Shell interpolation is permanently forbidden.

### RawExecutionOutput
The raw result captured by the `ExecutionRunner`.

| Field | Type | Purpose |
|---|---|---|
| `stdout` | `string` | Captured standard output |
| `stderr` | `string` | Captured standard error |
| `exitCode` | `number` | Process exit code |
| `durationMs` | `number` | Wall-clock execution time |
| `timedOut` | `boolean` | Whether the process was terminated by timeout |

### Finding
A single structured observation produced by a `Parser`.

| Field | Type | Purpose |
|---|---|---|
| `id` | `string` | Unique identifier for this finding |
| `type` | `string` | The finding category (maps to capability) |
| `severity` | `info / low / medium / high / critical` | Severity level |
| `title` | `string` | Human-readable summary |
| `description` | `string` | Full description of the finding |
| `target` | `string` | The specific artifact this finding describes |
| `evidence` | `string` | Raw evidence string |
| `confidence` | `number` | Confidence score between 0 and 1 |
| `metadata` | `Record<string, unknown>` | Tool-specific additional data |

### EvidenceCollection
The complete output of one execution cycle.

| Field | Type | Purpose |
|---|---|---|
| `findings` | `Finding[]` | All structured findings from this execution |
| `metadata` | `Record<string, unknown>` | Execution context (duration, parse errors, source tool) |

An empty `findings` array is a valid state. It means the tool ran cleanly and found nothing.

### ToolDefinition
The wiring record that describes a tool and maps it to a capability.

| Field | Type | Purpose |
|---|---|---|
| `capability` | `string` | The capability this tool implements |
| `adapter` | `ToolAdapter` | The adapter instance for this tool |
| `parser` | `Parser` | The parser instance for this tool's output |
| `requirements` | `ToolRequirements` | Binary name, supported platforms, version constraints |
| `metadata` | `ToolMetadata` | Author, version, homepage, description |

`ToolDefinition` is the exclusive unit of extension in the Execution Core.
Adding a new tool means registering a new `ToolDefinition`. Nothing else changes.

---

## 5. Tool System Design

### Tools Are Capabilities, Not Scanners

The system does not think in terms of tools. It thinks in terms of **capabilities**.

A capability is a named security function:
```
subdomain_discovery
web_crawling
vulnerability_scan
javascript_analysis
secret_detection
```

A tool is an implementation of a capability:
```
Subfinder   implements  subdomain_discovery
Amass       implements  subdomain_discovery
Katana      implements  web_crawling
Nuclei      implements  vulnerability_scan
```

The Intelligence Layer and Approval Boundary reason exclusively about capabilities.
Which tool implements a capability is an Execution Core concern, resolved by the `ToolAdapterRegistry`.

### The ToolAdapterRegistry

The registry is a map of `capability -> ToolDefinition[]` (multiple tools per capability).

When the Execution Core receives a `CapabilityRequest`, the registry:
1. Finds all registered tools for that capability.
2. Checks which tools are available in the current environment (binary present, platform supported).
3. Returns the highest-priority available `ToolDefinition`.

This allows graceful fallback: if Subfinder is not installed, the registry may fall back to Amass for the same `subdomain_discovery` capability without any other component being aware of the substitution.

### ToolDefinition Wiring

The `ToolAdapter` and `Parser` are wired together inside the `ToolDefinition`, not inside each other.

- The `Adapter` does not know which `Parser` will consume its output.
- The `Parser` does not know which `Adapter` produced its input.
- They are matched by the `ToolDefinition` record, which the Orchestrator consults.

This ensures Adapters and Parsers can be independently replaced, tested, and versioned.

---

## 6. Intelligence Layer Design

### EvidenceAccumulator

- A passive, session-scoped store.
- Receives every `EvidenceCollection` produced by the Execution Core during a session.
- Stores findings in chronological order, tagged with capability and source tool.
- Contains zero analysis logic. It is a ledger, not a reasoner.

### CorrelationEngine

- Reads from the `EvidenceAccumulator`.
- Detects duplicate findings across different tool executions.
- Combines corroborating signals to increase confidence scores.
- Flags contradictions between findings.
- Produces a deduplicated, confidence-weighted `CorrelatedFindingSet`.

### TargetProfileBuilder

- Reads from the `CorrelatedFindingSet`.
- Applies `ProfilerRules` to extract semantic meaning from correlated signals.
- Builds and maintains the `TargetProfile`: the system's current understanding of the target.
- The `TargetProfile` may contain: detected technologies, framework versions, exposed endpoints, authentication mechanisms, and identified attack surface areas.
- `ProfilerRules` are externalized — the builder evaluates rules, it does not hardcode knowledge.

### RecommendationEngine

- Reads only from the `TargetProfile`.
- Applies declarative `RecommendationRules` to produce `AttackRecommendation` objects.
- Rules are predicates over the `TargetProfile` that emit a recommendation when satisfied.

### Critical Rule: Intelligence Layer Rules Must Never Reference Tools

Rules reason over **profile concepts** only.

CORRECT:
```
IF profile.technologies contains { name: 'Next.js', version: '>= 14' }
AND profile.exposedCapabilities contains 'server_actions'
THEN recommend capability: 'server_actions_exploit'
```

FORBIDDEN:
```
IF Next.js is detected
THEN run nuclei with template nextjs-server-action-rce
```

Tool names inside Intelligence rules are a critical architectural violation.
Rules must survive tool replacement without modification.

---

## 7. Human Approval Model

### AttackRecommendation Is Not Executable

An `AttackRecommendation` is a **proposal addressed to a human**.
It contains no binary paths, no argument arrays, and no execution parameters.

| Field | Purpose |
|---|---|
| `id` | Unique identifier for this recommendation |
| `capability` | The capability being proposed (e.g., `bola_exploit`) |
| `targetContext` | The target this applies to |
| `rationale` | Human-readable explanation of why this is recommended |
| `confidence` | How confident the system is that this is a valid attack path |
| `severity` | Estimated severity if the attack succeeds |

### The Approval Lifecycle

1. The Intelligence Layer emits an `AttackRecommendation` and stores it in the **Recommendation Inbox**.
2. The human operator reviews the recommendation, including its rationale and confidence.
3. The operator makes an `ApprovalDecision`:
   - **Approve**: proceed as recommended.
   - **Approve with Overrides**: proceed but with operator-specified configuration changes.
   - **Reject**: discard the recommendation.
4. On approval, the **Intent Translator** synthesizes a valid `CapabilityRequest` from the recommendation and the operator's decision.
5. The `CapabilityRequest` is submitted to the Execution Core.
6. An audit record is created capturing the operator identity, timestamp, and exact configuration authorized.

### No Automatic Exploitation

No code path may create a `CapabilityRequest` that references an attack capability without a corresponding `ApprovalDecision`. This is not a policy. It is a structural guarantee enforced by the Approval Boundary's Intent Translator being the only component authorized to emit `CapabilityRequests` for non-recon capabilities.

---

## 8. Supported Target Philosophy

FixGuard is designed to support a wide range of target types without architectural modification.

### Supported Target Categories

Modern Web Applications:
- React, Vue, Angular single-page applications
- Next.js, Nuxt, SvelteKit server-side frameworks
- REST APIs, GraphQL APIs, gRPC services
- Cloud services (AWS, Azure, GCP)

Legacy Applications:
- WordPress and other CMS platforms
- PHP, ASP.NET, Java EE applications
- Unversioned or end-of-life software

Infrastructure:
- Subdomain and DNS infrastructure
- TLS and certificate analysis
- Cloud storage and misconfiguration
- Container and Kubernetes environments

Mobile and API Backends:
- Mobile API endpoints
- OAuth and authentication flows
- Business logic and authorization flaws

### How New Technology Support Is Added

New technology support **never requires modifying the Execution Core or Intelligence Core**.

It requires adding:
1. A new Capability name if the technology requires a new class of action.
2. A new Adapter if a new tool implements that capability.
3. A new Parser if the tool produces a new output format.
4. New ProfilerRules if the technology produces new fingerprinting signals.
5. New RecommendationRules if the technology introduces new attack surfaces.

Adding WordPress support: add WordPress fingerprinting rules, WordPress-specific capabilities, and WordPress-aware recommendations. The Core does not change.

---

## 9. Current Implementation Status

### Completed (V2 Foundation)

- `worker/src/v2/core/ExecutionContracts.ts` — CapabilityRequest, TargetContext, ExecutionRequest, RawExecutionOutput
- `worker/src/v2/core/Evidence.ts` — Finding, EvidenceCollection
- `worker/src/v2/core/ProcessRunner.ts` — ProcessRunner interface and LocalProcessRunner implementation
- `worker/src/v2/core/MinimalOrchestrator.ts` — Central execution sequencer
- `worker/src/v2/adapters/ToolAdapter.ts` — ToolAdapter interface and ValidationResult
- `worker/src/v2/adapters/SubfinderAdapter.ts` — First V2 adapter implementation
- `worker/src/v2/adapters/ToolAdapterRegistry.ts` — Capability-to-adapter registry
- `worker/src/v2/parsers/Parser.ts` — Parser interface
- `worker/src/v2/parsers/SubfinderJsonParser.ts` — First V2 parser implementation

The Subfinder vertical slice is the first working proof of the V2 architecture.
It demonstrates the full CapabilityRequest to EvidenceCollection flow without invoking any V1 code.

### Not Yet Implemented

- Full ToolDefinition registry (replacing current adapter-only registry)
- Intelligence Layer (EvidenceAccumulator, CorrelationEngine, TargetProfileBuilder, RecommendationEngine)
- Approval Boundary (Recommendation Inbox, Approval Gateway, Intent Translator)
- Audit logging
- Additional capabilities beyond subdomain_discovery
- UI integration
- Database persistence of sessions

---

## 10. Rules for Future Contributors

These rules are inviolable. Violating them requires an architectural review before the change is accepted.

### DO NOT

- **Modify V1 code** (cliRunner.ts, targetedOrchestrator.ts, existing scanners) unless fixing critical bugs with an explicit migration plan.
- **Add automatic exploitation** at any point. Every attack capability requires explicit human approval. There are no exceptions.
- **Put tool knowledge inside the Intelligence Layer**. Rules must reason over profile concepts. Tool names (subfinder, nuclei, katana) must never appear in Intelligence rules.
- **Make AttackRecommendation executable**. It must never contain binary paths, argument arrays, or execution parameters. It is a proposal, not a command.
- **Couple Adapters and Parsers directly**. They are wired together only inside ToolDefinition records. Neither may import the other.
- **Put business logic in the Orchestrator**. The MinimalOrchestrator is a sequencer and router. If you find yourself writing conditional logic based on tool type or finding content inside the orchestrator, that logic belongs in the Intelligence Layer.
- **Use shell string interpolation** for any process execution. Arguments must always be passed as string arrays to spawn() with shell: false.
- **Bypass the Approval Boundary** by creating CapabilityRequests for attack capabilities programmatically without an ApprovalDecision.
- **Let layers import each other**. The three layers communicate only through data contracts. No cross-layer imports.

### DO

- **Extend by adding ToolDefinitions** when adding new tool support.
- **Extend by adding rules** when adding new technology fingerprinting or attack recommendations.
- **Keep components single-responsibility**. If a component is doing two things, split it.
- **Respect the data flow direction**. Evidence flows forward. Decisions flow forward. Nothing flows backward automatically.
- **Tag every CapabilityRequest from approved attacks** with the sourceRecommendationId so evidence can be traced back to the human decision that authorized it.

---

## 11. Future Expansion Roadmap

All planned expansion enters the system through the established extension points.
None of it requires modifying the frozen Core.

### Planned Capabilities

- **WordPress intelligence** — fingerprinting rules, plugin enumeration capabilities, WordPress-specific attack recommendations.
- **Modern SPA analysis** — JavaScript source map analysis, Next.js Server Actions probing, hydration attack surface mapping.
- **API security** — REST endpoint enumeration, GraphQL introspection, gRPC reflection, BOLA/IDOR analysis.
- **Authenticated testing** — token injection via TargetContext.headers, session-aware crawling capabilities.
- **Cloud misconfiguration** — S3 bucket discovery, IAM analysis, metadata endpoint probing.
- **Deeper attack paths** — multi-step exploitation sequences, each step requiring individual human approval.

### Architecture Evolution Points

The following have been identified as future structural evolution points that may require targeted architectural decisions (not rewrites):

1. **Streaming evidence** — if tools stream output incrementally, the EvidenceAccumulator may need event-driven processing.
2. **Multi-target sessions** — if assessments span multiple related targets, the TargetProfile model will need to support cross-target relationship mapping.
3. **Non-CLI execution** — when a native-mode Playwright or cloud-API capability is added, the ExecutionRequest type discriminator should be activated.

---

## 12. Core Philosophy

FixGuard is not a collection of scanners.

It is an **adaptive assessment engine** where:

> **Evidence creates understanding.**
> **Understanding creates recommendations.**
> **Humans decide actions.**
> **Approved actions create new evidence.**

The system gets smarter with each approved cycle. Each round of execution deepens the TargetProfile. A deeper profile produces more targeted, high-confidence recommendations. The operator stays in full control at every escalation boundary.

This architecture is designed to remain relevant across technologies that do not yet exist, against targets that have not yet been built, using capabilities that have not yet been written.

The Core does not change. The world plugs into it.

---

*Document Version: 1.0 — Architecture Frozen*
*This document reflects the system as designed. See the implementation status section for what is currently built.*

Note:
The current implementation is an intermediate migration state.
The final frozen architecture uses ToolDefinition as the extension boundary.


## Intelligence Layer Rule

The Intelligence Layer may transform evidence into understanding.
It may never transform understanding directly into execution.

