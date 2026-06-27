# FixGuard AI Instructions

You are working on FixGuard V2.

Core architecture rule:

Tools execute. Intelligence decides. Humans authorize.

Respect these boundaries:

- V2 code lives under worker/src/v2.
- Do not import V1 modules into V2.
- Do not modify the legacy V1 system unless explicitly requested.
- Execution Core executes capabilities only.
- Intelligence Layer interprets evidence and creates recommendations only.
- Approval Boundary must approve recommendations before they become executable CapabilityRequests.
- Do not bypass the Approval Boundary.
- Do not create executable requests directly from intelligence rules.
- Do not use shell string commands.
- Do not use command interpolation.
- Use structured execution requests with binary and args arrays.
- Tool adapters prepare execution requests.
- Runners execute.
- Parsers parse raw output into evidence.
- Intelligence must not know concrete tool names when reasoning.
- Recommendations must not contain binary, args, shell commands, or executable parameters.

Before making significant changes:

1. Inspect the current V2 implementation.
2. Explain the architectural impact.
3. Prefer small, isolated changes.
4. Do not create a mega-orchestrator.
5. Keep smoke/demo harnesses separate from production runtime.

Relevant docs:

- FIXGUARD_V2_ARCHITECTURE.md
- FIXGUARD_V2_IMPLEMENTATION_STATUS.md
