# Egress Policy Boundary

This directory (`worker/src/v2/recon/policy/`) implements the deterministic Scope and Egress Policy Boundary for FixGuard V2 (Milestone 30).

## Core Principles
*   **Think like an attacker. Collect like an attacker. Validate like an attacker. Report and control like a defensive audit platform.**
*   **Permissive inside authorized public scope.**
*   **Strict outside authorized scope.**
*   **Preserve everything. Classify sensitive material safely.**

## Rules
*   **No Real Network**: This module is policy-only. It performs string and URL analysis to decide if a target is authorized. It does **not** fetch, resolve DNS, or execute processes. Future real adapters must use this policy before every request.
*   **SSRF Blocking**: Link-local, localhost, RFC1918 private IPs, and cloud metadata targets are strictly rejected.
*   **Candidate vs. Executable**: Discovered subdomains are explicitly modeled as `DiscoveredScopeCandidate`. They do not automatically become executable targets without human authorization or a broader scope configuration.
*   **Decision Persistence**: Blocked policy decisions are purely deterministic decisions and **are not vulnerability findings**. Future milestones may persist them as audit or policy events.
*   **Redirects**: Redirects are not followed by this policy. Future real HTTP adapters must re-validate the egress policy on every redirect hop.
*   **Sensitive Data**: Query strings are normalized deterministically. Sensitive keys (e.g. `token`, `password`, `api_key`) are classified safely, and `safeDisplayUrl` redacts their values. Future milestones will deal with sensitive artifact handling.
