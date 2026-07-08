# M48: Comparison to Evidence Mapping Boundary

This milestone defines a DB-free boundary for mapping safe response comparison results (M47) to non-persisted evidence drafts.

## Responsibilities
- **Consume** safe `ResponseComparisonResult` objects from M47.
- **Produce** `EvidenceMappingDecision` and `EvidenceDraftEnvelope`.
- **Require human review** for all mappings (`requiresHumanReview: true`).

## Strict Invariants
- **No Evidence Persistence**: M48 produces a "draft" (`EvidenceDraftEnvelope`), not a persisted record.
- **No Finding Creation**: M48 does not create findings or finding candidates.
- **No M45 EvidenceRecord**: The draft produced has a distinct shape (`EvidenceDraftEnvelope`) and sets `notM45EvidenceRecord: true`.
- **No Vulnerability Confirmation**: M48 makes no claims about vulnerability, severity, risk, or impact.
- **No Service Dependencies**: M48 operates entirely independently and does NOT call or import services from M45 or M47. It only uses shared safe types.
- **No External Execution**: M48 executes no tools, makes no network requests, and communicates with no external databases (e.g., Postgres). It is entirely DB-free and network-free.

## Mapping Logic
- **`draft_ready`**: Produced only when `comparisonSignalStrength` is "moderate" or "strong". Weak signals or cases with no significant differences result in `needs_more_review` (or similar blocked states).
- **Time-based mapping**: Requires `sourceComparisonMode === time_based_difference` to avoid generic HTTP delays being mapped as time-based evidence (which could falsely imply SQLi).
- **Authorization difference**: Requires `sourceComparisonMode === authorization_difference`.
- **Metadata sentinels**: Invalid mapping IDs, snapshot IDs, and timestamps are aggressively converted to safe sentinels (e.g., `invalid_mapping_id`, `1970-01-01T00:00:00.000Z`) to prevent echoing unsafe or secret data.

## Integration
M48 sits as an intermediary between M47 (Comparator) and the future construction of M45 evidence records. Its output is designed to be fed to an M45 Evidence Validator by a coordinator later in the pipeline, ensuring that tools cannot directly inject findings into the system.
