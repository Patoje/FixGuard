# Passive Recon Boundary

This directory (`worker/src/v2/recon/passive/`) contains the passive recon adapters/executors for FixGuard V2.

## Milestone 29 Rules
*   **Fixture Execution Only**: Passive recon currently relies entirely on deterministic fixture execution.
*   **No Network/Process/Scanner**: This is not a scanner integration layer. Passive capabilities here must not invoke shell, child_process, real network fetch, sockets, or scanner binaries.
*   **Evidence Cleanliness**: Passive observation evidence must omit response bodies, secrets, cookies, auth headers, and executable parameters.
