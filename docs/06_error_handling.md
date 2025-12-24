# 06. Error Handling

### Responsibility
Describes how Revealr handles failures across its distributed components.

### Why it exists
To differentiate between "System Crashes" (Bugs) and "Runtime Errors" (Network issues).

### Hierarchy of Errors

1.  **Critical Failures (Exit 1)**
    -   These stop the program immediately.
    -   *Examples:* Database lock failure, Interface not found, Invalid Config format.
    -   *Handled in:* `cmd/revealr/main.go`.

2.  **Scan Failures (Skip Target)**
    -   These affect a single target but allow the scan to proceed.
    -   *Examples:* Host unreachable, DNS resolution failure.
    -   *Handled in:* `pkg/app/orchestrator.go`.

3.  **Component Failures (Degraded Mode)**
    -   These disable a specific feature but keep the core running.
    -   *Examples:* Python script missing (Disables Intelligence), pcap missing (Disables Raw Scans).
    -   *Handled in:* Respective component initializers.

### Logging Strategy
-   **User-Facing:** Printed to Stdout. Uses `pkg/output` with colors. Concise.
-   **Debug (`--debug`):** Verbose logs including stack traces and raw error strings.

### Things you should not change lightly
-   **The "Fail-Safe" Philosophy:** We prefer to return partial results rather than crashing. E.g., if a port scan finishes but enrichment fails, we still save the open ports to the DB.
