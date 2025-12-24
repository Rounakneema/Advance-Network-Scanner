# 02. Execution Flow

### Responsibility
Details the exact step-by-step sequence of events when a user executes a scan.

### Why it exists
To help developers debug issues by understanding the order of operations.

### Sequence

1.  **CLI Initialization (`cmd/revealr/main.go`)**
    -   `cobra` parses flags (`--target`, `--ports`).
    -   `Execute()` is called.

2.  **Configuration & Setup**
    -   `config.LoadConfig()` reads YAML and applies CLI overrides.
    -   `core.NewSession()` initializes the SQLite database connection.

3.  **Orchestration Start (`pkg/app/orchestrator.go`)**
    -   `NewOrchestrator()` spins up the controller.
    -   `StartScan()` is invoked.

4.  **Target Resolution**
    -   Input strings (CIDRs, Hostnames) are resolved to a list of unique `net.IP` objects.

5.  **Host Discovery (`pkg/discovery/`)**
    -   Based on configuration (`icmp`, `tcp-probe`, `arp`), the system filters the IP list.
    -   **Outcome:** A subset of IPs deemed "Live".

6.  **Port Scanning (`pkg/scanner/`)**
    -   The Orchestrator iterates over "Live" hosts.
    -   `Scanner.ScanPorts()` spins up workers (goroutines).
    -   Ports are probed (`connect`, `syn`, etc.).
    -   **Outcome:** A list of `Open Ports` with initial raw banners.

7.  **Intelligence Enrichment (`plugins/intelligence.py`)**
    -   **If enabled:** The Go Host object is serialized to Protobuf.
    -   The Python subprocess is invoked.
    -   Python analyzes banners and may send active probes (HTTP GET, etc.).
    -   Enriched data (Service Name, Version, OS) is returned as JSON.
    -   Go merges this data back into the `Host` object.

8.  **Persistence**
    -   The final `Host` object is saved to `revealr.db`.

9.  **Reporting**
    -   Summary statistics are printed to the console (`PrintScanSummary`).

### Failure Behavior
-   If **Discovery** fails, the scan aborts for that batch.
-   If **Python** crashes or returns invalid JSON, the Orchestrator ignores the error, logs a warning, and saves the Host with only the Go-detected data.
