# 05. Intelligence Engine

### Responsibility
Explains the role of Python in the system and the interface contract it strictly follows.

### Why it exists
To delineate where "Scanning" ends and "Thinking" begins.

### The Logic Split
-   **Go's Job:** Find the door (Open Port) and knock (Get Banner).
-   **Python's Job:** Figure out who lives there (Service ID) and if the door is broken (Vulnerability).

### IPC Contract
Communication happens via **Stdin/Stdout**.
1.  **Format:**
    -   Request (Go -> Py): 4-byte Length Prefix + Protobuf `ScanResultRequest`.
    -   Response (Py -> Go): Raw JSON stream.

2.  **Why JSON for Response?**
    -   While the request is strict (Protobuf), the response is flexible (JSON) to allow Python to return unstructured "Details" maps that Go simply stores without strict schema validation.

### Plugin Structure (`plugins/`)
-   `intelligence.py`: The entry point. It loads sub-modules.
-   `probe/`: Contains custom probe definitions.
-   `web/`: (Planned) Logic for HTTP fingerprinting (CMS, Frameworks).

### Failure Behavior
The Intelligence Engine is designed to be **fail-open**.
-   If Python is missing: Scanning continues (basic headers only).
-   If a script hangs: Go kills the subprocess after a timeout.
-   If parsing fails: The specific port update is discarded, but the host remains.

### Things you should not change lightly
-   **The Entry Point:** `plugins/intelligence.py` is hardcoded in the Go Orchestrator. Moving or renaming it breaks the bridge.
-   **Length-Prefixed Protobuf:** This is the binary framing layer. Debugging it requires hex editors. Touch with care.
