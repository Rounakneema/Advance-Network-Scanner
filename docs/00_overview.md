# 00. Overview

### Responsibility
This document explains the philosophical and high-level design goals of Revealr. It serves as the mental orientation for new developers and users.

### Why it exists
To prevent scope creep and ensure all contributors understand *what* we are building and *why*. It defines the boundaries of the tool.

### Core Design Principles

1.  **Statefulness over "Fire and Forget"**
    Revealr is designed as a persistent reconnaissance engine. Unlike tools that output text and exit, Revealr maintains a database session (`data/db/revealr.db`). This allows for:
    - **Resumability:** Long-running scans can be stopped and restarted without losing progress.
    - **Deduplication:** We don't report the same open port twice unless it changes.
    - **History:** Users can query previous states of a network.

2.  **Hybrid Architecture (Go + Python)**
    We use the right tool for the job:
    - **Go:** Used for performance-critical, concurrent networking (Port scanning, Host Discovery). It handles thousands of goroutines effortlessly.
    - **Python:** Used for business logic, string parsing, and intelligence (Service fingerprinting, CVE lookups). It offers a rich ecosystem and rapid iteration speed.

3.  **Modular & Extensible**
    The core binary should not need recompilation to add a new service fingerprint. Logic specific to protocols (HTTP, SMB, FTP) resides in the Python layer, which serves as a plugin system.

### What Revealr IS NOT
-   **Not a simple port checker:** If you just want to know if port 80 is open, use `nc` or `telnet`.
-   **Not a pure Python script:** It relies on compiled Go code for speed.
-   **Not a distributed botnet:** It is designed for single-node security assessment.

### Things you should not change lightly
-   **The Hybrid Split:** Do not move high-performance loop logic to Python. Do not move complex text parsing logic to Go unless necessary for performance.
-   **The Database Requirement:** Revealr *must* always have a backing store. Removing persistence breaks the core value proposition.
