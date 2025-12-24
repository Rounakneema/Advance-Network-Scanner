# 07. Future Work

### Responsibility
Defines the roadmap and explicit non-goals for the project.

### Why it exists
To manage expectations and guide contributors toward high-priority areas.

### Roadmap

#### Phase 2: Intelligence & IPC (Current Focus)
-   [ ] **Plugin Loader:** Refactor `intelligence.py` to support dynamic loading of scripts from `plugins/web/`, `plugins/network/`.
-   [ ] **HTTP Deep Dive:** Add specific detection for CMS (WordPress, Joomla, Drupal) and API endpoints.

#### Phase 3: Vulnerability & Logic
-   [ ] **CVE Mapping:** Integrate a local lightweight CVE database to map `Service Version` -> `Vulnerabilities`.
-   [ ] **Cred Check:** Optional module to test default credentials (admin/admin) on discovered services.

#### Phase 4: Reporting
-   [ ] **HTML Report:** Generate a self-contained HTML dashboard from the SQLite database.
-   [ ] **Export:** Support JSON/CSV export flags.

### Non-Goals
-   **Distributed Scanning:** Revealr is designed as a standalone tool. Use Kubernetes/Celery wrappers if you need distribution.
-   **Web Exploitation:** We identify vulnerabilities; we do not auto-exploit them (e.g., no SQLMap integration).
-   **GUI Application:** We focus on CLI first. A web dashboard is possible, but a native desktop GUI is out of scope.
