# 03. Data Model

### Responsibility
Defines the core data structures and their ownership lifecycle.

### Why it exists
To prevent data corruption and ensure consistency between the Go memory model, the Database schema, and the Protobuf IPC format.

### Core Structures (`pkg/core/types.go`)

#### 1. Host
The root entity.
-   **Lifecycle:** Created during Target Resolution. Persisted after Enrichment.
-   **Fields:**
    *   `ID` (string): Usually the IP address. Primary Key.
    *   `IPAddress` (net.IP): Network object.
    *   `Ports` (List): Discovered ports.
    *   `Details` (Map): OS, MAC address, etc.

#### 2. Port
A child of Host.
-   **Lifecycle:** Created during Port Scanning.
-   **Fields:**
    *   `PortNumber` (int): 1-65535.
    *   `Protocol` (string): "tcp", "udp".
    *   `IsOpen` (bool): State.
    *   `Service` (Struct): Detected service info.

#### 3. Service
A child of Port.
-   **Lifecycle:** Initially populated by Go (raw banner). Refined by Python (Fingerprint).
-   **Fields:**
    *   `Name` (string): e.g., "http", "ssh", "apache".
    *   `Version` (string): e.g., "2.4.49", "OpenSSH 8.1".
    *   `Details` (Map): Extra info (e.g., "Ubuntu", "WordPress").

### Data Ownership
| Phase | Owner | Permission |
| :--- | :--- | :--- |
| **Discovery** | `HostDiscoverer` | Create Host |
| **Scanning** | `PortScanner` | Add Ports (Append Only) |
| **Enrichment** | `Python Plugin` | *Update* Service/Version/Details |
| **Persistence** | `Session` | Read/Write DB |

### Things you should not change lightly
-   **DB Schema:** Changing struct fields requires migration logic in `pkg/core/session.go`.
-   **Protobuf Defs:** Changing `revealr.proto` requires re-generating both Go and Python bindings.
