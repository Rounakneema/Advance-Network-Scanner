# 04. Scanning Pipeline

### Responsibility
Explains the technical details of how Revealr interacts with the network stack.

### Why it exists
To define the trade-offs between different scan modes and the privileges required.

### 1. Host Discovery Pipeline
Before ports are scanned, we must determine if a host is "up".
-   **ICMP (`--host-discovery icmp`)**: Standard Echo Request. Fast, but often blocked by Windows Firewalls.
-   **TCP Probe (`--host-discovery tcp-probe`)**: Sends TCP SYN/Connect to ports 80, 443, 22. If a RST or ACK is received, the host is UP. **Default for internet scans.**
-   **ARP (`--host-discovery arp`)**: Only works on local subnets. Uses `pcap` to read Layer 2 broadcasts.

### 2. Port Scan Modes and Privileges

| Mode | Flag | Method | Privileges | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Connect** | `-m connect` | `net.Dial` (Full Handshake) | **User** | Default. Slower, leaves logs on target. |
| **SYN** | `-m syn` | Raw Packet (Half-open) | **Admin/Root** | Stealthier. Requires `pcap` driver. |
| **FIN/NULL** | `-m fin` | Raw Packet (Flag manipulation) | **Admin/Root** | Evasion techniques. |
| **UDP** | `-m udp` | UDP Packet + ICMP Listen | **Admin/Root** | Slow. Relies on "Port Unreachable". |

### 3. Adaptive Mechanisms
We do not spam packets blindly. The `pkg/scanner/adaptive.go` module handles:
-   **Rate Limiting:** Global semaphore limits concurrent network ops.
-   **Timeouts:** Configurable per-probe timeouts.

### Things you should not change lightly
-   **Default Mode:** `connect` MUST remain the default to ensure Revealr runs out-of-the-box for non-admin users.
-   **Packet Libraries:** We use `gopacket`. Replacing this would rewrite the entire raw scanning engine.
