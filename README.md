# Revealr: The Adaptive Network Scanner

![Go Version](https://img.shields.io/github/go-mod/go-version/Rounakneema/Advance-Network-Scanner?color=blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux-lightgrey)

**Stop just scanning. Start revealing.**

Revealr isn't just another port scanner. It's a hybrid intelligence tool designed for security engineers who need more than just a list of open ports. By fusing a high-concurrency Go scanning engine with a modular Python intelligence layer, Revealr doesn't just tell you *what* is open—it tells you *what it is*, *what version it scans*, and *if it's dangerous*.

---

## ⚡ Why Use Revealr?

Most scanners are "fire and forget"—they dump output to your terminal and vanish. Revealr is different.

*   **Stateful Memory**: Every scan connects to a local SQLite database. Pause today, resume tomorrow. Diff your network state over time to catch drift.
*   **Hybrid Power**: The core engine is written in Go for raw speed (capable of 5000+ packets/sec). The brain is Python, allowing you to write complex vulnerability checks in a language you actually like.
*   **Context-Aware**: It correlates data. Discover an HTTP port? Revealr automatically triggers web-specific enumeration plugins. Found SMB? It checks for signing requirements.
*   **Safety First**: Includes "Paranoid" and "Stealthy" timing templates designed to evade IDS/IPS detection during red team engagements.

---

## 🛠️ Installation

### Prerequisites
*   **Go 1.23+** (Only if building from source)
*   **Python 3.10+** (Required for the Intelligence Engine)

### 1. Quick Install (Binaries)
Check the [Releases](https://github.com/Rounakneema/Advance-Network-Scanner/releases) page for the latest pre-compiled binaries for Windows and Linux. Extract the zip file, and you're good to go.

### 2. Build from Source
If you want the bleeding edge, build it yourself. We've included a build script that handles the heavy lifting.

```bash
git clone https://github.com/Rounakneema/Advance-Network-Scanner.git
cd revealr

# Initialize the environment (Windows)
setup.bat
# OR manually:
# go mod tidy
# build.bat
```

This will produce a `revealr.exe` in the `cmd/revealr/` directory.

---

## 🚀 Usage Guide

### The Basics
Run a safe, standard scan against a single target. This uses the default "Connect" mode which doesn't require root privileges.

```bash
revealr scan --target scanme.nmap.org
```

### Advanced Scanning Strategies

#### 1. The "Loud & Proud" Scan
Need results fast and don't care about noise? Crank up the concurrency and use SYN scanning (requires Admin/Root).

```bash
# -m syn:  Use SYN packets (half-open)
# -p all:  Scan all 65535 ports
# -T aggressive: High speed, lower timeouts
revealr scan -t 192.168.1.10 -p all -m syn -T aggressive
```

#### 2. The "Stealth" Audit
Trying to stay under the radar? Slow it down.

```bash
# -T polite: Adds delay between packets to reduce congestion/alerts
revealr scan -t 10.0.0.5 -p top1000 -T polite
```

#### 3. Intelligence Gathering (Discovery + Enrichment)
Don't just scan ports—discover live hosts first, then fingerprint them.

```bash
# Host discovery via TCP Probes
# Python plugins run automatically on open ports
revealr scan -t 192.168.1.0/24 --host-discovery tcp-probe
```

---

## 🔌 Plugin System (The "Brain")

Revealr's unique value is its plugin system. You can write simple Python scripts to check for specific vulnerabilities or gather metadata.

**Example: Checking for a specific HTTP Header**
Create a new file in `plugins/local/check_header.py`:

```python
from revealr_plugin import RevealrPlugin

class HeaderCheck(RevealrPlugin):
    def run(self, context):
        # 'context' contains ip, port, and detected service info
        if context['service'] == 'http':
             # ... your custom python logic ...
             return {"vulnerability": "Missing Security Headers", "severity": "Medium"}
```

Revealr handles the IPC bridge between Go and Python automatically.

---

## 🏗️ DevOps & Security Integration

We believe security tools should fit into your pipeline, not fight it.

*   **CI/CD Ready**: Returns standard exit codes. easy to integrate into Jenkins/GitHub Actions.
*   **Structured Output**: All internal data is structured. (JSON export coming soon).
*   **Infrastructure as Code**: Check the `ops/` folder for Dockerfiles and Terraform templates to deploy Revealr Scan Nodes.

---

## 🤝 Contributing

We love PRs! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.

1.  Fork the repo
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'Add some amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

---

*Built with ❤️ by Rounak Neema*
