# ClawCheck

<div align="center">

**🛡️ OpenClaw Vulnerability Scanner**

Detect the **ClawJacked** vulnerability (CVE-2026-CLAW) in OpenClaw installations

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

## Quick Start

```bash
pip install clawcheck
clawcheck
```

## Overview

**ClawCheck** is a CLI security tool that detects the **ClawJacked vulnerability** in OpenClaw installations. The vulnerability, disclosed by Oasis Security on February 26, 2026, allows any website to silently hijack OpenClaw agents through WebSocket exploitation.

**What it does:**
- ✅ Scans for OpenClaw installations
- ✅ Checks version against vulnerable range (`< 2026.2.25`)
- ✅ Probes WebSocket gateway for security indicators
- ✅ Provides remediation guidance
- ✅ CI/CD integration (JSON/SARIF output)

**What it doesn't do:**
- ❌ No external data transmission (offline-capable)
- ❌ No brute-force attacks (read-only probes)
- ❌ No system modifications (in scan mode)

## Installation

### pip (Recommended)

```bash
pip install clawcheck
```

### pipx (Isolated Installation)

```bash
pipx install clawcheck
```

### From Source

```bash
git clone https://github.com/yourusername/clawcheck.git
cd clawcheck
pip install -e .
```

## Usage

### Basic Scan

```bash
clawcheck
```

#### Scan Flow

```mermaid
flowchart TD
    A[clawcheck] --> B{OpenClaw Found?}
    B -->|No| C[Exit Code: 3]
    B -->|Yes| D{Version Vulnerable?}
    D -->|Yes| E[VULNERABLE]
    D -->|No| F[SECURE]
    E --> G[Show Remediation]
    F --> H[Exit Code: 0]
    C --> I[Exit Code: 3]
    G --> I

    style E fill:#ff6b6b
    style F fill:#51cf66
    style C fill:#ffd93d
```

#### Output Example

```mermaid
graph LR
    subgraph Target
        A[OpenClaw Version: 2026.2.12]
        B[Gateway: Running]
        C[Instance: Local]
    end

    subgraph ClawJacked
        D[VULNERABLE]
        E[Version Check: FAIL]
        F[Origin Validation: FAIL]
        G[Rate Limiting: FAIL]
    end

    subgraph Remediation
        H[openclaw upgrade]
    end

    A --> D
    B --> D
    C --> D
    D --> E
    E --> F
    F --> G
    G --> H

    style D fill:#ff6b6b
    style E fill:#ff6b6b
    style F fill:#ff6b6b
    style G fill:#ff6b6b
    style H fill:#51cf66
```

### JSON Output

```bash
clawcheck --json
clawcheck --json --output results.json
```

### SARIF Output (CI/CD)

```bash
clawcheck --sarif
```

### Verbose Mode

```bash
clawcheck -v        # Verbose
clawcheck -vv       # Extra verbose (includes WebSocket probing)
```

### Fix Mode

```bash
# Dry run - see what would be done
clawcheck fix --dry-run

# Apply fix (with confirmation)
clawcheck fix

# Apply fix without confirmation
clawcheck fix --force
```

### Monitoring Mode

```bash
# Monitor continuously (60s interval)
clawcheck monitor

# Custom interval
clawcheck monitor --interval 30

# With log file
clawcheck monitor --log-file clawcheck.log
```

### Advanced Options

```bash
# Custom timeout
clawcheck --timeout 60

# Custom config path
clawcheck --config-path /custom/path/openclaw.json

# All options combined
clawcheck -vv --json --output scan.json --timeout 60
```

## Exit Codes

```mermaid
flowchart TD
    Start[clawcheck scan] --> Check{OpenClaw Found?}
    Check -->|No| NotFound[Exit Code: 3]
    Check -->|Yes| Scan{Scan Success?}
    Scan -->|Error| Error[Exit Code: 2]
    Scan -->|Success| Vulnerable{Vulnerabilities Found?}
    Vulnerable -->|Yes| VulnExit[Exit Code: 1]
    Vulnerable -->|No| Secure[Exit Code: 0]

    NotFound --> End[End]
    Error --> End
    VulnExit --> End
    Secure --> End

    style NotFound fill:#ffd93d
    style Error fill:#ff6b6b
    style VulnExit fill:#ff6b6b
    style Secure fill:#51cf66
```

| Code | Meaning | Use Case |
|------|---------|----------|
| 0 | SECURE | No vulnerabilities found |
| 1 | VULNERABLE | Vulnerabilities detected |
| 2 | ERROR | Scan error (permissions, timeout, etc.) |
| 3 | NOT_FOUND | OpenClaw not installed or not running |

**Script Integration Example:**

```bash
#!/bin/bash
clawcheck --json --output scan.json
EXIT_CODE=$?

case $EXIT_CODE in
  0) echo "✓ Secure - no action needed" ;;
  1) echo "✗ Vulnerable - apply fix with: clawcheck fix" ;;
  2) echo "⚠ Error - check logs" ;;
  3) echo "○ OpenClaw not found" ;;
esac

exit $EXIT_CODE
```

## About the Vulnerability

### ClawJacked (CVE-2026-CLAW)

**Disclosed:** February 26, 2026
**Severity:** HIGH
**Affected Versions:** OpenClaw `< 2026.2.25`

#### Attack Chain

```mermaid
sequenceDiagram
    participant Victim as 🧑
    participant Website as 🌐
    participant Browser as 🌍
    participant OpenClaw as 🤖
    participant Attacker as 👾

    Note over Victim,Attacker: User visits malicious website
    Victim->>Website: Visits URL
    Website->>Browser: Injects malicious JS

    Note over Browser,OpenClaw: Step 1: WebSocket Origin Bypass
    Browser->>OpenClaw: WebSocket to localhost:18789
    Note right of OpenClaw: No CORS restriction!
    OpenClaw-->>Browser: Connection accepted

    Note over Browser,OpenClaw: Step 2: No Rate Limiting
    loop Brute Force (hundreds/sec)
        Browser->>OpenClaw: Auth attempt
        OpenClaw-->>Browser: Rejected
    end

    Note over Browser,OpenClaw: Step 3: Auto-Trust Registration
    Browser->>OpenClaw: Successful auth
    OpenClaw-->>Browser: Device auto-approved!

    Note over OpenClaw,Attacker: Step 4: Full Control
    Attacker->>OpenClaw: Send messages, read logs
    OpenClaw-->>Attacker: Exfiltrate data

    Note over Victim,Attacker: Workstation compromised!
```

#### Vulnerability Components

```mermaid
graph TB
    subgraph ClawJacked Vulnerability
        A[WebSocket Origin Bypass]
        B[No Localhost Rate Limiting]
        C[Auto Trust Registration]
    end

    subgraph Attack Consequences
        D[Full Workstation Compromise]
        E[Data Exfiltration]
        F[Privacy Violation]
    end

    A --> D
    B --> D
    C --> D
    D --> E
    D --> F

    style A fill:#ff6b6b
    style B fill:#ff6b6b
    style C fill:#ff6b6b
    style D fill:#c92a2a
    style E fill:#c92a2a
    style F fill:#c92a2a
```

**Impact:** Full workstation compromise initiated from a browser tab

**Fix:** Update to OpenClaw `2026.2.25` or later

**Source:** [Oasis Security Vulnerability Disclosure](https://www.oasis.security/blog/openclaw-vulnerability)

## Safety & Privacy

- ✅ **Offline-capable** - No external data transmission
- ✅ **Read-only probes** - No system modification
- ✅ **Rate-limited** - 1 request/second (AWS cooperative scanning guidelines)
- ✅ **No brute-force** - Never attempts password guessing
- ✅ **Open source** - Fully auditable code

## Development

### Architecture

```mermaid
flowchart TD
    subgraph CLI
        A[User]
        B[clawcheck command]
    end

    subgraph Discovery
        C[Config Scanner]
        D[CLI Runner]
        E[Port Prober]
    end

    subgraph Scan
        F[Vulnerability DB]
        G[Version Checker]
        H[WebSocket Probe]
    end

    subgraph Output
        I[Terminal Formatter]
        J[JSON Formatter]
        K[SARIF Formatter]
    end

    subgraph Fix
        L[Backup Manager]
        M[Update Executor]
        N[Verification]
    end

    A --> B
    B --> C
    B --> D
    B --> E
    C --> G
    D --> G
    G --> F
    F --> H
    H --> I
    H --> J
    H --> K

    B --> L
    L --> M
    M --> N

    style A fill:#e3f2fd
    style B fill:#bbdefb
    style I fill:#90caf9
    style J fill:#90caf9
    style K fill:#90caf9
```

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=clawcheck --cov-report=html
```

### Project Structure

```mermaid
graph TD
    Root[clawcheck/]

    Root --> Src[src/]
    Root --> Tests[tests/]
    Root --> Docs[docs/]
    Root --> Config[pyproject.toml, README.md, LICENSE]

    Src --> Package[clawcheck/]
    Package --> Init[__init__.py]
    Package --> CLI[cli.py - Click CLI interface]
    Package --> Discovery[discovery.py - OpenClaw discovery]
    Package --> Models[models.py - Data models]
    Package --> Output[output.py - Output formatters]
    Package --> Probe[probe.py - WebSocket probe]
    Package --> VulnDB[vuln_db.py - Vulnerability database]

    Tests --> Unit[unit/ - Unit tests]
    Tests --> Integration[integration/ - Integration tests]

    Docs --> Plans[plans/ - Implementation plans]

    style Root fill:#e3f2fd
    style Src fill:#bbdefb
    style Tests fill:#bbdefb
    style Docs fill:#bbdefb
    style Config fill:#bbdefb
    style Package fill:#90caf9
```

**File Overview:**

| Module | Purpose |
|--------|---------|
| `cli.py` | Click CLI interface (scan/fix/monitor commands) |
| `discovery.py` | OpenClaw discovery (config, CLI, port probing) |
| `models.py` | Data models (ScanResult, Finding, ExitCode, etc.) |
| `output.py` | Terminal/JSON/SARIF formatters |
| `probe.py` | WebSocket vulnerability probe |
| `vuln_db.py` | Vulnerability database with version checking |

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests and linting
6. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is for security testing purposes only. Always obtain proper authorization before scanning systems. The authors are not responsible for misuse of this software.

## Links

- [Oasis Security: ClawJacked Vulnerability](https://www.oasis.security/blog/openclaw-vulnerability)
- [OpenClaw Repository](https://github.com/openclaw/openclaw)
- [SARIF v2.1.0 Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

**Stay secure! 🛡️**
