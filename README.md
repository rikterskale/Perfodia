# Perfodia — Network Penetration Testing Framework

A modular Python 3 framework that orchestrates 30+ security tools into an 8-phase automated workflow with parallel execution, scope enforcement, centralized credential management, vulnerability scoring, password cracking, evidence capture, and multi-format reporting.

> **⚠️ FOR AUTHORIZED LAB USE ONLY.** Unauthorized access to computer systems is illegal.

---

## Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Guide](#usage-guide)
- [The 8 Workflow Phases](#the-8-workflow-phases)
- [Feature: Scope Enforcement](#feature-scope-enforcement)
- [Feature: Input Sanitization](#feature-input-sanitization)
- [Feature: Parallel Execution](#feature-parallel-execution)
- [Feature: Credential Vault](#feature-credential-vault)
- [Feature: Vulnerability Scoring & Risk Rating](#feature-vulnerability-scoring--risk-rating)
- [Feature: Password Cracking Integration](#feature-password-cracking-integration)
- [Feature: Web Application Module](#feature-web-application-module)
- [Feature: Active Directory Module](#feature-active-directory-module)
- [Feature: SNMPv3 Support](#feature-snmpv3-support)
- [Feature: Resume Capability](#feature-resume-capability)
- [Feature: Evidence Screenshots](#feature-evidence-screenshots)
- [Feature: PDF Report Generation](#feature-pdf-report-generation)
- [Feature: Interactive TUI Dashboard](#feature-interactive-tui-dashboard)
- [Feature: Config Wizard](#feature-config-wizard)
- [Custom Nmap Options](#custom-nmap-options)
- [Tool Reference](#tool-reference)
- [Nmap Scan Types & NSE Scripts](#nmap-scan-types--nse-scripts)
- [Error Handling & Logging](#error-handling--logging)
- [Unit Test Suite](#unit-test-suite)
- [Session & Report Structure](#session--report-structure)
- [Docker Support](#docker-support)
- [Extending the Framework](#extending-the-framework)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)

---

## Overview

Perfodia chains tools together so the output of one phase feeds the next automatically. Credentials from Phase 5 are reused in Phase 6. Service versions from Phase 2 are scored against vulnerability databases. Hashes from Phase 6 are cracked in Phase 7 and the passwords are stored back for Phase 8.

**8 phases:** Reconnaissance → Scanning → Enumeration → Web App Testing → Exploitation → Active Directory → Password Cracking → Post-Exploitation

**Key capabilities:** parallel execution, scope enforcement (blocks out-of-scope IPs), input sanitization (prevents injection via hostile banners), credential vault (cross-phase credential sharing), CVSS-based vulnerability scoring, resume from checkpoint, evidence screenshots, PDF reports, interactive TUI dashboard, config wizard.

---

## System Requirements

| Requirement | Details |
|------------|---------|
| **OS** | Debian 11/12, Ubuntu 22.04/24.04, Kali Linux 2023+, Parrot OS |
| **Python** | 3.10+ |
| **Privileges** | Root/sudo (or `--nmap-scan-type sT` for rootless scanning) |
| **RAM** | 2 GB min, 4 GB recommended |
| **Disk** | ~3 GB for full install |

---

## Installation

### Step 1: Clone

```bash
git clone <your-repo-url> pentestfw && cd perfodia
```

### Step 2: Install system tools

```bash
chmod +x install_deps.sh
sudo bash install_deps.sh --dry-run   # Preview first
sudo bash install_deps.sh --full      # Install everything
```

The installer handles 12 steps: build tools, nmap, recon tools, enumeration tools, exploitation tools, Python packages (impacket, enum4linux-ng, bloodhound-python, netexec), web tools (ffuf, gowitness, chromium), Responder, Metasploit (optional), and wordlists.

| Flag | Description |
|------|-------------|
| `--full` | Everything (default) |
| `--minimal` | Only nmap, dig, whois, curl |
| `--no-msf` | Skip Metasploit |
| `--dry-run` | Preview without installing |

### Step 3: Install Python dependencies

```bash
pip3 install -r requirements.txt
```

Core dependency is PyYAML. Recommended: `rich` (for TUI dashboard). Optional: `weasyprint` (for PDF reports).

### Step 4: Verify

```bash
sudo python3 perfodia.py --check-tools
```

Shows status of all 32 registered tools with version info.

### Quick Start (Kali Linux)

```bash
pip3 install -r requirements.txt
sudo python3 perfodia.py -t 192.168.1.100 -m full -v
```

---

## Project Structure

```
perfodia/                              # ~10,500 lines
├── perfodia.py                        # Main CLI entry point
├── requirements.txt                    # Python dependencies
├── install_deps.sh                     # System package installer
├── configs/
│   ├── default.yaml                    # All tunable parameters
│   └── settings.py                     # Config loader
├── modules/
│   ├── base.py                         # Abstract base (vault, scorer, parallel, scope)
│   ├── recon.py                        # Phase 1: DNS, WHOIS, zone transfers
│   ├── scanning.py                     # Phase 2: nmap/masscan with custom options
│   ├── enumeration.py                  # Phase 3: 12 service handlers + SNMPv3
│   ├── web_app.py                      # Phase 4: ffuf, sqlmap, header analysis
│   ├── exploitation.py                 # Phase 5: searchsploit, hydra, CME
│   ├── active_directory.py             # Phase 6: LDAP, BloodHound, Kerberos
│   ├── cracking.py                     # Phase 7: hashcat/john with vault feedback
│   └── post_exploitation.py            # Phase 8: impacket, priv-esc, pivoting
├── utils/
│   ├── scope_guard.py                  # Scope enforcement on every tool execution
│   ├── sanitizer.py                    # Input sanitization for all tool arguments
│   ├── parallel.py                     # Thread pool with per-host error isolation
│   ├── credential_vault.py             # Centralized credential store
│   ├── vuln_scorer.py                  # CVSS scoring, risk rating, findings
│   ├── session_state.py                # Checkpoint/resume capability
│   ├── screenshot.py                   # Web service evidence screenshots
│   ├── tui.py                          # Rich-based interactive dashboard
│   ├── config_wizard.py                # Interactive config generator
│   ├── logger.py                       # Dual file logging + error counter
│   ├── validators.py                   # Target/nmap/config validation
│   ├── tool_runner.py                  # Subprocess engine (sanitizer + scope integrated)
│   ├── parsers.py                      # Nmap XML, enum4linux, hydra parsers
│   └── report_generator.py             # HTML/JSON/Markdown/PDF reports
├── tests/
│   ├── conftest.py                     # Shared fixtures
│   ├── test_validators.py              # 11 tests
│   ├── test_sanitizer.py               # 15 tests
│   ├── test_scope_guard.py             # 11 tests
│   ├── test_credential_vault.py        # 12 tests
│   ├── test_vuln_scorer.py             # 12 tests
│   └── test_core.py                    # 22 tests (session, parallel, parsers)
├── Dockerfile                          # Multi-stage Docker build
├── docker-compose.yml                  # Docker services
├── docker-entrypoint.sh                # Docker entrypoint
└── DOCKER.md                           # Docker guide
```

---

## Quick Start

```bash
# Config wizard — creates a tailored config file by asking questions
sudo python3 perfodia.py --init

# Full 8-phase pentest
sudo python3 perfodia.py -t 192.168.1.100 -m full -v

# Interactive TUI dashboard (requires: pip install rich)
sudo python3 perfodia.py -t 192.168.1.100 -m full --interactive -v

# Dry run — shows commands without executing
sudo python3 perfodia.py -t 192.168.1.100 -m full --dry-run -vv

# Resume an interrupted session
sudo python3 perfodia.py -t 192.168.1.100 -m full --resume --session 20250322_143000
```

---

## Configuration

```bash
# Generate config interactively
sudo python3 perfodia.py --init

# Or copy and edit manually
cp configs/default.yaml configs/mylab.yaml
sudo python3 perfodia.py -t <target> -c configs/mylab.yaml
```

Key sections in `default.yaml`:

```yaml
general:
  threads: 10              # Parallel thread pool size
  timeout: 300             # Per-tool timeout (seconds)

nmap:
  default_ports: "1-65535"
  timing_template: 4       # 0=slowest/stealthiest ... 5=fastest

exploitation:
  safe_mode: true          # Skips brute-force when true

webapp:
  sqlmap_enabled: true
  check_git_exposure: true

ad:
  bloodhound_collect: true
  spray_passwords: ["Password1", "Welcome1", "Company123"]

cracking:
  enabled: true
  wordlist: "/usr/share/wordlists/rockyou.txt"
  max_runtime: 600
  use_rules: true

screenshots:
  enabled: true
  max_workers: 5

reporting:
  include_risk_rating: true
```

---

## Usage Guide

### Execution Modes

| Mode | Phases | When to use |
|------|--------|-------------|
| `recon` | 1 | Initial target research |
| `scan` | 2 | Host/port discovery |
| `scan --enum` | 2+3 | Discovery + service deep-dive |
| `webapp` | 2+4 | Web application focused |
| `exploit` | 2+3+5 | Exploitation workflow |
| `ad` | 2+3+6 | Active Directory focused |
| `crack` | 7 | Crack previously collected hashes |
| `post` | 8 | After gaining access |
| `full` | All 8 | Complete engagement |

### Module Selection

```bash
# Run specific phases in any combination
sudo python3 perfodia.py -t 192.168.1.100 --modules recon,scan,webapp,ad,crack
```

### Verbosity

| Flag | What you see |
|------|-------------|
| *(none)* | Errors and findings only |
| `-v` | Tool execution, results |
| `-vv` | Full commands, parsed data |

Everything always goes to `logs/all.log` regardless of verbosity.

---

## The 8 Workflow Phases

### Phase 1: Reconnaissance
**Tools:** dig, whois, dnsrecon, whatweb — DNS records, WHOIS, zone transfers, web fingerprinting.

### Phase 2: Network Scanning
**Tools:** nmap, masscan — Host discovery, port scanning, version detection, OS fingerprinting, NSE vulnerability scripts. Supports `--nmap-extra`, `--nmap-raw`, `--nmap-scan-type`, `--nmap-scripts`.

### Phase 3: Service Enumeration
**Tools:** enum4linux-ng, smbclient, snmpwalk (v2c + v3), onesixtyone, gobuster, nikto, curl, nmap NSE — Auto-routes each discovered service to the correct handler across 12 service types.

### Phase 4: Web Application Testing
**Tools:** ffuf, wfuzz, sqlmap, curl — Directory brute-forcing, SQL injection, security header analysis, technology detection, .git/.env exposure, backup file discovery, parameter enumeration.

### Phase 5: Exploitation
**Tools:** searchsploit, hydra, crackmapexec — ExploitDB cross-referencing, credential attacks with lockout protection, SMB null sessions, Metasploit RC script generation. All credentials stored in vault.

### Phase 6: Active Directory
**Tools:** ldapsearch, bloodhound-python, impacket suite, crackmapexec — DC detection, LDAP enumeration, BloodHound collection, AS-REP Roasting, Kerberoasting, password spraying, GPO enumeration, SMB signing checks.

### Phase 7: Password Cracking
**Tools:** hashcat, john — Collects all hashes from credential vault and loot files, identifies hash types, runs cracking with configurable wordlists and rules, stores cracked passwords back into the vault for Phase 8.

### Phase 8: Post-Exploitation
**Tools:** impacket-secretsdump, impacket-psexec — Credential validation, hash extraction, Kerberos attacks, priv-esc scripts (Linux/Windows), lateral movement guides.

---

## Feature: Scope Enforcement

**File:** `utils/scope_guard.py`

Every target IP is validated against an allow-list and deny-list before any tool executes. Out-of-scope IPs are blocked with a logged violation. This prevents the most dangerous real-world pentesting mistake.

**How it works:**
- Targets from `-t` and `-tL` define the allowed scope
- Exclusions from `--exclude` define the deny-list (takes priority)
- `ToolRunner` calls `scope_guard.check_tool_args()` before every subprocess
- IPs are extracted from tool arguments (bare IPs, `user@host`, `smb://host` patterns)
- Violations are logged to `logs/scope_violations.json` with timestamps
- Blocked tools return a `scope_violation` error category

**Example violation output:**
```
[SCOPE VIOLATION] Target '10.0.0.1' is OUT OF SCOPE. Tool: nmap. Execution BLOCKED.
```

---

## Feature: Input Sanitization

**File:** `utils/sanitizer.py`

Every argument passed to every external tool is sanitized before subprocess execution. This prevents command injection via hostile service banners, filenames, or tool output that feeds into subsequent commands.

**What it strips:** `;`, `|`, `&`, `` ` ``, `$()`, `${}`, `!`, `\\`, `<>`, null bytes, newlines. Preserves dashes, slashes, colons, and `@` which are needed for normal tool arguments.

**Integrated into ToolRunner** — no module code changes needed.

---

## Feature: Parallel Execution

**File:** `utils/parallel.py`

Per-host operations run concurrently via thread pool. Controlled by `general.threads` (default: 10, max: 50).

- Each host is isolated — one failure doesn't stop others
- Progress logging: `[PARALLEL] Scanning: 15/24 (62%) — 192.168.1.15 done`
- Single-host fast path (no threading overhead)
- Graceful shutdown on Ctrl+C

---

## Feature: Credential Vault

**File:** `utils/credential_vault.py`

Thread-safe store tracking every password, hash, ticket, and key across all phases.

- **Deduplication** — same credential discovered by multiple tools stored once
- **Source tracking** — which tool and phase found each credential
- **Verification** — mark credentials as confirmed working on specific hosts
- **Auto-persist** — saves to `loot/credential_vault.json` after every change
- **Cross-phase reuse** — `vault.get_for_host("192.168.1.200", service="smb")` returns applicable creds
- **Credential types:** password, ntlm_hash, net_ntlmv2, krb_tgt, krb_tgs, asrep_hash, ssh_key, token, cookie

---

## Feature: Vulnerability Scoring & Risk Rating

**File:** `utils/vuln_scorer.py`

Every finding is scored with CVSS and classified as CRITICAL/HIGH/MEDIUM/LOW/INFO.

- **15+ heuristic rules** — EternalBlue, Heartbleed, ShellShock, SMBGhost, Log4Shell, BlueKeep, anonymous FTP, null sessions, default creds, weak SSL, DNS recursion, SNMP defaults
- **CVE extraction** from NSE script output
- **Risk score** — weighted: Critical×40 + High×10 + Medium×3 + Low×1
- **Attack narrative** — auto-generated: *"Testing identified 3 critical vulnerabilities including MS17-010. Administrative access was achievable."*

**End-of-session output:**
```
  RISK ASSESSMENT
  Overall Risk:   CRITICAL
  Risk Score:     72
  Critical: 1  High: 4  Medium: 7  Low: 3
```

---

## Feature: Password Cracking Integration

**File:** `modules/cracking.py`

Automatically feeds discovered hashes to hashcat (preferred) or john and stores cracked passwords back into the credential vault.

**How it works:**
1. Collects hashes from the credential vault and loot directory files (secretsdump, AS-REP, Kerberoast)
2. Identifies hash types and maps to hashcat mode numbers (NTLM=1000, Net-NTLMv2=5600, AS-REP=18200, Kerberoast=13100, etc.)
3. Runs hashcat with configurable wordlist, rules, and runtime cap
4. Falls back to john if hashcat unavailable
5. Parses cracked passwords from potfile/output
6. Extracts usernames from hash format (secretsdump `user:rid:lm:nt`, Kerberos `$krb5asrep$user@DOMAIN`)
7. Stores cracked `username:password` pairs back into the vault

**Configuration:**
```yaml
cracking:
  enabled: true
  wordlist: "/usr/share/wordlists/rockyou.txt"
  max_runtime: 600     # seconds
  use_rules: true      # hashcat best64.rule
```

**Usage:**
```bash
# Crack after exploitation phase
sudo python3 perfodia.py -t 192.168.1.100 -m full -v

# Crack previously collected hashes only
sudo python3 perfodia.py -t 192.168.1.100 -m crack --session previous_session
```

---

## Feature: Web Application Module

**File:** `modules/web_app.py`

| Test | Tool | Details |
|------|------|---------|
| Directory brute-forcing | ffuf/wfuzz | Fast async fuzzing with configurable wordlists |
| Security headers | curl | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| Technology detection | curl | WordPress, Joomla, Drupal, Django, .NET, Laravel |
| SQL injection | sqlmap | Crawl + test with configurable risk/level |
| Exposure checks | curl | .git, .env, robots.txt, backup files (.bak, .sql, .zip) |
| Parameter discovery | curl | URL params and form fields from HTML |

---

## Feature: Active Directory Module

**File:** `modules/active_directory.py`

DC detection → LDAP enum → BloodHound collection → AS-REP Roasting → Kerberoasting → Password spraying → GPO enum → SMB signing checks. All hashes and credentials automatically stored in the vault.

---

## Feature: SNMPv3 Support

**Added to:** `modules/enumeration.py`

The SNMP handler now tests SNMPv3 in addition to v2c:

1. **noAuthNoPriv** — tests common usernames (initial, public, admin, snmpuser) without authentication
2. **authNoPriv** — tests username/password combinations with MD5/SHA authentication
3. Discovered credentials are stored in the vault
4. Misconfigurations are scored as findings

**Configuration:**
```yaml
enumeration:
  snmpv3:
    enabled: true
    usernames: [initial, public, admin, snmpuser]
    credentials:
      - {user: admin, auth_pass: admin123, auth_proto: SHA}
      - {user: snmpuser, auth_pass: snmpuser, auth_proto: MD5}
```

---

## Feature: Resume Capability

**File:** `utils/session_state.py`

```bash
# Start a scan — gets interrupted
sudo python3 perfodia.py -t 192.168.1.0/24 -m full --session mylab -v
# Ctrl+C during enumeration

# Resume from where it left off
sudo python3 perfodia.py -t 192.168.1.0/24 -m full --resume --session mylab -v
# [RESUME] Skipping 'recon' (already completed)
# [RESUME] Skipping 'scan' (already completed)
# Starting enumeration...
```

Checkpoints saved after each phase. Credential vault persists independently.

---

## Feature: Evidence Screenshots

**File:** `utils/screenshot.py`

Auto-captures screenshots of every web service. Backends (auto-detected): gowitness → cutycapt → chromium → curl HTML fallback. Screenshots appear in the HTML report gallery.

---

## Feature: PDF Report Generation

**Added to:** `utils/report_generator.py`

Three-backend fallback chain: WeasyPrint (Python) → wkhtmltopdf (CLI) → Chrome headless.

```bash
sudo python3 perfodia.py -t 192.168.1.100 -m full --report-format pdf
```

Install a backend: `pip install weasyprint` or `apt install wkhtmltopdf` or `apt install chromium-browser`.

---

## Feature: Interactive TUI Dashboard

**File:** `utils/tui.py`

Real-time terminal dashboard showing scan progress, live findings feed, credential count, and severity breakdown. Uses the `rich` library.

```bash
pip install rich
sudo python3 perfodia.py -t 192.168.1.100 -m full --interactive -v
```

**Dashboard panels:**
- **Header** — current phase, progress bar, active tool, elapsed time
- **Statistics** — hosts found, open ports, credentials, admin access, errors/warnings
- **Severity breakdown** — critical/high/medium/low finding counts (color-coded)
- **Latest findings** — live feed of discovered vulnerabilities
- **Event log** — real-time tool execution and result stream

Falls back to normal console output if `rich` is not installed.

---

## Feature: Config Wizard

**File:** `utils/config_wizard.py`

Interactive walkthrough that creates a tailored YAML config:

```bash
sudo python3 perfodia.py --init
```

**Questions asked:**
- Config file name
- Thread count and timeouts
- Scan approach (quick/normal/thorough/stealth)
- Lab environment (Windows/SMB? SNMP? Web servers? Active Directory?)
- SQL injection testing enabled?
- BloodHound collection? Password spraying?
- Safe mode? Automated exploitation?
- Wordlist path and lockout threshold
- Password cracking enabled?

Generates a ready-to-use YAML file in `configs/`.

---

## Custom Nmap Options

```bash
--nmap-extra '-sU -Pn --max-rate 500'          # Append to defaults
--nmap-raw '-sS -sV -p 22,80,443'              # Replace all defaults
--nmap-scan-type sT                             # Change scan type (sT=no root needed)
--nmap-scripts 'smb-vuln*,http-sql-injection'   # Override NSE scripts
```

All options validated: dangerous flags blocked, shell injection stripped, output conflicts skipped.

---

## Tool Reference

| Tool | Phase | Purpose |
|------|-------|---------|
| nmap | 2 | Port scanning, version detection, OS fingerprinting, NSE |
| masscan | 2 | High-speed port discovery |
| dig, whois, dnsrecon | 1 | DNS, WHOIS, subdomain enumeration |
| whatweb | 1 | Web technology fingerprinting |
| enum4linux-ng | 3 | SMB/RPC user/share/group enumeration |
| smbclient, rpcclient | 3 | SMB share access, RPC queries |
| snmpwalk, onesixtyone | 3 | SNMP v2c/v3 enumeration |
| nikto, gobuster | 3 | Web vulnerability scanning, directory brute-force |
| ffuf | 4 | Fast web fuzzing |
| sqlmap | 4 | SQL injection detection |
| searchsploit | 5 | Offline ExploitDB search |
| hydra | 5 | Online password cracking |
| crackmapexec/netexec | 5,6 | SMB/AD Swiss army knife |
| ldapsearch | 6 | LDAP enumeration |
| bloodhound-python | 6 | AD attack path data collection |
| impacket suite | 6,8 | Windows protocol tools (secretsdump, psexec, Kerberos) |
| hashcat, john | 7 | Offline hash cracking |
| gowitness | Evidence | Web service screenshots |

---

## Nmap Scan Types & NSE Scripts

| Scan Type | Flag | Root? | Use case |
|-----------|------|:-----:|----------|
| SYN | `-sS` | Yes | Default — fast, stealthy |
| Connect | `-sT` | No | No root needed |
| UDP | `-sU` | Yes | DNS, SNMP, TFTP |
| FIN/Xmas/Null | `-sF`/`-sX`/`-sN` | Yes | Firewall bypass |
| ACK | `-sA` | Yes | Firewall rule mapping |

| NSE Category | Risk | Purpose |
|-------------|------|---------|
| `default` | Low | General info gathering |
| `safe` | Low | Non-disruptive checks |
| `vuln` | Low | Known vulnerability checks |
| `exploit` | **High** | Actual exploitation |
| `brute` | **High** | Credential brute-forcing |

---

## Error Handling & Logging

**Pre-execution pipeline** (runs before every tool):
1. **Sanitize** all arguments (strip shell injection)
2. **Scope check** all target IPs (block out-of-scope)
3. **Resolve** tool binary path
4. **Execute** with timeout, retries, error categorization

**Error categories:** `not_found`, `permission`, `timeout`, `usage`, `runtime`, `os_error`, `scope_violation`

**Log files per session:**

| File | Contents |
|------|----------|
| `logs/all.log` | Everything (DEBUG+) |
| `logs/errors.log` | WARNING+ only |
| `logs/stderr/*.stderr.log` | Full stderr from failed tools |
| `logs/scope_violations.json` | Scope violation records |

---

## Unit Test Suite

**73 tests** covering all core utilities:

| Test File | Tests | What it covers |
|-----------|------:|---------------|
| `test_validators.py` | 11 | Target validation, nmap option parsing |
| `test_sanitizer.py` | 15 | Shell injection, null bytes, path traversal |
| `test_scope_guard.py` | 11 | IP/CIDR scope, exclusions, violations, arg scanning |
| `test_credential_vault.py` | 12 | Add/dedup/persist/verify/mask/reuse credentials |
| `test_vuln_scorer.py` | 12 | CVSS scoring, heuristics, risk rating, narratives |
| `test_core.py` | 22 | Session state, parallel runner, all 6 parsers |

**Run the tests:**
```bash
pip install pytest
python -m pytest tests/ -v
```

Or without pytest:
```bash
python3 tests/test_validators.py   # Each file is also standalone
```

---

## Session & Report Structure

```
reports/20250322_143000/
├── nmap/                         # Raw scan output (XML, gnmap, nmap)
├── recon/                        # DNS, WHOIS, whatweb
├── enum/                         # Per-service enumeration + SNMPv3
├── exploits/                     # Hydra, CME, MSF scripts
├── loot/
│   ├── credential_vault.json     # All discovered credentials
│   ├── asrep_hashes_*.txt        # AS-REP roast hashes
│   ├── kerberoast_*.txt          # Kerberoast hashes
│   ├── crack_*.cracked           # Cracked password output
│   ├── bloodhound/               # BloodHound ZIP files
│   ├── linux_privesc_enum.sh
│   ├── windows_privesc_enum.bat
│   └── lateral_movement_guide.txt
├── evidence/screenshots/         # Web service screenshots
├── logs/
│   ├── all.log                   # Full session log
│   ├── errors.log                # Errors only
│   ├── scope_violations.json     # Scope violation records
│   └── stderr/                   # Per-tool stderr
├── session_checkpoint.json       # Resume checkpoint
├── results.json                  # Final results
├── report.html                   # Styled HTML with risk rating
├── report.json                   # Machine-readable
├── report.md                     # Markdown with tables
└── report.pdf                    # PDF (if backend available)
```

---

## Docker Support

```bash
docker build -t perfodia .
docker run --rm --net=host -v ./reports:/opt/perfodia/reports \
    perfodia -t 192.168.1.100 -m full -v
```

See `DOCKER.md` for full details. Two variants: `full` (~1.5 GB) and `minimal` (~400 MB).

---

## Extending the Framework

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    MODULE_NAME = "mymod"

    def run(self, previous_results=None):
        self.log_phase_start("My Phase")
        results = {"status": "running"}

        # Parallel execution across hosts
        def scan_host(ip):
            return self.runner.run("mytool", ["--target", ip], timeout=60)
        pr = self.parallel.run_per_host(self.targets, scan_host, "My Scan")

        # Store credentials
        self._store_credential(username="found", password="pass",
                               host="1.1.1.1", service="ssh", source_tool="mytool")

        # Score findings
        from utils.vuln_scorer import Severity
        self._score_finding(title="Weak Config", host="1.1.1.1",
                            severity=Severity.MEDIUM, cvss=5.0)

        results["status"] = "completed"
        return results
```

Register in `perfodia.py` module_map. Add tools to `TOOL_REGISTRY` in `validators.py`.

---

## Troubleshooting

| Problem | Solution |
|---------|---------|
| Not running as root | `sudo` or `--nmap-scan-type sT` |
| Scan too slow | `--ports 1-1024`, `--scan-speed fast` |
| Tool not found | `--check-tools`, check `~/.local/bin` |
| Empty results | `ping` target, try `--nmap-extra '-Pn'` |
| Resume not working | `--session` must match directory name in `reports/` |
| No screenshots | Install gowitness: `sudo bash install_deps.sh` |
| No PDF | `pip install weasyprint` or `apt install wkhtmltopdf` |
| TUI not showing | `pip install rich` |
| Scope violation | Target IP not in `-t` range; check `logs/scope_violations.json` |
| Cracking finds nothing | Check wordlist path, increase `max_runtime` |
| AD module no DCs | Ensure LDAP(389)+Kerberos(88) in scan range |

---

## Glossary

| Term | Definition |
|------|-----------|
| **AS-REP Roasting** | Extracting hashes for AD accounts without Kerberos pre-auth |
| **BloodHound** | AD attack path analysis via graph database |
| **CIDR** | IP range notation — `192.168.1.0/24` = 256 addresses |
| **CVE** | Unique vulnerability ID (e.g., CVE-2021-44228) |
| **CVSS** | Vulnerability scoring system (0.0-10.0) |
| **Kerberoasting** | Extracting service ticket hashes for offline cracking |
| **NSE** | Nmap Scripting Engine — 600+ scripts |
| **Scope guard** | Framework component that blocks out-of-scope targets |
| **SNMPv3** | SNMP with authentication and encryption |
| **SPN** | Service Principal Name — Kerberoastable AD accounts |

---

## License

This project is provided as-is for educational and authorized testing purposes only.
