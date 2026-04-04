"""
Config Wizard — interactive configuration generator.

Walks the user through creating a tailored YAML config file by asking
questions about their lab environment and testing goals.

Launch with: perfodia.py --init
"""

import os
import sys
import yaml
import logging
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# ANSI colors for the wizard UI
CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
BOLD = "\033[1m"
NC = "\033[0m"


def _ask(prompt: str, default: str = "", choices: list = None) -> str:
    """Ask a question with optional default and choices."""
    suffix = ""
    if choices:
        suffix = f" ({'/'.join(choices)})"
    if default:
        suffix += f" [{default}]"

    try:
        answer = input(f"{CYAN}  ? {NC}{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not answer and default:
        return default
    if choices and answer and answer.lower() not in [c.lower() for c in choices]:
        print(f"{YELLOW}    Invalid choice. Using default: {default}{NC}")
        return default
    return answer or default


def _ask_bool(prompt: str, default: bool = True) -> bool:
    """Ask a yes/no question."""
    default_str = "Y/n" if default else "y/N"
    answer = _ask(prompt, default_str).lower()
    if answer in ("y", "yes", "y/n"):
        return True
    if answer in ("n", "no"):
        return False
    return default


def _ask_int(prompt: str, default: int, min_val: int = 0, max_val: int = 999) -> int:
    """Ask for an integer value."""
    answer = _ask(prompt, str(default))
    try:
        val = int(answer)
        return max(min_val, min(val, max_val))
    except ValueError:
        return default


def run_config_wizard(output_dir: str = "configs") -> str:
    """
    Run the interactive config wizard.

    Returns:
        Path to the generated config file.
    """
    print()
    print(f"{BOLD}{CYAN}{'='*60}{NC}")
    print(f"{BOLD}{CYAN}  Perfodia — Configuration Wizard{NC}")
    print(f"{BOLD}{CYAN}{'='*60}{NC}")
    print()
    print(f"  This wizard will help you create a tailored configuration")
    print(f"  file for your lab environment. Press Enter to accept defaults.")
    print()

    config: Dict[str, Any] = {}

    # ── Section 1: General ──
    print(f"\n{GREEN}  ── General Settings ──{NC}\n")

    config_name = _ask("Config file name", "mylab")
    threads = _ask_int("Parallel threads (how many hosts to test at once)", 10, 1, 50)
    timeout = _ask_int("Tool timeout in seconds", 300, 30, 1800)

    config["general"] = {
        "threads": threads,
        "timeout": timeout,
        "max_retries": 2,
        "retry_delay": 5,
    }

    # ── Section 2: Scanning ──
    print(f"\n{GREEN}  ── Scanning Configuration ──{NC}\n")

    scan_approach = _ask(
        "Scan approach",
        "normal",
        ["quick", "normal", "thorough", "stealth"],
    )

    port_presets = {
        "quick": "1-1024",
        "normal": "1-65535",
        "thorough": "1-65535",
        "stealth": "1-1024",
    }
    timing_presets = {"quick": 4, "normal": 4, "thorough": 3, "stealth": 2}

    config["nmap"] = {
        "default_ports": port_presets.get(scan_approach, "1-65535"),
        "timing_template": timing_presets.get(scan_approach, 4),
        "max_retries": 2,
        "host_timeout": "5m" if scan_approach != "thorough" else "10m",
        "scripts": ["default", "vuln", "safe"],
        "extra_args": [],
    }

    config["masscan"] = {"rate": 500 if scan_approach == "stealth" else 1000, "ports": "1-65535"}

    # ── Section 3: Enumeration ──
    print(f"\n{GREEN}  ── Service Enumeration ──{NC}\n")

    has_smb = _ask_bool("Does your lab have Windows/SMB hosts?")
    has_snmp = _ask_bool("Does your lab have SNMP devices (routers, switches)?")
    has_web = _ask_bool("Does your lab have web servers?")

    config["enumeration"] = {
        "smb": {"enabled": has_smb, "depth": "full" if has_smb else "basic"},
        "snmp": {
            "enabled": has_snmp,
            "community_strings": ["public", "private", "community"],
        },
        "dns": {"enabled": True, "wordlist": "/usr/share/wordlists/dns.txt"},
        "http": {
            "enabled": has_web,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "extensions": "php,html,txt,asp,aspx,jsp",
        },
    }

    # ── Section 4: Web Application Testing ──
    if has_web:
        print(f"\n{GREEN}  ── Web Application Testing ──{NC}\n")
        sqlmap = _ask_bool("Enable SQL injection testing (sqlmap)?")
        config["webapp"] = {
            "enabled": True,
            "sqlmap_enabled": sqlmap,
            "sqlmap_level": 1,
            "sqlmap_risk": 1,
            "check_git_exposure": True,
            "check_env_exposure": True,
            "check_backup_files": True,
        }
    else:
        config["webapp"] = {"enabled": False}

    # ── Section 5: Active Directory ──
    print(f"\n{GREEN}  ── Active Directory ──{NC}\n")

    has_ad = _ask_bool("Does your lab have an Active Directory environment?")
    if has_ad:
        bloodhound = _ask_bool("Enable BloodHound data collection?")
        spray = _ask_bool("Enable password spraying?")
        config["ad"] = {
            "enabled": True,
            "bloodhound_collect": bloodhound,
            "spray_passwords": ["Password1", "Welcome1", "Company123"],
            "max_spray_users": 200,
            "check_smb_signing": True,
        }
    else:
        config["ad"] = {"enabled": False}

    # ── Section 6: Exploitation ──
    print(f"\n{GREEN}  ── Exploitation Settings ──{NC}\n")

    safe_mode = _ask_bool("Enable safe mode (skip brute-force/destructive attacks)?")
    auto_exploit = False
    if not safe_mode:
        auto_exploit = _ask_bool("Enable automated exploitation? (ONLY for isolated labs)", False)

    config["exploitation"] = {
        "auto_exploit": auto_exploit,
        "safe_mode": safe_mode,
        "max_exploit_threads": 3,
    }

    # ── Section 7: Credentials ──
    print(f"\n{GREEN}  ── Credential Settings ──{NC}\n")

    wordlist_path = _ask("Password wordlist path", "/usr/share/wordlists/rockyou.txt")
    lockout_threshold = _ask_int("Account lockout threshold (max attempts per account)", 3, 1, 10)

    config["credentials"] = {
        "usernames": ["admin", "root", "administrator", "user", "test"],
        "passwords_file": wordlist_path,
        "spray_lockout_threshold": lockout_threshold,
        "spray_delay": 30,
    }

    # ── Section 8: Password Cracking ──
    print(f"\n{GREEN}  ── Password Cracking ──{NC}\n")

    cracking = _ask_bool("Enable password cracking (hashcat/john)?")
    config["cracking"] = {
        "enabled": cracking,
        "wordlist": wordlist_path,
        "max_runtime": 600,
        "use_rules": True,
    }

    # ── Section 9: Reporting ──
    config["reporting"] = {
        "include_raw_output": True,
        "severity_threshold": "low",
        "include_remediation": True,
        "include_risk_rating": True,
        "include_screenshots": True,
        "generate_pdf": False,
    }

    config["screenshots"] = {"enabled": True, "max_workers": 5, "timeout": 30}
    config["parallel"] = {"enabled": True}

    # ── Write config file ──
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{config_name}.yaml"

    print(f"\n{GREEN}  ── Saving Configuration ──{NC}\n")

    header = (
        "# =============================================================================\n"
        f"# Perfodia Configuration — Generated by Config Wizard\n"
        f"# File: {out_path}\n"
        "# WARNING: Only use against systems you own or have authorization to test.\n"
        "# =============================================================================\n\n"
    )

    try:
        with open(out_path, "w") as f:
            f.write(header)
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        print(f"  {GREEN}✓{NC} Configuration saved to: {BOLD}{out_path}{NC}")
        print()
        print(f"  Use it with:")
        print(f"    {CYAN}sudo python3 perfodia.py -t <target> -m full -c {out_path} -v{NC}")
        print()
        return str(out_path)

    except Exception as e:
        print(f"  {YELLOW}✗{NC} Failed to save config: {e}")
        return ""
