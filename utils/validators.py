"""
Validators for targets, tool dependencies, privileges, and configuration.
"""

import os
import re
import shutil
import socket
import ipaddress
import subprocess
import logging
from pathlib import Path
from typing import Tuple, Optional, Dict, Iterable

logger = logging.getLogger(__name__)

# ── All tools the framework can leverage ──

TOOL_ALIASES = {
    "crackmapexec": ("crackmapexec", "netexec", "nxc"),
}


def _candidate_binaries(tool_name: str) -> Iterable[str]:
    """Return the PATH candidates for a logical tool name."""
    return TOOL_ALIASES.get(tool_name, (tool_name,))


def resolve_tool_binary(tool_name: str) -> Optional[str]:
    """Resolve a logical tool name to the first matching executable in PATH."""
    for candidate in _candidate_binaries(tool_name):
        path = shutil.which(candidate)
        if path:
            return path
    return None


TOOL_REGISTRY: Dict[str, tuple[str, str, bool]] = {
    # (logical_name, package_hint, required)
    "nmap": ("nmap", "nmap", True),
    "masscan": ("masscan", "masscan", False),
    "nikto": ("nikto", "nikto", False),
    "enum4linux-ng": ("enum4linux-ng", "pip: enum4linux-ng", False),
    "gobuster": ("gobuster", "gobuster", False),
    "hydra": ("hydra", "hydra", False),
    "snmpwalk": ("snmpwalk", "snmp", False),
    "onesixtyone": ("onesixtyone", "onesixtyone", False),
    "whatweb": ("whatweb", "whatweb", False),
    "smbclient": ("smbclient", "smbclient", False),
    "rpcclient": ("rpcclient", "smbclient", False),
    "dig": ("dig", "dnsutils", False),
    "whois": ("whois", "whois", False),
    "searchsploit": ("searchsploit", "exploitdb", False),
    "msfconsole": ("msfconsole", "metasploit-framework", False),
    "crackmapexec": ("crackmapexec", "pip: netexec (or crackmapexec)", False),
    "john": ("john", "john", False),
    "hashcat": ("hashcat", "hashcat", False),
    "impacket-secretsdump": ("impacket-secretsdump", "pip: impacket", False),
    "impacket-psexec": ("impacket-psexec", "pip: impacket", False),
    "impacket-GetNPUsers": ("impacket-GetNPUsers", "pip: impacket", False),
    "impacket-GetUserSPNs": ("impacket-GetUserSPNs", "pip: impacket", False),
    "responder": ("responder", "responder", False),
    "nbtscan": ("nbtscan", "nbtscan", False),
    "dnsrecon": ("dnsrecon", "dnsrecon", False),
    "wfuzz": ("wfuzz", "pip: wfuzz", False),
    "curl": ("curl", "curl", True),
    # ── New tools ──
    "ffuf": ("ffuf", "github: ffuf/ffuf", False),
    "sqlmap": ("sqlmap", "sqlmap", False),
    "gowitness": ("gowitness", "github: sensepost/gowitness", False),
    "ldapsearch": ("ldapsearch", "ldap-utils", False),
    "bloodhound-python": ("bloodhound-python", "pip: bloodhound", False),
}


def validate_target(target: str) -> Tuple[bool, Optional[str]]:
    """
    Validate and normalize a target specification.

    Accepts:
        - IPv4 address (192.168.1.1)
        - IPv4 CIDR range (192.168.1.0/24)
        - Hostname (server.lab.local)

    Returns:
        (is_valid, normalized_target) tuple

    Rejects invalid formats and multicast addresses.
    Private/internal ranges are allowed since this is a lab framework.
    """
    target = target.strip()

    if not target:
        logger.error("Empty target provided")
        return False, None

    # Try as IP address
    try:
        addr = ipaddress.ip_address(target)
        if addr.is_multicast:
            logger.warning(f"Target {target} is a multicast address")
            return False, None
        logger.debug(f"Target validated as IP: {target}")
        return True, str(addr)
    except ValueError:
        pass

    # Try as CIDR network
    try:
        network = ipaddress.ip_network(target, strict=False)
        prefix = network.prefixlen
        if prefix < 16:
            logger.error(
                f"CIDR range /{prefix} is too broad. "
                f"Minimum /{16} for safety. Target: {target}"
            )
            return False, None
        logger.debug(f"Target validated as CIDR: {network}")
        return True, str(network)
    except ValueError:
        pass

    # Try as hostname
    hostname_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    if hostname_pattern.match(target):
        try:
            resolved = socket.gethostbyname(target)
            logger.debug(f"Hostname {target} resolved to {resolved}")
            return True, target
        except socket.gaierror:
            logger.warning(
                f"Hostname {target} could not be resolved. "
                f"Accepting anyway (may resolve later)."
            )
            return True, target

    logger.error(f"Invalid target format: {target}")
    return False, None


def validate_tool_dependencies(verbose: bool = False) -> bool:
    """
    Check availability of all registered tools.

    Args:
        verbose: Print status of each tool

    Returns:
        True if all *required* tools are available
    """
    all_required_ok = True
    available_count = 0
    missing_optional = []

    for name, (_logical_name, package_hint, required) in sorted(TOOL_REGISTRY.items()):
        path = resolve_tool_binary(name)
        found = path is not None

        if found:
            available_count += 1
            version = _get_tool_version(Path(path).name)
            if verbose:
                status = f"  [✓] {name:<28} {path}"
                if version:
                    status += f"  ({version})"
                print(status)
        else:
            if required:
                all_required_ok = False
                if verbose:
                    print(
                        f"  [✗] {name:<28} MISSING (REQUIRED) — install: {package_hint}"
                    )
            else:
                missing_optional.append(name)
                if verbose:
                    print(
                        f"  [—] {name:<28} not found (optional) — install: {package_hint}"
                    )

    total = len(TOOL_REGISTRY)
    print(f"\n  Tools found: {available_count}/{total}")
    if missing_optional and verbose:
        print(f"  Optional tools missing: {len(missing_optional)}")
    if not all_required_ok:
        print("  [!] Some REQUIRED tools are missing. Install them before proceeding.")

    return all_required_ok


def _get_tool_version(binary: str) -> Optional[str]:
    """Attempt to extract version string from a tool."""
    version_flags = ["--version", "-V", "-v", "version"]
    for flag in version_flags:
        try:
            result = subprocess.run(
                [binary, flag],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = (result.stdout + result.stderr).strip()
            if output:
                # Grab first line, truncate
                first_line = output.split("\n")[0][:80]
                return first_line
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            continue
        except Exception:
            continue
    return None


def check_root_privileges() -> bool:
    """Check if the framework is running with root privileges."""
    return os.geteuid() == 0


def validate_config(config) -> bool:
    """
    Basic sanity checks on loaded configuration.

    Returns:
        True if configuration passes validation
    """
    errors = []

    # Validate nmap timing template
    timing = config.get("nmap", "timing_template", default=4)
    if not isinstance(timing, int) or timing < 0 or timing > 5:
        errors.append(f"nmap.timing_template must be 0-5, got: {timing}")

    # Validate thread count
    threads = config.get("general", "threads", default=10)
    if not isinstance(threads, int) or threads < 1 or threads > 100:
        errors.append(f"general.threads must be 1-100, got: {threads}")

    # Validate timeout
    timeout = config.get("general", "timeout", default=300)
    if not isinstance(timeout, (int, float)) or timeout < 10:
        errors.append(f"general.timeout must be >= 10 seconds, got: {timeout}")

    for err in errors:
        logger.error(f"Config validation: {err}")

    return len(errors) == 0


def is_tool_available(tool_name: str) -> bool:
    """Quick check if a specific tool (or supported alias) is available in PATH."""
    return resolve_tool_binary(tool_name) is not None


# ── Nmap option validation ──

# Flags that could cause damage or scan the entire internet
_NMAP_DANGEROUS_FLAGS = {
    "--script-updatedb",  # Modifies local system
    "-iR",  # Random targets — never in a controlled lab framework
}

# Flags that override output files (framework manages its own)
_NMAP_OUTPUT_FLAGS = {"-oX", "-oN", "-oG", "-oA", "-oS"}

# Flags that the framework already handles (informational warning only)
_NMAP_MANAGED_FLAGS = {
    "-sS",
    "-sV",
    "-sC",
    "-O",
    "-T0",
    "-T1",
    "-T2",
    "-T3",
    "-T4",
    "-T5",
    "--open",
    "--reason",
}


def validate_nmap_options(
    opts_string: str,
    allow_all: bool = False,
) -> tuple:
    """
    Validate a user-supplied nmap option string.

    Checks for:
        - Dangerous flags that should never be used in a lab framework
        - Shell injection characters
        - Output flags that conflict with framework-managed output
        - Flags that duplicate the framework's defaults (warning only)

    Args:
        opts_string: Raw string from --nmap-extra or --nmap-raw
        allow_all:   If True (used by --nmap-raw), skip the "already managed"
                     warnings since the user is intentionally replacing defaults.

    Returns:
        (is_valid, parsed_args_list, warnings_list) tuple.
        ``is_valid`` is False only for truly dangerous / unparseable input.
        ``warnings_list`` contains non-fatal advisory messages.
    """
    import shlex

    warnings = []
    opts_string = opts_string.strip()

    if not opts_string:
        return True, [], []

    # ── Guard against shell metacharacters ──
    dangerous_chars = set(";|&`$(){}\\!")
    found_chars = dangerous_chars & set(opts_string)
    if found_chars:
        warnings.append(
            f"Shell metacharacters detected: {found_chars}. "
            f"These are stripped for safety. If you need them, "
            f"run nmap manually."
        )
        for ch in found_chars:
            opts_string = opts_string.replace(ch, "")

    # ── Parse into tokens ──
    try:
        tokens = shlex.split(opts_string)
    except ValueError as e:
        return False, [], [f"Could not parse nmap options (mismatched quotes?): {e}"]

    if not tokens:
        return True, [], []

    # ── Check each token ──
    clean_tokens = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue

        # Dangerous flags
        if token in _NMAP_DANGEROUS_FLAGS:
            return (
                False,
                [],
                [
                    f"Flag '{token}' is blocked — it is dangerous in an "
                    f"automated framework.  Run nmap manually if you need it."
                ],
            )

        # Output file flags — framework manages these; skip flag AND its value
        if token in _NMAP_OUTPUT_FLAGS:
            warnings.append(
                f"Flag '{token}' skipped — the framework manages its own "
                f"output files (-oX, -oN).  Your scan results will still "
                f"be saved automatically."
            )
            skip_next = True  # The next token is the file path — skip it too
            continue

        # Managed flags — informational only (only in --nmap-extra mode)
        if not allow_all and token in _NMAP_MANAGED_FLAGS:
            warnings.append(
                f"Flag '{token}' is already set by the framework's default "
                f"scan.  It will be included but may duplicate behavior.  "
                f"Use --nmap-raw to replace all defaults instead."
            )

        clean_tokens.append(token)

    return True, clean_tokens, warnings
