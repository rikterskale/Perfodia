"""
Scope Guard — enforces engagement scope by validating every target IP
against allowed/denied ranges before any tool execution.

Prevents the most dangerous real-world pentesting mistake: accidentally
testing systems outside the authorized scope.
"""

import ipaddress
import logging
import re
import threading
from pathlib import Path
from typing import List, Set, Optional, Union

logger = logging.getLogger(__name__)


class ScopeGuard:
    """
    Thread-safe scope enforcement for all tool executions.

    Maintains an allow-list (in-scope) and deny-list (excluded) of IP
    ranges and hostnames.  Every target IP is checked before any tool
    runs.  Violations are logged and blocked.

    Usage:
        guard = ScopeGuard(
            targets=["192.168.1.0/24"],
            exclusions=["192.168.1.1"],
        )
        guard.check("192.168.1.100")  # True — in scope
        guard.check("10.0.0.1")       # False — out of scope
        guard.check("192.168.1.1")    # False — excluded
    """

    def __init__(
        self,
        targets: List[str],
        exclusions: Optional[List[str]] = None,
        strict: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        self._strict = strict
        self._violations: List[dict] = []

        # Parse target ranges into networks
        self._allowed_networks: List[ipaddress.IPv4Network] = []
        self._allowed_hosts: Set[str] = set()
        for t in targets:
            self._add_target(t)

        # Parse exclusions
        self._denied_networks: List[ipaddress.IPv4Network] = []
        self._denied_hosts: Set[str] = set()
        for e in (exclusions or []):
            self._add_exclusion(e)

        logger.info(
            f"[SCOPE] Initialized: {len(self._allowed_networks)} allowed networks, "
            f"{len(self._allowed_hosts)} allowed hosts, "
            f"{len(self._denied_networks) + len(self._denied_hosts)} exclusions"
        )

    def _add_target(self, target: str) -> None:
        """Add a target to the allowed scope."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            self._allowed_networks.append(network)
        except ValueError:
            # Treat as hostname
            self._allowed_hosts.add(target.lower().strip())

    def _add_exclusion(self, exclusion: str) -> None:
        """Add an exclusion to the deny list."""
        try:
            network = ipaddress.ip_network(exclusion, strict=False)
            self._denied_networks.append(network)
        except ValueError:
            self._denied_hosts.add(exclusion.lower().strip())

    def check(self, target: str, tool_name: str = "", action: str = "") -> bool:
        """
        Check if a target is within scope.

        Args:
            target:    IP address or hostname to check
            tool_name: Name of the tool requesting the check (for logging)
            action:    Description of what the tool wants to do (for logging)

        Returns:
            True if in scope, False if out of scope or excluded.
        """
        target = target.strip()
        if not target:
            return False

        # Check if it's an IP address
        try:
            addr = ipaddress.ip_address(target)
            result = self._check_ip(addr)
        except ValueError:
            # Hostname — check against allowed hostnames first
            if target.lower() in self._allowed_hosts:
                result = True
            else:
                # Resolve hostname to IP and check that IP against scope
                import socket
                try:
                    resolved_ip = socket.gethostbyname(target)
                    addr = ipaddress.ip_address(resolved_ip)
                    result = self._check_ip(addr)
                    if not result:
                        logger.warning(
                            f"[SCOPE] Hostname '{target}' resolves to "
                            f"{resolved_ip} which is OUT OF SCOPE."
                        )
                except (socket.gaierror, ValueError):
                    # Cannot resolve — reject in strict mode
                    result = not self._strict

        if not result:
            self._record_violation(target, tool_name, action)

        return result

    def _check_ip(self, addr: ipaddress.IPv4Address) -> bool:
        """Check an IP against allowed and denied ranges."""
        # Deny list takes priority
        for network in self._denied_networks:
            if addr in network:
                return False

        # Check allow list
        for network in self._allowed_networks:
            if addr in network:
                return True

        # Not in any allowed range
        return False

    def _record_violation(self, target: str, tool_name: str, action: str) -> None:
        """Record and log a scope violation."""
        with self._lock:
            from datetime import datetime
            violation = {
                "target": target,
                "tool": tool_name,
                "action": action,
                "timestamp": datetime.now().isoformat(),
            }
            self._violations.append(violation)
            logger.error(
                f"[SCOPE VIOLATION] Target '{target}' is OUT OF SCOPE. "
                f"Tool: {tool_name or 'unknown'}, Action: {action or 'unknown'}. "
                f"Execution BLOCKED."
            )

    def extract_ips_from_args(self, args: List[str]) -> List[str]:
        """
        Extract IP addresses and hostnames from a tool's argument list.

        Checks for patterns like bare IPs, user@host, smb://host, etc.
        """
        ips: List[str] = []
        ip_pattern = re.compile(
            r'(?:^|[@/=\s])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[:/\s]|$)'
        )
        for arg in args:
            for match in ip_pattern.finditer(arg):
                ips.append(match.group(1))
        return ips

    def check_tool_args(self, tool_name: str, args: List[str]) -> bool:
        """
        Scan a tool's argument list for out-of-scope targets.

        Returns True if all targets in the args are in scope.
        """
        ips = self.extract_ips_from_args(args)
        for ip in ips:
            if not self.check(ip, tool_name=tool_name, action=f"args: {' '.join(args[:5])}"):
                return False
        return True

    @property
    def violations(self) -> List[dict]:
        """Return all recorded scope violations."""
        with self._lock:
            return list(self._violations)

    @property
    def violation_count(self) -> int:
        """Return total violation count."""
        with self._lock:
            return len(self._violations)

    def save_violations(self, session_dir: Path) -> None:
        """Save violations log to session directory."""
        if not self._violations:
            return
        import json
        path = session_dir / "logs" / "scope_violations.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(path, "w") as f:
                json.dump(self._violations, f, indent=2)
            logger.warning(f"[SCOPE] {len(self._violations)} violations saved to {path}")
        except Exception as e:
            logger.error(f"[SCOPE] Failed to save violations: {e}")
