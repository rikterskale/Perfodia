"""
Base module — abstract class all pentest phase modules inherit from.
"""

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional

from utils.tool_runner import ToolRunner
from utils.parallel import ParallelRunner

logger = logging.getLogger(__name__)


class BaseModule(ABC):
    """
    Abstract base for all penetration testing phase modules.

    Provides:
        - Shared configuration access
        - ToolRunner instance for executing external tools
        - ParallelRunner for concurrent per-host operations
        - CredentialVault access for cross-phase credential sharing
        - VulnScorer access for finding severity classification
        - Standardized run/report interface
    """

    MODULE_NAME = "base"

    def __init__(
        self,
        config,
        targets: List[str],
        exclusions: List[str],
        session_dir: Path,
        dry_run: bool = False,
        verbose: int = 0,
        credential_vault=None,
        vuln_scorer=None,
        scope_guard=None,
    ):
        self.config = config
        self.targets = targets
        self.exclusions = exclusions
        self.session_dir = session_dir
        self.dry_run = dry_run
        self.verbose = verbose
        self.credential_vault = credential_vault
        self.vuln_scorer = vuln_scorer
        self.scope_guard = scope_guard

        self.runner = ToolRunner(
            config=config,
            session_dir=session_dir,
            dry_run=dry_run,
            verbose=verbose,
            scope_guard=scope_guard,
        )

        # Parallel runner — uses thread count from config
        self.parallel = ParallelRunner(
            max_workers=config.get("general", "threads", default=10)
        )

        self.results: Dict[str, Any] = {"status": "pending"}

    @abstractmethod
    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Execute the module's workflow.

        Args:
            previous_results: Results from earlier phases (for chaining)

        Returns:
            Dictionary of structured results
        """
        pass

    def _get_open_ports_for_host(self, host_data: Dict) -> Dict[int, Dict]:
        """Extract open ports from scan results for a host."""
        ports = {}
        for p in host_data.get("ports", []):
            if p.get("state") == "open":
                ports[p["port"]] = p
        return ports

    def _get_hosts_with_service(
        self, scan_results: Dict, service_name: str
    ) -> List[Dict]:
        """Find hosts running a specific service from scan results."""
        matches = []
        for host in scan_results.get("hosts", []):
            for port in host.get("ports", []):
                svc = port.get("service", {})
                if service_name.lower() in svc.get("name", "").lower():
                    matches.append({
                        "ip": host.get("ip", ""),
                        "hostname": host.get("hostname", ""),
                        "port": port.get("port"),
                        "service": svc,
                    })
        return matches

    def _store_credential(self, **kwargs):
        """Store a credential in the vault (if available)."""
        if self.credential_vault:
            self.credential_vault.add_password(
                source_phase=self.MODULE_NAME,
                **kwargs,
            )

    def _store_hash(self, **kwargs):
        """Store a hash credential in the vault (if available)."""
        if self.credential_vault:
            self.credential_vault.add_hash(
                source_phase=self.MODULE_NAME,
                **kwargs,
            )

    def _score_finding(self, **kwargs):
        """Score a vulnerability finding (if scorer available)."""
        if self.vuln_scorer:
            return self.vuln_scorer.score_misconfiguration(
                source_phase=self.MODULE_NAME,
                **kwargs,
            )
        return None

    def log_phase_start(self, phase: str):
        """Log the beginning of a phase."""
        logger.info(f"[{self.MODULE_NAME.upper()}] Starting {phase}...")

    def log_phase_end(self, phase: str, success: bool = True):
        """Log the completion of a phase."""
        status = "completed" if success else "failed"
        logger.info(f"[{self.MODULE_NAME.upper()}] {phase} {status}")
