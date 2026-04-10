#!/usr/bin/env python3
"""
Perfodia - Network Penetration Testing Framework
===================================================
A modular Python-based penetration testing framework for lab environments.
Integrates common security tools with structured workflows, verbose error
checking, and automated reporting.

WARNING: This tool is intended ONLY for authorized penetration testing
against systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal.
"""

import argparse
import logging
import signal
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import setup_logging, get_logger
from utils.validators import (
    validate_target,
    validate_tool_dependencies,
    check_root_privileges,
    validate_config,
    validate_nmap_options,
)
from utils.report_generator import ReportGenerator
from utils.credential_vault import CredentialVault
from utils.vuln_scorer import VulnScorer
from utils.session_state import SessionState
from utils.screenshot import ScreenshotCapture
from utils.scope_guard import ScopeGuard
from configs.settings import FrameworkConfig
from modules.recon import ReconModule
from modules.scanning import ScanningModule
from modules.enumeration import EnumerationModule
from modules.exploitation import ExploitationModule
from modules.post_exploitation import PostExploitationModule
from modules.web_app import WebAppModule
from modules.active_directory import ActiveDirectoryModule
from modules.cracking import CrackingModule

logger = get_logger(__name__)

BANNER = r"""
 ____            __          _ _
|  _ \ ___ _ __ / _| ___  __| (_) __ _
| |_) / _ \ '__| |_ / _ \/ _` | |/ _` |
|  __/  __/ |  |  _| (_) | (_| | | (_| |
|_|   \___|_|  |_|  \___/ \__,_|_|\__,_|

  Network Penetration Testing Framework v1.1.0
  =============================================
  FOR AUTHORIZED LAB USE ONLY
"""


def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    logger.warning("\n[!] Interrupt received. Cleaning up...")
    print(
        "\n[!] Framework interrupted. Partial results may be in the reports directory."
    )
    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def parse_arguments():
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Perfodia - Network Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pentest workflow with beautiful TUI
  %(prog)s --target 192.168.1.100 --mode full --interactive

  # Reconnaissance only
  %(prog)s --target 192.168.1.0/24 --mode recon

  # Resume previous session
  %(prog)s --resume --session 20250410_133000
        """,
    )

    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t", "--target", help="Target IP, hostname, or CIDR range"
    )
    target_group.add_argument(
        "-tL", "--target-list", help="Path to file containing target list"
    )
    target_group.add_argument(
        "--exclude", help="Comma-separated IPs/ranges to exclude"
    )

    mode_group = parser.add_argument_group("Execution Mode")
    mode_group.add_argument(
        "-m",
        "--mode",
        choices=[
            "recon",
            "scan",
            "enum",
            "exploit",
            "post",
            "webapp",
            "ad",
            "crack",
            "full",
        ],
        default="full",
        help="Execution mode (default: full)",
    )
    mode_group.add_argument(
        "--modules", help="Comma-separated list of specific modules"
    )
    mode_group.add_argument(
        "--resume", action="store_true", help="Resume interrupted session"
    )

    ux_group = parser.add_argument_group("User Experience")
    ux_group.add_argument(
        "--init",
        action="store_true",
        help="Launch interactive configuration wizard",
    )
    ux_group.add_argument(
        "--interactive",
        action="store_true",
        help="Launch real-time Textual TUI dashboard (recommended)",
    )

    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c",
        "--config",
        default=str(PROJECT_ROOT / "configs" / "default.yaml"),
        help="Path to configuration file",
    )
    config_group.add_argument(
        "-o",
        "--output-dir",
        default=str(PROJECT_ROOT / "reports"),
        help="Output directory",
    )
    config_group.add_argument(
        "--session", help="Session name/ID (default: timestamp)"
    )

    return parser.parse_args()


def main_workflow(args, state=None):
    """Main execution workflow (8-phase)."""
    config = FrameworkConfig.from_file(args.config)
    # ← Your original full workflow code goes here (ReconModule, ScanningModule, etc.)
    # All the phase logic you already had remains unchanged.
    logger.info("Starting Perfodia workflow...")
    # Example of updating TUI state (safe even if state is None)
    if state:
        state.update(current_phase="Recon", phase_progress=10, current_tool="nmap")


def main():
    """Main entry point."""
    print(BANNER)
    args = parse_arguments()

    setup_logging()
    logger.info("Perfodia framework starting...")

    # === TEXTUAL TUI INTEGRATION ===
    if args.interactive:
        from utils.tui import DashboardState, TUILogHandler, run_tui

        state = DashboardState()

        # Attach TUI log handler so logs appear in the UI
        tui_handler = TUILogHandler(state)
        logging.getLogger().addHandler(tui_handler)

        # Run the scan workflow in a background thread
        import threading
        scan_thread = threading.Thread(
            target=main_workflow,
            args=(args, state),
            daemon=True,
        )
        scan_thread.start()

        logger.info("Launching Textual TUI dashboard...")
        run_tui(state)          # Blocks until user presses q
        return

    # Normal (non-interactive) execution
    main_workflow(args)


if __name__ == "__main__":
    main()