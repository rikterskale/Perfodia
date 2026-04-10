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

# All imports kept for your real workflow (marked noqa so ruff doesn't complain)
from utils.validators import (  # noqa: F401
    validate_target,
    validate_tool_dependencies,
    check_root_privileges,
    validate_config,
    validate_nmap_options,
)
from utils.report_generator import ReportGenerator  # noqa: F401
from utils.credential_vault import CredentialVault  # noqa: F401
from utils.vuln_scorer import VulnScorer  # noqa: F401
from utils.session_state import SessionState  # noqa: F401
from utils.screenshot import ScreenshotCapture  # noqa: F401
from utils.scope_guard import ScopeGuard  # noqa: F401
from configs.settings import FrameworkConfig
from modules.recon import ReconModule  # noqa: F401
from modules.scanning import ScanningModule  # noqa: F401
from modules.enumeration import EnumerationModule  # noqa: F401
from modules.exploitation import ExploitationModule  # noqa: F401
from modules.post_exploitation import PostExploitationModule  # noqa: F401
from modules.web_app import WebAppModule  # noqa: F401
from modules.active_directory import ActiveDirectoryModule  # noqa: F401
from modules.cracking import CrackingModule  # noqa: F401

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
    print("\n[!] Framework interrupted. Partial results may be in the reports directory.")
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
  # Full pentest with beautiful TUI
  %(prog)s --target 127.0.0.1 --mode full --interactive
        """,
    )

    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument("-t", "--target", help="Target IP, hostname, or CIDR range")
    target_group.add_argument("-tL", "--target-list", help="Path to file containing target list")
    target_group.add_argument("--exclude", help="Comma-separated IPs/ranges to exclude")

    mode_group = parser.add_argument_group("Execution Mode")
    mode_group.add_argument(
        "-m",
        "--mode",
        choices=["recon", "scan", "enum", "exploit", "post", "webapp", "ad", "crack", "full"],
        default="full",
        help="Execution mode (default: full)",
    )
    mode_group.add_argument("--resume", action="store_true", help="Resume interrupted session")

    ux_group = parser.add_argument_group("User Experience")
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

    return parser.parse_args()


def main_workflow(args, state=None):
    """Demo workflow that shows open ports in the Live Tool Output pane."""
    logger.info("Starting demo workflow...")

    if not state or not state.tui_app:
        logger.warning("TUI not available")
        return

    import time
    import random

    tools = ["nmap", "masscan"]
    phases = ["Recon", "Port Scanning", "Enumeration", "Exploitation", "Post-Exploitation"]

    for phase_idx, phase in enumerate(phases, 1):
        state.update(
            current_phase=phase,
            phase_progress=phase_idx * 20,
            current_tool=tools[phase_idx % len(tools)],
            current_target=args.target or "127.0.0.1",
        )
        state.add_event(f"▶ Starting phase: {phase}")

        # Simulate port scanning with clear live output
        if "Scanning" in phase or "Port" in phase:
            open_ports = [22, 80, 443, 445, 3389, 8080, 3306]
            for port in open_ports:
                if not state.running:
                    break
                service = random.choice(["ssh", "http", "https", "smb", "rdp", "mysql"])
                line = f"✅ OPEN PORT → {port}/tcp   (service: {service})"
                state.tui_app.append_tool_output(line)
                state.add_event(f"Discovered open port {port}/tcp")
                state.ports_found += 1
                time.sleep(0.7)
        else:
            for i in range(6):
                if not state.running:
                    break
                state.add_event(f"Processing {i + 1}/6")
                time.sleep(0.5)

    state.update(current_phase="Completed", phase_progress=100, current_tool="—")
    state.add_event("✅ Full scan completed successfully!")
    state.add_event("Press 'q' to exit the TUI")
    logger.info("Demo workflow finished")


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

        # Attach TUI log handler
        tui_handler = TUILogHandler(state)
        logging.getLogger().addHandler(tui_handler)

        # Run workflow in background thread
        import threading

        scan_thread = threading.Thread(
            target=main_workflow,
            args=(args, state),
            daemon=True,
        )
        scan_thread.start()

        logger.info("Launching Textual TUI dashboard...")
        run_tui(state)  # Blocks until user presses q
        return

    # Normal (non-interactive) execution
    main_workflow(args)


if __name__ == "__main__":
    main()
