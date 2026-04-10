#!/usr/bin/env python3
"""
Perfodia - Network Penetration Testing Framework
===================================================
A modular Python-based penetration testing framework for lab environments.
"""

import argparse
import logging
import signal
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from utils.config_wizard import run_config_wizard
from utils.logger import get_logger, setup_logging
from utils.validators import validate_tool_dependencies

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
    logger.warning("\n[!] Interrupt received. Cleaning up...")
    print("\n[!] Framework interrupted.")
    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Perfodia - Network Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP")
    parser.add_argument("-m", "--mode", default="full", help="Execution mode")
    parser.add_argument("--interactive", action="store_true", help="Launch Textual TUI")
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Validate tool dependencies and show versions",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Launch interactive configuration wizard",
    )
    return parser.parse_args()


def main_workflow(state, target):
    """Demo workflow – shows open ports in Live Tool Output pane."""
    if not state or not state.tui_app:
        logger.warning("TUI not available")
        return

    import random
    import time

    tools = ["nmap", "masscan"]
    phases = ["Recon", "Port Scanning", "Enumeration", "Exploitation", "Post-Exploitation"]

    for phase_idx, phase in enumerate(phases, 1):
        state.update(
            current_phase=phase,
            phase_progress=phase_idx * 20,
            current_tool=tools[phase_idx % len(tools)],
            current_target=target,
        )
        state.add_event(f"▶ Starting phase: {phase}")

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
    print(BANNER)
    args = parse_arguments()

    setup_logging()
    logger.info("Perfodia framework starting...")

    if args.check_tools:
        logger.info("Running tool dependency check...")
        ok = validate_tool_dependencies(verbose=True)
        sys.exit(0 if ok else 1)

    if args.init:
        generated = run_config_wizard(output_dir="configs")
        if generated:
            logger.info("Config wizard completed: %s", generated)
            sys.exit(0)
        logger.error("Config wizard did not generate a file")
        sys.exit(1)

    if args.interactive:
        from utils.tui import DashboardState, TUILogHandler, run_tui

        state = DashboardState()

        tui_handler = TUILogHandler(state)
        logging.getLogger().addHandler(tui_handler)

        logger.info("Launching Textual TUI dashboard...")
        run_tui(state)
        return

    logger.info("Non-interactive orchestration path is not yet implemented.")


if __name__ == "__main__":
    main()