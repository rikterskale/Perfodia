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
from datetime import datetime
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from configs.settings import FrameworkConfig
from modules.active_directory import ActiveDirectoryModule
from modules.cracking import CrackingModule
from modules.enumeration import EnumerationModule
from modules.exploitation import ExploitationModule
from modules.post_exploitation import PostExploitationModule
from modules.recon import ReconModule
from modules.scanning import ScanningModule
from modules.web_app import WebAppModule
from utils.config_wizard import run_config_wizard
from utils.credential_vault import CredentialVault
from utils.logger import get_logger, setup_logging
from utils.scope_guard import ScopeGuard
from utils.session_state import SessionState
from utils.validators import validate_config, validate_target, validate_tool_dependencies
from utils.vuln_scorer import VulnScorer

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

MODULE_MAP = {
    "recon": ReconModule,
    "scan": ScanningModule,
    "enum": EnumerationModule,
    "webapp": WebAppModule,
    "exploit": ExploitationModule,
    "ad": ActiveDirectoryModule,
    "crack": CrackingModule,
    "post": PostExploitationModule,
}

MODE_MAP = {
    "recon": ["recon"],
    "scan": ["scan"],
    "webapp": ["scan", "webapp"],
    "exploit": ["scan", "enum", "exploit"],
    "ad": ["scan", "enum", "ad"],
    "crack": ["crack"],
    "post": ["post"],
    "full": ["recon", "scan", "enum", "webapp", "exploit", "ad", "crack", "post"],
}


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
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP/CIDR/hostname")
    parser.add_argument("-m", "--mode", default="full", choices=sorted(MODE_MAP.keys()))
    parser.add_argument("--modules", help="Comma-separated explicit modules (overrides mode)")
    parser.add_argument("-c", "--config", default="configs/default.yaml", help="Path to config YAML")
    parser.add_argument("--exclude", action="append", default=[], help="Exclude target/IP/CIDR")
    parser.add_argument("--enum", action="store_true", help="With -m scan, also run enum phase")
    parser.add_argument("--session", help="Session name (default: timestamp)")
    parser.add_argument("--resume", action="store_true", help="Resume previous session if checkpoint exists")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without execution")
    parser.add_argument("--nmap-extra", help="Extra nmap options appended to defaults")
    parser.add_argument("--nmap-raw", help="Raw nmap options replacing defaults")
    parser.add_argument("--nmap-scan-type", help="Override nmap scan type (e.g. sT)")
    parser.add_argument("--nmap-scripts", help="Override nmap scripts list")
    parser.add_argument("--report-format", default="html", help="Report format")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("--interactive", action="store_true", help="Launch Textual TUI")
    parser.add_argument("--check-tools", action="store_true", help="Validate tool dependencies and show versions")
    parser.add_argument("--init", action="store_true", help="Launch interactive configuration wizard")
    return parser.parse_args()


def _resolve_module_chain(args) -> List[str]:
    if args.modules:
        chain = [m.strip().lower() for m in args.modules.split(",") if m.strip()]
        unknown = [m for m in chain if m not in MODULE_MAP]
        if unknown:
            raise ValueError(f"Unknown modules: {', '.join(unknown)}")
        return chain

    chain = list(MODE_MAP[args.mode])
    if args.mode == "scan" and args.enum and "enum" not in chain:
        chain.append("enum")
    return chain


def _prepare_targets(raw_targets: List[str]) -> List[str]:
    validated = []
    for target in raw_targets:
        ok, normalized = validate_target(target)
        if not ok or not normalized:
            raise ValueError(f"Invalid target: {target}")
        validated.append(normalized)
    return validated


def run_workflow(args) -> int:
    chain = _resolve_module_chain(args)
    targets = _prepare_targets([args.target])

    config = FrameworkConfig(args.config)
    if not validate_config(config):
        logger.error("Configuration validation failed")
        return 2

    session_name = args.session or datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    session_dir = Path("reports") / session_name
    session_dir.mkdir(parents=True, exist_ok=True)

    scope_guard = ScopeGuard(targets=targets, exclusions=args.exclude)
    credential_vault = CredentialVault(session_dir=session_dir)
    vuln_scorer = VulnScorer()
    session_state = SessionState(session_dir=session_dir)

    results: Dict[str, Dict] = {}
    resumed_completed = set()
    if args.resume and session_state.has_checkpoint():
        checkpoint = session_state.load_checkpoint()
        resumed_completed = set(checkpoint.get("_completed_phases", []))
        logger.info("Resuming session '%s' with %d completed modules", session_name, len(resumed_completed))

    for module_name in chain:
        if args.resume and module_name in resumed_completed:
            logger.info("[RESUME] Skipping '%s' (already completed)", module_name)
            continue

        module_cls = MODULE_MAP[module_name]
        module = module_cls(  # type: ignore[abstract]
            config=config,
            targets=targets,
            exclusions=args.exclude,
            session_dir=session_dir,
            dry_run=args.dry_run,
            verbose=args.verbose,
            credential_vault=credential_vault,
            vuln_scorer=vuln_scorer,
            scope_guard=scope_guard,
        )

        logger.info("[WORKFLOW] Running module: %s", module_name)
        module_result = module.run(previous_results=results)
        results[module_name] = module_result
        session_state.save_checkpoint(results, completed_phase=module_name)

    session_state.finalize(results)
    logger.info("Workflow completed. Session: %s", session_name)
    return 0


def main():
    print(BANNER)
    args = parse_arguments()

    log_level = logging.DEBUG if args.verbose >= 2 else (logging.INFO if args.verbose >= 1 else logging.WARNING)
    setup_logging(level=log_level)
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

    rc = run_workflow(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()