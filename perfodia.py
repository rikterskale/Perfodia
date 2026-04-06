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
import sys
import signal
import logging
from datetime import datetime
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

  Network Penetration Testing Framework v1.0.0
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
  # Full pentest workflow against a single target
  %(prog)s --target 192.168.1.100 --mode full

  # Reconnaissance only against a subnet
  %(prog)s --target 192.168.1.0/24 --mode recon

  # Scanning and enumeration
  %(prog)s --target 192.168.1.100 --mode scan --enum

  # Run specific modules
  %(prog)s --target 192.168.1.100 --modules recon,scan,enum

  # Exploitation with custom config
  %(prog)s --target 192.168.1.100 --mode exploit --config custom.yaml

  # Generate report from previous run
  %(prog)s --report-only --session 20250322_143000

  # Pass extra nmap options (appended to defaults)
  %(prog)s -t 192.168.1.100 -m scan --nmap-extra '-sU --max-rate 500'

  # Replace all nmap flags with your own
  %(prog)s -t 192.168.1.100 -m scan --nmap-raw '-sS -sV -p 22,80,443,8080'

  # Use specific NSE scripts for vuln scanning
  %(prog)s -t 192.168.1.100 -m scan --nmap-scripts 'smb-vuln*,http-sql-injection'

  # Full connect scan (no root needed)
  %(prog)s -t 192.168.1.100 -m scan --nmap-scan-type sT

  # Combined: UDP scan, slow speed, specific ports
  %(prog)s -t 192.168.1.0/24 -m scan --nmap-scan-type sU --scan-speed slow --ports 53,161,500
        """,
    )

    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument(
        "-t", "--target",
        help="Target IP, hostname, or CIDR range (e.g., 192.168.1.0/24)",
    )
    target_group.add_argument(
        "-tL", "--target-list",
        help="Path to file containing target list (one per line)",
    )
    target_group.add_argument(
        "--exclude",
        help="Comma-separated IPs/ranges to exclude from testing",
    )

    mode_group = parser.add_argument_group("Execution Mode")
    mode_group.add_argument(
        "-m", "--mode",
        choices=["recon", "scan", "enum", "exploit", "post", "webapp", "ad", "crack", "full"],
        default="full",
        help="Execution mode: recon|scan|enum|exploit|post|webapp|ad|crack|full (default: full)",
    )
    mode_group.add_argument(
        "--modules",
        help="Comma-separated list of specific modules to run",
    )
    mode_group.add_argument(
        "--enum",
        action="store_true",
        help="Include enumeration when running scan mode",
    )
    mode_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume an interrupted session from the last checkpoint",
    )

    ux_group = parser.add_argument_group("User Experience")
    ux_group.add_argument(
        "--init",
        action="store_true",
        help="Launch the interactive configuration wizard to create a config file",
    )
    ux_group.add_argument(
        "--interactive",
        action="store_true",
        help="Launch real-time TUI dashboard (requires 'rich' library: pip install rich)",
    )

    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "-c", "--config",
        default=str(PROJECT_ROOT / "configs" / "default.yaml"),
        help="Path to configuration file (default: configs/default.yaml)",
    )
    config_group.add_argument(
        "-o", "--output-dir",
        default=str(PROJECT_ROOT / "reports"),
        help="Output directory for reports and results",
    )
    config_group.add_argument(
        "--session",
        help="Session name/ID (default: timestamp-based)",
    )

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--ports",
        default="1-65535",
        help="Port range to scan (default: 1-65535)",
    )
    scan_group.add_argument(
        "--scan-speed",
        choices=["slow", "normal", "fast", "insane"],
        default="normal",
        help="Nmap timing template (default: normal)",
    )
    scan_group.add_argument(
        "--no-vuln-scan",
        action="store_true",
        help="Skip vulnerability scanning phase",
    )

    nmap_group = parser.add_argument_group(
        "Nmap Options",
        description=(
            "Pass any nmap flags directly to the scanner. These are APPENDED "
            "to the framework's default flags, so you can add extra behavior "
            "without losing the baseline scan. Use --nmap-raw to REPLACE the "
            "default flags entirely with your own."
        ),
    )
    nmap_group.add_argument(
        "--nmap-extra",
        metavar="'OPTS'",
        help=(
            "Extra nmap options appended to the default scan. Quote the "
            "whole string. Examples:\n"
            "  --nmap-extra '-sU'                  (add UDP scan)\n"
            "  --nmap-extra '-Pn --max-rate 500'   (skip ping, throttle)\n"
            "  --nmap-extra '--script smb-vuln*'   (add specific scripts)\n"
            "  --nmap-extra '-sN'                  (TCP Null scan)\n"
            "  --nmap-extra '--top-ports 1000'     (only top 1000 ports)\n"
            "  --nmap-extra '-D RND:5'             (decoy scan with 5 random IPs)"
        ),
    )
    nmap_group.add_argument(
        "--nmap-raw",
        metavar="'OPTS'",
        help=(
            "REPLACE the framework's default nmap flags entirely. You own "
            "the whole command line after 'nmap'. The target IP and output "
            "flags (-oX, -oN) are still appended automatically.\n"
            "  --nmap-raw '-sS -sV -p 22,80,443'"
        ),
    )
    nmap_group.add_argument(
        "--nmap-scripts",
        metavar="SCRIPTS",
        help=(
            "Override which NSE scripts run during the vuln scan phase. "
            "Comma-separated list of script names, categories, or paths.\n"
            "  --nmap-scripts 'vuln,exploit'\n"
            "  --nmap-scripts 'smb-vuln*,http-sql-injection'\n"
            "  --nmap-scripts 'default and safe'"
        ),
    )
    nmap_group.add_argument(
        "--nmap-scan-type",
        metavar="TYPE",
        help=(
            "Override the scan type flag (default: -sS). Pass the nmap flag "
            "letter(s) only, no dash.\n"
            "  --nmap-scan-type sT   (full connect scan — no root needed)\n"
            "  --nmap-scan-type sU   (UDP scan)\n"
            "  --nmap-scan-type sA   (ACK scan for firewall mapping)\n"
            "  --nmap-scan-type sF   (FIN scan)\n"
            "  --nmap-scan-type sX   (Xmas scan)"
        ),
    )

    report_group = parser.add_argument_group("Reporting")
    report_group.add_argument(
        "--report-only",
        action="store_true",
        help="Generate report from existing session data",
    )
    report_group.add_argument(
        "--report-format",
        choices=["html", "json", "markdown", "pdf", "all"],
        default="all",
        help="Report output format (default: all)",
    )

    misc_group = parser.add_argument_group("Miscellaneous")
    misc_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v, -vv, -vvv)",
    )
    misc_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be executed without running tools",
    )
    misc_group.add_argument(
        "--check-tools",
        action="store_true",
        help="Check all tool dependencies and exit",
    )
    misc_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    args = parser.parse_args()

    # Validation
    if not args.check_tools and not args.report_only and not args.init and not args.target and not args.target_list:
        parser.error("--target or --target-list is required unless using --check-tools, --report-only, or --init")

    return args


def load_targets(args):
    """Load and validate target list from arguments."""
    targets = []

    if args.target:
        targets.append(args.target)

    if args.target_list:
        target_file = Path(args.target_list)
        if not target_file.exists():
            logger.error(f"Target list file not found: {args.target_list}")
            sys.exit(1)
        try:
            with open(target_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
            logger.info(f"Loaded {len(targets)} targets from {args.target_list}")
        except PermissionError:
            logger.error(f"Permission denied reading target file: {args.target_list}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error reading target file: {e}")
            sys.exit(1)

    # Validate each target
    valid_targets = []
    for target in targets:
        is_valid, resolved = validate_target(target)
        if is_valid:
            valid_targets.append(resolved)
        else:
            logger.warning(f"Skipping invalid target: {target}")

    if not valid_targets:
        logger.error("No valid targets specified. Exiting.")
        sys.exit(1)

    # Handle exclusions
    exclusions = []
    if args.exclude:
        exclusions = [e.strip() for e in args.exclude.split(",")]
        logger.info(f"Excluding {len(exclusions)} targets/ranges")

    return valid_targets, exclusions


def run_workflow(args, config, targets, exclusions, session_dir,
                 credential_vault=None, vuln_scorer=None, session_state=None,
                 scope_guard=None, tui_state=None):
    """Execute the penetration testing workflow with all integrated subsystems."""
    results = {
        "session_id": session_dir.name,
        "start_time": datetime.now().isoformat(),
        "targets": targets,
        "exclusions": exclusions,
        "mode": args.mode,
        "phases": {},
    }

    # ── Resume: load previous checkpoint if available ──
    if args.resume and session_state and session_state.has_checkpoint():
        loaded = session_state.load_checkpoint()
        results = loaded
        results["resume_time"] = datetime.now().isoformat()
        logger.info("[RESUME] Continuing from previous checkpoint")

    # Determine which modules to run
    if args.modules:
        module_list = [m.strip().lower() for m in args.modules.split(",")]
    elif args.mode == "full":
        module_list = ["recon", "scan", "enum", "webapp", "exploit", "ad", "crack", "post"]
    elif args.mode == "recon":
        module_list = ["recon"]
    elif args.mode == "scan":
        module_list = ["scan"]
        if args.enum:
            module_list.append("enum")
    elif args.mode == "enum":
        module_list = ["enum"]
    elif args.mode == "exploit":
        module_list = ["scan", "enum", "exploit"]
    elif args.mode == "webapp":
        module_list = ["scan", "webapp"]
    elif args.mode == "ad":
        module_list = ["scan", "enum", "ad"]
    elif args.mode == "crack":
        module_list = ["crack"]
    elif args.mode == "post":
        module_list = ["post"]
    else:
        module_list = ["recon", "scan"]

    # Module registry
    module_map = {
        "recon": ("Reconnaissance", ReconModule),
        "scan": ("Network Scanning", ScanningModule),
        "enum": ("Service Enumeration", EnumerationModule),
        "webapp": ("Web Application Testing", WebAppModule),
        "exploit": ("Exploitation", ExploitationModule),
        "ad": ("Active Directory", ActiveDirectoryModule),
        "crack": ("Password Cracking", CrackingModule),
        "post": ("Post-Exploitation", PostExploitationModule),
    }

    total_modules = len(module_list)

    for idx, module_key in enumerate(module_list, 1):
        if module_key not in module_map:
            logger.warning(f"Unknown module: {module_key} — skipping")
            continue

        # ── Resume: skip already-completed phases ──
        if session_state and session_state.should_skip_phase(module_key):
            logger.info(f"[RESUME] Skipping '{module_key}' (already completed)")
            continue

        phase_name, module_class = module_map[module_key]
        separator = "=" * 60
        logger.info(f"\n{separator}")
        logger.info(f"  PHASE {idx}/{total_modules}: {phase_name.upper()}")
        logger.info(f"{separator}\n")

        # Update TUI state
        if tui_state:
            tui_state.update(
                current_phase=phase_name,
                phase_progress=idx,
                total_phases=total_modules,
            )

        try:
            module = module_class(
                config=config,
                targets=targets,
                exclusions=exclusions,
                session_dir=session_dir,
                dry_run=args.dry_run,
                verbose=args.verbose,
                credential_vault=credential_vault,
                vuln_scorer=vuln_scorer,
                scope_guard=scope_guard,
            )

            # Pass previous results for chaining
            phase_results = module.run(previous_results=results.get("phases", {}))
            results["phases"][module_key] = phase_results

            # ── Vulnerability scoring on scan results ──
            if module_key == "scan" and vuln_scorer:
                hosts = phase_results.get("hosts", [])
                if hosts:
                    vuln_scorer.score_nmap_scripts(hosts)
                    if tui_state:
                        tui_state.update(
                            hosts_found=len(hosts),
                            ports_found=sum(len(h.get("ports", [])) for h in hosts),
                        )

            # ── Score exploit matches ──
            if module_key == "exploit" and vuln_scorer:
                exploits = phase_results.get("exploits_found", [])
                if exploits:
                    vuln_scorer.score_exploit_match(exploits)
                for cred in phase_results.get("credentials", []):
                    vuln_scorer.score_credential(
                        username=cred.get("username", ""),
                        host=cred.get("host", ""),
                        service=cred.get("service", ""),
                    )

            # ── Update TUI credential count ──
            if tui_state and credential_vault:
                stats = credential_vault.stats()
                tui_state.update(
                    credentials_found=stats.get("total", 0),
                    admin_access=stats.get("admin_access", 0),
                )
            if tui_state and vuln_scorer:
                risk = vuln_scorer.compute_risk_rating()
                tui_state.update(severity_counts=risk.get("breakdown", {}))

            # ── Checkpoint after each phase ──
            if session_state:
                session_state.save_checkpoint(results, completed_phase=module_key)

            logger.info(f"[+] {phase_name} phase completed successfully")

        except KeyboardInterrupt:
            logger.warning(f"[!] {phase_name} phase interrupted by user")
            results["phases"][module_key] = {"status": "interrupted"}
            if session_state:
                session_state.save_checkpoint(results, completed_phase=f"{module_key}_partial")
            raise
        except Exception as e:
            logger.error(f"[!] {phase_name} phase failed: {e}", exc_info=True)
            results["phases"][module_key] = {"status": "error", "error": str(e)}
            if session_state:
                session_state.save_checkpoint(results, completed_phase=f"{module_key}_error")
            if args.verbose >= 2:
                import traceback
                traceback.print_exc()

    results["end_time"] = datetime.now().isoformat()

    # ── Attach scoring and credential data to results ──
    if vuln_scorer:
        results["vulnerability_scoring"] = vuln_scorer.to_report_data()
    if credential_vault:
        results["credential_vault"] = {
            "stats": credential_vault.stats(),
            "credentials": credential_vault.to_report_data(),
        }

    return results


def main():
    """Main entry point for the framework."""
    print(BANNER)

    args = parse_arguments()

    # ── Config wizard (--init) ──
    if getattr(args, "init", False):
        from utils.config_wizard import run_config_wizard
        run_config_wizard()
        sys.exit(0)

    # Setup logging
    log_level = {0: logging.WARNING, 1: logging.INFO, 2: logging.DEBUG}.get(
        args.verbose, logging.DEBUG
    )
    setup_logging(level=log_level, no_color=args.no_color)
    logger.info(f"Perfodia starting at {datetime.now().isoformat()}")

    # Load configuration
    config = FrameworkConfig(args.config)
    if not validate_config(config):
        logger.error("Invalid configuration. Check your config file.")
        sys.exit(1)

    # Tool dependency check
    if args.check_tools:
        logger.info("Checking tool dependencies...")
        all_good = validate_tool_dependencies(verbose=True)
        sys.exit(0 if all_good else 1)

    # ── Validate and inject custom nmap options ──
    nmap_user_opts = {}
    if getattr(args, "nmap_extra", None):
        ok, parsed, warnings = validate_nmap_options(args.nmap_extra)
        for w in warnings:
            logger.warning(f"[NMAP OPTS] {w}")
        if not ok:
            logger.error("[NMAP OPTS] Invalid flags. Review the warnings above.")
            sys.exit(1)
        nmap_user_opts["extra"] = parsed
        logger.info(f"[NMAP OPTS] Extra flags: {parsed}")
    if getattr(args, "nmap_raw", None):
        ok, parsed, warnings = validate_nmap_options(args.nmap_raw, allow_all=True)
        for w in warnings:
            logger.warning(f"[NMAP RAW] {w}")
        if not ok:
            logger.error("[NMAP RAW] Invalid flags.")
            sys.exit(1)
        nmap_user_opts["raw"] = parsed
    if getattr(args, "nmap_scripts", None):
        nmap_user_opts["scripts"] = args.nmap_scripts
    if getattr(args, "nmap_scan_type", None):
        st = args.nmap_scan_type
        nmap_user_opts["scan_type"] = f"-{st}" if not st.startswith("-") else st
    config.set("nmap_user_opts", value=nmap_user_opts)
    if args.ports != "1-65535":
        config.set("nmap", "default_ports", value=args.ports)

    # Handle report-only mode before creating a fresh session tree.
    if args.report_only:
        if not args.session:
            logger.error("--session is required with --report-only")
            sys.exit(1)

        session_dir = Path(args.output_dir) / args.session
        reporter = ReportGenerator(session_dir, config)
        try:
            reporter.require_session_data()
        except FileNotFoundError as exc:
            logger.error(str(exc))
            sys.exit(1)

        reporter.generate(format=args.report_format)
        logger.info(f"Reports regenerated from: {session_dir}")
        sys.exit(0)

    # Privilege check
    if not check_root_privileges():
        logger.warning("[!] Not running as root. Some tools require root.")
        if getattr(args, "nmap_scan_type", None) in (None, "sS", "-sS"):
            logger.warning("[!] Use --nmap-scan-type sT for rootless scanning.")

        if sys.stdin.isatty():
            response = input("[?] Continue anyway? (y/N): ").strip().lower()
            if response != "y":
                sys.exit(0)
        else:
            logger.warning("[!] Non-interactive session detected; continuing without prompt.")

    # Create session directory
    session_name = args.session or datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = Path(args.output_dir) / session_name
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
        for subdir in ["nmap", "recon", "enum", "exploits", "loot", "logs", "evidence"]:
            (session_dir / subdir).mkdir(exist_ok=True)
        logger.info(f"Session directory: {session_dir}")
    except (PermissionError, OSError) as e:
        logger.error(f"Cannot create session directory: {e}")
        sys.exit(1)

    # Enable file logging
    from utils.logger import add_session_file_logging
    add_session_file_logging(session_dir / "logs")

    # Load targets
    targets, exclusions = load_targets(args)
    logger.info(f"Targets: {', '.join(targets)}")
    if args.dry_run:
        logger.info("[DRY RUN] No tools will be executed")
    logger.info(f"Command: {' '.join(sys.argv)}")

    # ── Initialize subsystems ──
    credential_vault = CredentialVault(session_dir)
    vuln_scorer = VulnScorer()
    session_state = SessionState(session_dir)
    scope_guard = ScopeGuard(targets=targets, exclusions=exclusions)

    # Resume info
    if args.resume:
        info = session_state.get_resume_info()
        if info:
            logger.info(f"[RESUME] Completed phases: {info.get('completed_phases')}")
        else:
            logger.warning("[RESUME] No checkpoint found — starting fresh")

    logger.info(f"[INIT] Credential vault: {credential_vault.stats().get('total', 0)} existing")
    logger.info(f"[INIT] Scope guard: {len(targets)} targets, {len(exclusions)} exclusions")

    # ── Interactive TUI ──
    tui_state = None
    tui_dashboard = None
    if getattr(args, "interactive", False):
        from utils.tui import is_tui_available, DashboardState, TUIDashboard, TUILogHandler
        if is_tui_available():
            tui_state = DashboardState()
            tui_state.update(current_target=", ".join(targets[:3]))
            tui_dashboard = TUIDashboard(tui_state)
            # Attach TUI log handler
            tui_handler = TUILogHandler(tui_state)
            logging.getLogger().addHandler(tui_handler)
            tui_dashboard.start()
            logger.info("[TUI] Interactive dashboard started")
        else:
            logger.warning("[TUI] Install 'rich' for interactive mode: pip install rich")

    # ── Run the workflow ──
    try:
        results = run_workflow(
            args, config, targets, exclusions, session_dir,
            credential_vault=credential_vault,
            vuln_scorer=vuln_scorer,
            session_state=session_state,
            scope_guard=scope_guard,
            tui_state=tui_state,
        )
    except KeyboardInterrupt:
        logger.warning("\n[!] Workflow interrupted. Generating partial report...")
        results = {"status": "interrupted", "phases": {}}
        session_state.save_checkpoint(results, completed_phase="_interrupted")
    finally:
        if tui_dashboard:
            tui_dashboard.stop()

    # ── Evidence screenshots ──
    scan_data = results.get("phases", {}).get("scan", {})
    hosts = scan_data.get("hosts", [])
    if hosts:
        web_targets = ScreenshotCapture.extract_web_targets(hosts)
        if web_targets:
            logger.info(f"\n[SCREENSHOT] Capturing {len(web_targets)} screenshots...")
            try:
                from utils.tool_runner import ToolRunner as _TR
                sr = _TR(config, session_dir, dry_run=args.dry_run, verbose=args.verbose,
                         scope_guard=scope_guard)
                capture = ScreenshotCapture(session_dir, sr, config)
                results["screenshots"] = capture.capture_all(web_targets)
            except Exception as e:
                logger.warning(f"[SCREENSHOT] Failed: {e}")

    # ── Generate reports ──
    logger.info("\n" + "=" * 60)
    logger.info("  GENERATING REPORTS")
    logger.info("=" * 60 + "\n")
    try:
        reporter = ReportGenerator(session_dir, config)
        reporter.generate(results=results, format=args.report_format)
        logger.info(f"[+] Reports saved to: {session_dir}")
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)

    # Finalize session
    session_state.finalize(results)

    # ── Scope violation report ──
    if scope_guard.violation_count > 0:
        scope_guard.save_violations(session_dir)
        logger.warning(f"\n[SCOPE] {scope_guard.violation_count} scope violations detected!")

    # ── Risk rating summary ──
    if vuln_scorer:
        risk = vuln_scorer.compute_risk_rating()
        logger.info("\n" + "=" * 60)
        logger.info("  RISK ASSESSMENT")
        logger.info("=" * 60)
        logger.info(f"  Overall Risk:   {risk['overall_risk']}")
        logger.info(f"  Risk Score:     {risk['risk_score']}")
        bd = risk["breakdown"]
        logger.info(f"  Critical: {bd.get('critical',0)}  High: {bd.get('high',0)}  "
                     f"Medium: {bd.get('medium',0)}  Low: {bd.get('low',0)}")
        if risk.get("attack_narrative"):
            logger.info(f"  {risk['attack_narrative']}")

    # ── Credential vault summary ──
    stats = credential_vault.stats()
    if stats["total"] > 0:
        logger.info("\n" + "=" * 60)
        logger.info("  CREDENTIAL VAULT")
        logger.info("=" * 60)
        logger.info(f"  Total: {stats['total']}  Passwords: {stats['passwords']}  "
                     f"Hashes: {stats['hashes']}  Admin: {stats['admin_access']}")

    # ── Error summary ──
    from utils.logger import get_error_summary
    ec = get_error_summary()
    logger.info("\n" + "=" * 60)
    logger.info("  SESSION SUMMARY")
    logger.info("=" * 60)
    logger.info(f"  Errors: {ec.get('ERROR',0)}  Warnings: {ec.get('WARNING',0)}")
    logger.info(f"  Session: {session_dir}")
    logger.info(f"  Completed: {datetime.now().isoformat()}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
