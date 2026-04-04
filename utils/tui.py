"""
Interactive Terminal UI — real-time dashboard showing scan progress,
live findings feed, credential count, and severity breakdown.

Uses the `rich` library for rendering.  Falls back gracefully if
rich is not installed.

Launch with: perfodia.py --interactive -t <target> -m full
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)

_RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
    _RICH_AVAILABLE = True
except ImportError:
    pass


def is_tui_available() -> bool:
    """Check if rich library is installed for TUI support."""
    return _RICH_AVAILABLE


class DashboardState:
    """Thread-safe shared state for the TUI dashboard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.current_phase: str = "Initializing"
        self.phase_progress: int = 0
        self.total_phases: int = 0
        self.current_tool: str = ""
        self.current_target: str = ""
        self.hosts_found: int = 0
        self.ports_found: int = 0
        self.credentials_found: int = 0
        self.admin_access: int = 0
        self.findings: List[Dict[str, str]] = []
        self.severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        self.recent_events: List[str] = []
        self.errors: int = 0
        self.warnings: int = 0
        self.start_time: datetime = datetime.now()
        self.running: bool = True

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            for key, val in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, val)

    def add_event(self, msg: str) -> None:
        with self._lock:
            self.recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            if len(self.recent_events) > 15:
                self.recent_events.pop(0)

    def add_finding(self, severity: str, title: str, host: str = "") -> None:
        with self._lock:
            self.findings.append({"severity": severity, "title": title, "host": host})
            sev = severity.lower()
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1
            if len(self.findings) > 50:
                self.findings.pop(0)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "current_phase": self.current_phase,
                "phase_progress": self.phase_progress,
                "total_phases": self.total_phases,
                "current_tool": self.current_tool,
                "current_target": self.current_target,
                "hosts_found": self.hosts_found,
                "ports_found": self.ports_found,
                "credentials_found": self.credentials_found,
                "admin_access": self.admin_access,
                "findings": list(self.findings[-10:]),
                "severity_counts": dict(self.severity_counts),
                "recent_events": list(self.recent_events[-10:]),
                "errors": self.errors,
                "warnings": self.warnings,
                "elapsed": (datetime.now() - self.start_time).total_seconds(),
                "running": self.running,
            }


class TUIDashboard:
    """
    Rich-based terminal dashboard for real-time pentest monitoring.

    Usage:
        state = DashboardState()
        dashboard = TUIDashboard(state)
        dashboard.start()  # Starts background rendering thread
        # ... update state from modules ...
        state.update(current_phase="Scanning", hosts_found=15)
        state.add_event("Found open port 445 on 192.168.1.10")
        state.add_finding("high", "MS17-010 EternalBlue", "192.168.1.10")
        # ... when done ...
        dashboard.stop()
    """

    def __init__(self, state: DashboardState) -> None:
        self.state = state
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        if not _RICH_AVAILABLE:
            logger.warning(
                "[TUI] rich library not installed. Install with: pip install rich"
            )

    def start(self) -> None:
        """Start the background dashboard rendering thread."""
        if not _RICH_AVAILABLE:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._render_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the dashboard."""
        self._stop_event.set()
        self.state.running = False
        if self._thread:
            self._thread.join(timeout=3)

    def _render_loop(self) -> None:
        """Main rendering loop using rich Live display."""
        console = Console()
        try:
            with Live(self._build_layout(), console=console, refresh_per_second=2,
                       screen=True) as live:
                while not self._stop_event.is_set():
                    live.update(self._build_layout())
                    time.sleep(0.5)
        except Exception as e:
            logger.debug(f"[TUI] Render loop ended: {e}")

    def _build_layout(self) -> Layout:
        """Build the full dashboard layout."""
        snap = self.state.snapshot()
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["left"].split_column(
            Layout(name="stats", size=7),
            Layout(name="events"),
        )
        layout["right"].split_column(
            Layout(name="severity", size=12),
            Layout(name="findings"),
        )

        # Header
        elapsed = time.strftime("%H:%M:%S", time.gmtime(snap["elapsed"]))
        phase = snap["current_phase"]
        progress_pct = (
            f"{snap['phase_progress']}/{snap['total_phases']}"
            if snap["total_phases"] > 0 else "—"
        )
        header_text = Text.assemble(
            ("  Perfodia ", "bold cyan"),
            (f"  Phase: {phase} [{progress_pct}]  ", "bold white"),
            (f"  Tool: {snap['current_tool'] or '—'}  ", "dim"),
            (f"  Elapsed: {elapsed}  ", "green"),
        )
        layout["header"].update(Panel(header_text, style="on dark_blue"))

        # Stats panel
        stats_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        stats_table.add_column("Label", style="dim")
        stats_table.add_column("Value", style="bold cyan", justify="right")
        stats_table.add_row("Hosts Found", str(snap["hosts_found"]))
        stats_table.add_row("Open Ports", str(snap["ports_found"]))
        stats_table.add_row("Credentials", str(snap["credentials_found"]))
        stats_table.add_row("Admin Access", str(snap["admin_access"]))
        stats_table.add_row("Errors / Warnings", f"{snap['errors']} / {snap['warnings']}")
        layout["stats"].update(Panel(stats_table, title="Statistics", border_style="cyan"))

        # Severity breakdown
        sev = snap["severity_counts"]
        sev_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        sev_table.add_column("Severity")
        sev_table.add_column("Count", justify="right")
        colors = {"critical": "bold red", "high": "red", "medium": "yellow",
                  "low": "green", "info": "dim"}
        for s in ["critical", "high", "medium", "low", "info"]:
            sev_table.add_row(Text(s.upper(), style=colors[s]), str(sev.get(s, 0)))
        layout["severity"].update(Panel(sev_table, title="Findings", border_style="red"))

        # Recent findings
        findings_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        findings_table.add_column("Sev", width=5)
        findings_table.add_column("Host", width=15)
        findings_table.add_column("Finding")
        for f in reversed(snap["findings"][-8:]):
            sev_text = Text(f["severity"][:4].upper(),
                           style=colors.get(f["severity"].lower(), "dim"))
            findings_table.add_row(sev_text, f.get("host", "")[:15], f["title"][:40])
        layout["findings"].update(Panel(findings_table, title="Latest Findings", border_style="yellow"))

        # Event log
        event_text = "\n".join(snap["recent_events"][-12:]) or "  Waiting for events..."
        layout["events"].update(Panel(event_text, title="Event Log", border_style="green"))

        # Footer
        target = snap.get("current_target", "—")
        footer_text = Text.assemble(
            ("  Target: ", "dim"), (target, "bold"),
            ("  |  Press Ctrl+C to stop  ", "dim"),
        )
        layout["footer"].update(Panel(footer_text, style="on dark_blue"))

        return layout


class TUILogHandler(logging.Handler):
    """Logging handler that feeds log messages into the TUI dashboard state."""

    def __init__(self, state: DashboardState) -> None:
        super().__init__(logging.INFO)
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            # Shorten for display
            if len(msg) > 120:
                msg = msg[:117] + "..."
            self.state.add_event(msg)

            if record.levelno >= logging.ERROR:
                with self.state._lock:
                    self.state.errors += 1
            elif record.levelno >= logging.WARNING:
                with self.state._lock:
                    self.state.warnings += 1

            # Detect findings from log messages
            msg_lower = msg.lower()
            if "[!]" in msg and ("vuln" in msg_lower or "cred" in msg_lower or "found" in msg_lower):
                if "critical" in msg_lower or "cve" in msg_lower:
                    self.state.add_finding("critical", msg[:60])
                elif "credential" in msg_lower or "password" in msg_lower:
                    self.state.add_finding("high", msg[:60])
                else:
                    self.state.add_finding("medium", msg[:60])
        except Exception:
            pass
