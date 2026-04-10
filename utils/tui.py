"""
Interactive Terminal UI for Perfodia — real-time dashboard with keyboard support.

Hotkeys:
  q / Q          → Quit
  p / P          → Pause / Resume
  ↑ / ↓          → Scroll findings
  r / R          → Refresh
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Constants (kept for test compatibility)
MAX_EVENTS = 30
VISIBLE_EVENTS = 12
MAX_FINDINGS = 100
VISIBLE_FINDINGS = 8

_RICH_AVAILABLE = False
try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
    from rich.align import Align

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
        self.total_phases: int = 8
        self.current_tool: str = ""
        self.current_target: str = ""
        self.hosts_found: int = 0
        self.ports_found: int = 0
        self.credentials_found: int = 0
        self.admin_access: int = 0
        self.findings = deque(maxlen=MAX_FINDINGS)
        self.severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        self.recent_events = deque(maxlen=MAX_EVENTS)
        self.errors: int = 0
        self.warnings: int = 0
        self.start_time: datetime = datetime.now()
        self.running: bool = True
        self.paused: bool = False
        self.findings_scroll: int = 0

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            for key, val in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, val)

    def add_event(self, msg: str) -> None:
        with self._lock:
            self.recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    def add_finding(self, severity: str, title: str, host: str = "") -> None:
        with self._lock:
            self.findings.append({"severity": severity, "title": title, "host": host})
            sev = severity.lower()
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

    def toggle_pause(self) -> None:
        with self._lock:
            self.paused = not self.paused

    def scroll_findings(self, delta: int) -> None:
        with self._lock:
            max_scroll = max(0, len(self.findings) - VISIBLE_FINDINGS)
            self.findings_scroll = max(0, min(self.findings_scroll + delta, max_scroll))

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            findings_list = list(self.findings)
            start_idx = self.findings_scroll
            visible_findings = findings_list[start_idx : start_idx + VISIBLE_FINDINGS]

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
                "findings": visible_findings,
                "total_findings": len(self.findings),
                "severity_counts": dict(self.severity_counts),
                "recent_events": list(self.recent_events)[-VISIBLE_EVENTS:],
                "errors": self.errors,
                "warnings": self.warnings,
                "elapsed": (datetime.now() - self.start_time).total_seconds(),
                "running": self.running,
                "paused": self.paused,
            }


class TUILogHandler(logging.Handler):
    """Logging handler that feeds logs into the TUI."""

    def __init__(self, state: DashboardState) -> None:
        super().__init__(logging.INFO)
        self.state = state

    @staticmethod
    def _extract_finding(msg: str) -> Optional[Dict[str, str]]:
        msg_lower = msg.lower()
        if "[!]" not in msg or not any(x in msg_lower for x in ("vuln", "cred", "found")):
            return None

        host_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+\b",
            msg,
            re.IGNORECASE,
        )
        host = host_match.group(0) if host_match else ""

        if "critical" in msg_lower or re.search(r"\bCVE-\d{4}-\d{4,7}\b", msg, re.IGNORECASE):
            severity = "critical"
        elif any(x in msg_lower for x in ("credential", "password")):
            severity = "high"
        elif "vuln" in msg_lower:
            severity = "medium"
        else:
            severity = "medium"

        clean_title = re.sub(r"\s+", " ", msg).strip()[:80]
        return {"severity": severity, "title": clean_title, "host": host}

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            if len(msg) > 120:
                msg = msg[:117] + "..."
            self.state.add_event(msg)

            if record.levelno >= logging.ERROR:
                with self.state._lock:
                    self.state.errors += 1
            elif record.levelno >= logging.WARNING:
                with self.state._lock:
                    self.state.warnings += 1

            finding = self._extract_finding(msg)
            if finding:
                self.state.add_finding(
                    finding["severity"], finding["title"], finding.get("host", "")
                )
        except Exception:
            pass


class TUIDashboard:
    """Rich-based terminal dashboard with full keyboard handling."""

    def __init__(self, state: DashboardState) -> None:
        self.state = state
        self._stop_event = threading.Event()
        self._render_thread: Optional[threading.Thread] = None
        self._input_thread: Optional[threading.Thread] = None
        self.console = Console() if _RICH_AVAILABLE else None

        if not _RICH_AVAILABLE:
            logger.warning("[TUI] rich not installed → falling back to console logs")

    def start(self) -> None:
        if not _RICH_AVAILABLE or not self.console:
            return
        self._stop_event.clear()
        self._render_thread = threading.Thread(target=self._render_loop, daemon=True)
        self._input_thread = threading.Thread(target=self._input_loop, daemon=True)
        self._render_thread.start()
        self._input_thread.start()
        logger.info("[TUI] Dashboard started (keyboard enabled)")

    def stop(self) -> None:
        self._stop_event.set()
        self.state.running = False
        if self._render_thread and self._render_thread.is_alive():
            self._render_thread.join(timeout=2)
        if self._input_thread and self._input_thread.is_alive():
            self._input_thread.join(timeout=1)

    def _input_loop(self) -> None:
        """Non-blocking keyboard input thread."""
        while not self._stop_event.is_set():
            try:
                key = self.console.getkey()
                if key in ("q", "Q"):
                    logger.info("[TUI] User requested quit")
                    self.stop()
                    break
                elif key in ("p", "P"):
                    self.state.toggle_pause()
                    self.state.add_event("⏸️  PAUSED" if self.state.paused else "▶️  RESUMED")
                elif key in ("r", "R"):
                    self.state.add_event("🔄 Manual refresh")
                elif key == "\x1b[A":  # Up
                    self.state.scroll_findings(-1)
                elif key == "\x1b[B":  # Down
                    self.state.scroll_findings(1)
            except Exception:
                time.sleep(0.05)

    def _render_loop(self) -> None:
        """Main rendering loop."""
        try:
            with Live(
                self._build_layout(),
                console=self.console,
                refresh_per_second=6,
                screen=True,
                transient=True,
            ) as live:
                while not self._stop_event.is_set():
                    live.update(self._build_layout())
                    time.sleep(0.16)
        except Exception as e:
            logger.debug(f"[TUI] Render loop ended: {e}")

    def _build_layout(self) -> Layout:
        snap = self.state.snapshot()
        layout = Layout()

        layout.split(
            Layout(self._make_header_panel(snap), name="header", size=3),
            Layout(self._make_stats_panel(snap), name="stats", size=4),
            Layout(self._make_findings_panel(snap), name="findings", ratio=2),
            Layout(self._make_events_panel(snap), name="events", ratio=1),
            Layout(self._make_footer(snap), name="footer", size=3),
        )
        return layout

    # ... (the rest of the _make_*_panel methods are unchanged from before – they were already clean)
    def _make_header_panel(self, snap: Dict[str, Any]) -> Panel:
        elapsed = time.strftime("%H:%M:%S", time.gmtime(snap["elapsed"]))
        status = "[red]⏸ PAUSED[/red]" if snap["paused"] else "[green]🚀 RUNNING[/green]"
        title = f"[bold]Perfodia — {snap['current_phase']}[/bold] {status}"
        return Panel(
            f"[bold cyan]{snap['current_target'] or 'No target'}[/bold cyan]  •  "
            f"Tool: [yellow]{snap['current_tool'] or '—'}[/yellow]  •  "
            f"Elapsed: [dim]{elapsed}[/dim]",
            title=title,
            border_style="bright_blue",
            padding=(0, 1),
        )

    def _make_stats_panel(self, snap: Dict[str, Any]) -> Panel:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        )
        task = progress.add_task("", total=100, completed=snap["phase_progress"])
        progress.update(task, description=f"Phase {snap['phase_progress']}/{snap['total_phases']}")

        grid = Table.grid(padding=1)
        grid.add_row(
            Text(f"Hosts: {snap['hosts_found']}", style="bold cyan"),
            Text(f"Ports: {snap['ports_found']}", style="bold cyan"),
            Text(f"Creds: {snap['credentials_found']}", style="bold green"),
            Text(f"Admin: {snap['admin_access']}", style="bold green"),
        )
        grid.add_row(
            Text(f"Errors: {snap['errors']}", style="bold red"),
            Text(f"Warnings: {snap['warnings']}", style="bold yellow"),
        )
        return Panel(Group(progress, grid), title="📊 Live Stats", border_style="magenta")

    def _make_findings_panel(self, snap: Dict[str, Any]) -> Panel:
        table = Table(box=box.SIMPLE, expand=True, show_edge=False)
        table.add_column("Severity", width=10)
        table.add_column("Host", width=18)
        table.add_column("Finding")

        for f in snap["findings"]:
            color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "green",
                "info": "blue",
            }.get(f["severity"].lower(), "white")
            table.add_row(f"[{color}]{f['severity'].upper()}[/]", f["host"], f["title"])

        if not snap["findings"]:
            table.add_row("", "", "[dim]No findings yet[/dim]")

        return Panel(table, title=f"🔍 Findings ({snap['total_findings']})", border_style="cyan")

    def _make_events_panel(self, snap: Dict[str, Any]) -> Panel:
        events = "\n".join(snap["recent_events"]) or "[dim]Waiting for activity...[/dim]"
        return Panel(Text(events, style="dim"), title="📜 Recent Events", border_style="blue")

    def _make_footer(self, snap: Dict[str, Any]) -> Panel:
        paused = "[red]PAUSED[/red] " if snap["paused"] else ""
        footer_text = (
            f"{paused}[bold]q[/bold]=quit  [bold]p[/bold]=pause/resume  "
            f"[bold]↑↓[/bold]=scroll  [bold]r[/bold]=refresh"
        )
        return Panel(Align.center(footer_text), border_style="dim", style="dim")


# For backward compatibility / testing
if __name__ == "__main__":
    state = DashboardState()
    dashboard = TUIDashboard(state)
    dashboard.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        dashboard.stop()
