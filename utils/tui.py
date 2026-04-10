"""
Perfodia TUI — Textual (Fixed layout - now renders correctly)
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, RichLog, Static

logger = logging.getLogger(__name__)

MAX_EVENTS = 50
MAX_FINDINGS = 200


class DashboardState:
    """Thread-safe shared state."""

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
        self.tui_app: PerfodiaTUI | None = None

    def update(self, **kwargs: Any) -> None:
        with self._lock:
            for key, val in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, val)

    def add_event(self, msg: str) -> None:
        with self._lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.recent_events.append(f"[{timestamp}] {msg}")

    def add_finding(self, severity: str, title: str, host: str = "") -> None:
        with self._lock:
            self.findings.append({"severity": severity, "title": title, "host": host})
            sev = severity.lower()
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

    def toggle_pause(self) -> None:
        with self._lock:
            self.paused = not self.paused

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
                "findings": list(self.findings)[-20:],
                "total_findings": len(self.findings),
                "severity_counts": dict(self.severity_counts),
                "recent_events": list(self.recent_events),
                "errors": self.errors,
                "warnings": self.warnings,
                "elapsed": (datetime.now() - self.start_time).total_seconds(),
                "running": self.running,
                "paused": self.paused,
            }


class TUILogHandler(logging.Handler):
    def __init__(self, state: DashboardState) -> None:
        super().__init__(logging.INFO)
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            self.state.add_event(msg[:120] + "..." if len(msg) > 120 else msg)

            if record.levelno >= logging.ERROR:
                self.state.errors += 1
            elif record.levelno >= logging.WARNING:
                self.state.warnings += 1

            finding = self._extract_finding(msg)
            if finding:
                self.state.add_finding(**finding)
        except Exception:
            pass

    @staticmethod
    def _extract_finding(msg: str) -> Dict[str, str] | None:
        msg_lower = msg.lower()
        if "[!]" not in msg:
            return None
        host_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", msg)
        host = host_match.group(0) if host_match else ""
        severity = "medium"
        if "critical" in msg_lower or "cve-" in msg_lower:
            severity = "critical"
        elif "credential" in msg_lower or "password" in msg_lower:
            severity = "high"
        elif "vuln" in msg_lower:
            severity = "medium"
        title = re.sub(r"\s+", " ", msg).strip()[:90]
        return {"severity": severity, "title": title, "host": host}


class SettingsModal(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(self, state: DashboardState) -> None:
        super().__init__()
        self.state = state

    def compose(self) -> ComposeResult:
        snap = self.state.snapshot()
        yield Static(f"Target: {snap['current_target'] or '—'}")
        yield Static(
            f"Phase: {snap['current_phase']} ({snap['phase_progress']}/{snap['total_phases']})"
        )
        yield Static(f"Tool: {snap['current_tool'] or '—'}")
        yield Static(f"Paused: {'Yes' if snap['paused'] else 'No'}")
        yield Static(f"Findings: {snap['total_findings']} | Errors: {snap['errors']}")
        yield Button("Close", variant="primary", id="close-btn")

    def on_button_pressed(self, event) -> None:
        if event.button.id == "close-btn":
            self.dismiss()


class PerfodiaTUI(App):
    TITLE = "Perfodia"
    SUB_TITLE = "Modern Penetration Testing Framework"

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("p", "toggle_pause", "Pause/Resume", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("s", "settings", "Settings", show=True),
        Binding("o", "toggle_output", "Toggle Output", show=True),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(self, state: DashboardState) -> None:
        super().__init__()
        self.state = state
        self.show_tool_output: bool = True
        state.tui_app = self

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()

        # Main vertical layout
        with Vertical():
            yield Static(id="status", classes="status-bar")

            with Horizontal(classes="stats-row"):
                yield Static("Hosts: 0", id="stat-hosts")
                yield Static("Ports: 0", id="stat-ports")
                yield Static("Creds: 0", id="stat-creds")
                yield Static("Admin: 0", id="stat-admin")
                yield Button("🔄 Toggle Live Output", id="toggle-output-btn", variant="primary")

            with Horizontal(id="main-content"):
                yield DataTable(id="findings", expand=True)
                yield RichLog(
                    id="tool-output",
                    wrap=True,
                    highlight=True,
                    auto_scroll=True,
                    max_lines=500,
                )

            yield RichLog(
                id="events",
                wrap=True,
                highlight=True,
                auto_scroll=True,
                max_lines=200,
                classes="events-log",
            )

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("Severity", "Host", "Finding")
        table.cursor_type = "row"

        self.set_interval(0.3, self._refresh_ui)
        self.state.add_event("🚀 TUI ready — live output enabled")

    def _refresh_ui(self) -> None:
        snap = self.state.snapshot()

        elapsed = time.strftime("%H:%M:%S", time.gmtime(snap["elapsed"]))
        paused = " ⏸️ PAUSED" if snap["paused"] else " 🚀 RUNNING"
        status_text = (
            f"Phase {snap['phase_progress']}/{snap['total_phases']} • "
            f"{snap['current_phase']} • Tool: {snap['current_tool'] or '—'} • "
            f"Target: {snap['current_target'] or '—'} • {elapsed}{paused}"
        )
        self.query_one("#status", Static).update(status_text)

        self.query_one("#stat-hosts", Static).update(f"Hosts: {snap['hosts_found']}")
        self.query_one("#stat-ports", Static).update(f"Ports: {snap['ports_found']}")
        self.query_one("#stat-creds", Static).update(f"Creds: {snap['credentials_found']}")
        self.query_one("#stat-admin", Static).update(f"Admin: {snap['admin_access']}")

        table = self.query_one("#findings", DataTable)
        table.clear()
        for f in snap["findings"]:
            color = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "green",
                "info": "blue",
            }.get(f["severity"].lower(), "white")
            table.add_row(f"[{color}]{f['severity'].upper()}[/]", f.get("host", ""), f["title"])

        events_log = self.query_one("#events", RichLog)
        events_log.clear()
        for event in snap["recent_events"]:
            events_log.write(event)

        tool_output = self.query_one("#tool-output", RichLog)
        tool_output.display = self.show_tool_output

    def append_tool_output(self, text: str) -> None:
        if self.show_tool_output:
            tool_output = self.query_one("#tool-output", RichLog)
            self.call_from_thread(tool_output.write, text.strip())

    def on_button_pressed(self, event) -> None:
        if event.button.id == "toggle-output-btn":
            self.action_toggle_output()

    def action_toggle_output(self) -> None:
        self.show_tool_output = not self.show_tool_output
        status = "✅ Live Output ON" if self.show_tool_output else "⭕ Live Output OFF"
        self.state.add_event(status)
        self._refresh_ui()

    def action_settings(self) -> None:
        self.push_screen(SettingsModal(self.state))

    def action_toggle_pause(self) -> None:
        self.state.toggle_pause()
        status = "⏸️ PAUSED" if self.state.paused else "▶️ RESUMED"
        self.state.add_event(status)

    def action_refresh(self) -> None:
        self.state.add_event("🔄 Manual refresh")
        self._refresh_ui()

    def action_quit(self) -> None:
        self.state.running = False
        self.exit()


def run_tui(state: DashboardState) -> None:
    app = PerfodiaTUI(state)
    app.run()
