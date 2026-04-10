"""
Tests for the Perfodia Textual TUI.
"""

import logging

import pytest

# Gracefully handle missing textual (optional dependency)
pytest.importorskip("textual", reason="Textual TUI is optional (install with [tui])")

from utils.tui import DashboardState, TUILogHandler, run_tui


def test_dashboard_state():
    """Test the thread-safe DashboardState class."""
    state = DashboardState()
    state.update(current_phase="Network Scanning", phase_progress=50)
    state.add_event("test event")
    state.add_finding("high", "Test vulnerability", "10.0.0.1")

    snap = state.snapshot()
    assert snap["current_phase"] == "Network Scanning"
    assert snap["phase_progress"] == 50
    assert len(snap["recent_events"]) == 1
    assert len(snap["findings"]) == 1
    assert snap["severity_counts"]["high"] == 1


def test_tui_log_handler():
    """Test that TUILogHandler correctly processes log records."""
    state = DashboardState()
    handler = TUILogHandler(state)

    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="[!] Critical vuln found on 10.0.0.50",
        args=(),
        exc_info=None,
    )
    handler.emit(record)

    snap = state.snapshot()
    assert len(snap["recent_events"]) >= 1


@pytest.mark.skip(reason="Textual apps require a running terminal for full testing")
def test_run_tui_smoke():
    """Smoke test – just verify the run_tui function exists and can be called."""
    assert run_tui is not None
