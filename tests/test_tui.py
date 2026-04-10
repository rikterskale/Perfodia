"""
Tests for the Perfodia Rich TUI.
"""

import logging

import pytest

from utils.tui import (
    DashboardState,
    TUIDashboard,
    TUILogHandler,
    is_tui_available,
)


@pytest.mark.skipif(not is_tui_available(), reason="Rich not installed")
class TestTUIRenderSmoke:
    """Smoke tests for TUI rendering and basic functionality."""

    def test_dashboard_state(self):
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

    def test_tui_log_handler(self):
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

    def test_build_layout_smoke(self):
        """Test that the layout builds without errors and contains expected panels."""
        state = DashboardState()
        state.update(
            current_phase="Network Scanning",
            phase_progress=1,
            total_phases=3,
            current_target="192.168.1.1",
        )
        state.add_event("scan started")
        state.add_finding("medium", "Sample finding", "10.0.0.10")

        dashboard = TUIDashboard(state)
        layout = dashboard._build_layout()

        assert layout is not None

        # Check the actual named children we use in _build_layout()
        assert layout.get("header") is not None
        assert layout.get("stats") is not None
        assert layout.get("findings") is not None
        assert layout.get("events") is not None
        assert layout.get("footer") is not None


@pytest.mark.skipif(not is_tui_available(), reason="Rich not installed")
def test_tui_start_stop():
    """Test start/stop doesn't crash (smoke test)."""
    state = DashboardState()
    dashboard = TUIDashboard(state)
    dashboard.start()
    dashboard.stop()
    assert not state.running
