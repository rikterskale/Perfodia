"""Tests for TUI state and log handler behavior."""

import logging

from utils.tui import DashboardState, TUILogHandler, MAX_EVENTS, MAX_FINDINGS


class TestDashboardState:
    def test_event_retention_cap(self):
        state = DashboardState()
        for i in range(MAX_EVENTS + 5):
            state.add_event(f"event-{i}")

        assert len(state.recent_events) == MAX_EVENTS
        assert "event-0" not in state.recent_events[0]
        assert f"event-{MAX_EVENTS + 4}" in state.recent_events[-1]

    def test_finding_retention_and_severity_count(self):
        state = DashboardState()
        for i in range(MAX_FINDINGS + 3):
            state.add_finding("high", f"finding-{i}", "10.0.0.1")

        assert len(state.findings) == MAX_FINDINGS
        assert state.severity_counts["high"] == MAX_FINDINGS + 3


class TestTUILogHandler:
    def test_warn_and_error_counters(self):
        state = DashboardState()
        handler = TUILogHandler(state)
        handler.setFormatter(logging.Formatter("%(message)s"))

        warning = logging.LogRecord(
            "test", logging.WARNING, __file__, 1, "warn-msg", (), None
        )
        error = logging.LogRecord(
            "test", logging.ERROR, __file__, 1, "err-msg", (), None
        )
        handler.emit(warning)
        handler.emit(error)

        assert state.warnings == 1
        assert state.errors == 1

    def test_finding_detection_from_log_text(self):
        state = DashboardState()
        handler = TUILogHandler(state)
        handler.setFormatter(logging.Formatter("%(message)s"))

        record = logging.LogRecord(
            "test",
            logging.INFO,
            __file__,
            1,
            "[!] Found credential password reuse on 10.0.0.5",
            (),
            None,
        )
        handler.emit(record)

        assert len(state.findings) == 1
        assert state.findings[0]["severity"] == "high"
