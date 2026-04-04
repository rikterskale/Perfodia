"""Tests for session state (checkpoint/resume)."""

import pytest
from utils.session_state import SessionState


class TestSessionState:
    def test_no_checkpoint_initially(self, tmp_session):
        state = SessionState(tmp_session)
        assert state.has_checkpoint() is False

    def test_save_and_load_checkpoint(self, tmp_session):
        state = SessionState(tmp_session)
        results = {"session_id": "test", "phases": {"scan": {"hosts": []}}}
        state.save_checkpoint(results, "scan")

        assert state.has_checkpoint() is True
        loaded = state.load_checkpoint()
        assert "scan" in loaded.get("_completed_phases", [])

    def test_should_skip_completed(self, tmp_session):
        state = SessionState(tmp_session)
        results = {"phases": {}}
        state.save_checkpoint(results, "recon")
        state.save_checkpoint(results, "scan")

        state2 = SessionState(tmp_session)
        state2.load_checkpoint()
        assert state2.should_skip_phase("recon") is True
        assert state2.should_skip_phase("scan") is True
        assert state2.should_skip_phase("enum") is False

    def test_finalize(self, tmp_session):
        state = SessionState(tmp_session)
        results = {"session_id": "test", "phases": {}}
        state.finalize(results)
        assert (tmp_session / "results.json").exists()

    def test_get_resume_info(self, tmp_session):
        state = SessionState(tmp_session)
        results = {"session_id": "test123", "targets": ["1.1.1.1"], "mode": "full", "phases": {}}
        state.save_checkpoint(results, "scan")
        info = state.get_resume_info()
        assert info is not None
        assert info["session_id"] == "test123"
        assert "scan" in info["completed_phases"]

    def test_no_resume_info_without_checkpoint(self, tmp_session):
        state = SessionState(tmp_session)
        assert state.get_resume_info() is None


# ═══════════════════════════════════════════════════════════════
# Parallel runner tests
# ═══════════════════════════════════════════════════════════════

from utils.parallel import ParallelRunner, ParallelResult


class TestParallelRunner:
    def test_basic_execution(self):
        runner = ParallelRunner(max_workers=3)
        result = runner.run_per_host(
            hosts=["a", "b", "c"],
            func=lambda h: {"host": h},
            description="Test",
        )
        assert result.total == 3
        assert result.succeeded == 3
        assert result.failed == 0
        assert "a" in result.results

    def test_error_isolation(self):
        def fail_on_b(host):
            if host == "b":
                raise ValueError("deliberate failure")
            return {"ok": True}

        runner = ParallelRunner(max_workers=3)
        result = runner.run_per_host(
            hosts=["a", "b", "c"],
            func=fail_on_b,
            description="Test",
        )
        assert result.succeeded == 2
        assert result.failed == 1
        assert "b" in result.errors

    def test_single_host_sequential(self):
        runner = ParallelRunner(max_workers=1)
        result = runner.run_per_host(
            hosts=["only"],
            func=lambda h: {"host": h},
            description="Test",
        )
        assert result.succeeded == 1

    def test_empty_hosts(self):
        runner = ParallelRunner(max_workers=3)
        result = runner.run_per_host(hosts=[], func=lambda h: {}, description="Test")
        assert result.total == 0
        assert result.succeeded == 0

    def test_max_workers_capped(self):
        runner = ParallelRunner(max_workers=100)
        assert runner.max_workers == 50  # Capped at 50

    def test_min_workers(self):
        runner = ParallelRunner(max_workers=0)
        assert runner.max_workers == 1  # Minimum 1


# ═══════════════════════════════════════════════════════════════
# Parser tests
# ═══════════════════════════════════════════════════════════════

from utils.parsers import (
    parse_enum4linux_output,
    parse_hydra_output,
    parse_snmp_output,
    parse_searchsploit_json,
)


class TestParsers:
    def test_parse_enum4linux_users(self):
        output = """
user:[admin] rid:[0x1f4]
user:[guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
"""
        result = parse_enum4linux_output(output)
        assert len(result["users"]) == 3
        assert result["users"][0]["username"] == "admin"

    def test_parse_enum4linux_groups(self):
        output = "group:[Domain Admins] rid:[0x200]\ngroup:[Domain Users] rid:[0x201]\n"
        result = parse_enum4linux_output(output)
        assert len(result["groups"]) == 2

    def test_parse_enum4linux_empty(self):
        result = parse_enum4linux_output("")
        assert result["users"] == []
        assert result["shares"] == []

    def test_parse_hydra_output(self):
        output = """
[22][ssh] host: 192.168.1.100   login: admin   password: password123
[22][ssh] host: 192.168.1.100   login: root   password: toor
"""
        result = parse_hydra_output(output)
        assert len(result) == 2
        assert result[0]["username"] == "admin"
        assert result[0]["password"] == "password123"

    def test_parse_hydra_empty(self):
        assert parse_hydra_output("") == []
        assert parse_hydra_output("Hydra starting...") == []

    def test_parse_snmp_output(self):
        output = """
SNMPv2-MIB::sysDescr.0 = STRING: Linux server 5.15.0
SNMPv2-MIB::sysUpTime.0 = Timeticks: (12345) 0:02:03.45
"""
        result = parse_snmp_output(output)
        assert len(result) == 2
        assert result[0]["type"] == "STRING"

    def test_parse_snmp_timeout(self):
        assert parse_snmp_output("Timeout: No Response") == []

    def test_parse_searchsploit_json(self):
        import json
        data = json.dumps({
            "RESULTS_EXPLOIT": [
                {"Title": "Apache 2.4.49 RCE", "Path": "/exploits/12345",
                 "Type": "remote", "Platform": "linux"},
            ]
        })
        result = parse_searchsploit_json(data)
        assert len(result) == 1
        assert "Apache" in result[0]["title"]

    def test_parse_searchsploit_invalid_json(self):
        assert parse_searchsploit_json("not json") == []
