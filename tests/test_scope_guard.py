"""Tests for scope guard."""

import pytest
from utils.scope_guard import ScopeGuard


class TestScopeGuard:
    def test_ip_in_scope(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        assert guard.check("192.168.1.100") is True

    def test_ip_out_of_scope(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        assert guard.check("10.0.0.1") is False

    def test_exclusion_takes_priority(self):
        guard = ScopeGuard(
            targets=["192.168.1.0/24"],
            exclusions=["192.168.1.1"],
        )
        assert guard.check("192.168.1.1") is False
        assert guard.check("192.168.1.100") is True

    def test_single_ip_target(self):
        guard = ScopeGuard(targets=["192.168.1.100"])
        assert guard.check("192.168.1.100") is True
        assert guard.check("192.168.1.101") is False

    def test_hostname_target(self):
        guard = ScopeGuard(targets=["server.lab.local"])
        assert guard.check("server.lab.local") is True
        assert guard.check("other.lab.local") is False

    def test_multiple_ranges(self):
        guard = ScopeGuard(targets=["192.168.1.0/24", "10.0.0.0/24"])
        assert guard.check("192.168.1.50") is True
        assert guard.check("10.0.0.50") is True
        assert guard.check("172.16.0.1") is False

    def test_violation_recording(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        guard.check("10.0.0.1", tool_name="nmap", action="scan")
        assert guard.violation_count == 1
        assert guard.violations[0]["target"] == "10.0.0.1"

    def test_empty_target_rejected(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        assert guard.check("") is False

    def test_extract_ips_from_args(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        ips = guard.extract_ips_from_args([
            "-sV", "192.168.1.100", "--max-rate", "500",
            "admin:pass@10.0.0.1",
        ])
        assert "192.168.1.100" in ips
        assert "10.0.0.1" in ips

    def test_check_tool_args_in_scope(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        assert guard.check_tool_args("nmap", ["-sV", "192.168.1.100"]) is True

    def test_check_tool_args_out_of_scope(self):
        guard = ScopeGuard(targets=["192.168.1.0/24"])
        assert guard.check_tool_args("nmap", ["-sV", "10.0.0.1"]) is False
