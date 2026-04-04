"""
PentestFW Test Suite
====================
Run with: python -m pytest tests/ -v
"""

# ═══════════════════════════════════════════════════════════════
# tests/test_validators.py content
# ═══════════════════════════════════════════════════════════════

import pytest
from utils.validators import validate_target, validate_nmap_options, validate_config


class TestValidateTarget:
    """Target validation — IPs, CIDRs, hostnames."""

    def test_valid_ipv4(self):
        ok, result = validate_target("192.168.1.1")
        assert ok is True
        assert result == "192.168.1.1"

    def test_valid_cidr(self):
        ok, result = validate_target("10.0.0.0/24")
        assert ok is True
        assert "10.0.0.0" in result

    def test_cidr_too_broad(self):
        ok, result = validate_target("10.0.0.0/8")
        assert ok is False

    def test_cidr_minimum_boundary(self):
        ok, result = validate_target("10.0.0.0/16")
        assert ok is True

    def test_multicast_rejected(self):
        ok, result = validate_target("224.0.0.1")
        assert ok is False

    def test_empty_string(self):
        ok, result = validate_target("")
        assert ok is False

    def test_invalid_format(self):
        ok, result = validate_target("not!valid!")
        assert ok is False

    def test_hostname_format(self):
        ok, result = validate_target("server.lab.local")
        # May or may not resolve, but format is valid
        assert ok is True

    def test_whitespace_stripped(self):
        ok, result = validate_target("  192.168.1.1  ")
        assert ok is True
        assert result == "192.168.1.1"

    def test_loopback(self):
        ok, result = validate_target("127.0.0.1")
        assert ok is True


class TestValidateNmapOptions:
    """Nmap option validation and sanitization."""

    def test_valid_extra_flags(self):
        ok, tokens, warnings = validate_nmap_options("-sU -Pn --max-rate 500")
        assert ok is True
        assert "-sU" in tokens
        assert "-Pn" in tokens

    def test_dangerous_flag_blocked(self):
        ok, tokens, warnings = validate_nmap_options("-iR 100")
        assert ok is False

    def test_shell_injection_stripped(self):
        ok, tokens, warnings = validate_nmap_options("-sV; rm -rf /")
        assert ok is True
        assert ";" not in " ".join(tokens)

    def test_output_flag_skipped(self):
        ok, tokens, warnings = validate_nmap_options("-sV -oX /tmp/out.xml")
        assert ok is True
        assert "-oX" not in tokens
        assert any("output" in w.lower() for w in warnings)

    def test_managed_flag_warned(self):
        ok, tokens, warnings = validate_nmap_options("-sS")
        assert ok is True
        assert any("already set" in w for w in warnings)

    def test_raw_mode_no_warnings(self):
        ok, tokens, warnings = validate_nmap_options("-sS -sV", allow_all=True)
        assert ok is True
        assert len(warnings) == 0

    def test_empty_string(self):
        ok, tokens, warnings = validate_nmap_options("")
        assert ok is True
        assert tokens == []

    def test_complex_valid(self):
        ok, tokens, warnings = validate_nmap_options(
            "-Pn --max-rate 200 -sU --script smb-vuln*"
        )
        assert ok is True
        assert "--script" in tokens


class TestValidateConfig:
    """Configuration validation."""

    def test_valid_default_config(self, mock_config):
        assert validate_config(mock_config) is True
