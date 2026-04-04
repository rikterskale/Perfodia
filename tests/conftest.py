"""Shared fixtures for the PentestFW test suite."""

import sys
import pytest
from pathlib import Path

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def tmp_session(tmp_path):
    """Create a temporary session directory with standard subdirs."""
    for d in ["nmap", "recon", "enum", "exploits", "loot", "logs", "evidence"]:
        (tmp_path / d).mkdir()
    return tmp_path


@pytest.fixture
def mock_config():
    """Return a minimal FrameworkConfig-like object."""
    from configs.settings import FrameworkConfig
    return FrameworkConfig(None)  # Uses all defaults


@pytest.fixture
def sample_nmap_hosts():
    """Sample parsed nmap host data for testing."""
    return [
        {
            "ip": "192.168.1.10",
            "hostname": "dc01.lab.local",
            "ports": [
                {"port": 22, "protocol": "tcp", "state": "open",
                 "service": {"name": "ssh", "product": "OpenSSH", "version": "8.9"},
                 "scripts": []},
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service": {"name": "http", "product": "Apache", "version": "2.4.49"},
                 "scripts": []},
                {"port": 445, "protocol": "tcp", "state": "open",
                 "service": {"name": "microsoft-ds", "product": "", "version": ""},
                 "scripts": [
                     {"id": "smb-vuln-ms17-010", "output": "VULNERABLE: CVE-2017-0144"},
                 ]},
            ],
            "os_matches": [{"name": "Windows Server 2019", "accuracy": "95"}],
            "scripts": [],
        },
        {
            "ip": "192.168.1.20",
            "hostname": "web01.lab.local",
            "ports": [
                {"port": 80, "protocol": "tcp", "state": "open",
                 "service": {"name": "http", "product": "nginx", "version": "1.18"},
                 "scripts": []},
                {"port": 443, "protocol": "tcp", "state": "open",
                 "service": {"name": "https", "product": "nginx", "version": "1.18",
                             "tunnel": "ssl"},
                 "scripts": [
                     {"id": "ssl-cert", "output": "ssl-cert expired"},
                 ]},
            ],
            "os_matches": [{"name": "Ubuntu 22.04", "accuracy": "90"}],
            "scripts": [],
        },
    ]
