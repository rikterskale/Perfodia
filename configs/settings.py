"""
Framework configuration management.
Loads settings from YAML config files with sensible defaults.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


# ── Default tool paths (auto-discovered or overridden in config) ──

DEFAULT_TOOL_PATHS = {
    "nmap": "nmap",
    "masscan": "masscan",
    "nikto": "nikto",
    "enum4linux": "enum4linux-ng",
    "gobuster": "gobuster",
    "hydra": "hydra",
    "snmpwalk": "snmpwalk",
    "onesixtyone": "onesixtyone",
    "whatweb": "whatweb",
    "smbclient": "smbclient",
    "rpcclient": "rpcclient",
    "dig": "dig",
    "whois": "whois",
    "searchsploit": "searchsploit",
    "msfconsole": "msfconsole",
    "crackmapexec": "crackmapexec",
    "responder": "responder",
    "john": "john",
    "hashcat": "hashcat",
    "impacket_secretsdump": "impacket-secretsdump",
    "impacket_psexec": "impacket-psexec",
    "impacket_smbexec": "impacket-smbexec",
    "impacket_wmiexec": "impacket-wmiexec",
    "impacket_getTGT": "impacket-getTGT",
    "impacket_GetNPUsers": "impacket-GetNPUsers",
    "impacket_GetUserSPNs": "impacket-GetUserSPNs",
}


class FrameworkConfig:
    """
    Loads and manages framework configuration from a YAML file.
    Falls back to sensible defaults for all settings.
    """

    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self._data: Dict[str, Any] = {}
        self.tool_paths: Dict[str, str] = dict(DEFAULT_TOOL_PATHS)

        if config_path and Path(config_path).exists():
            self._load_config(config_path)
        else:
            if config_path:
                logger.warning(
                    f"Config file not found: {config_path} — using defaults"
                )
            self._apply_defaults()

    def _load_config(self, path: str):
        """Load configuration from YAML file with error handling."""
        try:
            with open(path, "r") as f:
                self._data = yaml.safe_load(f) or {}
            logger.info(f"Configuration loaded from {path}")
        except yaml.YAMLError as e:
            logger.error(f"YAML parse error in {path}: {e}")
            logger.warning("Falling back to default configuration")
            self._data = {}
        except PermissionError:
            logger.error(f"Permission denied reading config: {path}")
            self._data = {}
        except Exception as e:
            logger.error(f"Unexpected error loading config {path}: {e}")
            self._data = {}

        self._apply_defaults()

        # Override tool paths from config
        if "tool_paths" in self._data:
            self.tool_paths.update(self._data["tool_paths"])

    def _apply_defaults(self):
        """Fill in default values for any missing configuration keys."""
        defaults = {
            "general": {
                "threads": 10,
                "timeout": 300,
                "max_retries": 2,
                "retry_delay": 5,
            },
            "nmap": {
                "default_ports": "1-65535",
                "timing_template": 4,      # T4
                "max_retries": 2,
                "host_timeout": "5m",
                "scripts": [
                    "default",
                    "vuln",
                    "safe",
                ],
                "extra_args": [],
            },
            "masscan": {
                "rate": 1000,
                "ports": "1-65535",
            },
            "enumeration": {
                "smb": {"enabled": True, "depth": "full"},
                "snmp": {"enabled": True, "community_strings": ["public", "private"]},
                "dns": {"enabled": True, "wordlist": "/usr/share/wordlists/dns.txt"},
                "http": {"enabled": True, "wordlist": "/usr/share/wordlists/dirb/common.txt"},
            },
            "exploitation": {
                "auto_exploit": False,
                "safe_mode": True,
                "max_exploit_threads": 3,
            },
            "credentials": {
                "usernames": ["admin", "root", "administrator", "user"],
                "passwords_file": "/usr/share/wordlists/rockyou.txt",
                "spray_lockout_threshold": 3,
                "spray_delay": 30,
            },
            "reporting": {
                "include_raw_output": True,
                "severity_threshold": "low",
                "include_remediation": True,
                "include_risk_rating": True,
                "include_screenshots": True,
            },
            "webapp": {
                "enabled": True,
                "sqlmap_enabled": True,
                "sqlmap_level": 1,
                "sqlmap_risk": 1,
                "check_git_exposure": True,
                "check_env_exposure": True,
                "check_backup_files": True,
            },
            "ad": {
                "enabled": True,
                "bloodhound_collect": True,
                "spray_passwords": ["Password1", "Welcome1", "Company123"],
                "max_spray_users": 200,
                "check_smb_signing": True,
            },
            "cracking": {
                "enabled": True,
                "wordlist": "/usr/share/wordlists/rockyou.txt",
                "max_runtime": 600,
                "use_rules": True,
            },
            "screenshots": {
                "enabled": True,
                "max_workers": 5,
                "timeout": 30,
            },
            "parallel": {
                "enabled": True,
            },
        }

        for section, values in defaults.items():
            if section not in self._data:
                self._data[section] = values
            elif isinstance(values, dict):
                for key, val in values.items():
                    if key not in self._data[section]:
                        self._data[section][key] = val
                    elif isinstance(val, dict) and isinstance(self._data[section][key], dict):
                        # Recurse one more level for nested dicts like
                        # enumeration.smb, enumeration.snmp, etc.
                        for subkey, subval in val.items():
                            if subkey not in self._data[section][key]:
                                self._data[section][key][subkey] = subval

    def get(self, section: str, key: str = None, default=None):
        """
        Retrieve a configuration value.

        Args:
            section: Top-level config section (e.g., 'nmap')
            key: Optional key within section
            default: Fallback if key not found

        Returns:
            Config value or default
        """
        if key is None:
            return self._data.get(section, default)
        return self._data.get(section, {}).get(key, default)

    def set(self, section: str, key: str = None, value=None):
        """
        Set a configuration value.

        Args:
            section: Top-level config section (e.g., 'nmap')
            key: Optional key within section (if None, sets the section itself)
            value: The value to set
        """
        if key is None:
            self._data[section] = value
        else:
            self._data.setdefault(section, {})[key] = value

    def get_tool_path(self, tool_name: str) -> str:
        """Get the configured path/command for a tool."""
        return self.tool_paths.get(tool_name, tool_name)

    def to_dict(self) -> Dict:
        """Return full configuration as dictionary."""
        return dict(self._data)
