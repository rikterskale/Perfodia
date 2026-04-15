"""
Credential Vault — centralized credential management across all phases.

Tracks every username, password, hash, ticket, and key discovered during
the engagement with source attribution, deduplication, and automatic
reuse suggestions for subsequent attacks.
"""

import json
import logging
import threading
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class CredType(str, Enum):
    """Types of credentials the vault can store."""

    PASSWORD = "password"  # Cleartext password
    NTLM_HASH = "ntlm_hash"  # NTLM hash (LM:NT format)
    NET_NTLMV2 = "net_ntlmv2"  # Net-NTLMv2 hash (from Responder, etc.)
    KERBEROS_TGT = "krb_tgt"  # Kerberos TGT
    KERBEROS_TGS = "krb_tgs"  # Kerberos TGS (Kerberoast)
    ASREP_HASH = "asrep_hash"  # AS-REP roastable hash
    SSH_KEY = "ssh_key"  # SSH private key
    TOKEN = "token"  # API token, session token, etc.
    COOKIE = "cookie"  # Session cookie
    OTHER = "other"


@dataclass
class Credential:
    """A single discovered credential."""

    username: str
    secret: str  # Password, hash, key content
    cred_type: CredType = CredType.PASSWORD
    domain: str = ""  # AD domain if applicable
    host: str = ""  # Host where it was found
    port: int = 0  # Service port
    service: str = ""  # Service name (ssh, smb, http, etc.)
    source_phase: str = ""  # Which module discovered it
    source_tool: str = ""  # Which tool discovered it
    timestamp: str = ""  # When it was discovered
    verified: bool = False  # Has it been tested and confirmed working?
    verified_on: List[str] = field(default_factory=list)  # Hosts where it works
    admin_access: bool = False  # Grants admin/root?
    notes: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

    @property
    def identity(self) -> str:
        """Unique identity key for deduplication."""
        import hashlib

        domain_prefix = f"{self.domain}\\" if self.domain else ""
        # Use a hash of the full secret to avoid false deduplication of
        # long hashes that share a common prefix.
        secret_hash = hashlib.sha256(self.secret.encode(errors="replace")).hexdigest()[:16]
        return f"{domain_prefix}{self.username}:{self.cred_type.value}:{secret_hash}"

    @property
    def display(self) -> str:
        """Human-readable representation."""
        domain_prefix = f"{self.domain}\\" if self.domain else ""
        loc = f" on {self.host}:{self.port}" if self.host else ""
        return f"{domain_prefix}{self.username} ({self.cred_type.value}){loc}"

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["cred_type"] = self.cred_type.value
        return d


class CredentialVault:
    """
    Thread-safe central credential store for the entire engagement.

    Features:
        - Deduplication: same cred discovered by multiple tools stored once
        - Source tracking: which tool/phase found each credential
        - Verified tracking: mark creds as confirmed working on specific hosts
        - Auto-persist: saves to JSON after every change
        - Reuse suggestions: given a host and service, returns applicable creds
        - Statistics: counts by type, verified vs. unverified

    Usage:
        vault = CredentialVault(session_dir)
        vault.add(Credential(username="admin", secret="Password1",
                             host="192.168.1.100", service="smb",
                             source_phase="exploit", source_tool="hydra"))
        creds = vault.get_for_host("192.168.1.200", service="smb")
    """

    def __init__(self, session_dir: Path):
        self.session_dir = session_dir
        self._creds: Dict[str, Credential] = {}  # identity -> Credential
        self._lock = threading.Lock()
        self._save_path = session_dir / "loot" / "credential_vault.json"
        self._save_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._save_path.parent, 0o700)
        except OSError:
            pass

        # Load existing vault if resuming
        self._load()

    def add(self, cred: Credential) -> bool:
        """
        Add a credential to the vault.

        Returns:
            True if this is a new credential, False if duplicate.
        """
        with self._lock:
            key = cred.identity
            if key in self._creds:
                # Merge: update verification status and hosts
                existing = self._creds[key]
                if cred.verified and not existing.verified:
                    existing.verified = True
                for host in cred.verified_on:
                    if host not in existing.verified_on:
                        existing.verified_on.append(host)
                if cred.admin_access:
                    existing.admin_access = True
                logger.debug(f"[VAULT] Duplicate merged: {cred.display}")
                self._persist()
                return False

            self._creds[key] = cred
            logger.warning(f"[VAULT] NEW CREDENTIAL: {cred.display}")
            self._persist()
            return True

    def add_password(
        self,
        username: str,
        password: str,
        host: str = "",
        port: int = 0,
        service: str = "",
        source_phase: str = "",
        source_tool: str = "",
        domain: str = "",
        verified: bool = False,
        admin_access: bool = False,
    ) -> bool:
        """Convenience method to add a cleartext password credential."""
        return self.add(
            Credential(
                username=username,
                secret=password,
                cred_type=CredType.PASSWORD,
                host=host,
                port=port,
                service=service,
                domain=domain,
                source_phase=source_phase,
                source_tool=source_tool,
                verified=verified,
                admin_access=admin_access,
            )
        )

    def add_hash(
        self,
        username: str,
        hash_value: str,
        hash_type: CredType = CredType.NTLM_HASH,
        host: str = "",
        source_phase: str = "",
        source_tool: str = "",
        domain: str = "",
    ) -> bool:
        """Convenience method to add a hash credential."""
        return self.add(
            Credential(
                username=username,
                secret=hash_value,
                cred_type=hash_type,
                host=host,
                domain=domain,
                source_phase=source_phase,
                source_tool=source_tool,
            )
        )

    def mark_verified(self, username: str, secret: str, host: str, admin: bool = False):
        """Mark a credential as verified working on a specific host."""
        with self._lock:
            for cred in self._creds.values():
                if cred.username == username and cred.secret == secret:
                    cred.verified = True
                    if host not in cred.verified_on:
                        cred.verified_on.append(host)
                    if admin:
                        cred.admin_access = True
                    self._persist()
                    return

    def get_all(self) -> List[Credential]:
        """Return all credentials."""
        with self._lock:
            return list(self._creds.values())

    def get_for_host(
        self,
        host: str,
        service: str = "",
        verified_only: bool = False,
    ) -> List[Credential]:
        """
        Get credentials applicable to a specific host/service.

        Returns credentials that:
            - Were found on this host, OR
            - Have been verified on this host, OR
            - Are domain credentials (usable across hosts), OR
            - Are service-type matches (e.g., SSH creds for SSH ports)
        """
        with self._lock:
            results = []
            for cred in self._creds.values():
                if verified_only and not cred.verified:
                    continue

                matches = (
                    cred.host == host
                    or host in cred.verified_on
                    or cred.domain  # domain creds work across hosts
                    or (service and cred.service == service)
                )
                if matches:
                    results.append(cred)
            return results

    def get_by_type(self, cred_type: CredType) -> List[Credential]:
        """Get all credentials of a specific type."""
        with self._lock:
            return [c for c in self._creds.values() if c.cred_type == cred_type]

    def get_passwords(self) -> List[Credential]:
        """Get all cleartext password credentials."""
        return self.get_by_type(CredType.PASSWORD)

    def get_hashes(self) -> List[Credential]:
        """Get all hash credentials (NTLM, Net-NTLMv2, etc.)."""
        with self._lock:
            return [
                c
                for c in self._creds.values()
                if c.cred_type
                in (
                    CredType.NTLM_HASH,
                    CredType.NET_NTLMV2,
                    CredType.ASREP_HASH,
                    CredType.KERBEROS_TGS,
                )
            ]

    def get_admin_creds(self) -> List[Credential]:
        """Get credentials with confirmed admin access."""
        with self._lock:
            return [c for c in self._creds.values() if c.admin_access]

    def get_unique_usernames(self) -> Set[str]:
        """Get all unique usernames discovered."""
        with self._lock:
            return {c.username for c in self._creds.values()}

    def stats(self) -> Dict[str, Any]:
        """Return vault statistics for reporting."""
        with self._lock:
            creds = list(self._creds.values())
        return {
            "total": len(creds),
            "passwords": len([c for c in creds if c.cred_type == CredType.PASSWORD]),
            "hashes": len(
                [c for c in creds if c.cred_type in (CredType.NTLM_HASH, CredType.NET_NTLMV2)]
            ),
            "kerberos": len(
                [
                    c
                    for c in creds
                    if c.cred_type
                    in (
                        CredType.KERBEROS_TGT,
                        CredType.KERBEROS_TGS,
                        CredType.ASREP_HASH,
                    )
                ]
            ),
            "ssh_keys": len([c for c in creds if c.cred_type == CredType.SSH_KEY]),
            "verified": len([c for c in creds if c.verified]),
            "admin_access": len([c for c in creds if c.admin_access]),
            "unique_users": len({c.username for c in creds}),
            "unique_hosts": len({c.host for c in creds if c.host}),
        }

    def _persist(self):
        """Save vault to JSON file."""
        try:
            data = [c.to_dict() for c in self._creds.values()]
            tmp_path = self._save_path.with_suffix(".json.tmp")
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._save_path)
            try:
                os.chmod(self._save_path, 0o600)
            except OSError:
                pass
        except Exception as e:
            logger.error(f"[VAULT] Failed to save vault: {e}")

    def _load(self):
        """Load vault from JSON file (for resume capability)."""
        if not self._save_path.exists():
            return
        try:
            with open(self._save_path, "r") as f:
                data = json.load(f)
            for entry in data:
                entry["cred_type"] = CredType(entry.get("cred_type", "password"))
                cred = Credential(**entry)
                self._creds[cred.identity] = cred
            logger.info(f"[VAULT] Loaded {len(self._creds)} credentials from previous session")
        except Exception as e:
            logger.warning(f"[VAULT] Could not load existing vault: {e}")

    def to_report_data(self) -> List[Dict]:
        """Export vault contents for report generation (masks secrets)."""
        with self._lock:
            results = []
            for cred in self._creds.values():
                masked = cred.to_dict()
                # Mask secrets in report
                if cred.cred_type == CredType.PASSWORD:
                    if len(cred.secret) > 3:
                        masked["secret"] = (
                            cred.secret[:2] + "*" * (len(cred.secret) - 3) + cred.secret[-1]
                        )
                elif len(cred.secret) > 10:
                    masked["secret"] = cred.secret[:6] + "..." + cred.secret[-4:]
                results.append(masked)
            return results
