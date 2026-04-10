"""
Password Cracking module — feeds discovered hashes to hashcat or john
and stores cracked passwords back into the credential vault.

Uses: hashcat, john
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Any

from modules.base import BaseModule
from utils.validators import is_tool_available

logger = logging.getLogger(__name__)

# Hash type mappings for hashcat mode numbers
HASHCAT_MODES: Dict[str, int] = {
    "ntlm": 1000,
    "ntlmv2": 5600,
    "net-ntlmv2": 5600,
    "asrep": 18200,
    "kerberoast": 13100,
    "krb5tgs": 13100,
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1800,
    "bcrypt": 3200,
    "descrypt": 1500,
    "mscache2": 2100,
    "lm": 3000,
}

# Map credential vault CredType enum values to HASHCAT_MODES keys.
# CredType.value strings (e.g. "ntlm_hash") don't always match the
# short names used in HASHCAT_MODES (e.g. "ntlm").
_CREDTYPE_TO_HASHCAT: Dict[str, str] = {
    "ntlm_hash": "ntlm",
    "net_ntlmv2": "ntlmv2",
    "asrep_hash": "asrep",
    "krb_tgs": "kerberoast",
}


class CrackingModule(BaseModule):
    MODULE_NAME = "crack"

    def run(self, previous_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Password cracking workflow:
            1. Collect all hashes from credential vault and loot files
            2. Identify hash types
            3. Run hashcat (preferred) or john against each type
            4. Store cracked passwords back into the credential vault
        """
        self.log_phase_start("Password Cracking")
        results: Dict[str, Any] = {"status": "running", "cracked": 0, "total_hashes": 0}

        if not is_tool_available("hashcat") and not is_tool_available("john"):
            logger.warning("[CRACK] Neither hashcat nor john found — skipping")
            results["status"] = "no_tools"
            return results

        # ── Collect hashes from vault and loot files ──
        hash_sets = self._collect_hashes(previous_results or {})
        if not hash_sets:
            logger.info("[CRACK] No hashes found to crack")
            results["status"] = "no_hashes"
            return results

        results["total_hashes"] = sum(len(h["hashes"]) for h in hash_sets)
        logger.info(
            f"[CRACK] Collected {results['total_hashes']} hashes across {len(hash_sets)} type(s)"
        )

        cracking_config = self.config.get("cracking", default={})
        wordlist = cracking_config.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        max_runtime = cracking_config.get("max_runtime", 600)
        use_rules = cracking_config.get("use_rules", True)

        total_cracked = 0
        for hash_set in hash_sets:
            hash_type = hash_set["type"]
            hashes = hash_set["hashes"]
            source = hash_set.get("source", "unknown")

            logger.info(
                f"[CRACK] Cracking {len(hashes)} {hash_type} hashes from {source}"
            )

            # Write hashes to temp file
            hash_file = self.session_dir / "loot" / f"crack_{hash_type}_{source}.txt"
            hash_file.parent.mkdir(parents=True, exist_ok=True)
            hash_file.write_text("\n".join(hashes))

            # Try hashcat first, then john
            cracked = []
            if is_tool_available("hashcat"):
                cracked = self._run_hashcat(
                    hash_file, hash_type, wordlist, max_runtime, use_rules
                )
            elif is_tool_available("john"):
                cracked = self._run_john(hash_file, hash_type, wordlist, max_runtime)

            if cracked:
                total_cracked += len(cracked)
                results.setdefault("cracked_passwords", []).extend(cracked)
                logger.warning(f"  [!] Cracked {len(cracked)} passwords!")

                # Store back into credential vault
                self._store_cracked(cracked, hash_type, source)

        results["cracked"] = total_cracked
        results["status"] = "completed"
        self.log_phase_end("Password Cracking")
        return results

    def _collect_hashes(self, previous_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Collect all hashes from the credential vault and loot directory."""
        hash_sets: List[Dict[str, Any]] = []

        # From credential vault
        if self.credential_vault:
            vault_hashes = self.credential_vault.get_hashes()
            by_type: Dict[str, List[str]] = {}
            for cred in vault_hashes:
                # Map CredType value to hashcat-compatible type name
                raw_type = cred.cred_type.value
                t = _CREDTYPE_TO_HASHCAT.get(raw_type, raw_type)
                by_type.setdefault(t, []).append(cred.secret)
            for hash_type, hashes in by_type.items():
                if hashes:
                    hash_sets.append(
                        {"type": hash_type, "hashes": hashes, "source": "vault"}
                    )

        # From loot directory files
        loot_dir = self.session_dir / "loot"
        if loot_dir.exists():
            patterns = {
                "asrep_hashes_*.txt": "asrep",
                "kerberoast_*.txt": "kerberoast",
                "secretsdump_*.ntds": "ntlm",
            }
            for pattern, hash_type in patterns.items():
                for f in loot_dir.glob(pattern):
                    hashes = [
                        line.strip()
                        for line in f.read_text().split("\n")
                        if line.strip() and not line.startswith("#")
                    ]
                    if hashes:
                        hash_sets.append(
                            {"type": hash_type, "hashes": hashes, "source": f.stem}
                        )

        return hash_sets

    def _run_hashcat(
        self,
        hash_file: Path,
        hash_type: str,
        wordlist: str,
        max_runtime: int,
        use_rules: bool,
    ) -> List[Dict[str, str]]:
        """Run hashcat against a hash file."""
        mode = HASHCAT_MODES.get(hash_type)
        if mode is None:
            # Try to auto-detect
            logger.info(f"  No hashcat mode for '{hash_type}', trying auto-detect")
            mode_arg = []
        else:
            mode_arg = ["-m", str(mode)]

        pot_file = hash_file.with_suffix(".pot")
        out_file = hash_file.with_suffix(".cracked")

        args = [
            *mode_arg,
            str(hash_file),
            wordlist,
            "--potfile-path",
            str(pot_file),
            "--outfile",
            str(out_file),
            "--outfile-format",
            "2",  # hash:plain
            "--runtime",
            str(max_runtime),
            "--quiet",
            "--force",  # Required in VMs without GPU
        ]

        if use_rules and Path("/usr/share/hashcat/rules/best64.rule").exists():
            args.extend(["-r", "/usr/share/hashcat/rules/best64.rule"])

        self.runner.run(
            tool_name="hashcat",
            args=args,
            timeout=max_runtime + 60,
            output_file=f"loot/hashcat_{hash_type}_stdout.txt",
            retries=0,
        )

        cracked: List[Dict[str, str]] = []
        if out_file.exists():
            for line in out_file.read_text().strip().split("\n"):
                line = line.strip()
                if ":" in line:
                    parts = line.split(":", 1)
                    cracked.append({"hash": parts[0], "password": parts[1]})

        # Also check potfile for previously cracked
        if pot_file.exists():
            for line in pot_file.read_text().strip().split("\n"):
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    entry = {"hash": parts[0], "password": parts[1]}
                    if entry not in cracked:
                        cracked.append(entry)

        return cracked

    def _run_john(
        self,
        hash_file: Path,
        hash_type: str,
        wordlist: str,
        max_runtime: int,
    ) -> List[Dict[str, str]]:
        """Run john the ripper against a hash file."""
        john_format_map = {
            "ntlm": "NT",
            "ntlmv2": "netntlmv2",
            "asrep": "krb5asrep",
            "kerberoast": "krb5tgs",
            "md5": "Raw-MD5",
            "sha1": "Raw-SHA1",
            "sha256": "Raw-SHA256",
            "sha512": "Raw-SHA512",
        }

        fmt = john_format_map.get(hash_type)
        fmt_arg = [f"--format={fmt}"] if fmt else []

        self.runner.run(
            tool_name="john",
            args=[
                str(hash_file),
                f"--wordlist={wordlist}",
                *fmt_arg,
                f"--max-run-time={max_runtime}",
            ],
            timeout=max_runtime + 60,
            output_file=f"loot/john_{hash_type}_stdout.txt",
            retries=0,
        )

        # Extract cracked passwords with --show
        show_result = self.runner.run(
            tool_name="john",
            args=[str(hash_file), "--show", *fmt_arg],
            timeout=30,
            retries=0,
        )

        cracked: List[Dict[str, str]] = []
        if show_result.success and show_result.stdout:
            for line in show_result.stdout.strip().split("\n"):
                if ":" in line and "password hashes cracked" not in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        cracked.append({"hash": parts[0], "password": parts[1]})

        return cracked

    def _store_cracked(
        self,
        cracked: List[Dict[str, str]],
        hash_type: str,
        source: str,
    ) -> None:
        """Store cracked passwords back into the credential vault."""
        if not self.credential_vault:
            return

        for entry in cracked:
            password = entry.get("password", "")
            hash_val = entry.get("hash", "")

            # Try to find the original credential in the vault and update it
            username = self._extract_username_from_hash(hash_val, hash_type)
            if username and password:
                self.credential_vault.add_password(
                    username=username,
                    password=password,
                    source_phase="crack",
                    source_tool="hashcat" if is_tool_available("hashcat") else "john",
                    notes=f"Cracked from {hash_type} hash (source: {source})",
                )

    @staticmethod
    def _extract_username_from_hash(hash_val: str, hash_type: str) -> str:
        """Extract username from common hash formats."""
        # NTLM from secretsdump: user:rid:lmhash:nthash:::
        if hash_type in ("ntlm",) and ":" in hash_val:
            return hash_val.split(":")[0]
        # Kerberos: $krb5asrep$23$user@DOMAIN or $krb5tgs$23$*user$DOMAIN...
        krb_match = re.match(r"\$krb5(?:asrep|tgs)\$\d+\$\*?([^@$*]+)", hash_val)
        if krb_match:
            return krb_match.group(1)
        # Net-NTLMv2: user::domain:...
        if "::" in hash_val:
            return hash_val.split("::")[0]
        return ""
