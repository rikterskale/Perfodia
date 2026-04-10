"""
Service enumeration module — deep-dive enumeration of discovered services.
Uses: enum4linux-ng, smbclient, snmpwalk, onesixtyone, gobuster, nikto, nbtscan
"""

import logging
from typing import Dict, List, Any
from modules.base import BaseModule
from utils.validators import is_tool_available
from utils.parsers import parse_enum4linux_output, parse_snmp_output
from utils.vuln_scorer import Severity

logger = logging.getLogger(__name__)

# Map service names to enumeration handlers
SERVICE_ENUM_MAP = {
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "smb": "smb",
    "snmp": "snmp",
    "http": "http",
    "https": "http",
    "http-proxy": "http",
    "ftp": "ftp",
    "ssh": "ssh",
    "smtp": "smtp",
    "dns": "dns",
    "domain": "dns",
    "ldap": "ldap",
    "mysql": "mysql",
    "ms-sql-s": "mssql",
    "postgresql": "postgres",
    "rdp": "rdp",
    "ms-wbt-server": "rdp",
}


class EnumerationModule(BaseModule):
    MODULE_NAME = "enum"

    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Enumerate services discovered during scanning.

        Workflow:
            1. Identify services from scan results
            2. Run service-specific enumeration tools
            3. Consolidate and structure results
        """
        self.log_phase_start("Service Enumeration")
        results: Dict[str, Any] = {"status": "running"}

        scan_data = (previous_results or {}).get("scan", {})
        hosts = scan_data.get("hosts", [])

        if not hosts:
            logger.warning(
                "[ENUM] No scan data available. Run scan phase first or provide scan results."
            )
            results["status"] = "skipped"
            return results

        for host in hosts:
            ip = host.get("ip", "")
            if not ip:
                continue

            logger.info(f"\n[ENUM] Enumerating {ip}")
            host_results: Dict[str, Any] = {}

            open_ports = self._get_open_ports_for_host(host)
            if not open_ports:
                logger.info(f"  No open ports on {ip}")
                continue

            # Map each port's service to an enumeration handler
            services_to_enum = {}
            for port_num, port_data in open_ports.items():
                svc_name = port_data.get("service", {}).get("name", "").lower()
                handler = SERVICE_ENUM_MAP.get(svc_name)
                if handler:
                    services_to_enum.setdefault(handler, []).append((port_num, port_data))

            # Run enumeration for each service type
            for svc_type, port_list in services_to_enum.items():
                enum_func = getattr(self, f"_enum_{svc_type}", None)
                if enum_func:
                    logger.info(
                        f"  [{svc_type.upper()}] Enumerating on ports: {[p[0] for p in port_list]}"
                    )
                    try:
                        host_results[svc_type] = enum_func(ip, port_list)
                    except Exception as e:
                        logger.error(f"  [{svc_type.upper()}] Error: {e}")
                        host_results[svc_type] = {"error": str(e)}
                else:
                    logger.debug(f"  No handler for {svc_type}")

            results[ip] = host_results

        results["status"] = "completed"
        self.log_phase_end("Service Enumeration")
        return results

    # ─────────────────────────────────────────────────────────────
    # SMB Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_smb(self, ip: str, port_list: List) -> Dict:
        """
        SMB enumeration using enum4linux-ng, smbclient, and rpcclient.

        Enumerates: users, shares, groups, password policy, sessions, OS info
        """
        smb_results: Dict[str, Any] = {}

        # enum4linux-ng (preferred)
        if is_tool_available("enum4linux-ng"):
            result = self.runner.run(
                tool_name="enum4linux-ng",
                args=[
                    ip,
                    "-A",  # All enumeration
                    "-oJ",
                    str(self.session_dir / f"enum/enum4linux_{ip}"),
                ],
                timeout=300,
                output_file=f"enum/enum4linux_{ip}.txt",
            )
            if result.success:
                smb_results = parse_enum4linux_output(result.stdout)
                smb_results["raw_output"] = result.stdout[:5000]

        # smbclient share listing (null session)
        if is_tool_available("smbclient"):
            result = self.runner.run(
                tool_name="smbclient",
                args=["-L", f"//{ip}", "-N", "--no-pass"],
                timeout=30,
                output_file=f"enum/smbclient_{ip}.txt",
            )
            if result.success:
                smb_results["smbclient_shares"] = result.stdout

        # nbtscan
        if is_tool_available("nbtscan"):
            result = self.runner.run(
                tool_name="nbtscan",
                args=["-v", ip],
                timeout=15,
                output_file=f"enum/nbtscan_{ip}.txt",
            )
            if result.success:
                smb_results["nbtscan"] = result.stdout

        # rpcclient enumeration (null session)
        if is_tool_available("rpcclient"):
            for rpc_cmd in ["enumdomusers", "enumdomgroups", "getdompwinfo"]:
                result = self.runner.run(
                    tool_name="rpcclient",
                    args=["-U", "", "-N", ip, "-c", rpc_cmd],
                    timeout=15,
                    retries=0,
                )
                if result.success and result.stdout:
                    smb_results[f"rpc_{rpc_cmd}"] = result.stdout

        return smb_results

    # ─────────────────────────────────────────────────────────────
    # SNMP Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_snmp(self, ip: str, port_list: List) -> Dict:
        """
        SNMP enumeration using onesixtyone and snmpwalk.

        Enumerates: system info, interfaces, processes, installed software
        """
        snmp_results: Dict[str, Any] = {}
        community_strings = self.config.get("enumeration", "snmp", default={}).get(
            "community_strings", ["public"]
        )

        # Community string brute force
        valid_community = None
        if is_tool_available("onesixtyone"):
            cs_file = self.session_dir / "enum" / "snmp_communities.txt"
            cs_file.write_text("\n".join(community_strings))

            result = self.runner.run(
                tool_name="onesixtyone",
                args=[ip, "-c", str(cs_file)],
                timeout=30,
                output_file=f"enum/onesixtyone_{ip}.txt",
            )
            if result.success and result.stdout:
                snmp_results["community_scan"] = result.stdout
                # Extract valid community string
                for cs in community_strings:
                    if cs in result.stdout:
                        valid_community = cs
                        break

        if not valid_community:
            valid_community = "public"

        # snmpwalk with valid community string
        if is_tool_available("snmpwalk"):
            oids = {
                "system": "1.3.6.1.2.1.1",
                "interfaces": "1.3.6.1.2.1.2",
                "running_processes": "1.3.6.1.2.1.25.4.2.1.2",
                "installed_software": "1.3.6.1.2.1.25.6.3.1.2",
                "tcp_connections": "1.3.6.1.2.1.6.13.1.3",
                "users": "1.3.6.1.4.1.77.1.2.25",
            }

            for name, oid in oids.items():
                result = self.runner.run(
                    tool_name="snmpwalk",
                    args=[
                        "-v2c",
                        "-c",
                        valid_community,
                        ip,
                        oid,
                    ],
                    timeout=30,
                    output_file=f"enum/snmpwalk_{ip}_{name}.txt",
                    retries=0,
                )
                if result.success and result.stdout:
                    snmp_results[name] = parse_snmp_output(result.stdout)
                    logger.info(f"    SNMP {name}: {len(snmp_results[name])} entries")

        # ── SNMPv3 enumeration ──
        snmpv3_config = self.config.get("enumeration", "snmpv3", default={})
        if snmpv3_config.get("enabled", True) and is_tool_available("snmpwalk"):
            snmp_results["v3"] = self._enum_snmpv3(ip, snmpv3_config)

        return snmp_results

    def _enum_snmpv3(self, ip: str, v3_config: Dict) -> Dict:
        """
        SNMPv3 enumeration — tries noAuthNoPriv, authNoPriv, and authPriv
        security levels with configured credentials.

        SNMPv3 uses usernames instead of community strings, and supports
        authentication (MD5/SHA) and encryption (DES/AES).
        """
        v3_results: Dict[str, Any] = {}

        # Test 1: noAuthNoPriv (just a username, no auth or encryption)
        v3_users = v3_config.get("usernames", ["initial", "public", "admin", "snmpuser"])
        for user in v3_users:
            result = self.runner.run(
                tool_name="snmpwalk",
                args=[
                    "-v3",
                    "-l",
                    "noAuthNoPriv",
                    "-u",
                    user,
                    ip,
                    "1.3.6.1.2.1.1",  # System info
                ],
                timeout=15,
                retries=0,
            )
            if result.success and result.stdout and "Timeout" not in result.stdout:
                v3_results["noauth_user"] = user
                v3_results["noauth_data"] = result.stdout[:2000]
                logger.warning(f"    [!] SNMPv3 noAuthNoPriv access with user: {user}")
                # Score as finding
                if self.vuln_scorer:
                    self._score_finding(
                        title=f"SNMPv3 noAuthNoPriv access (user: {user})",
                        host=ip,
                        severity=Severity.MEDIUM,
                        cvss=5.3,
                        remediation="Configure SNMPv3 with authPriv security level.",
                        source_tool="snmpwalk",
                    )
                break

        # Test 2: authNoPriv with common credentials
        v3_creds = v3_config.get(
            "credentials",
            [
                {"user": "admin", "auth_pass": "admin123", "auth_proto": "SHA"},
                {"user": "snmpuser", "auth_pass": "snmpuser", "auth_proto": "MD5"},
            ],
        )

        for cred in v3_creds:
            user = cred.get("user", "")
            auth_pass = cred.get("auth_pass", "")
            auth_proto = cred.get("auth_proto", "SHA")

            result = self.runner.run(
                tool_name="snmpwalk",
                args=[
                    "-v3",
                    "-l",
                    "authNoPriv",
                    "-u",
                    user,
                    "-a",
                    auth_proto,
                    "-A",
                    auth_pass,
                    ip,
                    "1.3.6.1.2.1.1",
                ],
                timeout=15,
                retries=0,
            )
            if result.success and result.stdout and "Timeout" not in result.stdout:
                v3_results["auth_user"] = user
                v3_results["auth_proto"] = auth_proto
                v3_results["auth_data"] = result.stdout[:2000]
                logger.warning(f"    [!] SNMPv3 authNoPriv access: {user}/{auth_proto}")
                # Store credential
                if self.credential_vault:
                    self.credential_vault.add_password(
                        username=user,
                        password=auth_pass,
                        host=ip,
                        port=161,
                        service="snmpv3",
                        source_phase="enum",
                        source_tool="snmpwalk",
                    )
                break

        return v3_results

    # ─────────────────────────────────────────────────────────────
    # HTTP Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_http(self, ip: str, port_list: List) -> Dict:
        """
        HTTP service enumeration using gobuster, nikto, and curl.

        Enumerates: directories, technologies, headers, potential vulns
        """
        http_results: Dict[str, Any] = {}

        for port_num, port_data in port_list:
            svc = port_data.get("service", {})
            tunnel = svc.get("tunnel", "")
            scheme = "https" if tunnel == "ssl" or port_num == 443 else "http"
            base_url = f"{scheme}://{ip}:{port_num}"
            port_key = f"port_{port_num}"

            port_results: Dict[str, Any] = {"url": base_url}

            # Header grabbing with curl
            result = self.runner.run(
                tool_name="curl",
                args=[
                    "-s",
                    "-I",
                    "-k",  # Allow self-signed certs
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "15",
                    base_url,
                ],
                timeout=20,
                output_file=f"enum/http_headers_{ip}_{port_num}.txt",
            )
            if result.success:
                port_results["headers"] = result.stdout

            # Nikto scan
            if is_tool_available("nikto"):
                result = self.runner.run(
                    tool_name="nikto",
                    args=[
                        "-h",
                        base_url,
                        "-Format",
                        "txt",
                        "-o",
                        str(self.session_dir / f"enum/nikto_{ip}_{port_num}.txt"),
                        "-Tuning",
                        "123457890abc",
                        "-timeout",
                        "10",
                    ],
                    timeout=300,
                    output_file=f"enum/nikto_{ip}_{port_num}_stdout.txt",
                )
                if result.success:
                    port_results["nikto"] = result.stdout[:5000]

            # Gobuster directory brute force
            if is_tool_available("gobuster"):
                wordlist = self.config.get("enumeration", "http", default={}).get(
                    "wordlist", "/usr/share/wordlists/dirb/common.txt"
                )

                extensions = self.config.get("enumeration", "http", default={}).get(
                    "extensions", "php,html,txt"
                )

                result = self.runner.run(
                    tool_name="gobuster",
                    args=[
                        "dir",
                        "-u",
                        base_url,
                        "-w",
                        wordlist,
                        "-x",
                        extensions,
                        "-t",
                        "20",
                        "-k",  # Skip TLS verification
                        "--no-error",
                        "-q",
                        "-o",
                        str(self.session_dir / f"enum/gobuster_{ip}_{port_num}.txt"),
                    ],
                    timeout=300,
                    retries=0,
                )
                if result.success:
                    port_results["gobuster"] = result.stdout[:5000]

            http_results[port_key] = port_results

        return http_results

    # ─────────────────────────────────────────────────────────────
    # FTP Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_ftp(self, ip: str, port_list: List) -> Dict:
        """Check for anonymous FTP access."""
        ftp_results: Dict[str, Any] = {}

        for port_num, _ in port_list:
            result = self.runner.run(
                tool_name="curl",
                args=[
                    "-s",
                    "--connect-timeout",
                    "10",
                    "--max-time",
                    "15",
                    f"ftp://anonymous:anonymous@{ip}:{port_num}/",
                ],
                timeout=20,
            )
            if result.success:
                ftp_results[f"port_{port_num}"] = {
                    "anonymous_access": True,
                    "listing": result.stdout[:3000],
                }
                logger.warning(f"    [!] Anonymous FTP access on {ip}:{port_num}")
                # Score as a finding
                self._score_finding(
                    title=f"Anonymous FTP Access on port {port_num}",
                    host=ip,
                    severity=Severity.MEDIUM,
                    cvss=5.3,
                    remediation="Disable anonymous FTP access or restrict to read-only non-sensitive files.",
                    source_tool="curl",
                )
            else:
                ftp_results[f"port_{port_num}"] = {"anonymous_access": False}

        return ftp_results

    # ─────────────────────────────────────────────────────────────
    # SSH Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_ssh(self, ip: str, port_list: List) -> Dict:
        """Grab SSH banner and check authentication methods."""
        ssh_results: Dict[str, Any] = {}

        for port_num, port_data in port_list:
            svc = port_data.get("service", {})
            ssh_results[f"port_{port_num}"] = {
                "version": f"{svc.get('product', '')} {svc.get('version', '')}".strip(),
                "extra": svc.get("extrainfo", ""),
            }

        return ssh_results

    # ─────────────────────────────────────────────────────────────
    # SMTP Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_smtp(self, ip: str, port_list: List) -> Dict:
        """SMTP user enumeration via nmap NSE scripts."""
        smtp_results: Dict[str, Any] = {}

        for port_num, _ in port_list:
            # Use nmap SMTP enumeration scripts (VRFY, EXPN, RCPT TO)
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "--script",
                    "smtp-enum-users,smtp-commands,smtp-open-relay",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/smtp_{ip}_{port_num}.txt",
                retries=0,
            )

            port_results: Dict[str, Any] = {"valid_users": []}
            if result.success and result.stdout:
                port_results["raw"] = result.stdout[:3000]
                # Check for open relay
                if "open-relay" in result.stdout.lower() and "isn't" not in result.stdout.lower():
                    port_results["open_relay"] = True
                    logger.warning(f"    [!] SMTP open relay on {ip}:{port_num}")

            smtp_results[f"port_{port_num}"] = port_results

        return smtp_results

    # ─────────────────────────────────────────────────────────────
    # DNS Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_dns(self, ip: str, port_list: List) -> Dict:
        """DNS service enumeration — check for recursion and zone transfer."""
        dns_results: Dict[str, Any] = {}

        # Check for open recursion
        result = self.runner.run(
            tool_name="dig",
            args=["@" + ip, "google.com", "+short", "+time=5"],
            timeout=15,
        )
        if result.success and result.stdout.strip():
            dns_results["recursion_enabled"] = True
            logger.info(f"    DNS recursion enabled on {ip}")
        else:
            dns_results["recursion_enabled"] = False

        return dns_results

    # ─────────────────────────────────────────────────────────────
    # LDAP Enumeration
    # ─────────────────────────────────────────────────────────────

    def _enum_ldap(self, ip: str, port_list: List) -> Dict:
        """LDAP anonymous bind check."""
        ldap_results: Dict[str, Any] = {}

        for port_num, _ in port_list:
            # Use nmap LDAP scripts as primary approach
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "-sV",
                    "--script",
                    "ldap-rootdse,ldap-search",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/ldap_{ip}_{port_num}.txt",
            )
            if result.success:
                ldap_results[f"port_{port_num}"] = result.stdout

        return ldap_results

    # ─────────────────────────────────────────────────────────────
    # Database Enumeration stubs
    # ─────────────────────────────────────────────────────────────

    def _enum_mysql(self, ip: str, port_list: List) -> Dict:
        """MySQL service enumeration."""
        results: Dict[str, Any] = {}
        for port_num, _ in port_list:
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "--script",
                    "mysql-info,mysql-enum,mysql-empty-password",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/mysql_{ip}_{port_num}.txt",
            )
            if result.success:
                results[f"port_{port_num}"] = result.stdout
        return results

    def _enum_mssql(self, ip: str, port_list: List) -> Dict:
        """MSSQL service enumeration."""
        results: Dict[str, Any] = {}
        for port_num, _ in port_list:
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "--script",
                    "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/mssql_{ip}_{port_num}.txt",
            )
            if result.success:
                results[f"port_{port_num}"] = result.stdout
        return results

    def _enum_postgres(self, ip: str, port_list: List) -> Dict:
        """PostgreSQL service enumeration."""
        results: Dict[str, Any] = {}
        for port_num, _ in port_list:
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "--script",
                    "pgsql-brute",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/postgres_{ip}_{port_num}.txt",
            )
            if result.success:
                results[f"port_{port_num}"] = result.stdout
        return results

    def _enum_rdp(self, ip: str, port_list: List) -> Dict:
        """RDP service enumeration."""
        results: Dict[str, Any] = {}
        for port_num, _ in port_list:
            result = self.runner.run(
                tool_name="nmap",
                args=[
                    "--script",
                    "rdp-enum-encryption,rdp-ntlm-info",
                    "-p",
                    str(port_num),
                    ip,
                ],
                timeout=60,
                output_file=f"enum/rdp_{ip}_{port_num}.txt",
            )
            if result.success:
                results[f"port_{port_num}"] = result.stdout
        return results
