"""
Report generator — produces HTML, JSON, and Markdown reports with
executive summary, risk rating, prioritized findings, credential
vault summary, and evidence screenshot gallery.
"""

import json
import logging
from html import escape as html_escape
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate penetration testing reports in multiple formats."""

    def __init__(self, session_dir: Path, config):
        self.session_dir = session_dir
        self.config = config

    def generate(self, results: Dict = None, format: str = "all"):
        if results is None:
            results = self._load_session_data()
        if format in ("json", "all"):
            self._generate_json(results)
        if format in ("markdown", "all"):
            self._generate_markdown(results)
        if format in ("html", "all", "pdf"):
            self._generate_html(results)
        if format in ("pdf", "all"):
            self._generate_pdf(results)

    def require_session_data(self) -> Path:
        """Return the first available session data file or raise a clear error."""
        for name in ["results.json", "session_checkpoint.json"]:
            path = self.session_dir / name
            if path.exists():
                return path
        raise FileNotFoundError(
            f"No session data found in {self.session_dir}. Expected results.json or session_checkpoint.json."
        )

    def _load_session_data(self) -> Dict:
        path = self.require_session_data()
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {path.name}: {e}")
            raise

    def _generate_json(self, results: Dict):
        out_path = self.session_dir / "report.json"
        try:
            with open(out_path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"[+] JSON report: {out_path}")
        except Exception as e:
            logger.error(f"JSON report failed: {e}")

    # ─────────────────────────────────────────────────────────────
    # Markdown Report
    # ─────────────────────────────────────────────────────────────

    def _generate_markdown(self, results: Dict):
        out_path = self.session_dir / "report.md"
        lines = [
            "# Penetration Test Report",
            "",
            f"**Session:** {results.get('session_id', 'N/A')}  ",
            f"**Start:** {results.get('start_time', 'N/A')}  ",
            f"**End:** {results.get('end_time', 'N/A')}  ",
            f"**Targets:** {', '.join(results.get('targets', []))}  ",
            f"**Mode:** {results.get('mode', 'N/A')}  ",
            "",
            "---",
            "",
        ]

        phases = results.get("phases", {})

        # ── Executive Summary with Risk Rating ──
        lines.extend(self._md_executive_summary(results))

        # ── Vulnerability Findings ──
        lines.extend(self._md_findings(results))

        # ── Credential Vault ──
        lines.extend(self._md_credentials(results))

        # ── Phase Details ──
        if "scan" in phases:
            lines.extend(self._md_section_scan(phases["scan"]))
        if "enum" in phases:
            lines.extend(self._md_section_enum(phases["enum"]))
        if "webapp" in phases:
            lines.extend(self._md_section_webapp(phases["webapp"]))
        if "ad" in phases:
            lines.extend(self._md_section_ad(phases["ad"]))
        if "exploit" in phases:
            lines.extend(self._md_section_exploit(phases["exploit"]))
        if "crack" in phases:
            lines.extend(self._md_section_crack(phases["crack"]))

        # ── Screenshots ──
        lines.extend(self._md_screenshots(results))

        try:
            with open(out_path, "w") as f:
                f.write("\n".join(lines))
            logger.info(f"[+] Markdown report: {out_path}")
        except Exception as e:
            logger.error(f"Markdown report failed: {e}")

    def _md_executive_summary(self, results: Dict) -> list:
        lines = ["## Executive Summary", ""]

        scoring = results.get("vulnerability_scoring", {})
        risk = scoring.get("risk_rating", {})

        if risk:
            overall = risk.get("overall_risk", "UNKNOWN")
            score = risk.get("risk_score", 0)
            breakdown = risk.get("breakdown", {})
            narrative = risk.get("attack_narrative", "")

            lines.append(f"### Overall Risk: **{overall}** (Score: {score})")
            lines.append("")

            if narrative:
                lines.append(f"> {narrative}")
                lines.append("")

            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = breakdown.get(sev, 0)
                if count > 0:
                    lines.append(f"| **{sev.upper()}** | {count} |")
            lines.append("")
        else:
            # Fallback summary from phase data
            phases = results.get("phases", {})
            total_hosts = len(phases.get("scan", {}).get("hosts", []))
            total_ports = sum(
                len(h.get("ports", [])) for h in phases.get("scan", {}).get("hosts", [])
            )
            total_exploits = len(phases.get("exploit", {}).get("exploits_found", []))
            lines.append(f"- **Hosts discovered:** {total_hosts}")
            lines.append(f"- **Open ports found:** {total_ports}")
            lines.append(f"- **Potential exploits:** {total_exploits}")
            lines.append("")

        # Recommendations
        if self.config.get("reporting", "include_remediation"):
            lines.extend(
                [
                    "### Priority Recommendations",
                    "",
                    "1. Patch all critical and high-severity vulnerabilities immediately",
                    "2. Change all default and weak credentials discovered during testing",
                    "3. Enforce SMB signing and disable legacy protocols (SMBv1, TLS 1.0)",
                    "4. Implement network segmentation to limit lateral movement",
                    "5. Deploy multi-factor authentication on all administrative interfaces",
                    "6. Enable comprehensive logging and monitoring on all critical systems",
                    "",
                ]
            )
        return lines

    def _md_findings(self, results: Dict) -> list:
        scoring = results.get("vulnerability_scoring", {})
        findings = scoring.get("findings", [])
        if not findings:
            return []

        lines = [
            "## Vulnerability Findings",
            "",
            "| # | Severity | CVSS | Host | Title | Remediation |",
            "|---|----------|------|------|-------|-------------|",
        ]
        for i, f in enumerate(findings[:50], 1):
            lines.append(
                f"| {i} | **{f.get('severity', '').upper()}** "
                f"| {f.get('cvss_score', 0):.1f} "
                f"| {f.get('host', '')}:{f.get('port', '')} "
                f"| {f.get('title', '')[:60]} "
                f"| {f.get('remediation', '')[:60]} |"
            )
        lines.extend(
            [
                "",
                f"*Showing top {min(50, len(findings))} of {len(findings)} findings.*",
                "",
            ]
        )
        return lines

    def _md_credentials(self, results: Dict) -> list:
        vault = results.get("credential_vault", {})
        creds = vault.get("credentials", [])
        stats = vault.get("stats", {})
        if not creds:
            return []

        lines = [
            "## Credential Vault",
            "",
            f"**Total:** {stats.get('total', 0)} credentials "
            f"({stats.get('passwords', 0)} passwords, "
            f"{stats.get('hashes', 0)} hashes, "
            f"{stats.get('kerberos', 0)} Kerberos tickets)",
            "",
            f"**Verified:** {stats.get('verified', 0)} | "
            f"**Admin access:** {stats.get('admin_access', 0)}",
            "",
            "| Username | Type | Host | Service | Verified | Admin |",
            "|----------|------|------|---------|----------|-------|",
        ]
        for c in creds[:30]:
            domain = f"{c.get('domain', '')}\\\\".lstrip("\\\\") if c.get("domain") else ""
            lines.append(
                f"| {domain}{c.get('username', '')} "
                f"| {c.get('cred_type', '')} "
                f"| {c.get('host', '')} "
                f"| {c.get('service', '')} "
                f"| {'Yes' if c.get('verified') else 'No'} "
                f"| {'Yes' if c.get('admin_access') else 'No'} |"
            )
        lines.append("")
        return lines

    def _md_section_scan(self, data: Dict) -> list:
        lines = ["## Network Scanning Results", ""]
        hosts = data.get("hosts", [])
        lines.append(f"**Hosts discovered:** {len(hosts)}")
        lines.append("")
        for host in hosts:
            ip = host.get("ip", "")
            hostname = host.get("hostname", "")
            display = f"{ip} ({hostname})" if hostname else ip
            lines.append(f"### Host: {display}")
            os_matches = host.get("os_matches", [])
            if os_matches:
                lines.append(f"**OS:** {os_matches[0].get('name', 'Unknown')}")
                lines.append("")
            ports = host.get("ports", [])
            if ports:
                lines.append("| Port | State | Service | Version |")
                lines.append("|------|-------|---------|---------|")
                for p in ports:
                    svc = p.get("service", {})
                    lines.append(
                        f"| {p.get('port', '')}/{p.get('protocol', '')} "
                        f"| {p.get('state', '')} "
                        f"| {svc.get('name', '')} "
                        f"| {svc.get('product', '')} {svc.get('version', '')} |"
                    )
                lines.append("")
        return lines

    def _md_section_enum(self, data: Dict) -> list:
        lines = ["## Service Enumeration", ""]
        for target, tdata in data.items():
            if target in ("status", "error"):
                continue
            lines.append(f"### Target: {target}")
            if isinstance(tdata, dict):
                for svc, sdata in tdata.items():
                    lines.append(f"#### {svc.upper()}")
                    if isinstance(sdata, dict):
                        if sdata.get("users"):
                            lines.append(
                                "**Users:** "
                                + ", ".join(
                                    f"`{u.get('username', u) if isinstance(u, dict) else u}`"
                                    for u in sdata["users"][:20]
                                )
                            )
                        if sdata.get("shares"):
                            lines.append(
                                "**Shares:** "
                                + ", ".join(
                                    f"`{s.get('name', s) if isinstance(s, dict) else s}`"
                                    for s in sdata["shares"][:10]
                                )
                            )
                    lines.append("")
        return lines

    def _md_section_webapp(self, data: Dict) -> list:
        lines = ["## Web Application Testing", ""]
        for key, tdata in data.items():
            if key in ("status", "error", "targets"):
                continue
            if not isinstance(tdata, dict):
                continue
            url = tdata.get("url", key)
            lines.append(f"### {url}")
            headers = tdata.get("headers", {})
            if headers.get("missing_security_headers"):
                lines.append(
                    "**Missing Security Headers:** "
                    + ", ".join(headers["missing_security_headers"])
                )
            if headers.get("issues"):
                for issue in headers["issues"][:5]:
                    lines.append(f"- {issue}")
            tech = tdata.get("technologies", {})
            if tech.get("detected_frameworks"):
                lines.append(
                    "**Detected:** "
                    + ", ".join(f.get("framework", "") for f in tech["detected_frameworks"])
                )
            vulns = tdata.get("vuln_checks", {})
            if vulns.get("git_exposed"):
                lines.append("**⚠ .git directory exposed!**")
            if vulns.get("env_exposed"):
                lines.append("**⚠ .env file exposed!**")
            sqlmap = tdata.get("sqlmap", {})
            if sqlmap.get("vulnerable"):
                lines.append("**⚠ SQL INJECTION FOUND**")
            lines.append("")
        return lines

    def _md_section_ad(self, data: Dict) -> list:
        lines = ["## Active Directory Assessment", ""]
        domain = data.get("domain", "")
        if domain:
            lines.append(f"**Domain:** {domain}")
        dcs = data.get("domain_controllers", [])
        if dcs:
            lines.append(f"**Domain Controllers:** {len(dcs)}")
            for dc in dcs:
                lines.append(f"- {dc.get('ip', '')} ({dc.get('hostname', '')})")
        lines.append("")
        for key, dc_data in data.items():
            if key in ("status", "domain", "domain_controllers"):
                continue
            if not isinstance(dc_data, dict):
                continue
            lines.append(f"### DC: {key}")
            ldap = dc_data.get("ldap", {})
            if ldap.get("anonymous_bind"):
                lines.append("**⚠ LDAP anonymous bind successful!**")
            if ldap.get("users"):
                lines.append(f"**Users discovered:** {len(ldap['users'])}")
            if ldap.get("admin_accounts"):
                lines.append(f"**Admin accounts:** {len(ldap['admin_accounts'])}")
            asrep = dc_data.get("asrep_roast", {})
            if asrep.get("hashes_found", 0) > 0:
                lines.append(f"**⚠ AS-REP hashes found:** {asrep['hashes_found']}")
            kerb = dc_data.get("kerberoast", {})
            if kerb.get("hashes_found", 0) > 0:
                lines.append(f"**⚠ Kerberoast hashes found:** {kerb['hashes_found']}")
            signing = dc_data.get("smb_signing", {})
            if not signing.get("enforced", True):
                lines.append("**⚠ SMB signing NOT enforced — relay attacks possible**")
            lines.append("")
        return lines

    def _md_section_exploit(self, data: Dict) -> list:
        lines = ["## Exploitation Results", ""]
        exploits = data.get("exploits_found", [])
        if exploits:
            lines.append(f"**Potential exploits identified:** {len(exploits)}")
            lines.append("")
            lines.append("| Service/Version | Exploit | Platform |")
            lines.append("|----------------|---------|----------|")
            for e in exploits[:30]:
                lines.append(
                    f"| {e.get('query', '')} "
                    f"| {e.get('title', '')[:60]} "
                    f"| {e.get('platform', '')} |"
                )
            lines.append("")
        creds = data.get("credentials", [])
        if creds:
            lines.append("### Credentials Recovered")
            lines.append("| Host | Service | Username |")
            lines.append("|------|---------|----------|")
            for c in creds:
                lines.append(
                    f"| {c.get('host', '')} | {c.get('service', '')} | {c.get('username', '')} |"
                )
            lines.append("")
        return lines

    def _md_section_crack(self, data: Dict) -> list:
        """Render cracking phase results in markdown."""
        lines = ["## Password Cracking Results", ""]
        status = data.get("status", "unknown")
        total_hashes = data.get("total_hashes", 0)
        cracked_count = data.get("cracked", 0)

        lines.append(f"**Status:** {status}  ")
        lines.append(f"**Total hashes collected:** {total_hashes}  ")
        lines.append(f"**Passwords cracked:** {cracked_count}  ")
        lines.append("")

        cracked_passwords = data.get("cracked_passwords", [])
        if cracked_passwords:
            lines.append("### Cracked Passwords")
            lines.append("")
            lines.append("| Hash (truncated) | Password |")
            lines.append("|-----------------|----------|")
            for entry in cracked_passwords[:30]:
                hash_trunc = entry.get("hash", "")[:20] + "..."
                pwd = entry.get("password", "")
                # Mask password in report: show first 2 and last char
                if len(pwd) > 3:
                    masked = pwd[:2] + "*" * (len(pwd) - 3) + pwd[-1]
                else:
                    masked = "***"
                lines.append(f"| `{hash_trunc}` | `{masked}` |")
            lines.append("")
        elif status == "no_hashes":
            lines.append("*No hashes were found to crack.*")
            lines.append("")
        elif status == "no_tools":
            lines.append("*Neither hashcat nor john was available.*")
            lines.append("")

        return lines

    def _md_screenshots(self, results: Dict) -> list:
        screenshots = results.get("screenshots", {})
        if not screenshots:
            return []
        lines = ["## Evidence Screenshots", ""]
        for url, path in screenshots.items():
            if url.startswith("_"):
                continue
            lines.append(f"- **{url}**: `{path}`")
        lines.append("")
        return lines

    # ─────────────────────────────────────────────────────────────
    # HTML Report
    # ─────────────────────────────────────────────────────────────

    def _generate_html(self, results: Dict):
        out_path = self.session_dir / "report.html"
        phases = results.get("phases", {})
        scoring = results.get("vulnerability_scoring", {})
        risk = scoring.get("risk_rating", {})
        vault_data = results.get("credential_vault", {})

        risk_color = {
            "CRITICAL": "#ff1744",
            "HIGH": "#ff6b6b",
            "MEDIUM": "#ffd93d",
            "LOW": "#69f0ae",
            "INFORMATIONAL": "#4fc3f7",
        }.get(risk.get("overall_risk", ""), "#888")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Perfodia Report — {html_escape(str(results.get("session_id", "")))}</title>
<style>
body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; background: #0a0a1a; color: #e0e0e0; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 40px; }}
h1 {{ color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }}
h2 {{ color: #ff6b6b; margin-top: 40px; }}
h3 {{ color: #ffd93d; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
th, td {{ border: 1px solid #333; padding: 8px 12px; text-align: left; }}
th {{ background: #16213e; color: #00d4ff; }}
tr:nth-child(even) {{ background: #0f3460; }}
pre {{ background: #0a0a1a; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #333; }}
.risk-badge {{ display: inline-block; padding: 8px 24px; border-radius: 4px;
    font-size: 1.4em; font-weight: bold; color: #000; background: {risk_color}; }}
.finding-critical {{ border-left: 4px solid #ff1744; padding: 8px; margin: 5px 0; background: #1a0a0a; }}
.finding-high {{ border-left: 4px solid #ff6b6b; padding: 8px; margin: 5px 0; background: #1a1010; }}
.finding-medium {{ border-left: 4px solid #ffd93d; padding: 8px; margin: 5px 0; background: #1a1a10; }}
.finding-low {{ border-left: 4px solid #69f0ae; padding: 8px; margin: 5px 0; background: #101a10; }}
.meta {{ color: #888; font-size: 0.9em; }}
.stat {{ display: inline-block; background: #16213e; padding: 15px 25px; border-radius: 8px;
    margin: 5px; text-align: center; min-width: 120px; }}
.stat .number {{ font-size: 2em; font-weight: bold; color: #00d4ff; }}
.stat .label {{ font-size: 0.85em; color: #888; }}
blockquote {{ border-left: 3px solid #00d4ff; padding: 10px 15px; margin: 15px 0;
    background: #0f1a2e; font-style: italic; }}
</style>
</head>
<body>
<div class="container">
<h1>Penetration Test Report</h1>
<div class="meta">
    <p><strong>Session:</strong> {html_escape(str(results.get("session_id", "N/A")))} &nbsp;|&nbsp;
    <strong>Date:</strong> {html_escape(str(results.get("start_time", "N/A")))} &nbsp;|&nbsp;
    <strong>Targets:</strong> {html_escape(", ".join(results.get("targets", [])))}</p>
</div>
"""

        # ── Executive Summary ──
        html += "<h2>Executive Summary</h2>\n"
        if risk:
            html += f'<p>Overall Risk: <span class="risk-badge">{html_escape(str(risk.get("overall_risk", "N/A")))}</span>'
            html += f" &nbsp; Risk Score: <strong>{risk.get('risk_score', 0)}</strong></p>\n"
            narrative = risk.get("attack_narrative", "")
            if narrative:
                html += f"<blockquote>{html_escape(narrative)}</blockquote>\n"
            breakdown = risk.get("breakdown", {})
            html += '<div style="margin: 20px 0;">\n'
            for sev, label, color in [
                ("critical", "Critical", "#ff1744"),
                ("high", "High", "#ff6b6b"),
                ("medium", "Medium", "#ffd93d"),
                ("low", "Low", "#69f0ae"),
            ]:
                count = breakdown.get(sev, 0)
                html += f'<div class="stat"><div class="number" style="color:{color}">{count}</div>'
                html += f'<div class="label">{label}</div></div>\n'
            html += "</div>\n"

        # ── Stats row ──
        total_hosts = len(phases.get("scan", {}).get("hosts", []))
        total_ports = sum(len(h.get("ports", [])) for h in phases.get("scan", {}).get("hosts", []))
        vault_stats = vault_data.get("stats", {})
        html += '<div style="margin: 20px 0;">\n'
        for label, value in [
            ("Hosts", total_hosts),
            ("Open Ports", total_ports),
            ("Credentials", vault_stats.get("total", 0)),
            ("Admin Access", vault_stats.get("admin_access", 0)),
        ]:
            html += f'<div class="stat"><div class="number">{value}</div>'
            html += f'<div class="label">{label}</div></div>\n'
        html += "</div>\n"

        # ── Findings Table ──
        findings = scoring.get("findings", [])
        if findings:
            html += "<h2>Vulnerability Findings</h2>\n"
            html += "<table><tr><th>#</th><th>Severity</th><th>CVSS</th><th>Host</th><th>Title</th><th>Remediation</th></tr>\n"
            for i, f in enumerate(findings[:50], 1):
                sev = f.get("severity", "info")
                html += f'<tr class="finding-{html_escape(sev)}"><td>{i}</td><td><strong>{html_escape(sev.upper())}</strong></td>'
                html += f"<td>{f.get('cvss_score', 0):.1f}</td>"
                html += f"<td>{html_escape(str(f.get('host', '')))}:{html_escape(str(f.get('port', '')))}</td>"
                html += f"<td>{html_escape(str(f.get('title', '')))}</td>"
                html += f"<td>{html_escape(str(f.get('remediation', '')))}</td></tr>\n"
            html += "</table>\n"

        # ── Credential Vault ──
        creds = vault_data.get("credentials", [])
        if creds:
            html += "<h2>Credential Vault</h2>\n"
            html += "<table><tr><th>Username</th><th>Type</th><th>Host</th><th>Service</th><th>Verified</th><th>Admin</th></tr>\n"
            for c in creds[:30]:
                html += f"<tr><td>{html_escape(str(c.get('username', '')))}</td>"
                html += f"<td>{html_escape(str(c.get('cred_type', '')))}</td>"
                html += f"<td>{html_escape(str(c.get('host', '')))}</td>"
                html += f"<td>{html_escape(str(c.get('service', '')))}</td>"
                html += f"<td>{'✓' if c.get('verified') else ''}</td>"
                html += f"<td>{'✓' if c.get('admin_access') else ''}</td></tr>\n"
            html += "</table>\n"

        # ── Scan Results ──
        if "scan" in phases:
            html += "<h2>Network Scanning</h2>\n"
            for host in phases["scan"].get("hosts", []):
                ip = host.get("ip", "")
                hn = host.get("hostname", "")
                html += f"<h3>{html_escape(ip)} {f'({html_escape(hn)})' if hn else ''}</h3>\n"
                ports = host.get("ports", [])
                if ports:
                    html += "<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>\n"
                    for p in ports:
                        svc = p.get("service", {})
                        html += f"<tr><td>{html_escape(str(p.get('port', '')))}/{html_escape(str(p.get('protocol', '')))}</td>"
                        html += f"<td>{html_escape(str(p.get('state', '')))}</td>"
                        html += f"<td>{html_escape(str(svc.get('name', '')))}</td>"
                        html += f"<td>{html_escape(str(svc.get('product', '')))} {html_escape(str(svc.get('version', '')))}</td></tr>\n"
                    html += "</table>\n"

        # ── Screenshots ──
        screenshots = results.get("screenshots", {})
        if screenshots:
            html += "<h2>Evidence Screenshots</h2>\n"
            html += '<div style="display: flex; flex-wrap: wrap; gap: 15px;">\n'
            for url, path in screenshots.items():
                if url.startswith("_"):
                    continue
                if path.endswith((".png", ".jpg", ".jpeg")):
                    html += (
                        f'<div style="max-width:400px"><p><strong>{html_escape(url)}</strong></p>'
                    )
                    html += f'<img src="file://{html_escape(path)}" style="max-width:100%;border:1px solid #333;border-radius:4px;" />'
                    html += "</div>\n"
                else:
                    html += f"<p><strong>{html_escape(url)}</strong>: <code>{html_escape(path)}</code></p>\n"
            html += "</div>\n"

        html += """
<hr>
<p class="meta">Generated by Perfodia | FOR AUTHORIZED USE ONLY</p>
</div>
</body>
</html>
"""

        try:
            with open(out_path, "w") as f:
                f.write(html)
            logger.info(f"[+] HTML report: {out_path}")
        except Exception as e:
            logger.error(f"HTML report failed: {e}")

    def _generate_pdf(self, results: Dict):
        """
        Generate a PDF report from the HTML report using WeasyPrint.

        Falls back to wkhtmltopdf command-line tool if WeasyPrint is
        not installed.  If neither is available, logs a warning and skips.
        """
        html_path = self.session_dir / "report.html"
        pdf_path = self.session_dir / "report.pdf"

        if not html_path.exists():
            logger.warning("[PDF] HTML report not found — generate HTML first")
            return

        # Try WeasyPrint first (Python library)
        try:
            from weasyprint import HTML

            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"[+] PDF report (WeasyPrint): {pdf_path}")
            return
        except ImportError:
            logger.debug("[PDF] WeasyPrint not installed, trying wkhtmltopdf")
        except Exception as e:
            logger.warning(f"[PDF] WeasyPrint failed: {e}")

        # Try wkhtmltopdf (command-line tool)
        import shutil

        if shutil.which("wkhtmltopdf"):
            import subprocess

            try:
                subprocess.run(
                    [
                        "wkhtmltopdf",
                        "--quiet",
                        "--enable-local-file-access",
                        str(html_path),
                        str(pdf_path),
                    ],
                    timeout=60,
                    capture_output=True,
                    check=True,
                )
                if pdf_path.exists():
                    logger.info(f"[+] PDF report (wkhtmltopdf): {pdf_path}")
                    return
            except Exception as e:
                logger.warning(f"[PDF] wkhtmltopdf failed: {e}")

        # Try Chrome headless
        for chrome in ["chromium-browser", "google-chrome", "chromium"]:
            if shutil.which(chrome):
                import subprocess

                try:
                    subprocess.run(
                        [
                            chrome,
                            "--headless",
                            "--disable-gpu",
                            "--no-sandbox",
                            f"--print-to-pdf={pdf_path}",
                            str(html_path),
                        ],
                        timeout=60,
                        capture_output=True,
                        check=True,
                    )
                    if pdf_path.exists():
                        logger.info(f"[+] PDF report ({chrome}): {pdf_path}")
                        return
                except Exception as e:
                    logger.debug(f"[PDF] {chrome} failed: {e}")

        logger.warning(
            "[PDF] No PDF generator available. Install one of:\n"
            "  pip install weasyprint\n"
            "  apt install wkhtmltopdf\n"
            "  apt install chromium-browser"
        )
