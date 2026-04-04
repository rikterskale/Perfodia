"""
Vulnerability Scorer — assigns severity ratings to findings using
CVSS data from a local database and heuristic rules.

Provides overall risk ratings for the executive summary.
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Severity levels aligned with CVSS v3 rating scale."""
    CRITICAL = "critical"   # CVSS 9.0-10.0
    HIGH = "high"           # CVSS 7.0-8.9
    MEDIUM = "medium"       # CVSS 4.0-6.9
    LOW = "low"             # CVSS 0.1-3.9
    INFO = "info"           # Informational (no direct risk)

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO

    @property
    def numeric(self) -> int:
        """Numeric weight for sorting (higher = worse)."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


@dataclass
class Finding:
    """A scored vulnerability finding."""
    title: str
    severity: Severity
    cvss_score: float = 0.0
    cve_ids: List[str] = field(default_factory=list)
    host: str = ""
    port: int = 0
    service: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    source_phase: str = ""
    source_tool: str = ""
    mitre_attack: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = {
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cve_ids": self.cve_ids,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "description": self.description,
            "evidence": self.evidence[:500],
            "remediation": self.remediation,
            "source_phase": self.source_phase,
            "source_tool": self.source_tool,
            "mitre_attack": self.mitre_attack,
        }
        return d


# ── Known vulnerability patterns scored by heuristic ──
# These catch common findings from nmap NSE and other tools when
# no CVE match is available.

_HEURISTIC_RULES = [
    # (pattern_in_output, severity, cvss, title, remediation)
    (r"ms17-010|eternalblue", Severity.CRITICAL, 9.8,
     "MS17-010 (EternalBlue) SMB Remote Code Execution",
     "Patch with MS17-010. Disable SMBv1."),
    (r"ms08-067", Severity.CRITICAL, 10.0,
     "MS08-067 Windows Server Service Remote Code Execution",
     "Apply MS08-067 patch. Isolate system."),
    (r"heartbleed|ssl-heartbleed", Severity.HIGH, 7.5,
     "OpenSSL Heartbleed Information Disclosure",
     "Update OpenSSL to 1.0.1g+ or 1.0.2+."),
    (r"shellshock|CVE-2014-6271", Severity.CRITICAL, 9.8,
     "Bash Shellshock Remote Code Execution",
     "Update bash to patched version."),
    (r"anonymous.*ftp|ftp.*anonymous", Severity.MEDIUM, 5.3,
     "Anonymous FTP Access Enabled",
     "Disable anonymous FTP access or restrict to read-only non-sensitive files."),
    (r"null.*session|anonymous.*smb", Severity.MEDIUM, 5.3,
     "SMB Null Session / Anonymous Access",
     "Disable null sessions. Restrict anonymous access in Group Policy."),
    (r"default.*credentials|default.*password", Severity.HIGH, 8.1,
     "Default Credentials In Use",
     "Change all default credentials immediately."),
    (r"ssl-cert.*expired", Severity.LOW, 3.1,
     "Expired SSL/TLS Certificate",
     "Renew the SSL certificate."),
    (r"ssl.*weak|sslv[23]|tlsv1\.0", Severity.MEDIUM, 5.9,
     "Weak SSL/TLS Protocol Version",
     "Disable SSLv2, SSLv3, TLS 1.0. Enforce TLS 1.2+."),
    (r"dns.*recursion|recursion.*enabled", Severity.MEDIUM, 5.0,
     "DNS Recursion Enabled (Potential Amplification)",
     "Disable DNS recursion for external-facing servers."),
    (r"snmp.*public|community.*public", Severity.MEDIUM, 5.3,
     "SNMP Default Community String",
     "Change SNMP community strings. Use SNMPv3 with authentication."),
    (r"smb-vuln-cve-2020-0796|smbghost", Severity.CRITICAL, 10.0,
     "SMBGhost (CVE-2020-0796) Remote Code Execution",
     "Apply KB4551762 patch."),
    (r"log4j|log4shell|CVE-2021-44228", Severity.CRITICAL, 10.0,
     "Log4Shell Remote Code Execution",
     "Update Log4j to 2.17.0+. Set log4j2.formatMsgNoLookups=true."),
    (r"bluekeep|CVE-2019-0708", Severity.CRITICAL, 9.8,
     "BlueKeep RDP Remote Code Execution",
     "Patch with KB4499175. Disable RDP if not needed. Enable NLA."),
]


class VulnScorer:
    """
    Scores and classifies vulnerabilities discovered during the pentest.

    Methods:
        score_nmap_scripts()  — processes NSE script output from scan results
        score_exploit_match() — scores searchsploit results
        score_credential()    — scores credential-based findings
        score_misconfiguration() — scores enumeration findings
        compute_risk_rating() — overall engagement risk level
        get_findings()        — all findings sorted by severity
    """

    def __init__(self):
        self._findings: List[Finding] = []

    def score_nmap_scripts(self, hosts: List[Dict]) -> List[Finding]:
        """
        Score NSE script results from nmap scan data.

        Checks script output against known vulnerability patterns.
        Extracts CVE IDs from script names and output text.
        """
        findings = []
        for host in hosts:
            ip = host.get("ip", "")
            # Port-level scripts
            for port in host.get("ports", []):
                for script in port.get("scripts", []):
                    sid = script.get("id", "")
                    output = script.get("output", "")
                    finding = self._match_heuristic(
                        text=f"{sid} {output}",
                        host=ip,
                        port=port.get("port", 0),
                        service=port.get("service", {}).get("name", ""),
                        source_tool="nmap",
                        source_phase="scan",
                    )
                    if finding:
                        # Extract CVE IDs from output
                        cves = re.findall(r'CVE-\d{4}-\d{4,}', output, re.IGNORECASE)
                        finding.cve_ids = list(set(cves))
                        finding.evidence = output[:500]
                        findings.append(finding)

            # Host-level scripts
            for script in host.get("scripts", []):
                finding = self._match_heuristic(
                    text=f"{script.get('id', '')} {script.get('output', '')}",
                    host=ip,
                    source_tool="nmap",
                    source_phase="scan",
                )
                if finding:
                    findings.append(finding)

        self._findings.extend(findings)
        return findings

    def score_exploit_match(
        self,
        exploits: List[Dict],
        severity: Severity = Severity.HIGH,
        cvss: float = 7.5,
    ) -> List[Finding]:
        """Score searchsploit exploit matches."""
        findings = []
        for exploit in exploits:
            title = exploit.get("title", "")
            cves = re.findall(r'CVE-\d{4}-\d{4,}', title, re.IGNORECASE)

            finding = Finding(
                title=f"Known Exploit: {title[:100]}",
                severity=severity,
                cvss_score=cvss,
                cve_ids=cves,
                host=exploit.get("host", ""),
                port=exploit.get("port", 0),
                service=exploit.get("query", ""),
                description=f"ExploitDB match: {title}",
                evidence=f"Path: {exploit.get('path', '')}",
                remediation="Update the affected software to the latest version.",
                source_phase="exploit",
                source_tool="searchsploit",
            )
            findings.append(finding)

        self._findings.extend(findings)
        return findings

    def score_credential(
        self,
        username: str,
        host: str,
        service: str,
        admin: bool = False,
    ) -> Finding:
        """Score a credential-based finding."""
        if admin:
            severity = Severity.CRITICAL
            cvss = 9.0
            title = f"Administrative credentials obtained for {service}"
        else:
            severity = Severity.HIGH
            cvss = 7.5
            title = f"Valid credentials discovered for {service}"

        finding = Finding(
            title=title,
            severity=severity,
            cvss_score=cvss,
            host=host,
            service=service,
            description=f"User '{username}' credentials discovered via brute-force or default password.",
            remediation="Enforce strong password policies. Implement multi-factor authentication. Monitor for brute-force attempts.",
            source_phase="exploit",
            source_tool="hydra",
            mitre_attack=["T1110 — Brute Force"],
        )
        self._findings.append(finding)
        return finding

    def score_misconfiguration(
        self,
        title: str,
        host: str,
        severity: Severity = Severity.MEDIUM,
        cvss: float = 5.0,
        description: str = "",
        remediation: str = "",
        source_phase: str = "enum",
        source_tool: str = "",
    ) -> Finding:
        """Score a misconfiguration finding from enumeration."""
        finding = Finding(
            title=title,
            severity=severity,
            cvss_score=cvss,
            host=host,
            description=description,
            remediation=remediation,
            source_phase=source_phase,
            source_tool=source_tool,
        )
        self._findings.append(finding)
        return finding

    def compute_risk_rating(self) -> Dict[str, Any]:
        """
        Compute the overall engagement risk rating based on all findings.

        Returns:
            Dictionary with overall_risk, risk_score, breakdown by severity,
            and attack_narrative (plain-English summary of the worst path).
        """
        counts = {s: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity] += 1

        # Risk score: weighted sum
        weights = {Severity.CRITICAL: 40, Severity.HIGH: 10,
                   Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}
        score = sum(counts[s] * weights[s] for s in Severity)

        # Overall rating
        if counts[Severity.CRITICAL] > 0 or score >= 100:
            overall = "CRITICAL"
        elif counts[Severity.HIGH] >= 3 or score >= 50:
            overall = "HIGH"
        elif counts[Severity.HIGH] > 0 or score >= 20:
            overall = "MEDIUM"
        elif counts[Severity.MEDIUM] > 0 or score >= 5:
            overall = "LOW"
        else:
            overall = "INFORMATIONAL"

        # Attack narrative — describe the worst-case path
        narrative = self._build_attack_narrative()

        return {
            "overall_risk": overall,
            "risk_score": score,
            "breakdown": {s.value: counts[s] for s in Severity},
            "total_findings": len(self._findings),
            "attack_narrative": narrative,
        }

    def get_findings(
        self, min_severity: Severity = Severity.INFO
    ) -> List[Finding]:
        """Return all findings sorted by severity (worst first)."""
        return sorted(
            [f for f in self._findings if f.severity.numeric >= min_severity.numeric],
            key=lambda f: (-f.severity.numeric, -f.cvss_score),
        )

    def get_findings_by_host(self) -> Dict[str, List[Finding]]:
        """Group findings by host."""
        by_host: Dict[str, List[Finding]] = {}
        for f in self._findings:
            key = f.host or "general"
            by_host.setdefault(key, []).append(f)
        return by_host

    def to_report_data(self) -> Dict[str, Any]:
        """Export all scoring data for report generation."""
        return {
            "risk_rating": self.compute_risk_rating(),
            "findings": [f.to_dict() for f in self.get_findings()],
            "findings_by_host": {
                host: [f.to_dict() for f in findings]
                for host, findings in self.get_findings_by_host().items()
            },
        }

    def _match_heuristic(
        self, text: str, host: str = "", port: int = 0,
        service: str = "", source_tool: str = "", source_phase: str = "",
    ) -> Optional[Finding]:
        """Match text against known vulnerability patterns."""
        text_lower = text.lower()
        for pattern, severity, cvss, title, remediation in _HEURISTIC_RULES:
            if re.search(pattern, text_lower):
                return Finding(
                    title=title,
                    severity=severity,
                    cvss_score=cvss,
                    host=host,
                    port=port,
                    service=service,
                    remediation=remediation,
                    source_phase=source_phase,
                    source_tool=source_tool,
                )
        return None

    def _build_attack_narrative(self) -> str:
        """Build a plain-English attack path narrative from findings."""
        critical = [f for f in self._findings if f.severity == Severity.CRITICAL]
        high = [f for f in self._findings if f.severity == Severity.HIGH]
        creds = [f for f in self._findings if "credential" in f.title.lower()]
        admin = [f for f in self._findings if f.mitre_attack or "admin" in f.title.lower()]

        parts = []
        if not self._findings:
            return "No significant vulnerabilities were identified during testing."

        if critical:
            parts.append(
                f"Testing identified {len(critical)} critical vulnerabilities "
                f"including: {critical[0].title}."
            )
        if creds:
            parts.append(
                f"Valid credentials were recovered for {len(creds)} service(s), "
                f"enabling authenticated access."
            )
        if admin:
            parts.append(
                "Administrative-level access was achievable, potentially "
                "allowing full control of affected systems."
            )
        if not parts:
            if high:
                parts.append(
                    f"{len(high)} high-severity findings were identified "
                    f"that warrant immediate attention."
                )
            else:
                parts.append(
                    "Findings were limited to medium and low severity issues. "
                    "No critical attack paths were identified."
                )

        return " ".join(parts)
