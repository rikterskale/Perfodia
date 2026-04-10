"""
Reconnaissance module — passive and active information gathering.
Uses: dig, whois, dnsrecon, whatweb
"""

import logging
import re
from typing import Dict, Any
from modules.base import BaseModule
from utils.validators import is_tool_available

logger = logging.getLogger(__name__)


class ReconModule(BaseModule):
    MODULE_NAME = "recon"

    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Execute reconnaissance workflow:
            1. DNS resolution and record enumeration
            2. WHOIS lookups
            3. Reverse DNS on discovered IPs
            4. Web technology fingerprinting (if HTTP detected)
        """
        self.log_phase_start("Reconnaissance")
        results: Dict[str, Any] = {"status": "running"}

        for target in self.targets:
            target_results: Dict[str, Any] = {}

            # ── DNS Enumeration ──
            self.log_phase_start(f"DNS enumeration for {target}")
            target_results["dns"] = self._dns_enum(target)

            # ── WHOIS ──
            self.log_phase_start(f"WHOIS lookup for {target}")
            target_results["whois"] = self._whois_lookup(target)

            # ── Reverse DNS ──
            self.log_phase_start(f"Reverse DNS for {target}")
            target_results["reverse_dns"] = self._reverse_dns(target)

            # ── Web fingerprinting ──
            if is_tool_available("whatweb"):
                self.log_phase_start(f"Web fingerprinting for {target}")
                target_results["web_fingerprint"] = self._web_fingerprint(target)

            # ── DNS zone transfer attempt ──
            self.log_phase_start(f"DNS zone transfer check for {target}")
            target_results["zone_transfer"] = self._zone_transfer(target)

            results[target] = target_results

        results["status"] = "completed"
        self.log_phase_end("Reconnaissance")
        return results

    def _dns_enum(self, target: str) -> Dict:
        """Perform DNS record enumeration using dig."""
        dns_results: Dict[str, Any] = {"records": {}}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]

        for rtype in record_types:
            result = self.runner.run(
                tool_name="dig",
                args=[target, rtype, "+short", "+time=5", "+tries=2"],
                timeout=15,
                output_file=f"recon/dns_{target}_{rtype}.txt",
                retries=1,
            )
            if result.success and result.stdout.strip():
                records = [
                    line.strip()
                    for line in result.stdout.strip().split("\n")
                    if line.strip()
                ]
                if records:
                    dns_results["records"][rtype] = records
                    logger.info(f"  {rtype}: {', '.join(records[:5])}")

        # Full dig output for reference
        full_result = self.runner.run(
            tool_name="dig",
            args=[target, "ANY", "+noall", "+answer"],
            timeout=15,
            output_file=f"recon/dns_{target}_full.txt",
        )
        if full_result.success:
            dns_results["raw"] = full_result.stdout

        # dnsrecon if available
        if is_tool_available("dnsrecon"):
            dr_result = self.runner.run(
                tool_name="dnsrecon",
                args=["-d", target, "-t", "std"],
                timeout=60,
                output_file=f"recon/dnsrecon_{target}.txt",
            )
            if dr_result.success:
                dns_results["dnsrecon"] = dr_result.stdout

        return dns_results

    def _whois_lookup(self, target: str) -> Dict:
        """Perform WHOIS lookup."""
        result = self.runner.run(
            tool_name="whois",
            args=[target],
            timeout=30,
            output_file=f"recon/whois_{target}.txt",
            retries=1,
        )

        whois_data: Dict[str, Any] = {"raw": ""}

        if result.success and result.stdout:
            whois_data["raw"] = result.stdout

            # Extract key fields
            patterns = {
                "registrar": r"Registrar:\s*(.+)",
                "creation_date": r"Creation Date:\s*(.+)",
                "expiry_date": r"Expir\w+ Date:\s*(.+)",
                "name_servers": r"Name Server:\s*(.+)",
                "org": r"Org(?:anization)?:\s*(.+)",
                "netrange": r"NetRange:\s*(.+)",
                "cidr": r"CIDR:\s*(.+)",
            }
            for key, pattern in patterns.items():
                matches = re.findall(pattern, result.stdout, re.IGNORECASE)
                if matches:
                    whois_data[key] = (
                        matches if len(matches) > 1 else matches[0].strip()
                    )

        return whois_data

    def _reverse_dns(self, target: str) -> Dict:
        """Perform reverse DNS lookup."""
        result = self.runner.run(
            tool_name="dig",
            args=["-x", target, "+short"],
            timeout=15,
            retries=1,
        )

        if result.success and result.stdout.strip():
            return {"ptr_records": result.stdout.strip().split("\n")}
        return {"ptr_records": []}

    def _web_fingerprint(self, target: str) -> Dict:
        """Fingerprint web technologies using whatweb."""
        web_results: Dict[str, Any] = {}

        for scheme in ["http", "https"]:
            result = self.runner.run(
                tool_name="whatweb",
                args=[
                    f"{scheme}://{target}",
                    "--color=never",
                    "-a",
                    "3",  # Aggression level
                    "--log-json",
                    str(self.session_dir / f"recon/whatweb_{target}_{scheme}.json"),
                ],
                timeout=60,
                retries=0,
            )
            if result.success and result.stdout:
                web_results[scheme] = result.stdout

        return web_results

    def _zone_transfer(self, target: str) -> Dict:
        """Attempt DNS zone transfer."""
        # First get NS records
        ns_result = self.runner.run(
            tool_name="dig",
            args=[target, "NS", "+short"],
            timeout=15,
        )

        zt_results: Dict[str, Any] = {"attempted": False, "vulnerable": False}

        if ns_result.success and ns_result.stdout.strip():
            nameservers = [
                ns.strip().rstrip(".")
                for ns in ns_result.stdout.strip().split("\n")
                if ns.strip()
            ]

            zt_results["attempted"] = True
            zt_results["nameservers_tested"] = nameservers

            for ns in nameservers:
                axfr = self.runner.run(
                    tool_name="dig",
                    args=["@" + ns, target, "AXFR", "+time=5"],
                    timeout=15,
                    output_file=f"recon/zone_transfer_{target}_{ns}.txt",
                    retries=0,
                )
                if axfr.success and "XFR size" in axfr.stdout:
                    zt_results["vulnerable"] = True
                    zt_results[f"transfer_{ns}"] = axfr.stdout
                    logger.warning(f"  [!] Zone transfer successful from {ns}!")

        return zt_results
