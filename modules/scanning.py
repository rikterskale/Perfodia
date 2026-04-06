"""
Network scanning module — host discovery, port scanning, service
detection, OS fingerprinting, and vulnerability scanning.
Uses: nmap, masscan
"""

import logging
from typing import Dict, List, Any, Optional
from modules.base import BaseModule
from utils.validators import is_tool_available
from utils.parsers import parse_nmap_xml

logger = logging.getLogger(__name__)


class ScanningModule(BaseModule):
    MODULE_NAME = "scan"

    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Execute scanning workflow:
            1. Host discovery (ping sweep)
            2. Quick port scan (top ports or masscan)
            3. Detailed nmap scan on discovered ports
            4. Service version detection + OS fingerprinting
            5. NSE vulnerability scripts
        """
        self.log_phase_start("Network Scanning")
        results: Dict[str, Any] = {"status": "running", "hosts": []}
        all_hosts_data = []

        for target in self.targets:
            logger.info(f"\n[SCAN] Target: {target}")

            # ── Phase 1: Host Discovery ──
            live_hosts = self._host_discovery(target)
            if not live_hosts:
                logger.warning(f"  No live hosts found for {target}")
                continue
            logger.info(f"  Live hosts: {len(live_hosts)}")

            # ── Phase 2: Quick Port Scan ──
            # Use masscan if available for speed, otherwise nmap top ports
            if is_tool_available("masscan") and "/" in target:
                quick_ports = self._masscan_sweep(target)
            else:
                quick_ports = None  # Will do full nmap instead

            # ── Phase 3: Detailed Nmap Scan ──
            for host_ip in live_hosts:
                host_data = self._detailed_scan(host_ip, quick_ports)
                if host_data:
                    all_hosts_data.append(host_data)

            # ── Phase 4: Vulnerability Scan ──
            if not self.config.get("nmap", "extra_args") == "no-vuln":
                for host_data in all_hosts_data:
                    open_ports = [
                        str(p["port"])
                        for p in host_data.get("ports", [])
                        if p.get("state") == "open"
                    ]
                    if open_ports:
                        vuln_data = self._vuln_scan(
                            host_data["ip"], open_ports
                        )
                        if vuln_data:
                            # Merge vuln script results into port data
                            self._merge_vuln_results(host_data, vuln_data)

        results["hosts"] = all_hosts_data
        results["status"] = "completed"
        results["total_hosts"] = len(all_hosts_data)
        results["total_open_ports"] = sum(
            len([p for p in h.get("ports", []) if p.get("state") == "open"])
            for h in all_hosts_data
        )

        logger.info(
            f"\n[SCAN] Summary: {results['total_hosts']} hosts, "
            f"{results['total_open_ports']} open ports"
        )
        self.log_phase_end("Network Scanning")
        return results

    def _host_discovery(self, target: str) -> List[str]:
        """
        Discover live hosts using nmap ping sweep.

        Uses multiple discovery techniques:
            -sn (no port scan), -PE (ICMP echo), -PP (timestamp),
            -PS (TCP SYN), -PA (TCP ACK)
        """
        self.log_phase_start(f"Host discovery for {target}")

        result = self.runner.run(
            tool_name="nmap",
            args=[
                "-sn",               # No port scan
                "-PE", "-PP",        # ICMP echo + timestamp
                "-PS80,443,22,445",  # TCP SYN probes
                "-PA80,443",         # TCP ACK probes
                "--min-rate", "300",
                "-oG", str(self.session_dir / f"nmap/discovery_{target.replace('/', '_')}.gnmap"),
                target,
            ],
            timeout=120,
            output_file=f"nmap/discovery_{target.replace('/', '_')}.txt",
        )

        live_hosts = []
        if result.success and result.stdout:
            for line in result.stdout.split("\n"):
                if "Nmap scan report for" in line:
                    # Extract IP — handle "hostname (ip)" and bare IP
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    # Use scope_guard for exclusion check (supports CIDR ranges)
                    if self.scope_guard and not self.scope_guard.check(ip, tool_name="nmap", action="host_discovery"):
                        logger.debug(f"  Excluding {ip} (out of scope or excluded)")
                    elif ip in self.exclusions:
                        # Fallback string check when no scope_guard
                        logger.debug(f"  Excluding {ip}")
                    else:
                        live_hosts.append(ip)

        return live_hosts

    def _masscan_sweep(self, target: str) -> Optional[Dict[str, List[int]]]:
        """
        Quick port discovery with masscan (for large ranges).

        Returns:
            Dict mapping IPs to lists of open ports, or None on failure
        """
        self.log_phase_start(f"Masscan sweep on {target}")

        rate = self.config.get("masscan", "rate", default=1000)
        ports = self.config.get("masscan", "ports", default="1-65535")

        result = self.runner.run(
            tool_name="masscan",
            args=[
                target,
                "-p", ports,
                "--rate", str(rate),
                "--open-only",
                "-oG", str(self.session_dir / f"nmap/masscan_{target.replace('/', '_')}.gnmap"),
            ],
            timeout=600,
            output_file=f"nmap/masscan_{target.replace('/', '_')}.txt",
        )

        if not result.success:
            logger.warning("Masscan failed — falling back to nmap")
            return None

        host_ports: Dict[str, List[int]] = {}
        for line in result.stdout.split("\n"):
            if "open" in line.lower() and "tcp" in line.lower():
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "on":
                        ip = parts[i + 1] if i + 1 < len(parts) else None
                        port_str = parts[i - 2] if i >= 2 else None
                        if ip and port_str:
                            try:
                                port = int(port_str.split("/")[0])
                                host_ports.setdefault(ip, []).append(port)
                            except (ValueError, IndexError):
                                pass

        return host_ports if host_ports else None

    def _detailed_scan(
        self, host_ip: str, quick_ports: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Full nmap scan with service detection and OS fingerprinting.

        Honors user-supplied nmap options:
            --nmap-extra      → appended to the default flags
            --nmap-raw        → replaces the default flags entirely
            --nmap-scan-type  → overrides the scan type flag (e.g. -sS → -sT)
        """
        self.log_phase_start(f"Detailed scan on {host_ip}")

        timing = self.config.get("nmap", "timing_template", default=4)
        xml_path = str(self.session_dir / f"nmap/scan_{host_ip}.xml")
        nmap_path = str(self.session_dir / f"nmap/scan_{host_ip}.nmap")

        # Build port argument
        if quick_ports and host_ip in quick_ports:
            port_list = ",".join(str(p) for p in sorted(quick_ports[host_ip]))
            port_arg = ["-p", port_list]
        else:
            port_arg = ["-p", self.config.get("nmap", "default_ports", default="1-65535")]

        # ── Retrieve user nmap overrides ──
        user_opts = self.config.get("nmap_user_opts", default={})
        raw_flags = user_opts.get("raw")       # list or None
        extra_flags = user_opts.get("extra")   # list or None
        scan_type = user_opts.get("scan_type") # e.g. "-sT" or None

        if raw_flags is not None:
            # ── RAW mode: user replaces all default flags ──
            nmap_args = list(raw_flags) + [
                "-oX", xml_path,
                "-oN", nmap_path,
            ] + port_arg + [host_ip]

            logger.info(
                f"[NMAP RAW] Using user-supplied flags for {host_ip}: "
                f"{' '.join(raw_flags)}"
            )
        else:
            # ── Normal mode: framework defaults ──
            effective_scan_type = scan_type or "-sS"

            # Determine if OS detection is safe to include.
            # -O requires root and is incompatible with rootless scan types.
            rootless_scan_types = {"-sT"}
            include_os_detection = effective_scan_type not in rootless_scan_types

            nmap_args = [
                effective_scan_type,            # SYN scan (or user override)
                "-sV",                          # Service version detection
                "-sC",                          # Default scripts
            ]

            if include_os_detection:
                nmap_args.append("-O")          # OS detection (requires root)

            nmap_args.extend([
                f"-T{timing}",
                "--reason",
                "--open",                       # Only show open ports
                "--min-rate", "300",
                "--max-retries", str(self.config.get("nmap", "max_retries", default=2)),
                "--host-timeout", self.config.get("nmap", "host_timeout", default="5m"),
                "-oX", xml_path,
                "-oN", nmap_path,
            ] + port_arg + [host_ip])

            # Add any extra args from config file
            config_extra = self.config.get("nmap", "extra_args", default=[])
            if config_extra:
                nmap_args.extend(config_extra)

            # ── EXTRA mode: append user CLI flags ──
            if extra_flags:
                nmap_args.extend(extra_flags)
                logger.info(
                    f"[NMAP EXTRA] Appending user flags for {host_ip}: "
                    f"{' '.join(extra_flags)}"
                )

        # Log the full nmap command for transparency
        logger.info(f"[NMAP CMD] nmap {' '.join(nmap_args)}")

        result = self.runner.run(
            tool_name="nmap",
            args=nmap_args,
            timeout=600,
            output_file=f"nmap/scan_{host_ip}_stdout.txt",
        )

        if not result.success:
            logger.error(
                f"Nmap scan failed for {host_ip} "
                f"(exit code {result.return_code})"
            )
            if result.stderr:
                # Log first 5 stderr lines for quick diagnosis
                for line in result.stderr.strip().split("\n")[:5]:
                    logger.error(f"  nmap stderr: {line}")
            if result.return_code == 1 and "requires root" in (result.stderr or "").lower():
                logger.error(
                    "  HINT: This scan type requires root privileges. "
                    "Run with sudo or use --nmap-scan-type sT for a "
                    "non-privileged full-connect scan."
                )
            return None

        # Parse XML output
        try:
            parsed = parse_nmap_xml(xml_path)
        except Exception as e:
            logger.error(f"Failed to parse nmap XML for {host_ip}: {e}")
            return None

        if parsed and parsed.get("hosts"):
            return parsed["hosts"][0]

        logger.warning(
            f"Nmap produced no host data for {host_ip}. The host may "
            f"be down, firewalled, or the scan type returned no results."
        )
        return None

    def _vuln_scan(self, host_ip: str, ports: List[str]) -> Optional[Dict]:
        """
        Run nmap NSE vulnerability scripts against discovered services.

        Honors --nmap-scripts if the user provided a custom script list.
        """
        self.log_phase_start(f"Vulnerability scan on {host_ip}")

        port_str = ",".join(ports[:100])  # Cap ports to avoid timeouts
        xml_path = str(self.session_dir / f"nmap/vuln_{host_ip}.xml")

        # ── Script selection: user override → config → defaults ──
        user_opts = self.config.get("nmap_user_opts", default={})
        user_scripts = user_opts.get("scripts")  # from --nmap-scripts

        if user_scripts:
            script_str = user_scripts
            logger.info(f"[NMAP SCRIPTS] Using user-specified scripts: {script_str}")
        else:
            scripts = self.config.get("nmap", "scripts", default=["vuln", "safe"])
            script_str = ",".join(scripts)

        vuln_args = [
            "-sV",
            "--script", script_str,
            "-p", port_str,
            "-oX", xml_path,
            "--host-timeout", "10m",
            host_ip,
        ]

        # Append user extra flags to vuln scan too
        extra_flags = user_opts.get("extra")
        if extra_flags:
            vuln_args = vuln_args[:-1] + extra_flags + [host_ip]

        logger.info(f"[NMAP CMD] nmap {' '.join(vuln_args)}")

        result = self.runner.run(
            tool_name="nmap",
            args=vuln_args,
            timeout=900,
        )

        if result.success:
            try:
                return parse_nmap_xml(xml_path)
            except Exception as e:
                logger.error(f"Failed to parse vuln scan XML for {host_ip}: {e}")
                return None
        else:
            logger.error(
                f"Vulnerability scan failed for {host_ip} "
                f"(exit code {result.return_code})"
            )
            if result.stderr:
                for line in result.stderr.strip().split("\n")[:3]:
                    logger.error(f"  nmap vuln stderr: {line}")
            return None

    def _merge_vuln_results(self, host_data: Dict, vuln_data: Dict):
        """Merge vulnerability scan script results into host data."""
        vuln_hosts = vuln_data.get("hosts", [])
        if not vuln_hosts:
            return

        vuln_host = vuln_hosts[0]
        vuln_port_map = {
            p["port"]: p for p in vuln_host.get("ports", [])
        }

        for port in host_data.get("ports", []):
            vuln_port = vuln_port_map.get(port["port"])
            if vuln_port and vuln_port.get("scripts"):
                existing_ids = {s["id"] for s in port.get("scripts", [])}
                for script in vuln_port["scripts"]:
                    if script["id"] not in existing_ids:
                        port.setdefault("scripts", []).append(script)

        # Merge host-level scripts
        if vuln_host.get("scripts"):
            existing_ids = {s["id"] for s in host_data.get("scripts", [])}
            for script in vuln_host["scripts"]:
                if script["id"] not in existing_ids:
                    host_data.setdefault("scripts", []).append(script)
