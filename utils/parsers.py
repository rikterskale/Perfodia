"""
Parsers for tool output — extract structured data from raw tool output.
Supports nmap XML, grep-friendly nmap, enum4linux, SNMP, and generic formats.
"""

import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_path: str) -> Dict[str, Any]:
    """
    Parse nmap XML output into structured host/port data.

    Args:
        xml_path: Path to nmap XML output file

    Returns:
        Dictionary with hosts, ports, services, OS info, and scripts
    """
    try:
        import xml.etree.ElementTree as ET
    except ImportError:
        logger.error("xml.etree.ElementTree not available")
        return {}

    xml_file = Path(xml_path)
    if not xml_file.exists():
        logger.error(f"Nmap XML file not found: {xml_path}")
        return {}

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error(f"Failed to parse nmap XML: {e}")
        return {}

    results = {
        "scanner": root.get("scanner", "nmap"),
        "args": root.get("args", ""),
        "start_time": root.get("startstr", ""),
        "hosts": [],
    }

    for host_elem in root.findall(".//host"):
        host = _parse_nmap_host(host_elem)
        if host:
            results["hosts"].append(host)

    # Summary
    runstats = root.find(".//runstats/finished")
    if runstats is not None:
        results["elapsed"] = runstats.get("elapsed", "")
        results["summary"] = runstats.get("summary", "")

    hosts_stat = root.find(".//runstats/hosts")
    if hosts_stat is not None:
        results["hosts_up"] = int(hosts_stat.get("up", 0))
        results["hosts_down"] = int(hosts_stat.get("down", 0))
        results["hosts_total"] = int(hosts_stat.get("total", 0))

    logger.info(f"Parsed nmap XML: {len(results['hosts'])} hosts found")
    return results


def _parse_nmap_host(host_elem) -> Optional[Dict]:
    """Parse a single host element from nmap XML."""
    status = host_elem.find("status")
    if status is not None and status.get("state") != "up":
        return None

    host: Dict[str, Any] = {
        "ip": "",
        "hostname": "",
        "state": "up",
        "ports": [],
        "os_matches": [],
        "scripts": [],
    }

    # Address
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") == "ipv4":
            host["ip"] = addr.get("addr", "")
        elif addr.get("addrtype") == "mac":
            host["mac"] = addr.get("addr", "")
            host["mac_vendor"] = addr.get("vendor", "")

    # Hostname
    hostnames = host_elem.find("hostnames")
    if hostnames is not None:
        hn = hostnames.find("hostname")
        if hn is not None:
            host["hostname"] = hn.get("name", "")

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port = _parse_nmap_port(port_elem)
            if port:
                host["ports"].append(port)

    # OS detection
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for osmatch in os_elem.findall("osmatch"):
            host["os_matches"].append(
                {
                    "name": osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                }
            )

    # Host scripts
    hostscript = host_elem.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            host["scripts"].append(
                {
                    "id": script.get("id", ""),
                    "output": script.get("output", ""),
                }
            )

    return host


def _parse_nmap_port(port_elem) -> Optional[Dict]:
    """Parse a single port element from nmap XML."""
    state_elem = port_elem.find("state")
    if state_elem is None:
        return None

    port = {
        "port": int(port_elem.get("portid", 0)),
        "protocol": port_elem.get("protocol", "tcp"),
        "state": state_elem.get("state", ""),
        "reason": state_elem.get("reason", ""),
        "service": {},
        "scripts": [],
    }

    # Service detection
    svc = port_elem.find("service")
    if svc is not None:
        port["service"] = {
            "name": svc.get("name", ""),
            "product": svc.get("product", ""),
            "version": svc.get("version", ""),
            "extrainfo": svc.get("extrainfo", ""),
            "tunnel": svc.get("tunnel", ""),
            "method": svc.get("method", ""),
            "conf": svc.get("conf", ""),
        }

    # Port scripts (NSE)
    for script in port_elem.findall("script"):
        port["scripts"].append(
            {
                "id": script.get("id", ""),
                "output": script.get("output", ""),
            }
        )

    return port


def parse_nmap_gnmap(gnmap_path: str) -> List[Dict]:
    """
    Parse nmap grepable output format.

    Returns:
        List of dicts with host/port info
    """
    results = []
    gnmap_file = Path(gnmap_path)

    if not gnmap_file.exists():
        logger.error(f"Gnmap file not found: {gnmap_path}")
        return results

    try:
        with open(gnmap_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "Ports:" in line:
                    host_data = _parse_gnmap_line(line)
                    if host_data:
                        results.append(host_data)
    except Exception as e:
        logger.error(f"Error parsing gnmap: {e}")

    return results


def _parse_gnmap_line(line: str) -> Optional[Dict]:
    """Parse a single grepable nmap output line."""
    host_match = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
    if not host_match:
        return None

    ip = host_match.group(1)
    hostname = host_match.group(2)

    ports = []
    ports_section = re.search(r"Ports:\s+(.*?)(?:\t|$)", line)
    if ports_section:
        port_entries = ports_section.group(1).split(",")
        for entry in port_entries:
            entry = entry.strip()
            parts = entry.split("/")
            if len(parts) >= 5:
                ports.append(
                    {
                        "port": int(parts[0]) if parts[0].isdigit() else 0,
                        "state": parts[1],
                        "protocol": parts[2],
                        "service": parts[4],
                        "version": parts[6] if len(parts) > 6 else "",
                    }
                )

    return {"ip": ip, "hostname": hostname, "ports": ports}


def parse_enum4linux_output(output: str) -> Dict[str, Any]:
    """
    Parse enum4linux(-ng) output into structured data.

    Extracts users, shares, groups, password policy, and OS info.
    """
    result: Dict[str, Any] = {
        "users": [],
        "shares": [],
        "groups": [],
        "password_policy": {},
        "os_info": "",
        "domain_info": "",
    }

    # Users
    user_pattern = re.compile(r"user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]")
    for match in user_pattern.finditer(output):
        result["users"].append(
            {
                "username": match.group(1),
                "rid": match.group(2),
            }
        )

    # Shares
    share_pattern = re.compile(r"(\S+)\s+(?:Disk|IPC|Printer)\s+(.*)")
    for match in share_pattern.finditer(output):
        result["shares"].append(
            {
                "name": match.group(1),
                "comment": match.group(2).strip(),
            }
        )

    # Groups
    group_pattern = re.compile(r"group:\[([^\]]+)\]\s+rid:\[([^\]]+)\]")
    for match in group_pattern.finditer(output):
        result["groups"].append(
            {
                "name": match.group(1),
                "rid": match.group(2),
            }
        )

    # OS info
    os_match = re.search(r"OS:\s*(.+)", output)
    if os_match:
        result["os_info"] = os_match.group(1).strip()

    # Password policy
    lockout_match = re.search(r"Account Lockout Threshold:\s*(\S+)", output)
    if lockout_match:
        result["password_policy"]["lockout_threshold"] = lockout_match.group(1)
    min_len = re.search(r"Minimum password length:\s*(\S+)", output)
    if min_len:
        result["password_policy"]["min_length"] = min_len.group(1)

    logger.info(
        f"Parsed enum4linux: {len(result['users'])} users, "
        f"{len(result['shares'])} shares, {len(result['groups'])} groups"
    )
    return result


def parse_snmp_output(output: str) -> List[Dict]:
    """Parse snmpwalk output into key-value pairs."""
    results = []
    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("Timeout") or line.startswith("No Response"):
            continue
        match = re.match(r"(\S+)\s+=\s+(\S+):\s+(.*)", line)
        if match:
            results.append(
                {
                    "oid": match.group(1),
                    "type": match.group(2),
                    "value": match.group(3).strip('"'),
                }
            )
    return results


def parse_hydra_output(output: str) -> List[Dict]:
    """Parse hydra output for successful credentials."""
    creds = []
    pattern = re.compile(r"\[(\d+)\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)")
    for match in pattern.finditer(output):
        creds.append(
            {
                "port": match.group(1),
                "service": match.group(2),
                "host": match.group(3),
                "username": match.group(4),
                "password": match.group(5),
            }
        )
    return creds


def parse_searchsploit_json(output: str) -> List[Dict]:
    """Parse searchsploit JSON output."""
    try:
        data = json.loads(output)
        exploits = []
        for entry in data.get("RESULTS_EXPLOIT", []):
            exploits.append(
                {
                    "title": entry.get("Title", ""),
                    "path": entry.get("Path", ""),
                    "type": entry.get("Type", ""),
                    "platform": entry.get("Platform", ""),
                }
            )
        return exploits
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse searchsploit JSON: {e}")
        return []
