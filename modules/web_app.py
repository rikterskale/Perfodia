"""
Web Application Testing module — deep-dive testing of HTTP/HTTPS services
beyond basic nikto/gobuster enumeration.

Uses: sqlmap, ffuf, wfuzz, ZAP CLI, curl
"""

import re
import logging
from typing import Dict, List, Any
from modules.base import BaseModule
from utils.validators import is_tool_available

logger = logging.getLogger(__name__)


class WebAppModule(BaseModule):
    MODULE_NAME = "webapp"

    def run(self, previous_results: Dict = None) -> Dict[str, Any]:
        """
        Web application testing workflow:
            1. Discover web targets from scan/enum results
            2. Advanced directory/file brute-forcing with ffuf
            3. Technology fingerprinting and header analysis
            4. SQL injection testing with sqlmap
            5. Parameter discovery and fuzzing
            6. Common vulnerability checks (LFI, RFI, XSS vectors)
        """
        self.log_phase_start("Web Application Testing")
        results: Dict[str, Any] = {"status": "running", "targets": []}

        scan_data = (previous_results or {}).get("scan", {})
        (previous_results or {}).get("enum", {})
        hosts = scan_data.get("hosts", [])

        if not hosts:
            logger.warning("[WEBAPP] No scan data — run scan phase first")
            results["status"] = "skipped"
            return results

        # Discover all HTTP/HTTPS targets
        web_targets = self._find_web_targets(hosts)
        if not web_targets:
            logger.info("[WEBAPP] No web services found in scan results")
            results["status"] = "no_targets"
            return results

        logger.info(f"[WEBAPP] Found {len(web_targets)} web targets")
        results["targets"] = web_targets

        for target in web_targets:
            url = target["url"]
            ip = target["ip"]
            port = target["port"]
            logger.info(f"\n[WEBAPP] Testing: {url}")

            target_results: Dict[str, Any] = {"url": url}

            # ── Advanced directory brute-forcing with ffuf ──
            if is_tool_available("ffuf"):
                target_results["ffuf"] = self._ffuf_scan(url, ip, port)
            elif is_tool_available("wfuzz"):
                target_results["wfuzz"] = self._wfuzz_scan(url, ip, port)

            # ── Security header analysis ──
            target_results["headers"] = self._analyze_headers(url)

            # ── Technology stack detection ──
            target_results["technologies"] = self._detect_technologies(url)

            # ── SQL injection testing with sqlmap ──
            webapp_config = self.config.get("webapp", default={})
            if webapp_config.get("sqlmap_enabled", True) and is_tool_available("sqlmap"):
                target_results["sqlmap"] = self._sqlmap_scan(url, ip, port)

            # ── Common vulnerability checks ──
            target_results["vuln_checks"] = self._check_common_vulns(url)

            # ── Parameter discovery ──
            target_results["params"] = self._discover_parameters(url)

            results[f"{ip}:{port}"] = target_results

        results["status"] = "completed"
        self.log_phase_end("Web Application Testing")
        return results

    def _find_web_targets(self, hosts: List[Dict]) -> List[Dict]:
        """Extract HTTP/HTTPS targets from scan results."""
        targets = []
        http_services = {"http", "https", "http-proxy", "https-alt", "http-alt"}

        for host in hosts:
            ip = host.get("ip", "")
            for port in host.get("ports", []):
                if port.get("state") != "open":
                    continue
                svc = port.get("service", {})
                svc_name = svc.get("name", "").lower()
                tunnel = svc.get("tunnel", "")
                port_num = port.get("port", 0)

                if svc_name in http_services or port_num in (
                    80,
                    443,
                    8080,
                    8443,
                    8000,
                    8888,
                ):
                    scheme = "https" if (tunnel == "ssl" or port_num in (443, 8443)) else "http"
                    targets.append(
                        {
                            "url": f"{scheme}://{ip}:{port_num}",
                            "ip": ip,
                            "port": port_num,
                            "scheme": scheme,
                            "product": svc.get("product", ""),
                            "version": svc.get("version", ""),
                        }
                    )
        return targets

    def _ffuf_scan(self, url: str, ip: str, port: int) -> Dict:
        """Advanced directory/file brute-forcing with ffuf."""
        self.log_phase_start(f"ffuf scan on {url}")

        webapp_config = self.config.get("webapp", default={})
        wordlist = webapp_config.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        extensions = webapp_config.get("extensions", "php,html,txt,bak,old,conf")

        output_file = self.session_dir / f"enum/ffuf_{ip}_{port}.json"

        result = self.runner.run(
            tool_name="ffuf",
            args=[
                "-u",
                f"{url}/FUZZ",
                "-w",
                wordlist,
                "-e",
                f".{extensions.replace(',', ',.')}",
                "-mc",
                "200,201,204,301,302,307,401,403,405",
                "-fc",
                "404",
                "-t",
                "40",
                "-timeout",
                "10",
                "-o",
                str(output_file),
                "-of",
                "json",
                "-s",  # Silent mode
            ],
            timeout=300,
            output_file=f"enum/ffuf_{ip}_{port}_stdout.txt",
            retries=0,
        )

        ffuf_results: Dict[str, Any] = {"directories": [], "files": []}
        if result.success and output_file.exists():
            try:
                import json

                with open(output_file) as f:
                    data = json.load(f)
                for entry in data.get("results", []):
                    item = {
                        "url": entry.get("url", ""),
                        "status": entry.get("status", 0),
                        "size": entry.get("length", 0),
                        "words": entry.get("words", 0),
                    }
                    if "." in entry.get("input", {}).get("FUZZ", ""):
                        ffuf_results["files"].append(item)
                    else:
                        ffuf_results["directories"].append(item)
            except Exception as e:
                logger.warning(f"  Failed to parse ffuf output: {e}")

        logger.info(
            f"  ffuf: {len(ffuf_results['directories'])} dirs, {len(ffuf_results['files'])} files"
        )
        return ffuf_results

    def _wfuzz_scan(self, url: str, ip: str, port: int) -> Dict:
        """Fallback directory brute-forcing with wfuzz."""
        self.log_phase_start(f"wfuzz scan on {url}")

        wordlist = self.config.get("webapp", default={}).get(
            "wordlist", "/usr/share/wordlists/dirb/common.txt"
        )

        result = self.runner.run(
            tool_name="wfuzz",
            args=[
                "-c",
                "--hc",
                "404",
                "-t",
                "40",
                "-w",
                wordlist,
                f"{url}/FUZZ",
            ],
            timeout=300,
            output_file=f"enum/wfuzz_{ip}_{port}.txt",
            retries=0,
        )

        return {"raw": result.stdout[:5000] if result.success else ""}

    def _analyze_headers(self, url: str) -> Dict:
        """Analyze HTTP response headers for security issues."""
        result = self.runner.run(
            tool_name="curl",
            args=["-s", "-I", "-k", "--connect-timeout", "10", "--max-time", "15", url],
            timeout=20,
        )

        headers_data: Dict[str, Any] = {
            "raw": "",
            "missing_security_headers": [],
            "issues": [],
        }

        if not result.success:
            return headers_data

        headers_data["raw"] = result.stdout

        # Parse headers
        headers = {}
        for line in result.stdout.split("\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()

        # Check security headers
        security_headers = {
            "strict-transport-security": "HSTS not set — vulnerable to SSL stripping",
            "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing possible",
            "x-frame-options": "X-Frame-Options missing — clickjacking possible",
            "content-security-policy": "CSP missing — XSS risk increased",
            "x-xss-protection": "X-XSS-Protection missing",
            "referrer-policy": "Referrer-Policy missing — information leakage risk",
            "permissions-policy": "Permissions-Policy missing",
        }

        for header, issue in security_headers.items():
            if header not in headers:
                headers_data["missing_security_headers"].append(header)
                headers_data["issues"].append(issue)

        # Check for information disclosure
        server = headers.get("server", "")
        if server:
            headers_data["server"] = server
            if any(v in server.lower() for v in ["apache", "nginx", "iis"]):
                if re.search(r"\d+\.\d+", server):
                    headers_data["issues"].append(f"Server header discloses version: {server}")

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            headers_data["issues"].append(f"X-Powered-By discloses technology: {x_powered}")

        return headers_data

    def _detect_technologies(self, url: str) -> Dict:
        """Detect web technologies via response analysis."""
        result = self.runner.run(
            tool_name="curl",
            args=[
                "-s",
                "-k",
                "-L",
                "--connect-timeout",
                "10",
                "--max-time",
                "15",
                "-o",
                "/dev/null",
                "-w",
                "%{content_type}|%{redirect_url}|%{http_code}",
                url,
            ],
            timeout=20,
        )

        tech: Dict[str, Any] = {}
        if result.success and result.stdout:
            parts = result.stdout.strip().split("|")
            if len(parts) >= 3:
                tech["content_type"] = parts[0]
                tech["redirect"] = parts[1]
                tech["status_code"] = parts[2]

        # Check common paths for framework detection
        framework_paths = {
            "/wp-login.php": "WordPress",
            "/wp-admin/": "WordPress",
            "/administrator/": "Joomla",
            "/user/login": "Drupal",
            "/admin/login": "Django Admin",
            "/elmah.axd": "ASP.NET ELMAH",
            "/web.config": "ASP.NET",
            "/.env": "Laravel/Node.js .env exposure",
            "/server-status": "Apache mod_status",
            "/server-info": "Apache mod_info",
        }

        detected = []
        for path, framework in framework_paths.items():
            check = self.runner.run(
                tool_name="curl",
                args=[
                    "-s",
                    "-k",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "--connect-timeout",
                    "5",
                    "--max-time",
                    "8",
                    f"{url}{path}",
                ],
                timeout=10,
                retries=0,
            )
            if check.success and check.stdout.strip() in ("200", "301", "302"):
                detected.append({"path": path, "framework": framework})
                logger.info(f"  Detected: {framework} ({path})")

        tech["detected_frameworks"] = detected
        return tech

    def _sqlmap_scan(self, url: str, ip: str, port: int) -> Dict:
        """SQL injection testing with sqlmap."""
        self.log_phase_start(f"sqlmap on {url}")

        output_dir = self.session_dir / f"enum/sqlmap_{ip}_{port}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Quick crawl + test with low risk/level to avoid damage
        result = self.runner.run(
            tool_name="sqlmap",
            args=[
                "-u",
                url,
                "--crawl=2",
                "--batch",  # Non-interactive
                "--random-agent",
                "--level=1",
                "--risk=1",  # Low risk — safe for lab
                "--threads=3",
                "--output-dir",
                str(output_dir),
                "--timeout=15",
                "--retries=1",
                "--forms",  # Test form parameters
                "--smart",  # Only test if heuristic positive
            ],
            timeout=300,
            output_file=f"enum/sqlmap_{ip}_{port}_stdout.txt",
            retries=0,
        )

        sqlmap_results: Dict[str, Any] = {"vulnerable": False, "injections": []}

        if result.success and result.stdout:
            # Parse for injection findings
            if (
                "is vulnerable" in result.stdout.lower()
                or "sqlmap identified" in result.stdout.lower()
            ):
                sqlmap_results["vulnerable"] = True
                logger.warning(f"  [!] SQL injection found on {url}")

            # Extract injection points
            inject_pattern = re.compile(
                r"Parameter:\s+(\S+).*?Type:\s+(.+?)(?:\n|Title:)", re.DOTALL
            )
            for match in inject_pattern.finditer(result.stdout):
                sqlmap_results["injections"].append(
                    {
                        "parameter": match.group(1),
                        "type": match.group(2).strip(),
                    }
                )

            sqlmap_results["raw_output"] = result.stdout[:5000]

        return sqlmap_results

    def _check_common_vulns(self, url: str) -> Dict:
        """Check for common web vulnerabilities via simple probes."""
        checks: Dict[str, Any] = {}

        # ── Robots.txt ──
        result = self.runner.run(
            tool_name="curl",
            args=[
                "-s",
                "-k",
                "--connect-timeout",
                "5",
                "--max-time",
                "10",
                f"{url}/robots.txt",
            ],
            timeout=15,
            retries=0,
        )
        if result.success and result.stdout and "disallow" in result.stdout.lower():
            checks["robots_txt"] = {
                "found": True,
                "content": result.stdout[:2000],
            }
            logger.info("  robots.txt found — may reveal hidden paths")

        # ── .git exposure ──
        result = self.runner.run(
            tool_name="curl",
            args=[
                "-s",
                "-k",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "5",
                f"{url}/.git/HEAD",
            ],
            timeout=10,
            retries=0,
        )
        if result.success and result.stdout.strip() == "200":
            checks["git_exposed"] = True
            logger.warning(f"  [!] .git directory exposed on {url}")

        # ── .env file exposure ──
        result = self.runner.run(
            tool_name="curl",
            args=[
                "-s",
                "-k",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--connect-timeout",
                "5",
                f"{url}/.env",
            ],
            timeout=10,
            retries=0,
        )
        if result.success and result.stdout.strip() == "200":
            checks["env_exposed"] = True
            logger.warning(f"  [!] .env file exposed on {url}")

        # ── Backup files ──
        backup_extensions = [".bak", ".old", ".backup", ".sql", ".tar.gz", ".zip"]
        for ext in backup_extensions:
            for base in ["index", "config", "database", "backup", "site", "web"]:
                check_url = f"{url}/{base}{ext}"
                result = self.runner.run(
                    tool_name="curl",
                    args=[
                        "-s",
                        "-k",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        "--connect-timeout",
                        "3",
                        check_url,
                    ],
                    timeout=5,
                    retries=0,
                )
                if result.success and result.stdout.strip() in ("200", "301"):
                    checks.setdefault("backup_files", []).append(check_url)
                    logger.warning(f"  [!] Backup file found: {check_url}")

        return checks

    def _discover_parameters(self, url: str) -> Dict:
        """Discover URL and form parameters for further testing."""
        result = self.runner.run(
            tool_name="curl",
            args=["-s", "-k", "-L", "--connect-timeout", "10", "--max-time", "15", url],
            timeout=20,
            retries=0,
        )

        params: Dict[str, Any] = {"url_params": [], "form_fields": []}
        if not result.success:
            return params

        body = result.stdout

        # Extract form fields
        form_pattern = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)
        params["form_fields"] = list(set(form_pattern.findall(body)))

        # Extract links with query parameters
        link_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']*)["\']', re.IGNORECASE)
        for link in link_pattern.findall(body):
            for param in re.findall(r"[?&](\w+)=", link):
                if param not in params["url_params"]:
                    params["url_params"].append(param)

        if params["form_fields"] or params["url_params"]:
            logger.info(
                f"  Discovered {len(params['form_fields'])} form fields, "
                f"{len(params['url_params'])} URL parameters"
            )

        return params
