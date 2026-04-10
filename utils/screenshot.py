"""
Evidence Screenshot — captures visual evidence of web services
discovered during scanning.

Supports multiple backends:
    1. gowitness (preferred — fast, Go-based, purpose-built)
    2. cutycapt (Qt-based, works headless)
    3. Selenium/Chrome headless (fallback)
    4. curl-based HTML snapshot (last resort)

Screenshots are saved to the session's evidence/ directory
and referenced in the final report.
"""

import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class ScreenshotCapture:
    """
    Captures screenshots of HTTP/HTTPS services for evidence.

    Usage:
        capture = ScreenshotCapture(session_dir, runner, config)
        results = capture.capture_all(web_targets)
        # results = {"http://192.168.1.1:80": "/path/to/screenshot.png", ...}
    """

    def __init__(self, session_dir: Path, runner, config):
        self.session_dir = session_dir
        self.runner = runner
        self.config = config
        self.evidence_dir = session_dir / "evidence" / "screenshots"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect the best available screenshot tool."""
        backends = [
            ("gowitness", "gowitness"),
            ("cutycapt", "cutycapt"),
            ("chromium", "chromium-browser"),
            ("chrome", "google-chrome"),
        ]
        for name, binary in backends:
            if shutil.which(binary):
                logger.info(f"[SCREENSHOT] Using backend: {name}")
                return name

        logger.warning(
            "[SCREENSHOT] No screenshot tool found. Install gowitness, "
            "cutycapt, or chromium-browser for visual evidence."
        )
        return "curl_fallback"

    def capture_all(
        self,
        web_targets: List[Dict],
        max_workers: int = 5,
        timeout: int = 30,
    ) -> Dict[str, str]:
        """
        Capture screenshots of all web targets.

        Args:
            web_targets: List of dicts with 'url', 'ip', 'port' keys
            max_workers: Parallel screenshot threads
            timeout:     Per-screenshot timeout in seconds

        Returns:
            Dict mapping URLs to screenshot file paths
        """
        if not web_targets:
            return {}

        logger.info(
            f"[SCREENSHOT] Capturing {len(web_targets)} web service screenshots"
        )

        # Use gowitness batch mode if available (much faster)
        if self._backend == "gowitness" and len(web_targets) > 1:
            return self._gowitness_batch(web_targets, timeout)

        # Individual captures for other backends
        results = {}
        workers = min(max_workers, len(web_targets))

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for target in web_targets:
                url = target.get("url", "")
                if not url:
                    continue
                future = executor.submit(self._capture_single, url, timeout)
                futures[future] = url

            for future in as_completed(futures):
                url = futures[future]
                try:
                    path = future.result(timeout=timeout + 10)
                    if path:
                        results[url] = path
                except Exception as e:
                    logger.warning(f"[SCREENSHOT] Failed for {url}: {e}")

        logger.info(
            f"[SCREENSHOT] Captured {len(results)}/{len(web_targets)} screenshots"
        )
        return results

    def _gowitness_batch(self, targets: List[Dict], timeout: int) -> Dict[str, str]:
        """Use gowitness to capture all URLs in batch mode."""
        # Write URLs to file
        url_file = self.evidence_dir / "urls.txt"
        urls = []
        for t in targets:
            url = t.get("url", "")
            if url:
                urls.append(url)
        url_file.write_text("\n".join(urls))

        result = self.runner.run(
            tool_name="gowitness",
            args=[
                "scan",
                "file",
                "-f",
                str(url_file),
                "--screenshot-path",
                str(self.evidence_dir),
                "--timeout",
                str(timeout),
                "--threads",
                "5",
                "--disable-logging",
            ],
            timeout=timeout * len(urls),
            retries=0,
        )

        # Map URLs to screenshot files
        results = {}
        if result.success:
            for png in self.evidence_dir.glob("*.png"):
                # gowitness names files by URL hash or domain
                results[png.stem] = str(png)

            # Also check gowitness database
            db_path = self.evidence_dir / "gowitness.sqlite3"
            if db_path.exists():
                results["_database"] = str(db_path)

        # Fallback: map by matching filenames to URLs
        for url in urls:
            safe_name = self._safe_filename(url)
            for ext in [".png", ".jpg", ".jpeg"]:
                candidate = self.evidence_dir / f"{safe_name}{ext}"
                if candidate.exists():
                    results[url] = str(candidate)

        return results

    def _capture_single(self, url: str, timeout: int) -> Optional[str]:
        """Capture a single URL screenshot using the detected backend."""
        safe_name = self._safe_filename(url)
        output_path = self.evidence_dir / f"{safe_name}.png"

        if self._backend == "gowitness":
            return self._capture_gowitness(url, output_path, timeout)
        elif self._backend == "cutycapt":
            return self._capture_cutycapt(url, output_path, timeout)
        elif self._backend in ("chromium", "chrome"):
            return self._capture_chrome(url, output_path, timeout)
        else:
            return self._capture_curl_fallback(url, output_path, timeout)

    def _capture_gowitness(self, url: str, output: Path, timeout: int) -> Optional[str]:
        """Screenshot using gowitness."""
        self.runner.run(
            tool_name="gowitness",
            args=[
                "scan",
                "single",
                "--url",
                url,
                "--screenshot-path",
                str(output.parent),
                "--timeout",
                str(timeout),
            ],
            timeout=timeout + 10,
            retries=0,
        )
        # Find the output file
        for f in output.parent.glob("*.png"):
            return str(f)
        return None

    def _capture_cutycapt(self, url: str, output: Path, timeout: int) -> Optional[str]:
        """Screenshot using CutyCapt."""
        self.runner.run(
            tool_name="cutycapt",
            args=[
                f"--url={url}",
                f"--out={output}",
                "--insecure",
                f"--max-wait={timeout * 1000}",
                "--min-width=1280",
                "--min-height=800",
            ],
            timeout=timeout + 10,
            retries=0,
        )
        return str(output) if output.exists() else None

    def _capture_chrome(self, url: str, output: Path, timeout: int) -> Optional[str]:
        """Screenshot using headless Chrome/Chromium."""
        chrome_bin = (
            "chromium-browser" if self._backend == "chromium" else "google-chrome"
        )
        self.runner.run(
            tool_name=chrome_bin,
            args=[
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                f"--screenshot={output}",
                "--window-size=1280,800",
                "--hide-scrollbars",
                "--ignore-certificate-errors",
                url,
            ],
            timeout=timeout + 10,
            retries=0,
        )
        return str(output) if output.exists() else None

    def _capture_curl_fallback(
        self, url: str, output: Path, timeout: int
    ) -> Optional[str]:
        """
        Fallback: save raw HTML with curl (no visual screenshot,
        but preserves the response for evidence).
        """
        html_output = output.with_suffix(".html")
        result = self.runner.run(
            tool_name="curl",
            args=[
                "-s",
                "-k",
                "--connect-timeout",
                "10",
                "--max-time",
                str(timeout),
                "-o",
                str(html_output),
                "-D",
                str(output.with_suffix(".headers")),
                url,
            ],
            timeout=timeout + 5,
            retries=0,
        )
        if result.success and html_output.exists():
            logger.info(
                f"[SCREENSHOT] Saved HTML snapshot for {url} "
                f"(no visual screenshot tool available)"
            )
            return str(html_output)
        return None

    @staticmethod
    def _safe_filename(url: str) -> str:
        """Convert a URL to a safe filename."""
        import re

        safe = re.sub(r"https?://", "", url)
        safe = re.sub(r"[^\w\-.]", "_", safe)
        return safe[:100]

    @staticmethod
    def extract_web_targets(scan_hosts: List[Dict]) -> List[Dict]:
        """
        Extract web service targets from scan results.

        Returns list of dicts with 'url', 'ip', 'port', 'scheme'.
        """
        targets = []
        http_services = {"http", "https", "http-proxy", "https-alt", "http-alt"}

        for host in scan_hosts:
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
                    scheme = (
                        "https"
                        if (tunnel == "ssl" or port_num in (443, 8443))
                        else "http"
                    )
                    url = f"{scheme}://{ip}:{port_num}"
                    targets.append(
                        {
                            "url": url,
                            "ip": ip,
                            "port": port_num,
                            "scheme": scheme,
                            "service": svc_name,
                        }
                    )

        return targets
