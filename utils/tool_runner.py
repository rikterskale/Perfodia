"""
Tool runner — handles subprocess execution of external security tools
with verbose error checking, timeout management, retry logic, and
structured output capture.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Structured result from a tool execution."""

    tool: str
    command: List[str]
    return_code: int
    stdout: str
    stderr: str
    duration: float
    success: bool
    output_files: List[str] = field(default_factory=list)
    parsed_data: Optional[Any] = None
    error_message: Optional[str] = None
    error_category: Optional[str] = None  # timeout, permission, not_found, usage, runtime, os_error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "command": " ".join(self.command),
            "return_code": self.return_code,
            "stdout_lines": self.stdout.count("\n") + 1 if self.stdout else 0,
            "stderr_lines": self.stderr.count("\n") + 1 if self.stderr else 0,
            "stderr_preview": self.stderr[:500] if self.stderr else "",
            "duration_seconds": round(self.duration, 2),
            "success": self.success,
            "output_files": self.output_files,
            "error_message": self.error_message,
            "error_category": self.error_category,
        }


class ToolRunner:
    """
    Manages execution of external penetration testing tools.

    Features:
        - Pre-flight checks (tool exists, correct permissions)
        - Configurable timeouts and retry logic
        - Real-time output streaming in verbose mode
        - Structured result capture
        - Dry-run support
    """

    def __init__(
        self,
        config,
        session_dir: Path,
        dry_run: bool = False,
        verbose: int = 0,
        scope_guard=None,
    ):
        self.config = config
        self.session_dir = session_dir
        self.dry_run = dry_run
        self.verbose = verbose
        self.scope_guard = scope_guard
        self.default_timeout = config.get("general", "timeout", default=300)
        self.max_retries = config.get("general", "max_retries", default=2)
        self.retry_delay = config.get("general", "retry_delay", default=5)

    def run(
        self,
        tool_name: str,
        args: List[str],
        timeout: Optional[int] = None,
        output_file: Optional[str] = None,
        parse_func=None,
        retries: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[str] = None,
    ) -> ToolResult:
        """Execute an external tool with full error handling."""
        timeout = timeout or self.default_timeout
        retries = retries if retries is not None else self.max_retries

        from utils.sanitizer import sanitize_args

        args = sanitize_args(args, tool_name=tool_name)

        if self.scope_guard and not self.scope_guard.check_tool_args(tool_name, args):
            msg = (
                f"SCOPE VIOLATION: {tool_name} targets an out-of-scope IP. "
                f"Execution blocked. Check scope configuration."
            )
            logger.error("[SCOPE] %s", msg)
            return ToolResult(
                tool=tool_name,
                command=[tool_name] + args,
                return_code=-1,
                stdout="",
                stderr=msg,
                duration=0,
                success=False,
                error_message=msg,
                error_category="scope_violation",
            )

        tool_path = self._resolve_tool(tool_name)
        if tool_path is None:
            msg = f"Tool '{tool_name}' not found in PATH. Install it or update tool_paths in config."
            logger.error("[PRE-FLIGHT FAIL] %s", msg)
            return ToolResult(
                tool=tool_name,
                command=[tool_name] + args,
                return_code=-1,
                stdout="",
                stderr=msg,
                duration=0,
                success=False,
                error_message=msg,
                error_category="not_found",
            )

        full_cmd = [tool_path] + args

        if self.dry_run:
            logger.info("[DRY RUN] Would execute: %s", self._redact_command_for_logging(full_cmd))
            return ToolResult(
                tool=tool_name,
                command=full_cmd,
                return_code=0,
                stdout="",
                stderr="",
                duration=0,
                success=True,
                error_message="dry_run",
            )

        attempt = 0
        last_result: Optional[ToolResult] = None

        while attempt <= retries:
            if attempt > 0:
                logger.warning(
                    "[RETRY] %s attempt %d/%d (waiting %ss)",
                    tool_name,
                    attempt + 1,
                    retries + 1,
                    self.retry_delay,
                )
                time.sleep(self.retry_delay)

            last_result = self._execute(full_cmd, timeout, cwd, env, stdin_data)
            if last_result.success:
                break

            if last_result.error_category in ("usage", "permission", "not_found"):
                logger.error(
                    "[NO RETRY] %s — %s error, retrying won't help",
                    tool_name,
                    last_result.error_category,
                )
                break
            attempt += 1

        assert last_result is not None

        if output_file and last_result.stdout:
            try:
                out_path = self.session_dir / output_file
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(last_result.stdout)
                last_result.output_files.append(str(out_path))
                logger.debug("Output saved to %s", out_path)
            except PermissionError:
                logger.error(
                    "Permission denied writing output file %s. Check session directory writable.",
                    output_file,
                )
            except OSError as e:
                logger.error("Failed to save output file %s: %s", output_file, e)

        if output_file and not last_result.success and last_result.stderr:
            try:
                err_path = self.session_dir / (output_file + ".stderr")
                err_path.parent.mkdir(parents=True, exist_ok=True)
                with open(err_path, "w", encoding="utf-8") as f:
                    f.write(f"# Tool: {tool_name}\n")
                    f.write(
                        f"# Command: {self._redact_command_for_logging(last_result.command)}\n"
                    )
                    f.write(f"# Exit code: {last_result.return_code}\n")
                    f.write(f"# Category: {last_result.error_category}\n")
                    f.write("# ---\n")
                    f.write(last_result.stderr)
                last_result.output_files.append(str(err_path))
                logger.debug("Stderr saved to %s", err_path)
            except Exception as e:
                logger.debug("Could not save stderr file: %s", e)

        if parse_func and last_result.success and last_result.stdout:
            try:
                last_result.parsed_data = parse_func(last_result.stdout)
            except Exception as e:
                logger.warning("Output parsing failed for %s: %s", tool_name, e)

        return last_result

    def _resolve_tool(self, tool_name: str) -> Optional[str]:
        configured = self.config.get_tool_path(tool_name)
        if configured != tool_name and Path(configured).exists():
            return configured

        from utils.validators import resolve_tool_binary

        found = resolve_tool_binary(tool_name)
        if found:
            return found

        alt_paths = [
            f"/usr/bin/{tool_name}",
            f"/usr/local/bin/{tool_name}",
            f"/usr/share/{tool_name}/{tool_name}",
            f"/opt/{tool_name}/{tool_name}",
        ]
        for alt in alt_paths:
            if Path(alt).exists():
                return alt
        return None

    def _execute(
        self,
        cmd: List[str],
        timeout: int,
        cwd: Optional[str],
        env: Optional[Dict[str, str]],
        stdin_data: Optional[str],
    ) -> ToolResult:
        cmd_str = self._redact_command_for_logging(cmd)
        tool_name = Path(cmd[0]).name
        logger.info("[EXEC] %s", cmd_str)

        start_time = time.time()

        try:
            import os as _os

            run_env = _os.environ.copy()
            if env:
                run_env.update(env)

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=run_env,
                input=stdin_data,
            )

            duration = time.time() - start_time
            success = process.returncode == 0

            error_category = None
            error_message = None
            if not success:
                stderr_lower = (process.stderr or "").lower()
                if process.returncode in (1, 2) and ("usage" in stderr_lower or "help" in stderr_lower):
                    error_category = "usage"
                    error_message = (
                        f"{tool_name} rejected the arguments (exit code {process.returncode}). "
                        "Check that the flags you passed are valid for this tool version."
                    )
                elif "permission denied" in stderr_lower or "requires root" in stderr_lower:
                    error_category = "permission"
                    error_message = (
                        f"{tool_name} needs higher privileges. Run with sudo, or choose options "
                        "that do not require root (e.g. --nmap-scan-type sT)."
                    )
                else:
                    error_category = "runtime"
                    error_message = f"{tool_name} exited with code {process.returncode}."

            if success:
                logger.info("[OK] %s completed in %.1fs (%d bytes stdout)", tool_name, duration, len(process.stdout))
            else:
                logger.error(
                    "[FAIL] %s exited with code %d in %.1fs (category: %s)",
                    tool_name,
                    process.returncode,
                    duration,
                    error_category,
                )
                if error_message:
                    logger.error("  → %s", error_message)

                if process.stderr:
                    stderr_lines = process.stderr.strip().split("\n")
                    for i, line in enumerate(stderr_lines):
                        logger.debug("  stderr[%d]: %s", i, line)
                        if i < 10:
                            logger.warning("  stderr: %s", line)
                    if len(stderr_lines) > 10:
                        logger.warning("  ... (%d more stderr lines in all.log)", len(stderr_lines) - 10)

                self._save_stderr(tool_name, process.stderr)

            if self.verbose >= 2 and process.stdout:
                for line in process.stdout.strip().split("\n")[:20]:
                    logger.debug("  stdout: %s", line)

            return ToolResult(
                tool=tool_name,
                command=cmd,
                return_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration=duration,
                success=success,
                error_message=error_message,
                error_category=error_category,
            )

        except subprocess.TimeoutExpired as exc:
            duration = time.time() - start_time
            msg = (
                f"{tool_name} timed out after {timeout}s. Consider increasing general.timeout "
                "or reducing scan scope."
            )
            logger.error("[TIMEOUT] %s", msg)
            partial_stdout = ""
            if getattr(exc, "stdout", None):
                partial_stdout = (
                    exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
                )
            return ToolResult(
                tool=tool_name,
                command=cmd,
                return_code=-1,
                stdout=partial_stdout,
                stderr=msg,
                duration=duration,
                success=False,
                error_message=msg,
                error_category="timeout",
            )

        except PermissionError:
            duration = time.time() - start_time
            msg = f"Permission denied executing {tool_name}. Try running with sudo or check file permissions."
            logger.error("[PERM] %s", msg)
            return ToolResult(
                tool=tool_name,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=msg,
                duration=duration,
                success=False,
                error_message=msg,
                error_category="permission",
            )

        except FileNotFoundError:
            duration = time.time() - start_time
            msg = f"Binary vanished between pre-flight check and execution: {cmd[0]}."
            logger.error("[NOT FOUND] %s", msg)
            return ToolResult(
                tool=tool_name,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=msg,
                duration=duration,
                success=False,
                error_message=msg,
                error_category="not_found",
            )

        except OSError as e:
            duration = time.time() - start_time
            msg = f"OS error executing {tool_name}: {e}."
            logger.error("[OS ERROR] %s", msg)
            return ToolResult(
                tool=tool_name,
                command=cmd,
                return_code=-1,
                stdout="",
                stderr=msg,
                duration=duration,
                success=False,
                error_message=msg,
                error_category="os_error",
            )

    def _save_stderr(self, tool_name: str, stderr: str) -> None:
        if not stderr or not stderr.strip():
            return
        try:
            err_dir = self.session_dir / "logs" / "stderr"
            err_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%H%M%S")
            err_file = err_dir / f"{tool_name}_{ts}.stderr.log"
            with open(err_file, "w", encoding="utf-8") as f:
                f.write(f"# Tool: {tool_name}\n")
                f.write(f"# Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# ---\n")
                f.write(stderr)
            logger.debug("  stderr saved to %s", err_file)
        except Exception as e:
            logger.debug("  Could not save stderr file: %s", e)

    @staticmethod
    def _redact_command_for_logging(cmd: List[str]) -> str:
        rendered = " ".join(cmd)
        rendered = re.sub(r"([^\s/:@]+/[^\s:]+):([^\s]+)", r"\1:***", rendered)
        rendered = re.sub(r"([^\s:@]+):([^\s@]+)@", r"\1:***@", rendered)
        rendered = re.sub(r"(://[^\s:@]+):([^\s@]+)@", r"\1:***@", rendered)
        rendered = re.sub(r"(\s(?:-p|--password|-w)\s+)(\S+)", r"\1***", rendered)
        rendered = re.sub(r"(\s(?:-H|--hash)\s+)(\S+)", r"\1***", rendered)
        return rendered
