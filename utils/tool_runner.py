"""
Tool runner — handles subprocess execution of external security tools
with verbose error checking, timeout management, retry logic, and
structured output capture.
"""

import subprocess
import shutil
import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

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
    error_category: Optional[str] = None   # timeout, permission, not_found, usage, runtime, os_error

    def to_dict(self) -> Dict:
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

    def __init__(self, config, session_dir: Path, dry_run: bool = False, verbose: int = 0,
                 scope_guard=None):
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
        env: Optional[Dict] = None,
        stdin_data: Optional[str] = None,
    ) -> ToolResult:
        """
        Execute an external tool with full error handling.

        Pre-execution pipeline:
            1. Sanitize all arguments (remove shell injection chars)
            2. Scope check (verify target IPs are in scope)
            3. Resolve tool binary path
            4. Execute with timeout and retry logic
        """
        timeout = timeout or self.default_timeout
        retries = retries if retries is not None else self.max_retries

        # ── Step 1: Sanitize arguments ──
        from utils.sanitizer import sanitize_args
        args = sanitize_args(args, tool_name=tool_name)

        # ── Step 2: Scope enforcement ──
        if self.scope_guard:
            if not self.scope_guard.check_tool_args(tool_name, args):
                msg = (
                    f"SCOPE VIOLATION: {tool_name} targets an out-of-scope IP. "
                    f"Execution blocked. Check scope configuration."
                )
                logger.error(f"[SCOPE] {msg}")
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

        # ── Step 3: Pre-flight checks ──
        tool_path = self._resolve_tool(tool_name)
        if tool_path is None:
            msg = (
                f"Tool '{tool_name}' not found in PATH. "
                f"Install it or update tool_paths in config."
            )
            logger.error(f"[PRE-FLIGHT FAIL] {msg}")
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

        # ── Dry run ──
        if self.dry_run:
            cmd_str = " ".join(full_cmd)
            logger.info(f"[DRY RUN] Would execute: {cmd_str}")
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

        # ── Execute with retry logic ──
        attempt = 0
        last_result = None

        while attempt <= retries:
            if attempt > 0:
                logger.warning(
                    f"[RETRY] {tool_name} attempt {attempt + 1}/{retries + 1} "
                    f"(waiting {self.retry_delay}s)"
                )
                time.sleep(self.retry_delay)

            last_result = self._execute(
                full_cmd, timeout, cwd, env, stdin_data
            )

            if last_result.success:
                break

            # Don't retry usage errors (wrong arguments) or permission errors
            if last_result.error_category in ("usage", "permission"):
                logger.error(
                    f"[NO RETRY] {tool_name} — {last_result.error_category} error, "
                    f"retrying won't help"
                )
                break

            # Don't retry not_found (binary gone)
            if last_result.error_category == "not_found":
                logger.error(
                    f"[NO RETRY] {tool_name} — binary not found"
                )
                break

            attempt += 1

        # ── Save output to file ──
        if output_file and last_result.stdout:
            try:
                out_path = self.session_dir / output_file
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, "w") as f:
                    f.write(last_result.stdout)
                last_result.output_files.append(str(out_path))
                logger.debug(f"Output saved to {out_path}")
            except PermissionError:
                logger.error(
                    f"Permission denied writing output file {output_file}. "
                    f"Check that the session directory is writable."
                )
            except OSError as e:
                logger.error(
                    f"Failed to save output file {output_file}: {e}. "
                    f"Possible disk full or path issue."
                )

        # ── Save stderr to file on failure ──
        if output_file and not last_result.success and last_result.stderr:
            try:
                err_path = self.session_dir / (output_file + ".stderr")
                err_path.parent.mkdir(parents=True, exist_ok=True)
                with open(err_path, "w") as f:
                    f.write(f"# Tool: {tool_name}\n")
                    f.write(f"# Command: {' '.join(last_result.command)}\n")
                    f.write(f"# Exit code: {last_result.return_code}\n")
                    f.write(f"# Category: {last_result.error_category}\n")
                    f.write("# ---\n")
                    f.write(last_result.stderr)
                last_result.output_files.append(str(err_path))
                logger.debug(f"Stderr saved to {err_path}")
            except Exception as e:
                logger.debug(f"Could not save stderr file: {e}")

        # ── Parse output ──
        if parse_func and last_result.success and last_result.stdout:
            try:
                last_result.parsed_data = parse_func(last_result.stdout)
            except Exception as e:
                logger.warning(f"Output parsing failed for {tool_name}: {e}")

        return last_result

    def _resolve_tool(self, tool_name: str) -> Optional[str]:
        """Resolve tool binary path."""
        # Check config overrides first
        configured = self.config.get_tool_path(tool_name)
        if configured != tool_name:
            if Path(configured).exists():
                return configured

        # Fall back to PATH lookup
        found = shutil.which(tool_name)
        if found:
            return found

        # Try common alternate locations
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
        env: Optional[Dict],
        stdin_data: Optional[str],
    ) -> ToolResult:
        """
        Core subprocess execution with comprehensive error handling.

        Error categories produced:
            runtime    — tool ran but returned non-zero exit code
            usage      — tool printed a usage/help message (bad arguments)
            timeout    — tool exceeded the configured timeout
            permission — OS denied execution (missing sudo, wrong perms)
            not_found  — binary disappeared between resolve and exec
            os_error   — any other OS-level failure (disk full, etc.)
        """
        cmd_str = " ".join(cmd)
        tool_name = Path(cmd[0]).name
        logger.info(f"[EXEC] {cmd_str}")

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

            # ── Determine error category for failures ──
            error_category = None
            error_message = None

            if not success:
                stderr_lower = (process.stderr or "").lower()
                if process.returncode in (1, 2) and ("usage" in stderr_lower or "help" in stderr_lower):
                    error_category = "usage"
                    error_message = (
                        f"{tool_name} rejected the arguments (exit code "
                        f"{process.returncode}).  Check that the flags you "
                        f"passed are valid for this tool version."
                    )
                elif "permission denied" in stderr_lower or "requires root" in stderr_lower:
                    error_category = "permission"
                    error_message = (
                        f"{tool_name} needs higher privileges.  Run the "
                        f"framework with sudo, or choose a scan type that "
                        f"does not require root (e.g. --nmap-scan-type sT)."
                    )
                else:
                    error_category = "runtime"
                    error_message = (
                        f"{tool_name} exited with code {process.returncode}."
                    )

            # ── Log results ──
            if success:
                logger.info(
                    f"[OK] {tool_name} completed in {duration:.1f}s "
                    f"({len(process.stdout)} bytes stdout)"
                )
            else:
                logger.error(
                    f"[FAIL] {tool_name} exited with code {process.returncode} "
                    f"in {duration:.1f}s  (category: {error_category})"
                )
                if error_message:
                    logger.error(f"  → {error_message}")

                # Log ALL stderr lines to the file logger (DEBUG level so
                # they always land in all.log), and the first 10 lines to
                # the console at WARNING.
                if process.stderr:
                    stderr_lines = process.stderr.strip().split("\n")
                    for i, line in enumerate(stderr_lines):
                        logger.debug(f"  stderr[{i}]: {line}")
                        if i < 10:
                            logger.warning(f"  stderr: {line}")
                    if len(stderr_lines) > 10:
                        logger.warning(
                            f"  ... ({len(stderr_lines) - 10} more stderr "
                            f"lines in all.log)"
                        )

                # Save full stderr to a dedicated file for post-mortem
                self._save_stderr(tool_name, process.stderr)

            # Verbose stdout
            if self.verbose >= 2 and process.stdout:
                for line in process.stdout.strip().split("\n")[:20]:
                    logger.debug(f"  stdout: {line}")

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
                f"{tool_name} timed out after {timeout}s.  Consider "
                f"increasing the timeout in config (general.timeout) or "
                f"reducing the scan scope (fewer ports, smaller CIDR)."
            )
            logger.error(f"[TIMEOUT] {msg}")
            # Capture any partial output
            partial_stdout = ""
            if hasattr(exc, "stdout") and exc.stdout:
                partial_stdout = exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace")
                logger.debug(f"  Partial stdout captured ({len(partial_stdout)} bytes)")
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
            msg = (
                f"Permission denied executing {tool_name}.  "
                f"Try running with sudo or check file permissions on "
                f"{cmd[0]}."
            )
            logger.error(f"[PERM] {msg}")
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
            msg = (
                f"Binary vanished between pre-flight check and execution: "
                f"{cmd[0]}.  This usually means a symlink is broken or "
                f"the tool was uninstalled mid-run."
            )
            logger.error(f"[NOT FOUND] {msg}")
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
            msg = (
                f"OS error executing {tool_name}: {e}.  "
                f"This may indicate a full disk, missing shared library, "
                f"or corrupted binary."
            )
            logger.error(f"[OS ERROR] {msg}")
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

    def _save_stderr(self, tool_name: str, stderr: str):
        """Save full stderr output to a dedicated file for post-mortem analysis."""
        if not stderr or not stderr.strip():
            return
        try:
            err_dir = self.session_dir / "logs" / "stderr"
            err_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime("%H%M%S")
            err_file = err_dir / f"{tool_name}_{ts}.stderr.log"
            with open(err_file, "w") as f:
                f.write(f"# Tool: {tool_name}\n")
                f.write(f"# Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# ---\n")
                f.write(stderr)
            logger.debug(f"  stderr saved to {err_file}")
        except Exception as e:
            logger.debug(f"  Could not save stderr file: {e}")
