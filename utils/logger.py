"""
Logging configuration with optional colored terminal output,
session-based file logging, dedicated error log, and error summary.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from collections import Counter
from typing import Dict


# ── Global error counter (captures all WARNING+ across the session) ──

class _ErrorCounter(logging.Handler):
    """Silent handler that only counts records by level."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.counts: Counter = Counter()

    def emit(self, record):
        self.counts[record.levelname] += 1


_error_counter = _ErrorCounter()


class ColorFormatter(logging.Formatter):
    """Custom formatter with ANSI color codes for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",       # Cyan
        "INFO": "\033[32m",        # Green
        "WARNING": "\033[33m",     # Yellow
        "ERROR": "\033[31m",       # Red
        "CRITICAL": "\033[1;31m",  # Bold Red
    }
    RESET = "\033[0m"

    def __init__(self, fmt=None, datefmt=None, use_color=True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record):
        if self.use_color and record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
            )
        return super().format(record)


def setup_logging(level=logging.INFO, log_dir=None, no_color=False):
    """
    Configure console logging for the framework.

    This sets up the root logger with a console handler and the global
    error counter.  Call ``add_session_file_logging()`` once the session
    directory exists to bolt on two file handlers (all.log + errors.log).

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_dir: *Deprecated* — use ``add_session_file_logging`` instead.
                 If provided, behaves as before for backward compat.
        no_color: Disable colored terminal output
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # Always capture everything; handlers filter
    root.handlers.clear()

    # Console handler (respects user-chosen verbosity)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%H:%M:%S"

    if sys.stdout.isatty() and not no_color:
        console.setFormatter(ColorFormatter(fmt, datefmt, use_color=True))
    else:
        console.setFormatter(logging.Formatter(fmt, datefmt))

    root.addHandler(console)

    # Global error counter
    root.addHandler(_error_counter)

    # Legacy log_dir support (kept for backward compat)
    if log_dir:
        add_session_file_logging(Path(log_dir))


def add_session_file_logging(log_dir: Path):
    """
    Add two file handlers to the root logger:

    1. **all.log** — every message at DEBUG and above, so you can
       reconstruct exactly what happened during the session.
    2. **errors.log** — only WARNING, ERROR, and CRITICAL, giving
       you a quick-scan summary of everything that went wrong.

    Call this once the session directory is known.  Safe to call more
    than once (duplicate calls are a no-op).

    Args:
        log_dir: Directory to write log files into (created if absent).
    """
    root = logging.getLogger()

    # Guard against duplicate file handlers
    for h in root.handlers:
        if isinstance(h, logging.FileHandler):
            if str(log_dir) in str(getattr(h, "baseFilename", "")):
                return

    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    detailed_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s:%(lineno)d — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # all.log — everything
    all_handler = logging.FileHandler(log_dir / "all.log", mode="a")
    all_handler.setLevel(logging.DEBUG)
    all_handler.setFormatter(detailed_fmt)
    root.addHandler(all_handler)

    # errors.log — WARNING and above only
    err_handler = logging.FileHandler(log_dir / "errors.log", mode="a")
    err_handler.setLevel(logging.WARNING)
    err_handler.setFormatter(detailed_fmt)
    root.addHandler(err_handler)


def get_error_summary() -> Dict[str, int]:
    """
    Return a mapping of log level names to the number of messages
    recorded at that level during this process.

    Example return: ``{"WARNING": 12, "ERROR": 3, "CRITICAL": 0}``
    """
    return dict(_error_counter.counts)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)
