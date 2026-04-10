"""
Input Sanitizer — scrubs all tool arguments before subprocess execution
to prevent command injection via hostile service banners, filenames,
or user input.

Every argument passed to any external tool flows through sanitize_args()
in ToolRunner before the subprocess fires.
"""

import re
import logging
from typing import List

logger = logging.getLogger(__name__)

# Characters that could enable shell injection or argument confusion
_DANGEROUS_CHARS = set(";&|`$(){}!\\<>\n\r\x00")

# Patterns that look like command chaining
_INJECTION_PATTERNS = [
    re.compile(r";\s*\w"),  # ; command
    re.compile(r"\|\s*\w"),  # | command
    re.compile(r"&&\s*\w"),  # && command
    re.compile(r"\|\|\s*\w"),  # || command
    re.compile(r"\$\("),  # $(command)
    re.compile(r"`[^`]+`"),  # `command`
    re.compile(r"\$\{"),  # ${variable}
]


def sanitize_arg(arg: str, tool_name: str = "") -> str:
    """
    Sanitize a single tool argument by removing dangerous characters.

    Args:
        arg:       The raw argument string
        tool_name: Tool name for logging context

    Returns:
        Sanitized argument string
    """
    if not arg:
        return arg

    original = arg
    # Remove null bytes
    arg = arg.replace("\x00", "")
    # Remove newlines (can break argument parsing)
    arg = arg.replace("\n", " ").replace("\r", "")

    # Check for injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(arg):
            cleaned = pattern.sub("", arg)
            logger.warning(
                f"[SANITIZE] Injection pattern removed from {tool_name} arg: "
                f"'{original[:60]}' → '{cleaned[:60]}'"
            )
            arg = cleaned

    # Remove remaining dangerous characters (preserve dashes, slashes, colons
    # which are needed for tool arguments like -sS, /path, user:pass@host)
    dangerous_found = _DANGEROUS_CHARS & set(arg)
    if dangerous_found:
        for ch in dangerous_found:
            arg = arg.replace(ch, "")
        if arg != original:
            logger.warning(
                f"[SANITIZE] Dangerous chars {dangerous_found} removed from "
                f"{tool_name} arg: '{original[:60]}'"
            )

    return arg.strip()


def sanitize_args(args: List[str], tool_name: str = "") -> List[str]:
    """
    Sanitize a list of tool arguments.

    Args:
        args:      List of raw argument strings
        tool_name: Tool name for logging context

    Returns:
        List of sanitized argument strings (empty strings removed)
    """
    sanitized = []
    for arg in args:
        clean = sanitize_arg(arg, tool_name)
        if clean:  # Drop empty args after sanitization
            sanitized.append(clean)
    return sanitized


def is_safe_path(path: str) -> bool:
    """
    Check if a file path is safe (no directory traversal, no shell chars).
    """
    if not path:
        return False
    # Block path traversal
    if ".." in path:
        return False
    # Block shell chars in paths
    if _DANGEROUS_CHARS & set(path):
        return False
    return True


def sanitize_hostname(hostname: str) -> str:
    """Sanitize a hostname/IP extracted from scan results."""
    # Only allow alphanumeric, dots, dashes, colons (IPv6)
    return re.sub(r"[^a-zA-Z0-9.\-:]", "", hostname)
