"""Logging configuration for AP Scanner."""

import logging
import sys

# Stores the stderr handler's original level so it can be restored after scan.
_stderr_original_level: int = logging.INFO


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configure logging for ap_scanner.

    Logs go to stderr (not stdout, which is reserved for the ANSI display).
    When a log_file is specified, DEBUG-level output is always written there.
    """
    global _stderr_original_level
    level = logging.DEBUG if verbose else logging.INFO
    _stderr_original_level = level
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger("ap_scanner")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    # stderr handler — WARNING+ during scan to avoid ANSI display corruption
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
    root.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(fmt, datefmt=datefmt))
        root.addHandler(file_handler)


def suppress_stderr_during_scan() -> None:
    """Raise stderr handler level to avoid corrupting the ANSI display."""
    root = logging.getLogger("ap_scanner")
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr:
            h.setLevel(logging.CRITICAL)


def restore_stderr_after_scan() -> None:
    """Restore stderr handler to its original level."""
    root = logging.getLogger("ap_scanner")
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr:
            h.setLevel(_stderr_original_level)
