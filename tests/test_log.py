"""Tests for ap_scanner.log — logging level save/restore."""

import logging
import sys

from ap_scanner.log import (
    restore_stderr_after_scan,
    setup_logging,
    suppress_stderr_during_scan,
)


def _get_stderr_handler_level() -> int | None:
    """Return the level of the stderr handler on the ap_scanner logger."""
    root = logging.getLogger("ap_scanner")
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler) and h.stream is sys.stderr:
            return h.level
    return None


def test_restore_level_info():
    """After setup(verbose=False), restore returns to INFO (not DEBUG)."""
    setup_logging(verbose=False, log_file=None)
    assert _get_stderr_handler_level() == logging.INFO

    suppress_stderr_during_scan()
    assert _get_stderr_handler_level() == logging.CRITICAL

    restore_stderr_after_scan()
    assert _get_stderr_handler_level() == logging.INFO


def test_restore_level_debug():
    """After setup(verbose=True), restore returns to DEBUG."""
    setup_logging(verbose=True, log_file=None)
    assert _get_stderr_handler_level() == logging.DEBUG

    suppress_stderr_during_scan()
    assert _get_stderr_handler_level() == logging.CRITICAL

    restore_stderr_after_scan()
    assert _get_stderr_handler_level() == logging.DEBUG
