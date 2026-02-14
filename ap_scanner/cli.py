"""Command-line argument parsing."""

import argparse

from ap_scanner import __version__


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="uaf",
        description="UAF (Ultimate AP Finder) - wireless AP scanner for PCI-DSS auditing",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Wireless interface to use (default: auto-detect)",
    )
    parser.add_argument(
        "-c", "--channels",
        type=str,
        default=None,
        help="Channels to scan, e.g. '1,6,11' or '36-48' (default: all)",
    )
    parser.add_argument(
        "-b", "--band",
        type=str,
        choices=["2.4", "5", "6", "all"],
        default="all",
        help="Band filter: 2.4, 5, 6 (6GHz), or all (default: all)",
    )
    parser.add_argument(
        "-w", "--write",
        type=str,
        default=None,
        help="CSV output file path (auto-saves on exit)",
    )
    parser.add_argument(
        "--sort",
        type=str,
        choices=["rssi", "channel", "essid", "enc"],
        default="rssi",
        help="Sort by field (default: rssi)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable colored output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG level) logging",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Write log output to file",
    )
    parser.add_argument(
        "--dwell",
        type=float,
        default=None,
        help="Channel dwell time in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config file (default: ~/.config/ap-scanner/config.ini)",
    )
    return parser.parse_args(argv)
