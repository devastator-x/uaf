"""Entry point: python -m ap_scanner"""

import logging
import os
import select
import signal
import sys
import termios
import threading
import time
import tty

from ap_scanner.cli import parse_args
from ap_scanner.config import apply_config_to_args, load_config
from ap_scanner.display import Display
from ap_scanner.exporter import save_csv, save_json
from ap_scanner.log import restore_stderr_after_scan, setup_logging, suppress_stderr_during_scan
from ap_scanner.monitor import MonitorMode
from ap_scanner.scanner import ScannerEngine
from ap_scanner.utils import (
    ALL_CHANNELS,
    CHANNELS_2G,
    CHANNELS_5G,
    CHANNELS_6G,
    check_ip,
    check_iw,
    check_root,
    find_wireless_interfaces,
    get_supported_channels,
    parse_channels_arg,
)

logger = logging.getLogger("ap_scanner.main")

# Key constants for escape sequence parsing
KEY_UP = "UP"
KEY_DOWN = "DOWN"
KEY_ENTER = "ENTER"
KEY_ESC = "ESC"


def _read_key(timeout: float = 1.0) -> str | None:
    """Read a single key or escape sequence from stdin.

    Uses os.read() on the raw fd to avoid Python buffered IO issues where
    sys.stdin.read(1) drains the entire escape sequence from the kernel buffer
    into Python's internal buffer, causing select() to miss the continuation bytes.

    Returns None on timeout.
    """
    fd = sys.stdin.fileno()

    try:
        readable, _, _ = select.select([fd], [], [], timeout)
    except InterruptedError:
        return None
    if not readable:
        return None

    # Read all available bytes at once — escape sequences (e.g. \x1b[A)
    # arrive as a single chunk in the kernel buffer
    data = os.read(fd, 32)
    if not data:
        return None

    if data[0] == 0x1B:  # ESC
        if len(data) >= 3 and data[1] == ord("["):
            if data[2] == ord("A"):
                return KEY_UP
            if data[2] == ord("B"):
                return KEY_DOWN
            return None  # unknown CSI sequence
        if len(data) == 1:
            return KEY_ESC
        return None
    if data[0] in (0x0D, 0x0A):  # \r, \n
        return KEY_ENTER
    if data[0] == 0x03:  # Ctrl+C
        return "\x03"
    return chr(data[0])


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    # Load config file and apply defaults (CLI args take precedence)
    config = load_config(args.config)
    apply_config_to_args(args, config)

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Check root
    if not check_root():
        logger.error("This tool requires root privileges.")
        logger.error("Run with: sudo python -m ap_scanner")
        return 1

    # Check required system tools
    if not check_iw():
        logger.error("'iw' command not found. Install with: sudo apt install iw")
        return 1
    if not check_ip():
        logger.error("'ip' command not found. Install with: sudo apt install iproute2")
        return 1

    # Resolve interface
    interface = args.interface
    if interface is None:
        interfaces = find_wireless_interfaces()
        if not interfaces:
            logger.error("No wireless interfaces found.")
            return 1
        interface = interfaces[0]
        logger.info("Auto-detected interface: %s", interface)

    # Resolve channels
    if args.channels:
        channels = parse_channels_arg(args.channels)
    elif args.band == "2.4":
        channels = CHANNELS_2G
    elif args.band == "5":
        channels = CHANNELS_5G
    elif args.band == "6":
        channels = CHANNELS_6G
    else:
        channels = ALL_CHANNELS

    if not channels:
        logger.error("No valid channels specified.")
        return 1

    # Filter to only channels the adapter hardware supports
    supported = get_supported_channels(interface)
    supported_set = set(supported)
    original_count = len(channels)
    channels = [ch for ch in channels if ch in supported_set]
    if not channels:
        logger.warning(
            "None of the requested channels are supported by %s. "
            "Using adapter's supported channels instead.", interface,
        )
        channels = supported
    elif len(channels) < original_count:
        logger.info(
            "Filtered to %d supported channels (adapter supports %d of %d requested)",
            len(channels), len(channels), original_count,
        )

    logger.info("Interface: %s", interface)
    logger.info("Channels: %d (%d-%d)", len(channels), channels[0], channels[-1])

    # Resolve dwell time
    dwell_time = args.dwell if args.dwell is not None else 0.5

    # Setup display
    display = Display(no_color=args.no_color)
    display.set_sort(args.sort)
    if args.band != "all":
        display.band_filter = args.band + "GHz"

    # Enable monitor mode
    monitor = MonitorMode(interface)
    try:
        monitor.enable()
    except RuntimeError as e:
        logger.error("%s", e)
        return 1

    # Create scanner engine
    engine = ScannerEngine(interface, channels, dwell_time=dwell_time)

    # Signal handler for clean shutdown — use threading.Event for thread safety
    shutdown_event = threading.Event()

    def signal_handler(signum, frame):
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start scanning
    engine.start()
    logger.info("Scanning started (Ctrl+C or 'q' to stop)")
    time.sleep(0.5)

    # Suppress stderr logging during interactive display
    suppress_stderr_during_scan()

    # Setup terminal for non-blocking key input
    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        _main_loop(engine, display, monitor, interface, args.write, shutdown_event)
    finally:
        # Print newline to separate from display before cleanup logs
        print()
        # Re-enable stderr logging for shutdown messages
        restore_stderr_after_scan()

        # Each cleanup step is individually protected so a failure in one
        # does not prevent the others from running.
        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        except Exception:
            logger.error("Failed to restore terminal settings")
        try:
            engine.stop()
        except Exception:
            logger.error("Failed to stop scanner engine")
        try:
            monitor.disable()
        except Exception:
            logger.error("Failed to restore interface to managed mode")

    return 0


def _main_loop(
    engine: ScannerEngine,
    display: Display,
    monitor: MonitorMode,
    interface: str,
    csv_path: str | None,
    shutdown_event: threading.Event,
) -> None:
    """Main display loop with 2-mode key dispatch (normal / selection)."""
    frozen_aps = None  # Snapshot of APs when entering selection mode

    while not shutdown_event.is_set():
        # In selection mode, use frozen snapshot; otherwise use live data
        if display._selection_mode and frozen_aps is not None:
            aps = frozen_aps
        else:
            aps = engine.access_points

        display.render(aps, interface, engine.current_channel)

        key = _read_key(timeout=1.0)
        if key is None:
            continue

        if display._selection_mode:
            sel_result = _handle_selection_key(
                key, display, engine, monitor, interface, shutdown_event, frozen_aps
            )
            if sel_result == "exit_selection":
                frozen_aps = None
        else:
            result = _handle_normal_key(key, display, engine, csv_path, shutdown_event)
            # If we just entered selection mode, freeze the AP list
            if result == "enter_selection":
                frozen_aps = engine.access_points
            elif result == "exit_selection":
                frozen_aps = None



def _handle_normal_key(
    key: str,
    display: Display,
    engine: ScannerEngine,
    csv_path: str | None,
    shutdown_event: threading.Event,
) -> str | None:
    """Handle keys in normal (non-selection) mode. Returns action taken."""
    if key == "q" or key == "\x03":
        shutdown_event.set()
    elif key == "w":
        try:
            filepath = save_csv(engine.access_points, csv_path)
            display.show_message(f"Saved to {filepath}")
        except (OSError, IOError) as e:
            display.show_message(f"Save failed: {e}")
        time.sleep(1)
    elif key == "j":
        try:
            filepath = save_json(engine.access_points)
            display.show_message(f"Saved JSON to {filepath}")
        except (OSError, IOError) as e:
            display.show_message(f"JSON save failed: {e}")
        time.sleep(1)
    elif key == "b":
        band = display.cycle_band()
        display.show_message(f"Band filter: {band}")
        time.sleep(0.5)
    elif key == "s":
        sort_field = display.cycle_sort()
        display.show_message(f"Sort by: {sort_field}")
        time.sleep(0.5)
    elif key == KEY_ENTER:
        sorted_aps = display.get_sorted_filtered(engine.access_points)
        if sorted_aps:
            display.enter_selection_mode()
            return "enter_selection"
    return None


def _handle_selection_key(
    key: str,
    display: Display,
    engine: ScannerEngine,
    monitor: MonitorMode,
    interface: str,
    shutdown_event: threading.Event,
    frozen_aps: dict | None,
) -> str | None:
    """Handle keys in AP selection mode. Returns action taken."""
    if key == KEY_ESC or key == "\x03":
        display.exit_selection_mode()
        return "exit_selection"
    elif key == KEY_UP:
        sorted_aps = display.get_sorted_filtered(frozen_aps or engine.access_points)
        display.move_selection(-1, len(sorted_aps))
    elif key == KEY_DOWN:
        sorted_aps = display.get_sorted_filtered(frozen_aps or engine.access_points)
        display.move_selection(1, len(sorted_aps))
    elif key == KEY_ENTER:
        sorted_aps = display.get_sorted_filtered(frozen_aps or engine.access_points)
        if sorted_aps and display._selected_index < len(sorted_aps):
            selected_ap = sorted_aps[display._selected_index]
            display.exit_selection_mode()
            if selected_ap.encryption == "OPN":
                _run_active_scan(selected_ap, engine, display, monitor, interface)
                return "exit_selection"
            else:
                display.show_message(
                    f"Active scan only available for open (OPN) APs — "
                    f"{selected_ap.display_ssid} uses {selected_ap.encryption}"
                )
                time.sleep(2)
                return "exit_selection"
    return None


def _run_active_scan(ap, engine, display, monitor, interface):
    """Orchestrate active scan: stop capture, switch to managed, scan, restore."""
    from ap_scanner.active_scanner import ActiveScanner

    display.set_status(f"Stopping capture for active scan on {ap.display_ssid}...")

    # 1. Stop packet capture + channel hopping
    engine.stop()

    # 2. Switch to managed mode (fast, no NM restart)
    display.set_status(f"Switching {interface} to managed mode...")
    try:
        monitor.temporarily_disable()
    except Exception as e:
        logger.error("Failed to switch to managed mode: %s", e)
        display.set_status("")
        engine.start()
        return

    try:
        # 3. Run active scan
        display.set_status(
            f"Active scanning {ap.display_ssid} ({ap.bssid}) — "
            f"scan/connect/DHCP/ARP/ports..."
        )
        scanner = ActiveScanner(interface)
        result = scanner.scan(ap)

        # 4. Store result on AP object
        ap.active_scan_result = result

        # 5. Show overlay with results
        _show_scan_overlay(display, result)

        # Wait for user to dismiss
        _read_key(timeout=300)
    finally:
        display.set_status("Restoring monitor mode...")
        # 6. Always restore monitor mode
        try:
            monitor.re_enable_monitor()
        except RuntimeError:
            logger.critical(
                "CRITICAL: Failed to restore monitor mode on %s. "
                "Run manually: sudo iw dev %s set type monitor",
                interface, interface,
            )
            display.set_status("CRITICAL: Monitor mode restore failed!")
            time.sleep(3)

        # 7. Restart capture
        display.set_status("")
        engine.start()


def _show_scan_overlay(display, result):
    """Build and render the active scan results overlay."""
    lines = []

    if result.error:
        lines.append(f"Error: {result.error}")
        lines.append("")

    if result.assigned_ip:
        lines.append(f"Assigned IP:  {result.assigned_ip}")
    if result.subnet_mask:
        lines.append(f"Subnet Mask:  {result.subnet_mask}")
    if result.gateway_ip:
        gw = result.gateway_ip
        if result.gateway_mac:
            gw += f" ({result.gateway_mac})"
        lines.append(f"Gateway:      {gw}")
    if result.dhcp_server:
        lines.append(f"DHCP Server:  {result.dhcp_server}")
    if result.dns_servers:
        lines.append(f"DNS Servers:  {', '.join(result.dns_servers)}")
    lines.append("")

    if result.gateway_open_ports:
        ports = ", ".join(str(p) for p in result.gateway_open_ports)
        lines.append(f"Gateway Ports: {ports}")
        lines.append("")

    if result.clients:
        lines.append(f"Connected Clients: {result.client_count}")
        for client in result.clients[:10]:
            vendor = f"  {client.vendor}" if client.vendor else ""
            lines.append(f"  {client.ip:<16s} {client.mac}{vendor}")
        if result.client_count > 10:
            lines.append(f"  ... +{result.client_count - 10} more")
        lines.append("")

    lines.append(f"Duration: {result.duration_secs}s")

    title = f"ACTIVE SCAN: {result.ssid} ({result.bssid})"
    display.render_overlay(lines, title)


if __name__ == "__main__":
    sys.exit(main())
