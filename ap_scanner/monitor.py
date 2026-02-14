"""Monitor mode management for wireless interfaces."""

import atexit
import logging
import subprocess
import sys
import time

from ap_scanner.utils import get_interface_mode

logger = logging.getLogger("ap_scanner.monitor")


class MonitorMode:
    """Context manager for enabling/disabling monitor mode on a wireless interface.

    Usage:
        with MonitorMode("wlan0") as iface:
            # iface is in monitor mode
            ...
        # iface is restored to managed mode
    """

    def __init__(self, interface: str):
        self.interface = interface
        self._original_mode: str | None = None
        self._enabled = False
        self._cleanup_registered = False

    def enable(self) -> str:
        """Enable monitor mode on the interface. Returns the interface name."""
        self._original_mode = get_interface_mode(self.interface)

        if self._original_mode == "monitor":
            self._enabled = True
            self._register_cleanup()
            return self.interface

        # Bring interface down
        self._run_cmd(["ip", "link", "set", self.interface, "down"])

        # Set monitor mode
        self._run_cmd(["iw", "dev", self.interface, "set", "monitor", "none"])

        # Bring interface up
        self._run_cmd(["ip", "link", "set", self.interface, "up"])

        # Verify
        mode = get_interface_mode(self.interface)
        if mode != "monitor":
            # Try to restore
            self._restore_managed()
            raise RuntimeError(
                f"Failed to set monitor mode on {self.interface}. "
                f"Current mode: {mode}. "
                f"Ensure the adapter supports monitor mode and the correct driver is loaded."
            )

        self._enabled = True
        self._register_cleanup()
        logger.info("%s: monitor mode enabled", self.interface)
        return self.interface

    def disable(self) -> None:
        """Disable monitor mode and restore the interface to managed mode."""
        if not self._enabled:
            return

        self._restore_managed()
        self._enabled = False
        logger.info("%s: managed mode restored", self.interface)

    def _restore_managed(self) -> None:
        """Restore the interface to managed mode."""
        try:
            self._run_cmd(["ip", "link", "set", self.interface, "down"],
                          ignore_errors=True)
            self._run_cmd(["iw", "dev", self.interface, "set", "type", "managed"],
                          ignore_errors=True)
            self._run_cmd(["ip", "link", "set", self.interface, "up"],
                          ignore_errors=True)
        except Exception:
            pass

        # Restart NetworkManager to re-manage the interface
        self._restart_network_manager()

        # Verify restoration
        mode = get_interface_mode(self.interface)
        if mode and mode != "managed":
            print(
                f"[!] Warning: {self.interface} is in '{mode}' mode, expected 'managed'.\n"
                f"[!] Run manually: sudo iw dev {self.interface} set type managed",
                file=sys.stderr,
            )

    def _restart_network_manager(self) -> None:
        """Re-manage only this interface in NetworkManager (without full restart).

        Uses ``nmcli device set <iface> managed yes`` so that other
        interfaces (e.g. internal WiFi) are not disrupted.  Falls back to
        a full ``systemctl restart NetworkManager`` only if nmcli fails.
        """
        try:
            # Check if NM is running first
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "NetworkManager"],
                timeout=3,
            )
            if result.returncode != 0:
                return  # NM not running, nothing to do

            # Targeted: re-manage only the scanned interface
            result = subprocess.run(
                ["nmcli", "device", "set", self.interface, "managed", "yes"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return  # success — other interfaces untouched

            # Fallback: full restart (last resort)
            logger.debug("nmcli set managed failed, falling back to NM restart")
            subprocess.run(
                ["systemctl", "restart", "NetworkManager"],
                capture_output=True, timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def temporarily_disable(self) -> None:
        """Switch to managed mode for active scanning (skips NM restart for speed).

        Raises RuntimeError if the interface cannot be switched to managed mode.
        """
        if not self._enabled:
            return

        self._run_cmd(["ip", "link", "set", self.interface, "down"])
        self._run_cmd(["iw", "dev", self.interface, "set", "type", "managed"])
        self._run_cmd(["ip", "link", "set", self.interface, "up"])

        # Verify mode switch
        time.sleep(0.5)  # let the driver settle
        mode = get_interface_mode(self.interface)
        if mode != "managed":
            raise RuntimeError(
                f"Failed to switch {self.interface} to managed mode "
                f"(current: {mode})"
            )
        logger.info("%s: temporarily switched to managed mode", self.interface)

    def re_enable_monitor(self) -> None:
        """Re-enable monitor mode after active scanning."""
        try:
            self._run_cmd(["ip", "link", "set", self.interface, "down"])
            self._run_cmd(["iw", "dev", self.interface, "set", "monitor", "none"])
            self._run_cmd(["ip", "link", "set", self.interface, "up"])
        except RuntimeError as e:
            logger.critical("Failed to restore monitor mode: %s", e)
            raise

        mode = get_interface_mode(self.interface)
        if mode != "monitor":
            logger.critical(
                "%s is in '%s' mode after re_enable_monitor, expected 'monitor'",
                self.interface, mode,
            )
            raise RuntimeError(
                f"Failed to restore monitor mode on {self.interface}. "
                f"Current mode: {mode}"
            )
        logger.info("%s: monitor mode re-enabled", self.interface)

    def _register_cleanup(self) -> None:
        """Register atexit handler for emergency cleanup."""
        if not self._cleanup_registered:
            atexit.register(self._emergency_cleanup)
            self._cleanup_registered = True

    def _emergency_cleanup(self) -> None:
        """Best-effort cleanup on unexpected exit."""
        if self._enabled:
            try:
                self._restore_managed()
            except Exception:
                logger.error(
                    "Could not restore %s to managed mode. "
                    "Run manually: sudo iw dev %s set type managed",
                    self.interface, self.interface,
                )

    @staticmethod
    def _run_cmd(cmd: list[str], ignore_errors: bool = False) -> subprocess.CompletedProcess:
        """Run a subprocess command."""
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0 and not ignore_errors:
            raise RuntimeError(
                f"Command failed: {' '.join(cmd)}\n"
                f"stderr: {result.stderr.strip()}"
            )
        return result

    def __enter__(self) -> str:
        return self.enable()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disable()
