"""Terminal display: real-time AP listing with ANSI escape sequences."""

import os
import sys
import unicodedata
from datetime import datetime, timedelta

from ap_scanner.models import AccessPoint


def _display_width(s: str) -> int:
    """Calculate terminal display width accounting for wide (CJK) characters."""
    width = 0
    for ch in s:
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def _truncate_to_width(s: str, max_width: int) -> str:
    """Truncate string to fit within max_width terminal cells, adding ellipsis if needed."""
    width = 0
    for i, ch in enumerate(s):
        eaw = unicodedata.east_asian_width(ch)
        char_width = 2 if eaw in ("W", "F") else 1
        if width + char_width > max_width:
            return s[:i] + "\u2026"
        width += char_width
    return s


def _pad_to_width(s: str, target_width: int) -> str:
    """Pad string with spaces to reach target terminal width."""
    current = _display_width(s)
    return s + " " * max(0, target_width - current)


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BG_BLUE = "\033[44m"
    REVERSE = "\033[7m"


class NoColors:
    """No-op colors for --no-color mode."""
    RESET = BOLD = DIM = ""
    RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    BG_BLUE = REVERSE = ""


class Display:
    """Renders AP scan results to the terminal in airodump-ng style."""

    SORT_KEYS = {
        "rssi": lambda ap: (ap.rssi if ap.rssi is not None else -999, ap.bssid),
        "channel": lambda ap: (ap.channel, ap.bssid),
        "essid": lambda ap: (ap.display_ssid.lower(), ap.bssid),
        "enc": lambda ap: (ap.encryption, ap.bssid),
    }

    SORT_REVERSE = {
        "rssi": True,  # strongest first (-42 > -80)
        "channel": False,
        "essid": False,
        "enc": False,
    }

    NEW_AP_HIGHLIGHT_SECS = 5

    def __init__(self, no_color: bool = False):
        self.c = NoColors if no_color else Colors
        self.sort_field = "rssi"
        self.band_filter: str | None = None  # None = all, "2.4GHz", "5GHz"
        self._start_time = datetime.now()
        self._first_render = True
        self._known_bssids: set[str] = set()
        self._new_bssids: dict[str, datetime] = {}  # bssid -> discovered time
        self._selected_index: int = 0
        self._selection_mode: bool = False
        self._status_message: str = ""

    def set_sort(self, field: str) -> None:
        if field in self.SORT_KEYS:
            self.sort_field = field

    def cycle_sort(self) -> str:
        """Cycle through sort fields. Returns the new sort field name."""
        fields = list(self.SORT_KEYS.keys())
        idx = fields.index(self.sort_field)
        self.sort_field = fields[(idx + 1) % len(fields)]
        return self.sort_field

    def cycle_band(self) -> str:
        """Cycle through band filters: all -> 2.4GHz -> 5GHz -> 6GHz -> all."""
        cycle = [None, "2.4GHz", "5GHz", "6GHz"]
        try:
            idx = cycle.index(self.band_filter)
        except ValueError:
            idx = 0
        self.band_filter = cycle[(idx + 1) % len(cycle)]
        return self.band_filter or "all"

    def enter_selection_mode(self) -> None:
        """Enter AP selection mode for interactive navigation."""
        self._selection_mode = True
        self._selected_index = 0

    def exit_selection_mode(self) -> None:
        """Exit AP selection mode."""
        self._selection_mode = False
        self._selected_index = 0

    def move_selection(self, delta: int, total: int) -> None:
        """Move selection cursor by delta, clamping to valid range."""
        if total <= 0:
            self._selected_index = 0
            return
        self._selected_index = max(0, min(total - 1, self._selected_index + delta))

    def get_sorted_filtered(self, aps: dict[str, "AccessPoint"]) -> list["AccessPoint"]:
        """Return the currently filtered and sorted AP list (matches render order)."""
        filtered = aps.values()
        if self.band_filter:
            filtered = [ap for ap in filtered if ap.band == self.band_filter]
        else:
            filtered = list(filtered)
        sort_key = self.SORT_KEYS[self.sort_field]
        reverse = self.SORT_REVERSE[self.sort_field]
        return sorted(filtered, key=sort_key, reverse=reverse)

    def set_status(self, msg: str) -> None:
        """Set a persistent status message (cleared on next render if empty)."""
        self._status_message = msg

    def render(
        self,
        aps: dict[str, AccessPoint],
        interface: str,
        current_channel: int,
    ) -> None:
        """Clear screen and render the AP table."""
        c = self.c
        term_width, term_height = os.get_terminal_size()

        # Reuse get_sorted_filtered to avoid duplicating filter+sort logic
        sorted_aps = self.get_sorted_filtered(aps)

        # Elapsed time
        elapsed = datetime.now() - self._start_time
        elapsed_str = str(timedelta(seconds=int(elapsed.total_seconds())))

        # Count stats in single pass
        total = len(aps)
        count_2g = count_5g = count_6g = count_hidden = 0
        for ap in aps.values():
            band = ap.band
            if band == "2.4GHz":
                count_2g += 1
            elif band == "5GHz":
                count_5g += 1
            elif band == "6GHz":
                count_6g += 1
            if ap.is_hidden:
                count_hidden += 1

        # Build output
        lines: list[str] = []

        # First render: clear entire screen; subsequent: just move cursor home
        if self._first_render:
            lines.append("\033[2J\033[H")
            self._first_render = False
        else:
            lines.append("\033[H")

        # Header
        band_str = f"Band: {self.band_filter or 'all'}"
        sort_str = f"Sort: {self.sort_field}"
        header_text = (
            f" AP Scanner v1.0 | {interface} | Monitor | "
            f"CH: {current_channel:<3} | {elapsed_str} | "
            f"{band_str} | {sort_str}"
        )
        header = f" {c.BOLD}{c.WHITE}{c.BG_BLUE}{header_text}"
        padding = max(0, term_width - len(header_text) - 1)
        header += " " * padding + c.RESET
        lines.append(header)
        lines.append("")

        # Column headers
        col_header = (
            f" {c.BOLD}{c.CYAN}"
            f"{'SSID':<24s} {'BSSID':<18s} {'RSSI':>5s} "
            f"{'CH':<16s} {'Band':<6s} {'W':>3s} "
            f"{'802.11':<14s} "
            f"{'ENC':<10s} {'WPA2':<12s} {'WPA3':<12s} "
            f"{'WPS':<4s} {'Vendor'}"
            f"{c.RESET}"
        )
        lines.append(col_header)

        # Separator
        lines.append(f" {c.DIM}{'-' * min(term_width - 2, 150)}{c.RESET}")

        # AP rows
        max_rows = max(term_height - 9, 5)
        now = datetime.now()

        # Track newly discovered APs
        for bssid in aps:
            if bssid not in self._known_bssids:
                self._known_bssids.add(bssid)
                self._new_bssids[bssid] = now
        # Expire old highlights
        expired = [b for b, t in self._new_bssids.items()
                   if (now - t).total_seconds() > self.NEW_AP_HIGHLIGHT_SECS]
        for b in expired:
            del self._new_bssids[b]

        for i, ap in enumerate(sorted_aps[:max_rows]):
            rssi_str = f"{ap.rssi:>4d}" if ap.rssi is not None else " N/A"
            rssi_color = self._rssi_color(ap.rssi)

            is_open = ap.encryption == "OPN"
            # Highlight newly discovered APs
            is_new = ap.bssid in self._new_bssids
            # Dim APs not seen in last 30 seconds
            stale = (now - ap.last_seen) > timedelta(seconds=30)

            # Selection mode: selected row gets REVERSE video
            if self._selection_mode and i == self._selected_index:
                row_prefix = c.REVERSE
            elif is_new:
                row_prefix = f"{c.BOLD}{c.GREEN}"
            elif stale:
                row_prefix = c.DIM
            elif is_open:
                row_prefix = f"{c.BOLD}{c.RED}"
            else:
                row_prefix = ""

            ssid = _truncate_to_width(ap.display_ssid, 23)
            ssid_padded = _pad_to_width(ssid, 24)
            if ap.is_hidden and not is_new:
                ssid_str = f"{c.RED}{ssid_padded}{c.RESET}{row_prefix}"
            else:
                ssid_str = ssid_padded

            enc_color = self._enc_color(ap.encryption)
            vendor = ap.vendor[:20] if ap.vendor else ""

            line = (
                f" {row_prefix}"
                f"{ssid_str}"
                f"{ap.bssid:<18s} "
                f"{rssi_color}{rssi_str}{c.RESET}{row_prefix} "
                f"{ap.channel_display:<16s} "
                f"{ap.band:<6s} {ap.width:>3d} "
                f"{ap.standard_display:<14s} "
                f"{enc_color}{ap.encryption:<10s}{c.RESET}{row_prefix} "
                f"{ap.wpa2:<12s} {ap.wpa3:<12s} "
                f"{ap.wps:<4s} {vendor}"
                f"{c.RESET}"
            )
            lines.append(line)

        # Remaining count
        if len(sorted_aps) > max_rows:
            remaining = len(sorted_aps) - max_rows
            lines.append(f" {c.DIM}... +{remaining} more APs{c.RESET}")

        # Padding to push footer to bottom (status + stats + keys = 4 lines)
        current_lines = len(lines)
        for _ in range(max(0, term_height - current_lines - 4)):
            lines.append("")

        # Status message (e.g., active scan progress)
        if self._status_message:
            lines.append(f" {c.BOLD}{c.YELLOW}{self._status_message}{c.RESET}")
        else:
            lines.append("")

        # Stats line
        stats = (
            f" {c.BOLD}"
            f"APs: {c.WHITE}{total}{c.RESET}{c.BOLD} | "
            f"2.4GHz: {c.GREEN}{count_2g}{c.RESET}{c.BOLD} | "
            f"5GHz: {c.CYAN}{count_5g}{c.RESET}{c.BOLD} | "
            f"6GHz: {c.MAGENTA}{count_6g}{c.RESET}{c.BOLD} | "
            f"Hidden: {c.RED}{count_hidden}{c.RESET}"
        )
        lines.append(stats)

        # Keybindings (mode-dependent)
        if self._selection_mode:
            keys = (
                f" {c.DIM}"
                f"[\u2191/\u2193] Navigate  |  [Enter] Active Scan  |  [Esc] Cancel"
                f"{c.RESET}"
            )
        else:
            keys = (
                f" {c.DIM}"
                f"[q] Quit  |  [w] CSV  |  [j] JSON  |  "
                f"[b] Band  |  [s] Sort  |  [Enter] Select AP"
                f"{c.RESET}"
            )
        lines.append(keys)

        # Append clear-to-end-of-line on every line so leftover text is erased,
        # then clear any remaining lines below the last one we wrote.
        eol = "\033[K"
        output = ("\n" + eol).join(lines)
        # Erase from current position to bottom of screen
        output += "\033[J"
        sys.stdout.write(output)
        sys.stdout.flush()

    def _rssi_color(self, rssi: int | None) -> str:
        c = self.c
        if rssi is None:
            return c.DIM
        if rssi >= -50:
            return c.GREEN
        if rssi >= -70:
            return c.YELLOW
        return c.RED

    def _enc_color(self, encryption: str) -> str:
        c = self.c
        if encryption == "OPN":
            return c.RED
        if encryption in ("WPA3", "WPA2/WPA3"):
            return c.GREEN
        if encryption == "WPA2":
            return c.CYAN
        if encryption == "WPA":
            return c.YELLOW
        if encryption == "WEP":
            return c.RED
        return ""

    def render_overlay(self, lines_content: list[str], title: str = "") -> None:
        """Render a centered overlay panel on top of the AP table."""
        c = self.c
        term_width, term_height = os.get_terminal_size()
        box_width = min(term_width - 4, 72)
        start_row = max(3, (term_height - len(lines_content) - 4) // 2)

        border_h = "+" + "-" * (box_width - 2) + "+"

        sys.stdout.write(f"\033[{start_row};1H")
        sys.stdout.write(f" {c.BOLD}{c.CYAN}{border_h}{c.RESET}\033[K\n")

        if title:
            title_line = f"| {title}"
            pad = box_width - 3 - _display_width(title)
            title_line += " " * max(0, pad) + "|"
            sys.stdout.write(f" {c.BOLD}{c.CYAN}{title_line}{c.RESET}\033[K\n")
            sys.stdout.write(f" {c.BOLD}{c.CYAN}|{' ' * (box_width - 2)}|{c.RESET}\033[K\n")

        for line in lines_content:
            display_line = _truncate_to_width(line, box_width - 4)
            pad = box_width - 2 - _display_width(display_line) - 1
            row = f"| {display_line}" + " " * max(0, pad) + "|"
            sys.stdout.write(f" {c.CYAN}{row}{c.RESET}\033[K\n")

        sys.stdout.write(f" {c.BOLD}{c.CYAN}{border_h}{c.RESET}\033[K\n")
        sys.stdout.write(
            f" {c.DIM}Press any key to dismiss{c.RESET}\033[K"
        )
        sys.stdout.flush()

    def show_message(self, msg: str) -> None:
        """Show a temporary message at the bottom of the screen."""
        c = self.c
        _, term_height = os.get_terminal_size()
        sys.stdout.write(f"\033[{term_height};0H\033[2K {c.BOLD}{c.GREEN}{msg}{c.RESET}")
        sys.stdout.flush()
