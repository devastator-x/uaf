"""Utility functions: channel/frequency mapping, privilege checks, interface detection."""

import os
import shutil
import subprocess
from pathlib import Path

# 2.4 GHz channels (1-14)
CHANNELS_2G = list(range(1, 15))

# 5 GHz channels (common UNII bands)
CHANNELS_5G = [
    36, 40, 44, 48,       # UNII-1
    52, 56, 60, 64,       # UNII-2
    100, 104, 108, 112,   # UNII-2 Extended
    116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161,   # UNII-3
    165,
]

# 6 GHz channels (WiFi 6E / 7, UNII-5 through UNII-8)
CHANNELS_6G = [
    1, 5, 9, 13, 17, 21, 25, 29,       # UNII-5
    33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93,     # UNII-6
    97, 101, 105, 109, 113, 117,
    121, 125, 129, 133, 137, 141,        # UNII-7
    145, 149, 153, 157, 161, 165,
    169, 173, 177, 181, 185, 189,        # UNII-8
    193, 197, 201, 205, 209, 213,
    217, 221, 225, 229, 233,
]

ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G

# Channel -> Center Frequency (MHz) mapping
CHANNEL_TO_FREQ: dict[int, int] = {}
# 2.4 GHz: channel 1 = 2412 MHz, each channel +5 MHz, channel 14 = 2484 MHz
for ch in range(1, 14):
    CHANNEL_TO_FREQ[ch] = 2407 + ch * 5
CHANNEL_TO_FREQ[14] = 2484
# 5 GHz: freq = 5000 + channel * 5
for ch in CHANNELS_5G:
    CHANNEL_TO_FREQ[ch] = 5000 + ch * 5
# 6 GHz: freq = 5950 + channel * 5  (channel 1 = 5955 MHz)
CHANNEL_TO_FREQ_6G: dict[int, int] = {}
for ch in CHANNELS_6G:
    CHANNEL_TO_FREQ_6G[ch] = 5950 + ch * 5

# Reverse mapping (2.4G + 5G only; 6G channels overlap with 2.4G/5G numbers)
FREQ_TO_CHANNEL: dict[int, int] = {freq: ch for ch, freq in CHANNEL_TO_FREQ.items()}
# Add 6 GHz reverse mapping (no overlap since frequencies are unique)
for ch, freq in CHANNEL_TO_FREQ_6G.items():
    FREQ_TO_CHANNEL[freq] = ch


def freq_to_channel(freq_mhz: int) -> int:
    """Convert frequency in MHz to channel number."""
    if freq_mhz in FREQ_TO_CHANNEL:
        return FREQ_TO_CHANNEL[freq_mhz]
    # Approximate: find closest frequency
    if 2400 <= freq_mhz <= 2500:
        return round((freq_mhz - 2407) / 5)
    elif 5925 <= freq_mhz <= 7125:
        return round((freq_mhz - 5950) / 5)
    elif freq_mhz >= 5000:
        return round((freq_mhz - 5000) / 5)
    return 0


def channel_to_freq(channel: int) -> int:
    """Convert channel number to frequency in MHz."""
    return CHANNEL_TO_FREQ.get(channel, 0)


def is_5ghz(channel: int) -> bool:
    """Check if a channel is in the 5 GHz band."""
    return channel in CHANNELS_5G


def channel_band(channel: int, freq: int = 0) -> str:
    """Return '2.4', '5', or '6' for a given channel.

    Uses frequency to disambiguate overlapping channel numbers between
    2.4GHz/5GHz and 6GHz bands.
    """
    if freq >= 5925:
        return "6"
    if freq >= 4900:
        return "5"
    if freq > 0:
        return "2.4"
    # Fallback: channel number only (no freq info, cannot detect 6GHz)
    return "5" if is_5ghz(channel) else "2.4"


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def check_iw() -> bool:
    """Check if 'iw' command is available."""
    return shutil.which("iw") is not None


def check_ip() -> bool:
    """Check if 'ip' command is available."""
    return shutil.which("ip") is not None


def find_wireless_interfaces() -> list[str]:
    """Find available wireless interfaces by checking /sys/class/net/*/wireless."""
    interfaces = []
    net_path = Path("/sys/class/net")
    if not net_path.exists():
        return interfaces
    for iface_path in net_path.iterdir():
        wireless_path = iface_path / "wireless"
        if wireless_path.exists():
            interfaces.append(iface_path.name)
    return sorted(interfaces)


def get_interface_mode(interface: str) -> str | None:
    """Get the current mode of a wireless interface (managed, monitor, etc.)."""
    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("type "):
                return line.split("type ", 1)[1].strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return None


def get_interface_driver(interface: str) -> str:
    """Get the driver name for a wireless interface."""
    driver_link = Path(f"/sys/class/net/{interface}/device/driver")
    try:
        return driver_link.resolve().name
    except (OSError, ValueError):
        return "unknown"


def get_supported_channels(interface: str) -> list[int]:
    """Query the adapter's supported channels via 'iw phy'.

    Returns a sorted list of channels the hardware can actually use.
    Falls back to ALL_CHANNELS if the query fails.
    """
    # Get phy name for this interface
    phy_path = Path(f"/sys/class/net/{interface}/phy80211/name")
    try:
        phy_name = phy_path.read_text().strip()
    except (OSError, ValueError):
        return ALL_CHANNELS

    try:
        result = subprocess.run(
            ["iw", "phy", phy_name, "channels"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return ALL_CHANNELS
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ALL_CHANNELS

    channels = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Lines look like: "* 2412 MHz [1] (20.0 dBm)"
        # or disabled: "* 5260 MHz [52] (disabled)"
        if not line.startswith("*"):
            continue
        if "disabled" in line.lower():
            continue
        # Note: "no IR" channels are valid for monitor mode (receive-only)
        # Extract channel number from [N]
        bracket_start = line.find("[")
        bracket_end = line.find("]")
        if bracket_start == -1 or bracket_end == -1:
            continue
        try:
            ch = int(line[bracket_start + 1 : bracket_end])
            channels.append(ch)
        except ValueError:
            continue

    return sorted(set(channels)) if channels else ALL_CHANNELS


def parse_channels_arg(channels_str: str) -> list[int]:
    """Parse channel argument string like '1,6,11' or '36-48' into a list of channels."""
    channels = []
    for part in channels_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start.strip()), int(end.strip())
            channels.extend(ch for ch in ALL_CHANNELS if start <= ch <= end)
        else:
            ch = int(part)
            if ch in ALL_CHANNELS:
                channels.append(ch)
    return sorted(set(channels)) if channels else ALL_CHANNELS
