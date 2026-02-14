"""Data models for AP Scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ActiveScanClient:
    """A client discovered during active ARP scanning."""

    ip: str
    mac: str
    vendor: str = ""


@dataclass
class ActiveScanResult:
    """Results from an active scan of an open AP."""

    bssid: str
    ssid: str
    scan_time: datetime = field(default_factory=datetime.now)
    connected: bool = False
    assigned_ip: str = ""
    subnet_mask: str = ""
    gateway_ip: str = ""
    gateway_mac: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dhcp_server: str = ""
    clients: list[ActiveScanClient] = field(default_factory=list)
    gateway_open_ports: list[int] = field(default_factory=list)
    duration_secs: float = 0.0
    error: str = ""

    @property
    def client_count(self) -> int:
        return len(self.clients)

    @property
    def summary(self) -> str:
        if self.error:
            return f"Failed: {self.error}"
        parts = []
        if self.assigned_ip:
            parts.append(f"IP: {self.assigned_ip}")
        if self.gateway_ip:
            parts.append(f"GW: {self.gateway_ip}")
        if self.clients:
            parts.append(f"Clients: {self.client_count}")
        if self.gateway_open_ports:
            parts.append(f"Ports: {','.join(str(p) for p in self.gateway_open_ports)}")
        return " | ".join(parts) if parts else "No data collected"


@dataclass
class AccessPoint:
    """Represents a discovered wireless access point."""

    bssid: str
    ssid: str  # empty string for hidden networks
    channel: int  # primary channel
    rssi: int | None  # dBm (e.g., -42)
    encryption: str  # OPN, WEP, WPA, WPA2, WPA3, WPA2/WPA3
    cipher: str  # CCMP, TKIP, CCMP/TKIP, --
    auth: str  # PSK, SAE, MGT, PSK/SAE, --
    band: str  # "2.4GHz" or "5GHz"
    wifi_standard: str  # "b, g, n" or "a, n, ac, ax" (comma-separated, all supported)
    width: int = 20  # Channel width: 20, 40, 80, 160 MHz
    channel_desc: str = ""  # Bonded channels: "36+40+44+48"
    vendor: str = ""  # OUI vendor name
    wps: str = ""  # WPS version: "1.0", "2.0", or ""
    wep: str = ""  # WEP security detail (auth-cipher) or ""
    wpa: str = ""  # WPA security detail (auth-cipher) or ""
    wpa2: str = ""  # WPA2 security detail (auth-cipher) or ""
    wpa3: str = ""  # WPA3 security detail (auth-cipher) or ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    beacon_count: int = 0
    frequency: int = 0  # MHz
    active_scan_result: ActiveScanResult | None = None

    @property
    def is_hidden(self) -> bool:
        return len(self.ssid.strip("\x00").strip()) == 0

    @property
    def display_ssid(self) -> str:
        return "[Hidden]" if self.is_hidden else self.ssid

    @property
    def rssi_display(self) -> str:
        return str(self.rssi) if self.rssi is not None else "N/A"

    @property
    def standard_display(self) -> str:
        return self.wifi_standard if self.wifi_standard else "--"

    @property
    def channel_display(self) -> str:
        """Show bonded channels if available, otherwise primary channel."""
        return self.channel_desc if self.channel_desc else str(self.channel)
