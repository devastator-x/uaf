"""CSV and JSON export for scan results."""

import csv
import json
from datetime import datetime
from pathlib import Path

from ap_scanner.models import AccessPoint


def generate_filename(ext: str = "csv") -> str:
    """Generate a default filename with timestamp."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"ap_scan_{ts}.{ext}"


def save_csv(aps: dict[str, AccessPoint], filepath: str | None = None) -> str:
    """Save AP scan results to CSV file in wifi-inspector compatible format.

    Returns the filepath that was written.
    """
    if filepath is None:
        filepath = generate_filename()

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "SSID", "MAC Address", "RSSI",
        "Channel", "Band", "Width", "802.11",
        "WEP", "WPA", "WPA2", "WPA3", "WPS",
        "Vendor", "Beacon Count",
        "First seen", "Last seen",
        "Active Scan IP", "Active Scan Gateway",
        "Active Scan Clients", "Active Scan Ports",
    ]

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: (ap.rssi if ap.rssi is not None else -999),
        reverse=True,
    )

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";",
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for ap in sorted_aps:
            asr = ap.active_scan_result
            writer.writerow({
                "SSID": ap.display_ssid,
                "MAC Address": ap.bssid,
                "RSSI": str(ap.rssi) if ap.rssi is not None else "",
                "Channel": ap.channel_display,
                "Band": ap.band,
                "Width": str(ap.width),
                "802.11": ap.wifi_standard,
                "WEP": ap.wep,
                "WPA": ap.wpa,
                "WPA2": ap.wpa2,
                "WPA3": ap.wpa3,
                "WPS": ap.wps,
                "Vendor": ap.vendor,
                "Beacon Count": str(ap.beacon_count),
                "First seen": ap.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "Last seen": ap.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
                "Active Scan IP": asr.assigned_ip if asr else "",
                "Active Scan Gateway": asr.gateway_ip if asr else "",
                "Active Scan Clients": str(asr.client_count) if asr else "",
                "Active Scan Ports": ",".join(str(p) for p in asr.gateway_open_ports) if asr else "",
            })

    return str(path)


def save_json(aps: dict[str, AccessPoint], filepath: str | None = None) -> str:
    """Save AP scan results to JSON file.

    Returns the filepath that was written.
    """
    if filepath is None:
        filepath = generate_filename("json")

    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    sorted_aps = sorted(
        aps.values(),
        key=lambda ap: (ap.rssi if ap.rssi is not None else -999),
        reverse=True,
    )

    records = []
    for ap in sorted_aps:
        record = {
            "ssid": ap.display_ssid,
            "bssid": ap.bssid,
            "rssi": ap.rssi,
            "channel": ap.channel,
            "channel_display": ap.channel_display,
            "band": ap.band,
            "width": ap.width,
            "wifi_standard": ap.wifi_standard,
            "encryption": ap.encryption,
            "wep": ap.wep,
            "wpa": ap.wpa,
            "wpa2": ap.wpa2,
            "wpa3": ap.wpa3,
            "wps": ap.wps,
            "vendor": ap.vendor,
            "beacon_count": ap.beacon_count,
            "first_seen": ap.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": ap.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if ap.active_scan_result:
            asr = ap.active_scan_result
            record["active_scan"] = {
                "scan_time": asr.scan_time.isoformat(),
                "connected": asr.connected,
                "assigned_ip": asr.assigned_ip,
                "subnet_mask": asr.subnet_mask,
                "gateway_ip": asr.gateway_ip,
                "gateway_mac": asr.gateway_mac,
                "dns_servers": asr.dns_servers,
                "dhcp_server": asr.dhcp_server,
                "gateway_open_ports": asr.gateway_open_ports,
                "clients": [
                    {"ip": c.ip, "mac": c.mac, "vendor": c.vendor}
                    for c in asr.clients
                ],
                "duration_secs": asr.duration_secs,
                "error": asr.error,
            }
        records.append(record)

    with open(path, "w", encoding="utf-8") as f:
        json.dump({"scan_time": datetime.now().isoformat(), "access_points": records},
                  f, ensure_ascii=False, indent=2)

    return str(path)
