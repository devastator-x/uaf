"""OUI (Organizationally Unique Identifier) vendor lookup from MAC address."""

from pathlib import Path

# Common WiFi AP/router vendors - covers most consumer and enterprise APs
# Format: first 3 bytes of MAC (uppercase, colon-separated) -> vendor name
_BUILTIN_OUI: dict[str, str] = {
    # TP-Link
    "5C:A6:E6": "TP-Link", "E8:48:B8": "TP-Link", "50:C7:BF": "TP-Link",
    "98:DA:C4": "TP-Link", "B0:BE:76": "TP-Link", "60:32:B1": "TP-Link",
    "A4:2B:B0": "TP-Link", "30:DE:4B": "TP-Link", "C0:06:C3": "TP-Link",
    "F4:EC:38": "TP-Link", "AC:84:C6": "TP-Link", "14:EB:B6": "TP-Link",
    "EC:08:6B": "TP-Link", "78:8C:B5": "TP-Link", "B4:B0:24": "TP-Link",
    # Netgear
    "34:98:B5": "NETGEAR", "C4:04:15": "NETGEAR", "20:0C:C8": "NETGEAR",
    "A0:40:A0": "NETGEAR", "E0:46:9A": "NETGEAR", "28:C6:8E": "NETGEAR",
    "6C:B0:CE": "NETGEAR", "B0:7F:B9": "NETGEAR", "DC:EF:09": "NETGEAR",
    # Cisco / Meraki
    "00:1B:2A": "Cisco", "00:26:0B": "Cisco", "F8:C2:88": "Cisco Meraki",
    "0C:8D:DB": "Cisco Meraki", "AC:17:C8": "Cisco Meraki", "34:56:FE": "Cisco",
    "00:18:74": "Cisco", "00:1A:A1": "Cisco", "B0:AA:77": "Cisco",
    # Aruba / HPE
    "00:0B:86": "Aruba Networks", "24:DE:C6": "Aruba Networks",
    "AC:A3:1E": "Aruba Networks", "D8:C7:C8": "Aruba Networks",
    "9C:1C:12": "Aruba Networks", "70:3A:0E": "Aruba Networks",
    # Ubiquiti
    "24:A4:3C": "Ubiquiti", "FC:EC:DA": "Ubiquiti", "68:D7:9A": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "18:E8:29": "Ubiquiti", "74:83:C2": "Ubiquiti",
    # Ruckus
    "C4:10:8A": "Ruckus", "EC:58:EA": "Ruckus", "74:91:1A": "Ruckus",
    "A4:12:42": "Ruckus", "58:B6:33": "Ruckus",
    # Samsung
    "A8:7C:01": "Samsung", "F4:42:8F": "Samsung", "C0:BD:D1": "Samsung",
    "5C:3A:45": "Samsung", "B4:3A:28": "Samsung", "D0:22:BE": "Samsung",
    "78:BD:BC": "Samsung", "CC:07:AB": "Samsung", "58:CB:52": "Samsung",
    # Apple
    "00:1C:B3": "Apple", "28:CF:E9": "Apple", "3C:06:30": "Apple",
    "70:3E:AC": "Apple", "AC:BC:32": "Apple", "F0:D1:A9": "Apple",
    "14:7D:DA": "Apple", "18:AF:61": "Apple", "D0:E1:40": "Apple",
    "A8:8E:24": "Apple", "F8:FF:C2": "Apple", "DC:A9:04": "Apple",
    # Intel
    "8C:17:59": "Intel", "14:85:7F": "Intel", "A0:C5:89": "Intel",
    "68:05:CA": "Intel", "34:13:E8": "Intel", "80:86:F2": "Intel",
    "48:51:B7": "Intel", "7C:B2:7D": "Intel",
    # Huawei / Honor
    "00:E0:FC": "Huawei", "48:46:FB": "Huawei", "88:28:B3": "Huawei",
    "C8:D1:5E": "Huawei", "04:F9:38": "Huawei", "4C:B1:6C": "Huawei",
    "70:8C:B6": "Huawei", "AC:61:EA": "Huawei",
    # ASUS
    "F8:32:E4": "ASUS", "04:D9:F5": "ASUS", "2C:FD:A1": "ASUS",
    "1C:87:2C": "ASUS", "38:D5:47": "ASUS", "60:45:CB": "ASUS",
    "AC:22:0B": "ASUS", "B0:6E:BF": "ASUS",
    # D-Link
    "00:1C:F0": "D-Link", "1C:7E:E5": "D-Link", "28:10:7B": "D-Link",
    "84:C9:B2": "D-Link", "C8:D3:A3": "D-Link", "FC:75:16": "D-Link",
    "B8:A3:86": "D-Link",
    # Linksys / Belkin
    "C0:56:27": "Linksys", "20:AA:4B": "Linksys", "58:6D:8F": "Linksys",
    "E8:9F:80": "Belkin", "94:44:52": "Belkin", "08:86:3B": "Belkin",
    # EFM Networks (ipTIME)
    "70:5D:CC": "EFM Networks", "58:86:94": "EFM Networks",
    "88:36:6C": "EFM Networks", "00:08:9F": "EFM Networks",
    "90:9F:33": "EFM Networks", "00:26:66": "EFM Networks",
    "C8:3A:35": "EFM Networks", "04:BD:70": "EFM Networks",
    # LG
    "00:1E:75": "LG Electronics", "10:68:3F": "LG Electronics",
    "64:99:68": "LG Electronics", "C4:36:6C": "LG Electronics",
    "A8:23:FE": "LG Electronics",
    # OHSUNG (LG IoT devices)
    "1C:39:29": "OHSUNG",
    # Fortinet
    "E8:1C:BA": "Fortinet", "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet",
    # Xiaomi
    "28:6C:07": "Xiaomi", "64:CC:2E": "Xiaomi", "78:11:DC": "Xiaomi",
    "50:EC:50": "Xiaomi", "7C:1D:D9": "Xiaomi",
    # Qualcomm / Mediatek (chipset vendors)
    "00:03:7F": "Atheros", "00:1A:6B": "Atheros",
    "00:0C:E7": "MediaTek", "00:0C:43": "Ralink",
    # Realtek
    "00:E0:4C": "Realtek", "48:5D:60": "Realtek", "52:54:00": "Realtek",
    # Broadcom
    "00:10:18": "Broadcom", "00:1A:2B": "Broadcom",
    # Google
    "F4:F5:D8": "Google", "54:60:09": "Google", "A4:77:33": "Google",
    # Amazon (eero, Ring, etc.)
    "F0:72:EA": "Amazon", "68:54:FD": "Amazon", "40:B4:CD": "Amazon",
    # Seongji Industry
    "88:57:1D": "Seongji Industry",
    # SHENZHEN GONGJIN (ZTE ODM)
    "80:CA:4B": "SHENZHEN GONGJIN ELECTRONICS",
    # Alfa Network
    "00:C0:CA": "Alfa Network",
}

# Loaded entries from system OUI file
_loaded_oui: dict[str, str] = {}
_oui_loaded = False


def _load_system_oui() -> None:
    """Try to load the system OUI database (e.g., from aircrack-ng or wireshark)."""
    global _oui_loaded, _loaded_oui
    if _oui_loaded:
        return
    _oui_loaded = True

    oui_paths = [
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/misc/oui.txt"),
        Path("/usr/share/wireshark/manuf"),
        Path("/usr/share/aircrack-ng/airodump-ng-oui.txt"),
        Path("/etc/aircrack-ng/airodump-ng-oui.txt"),
    ]

    for oui_path in oui_paths:
        if oui_path.exists():
            try:
                _parse_oui_file(oui_path)
                return
            except Exception:
                continue


def _parse_oui_file(path: Path) -> None:
    """Parse an OUI file (IEEE format or Wireshark manuf format)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # IEEE format: "AA-BB-CC   (hex)        Vendor Name"
            if "(hex)" in line:
                parts = line.split("(hex)")
                if len(parts) == 2:
                    oui = parts[0].strip().replace("-", ":").upper()
                    vendor = parts[1].strip()
                    if len(oui) == 8 and vendor:
                        _loaded_oui[oui] = vendor

            # Wireshark manuf format: "AA:BB:CC<tab>ShortName<tab>Long Name"
            elif "\t" in line:
                parts = line.split("\t")
                if len(parts) >= 2:
                    oui = parts[0].strip().upper().replace("-", ":")
                    vendor = parts[-1].strip() if len(parts) >= 3 else parts[1].strip()
                    if len(oui) == 8 and vendor:
                        _loaded_oui[oui] = vendor


def lookup_vendor(mac: str) -> str:
    """Look up vendor name from MAC address.

    Args:
        mac: MAC address in format "AA:BB:CC:DD:EE:FF"

    Returns:
        Vendor name or empty string if not found.
    """
    oui = mac[:8].upper()

    # Check builtin first (curated, clean names)
    if oui in _BUILTIN_OUI:
        return _BUILTIN_OUI[oui]

    # Try system OUI database
    _load_system_oui()
    if oui in _loaded_oui:
        return _loaded_oui[oui]

    return ""
