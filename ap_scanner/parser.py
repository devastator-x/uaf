"""Parse 802.11 Beacon and Probe Response frames into AccessPoint objects."""

from datetime import datetime

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)

from ap_scanner.models import AccessPoint
from ap_scanner.oui import lookup_vendor
from ap_scanner.utils import CHANNELS_5G, channel_band, freq_to_channel


def parse_packet(pkt) -> AccessPoint | None:
    """Parse a Scapy packet into an AccessPoint. Returns None if not a beacon/probe response."""
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    try:
        bssid = pkt[Dot11].addr3
        if not bssid:
            return None
        bssid = bssid.upper()
    except (IndexError, AttributeError):
        return None

    # Collect all Information Elements in a single pass
    ies = _collect_ies(pkt)

    # SSID
    ssid = _extract_ssid(ies)

    # Channel and frequency
    channel, frequency = _extract_channel_and_freq(pkt, ies)
    if channel == 0:
        return None

    # RSSI
    rssi = _extract_rssi(pkt)

    # Channel width and bonded channels
    width, secondary_channels = _extract_channel_width(ies, channel)
    channel_desc = _build_channel_desc(channel, secondary_channels)

    # Security: encryption, cipher, auth + per-protocol detail
    security = _extract_security(pkt, ies)

    # Band (use frequency to disambiguate 6GHz from 2.4/5GHz)
    band = channel_band(channel, frequency) + "GHz"

    # WiFi standards (all supported, comma-separated)
    wifi_standard = _detect_all_standards(ies, channel)

    # Vendor from OUI
    vendor = lookup_vendor(bssid)

    # WPS
    wps = _extract_wps(ies)

    now = datetime.now()
    return AccessPoint(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=rssi,
        encryption=security["encryption"],
        cipher=security["cipher"],
        auth=security["auth"],
        band=band,
        wifi_standard=wifi_standard,
        width=width,
        channel_desc=channel_desc,
        vendor=vendor,
        wps=wps,
        wep=security["wep"],
        wpa=security["wpa"],
        wpa2=security["wpa2"],
        wpa3=security["wpa3"],
        first_seen=now,
        last_seen=now,
        beacon_count=1,
        frequency=frequency,
    )


def parse_probe_request(pkt) -> tuple[str, str] | None:
    """Parse a Probe Request frame to extract SSID and source MAC.

    Clients looking for hidden networks send Probe Requests with the target SSID.
    By capturing these, we can map SSIDs to hidden APs when the client is also
    seen communicating with that AP.

    Returns:
        (ssid, client_mac) or None if not a probe request or SSID is empty/broadcast.
    """
    if not pkt.haslayer(Dot11ProbeReq):
        return None

    try:
        client_mac = pkt[Dot11].addr2
        if not client_mac:
            return None
        client_mac = client_mac.upper()
    except (IndexError, AttributeError):
        return None

    # Extract SSID from IE
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0 and elt.info:
            ssid = elt.info.decode("utf-8", errors="replace").strip("\x00").strip()
            if ssid:  # Skip broadcast probes (empty SSID)
                return ssid, client_mac
            return None
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

    return None


# ---------------------------------------------------------------------------
# IE collection
# ---------------------------------------------------------------------------

def _collect_ies(pkt) -> dict[int, list[bytes]]:
    """Walk all Dot11Elt layers and group by IE ID. Returns {id: [info_bytes, ...]}."""
    ies: dict[int, list[bytes]] = {}
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        ie_id = elt.ID
        info = elt.info if elt.info else b""
        ies.setdefault(ie_id, []).append(info)
        elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
    return ies


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------

def _extract_ssid(ies: dict) -> str:
    """Extract SSID from IE ID=0. Capped at 32 bytes per 802.11 spec."""
    for info in ies.get(0, []):
        try:
            return info[:32].decode("utf-8", errors="replace")
        except (UnicodeDecodeError, AttributeError):
            return ""
    return ""


def _extract_channel_and_freq(pkt, ies: dict) -> tuple[int, int]:
    """Extract primary channel and frequency."""
    channel = 0
    frequency = 0

    # DS Parameter Set (IE 3)
    for info in ies.get(3, []):
        if info and len(info) >= 1:
            channel = info[0]
            break

    # RadioTap frequency
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        if hasattr(rt, "ChannelFrequency") and rt.ChannelFrequency:
            frequency = rt.ChannelFrequency
            if channel == 0:
                channel = freq_to_channel(frequency)

    return channel, frequency


def _extract_rssi(pkt) -> int | None:
    """Extract RSSI (dBm) from RadioTap header."""
    if pkt.haslayer(RadioTap):
        rt = pkt[RadioTap]
        if hasattr(rt, "dBm_AntSignal") and rt.dBm_AntSignal is not None:
            return rt.dBm_AntSignal
    return None


# ---------------------------------------------------------------------------
# Channel width and bonded channels
# ---------------------------------------------------------------------------

# 5 GHz channel groupings for bonded channel calculation
_5G_40MHZ_PAIRS = [
    (36, 40), (44, 48), (52, 56), (60, 64),
    (100, 104), (108, 112), (116, 120), (124, 128),
    (132, 136), (140, 144), (149, 153), (157, 161),
]
_5G_80MHZ_GROUPS = [
    (36, 40, 44, 48), (52, 56, 60, 64),
    (100, 104, 108, 112), (116, 120, 124, 128),
    (132, 136, 140, 144), (149, 153, 157, 161),
]
_5G_160MHZ_GROUPS = [
    (36, 40, 44, 48, 52, 56, 60, 64),
    (100, 104, 108, 112, 116, 120, 124, 128),
    (132, 136, 140, 144, 149, 153, 157, 161),
]

# 2.4 GHz secondary channel offsets
def _2g_40mhz_channels(primary: int, above: bool) -> list[int]:
    """Get secondary channel for 2.4GHz 40MHz."""
    if above:
        secondary = primary + 4
    else:
        secondary = primary - 4
    if 1 <= secondary <= 14:
        return [secondary]
    return []


def _extract_channel_width(ies: dict, primary_channel: int) -> tuple[int, list[int]]:
    """Extract channel width and secondary channel list from HT/VHT/HE Operation IEs.

    Returns:
        (width_mhz, [secondary_channels])
    """
    width = 20
    secondary_channels: list[int] = []
    is_5ghz = primary_channel in CHANNELS_5G

    # HT Operation (IE 61): determines 20 vs 40 MHz
    ht_secondary_offset = 0
    for info in ies.get(61, []):
        if len(info) >= 2:
            # byte 0: primary channel
            # byte 1, bits 0-1: secondary channel offset (0=none, 1=above, 3=below)
            ht_secondary_offset = info[1] & 0x03
            if ht_secondary_offset in (1, 3):
                width = 40
                above = (ht_secondary_offset == 1)
                if is_5ghz:
                    # Find the 40MHz pair containing this channel
                    for pair in _5G_40MHZ_PAIRS:
                        if primary_channel in pair:
                            secondary_channels = [ch for ch in pair if ch != primary_channel]
                            break
                else:
                    secondary_channels = _2g_40mhz_channels(primary_channel, above)
            break

    # VHT Operation (IE 192): determines 80/160 MHz
    for info in ies.get(192, []):
        if len(info) >= 1:
            vht_width = info[0]
            if vht_width == 1:  # 80 MHz
                width = 80
                if is_5ghz:
                    for group in _5G_80MHZ_GROUPS:
                        if primary_channel in group:
                            secondary_channels = [ch for ch in group if ch != primary_channel]
                            break
            elif vht_width in (2, 3):  # 160 MHz or 80+80
                width = 160
                if is_5ghz:
                    for group in _5G_160MHZ_GROUPS:
                        if primary_channel in group:
                            secondary_channels = [ch for ch in group if ch != primary_channel]
                            break
        break

    # HE Operation (IE 255, ext ID=36): may indicate wider bandwidth
    for info in ies.get(255, []):
        if len(info) > 0 and info[0] == 36 and len(info) >= 7:
            # HE Operation extension - check channel width
            # byte 4 bits: channel width (bit 1 = 40MHz in 2.4, bit 2 = 40/80 in 5, bit 3 = 160 in 5)
            he_params = info[1] if len(info) > 1 else 0
            # This is complex; we rely on VHT/HT info primarily and only override if HE says wider
            if len(info) >= 7:
                he_ch_width = info[5]  # Control channel width
                if he_ch_width == 3 and width < 160:
                    width = 160
                    if is_5ghz:
                        for group in _5G_160MHZ_GROUPS:
                            if primary_channel in group:
                                secondary_channels = [ch for ch in group if ch != primary_channel]
                                break
            break

    return width, secondary_channels


def _build_channel_desc(primary: int, secondary_channels: list[int]) -> str:
    """Build channel description string like '36+40+44+48'."""
    all_channels = sorted([primary] + secondary_channels)
    return "+".join(str(ch) for ch in all_channels)


# ---------------------------------------------------------------------------
# Security extraction
# ---------------------------------------------------------------------------

def _extract_security(pkt, ies: dict) -> dict[str, str]:
    """Extract all security information.

    Returns dict with keys: encryption, cipher, auth, wep, wpa, wpa2, wpa3
    """
    result = {
        "encryption": "OPN",
        "cipher": "--",
        "auth": "--",
        "wep": "",
        "wpa": "",
        "wpa2": "",
        "wpa3": "",
    }

    # Check privacy bit (bit 4 = 0x0010 in 802.11 Capability Info)
    # Direct bit check instead of sprintf() which is ~10x slower
    has_privacy = False
    if pkt.haslayer(Dot11Beacon):
        has_privacy = bool(pkt[Dot11Beacon].cap & 0x0010)
    elif pkt.haslayer(Dot11ProbeResp):
        has_privacy = bool(pkt[Dot11ProbeResp].cap & 0x0010)

    # Parse RSN IE (ID=48) -> WPA2/WPA3
    rsn_info = None
    for info in ies.get(48, []):
        rsn_info = _parse_rsn_wpa_ie(info, is_rsn=True)
        break

    # Parse WPA IE (Vendor IE ID=221, OUI 00:50:F2, type 1)
    wpa_info = None
    for info in ies.get(221, []):
        if info[:4] == b"\x00\x50\xf2\x01":
            wpa_info = _parse_rsn_wpa_ie(info, is_rsn=False)
            break

    # Build per-protocol detail strings (AUTH-CIPHER format, matching wifi-inspector)
    if rsn_info:
        rsn_auth = rsn_info["auth"]
        rsn_cipher = rsn_info["cipher"]
        auth_cipher = f"{rsn_auth}-{rsn_cipher}" if rsn_cipher != "--" else rsn_auth

        if "SAE" in rsn_auth:
            result["wpa3"] = auth_cipher
            if "PSK" in rsn_auth:
                # Transition mode: WPA2 PSK + WPA3 SAE
                result["wpa2"] = f"PSK-{rsn_cipher}"
                result["wpa3"] = f"SAE-{rsn_cipher}"
                result["encryption"] = "WPA2/WPA3"
            else:
                result["encryption"] = "WPA3"
        else:
            result["wpa2"] = auth_cipher
            result["encryption"] = "WPA2"

        result["cipher"] = rsn_cipher
        result["auth"] = rsn_auth

    if wpa_info:
        wpa_auth = wpa_info["auth"]
        wpa_cipher = wpa_info["cipher"]
        auth_cipher = f"{wpa_auth}-{wpa_cipher}" if wpa_cipher != "--" else wpa_auth
        result["wpa"] = auth_cipher

        if not rsn_info:
            result["encryption"] = "WPA"
            result["cipher"] = wpa_cipher
            result["auth"] = wpa_auth

    if not rsn_info and not wpa_info:
        if has_privacy:
            result["encryption"] = "WEP"
            result["wep"] = "WEP"
            result["cipher"] = "WEP"
        else:
            result["encryption"] = "OPN"

    return result


def _parse_rsn_wpa_ie(data: bytes, is_rsn: bool) -> dict[str, str]:
    """Parse RSN (WPA2/WPA3) or WPA Information Element."""
    result = {"cipher": "--", "auth": "--"}
    try:
        offset = 2 if is_rsn else 6  # RSN: skip version; WPA: skip OUI+type+version

        # Group cipher suite (4 bytes)
        offset += 4

        # Pairwise cipher suites
        if offset + 2 > len(data):
            return result
        pw_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2

        ciphers = set()
        for _ in range(pw_count):
            if offset + 4 > len(data):
                break
            ciphers.add(_cipher_suite_name(data[offset + 3]))
            offset += 4

        result["cipher"] = "/".join(sorted(ciphers)) if ciphers else "--"

        # AKM suites
        if offset + 2 > len(data):
            return result
        akm_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2

        auths = set()
        for _ in range(akm_count):
            if offset + 4 > len(data):
                break
            auths.add(_akm_suite_name(data[offset + 3]))
            offset += 4

        result["auth"] = "/".join(sorted(auths)) if auths else "--"

    except (IndexError, ValueError):
        pass

    return result


def _cipher_suite_name(cipher_type: int) -> str:
    return {
        0: "GROUP", 1: "WEP40", 2: "TKIP", 3: "RESERVED",
        4: "CCMP", 5: "WEP104", 6: "BIP-CMAC",
        8: "GCMP", 9: "GCMP-256", 10: "CCMP-256",
    }.get(cipher_type, f"CIPHER({cipher_type})")


def _akm_suite_name(akm_type: int) -> str:
    return {
        1: "MGT", 2: "PSK", 3: "FT-MGT", 4: "FT-PSK",
        6: "MGT-SHA256", 8: "SAE", 9: "FT-SAE",
        12: "OWE", 18: "OWE",
    }.get(akm_type, f"AKM({akm_type})")


# ---------------------------------------------------------------------------
# WiFi standard detection
# ---------------------------------------------------------------------------

def _detect_all_standards(ies: dict, channel: int) -> str:
    """Detect all supported WiFi standards from IEs.

    Returns comma-separated string like "b, g, n" or "a, n, ac, ax".
    """
    standards: list[str] = []
    is_5ghz = channel in CHANNELS_5G

    # Base standard from band
    if is_5ghz:
        standards.append("a")
    else:
        # Check supported rates to determine b and/or g
        supported_rates = _collect_rates(ies)
        ofdm_rates = {6, 9, 12, 18, 24, 36, 48, 54}
        b_rates = {1, 2, 5.5, 11}

        has_b = any(r in b_rates for r in supported_rates)
        has_g = any(r in ofdm_rates for r in supported_rates)

        if has_b:
            standards.append("b")
        if has_g:
            standards.append("g")
        if not has_b and not has_g and supported_rates:
            standards.append("b")  # fallback

    # HT Capabilities (IE 45) -> 802.11n
    if 45 in ies:
        standards.append("n")

    # VHT Capabilities (IE 191) -> 802.11ac
    if 191 in ies:
        standards.append("ac")

    # HE Capabilities (IE 255, ext ID 35) -> 802.11ax
    for info in ies.get(255, []):
        if info and len(info) > 0 and info[0] == 35:
            standards.append("ax")
            break

    return ", ".join(standards)


def _collect_rates(ies: dict) -> set[float]:
    """Collect supported rates from IE 1 (Supported Rates) and IE 50 (Extended Rates)."""
    rates: set[float] = set()
    for ie_id in (1, 50):
        for info in ies.get(ie_id, []):
            for byte in info:
                rate = (byte & 0x7F) * 0.5
                rates.add(rate)
    return rates


# ---------------------------------------------------------------------------
# WPS detection
# ---------------------------------------------------------------------------

def _extract_wps(ies: dict) -> str:
    """Extract WPS version from Vendor Specific IEs.

    WPS IE: Vendor IE (221) with OUI 00:50:F2, type 4.
    """
    for info in ies.get(221, []):
        if len(info) >= 4 and info[:4] == b"\x00\x50\xf2\x04":
            # WPS IE found - parse WPS attributes to find version
            return _parse_wps_version(info[4:])
    return ""


def _parse_wps_version(data: bytes) -> str:
    """Parse WPS attributes to extract version.

    WPS TLV format: Type (2 bytes BE) | Length (2 bytes BE) | Value
    Version attribute type = 0x104A
    Version2 attribute type = 0x1032 (inside Vendor Extension 0x1049)
    """
    offset = 0
    version = ""
    while offset + 4 <= len(data):
        attr_type = int.from_bytes(data[offset:offset + 2], "big")
        attr_len = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4

        if offset + attr_len > len(data):
            break

        attr_data = data[offset:offset + attr_len]

        if attr_type == 0x104A and attr_len >= 1:
            # Version: single byte, major.minor (0x10 = 1.0, 0x20 = 2.0)
            ver_byte = attr_data[0]
            major = (ver_byte >> 4) & 0x0F
            minor = ver_byte & 0x0F
            version = f"{major}.{minor}"
        elif attr_type == 0x1049:
            # Vendor Extension - may contain Version2 (sub-element ID 0x00)
            sub_offset = 3  # skip 3-byte WFA vendor ID
            while sub_offset + 2 <= len(attr_data):
                sub_id = attr_data[sub_offset]
                sub_len = attr_data[sub_offset + 1]
                sub_offset += 2
                if sub_offset + sub_len > len(attr_data):
                    break  # malformed sub-element
                if sub_id == 0x00 and sub_len >= 1:
                    ver_byte = attr_data[sub_offset]
                    major = (ver_byte >> 4) & 0x0F
                    minor = ver_byte & 0x0F
                    version = f"{major}.{minor}"
                sub_offset += sub_len

        offset += attr_len

    return version
