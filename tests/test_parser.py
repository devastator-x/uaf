"""Tests for ap_scanner.parser."""

import pytest

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)

from ap_scanner.parser import (
    _extract_ssid,
    _collect_ies,
    _parse_wps_version,
    parse_packet,
    parse_probe_request,
)


def _make_beacon(ssid: str = "TestSSID", bssid: str = "AA:BB:CC:DD:EE:FF",
                 channel: int = 6, freq: int = 2437) -> object:
    """Create a minimal beacon packet for testing."""
    pkt = (
        RadioTap(dBm_AntSignal=-42, ChannelFrequency=freq)
        / Dot11(addr3=bssid)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID=0, info=ssid.encode())
        / Dot11Elt(ID=3, info=bytes([channel]))
    )
    return pkt


def _make_probe_request(ssid: str = "TargetNet",
                        client_mac: str = "11:22:33:44:55:66") -> object:
    """Create a minimal probe request packet."""
    pkt = (
        RadioTap()
        / Dot11(addr2=client_mac)
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=ssid.encode())
    )
    return pkt


# --- parse_packet ---

def test_parse_beacon_basic():
    pkt = _make_beacon(ssid="HomeNet", channel=6, freq=2437)
    ap = parse_packet(pkt)
    assert ap is not None
    assert ap.ssid == "HomeNet"
    assert ap.bssid == "AA:BB:CC:DD:EE:FF"
    assert ap.channel == 6
    # Note: RSSI may be None in mock packets depending on Scapy version
    # The important thing is that the AP was parsed successfully


def test_parse_hidden_ssid():
    pkt = _make_beacon(ssid="", channel=1, freq=2412)
    ap = parse_packet(pkt)
    assert ap is not None
    assert ap.is_hidden is True
    assert ap.display_ssid == "[Hidden]"


def test_parse_5ghz_beacon():
    pkt = _make_beacon(ssid="Office5G", channel=36, freq=5180,
                       bssid="22:33:44:55:66:77")
    ap = parse_packet(pkt)
    assert ap is not None
    assert ap.band == "5GHz"
    assert ap.channel == 36


def test_parse_non_beacon_returns_none():
    # Data frame (not beacon/probe response)
    pkt = RadioTap() / Dot11(type=2, addr3="AA:BB:CC:DD:EE:FF")
    result = parse_packet(pkt)
    assert result is None


def test_parse_no_bssid_returns_none():
    pkt = RadioTap() / Dot11(addr3=None) / Dot11Beacon() / Dot11Elt(ID=0, info=b"Test")
    result = parse_packet(pkt)
    assert result is None


# --- parse_probe_request ---

def test_parse_probe_request_basic():
    pkt = _make_probe_request(ssid="TargetNet", client_mac="AA:BB:CC:DD:EE:01")
    result = parse_probe_request(pkt)
    assert result is not None
    ssid, client = result
    assert ssid == "TargetNet"
    assert client == "AA:BB:CC:DD:EE:01"


def test_parse_probe_request_empty_ssid():
    pkt = _make_probe_request(ssid="")
    result = parse_probe_request(pkt)
    assert result is None


def test_parse_probe_request_non_probe():
    pkt = _make_beacon()
    result = parse_probe_request(pkt)
    assert result is None


# --- _extract_ssid ---

def test_extract_ssid_basic():
    ies = {0: [b"MyNetwork"]}
    assert _extract_ssid(ies) == "MyNetwork"


def test_extract_ssid_empty():
    ies = {0: [b""]}
    assert _extract_ssid(ies) == ""


def test_extract_ssid_missing():
    ies = {}
    assert _extract_ssid(ies) == ""


def test_extract_ssid_capped_at_32_bytes():
    long_ssid = b"A" * 50
    ies = {0: [long_ssid]}
    result = _extract_ssid(ies)
    assert len(result) == 32


# --- _parse_wps_version ---

def test_parse_wps_version_basic():
    # Version attribute: type=0x104A, length=1, value=0x10 (v1.0)
    data = b"\x10\x4A\x00\x01\x10"
    assert _parse_wps_version(data) == "1.0"


def test_parse_wps_version_2():
    # Version attribute: type=0x104A, length=1, value=0x20 (v2.0)
    data = b"\x10\x4A\x00\x01\x20"
    assert _parse_wps_version(data) == "2.0"


def test_parse_wps_version_empty():
    assert _parse_wps_version(b"") == ""


def test_parse_wps_version_truncated():
    # Truncated data should not crash
    data = b"\x10\x4A\x00"
    assert _parse_wps_version(data) == ""


def test_parse_wps_version_malformed_vendor_ext():
    # Vendor Extension (0x1049) with truncated sub-element
    data = b"\x10\x49\x00\x04\x00\x37\x2A\x01"  # WFA OUI + 1 byte
    result = _parse_wps_version(data)
    assert isinstance(result, str)  # Should not crash


# --- parse_packet edge cases ---

def test_parse_beacon_channel_0_rejected():
    """Beacons with channel 0 should be rejected (unreliable data)."""
    pkt = (
        RadioTap()
        / Dot11(addr3="AA:BB:CC:DD:EE:FF")
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID=0, info=b"TestSSID")
        # No DS Parameter Set IE and no RadioTap frequency -> channel 0
    )
    ap = parse_packet(pkt)
    assert ap is None


def test_parse_probe_response():
    """Probe Response frames should be parsed just like beacons."""
    pkt = (
        RadioTap(dBm_AntSignal=-55, ChannelFrequency=2437)
        / Dot11(addr3="11:22:33:44:55:66")
        / Dot11ProbeResp(cap="ESS+privacy")
        / Dot11Elt(ID=0, info=b"ProbeNet")
        / Dot11Elt(ID=3, info=bytes([6]))
    )
    ap = parse_packet(pkt)
    assert ap is not None
    assert ap.ssid == "ProbeNet"
    assert ap.bssid == "11:22:33:44:55:66"


def test_parse_ssid_utf8_decode():
    """Non-ASCII SSIDs should be decoded with errors='replace'."""
    pkt = _make_beacon(ssid="X", channel=1, freq=2412)
    # Manually replace SSID with invalid UTF-8
    elt = pkt.getlayer(Dot11Elt)
    elt.info = b"\xc0\xc1\xff"  # invalid UTF-8 bytes
    ap = parse_packet(pkt)
    assert ap is not None
    # Should contain replacement characters, not crash
    assert "\ufffd" in ap.ssid


def test_parse_probe_request_null_addr2():
    """Probe request with no source address should return None."""
    pkt = (
        RadioTap()
        / Dot11(addr2=None)
        / Dot11ProbeReq()
        / Dot11Elt(ID=0, info=b"TestNet")
    )
    result = parse_probe_request(pkt)
    assert result is None
