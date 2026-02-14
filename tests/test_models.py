"""Tests for ap_scanner.models."""

from ap_scanner.models import AccessPoint, ActiveScanClient, ActiveScanResult


def test_is_hidden_empty_ssid(hidden_ap):
    assert hidden_ap.is_hidden is True


def test_is_hidden_normal_ssid(sample_ap):
    assert sample_ap.is_hidden is False


def test_is_hidden_null_bytes():
    ap = AccessPoint(
        bssid="FF:FF:FF:FF:FF:FF", ssid="\x00\x00\x00",
        channel=1, rssi=-50, encryption="OPN", cipher="--",
        auth="--", band="2.4GHz", wifi_standard="b",
    )
    assert ap.is_hidden is True


def test_is_hidden_whitespace_only():
    ap = AccessPoint(
        bssid="FF:FF:FF:FF:FF:FF", ssid="   ",
        channel=1, rssi=-50, encryption="OPN", cipher="--",
        auth="--", band="2.4GHz", wifi_standard="b",
    )
    assert ap.is_hidden is True


def test_display_ssid_hidden(hidden_ap):
    assert hidden_ap.display_ssid == "[Hidden]"


def test_display_ssid_normal(sample_ap):
    assert sample_ap.display_ssid == "TestNetwork"


def test_rssi_display_none():
    ap = AccessPoint(
        bssid="FF:FF:FF:FF:FF:FF", ssid="Test",
        channel=1, rssi=None, encryption="OPN", cipher="--",
        auth="--", band="2.4GHz", wifi_standard="b",
    )
    assert ap.rssi_display == "N/A"


def test_rssi_display_value(sample_ap):
    assert sample_ap.rssi_display == "-42"


def test_standard_display_empty():
    ap = AccessPoint(
        bssid="FF:FF:FF:FF:FF:FF", ssid="Test",
        channel=1, rssi=-50, encryption="OPN", cipher="--",
        auth="--", band="2.4GHz", wifi_standard="",
    )
    assert ap.standard_display == "--"


def test_standard_display_value(sample_ap):
    assert sample_ap.standard_display == "b, g, n"


def test_channel_display_bonded(hidden_ap):
    assert hidden_ap.channel_display == "36+40+44+48"


def test_channel_display_primary():
    ap = AccessPoint(
        bssid="FF:FF:FF:FF:FF:FF", ssid="Test",
        channel=6, rssi=-50, encryption="OPN", cipher="--",
        auth="--", band="2.4GHz", wifi_standard="b",
    )
    assert ap.channel_display == "6"


# --- ActiveScanResult ---

def test_active_scan_result_defaults():
    r = ActiveScanResult(bssid="AA:BB:CC:DD:EE:FF", ssid="Test")
    assert r.connected is False
    assert r.error == ""
    assert r.clients == []
    assert r.gateway_open_ports == []
    assert r.client_count == 0


def test_active_scan_result_summary_success():
    r = ActiveScanResult(
        bssid="AA:BB:CC:DD:EE:FF", ssid="Test",
        connected=True, assigned_ip="192.168.1.100",
        gateway_ip="192.168.1.1",
        clients=[ActiveScanClient(ip="192.168.1.50", mac="AA:AA:AA:AA:AA:AA")],
        gateway_open_ports=[80, 443],
    )
    s = r.summary
    assert "IP: 192.168.1.100" in s
    assert "GW: 192.168.1.1" in s
    assert "Clients: 1" in s
    assert "80,443" in s


def test_active_scan_result_summary_failed():
    r = ActiveScanResult(
        bssid="AA:BB:CC:DD:EE:FF", ssid="Test",
        error="Connection refused",
    )
    assert "Failed:" in r.summary
    assert "Connection refused" in r.summary


def test_active_scan_result_summary_empty():
    r = ActiveScanResult(bssid="AA:BB:CC:DD:EE:FF", ssid="Test")
    assert r.summary == "No data collected"


def test_access_point_active_scan_none(sample_ap):
    assert sample_ap.active_scan_result is None
