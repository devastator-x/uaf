"""Common test fixtures for AP Scanner tests."""

import pytest
from datetime import datetime

from ap_scanner.models import AccessPoint


@pytest.fixture
def sample_ap():
    return AccessPoint(
        bssid="AA:BB:CC:DD:EE:FF",
        ssid="TestNetwork",
        channel=6,
        rssi=-42,
        encryption="WPA2",
        cipher="CCMP",
        auth="PSK",
        band="2.4GHz",
        wifi_standard="b, g, n",
        width=40,
        channel_desc="6",
        vendor="TP-Link",
        wps="2.0",
        wpa2="PSK-CCMP",
        first_seen=datetime(2026, 1, 1, 12, 0, 0),
        last_seen=datetime(2026, 1, 1, 12, 5, 0),
        beacon_count=100,
        frequency=2437,
    )


@pytest.fixture
def hidden_ap():
    return AccessPoint(
        bssid="11:22:33:44:55:66",
        ssid="",
        channel=36,
        rssi=-65,
        encryption="WPA3",
        cipher="CCMP-256",
        auth="SAE",
        band="5GHz",
        wifi_standard="a, n, ac, ax",
        width=80,
        channel_desc="36+40+44+48",
        wpa3="SAE-CCMP-256",
        first_seen=datetime(2026, 1, 1, 12, 0, 0),
        last_seen=datetime(2026, 1, 1, 12, 5, 0),
        beacon_count=50,
        frequency=5180,
    )


@pytest.fixture
def open_ap():
    return AccessPoint(
        bssid="AA:AA:AA:AA:AA:AA",
        ssid="CafeGuest",
        channel=11,
        rssi=-73,
        encryption="OPN",
        cipher="--",
        auth="--",
        band="2.4GHz",
        wifi_standard="b, g, n",
    )
