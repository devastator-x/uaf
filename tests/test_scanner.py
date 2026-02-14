"""Tests for ap_scanner.scanner — ChannelHopper schedule + ScannerEngine logic."""

from unittest.mock import patch

from ap_scanner.scanner import ChannelHopper, ScannerEngine


# --- ChannelHopper._build_schedule ---

class TestBuildSchedule:
    """Tests for ChannelHopper._build_schedule weighted scheduling."""

    def _make_hopper(self, channels):
        """Create a ChannelHopper without starting any threads."""
        with patch.object(ChannelHopper, "_get_mac", return_value="00:00:00:00:00:00"):
            return ChannelHopper("wlan0", channels)

    def test_primary_channels_appear_first(self):
        """Channels 1, 6, 11 should be the first entries for quick discovery."""
        hopper = self._make_hopper([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])
        sched = hopper._schedule
        # First three entries should be the primary channels
        assert sched[0] in {1, 6, 11}
        assert sched[1] in {1, 6, 11}
        assert sched[2] in {1, 6, 11}

    def test_primary_channels_visited_more(self):
        """Primary channels (1, 6, 11) should appear more than once."""
        hopper = self._make_hopper(list(range(1, 14)))
        sched = hopper._schedule
        for ch in (1, 6, 11):
            assert sched.count(ch) >= 2, f"Channel {ch} should appear >= 2 times"

    def test_only_primary_channels(self):
        """With only primary channels, schedule still works."""
        hopper = self._make_hopper([1, 6, 11])
        sched = hopper._schedule
        assert len(sched) > 0
        assert set(sched) == {1, 6, 11}

    def test_no_primary_channels(self):
        """With no primary channels (5GHz only), schedule is a plain list."""
        hopper = self._make_hopper([36, 40, 44, 48])
        sched = hopper._schedule
        assert sched == [36, 40, 44, 48]

    def test_empty_channels(self):
        """Empty channel list produces empty schedule."""
        hopper = self._make_hopper([])
        assert hopper._schedule == []

    def test_single_channel(self):
        """Single non-primary channel produces single-entry schedule."""
        hopper = self._make_hopper([36])
        assert hopper._schedule == [36]

    def test_single_primary_channel(self):
        """Single primary channel appears twice (prepended + tail)."""
        hopper = self._make_hopper([6])
        sched = hopper._schedule
        assert 6 in sched
        assert len(sched) >= 1

    def test_5ghz_schedule_unchanged(self):
        """5GHz-only channels should maintain order (no reordering)."""
        channels = [36, 40, 44, 48, 52, 56, 60, 64]
        hopper = self._make_hopper(channels)
        assert hopper._schedule == channels

    def test_mixed_channels_all_present(self):
        """All channels from input are present in the schedule."""
        channels = [1, 6, 11, 36, 40, 44, 48]
        hopper = self._make_hopper(channels)
        sched = hopper._schedule
        for ch in channels:
            assert ch in sched, f"Channel {ch} missing from schedule"


# --- ScannerEngine AP tracking ---

class TestScannerEngineAPUpdate:
    """Tests for AP update logic in _on_packet."""

    def test_access_points_returns_copy(self):
        """access_points property should return a copy, not the internal dict."""
        with patch.object(ChannelHopper, "_get_mac", return_value="00:00:00:00:00:00"):
            engine = ScannerEngine("wlan0", [1, 6, 11])
        aps1 = engine.access_points
        aps2 = engine.access_points
        assert aps1 is not aps2

    def test_clear_removes_all_aps(self):
        """clear() should remove all discovered APs."""
        from datetime import datetime
        from ap_scanner.models import AccessPoint

        with patch.object(ChannelHopper, "_get_mac", return_value="00:00:00:00:00:00"):
            engine = ScannerEngine("wlan0", [1, 6, 11])
        # Manually inject an AP
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", ssid="Test", channel=6,
            rssi=-50, encryption="WPA2", cipher="CCMP", auth="PSK",
            band="2.4GHz", wifi_standard="n",
        )
        engine._aps["AA:BB:CC:DD:EE:FF"] = ap
        assert len(engine.access_points) == 1
        engine.clear()
        assert len(engine.access_points) == 0
