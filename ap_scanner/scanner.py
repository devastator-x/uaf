"""Scanner engine: packet capture, channel hopping, AP management."""

import logging
import subprocess
import threading
import time
from datetime import datetime

from scapy.all import sendp, sniff
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap

from ap_scanner.models import AccessPoint
from ap_scanner.parser import parse_packet, parse_probe_request

logger = logging.getLogger("ap_scanner.scanner")

# Memory bounds for tracking maps
MAX_CLIENTS = 10000
MAX_PROBE_SSIDS = 5000
_CLEANUP_INTERVAL = 60  # seconds


class ChannelHopper:
    """Hops through WiFi channels in a background thread.

    Uses a weighted schedule so primary 2.4 GHz channels (1, 6, 11) are
    visited more frequently, improving discovery of the most common APs.
    """

    # Primary 2.4 GHz channels — visited twice per cycle for better coverage
    _PRIMARY_24 = {1, 6, 11}

    def __init__(
        self,
        interface: str,
        channels: list[int],
        dwell_time: float = 0.5,
    ):
        self.interface = interface
        self.channels = channels
        self.dwell_time = dwell_time
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._current_channel: int = 0
        self._lock = threading.Lock()
        self._fail_count: dict[int, int] = {}  # ch -> consecutive failure count
        self._failed_channels: set[int] = set()  # permanently skipped after 3 failures
        self._probe_src_mac = self._get_mac()
        self._schedule = self._build_schedule()

    def _get_mac(self) -> str:
        """Read the interface MAC address for Probe Request source."""
        try:
            mac_path = f"/sys/class/net/{self.interface}/address"
            with open(mac_path) as f:
                return f.read().strip()
        except (OSError, ValueError):
            return "00:00:00:00:00:00"

    def _build_schedule(self) -> list[int]:
        """Build a weighted channel schedule.

        Primary 2.4 GHz channels (1, 6, 11) are interleaved between other
        channels so they get visited roughly twice as often.
        """
        primary = [ch for ch in self.channels if ch in self._PRIMARY_24]
        others = [ch for ch in self.channels if ch not in self._PRIMARY_24]

        if not primary:
            return list(self.channels)

        # Interleave: after every N other channels, insert a primary channel
        # With ~36 other channels and 3 primary, insert one primary every 12 channels
        schedule: list[int] = []
        step = max(len(others) // len(primary), 3) if others else 1
        pri_idx = 0

        for i, ch in enumerate(others):
            schedule.append(ch)
            if (i + 1) % step == 0 and pri_idx < len(primary):
                schedule.append(primary[pri_idx])
                pri_idx += 1

        # Append any remaining primary channels
        while pri_idx < len(primary):
            schedule.append(primary[pri_idx])
            pri_idx += 1

        # Prepend all primary channels at the start for quick first results
        return primary + schedule

    @property
    def current_channel(self) -> int:
        with self._lock:
            return self._current_channel

    def start(self) -> None:
        self._stop_event.clear()
        self._fail_count.clear()
        self._failed_channels.clear()
        self._thread = threading.Thread(target=self._hop_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
            if self._thread.is_alive():
                logger.warning("Channel hopper thread did not stop within timeout")

    def _send_probe_request(self) -> None:
        """Inject a broadcast Probe Request to trigger Probe Responses from APs.

        This is the key difference between passive and active scanning.
        APs respond to Probe Requests even when the next beacon is far away.
        """
        try:
            probe = (
                RadioTap()
                / Dot11(
                    type=0,
                    subtype=4,
                    addr1="ff:ff:ff:ff:ff:ff",
                    addr2=self._probe_src_mac,
                    addr3="ff:ff:ff:ff:ff:ff",
                )
                / Dot11ProbeReq()
                / Dot11Elt(ID=0, info=b"")  # broadcast SSID
                / Dot11Elt(ID=1, info=b"\x02\x04\x0b\x16\x0c\x12\x18\x24")  # rates
            )
            sendp(probe, iface=self.interface, verbose=False, count=1)
        except Exception:
            pass  # best-effort; injection may not be supported

    def _hop_loop(self) -> None:
        _BLACKLIST_THRESHOLD = 3  # failures before permanent skip

        while not self._stop_event.is_set():
            for ch in self._schedule:
                if self._stop_event.is_set():
                    break
                # Skip channels that have consistently failed
                if ch in self._failed_channels:
                    continue
                try:
                    result = subprocess.run(
                        ["iw", "dev", self.interface, "set", "channel", str(ch)],
                        capture_output=True,
                        timeout=2,
                    )
                    if result.returncode != 0:
                        count = self._fail_count.get(ch, 0) + 1
                        self._fail_count[ch] = count
                        if count >= _BLACKLIST_THRESHOLD:
                            self._failed_channels.add(ch)
                            logger.debug("Channel %d failed %d times — skipping", ch, count)
                        continue
                    # Success — reset failure counter
                    self._fail_count.pop(ch, None)
                    with self._lock:
                        self._current_channel = ch
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    count = self._fail_count.get(ch, 0) + 1
                    self._fail_count[ch] = count
                    if count >= _BLACKLIST_THRESHOLD:
                        self._failed_channels.add(ch)
                    continue

                # Send Probe Request to trigger AP responses on this channel
                self._send_probe_request()

                self._stop_event.wait(self.dwell_time)


class ScannerEngine:
    """Orchestrates packet capture and channel hopping to discover APs."""

    # Check time-based cleanup every N packets to avoid syscall on every packet
    _CLEANUP_CHECK_INTERVAL = 5000

    def __init__(
        self,
        interface: str,
        channels: list[int],
        dwell_time: float = 0.5,
    ):
        self.interface = interface
        self.channels = channels

        self._aps: dict[str, AccessPoint] = {}
        # client_mac -> set of BSSIDs they communicate with
        self._client_ap_map: dict[str, set[str]] = {}
        # SSID -> set of client MACs that probed for it
        self._probe_ssids: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._hopper = ChannelHopper(interface, channels, dwell_time=dwell_time)
        self._capture_thread: threading.Thread | None = None
        self._last_cleanup = time.monotonic()
        self._pkt_count = 0

    @property
    def access_points(self) -> dict[str, AccessPoint]:
        """Return a copy of the current AP dictionary."""
        with self._lock:
            return dict(self._aps)

    @property
    def current_channel(self) -> int:
        return self._hopper.current_channel

    def start(self) -> None:
        """Start scanning: channel hopper + packet capture."""
        self._stop_event.clear()
        self._hopper.start()
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()

    def stop(self) -> None:
        """Stop scanning and clean up threads."""
        self._stop_event.set()
        # Suppress Scapy socket warnings during intentional shutdown
        logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
        logging.getLogger("scapy").setLevel(logging.CRITICAL)
        self._hopper.stop()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5)
            if self._capture_thread.is_alive():
                logger.warning("Capture thread did not stop within timeout")

    def clear(self) -> None:
        """Clear all discovered APs."""
        with self._lock:
            self._aps.clear()

    @staticmethod
    def _pick_bpf_filter(interface: str) -> str:
        """Try BPF filter candidates and return the first one that compiles.

        Returns empty string if none work (safe fallback = no filter).
        """
        candidates = ["type mgt", ""]
        for bpf in candidates:
            if not bpf:
                return ""
            try:
                # Dry-run: open a sniff socket with the filter to see if it compiles
                from scapy.arch.common import compile_filter
                compile_filter(bpf, interface)
                return bpf
            except Exception:
                continue
        return ""

    def _capture_loop(self) -> None:
        """Run Scapy sniff in the capture thread.

        Tries to apply a BPF filter for 802.11 management frames only,
        falling back to no filter + fast Python-level type check.
        """
        bpf = self._pick_bpf_filter(self.interface)
        if bpf:
            logger.debug("Using BPF filter: %s", bpf)
        else:
            logger.debug("BPF filter not available — using Python-level filtering")

        try:
            while not self._stop_event.is_set():
                sniff(
                    iface=self.interface,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                    timeout=2,
                    monitor=True,
                    **({"filter": bpf} if bpf else {}),
                )
        except OSError as e:
            if not self._stop_event.is_set():
                logger.error("Capture error on %s: %s", self.interface, e)

    def _maybe_cleanup(self) -> None:
        """Periodically evict old entries from tracking maps to bound memory.

        Uses a packet counter to avoid calling time.monotonic() on every packet.
        """
        self._pkt_count += 1
        if self._pkt_count < self._CLEANUP_CHECK_INTERVAL:
            return
        self._pkt_count = 0

        now = time.monotonic()
        if now - self._last_cleanup < _CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        with self._lock:
            if len(self._client_ap_map) > MAX_CLIENTS:
                keys = list(self._client_ap_map.keys())
                for k in keys[: len(keys) // 2]:
                    del self._client_ap_map[k]
            if len(self._probe_ssids) > MAX_PROBE_SSIDS:
                keys = list(self._probe_ssids.keys())
                for k in keys[: len(keys) // 2]:
                    del self._probe_ssids[k]

    def _on_packet(self, pkt) -> None:
        """Callback for each captured packet."""
        # Fast reject: extract Dot11 layer once and reuse throughout.
        dot11 = pkt.getlayer(Dot11)
        if dot11 is None:
            return
        frame_type = dot11.type
        if frame_type == 1:  # Control frame — skip
            return

        self._maybe_cleanup()

        # Track client-AP associations (Data/Auth frames only)
        if frame_type in (0, 2):
            self._track_client_ap(dot11)

        # Try to resolve hidden SSIDs from Probe Requests
        probe = parse_probe_request(pkt)
        if probe:
            ssid, client_mac = probe
            with self._lock:
                self._probe_ssids.setdefault(ssid, set()).add(client_mac)
                self._try_resolve_hidden(ssid, client_mac)

        ap = parse_packet(pkt)
        if ap is None:
            return

        with self._lock:
            existing = self._aps.get(ap.bssid)
            if existing:
                existing.last_seen = datetime.now()
                existing.beacon_count += 1
                if ap.rssi is not None:
                    existing.rssi = ap.rssi
                if existing.is_hidden and not ap.is_hidden:
                    existing.ssid = ap.ssid
                if ap.encryption != "OPN" and existing.encryption == "OPN":
                    existing.encryption = ap.encryption
                    existing.cipher = ap.cipher
                    existing.auth = ap.auth
                if ap.wpa2 and not existing.wpa2:
                    existing.wpa2 = ap.wpa2
                if ap.wpa3 and not existing.wpa3:
                    existing.wpa3 = ap.wpa3
                if ap.wpa and not existing.wpa:
                    existing.wpa = ap.wpa
                if ap.wep and not existing.wep:
                    existing.wep = ap.wep
                if ap.wifi_standard and not existing.wifi_standard:
                    existing.wifi_standard = ap.wifi_standard
                if ap.width > existing.width:
                    existing.width = ap.width
                    existing.channel_desc = ap.channel_desc
                if ap.vendor and not existing.vendor:
                    existing.vendor = ap.vendor
                if ap.wps and not existing.wps:
                    existing.wps = ap.wps
            else:
                self._aps[ap.bssid] = ap
                if ap.is_hidden:
                    self._try_resolve_hidden_for_ap(ap.bssid)

    def _track_client_ap(self, dot11) -> None:
        """Track which clients are communicating with which APs.

        Receives the Dot11 layer directly (already extracted by _on_packet).
        """
        addr1 = dot11.addr1  # receiver
        addr2 = dot11.addr2  # transmitter
        addr3 = dot11.addr3  # BSSID (in most cases)

        if not addr2 or not addr3:
            return

        addr2_upper = addr2.upper()
        addr3_upper = addr3.upper()

        with self._lock:
            if addr3_upper in self._aps:
                if addr2_upper != addr3_upper:
                    self._client_ap_map.setdefault(addr2_upper, set()).add(addr3_upper)
            elif addr2_upper in self._aps:
                if addr1:
                    client = addr1.upper()
                    if client != addr2_upper:
                        self._client_ap_map.setdefault(client, set()).add(addr2_upper)

    def _try_resolve_hidden(self, ssid: str, client_mac: str) -> None:
        """Try to match a probe request SSID to a hidden AP via client association.

        If this client is associated with a hidden AP, the probed SSID is likely
        the hidden AP's real name.
        """
        bssids = self._client_ap_map.get(client_mac, set())
        for bssid in bssids:
            ap = self._aps.get(bssid)
            if ap and ap.is_hidden:
                ap.ssid = ssid

    def _try_resolve_hidden_for_ap(self, bssid: str) -> None:
        """When a new hidden AP appears, check if any known clients can reveal its SSID."""
        # Find clients associated with this BSSID
        for client_mac, associated_bssids in self._client_ap_map.items():
            if bssid in associated_bssids:
                # Check if this client has probed for any SSIDs
                for ssid, probing_clients in self._probe_ssids.items():
                    if client_mac in probing_clients:
                        ap = self._aps.get(bssid)
                        if ap and ap.is_hidden:
                            ap.ssid = ssid
                            return
