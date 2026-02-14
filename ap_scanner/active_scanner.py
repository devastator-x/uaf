"""Active scanner: connect to open APs and gather network intelligence."""

import logging
import re
import socket
import struct
import subprocess
import time
from datetime import datetime
from pathlib import Path

from ap_scanner.models import AccessPoint, ActiveScanClient, ActiveScanResult

logger = logging.getLogger("ap_scanner.active_scanner")

# Common gateway ports to probe
GATEWAY_PORTS = [22, 53, 80, 443, 8080, 8443]

# Timeouts
DHCP_TIMEOUT = 15
CONNECT_TIMEOUT = 10
PORT_SCAN_TIMEOUT = 1
ARP_TIMEOUT = 3
OVERALL_TIMEOUT = 90


class ActiveScanner:
    """Performs active reconnaissance on open (OPN) access points.

    Sequence: connect -> DHCP -> parse network info -> ARP scan -> port scan -> disconnect.
    """

    def __init__(self, interface: str):
        self.interface = interface

    def scan(self, ap: AccessPoint) -> ActiveScanResult:
        """Run full active scan on an open AP. Returns results even on partial failure."""
        start = time.monotonic()
        result = ActiveScanResult(bssid=ap.bssid, ssid=ap.display_ssid)

        def _timed_out() -> bool:
            return (time.monotonic() - start) >= OVERALL_TIMEOUT

        try:
            # Step 1: Connect
            if not self._connect(ap):
                result.error = "Failed to connect to AP"
                return result
            result.connected = True

            if _timed_out():
                result.error = "Overall timeout exceeded after connect"
                return result

            # Step 2: DHCP
            if not self._acquire_dhcp():
                result.error = "DHCP failed — no IP assigned"
                self._disconnect()
                return result

            if _timed_out():
                result.error = "Overall timeout exceeded after DHCP"
                return result

            # Step 3: Parse network info
            self._parse_network_info(result)

            # Step 4: Resolve gateway MAC
            if result.gateway_ip and not _timed_out():
                self._resolve_gateway_mac(result)

            # Step 5: ARP scan (best-effort)
            if result.assigned_ip and result.subnet_mask and not _timed_out():
                try:
                    self._arp_scan(result)
                except Exception as e:
                    logger.warning("ARP scan failed: %s", e)

            # Step 6: Port scan gateway (best-effort)
            if result.gateway_ip and not _timed_out():
                try:
                    self._port_scan(result)
                except Exception as e:
                    logger.warning("Port scan failed: %s", e)

        except Exception as e:
            result.error = str(e)
            logger.error("Active scan error: %s", e)
        finally:
            result.duration_secs = round(time.monotonic() - start, 1)
            self._disconnect()

        return result

    # --- Connection ---

    def _connect(self, ap: AccessPoint) -> bool:
        """Connect to an open AP using iw, falling back to wpa_supplicant."""
        ssid = ap.ssid
        if not ssid:
            logger.warning("Cannot connect: AP has empty/hidden SSID")
            return False

        # Prevent NetworkManager from grabbing the interface while we connect.
        self._run(
            ["nmcli", "device", "set", self.interface, "managed", "no"],
            timeout=5, ignore_errors=True,
        )

        # Trigger a scan so the AP appears in the driver's BSS list.
        # Without this, 'iw connect' often fails with "not found" because
        # the driver has no cached scan results after a mode switch.
        logger.info("Scanning for %s on %s ...", ssid, self.interface)
        scan_ret = self._run(
            ["iw", "dev", self.interface, "scan"],
            timeout=15, ignore_errors=True,
        )
        if ssid in scan_ret.stdout:
            logger.info("AP '%s' found in scan results", ssid)
        else:
            logger.warning("AP '%s' not found in scan results — connecting anyway", ssid)

        # Method 1: iw connect with BSSID + frequency for precise targeting
        freq = str(ap.frequency) if ap.frequency else ""
        iw_cmd = ["iw", "dev", self.interface, "connect", ssid]
        if freq:
            iw_cmd.append(freq)
        iw_cmd.append(ap.bssid)

        logger.info("Attempting: %s", " ".join(iw_cmd))
        ret = self._run(iw_cmd, timeout=CONNECT_TIMEOUT)
        if ret.returncode == 0:
            for _ in range(5):
                time.sleep(1)
                if self._is_connected():
                    logger.info("Connected to %s via iw", ssid)
                    return True
            logger.info("iw connect returned 0 but not associated after 5s")
        else:
            logger.info("iw connect failed: %s", ret.stderr.strip())

        # Method 2: wpa_supplicant with key_mgmt=NONE + bssid
        logger.info("Falling back to wpa_supplicant for '%s' ...", ssid)
        # Sanitize SSID for wpa_supplicant config (escape \ and " to prevent injection)
        safe_ssid = ssid.replace("\\", "\\\\").replace('"', '\\"')
        conf = (
            f'network={{\n'
            f'  ssid="{safe_ssid}"\n'
            f'  bssid={ap.bssid}\n'
            f'  key_mgmt=NONE\n'
            f'  scan_ssid=1\n'
            f'}}\n'
        )
        conf_path = Path(f"/tmp/ap_scanner_wpa_{self.interface}.conf")
        conf_path.write_text(conf)

        # Kill any existing wpa_supplicant on this interface
        self._run(["pkill", "-f", f"wpa_supplicant.*{self.interface}"],
                  timeout=3, ignore_errors=True)
        time.sleep(0.5)

        ret = self._run(
            ["wpa_supplicant", "-B", "-i", self.interface,
             "-c", str(conf_path), "-D", "nl80211"],
            timeout=CONNECT_TIMEOUT, ignore_errors=True,
        )
        logger.info("wpa_supplicant launch: rc=%d stderr=%s",
                     ret.returncode, ret.stderr.strip())

        for _ in range(8):
            time.sleep(1)
            if self._is_connected():
                logger.info("Connected to %s via wpa_supplicant", ssid)
                return True

        # Log diagnostics on failure
        link = self._run(["iw", "dev", self.interface, "link"],
                         timeout=5, ignore_errors=True)
        logger.warning(
            "Failed to connect to %s — link status: %s",
            ssid, link.stdout.strip(),
        )
        return False

    def _is_connected(self) -> bool:
        """Check if interface is associated to an AP."""
        ret = self._run(["iw", "dev", self.interface, "link"], timeout=5)
        return ret.returncode == 0 and "Connected to" in ret.stdout

    # --- DHCP ---

    def _acquire_dhcp(self) -> bool:
        """Acquire an IP via DHCP (dhclient, falling back to udhcpc)."""
        # Try dhclient
        ret = self._run(
            ["dhclient", "-1", "-v", "-timeout", str(DHCP_TIMEOUT), self.interface],
            timeout=DHCP_TIMEOUT + 5, ignore_errors=True,
        )
        if ret.returncode == 0 and self._has_ip():
            logger.info("DHCP lease acquired via dhclient")
            return True

        # Fallback: udhcpc
        ret = self._run(
            ["udhcpc", "-i", self.interface, "-t", "5", "-T", "3", "-n", "-q"],
            timeout=DHCP_TIMEOUT + 5, ignore_errors=True,
        )
        if ret.returncode == 0 and self._has_ip():
            logger.info("DHCP lease acquired via udhcpc")
            return True

        logger.warning("DHCP failed on %s", self.interface)
        return False

    def _has_ip(self) -> bool:
        """Check if the interface has an IPv4 address."""
        ret = self._run(["ip", "-4", "addr", "show", self.interface], timeout=5)
        return "inet " in ret.stdout

    # --- Network info parsing ---

    def _parse_network_info(self, result: ActiveScanResult) -> None:
        """Parse IP, subnet, gateway, DNS from system commands."""
        # IP and subnet
        ret = self._run(["ip", "-4", "addr", "show", self.interface], timeout=5)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", ret.stdout)
        if m:
            result.assigned_ip = m.group(1)
            result.subnet_mask = _cidr_to_netmask(int(m.group(2)))

        # Default gateway
        ret = self._run(["ip", "route", "show", "dev", self.interface], timeout=5)
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", ret.stdout)
        if m:
            result.gateway_ip = m.group(1)

        # DNS servers
        try:
            resolv = Path("/etc/resolv.conf").read_text()
            result.dns_servers = re.findall(r"nameserver\s+(\d+\.\d+\.\d+\.\d+)", resolv)
        except OSError:
            pass

        # DHCP server (from dhclient lease file)
        for lease_path in Path("/var/lib/dhcp").glob("*.leases"):
            try:
                content = lease_path.read_text()
                m = re.search(r"dhcp-server-identifier\s+(\d+\.\d+\.\d+\.\d+)", content)
                if m:
                    result.dhcp_server = m.group(1)
                    break
            except OSError:
                continue

    # --- ARP operations ---

    def _resolve_gateway_mac(self, result: ActiveScanResult) -> None:
        """Resolve gateway MAC via a single ARP request using scapy."""
        try:
            from scapy.all import ARP, Ether, sr1

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op="who-has", pdst=result.gateway_ip
            )
            resp = sr1(pkt, iface=self.interface, timeout=ARP_TIMEOUT, verbose=0)
            if resp and resp.haslayer(ARP):
                result.gateway_mac = resp[ARP].hwsrc
        except Exception as e:
            logger.warning("Gateway MAC resolution failed: %s", e)

    def _arp_scan(self, result: ActiveScanResult) -> None:
        """ARP scan the local subnet to discover connected clients."""
        from scapy.all import ARP, Ether, srp

        network = _calculate_network(result.assigned_ip, result.subnet_mask)
        if not network:
            return

        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op="who-has", pdst=network)
        answered, _ = srp(pkt, iface=self.interface, timeout=ARP_TIMEOUT, verbose=0)

        for _, recv in answered:
            if recv.haslayer(ARP):
                ip = recv[ARP].psrc
                mac = recv[ARP].hwsrc
                # Skip our own IP
                if ip == result.assigned_ip:
                    continue
                result.clients.append(ActiveScanClient(ip=ip, mac=mac))

    # --- Port scan ---

    def _port_scan(self, result: ActiveScanResult) -> None:
        """TCP connect scan on common gateway ports."""
        for port in GATEWAY_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(PORT_SCAN_TIMEOUT)
                    if sock.connect_ex((result.gateway_ip, port)) == 0:
                        result.gateway_open_ports.append(port)
            except (OSError, socket.error):
                pass

    # --- Disconnect / Cleanup ---

    def _disconnect(self) -> None:
        """Release DHCP, kill wpa_supplicant, disconnect, flush IP."""
        self._run(["dhclient", "-r", self.interface],
                  timeout=5, ignore_errors=True)
        self._run(["pkill", "-f", f"wpa_supplicant.*{self.interface}"],
                  timeout=3, ignore_errors=True)
        self._run(["iw", "dev", self.interface, "disconnect"],
                  timeout=5, ignore_errors=True)
        self._run(["ip", "addr", "flush", "dev", self.interface],
                  timeout=5, ignore_errors=True)
        # Re-enable NetworkManager management
        self._run(["nmcli", "device", "set", self.interface, "managed", "yes"],
                  timeout=5, ignore_errors=True)
        # Clean up temp config
        conf_path = Path(f"/tmp/ap_scanner_wpa_{self.interface}.conf")
        conf_path.unlink(missing_ok=True)

    # --- Utilities ---

    @staticmethod
    def _run(
        cmd: list[str],
        timeout: int = 10,
        ignore_errors: bool = False,
    ) -> subprocess.CompletedProcess:
        """Run a command, returning CompletedProcess."""
        try:
            return subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
        except FileNotFoundError:
            if not ignore_errors:
                raise
            return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
        except subprocess.TimeoutExpired:
            if not ignore_errors:
                raise
            return subprocess.CompletedProcess(cmd, 124, "", "timeout")


# --- Module-level utility functions ---

def _cidr_to_netmask(prefix: int) -> str:
    """Convert CIDR prefix length to dotted netmask (e.g. 24 -> 255.255.255.0)."""
    bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return socket.inet_ntoa(struct.pack("!I", bits))


def _calculate_network(ip: str, netmask: str) -> str:
    """Calculate network address in CIDR notation for ARP scan target."""
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
        net_int = ip_int & mask_int
        # Count prefix bits
        prefix = bin(mask_int).count("1")
        net_addr = socket.inet_ntoa(struct.pack("!I", net_int))
        return f"{net_addr}/{prefix}"
    except (OSError, struct.error):
        return ""


def _is_ip(s: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_aton(s)
        parts = s.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (OSError, ValueError):
        return False
