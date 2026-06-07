"""
WiFi Network Scanner Module

Scans for wireless networks by sniffing beacon and probe response frames.
Detects SSID, BSSID, channel, signal strength, encryption type, and PMF status.
"""

import os
import re
import subprocess
import sys
import time
from typing import List, Dict, Optional

# Scapy imports with fallback
try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


def get_wireless_interfaces() -> List[str]:
    """
    Detect available wireless interfaces on the system.
    Supports Linux (iwconfig/iw), Windows (netsh), and macOS (networksetup).
    """
    interfaces = []

    if sys.platform.startswith("linux"):
        # Linux: use iwconfig or iw
        try:
            result = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "IEEE 802.11" in line:
                    iface = line.split()[0]
                    if iface:
                        interfaces.append(iface)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: list wireless interfaces via iw dev
        if not interfaces:
            try:
                result = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "Interface" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            interfaces.append(parts[-1])
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Last resort: list all 'wl' prefixed interfaces from /sys
        if not interfaces:
            try:
                for entry in os.listdir("/sys/class/net"):
                    if entry.startswith("wl"):
                        interfaces.append(entry)
            except FileNotFoundError:
                pass

    elif sys.platform == "win32":
        # Windows: use netsh wlan
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Name"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        iface_name = parts[1].strip()
                        interfaces.append(iface_name)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif sys.platform == "darwin":
        # macOS
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split("\n")
            capture_next = False
            for line in lines:
                if "Wi-Fi" in line or "AirPort" in line:
                    capture_next = True
                elif capture_next and "Device" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        interfaces.append(parts[1].strip())
                    capture_next = False
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return interfaces


def enable_monitor_mode(interface: str) -> bool:
    """Attempt to enable monitor mode on the interface (Linux only)."""
    if not sys.platform.startswith("linux"):
        print("[!] Monitor mode is only supported on Linux.")
        print("    On Windows/macOS, use managed-mode scanning (limited).")
        return False

    try:
        # Bring interface down
        subprocess.run(["ip", "link", "set", interface, "down"],
                       capture_output=True, timeout=5)
        # Set monitor mode
        subprocess.run(["iw", "dev", interface, "set", "type", "monitor"],
                       capture_output=True, timeout=5)
        # Bring interface up
        subprocess.run(["ip", "link", "set", interface, "up"],
                       capture_output=True, timeout=5)
        return True
    except Exception as e:
        print(f"[VERBOSE] Failed to set monitor mode: {e}")
        return False


def disable_monitor_mode(interface: str):
    """Restore managed mode on the interface."""
    if not sys.platform.startswith("linux"):
        return
    try:
        subprocess.run(["ip", "link", "set", interface, "down"],
                       capture_output=True, timeout=5)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                       capture_output=True, timeout=5)
        subprocess.run(["ip", "link", "set", interface, "up"],
                       capture_output=True, timeout=5)
    except Exception:
        pass


def parse_encryption_from_capabilities(cap: str, rsn_ie: bool = False) -> str:
    """
    Determine encryption type from capabilities and RSN information.
    Returns a short string like 'WPA2', 'WPA3', 'WPA2/3', 'OPEN', 'WEP'.
    """
    if rsn_ie:
        # Check for WPA3/SAE capabilities in RSN
        if "SAE" in cap or "00-0F-AC:8" in cap:
            return "WPA3"
        if "00-0F-AC:4" in cap:  # CCMP
            return "WPA2"
        return "WPA2"
    if "WPA" in cap:
        return "WPA"
    if "WEP" in cap:
        return "WEP"
    return "OPEN"


def scan_networks(interface: str, scan_time: int = 5,
                  verbose: bool = False) -> List[Dict]:
    """
    Scan for WiFi networks by sniffing beacon frames.
    Returns a list of dicts with network information.

    Uses scapy for packet capture. Falls back to system commands if scapy
    is unavailable.
    """
    if not HAVE_SCAPY:
        print("[!] Scapy not installed. Falling back to system command scanning.")
        return scan_networks_system(interface, scan_time, verbose)

    networks: Dict[str, Dict] = {}
    start_time = time.time()

    def packet_handler(pkt):
        """Process each captured packet."""
        nonlocal start_time

        # Check if we have a Dot11 layer
        if not pkt.haslayer(Dot11):
            return

        # Look for Beacon or Probe Response frames
        is_beacon = pkt.haslayer(Dot11Beacon)
        is_probe_resp = pkt.haslayer(Dot11ProbeResp)

        if not (is_beacon or is_probe_resp):
            return

        # Extract BSSID (source MAC)
        bssid = pkt.addr2
        if not bssid:
            return

        # Extract SSID from Dot11Elt
        ssid = ""
        channel = None
        rsn_present = False
        rsn_capabilities = ""

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    ssid = "<non-printable>"
            elif elt.ID == 3:  # Channel (DS Parameter Set)
                if len(elt.info) > 0:
                    channel = int.from_bytes(elt.info[:1], "little")

            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

        # Skip hidden SSID probes
        if not ssid or ssid == "":
            return

        # Get signal strength from RadioTap
        signal = -100
        if pkt.haslayer(RadioTap):
            try:
                rt = pkt.getlayer(RadioTap)
                if hasattr(rt, 'dBm_AntSignal') and rt.dBm_AntSignal is not None:
                    signal = int(rt.dBm_AntSignal)
                elif hasattr(rt, 'AntennaSignal') and rt.AntennaSignal is not None:
                    signal = int(rt.AntennaSignal) - 256 if int(rt.AntennaSignal) > 128 else int(rt.AntennaSignal)
            except (ValueError, TypeError):
                pass

        # Detect encryption and PMF from RSN element
        encryption = "?"
        pmf = False

        # Check RSN IE and Vendor-specific IEs
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            # RSN Information Element (ID=48)
            if elt.ID == 48:
                rsn_present = True
                info = elt.info.hex() if hasattr(elt.info, 'hex') else ''
                # RSN capabilities: bytes after pairwise/group cipher suites
                # Typically at offset depends on auth key management count
                # PMF is indicated by RSN capabilities bit 7 (Management Frame Protection Required)
                # and bit 6 (Management Frame Protection Capable)

                if len(elt.info) >= 8:
                    # RSN capabilities are at variable offsets; simplest detection:
                    rsn_bytes = bytes(elt.info)
                    if len(rsn_bytes) > 6:
                        # AKM count at offset 4 * (group_cipher_count = 1) + 4 = 8
                        # Actually parse properly:
                        try:
                            # Group cipher suite: 4 bytes for OUI + 1 byte type = starting at offset 2
                            gc_count = int.from_bytes(rsn_bytes[2:4], 'little')
                            pairwise_offset = 4 + gc_count * 4
                            pw_count = int.from_bytes(rsn_bytes[pairwise_offset:pairwise_offset + 2], 'little')
                            akm_offset = pairwise_offset + 2 + pw_count * 4
                            ak_count = int.from_bytes(rsn_bytes[akm_offset:akm_offset + 2], 'little')
                            rsn_cap_offset = akm_offset + 2 + ak_count * 4

                            if len(rsn_bytes) >= rsn_cap_offset + 2:
                                rsn_cap = int.from_bytes(rsn_bytes[rsn_cap_offset:rsn_cap_offset + 2], 'little')
                                # Bit 7 (0x40) = MFP Required
                                # Bit 6 (0x20) = MFP Capable
                                pmf = bool(rsn_cap & 0x60)
                        except Exception:
                            pass

                    # Detect WPA3 via AKM suite type 8 (SAE)
                    if b'\x00\x0f\xac\x08' in rsn_bytes:
                        encryption = "WPA3"
                    elif b'\x00\x0f\xac\x04' in rsn_bytes:
                        encryption = "WPA2"
                    elif b'\x00\x0f\xac\x01' in rsn_bytes:
                        encryption = "WPA"
                    elif b'\x00\x0f\xac\x02' in rsn_bytes:
                        encryption = "WPA"

            # WPA IE (Vendor-specific with WPA OUI)
            if elt.ID == 221 and hasattr(elt, 'info'):
                info = bytes(elt.info) if hasattr(elt.info, '__iter__') else b''
                if info[:4] == b'\x00P\xf2\x01':  # Microsoft WPA OUI
                    if encryption == "?":
                        encryption = "WPA"

            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None

        if encryption == "?":
            encryption = "OPEN"

        if verbose:
            print(f"[VERBOSE] Found network: {ssid} ({bssid}) CH:{channel} "
                  f"SIG:{signal}dBm ENCR:{encryption} PMF:{pmf}")

        # Store or update network info (keep best signal)
        if bssid not in networks or signal > networks[bssid].get("signal", -100):
            networks[bssid] = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel or 0,
                "signal": signal,
                "encryption": encryption,
                "pmf": pmf,
            }

    # Start sniffing
    print(f"[*] Sniffing on {interface} for {scan_time} seconds...")
    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=0,
            timeout=scan_time,
            monitor=True,
        )
    except PermissionError:
        print("[!] Permission denied. Run as root/administrator.")
        return []
    except Exception as e:
        print(f"[!] Error during sniffing: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        return []

    if verbose:
        print(f"[VERBOSE] Scan completed. Found {len(networks)} unique networks.")

    # Sort by signal strength (descending)
    result = sorted(networks.values(), key=lambda n: n.get("signal", -100), reverse=True)
    return result


def scan_networks_system(interface: str, scan_time: int = 5,
                          verbose: bool = False) -> List[Dict]:
    """
    Fallback scanner using system commands (iw dev scan on Linux,
    netsh wlan show networks on Windows).
    """
    networks = []

    if sys.platform.startswith("linux"):
        try:
            # Trigger scan
            subprocess.run(
                ["iw", "dev", interface, "scan", "-u"],
                capture_output=True, timeout=scan_time + 5
            )

            # Parse scan results
            result = subprocess.run(
                ["iw", "dev", interface, "scan"],
                capture_output=True, text=True, timeout=10
            )

            current = {}
            for line in result.stdout.split("\n"):
                line = line.strip()

                if line.startswith("BSS "):
                    if current and "ssid" in current:
                        networks.append(current)
                    bssid = line.split()[1].strip("()")
                    current = {"bssid": bssid, "ssid": "", "channel": 0,
                               "signal": -100, "encryption": "?", "pmf": False}

                elif "SSID:" in line and current:
                    parts = line.split("SSID:", 1)
                    if len(parts) == 2:
                        current["ssid"] = parts[1].strip()

                elif "freq:" in line and current:
                    parts = line.split("freq:", 1)
                    if len(parts) == 2:
                        freq = int(parts[1].strip())
                        # Convert frequency to channel
                        if 2412 <= freq <= 2484:
                            current["channel"] = (freq - 2412) // 5 + 1
                        elif 5180 <= freq <= 5825:
                            current["channel"] = (freq - 5180) // 5 + 36

                elif "signal:" in line and current:
                    parts = line.split("signal:", 1)
                    if len(parts) == 2:
                        try:
                            current["signal"] = int(float(parts[1].strip().split()[0]))
                        except (ValueError, IndexError):
                            pass

                elif "RSN:" in line or "WPA:" in line:
                    if current:
                        current["encryption"] = "WPA2" if "RSN" in line else "WPA"

                elif "* Authentication suites:" in line and current:
                    if "SAE" in line:
                        current["encryption"] = "WPA3"

                # PMF detection via RSN capabilities
                elif "Capabilities:" in line and current and "0x" in line:
                    try:
                        cap_str = line.split("Capabilities:")[1].strip()
                        cap_val = int(cap_str, 16)
                        # 0x40 = MFP Required, 0x20 = MFP Capable
                        current["pmf"] = bool(cap_val & 0x60)
                    except (ValueError, IndexError):
                        pass

            if current and "ssid" in current:
                networks.append(current)

        except FileNotFoundError:
            print("[!] iw command not found. Install iw with: apt install iw")
        except subprocess.TimeoutExpired:
            print("[!] Scan timed out.")

    elif sys.platform == "win32":
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=15
            )
            current = {}
            for line in result.stdout.split("\n"):
                line = line.strip()

                if line.startswith("SSID"):
                    if current and "ssid" in current:
                        networks.append(current)
                    current = {"ssid": line.split(":", 1)[1].strip() if ":" in line else "",
                               "bssid": "", "channel": 0, "signal": -100,
                               "encryption": "?", "pmf": False}

                elif "BSSID" in line and current:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        current["bssid"] = parts[1].strip()

                elif "Channel" in line and current:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        try:
                            current["channel"] = int(parts[1].strip())
                        except ValueError:
                            pass

                elif "Signal" in line and current:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        sig_str = parts[1].strip().replace("%", "")
                        try:
                            sig_pct = int(sig_str)
                            # Convert percentage to approximate dBm
                            current["signal"] = -100 + (sig_pct // 2)
                        except ValueError:
                            pass

                elif "Authentication" in line and current:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        auth = parts[1].strip()
                        if "WPA3" in auth or "SAE" in auth:
                            current["encryption"] = "WPA3"
                        elif "WPA2" in auth:
                            current["encryption"] = "WPA2"
                        elif "WPA" in auth:
                            current["encryption"] = "WPA"
                        elif "Open" in auth:
                            current["encryption"] = "OPEN"

            if current and "ssid" in current:
                networks.append(current)

        except FileNotFoundError:
            print("[!] netsh not found.")
        except subprocess.TimeoutExpired:
            print("[!] netsh scan timed out.")

    # Sort by signal
    networks.sort(key=lambda n: n.get("signal", -100), reverse=True)
    return networks
