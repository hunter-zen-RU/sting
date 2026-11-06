"""WiFi network scanner.

Captures beacon and probe-response frames with Scapy and extracts SSID,
BSSID, channel, signal strength, encryption type, PMF and WPS information.
When Scapy is unavailable, falls back to ``iw``/``netsh``.
"""

import importlib.util
import re
import subprocess
import sys
import threading
import time
from typing import Dict, List, Optional

from sting.ieee80211 import (
    channel_from_frequency,
    classify_security,
    parse_rsn_ie,
    parse_wpa_ie,
)
from sting.system import get_interface_mode, get_wireless_interfaces, set_channel

# Scapy is imported lazily so commands that do not capture packets (version,
# help, education, interface listing) start quickly and quietly.
HAVE_SCAPY = importlib.util.find_spec("scapy") is not None

Dot11 = Dot11Beacon = Dot11Elt = Dot11ProbeResp = RadioTap = sniff = None


def _load_scapy() -> bool:
    """Import Scapy on first use. Returns True when it is available."""
    global Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap, sniff
    if sniff is not None:
        return True
    if not HAVE_SCAPY:
        return False
    try:
        from scapy.all import (
            Dot11 as scapy_dot11,
            Dot11Beacon as scapy_beacon,
            Dot11Elt as scapy_elt,
            Dot11ProbeResp as scapy_probe_resp,
            RadioTap as scapy_radiotap,
            sniff as scapy_sniff,
        )
    except ImportError:
        return False
    Dot11 = scapy_dot11
    Dot11Beacon = scapy_beacon
    Dot11Elt = scapy_elt
    Dot11ProbeResp = scapy_probe_resp
    RadioTap = scapy_radiotap
    sniff = scapy_sniff
    return True


# Re-exported for backwards compatibility.
__all__ = [
    "HAVE_SCAPY",
    "get_wireless_interfaces",
    "scan_networks",
    "scan_networks_system",
]


# ---------------------------------------------------------------------------
# Scapy helpers
# ---------------------------------------------------------------------------

def _as_bytes(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("latin-1", errors="replace")
    try:
        return bytes(value)
    except (TypeError, ValueError):
        return b""


def _extract_frequency(pkt) -> Optional[int]:
    if RadioTap is None or not pkt.haslayer(RadioTap):
        return None
    radiotap = pkt.getlayer(RadioTap)
    frequency = getattr(radiotap, "ChannelFrequency", None)
    if frequency is None:
        return None
    try:
        frequency = int(frequency)
    except (TypeError, ValueError):
        return None
    return frequency if 2400 <= frequency <= 7125 else None


def _extract_signal(pkt) -> int:
    if RadioTap is None or not pkt.haslayer(RadioTap):
        return -100
    radiotap = pkt.getlayer(RadioTap)
    value = getattr(radiotap, "dBm_AntSignal", None)
    if value is None:
        value = getattr(radiotap, "AntennaSignal", None)
    if value is None:
        return -100
    try:
        signal = int(value)
    except (TypeError, ValueError):
        return -100
    # Raw radiotap antenna signal is an unsigned byte.
    if signal > 127:
        signal -= 256
    return max(-128, min(127, signal))


def _capability_field(pkt) -> int:
    layer = None
    if Dot11Beacon is not None and pkt.haslayer(Dot11Beacon):
        layer = pkt.getlayer(Dot11Beacon)
    elif Dot11ProbeResp is not None and pkt.haslayer(Dot11ProbeResp):
        layer = pkt.getlayer(Dot11ProbeResp)
    if layer is None:
        return 0
    try:
        return int(getattr(layer, "cap", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _iter_elements(pkt):
    element = pkt.getlayer(Dot11Elt)
    while element is not None:
        yield element
        payload = element.payload
        element = payload.getlayer(Dot11Elt) if hasattr(payload, "getlayer") else None


def _process_packet(pkt, networks: Dict[str, Dict], verbose: bool,
                    include_hidden: bool) -> None:
    if Dot11 is None or not pkt.haslayer(Dot11):
        return
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return

    bssid = getattr(pkt, "addr2", None)
    if not bssid:
        return
    bssid = str(bssid).lower()

    ssid = ""
    ds_channel = 0
    rsn_bytes = b""
    wpa_bytes = b""
    wps = False

    for element in _iter_elements(pkt):
        element_id = getattr(element, "ID", None)
        info = _as_bytes(getattr(element, "info", b""))
        if element_id == 0:  # SSID
            ssid = info.decode("utf-8", errors="replace").rstrip("\x00")
        elif element_id == 3:  # DS Parameter Set
            if info:
                ds_channel = info[0]
        elif element_id == 48:  # RSN
            rsn_bytes = info
        elif element_id == 221:  # Vendor specific
            if info[:4] == b"\x00\x50\xf2\x01":
                wpa_bytes = info
            elif info[:4] == b"\x00\x50\xf2\x04":
                wps = True

    hidden = not ssid
    if hidden and not include_hidden:
        return

    frequency = _extract_frequency(pkt)
    channel = ds_channel or channel_from_frequency(frequency)
    signal = _extract_signal(pkt)
    privacy = bool(_capability_field(pkt) & 0x0010)

    rsn = parse_rsn_ie(rsn_bytes) if rsn_bytes else None
    wpa = parse_wpa_ie(wpa_bytes) if wpa_bytes else None
    encryption = classify_security(rsn, wpa, privacy)

    entry = {
        "ssid": ssid or "<hidden>",
        "hidden": hidden,
        "bssid": bssid,
        "channel": int(channel or 0),
        "frequency": int(frequency or 0),
        "signal": signal,
        "encryption": encryption,
        "pmf": bool(rsn and rsn.get("pmf")),
        "pmf_required": bool(rsn and rsn.get("pmf_required")),
        "pmf_capable": bool(rsn and rsn.get("pmf_capable")),
        "wps": wps,
        "last_seen": time.time(),
    }

    if verbose:
        print(
            f"[VERBOSE] {entry['ssid']} ({entry['bssid']}) "
            f"CH:{entry['channel']} SIG:{entry['signal']}dBm "
            f"ENCR:{entry['encryption']} PMF:{entry['pmf']} WPS:{entry['wps']}"
        )

    existing = networks.get(bssid)
    if existing is not None and existing.get("signal", -100) >= signal:
        return
    networks[bssid] = entry


def _hop_channels(interface: str, channels: List[int], dwell: float,
                  stop_event: threading.Event, verbose: bool) -> None:
    """Background thread that cycles through channels while sniffing."""
    index = 0
    failures = 0
    while not stop_event.is_set():
        channel = channels[index % len(channels)]
        index += 1
        if set_channel(interface, channel):
            failures = 0
        else:
            failures += 1
            if failures >= min(3, len(channels)):
                if verbose:
                    print("[VERBOSE] Channel hopping disabled "
                          "(could not tune the interface).")
                return
        if stop_event.wait(dwell):
            return


def _start_hopping(interface: str, channels: Optional[List[int]], dwell: float,
                   verbose: bool):
    """Start channel hopping when the interface supports it."""
    if not channels or len(channels) <= 1:
        return None, None

    mode = get_interface_mode(interface)
    if mode not in (None, "monitor"):
        if verbose:
            print(f"[VERBOSE] Not hopping: interface {interface} is in {mode} mode.")
        return None, None

    stop_event = threading.Event()
    thread = threading.Thread(
        target=_hop_channels,
        args=(interface, channels, max(0.05, dwell), stop_event, verbose),
        daemon=True,
        name="sting-channel-hop",
    )
    thread.start()
    return thread, stop_event


def _stop_hopping(thread, stop_event) -> None:
    if stop_event is not None:
        stop_event.set()
    if thread is not None:
        thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Public scan API
# ---------------------------------------------------------------------------

def scan_networks(interface: str, scan_time: float = 10, verbose: bool = False,
                  channels: Optional[List[int]] = None, dwell: float = 0.25,
                  hop: bool = True, include_hidden: bool = True) -> List[Dict]:
    """Scan for WiFi networks.

    Args:
        interface: Wireless interface name.
        scan_time: Total capture time in seconds.
        verbose: Print per-network details.
        channels: Optional channel list used for hopping.
        dwell: Seconds to spend on each channel.
        hop: Set to False to disable channel hopping.
        include_hidden: Include networks with a hidden/empty SSID.
    """
    if not HAVE_SCAPY:
        print("[!] Scapy not installed. Falling back to system command scanning.")
        return scan_networks_system(interface, scan_time, verbose,
                                    include_hidden=include_hidden)
    if not _load_scapy():
        print("[!] Scapy could not be imported. Falling back to system scanning.")
        return scan_networks_system(interface, scan_time, verbose,
                                    include_hidden=include_hidden)

    networks: Dict[str, Dict] = {}
    thread = None
    stop_event = None
    if hop:
        thread, stop_event = _start_hopping(interface, channels, dwell, verbose)

    print(f"[*] Sniffing on {interface} for {scan_time:g} seconds...")

    sniff_kwargs = dict(iface=interface, prn=lambda pkt: _process_packet(
        pkt, networks, verbose, include_hidden), store=0, timeout=scan_time)

    try:
        try:
            sniff(monitor=False, **sniff_kwargs)
        except TypeError:
            # Older Scapy versions do not accept the ``monitor`` kwarg.
            sniff(**sniff_kwargs)
    except PermissionError:
        print("[!] Permission denied. Run as root/administrator.")
        return []
    except OSError as exc:
        print(f"[!] Could not capture on {interface}: {exc}")
        return []
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        print(f"[!] Error during sniffing: {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        return []
    finally:
        _stop_hopping(thread, stop_event)

    if verbose:
        print(f"[VERBOSE] Scan completed. Found {len(networks)} unique networks.")

    return sorted(networks.values(), key=lambda net: net.get("signal", -100),
                  reverse=True)


# ---------------------------------------------------------------------------
# System-command fallback
# ---------------------------------------------------------------------------

def _parse_iw_scan_output(output: str, include_hidden: bool) -> List[Dict]:
    networks: Dict[str, Dict] = {}
    blocks = re.split(r"(?m)^BSS\s+", output)

    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines:
            continue
        bssid = lines[0].strip().split("(")[0].strip().lower()
        if not bssid:
            continue

        ssid = ""
        frequency = 0
        signal = -100
        channel = 0
        privacy = False
        wps = False
        rsn_present = False
        wpa_present = False
        in_rsn = False
        akms: List[str] = []
        capabilities = 0

        for raw_line in lines[1:]:
            line = raw_line.strip()
            if line.startswith("* "):
                line = line[2:].strip()

            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("freq:"):
                try:
                    frequency = int(float(line.split(":", 1)[1].strip()))
                except (ValueError, IndexError):
                    pass
            elif line.startswith("signal:"):
                try:
                    signal = int(float(line.split(":", 1)[1].strip().split()[0]))
                except (ValueError, IndexError):
                    pass
            elif line.startswith("capability:"):
                privacy = "Privacy" in line
            elif line.startswith("DS Parameter set:"):
                match = re.search(r"channel\s+(\d+)", line)
                if match:
                    channel = int(match.group(1))
            elif line.startswith("RSN:"):
                rsn_present = True
                in_rsn = True
            elif line.startswith("WPA:"):
                wpa_present = True
                in_rsn = False
            elif line.startswith("WPS:"):
                wps = True
            elif in_rsn and line.startswith("Authentication suites:"):
                value = line.split(":", 1)[1]
                for akm in ("SAE", "OWE", "PSK", "802.1X"):
                    if akm in value and akm not in akms:
                        akms.append(akm)
            elif in_rsn and line.startswith("Capabilities:"):
                match = re.search(r"0x([0-9a-fA-F]+)", line)
                if match:
                    capabilities = int(match.group(1), 16)

        hidden = not ssid
        if hidden and not include_hidden:
            continue

        channel = channel or channel_from_frequency(frequency)
        rsn = None
        wpa = None
        if rsn_present:
            rsn = {
                "akms": akms,
                "pairwise_ciphers": ["CCMP"],
                "pmf_required": bool(capabilities & 0x0040),
                "pmf_capable": bool(capabilities & 0x0080),
                "pmf": bool(capabilities & 0x00C0),
            }
        if wpa_present:
            wpa = {"akms": ["PSK"], "pairwise_ciphers": ["TKIP"]}

        encryption = classify_security(rsn, wpa, privacy)
        entry = {
            "ssid": ssid or "<hidden>",
            "hidden": hidden,
            "bssid": bssid,
            "channel": int(channel or 0),
            "frequency": frequency,
            "signal": signal,
            "encryption": encryption,
            "pmf": bool(rsn and rsn.get("pmf")),
            "pmf_required": bool(rsn and rsn.get("pmf_required")),
            "pmf_capable": bool(rsn and rsn.get("pmf_capable")),
            "wps": wps,
            "last_seen": time.time(),
        }

        existing = networks.get(bssid)
        if existing is None or signal > existing.get("signal", -100):
            networks[bssid] = entry

    return sorted(networks.values(), key=lambda net: net.get("signal", -100),
                  reverse=True)


def _parse_netsh_output(output: str, include_hidden: bool) -> List[Dict]:
    networks: Dict[str, Dict] = {}
    current: Optional[Dict] = None

    def finish():
        nonlocal current
        if current and current.get("bssid"):
            bssid = current["bssid"].lower()
            existing = networks.get(bssid)
            if existing is None or current.get("signal", -100) > existing.get("signal", -100):
                networks[bssid] = current
        current = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            finish()
            ssid = line.split(":", 1)[1].strip() if ":" in line else ""
            if not ssid and not include_hidden:
                current = None
                continue
            current = {
                "ssid": ssid or "<hidden>",
                "hidden": not ssid,
                "bssid": "",
                "channel": 0,
                "frequency": 0,
                "signal": -100,
                "encryption": "?",
                "pmf": False,
                "pmf_required": False,
                "pmf_capable": False,
                "wps": False,
                "last_seen": time.time(),
            }
        elif current is not None and "BSSID" in line:
            current["bssid"] = line.split(":", 1)[1].strip()
        elif current is not None and "Channel" in line:
            try:
                current["channel"] = int(line.split(":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif current is not None and "Signal" in line:
            try:
                percent = int(line.split(":", 1)[1].strip().replace("%", ""))
                current["signal"] = -100 + (percent // 2)
            except (ValueError, IndexError):
                pass
        elif current is not None and "Authentication" in line:
            auth = line.split(":", 1)[1].strip() if ":" in line else ""
            if "WPA3" in auth or "SAE" in auth:
                current["encryption"] = "WPA3"
            elif "WPA2" in auth:
                current["encryption"] = "WPA2"
            elif "WPA" in auth:
                current["encryption"] = "WPA"
            elif "Open" in auth:
                current["encryption"] = "OPEN"

    finish()
    return sorted(networks.values(), key=lambda net: net.get("signal", -100),
                  reverse=True)


def scan_networks_system(interface: str, scan_time: float = 10,
                         verbose: bool = False,
                         include_hidden: bool = True) -> List[Dict]:
    """Fallback scanner using ``iw`` (Linux) or ``netsh`` (Windows)."""
    if sys.platform.startswith("linux"):
        try:
            subprocess.run(["iw", "dev", interface, "scan", "-u"],
                           capture_output=True, timeout=scan_time + 5)
            result = subprocess.run(["iw", "dev", interface, "scan"],
                                    capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            print("[!] iw command not found. Install iw with: apt install iw")
            return []
        except subprocess.TimeoutExpired:
            print("[!] Scan timed out.")
            return []

        if result.returncode != 0:
            message = result.stderr.strip() or "iw scan failed"
            print(f"[!] {message}")
            if "monitor" in message.lower() or "busy" in message.lower():
                print("    Tip: run without --no-monitor, or use managed mode.")
            return []

        networks = _parse_iw_scan_output(result.stdout, include_hidden)
        if verbose:
            print(f"[VERBOSE] iw scan found {len(networks)} networks.")
        return networks

    if sys.platform == "win32":
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            print("[!] netsh not found.")
            return []
        except subprocess.TimeoutExpired:
            print("[!] netsh scan timed out.")
            return []
        networks = _parse_netsh_output(result.stdout, include_hidden)
        if verbose:
            print(f"[VERBOSE] netsh scan found {len(networks)} networks.")
        return networks

    print(f"[!] System-command scanning is not supported on {sys.platform}.")
    return []
