"""Pure IEEE 802.11 helpers.

This module contains no OS or Scapy dependencies on purpose so that the
parsing logic can be unit-tested without root privileges or a wireless card.

Everything here deals with raw information elements, MAC addresses, channel
numbers, and frequency mapping.
"""

import re
from typing import Dict, Iterable, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

RSN_OUI = b"\x00\x0f\xac"
WPA_OUI = b"\x00\x50\xf2"

# RSN capabilities (IEEE 802.11-2020, 9.4.2.27)
PMF_REQUIRED = 0x0040  # Management Frame Protection Required (bit 6)
PMF_CAPABLE = 0x0080   # Management Frame Protection Capable (bit 7)

CIPHER_SUITES = {
    0: "Use-Group",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP",
    5: "WEP-104",
    8: "GCMP",
    9: "GCMP-256",
    10: "CCMP-256",
}

AKM_SUITES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    18: "OWE",
    24: "SAE-EXT",
    25: "FT-SAE-EXT",
}

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")

CHANNELS_24_GHZ: List[int] = list(range(1, 14))
CHANNELS_5_GHZ: List[int] = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
]
# 6 GHz uses 20 MHz channel numbers 1, 5, 9, ... 233 (plus wider channels).
CHANNELS_6_GHZ: List[int] = list(range(1, 234, 4))


# ---------------------------------------------------------------------------
# MAC addresses
# ---------------------------------------------------------------------------

def normalize_mac(mac: str) -> str:
    """Return a lower-case, colon-separated MAC address."""
    if not isinstance(mac, str):
        raise ValueError("MAC address must be a string")
    value = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(value):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return value


def is_valid_mac(mac: str) -> bool:
    """Return True when *mac* is a syntactically valid unicast/broadcast MAC."""
    try:
        normalize_mac(mac)
        return True
    except (ValueError, TypeError):
        return False


def is_broadcast_mac(mac: str) -> bool:
    """Return True when *mac* is the Ethernet/WiFi broadcast address."""
    try:
        return normalize_mac(mac) == BROADCAST_MAC
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Channels and frequencies
# ---------------------------------------------------------------------------

def channel_from_frequency(frequency: Optional[int]) -> int:
    """Convert a frequency in MHz to a WiFi channel number (0 if unknown)."""
    if frequency is None:
        return 0
    try:
        freq = int(frequency)
    except (TypeError, ValueError):
        return 0

    if 2412 <= freq <= 2484:
        return 14 if freq == 2484 else (freq - 2407) // 5
    if 5000 <= freq < 5925:
        return (freq - 5000) // 5
    if 5925 <= freq <= 7125:
        return (freq - 5950) // 5
    return 0


def frequency_from_channel(channel: int, band: Optional[str] = None) -> int:
    """Convert a channel number to MHz.

    ``band`` disambiguates the overlapping channel numbers used by 2.4 GHz,
    5 GHz and 6 GHz.  When omitted, values <= 14 are treated as 2.4 GHz and
    everything else as 5 GHz.
    """
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return 0
    if ch <= 0:
        return 0

    if band == "6":
        return 5950 + 5 * ch
    if band == "5":
        return 5000 + 5 * ch
    if band == "2.4":
        return 2484 if ch == 14 else 2407 + 5 * ch

    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2407 + 5 * ch
    return 5000 + 5 * ch


def parse_bands(spec: Optional[str]) -> List[str]:
    """Parse a ``--band`` style value into a list of band names."""
    if not spec:
        return ["2.4", "5"]
    if spec == "all":
        return ["2.4", "5", "6"]
    if spec == "2.4+5":
        return ["2.4", "5"]
    if spec in ("2.4", "5", "6"):
        return [spec]
    raise ValueError(f"Unknown band: {spec!r}")


def channels_for_bands(bands: Iterable[str]) -> List[int]:
    """Return an ordered, de-duplicated channel list for the given bands."""
    result: List[int] = []
    for band in bands:
        if band == "2.4":
            candidates = CHANNELS_24_GHZ
        elif band == "5":
            candidates = CHANNELS_5_GHZ
        elif band == "6":
            candidates = CHANNELS_6_GHZ
        else:
            raise ValueError(f"Unknown band: {band!r}")
        for channel in candidates:
            if channel not in result:
                result.append(channel)
    return result


def parse_channel_spec(spec: str) -> List[int]:
    """Parse a channel specification such as ``1-11,36,149``.

    Ranges are inclusive.  Order is preserved and duplicates are removed.
    """
    if not spec or not spec.strip():
        raise ValueError("Empty channel specification")

    result: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            left, right = part.split("-", 1)
            try:
                start, end = int(left), int(right)
            except ValueError as exc:
                raise ValueError(f"Invalid channel range: {part!r}") from exc
            if start > end:
                start, end = end, start
            if end - start > 1024:
                raise ValueError(f"Channel range too large: {part!r}")
            candidates: Sequence[int] = range(start, end + 1)
        else:
            try:
                candidates = [int(part)]
            except ValueError as exc:
                raise ValueError(f"Invalid channel: {part!r}") from exc

        for channel in candidates:
            if channel < 1 or channel > 4095:
                raise ValueError(f"Channel out of range: {channel}")
            if channel not in result:
                result.append(channel)

    if not result:
        raise ValueError(f"No channels in specification: {spec!r}")
    return result


# ---------------------------------------------------------------------------
# Information elements
# ---------------------------------------------------------------------------

def _as_bytes(value) -> bytes:
    """Best-effort conversion of a Scapy information-element payload to bytes."""
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


def _u16(data: bytes, offset: int) -> Optional[int]:
    if offset < 0 or offset + 2 > len(data):
        return None
    return int.from_bytes(data[offset:offset + 2], "little")


def _suite_name(suite: bytes, table: Dict[int, str]) -> str:
    if len(suite) < 4:
        return "unknown"
    oui, suite_type = suite[:3], suite[3]
    if oui in (RSN_OUI, WPA_OUI):
        return table.get(suite_type, f"type-{suite_type}")
    return f"{suite.hex()}"


def _empty_rsn() -> Dict:
    return {
        "version": 0,
        "group_cipher": "unknown",
        "pairwise_ciphers": [],
        "akms": [],
        "capabilities": 0,
        "pmf_required": False,
        "pmf_capable": False,
        "pmf": False,
    }


def parse_rsn_ie(data) -> Dict:
    """Parse an RSN information element (ID 48) body.

    Returns a dict with cipher suites, AKM suites and PMF capability flags.
    Malformed or truncated elements are handled gracefully and return whatever
    could be parsed.
    """
    result = _empty_rsn()
    raw = _as_bytes(data)
    if len(raw) < 8:
        return result

    version = _u16(raw, 0)
    result["version"] = version or 0
    result["group_cipher"] = _suite_name(raw[2:6], CIPHER_SUITES)

    pairwise_count = _u16(raw, 6)
    if pairwise_count is None or pairwise_count > 64:
        return result

    offset = 8
    for _ in range(pairwise_count):
        if offset + 4 > len(raw):
            return result
        result["pairwise_ciphers"].append(
            _suite_name(raw[offset:offset + 4], CIPHER_SUITES)
        )
        offset += 4

    akm_count = _u16(raw, offset)
    if akm_count is None or akm_count > 64:
        return result
    offset += 2

    for _ in range(akm_count):
        if offset + 4 > len(raw):
            return result
        result["akms"].append(_suite_name(raw[offset:offset + 4], AKM_SUITES))
        offset += 4

    capabilities = _u16(raw, offset)
    if capabilities is not None:
        result["capabilities"] = capabilities
        result["pmf_required"] = bool(capabilities & PMF_REQUIRED)
        result["pmf_capable"] = bool(capabilities & PMF_CAPABLE)
        result["pmf"] = result["pmf_required"] or result["pmf_capable"]

    return result


def parse_wpa_ie(data) -> Dict:
    """Parse a WPA vendor-specific information element (ID 221)."""
    result = _empty_rsn()
    raw = _as_bytes(data)
    # OUI (3) + type (1) + version (2) + group cipher (4) + count (2)
    if len(raw) < 12 or raw[:4] != b"\x00\x50\xf2\x01":
        return result

    result["version"] = _u16(raw, 4) or 0
    result["group_cipher"] = _suite_name(raw[6:10], CIPHER_SUITES)

    pairwise_count = _u16(raw, 10)
    if pairwise_count is None or pairwise_count > 64:
        return result

    offset = 12
    for _ in range(pairwise_count):
        if offset + 4 > len(raw):
            return result
        result["pairwise_ciphers"].append(
            _suite_name(raw[offset:offset + 4], CIPHER_SUITES)
        )
        offset += 4

    akm_count = _u16(raw, offset)
    if akm_count is None or akm_count > 64:
        return result
    offset += 2

    for _ in range(akm_count):
        if offset + 4 > len(raw):
            return result
        result["akms"].append(_suite_name(raw[offset:offset + 4], AKM_SUITES))
        offset += 4

    return result


def classify_security(rsn: Optional[Dict], wpa: Optional[Dict],
                      privacy: bool = False) -> str:
    """Classify the security/encryption type of a network.

    The return value is a short human-readable label used in the scan table.
    """
    if rsn and (rsn.get("akms") or rsn.get("pairwise_ciphers")):
        akms = set(rsn.get("akms", []))
        if "OWE" in akms:
            return "OWE"
        sae = akms & {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"}
        psk = akms & {"PSK", "FT-PSK", "PSK-SHA256"}
        enterprise = {a for a in akms if a.startswith("802.1X")}
        if sae and psk:
            return "WPA2/3"
        if sae:
            return "WPA3"
        if enterprise:
            return "WPA3-ENT" if "802.1X-SHA256" in akms else "WPA2-ENT"
        if psk:
            return "WPA2"
        return "WPA2"

    if wpa and (wpa.get("akms") or wpa.get("pairwise_ciphers")):
        return "WPA"
    if privacy:
        return "WEP"
    return "OPEN"


def pmf_label(required: bool, capable: bool) -> str:
    """Return a compact PMF label: REQ, CAP or NO."""
    if required:
        return "REQ"
    if capable:
        return "CAP"
    return "NO"
