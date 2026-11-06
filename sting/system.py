"""Operating-system helpers for wireless interfaces.

Handles interface discovery, monitor/managed mode changes and channel
selection on Linux, with best-effort support for Windows and macOS.
"""

import os
import re
import subprocess
import sys
from contextlib import contextmanager
from typing import Iterator, List, Optional


def _run(command: List[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def _quiet(command: List[str], timeout: float = 5.0) -> bool:
    try:
        return _run(command, timeout=timeout).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _append_unique(items: List[str], value: str) -> None:
    value = value.strip()
    if value and value not in items:
        items.append(value)


def get_wireless_interfaces() -> List[str]:
    """Return a list of wireless interface names present on the system."""
    interfaces: List[str] = []

    if sys.platform.startswith("linux"):
        # ``iw dev`` is the most reliable source on modern Linux.
        try:
            result = _run(["iw", "dev"], timeout=5)
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface "):
                    _append_unique(interfaces, stripped.split(None, 1)[1])
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        # Fall back to iwconfig (still available on many systems).
        if not interfaces:
            try:
                result = _run(["iwconfig"], timeout=5)
                for line in result.stdout.splitlines():
                    if "IEEE 802.11" in line:
                        _append_unique(interfaces, line.split()[0])
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass

        # Last resort: inspect /sys/class/net for wireless devices.
        if not interfaces:
            try:
                for entry in os.listdir("/sys/class/net"):
                    path = os.path.join("/sys/class/net", entry)
                    if (os.path.isdir(os.path.join(path, "wireless"))
                            or entry.startswith(("wl", "wlan"))):
                        _append_unique(interfaces, entry)
            except FileNotFoundError:
                pass

    elif sys.platform == "win32":
        try:
            result = _run(["netsh", "wlan", "show", "interfaces"], timeout=10)
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Name"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        _append_unique(interfaces, parts[1])
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    elif sys.platform == "darwin":
        try:
            result = _run(["networksetup", "-listallhardwareports"], timeout=5)
            capture_next = False
            for line in result.stdout.splitlines():
                if "Wi-Fi" in line or "AirPort" in line:
                    capture_next = True
                elif capture_next and "Device" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        _append_unique(interfaces, parts[1])
                    capture_next = False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    return interfaces


def get_interface_mode(interface: str) -> Optional[str]:
    """Return ``monitor``/``managed``/... for an interface, or None if unknown."""
    if not sys.platform.startswith("linux"):
        return None

    try:
        result = _run(["iw", "dev", interface, "info"], timeout=5)
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("type "):
                return stripped.split(None, 1)[1].strip().lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    try:
        result = _run(["iwconfig", interface], timeout=5)
        match = re.search(r"Mode:(\w+)", result.stdout)
        if match:
            return match.group(1).lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return None


def set_interface_mode(interface: str, mode: str) -> bool:
    """Set the interface type (``monitor``, ``managed``, ...) on Linux."""
    if not sys.platform.startswith("linux"):
        return False

    if get_interface_mode(interface) == mode.lower():
        return True

    ok = False
    try:
        _quiet(["ip", "link", "set", interface, "down"])
        ok = _quiet(["iw", "dev", interface, "set", "type", mode])
        if not ok:
            # Older systems may only have iwconfig; mode names are capitalized.
            ok = _quiet(["iwconfig", interface, "mode", mode.lower()])
    except Exception:
        ok = False
    finally:
        _quiet(["ip", "link", "set", interface, "up"])
    return ok


def enable_monitor_mode(interface: str) -> bool:
    """Enable monitor mode (Linux only)."""
    return set_interface_mode(interface, "monitor")


def disable_monitor_mode(interface: str) -> bool:
    """Restore managed mode (Linux only)."""
    return set_interface_mode(interface, "managed")


@contextmanager
def monitor_mode(interface: str, enabled: bool = True,
                 restore: bool = True) -> Iterator[bool]:
    """Context manager that enables monitor mode and optionally restores it.

    Yields True when the interface is in (or was already in) monitor mode.
    On non-Linux platforms and when ``enabled`` is False it yields False.
    """
    if not enabled or not sys.platform.startswith("linux"):
        yield False
        return

    previous = get_interface_mode(interface)
    if previous == "monitor":
        yield True
        return

    enabled_ok = set_interface_mode(interface, "monitor")
    try:
        yield enabled_ok
    finally:
        if enabled_ok and restore:
            set_interface_mode(interface, previous or "managed")


def set_channel(interface: str, channel: int) -> bool:
    """Tune the interface to *channel*. Returns True on success."""
    try:
        channel = int(channel)
    except (TypeError, ValueError):
        return False
    if channel <= 0:
        return False

    if not sys.platform.startswith("linux"):
        return False

    if _quiet(["iw", "dev", interface, "set", "channel", str(channel)], timeout=5):
        return True
    # Fallback for older wireless extensions.
    return _quiet(["iwconfig", interface, "channel", str(channel)], timeout=5)
