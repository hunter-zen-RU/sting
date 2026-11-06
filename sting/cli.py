"""STING command-line interface."""

import argparse
import csv
import io
import json
import os
import signal
import sys
from typing import Dict, List, Optional

from sting import BANNER, DEAUTH_REASON_CODES, __github_url__, __version__
from sting.ieee80211 import (
    BROADCAST_MAC,
    channels_for_bands,
    is_broadcast_mac,
    is_valid_mac,
    parse_bands,
    parse_channel_spec,
    pmf_label,
)
from sting.security_features import (
    print_6ghz_education,
    print_all_education,
    print_beacon_protection_education,
    print_owe_education,
    print_pmf_education,
    print_wpa3_education,
)
from sting.scanner import HAVE_SCAPY
from sting.system import get_interface_mode, get_wireless_interfaces, monitor_mode
from sting.updater import SelfUpdater

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UPDATE_AVAILABLE = 2

keep_running = True


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def signal_handler(sig, frame):
    global keep_running
    if keep_running:
        print("\n[!] Interrupt received. Gracefully shutting down...")
        keep_running = False
    else:
        print("\n[!] Force exit.")
        sys.exit(1)


def install_signal_handlers() -> None:
    try:
        signal.signal(signal.SIGINT, signal_handler)
    except (ValueError, AttributeError):
        pass
    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, signal_handler)
        except (ValueError, AttributeError):
            pass


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected an integer, got {value!r}") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return number


def _non_negative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected a number, got {value!r}") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("value cannot be negative")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sting",
        description="STING - Security Testing & Investigation of Networks & Gateways",
        epilog="For educational purposes only. Use only on networks you own.",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="verbose output")
    parser.add_argument("-i", "--interface", type=str, default=None,
                        help="wireless interface (e.g. wlan0)")
    parser.add_argument("-c", "--channel", type=_positive_int, default=None,
                        help="channel to operate on")
    parser.add_argument("-r", "--reason", type=int, default=7,
                        choices=sorted(DEAUTH_REASON_CODES),
                        help="deauth reason code (default: 7)")
    parser.add_argument("-n", "--count", type=_positive_int, default=3,
                        help="frames per cycle (default: 3)")
    parser.add_argument("-d", "--delay", type=_non_negative_float, default=0.1,
                        help="delay between cycles in seconds (default: 0.1)")
    parser.add_argument("--duration", type=_positive_float, default=None,
                        help="stop the attack after this many seconds")
    parser.add_argument("-b", "--bssid", type=str, default=None,
                        help="target AP BSSID (skips interactive selection)")
    parser.add_argument("-s", "--station", type=str, default=BROADCAST_MAC,
                        help="target station MAC (default: broadcast)")
    parser.add_argument("--dry-run", action="store_true",
                        help="build packets and show statistics without sending")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="skip the interactive confirmation prompt")

    scan_group = parser.add_argument_group("scanning")
    scan_group.add_argument("--scan", action="store_true",
                            help="scan and print results without attacking")
    scan_group.add_argument("--scan-time", type=_positive_float, default=10.0,
                            help="total scan duration in seconds (default: 10)")
    scan_group.add_argument("--ssid", type=str, default=None,
                            help="only show SSIDs containing this text")
    scan_group.add_argument("--min-signal", type=int, default=None,
                            help="only show networks at or above this dBm value")
    scan_group.add_argument("--hide-hidden", action="store_true",
                            help="hide networks with an empty/hidden SSID")
    scan_group.add_argument("--sort", choices=["signal", "ssid", "channel"],
                            default="signal", help="scan result ordering")
    scan_group.add_argument("--band", choices=["2.4", "5", "6", "2.4+5", "all"],
                            default="2.4+5", help="bands to hop (default: 2.4+5)")
    scan_group.add_argument("--channels", type=str, default=None,
                            help="explicit channel list, e.g. 1-11,36,149")
    scan_group.add_argument("--dwell", type=_positive_float, default=0.25,
                            help="seconds per channel while hopping (default: 0.25)")
    scan_group.add_argument("--no-hop", action="store_true",
                            help="do not hop between channels")
    scan_group.add_argument("--format", choices=["table", "json", "csv"],
                            default="table", help="scan output format (default: table)")
    scan_group.add_argument("--output", type=str, default=None,
                            help="write scan results to a file")

    control = parser.add_argument_group("interface control")
    control.add_argument("--no-monitor", action="store_true",
                         help="do not enable monitor mode automatically")
    control.add_argument("--keep-monitor", action="store_true",
                         help="leave the interface in monitor mode on exit")

    parser.add_argument("--update", action="store_true",
                        help="check for and install updates from GitHub")
    parser.add_argument("--check-updates", action="store_true",
                        help="check for updates without installing")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="list wireless interfaces and their mode")
    parser.add_argument("--no-banner", action="store_true",
                        help="suppress the startup banner")
    parser.add_argument("--version", action="version",
                        version=f"STING v{__version__}\n{__github_url__}")

    learn = parser.add_argument_group("education")
    learn.add_argument("--learn-pmf", action="store_true",
                       help="explain PMF (802.11w)")
    learn.add_argument("--learn-wpa3", action="store_true",
                       help="explain WPA3/SAE")
    learn.add_argument("--learn-beacon-protection", action="store_true",
                       help="explain beacon protection")
    learn.add_argument("--learn-owe", action="store_true",
                       help="explain OWE (Enhanced Open)")
    learn.add_argument("--learn-6ghz", action="store_true",
                       help="explain 6 GHz security")
    learn.add_argument("--learn-all", action="store_true",
                       help="show all educational modules")
    return parser


def _print_banner(args: argparse.Namespace) -> None:
    if args.no_banner:
        return
    print(BANNER)
    print(f"  v{__version__} | {__github_url__}")
    print(f"  {'=' * 55}")
    print()


def _interface_exists(interface: str) -> bool:
    if sys.platform.startswith("linux"):
        return os.path.isdir(os.path.join("/sys/class/net", interface))
    return True


def select_interface(args: argparse.Namespace) -> str:
    interfaces = get_wireless_interfaces()
    if args.interface:
        if args.interface not in interfaces and not _interface_exists(args.interface):
            available = ", ".join(interfaces) if interfaces else "none"
            raise RuntimeError(
                f"Interface '{args.interface}' not found (available: {available})."
            )
        return args.interface
    if not interfaces:
        raise RuntimeError("No wireless interfaces found.")
    return interfaces[0]


def _scan_channels(args: argparse.Namespace) -> Optional[List[int]]:
    if args.channels:
        return parse_channel_spec(args.channels)
    if args.channel:
        return [args.channel]
    if args.no_hop:
        return None
    return channels_for_bands(parse_bands(args.band))


def _run_scan(args: argparse.Namespace, interface: str) -> List[Dict]:
    from sting.scanner import scan_networks

    channels = _scan_channels(args)
    return scan_networks(
        interface,
        scan_time=args.scan_time,
        verbose=args.verbose,
        channels=channels,
        dwell=args.dwell,
        hop=not args.no_hop,
        include_hidden=not args.hide_hidden,
    )


def filter_networks(networks: List[Dict], ssid: Optional[str] = None,
                    min_signal: Optional[int] = None,
                    hide_hidden: bool = False,
                    sort_by: str = "signal") -> List[Dict]:
    """Apply CLI filters and ordering to a scan result list."""
    result = []
    for network in networks:
        if hide_hidden and network.get("hidden"):
            continue
        if ssid and ssid.casefold() not in str(network.get("ssid", "")).casefold():
            continue
        if min_signal is not None and network.get("signal", -100) < min_signal:
            continue
        result.append(network)

    if sort_by == "signal":
        result.sort(key=lambda net: net.get("signal", -100), reverse=True)
    elif sort_by == "ssid":
        result.sort(key=lambda net: (str(net.get("ssid", "")).casefold(),
                                     net.get("bssid", "")))
    else:
        result.sort(key=lambda net: (net.get("channel", 0), net.get("bssid", "")))
    return result


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def render_table(networks: List[Dict]) -> str:
    lines = [
        f"    {'#':<4} {'SSID':<32} {'BSSID':<18} {'CH':<4} "
        f"{'SIG':<7} {'ENCR':<10} {'PMF':<4} {'WPS':<4}",
        f"    {'-' * 4} {'-' * 32} {'-' * 18} {'-' * 4} "
        f"{'-' * 7} {'-' * 10} {'-' * 4} {'-' * 4}",
    ]
    for index, network in enumerate(networks, 1):
        ssid = str(network.get("ssid", "<hidden>"))
        if network.get("hidden") and ssid not in ("", "<hidden>"):
            ssid = f"{ssid} <hidden>"
        pmf = pmf_label(bool(network.get("pmf_required")),
                        bool(network.get("pmf_capable")))
        lines.append(
            f"    {index:<4} {ssid[:31]:<32} {network.get('bssid', ''):<18} "
            f"{str(network.get('channel', '?')):<4} "
            f"{str(network.get('signal', -100)) + 'dBm':<7} "
            f"{str(network.get('encryption', '?')):<10} {pmf:<4} "
            f"{'YES' if network.get('wps') else '-':<4}"
        )
    lines.append("")
    lines.append("    PMF: REQ = required, CAP = capable, NO = not advertised")
    return "\n".join(lines)


def render_json(networks: List[Dict]) -> str:
    return json.dumps(networks, indent=2, ensure_ascii=False)


CSV_FIELDS = [
    "ssid", "bssid", "channel", "frequency", "signal", "encryption",
    "pmf", "pmf_required", "pmf_capable", "wps", "hidden",
]


def render_csv(networks: List[Dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for network in networks:
        writer.writerow(network)
    return buffer.getvalue()


def render_networks(networks: List[Dict], output_format: str) -> str:
    if output_format == "json":
        return render_json(networks)
    if output_format == "csv":
        return render_csv(networks)
    return render_table(networks)


def write_output(path: str, text: str) -> bool:
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
        return True
    except OSError as exc:
        print(f"[!] Could not write {path}: {exc}")
        return False


def emit_scan_results(networks: List[Dict], args: argparse.Namespace,
                      interactive: bool = False) -> int:
    if args.output:
        text = render_networks(networks, args.format)
        if not write_output(args.output, text):
            return EXIT_ERROR
        print(f"[*] Wrote {len(networks)} network(s) to {args.output} "
              f"({args.format}).")
        if interactive:
            print(render_table(networks))
    else:
        print(render_networks(networks, args.format))
    return EXIT_OK


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def run_education(args: argparse.Namespace) -> bool:
    if args.learn_all:
        print_all_education()
        return True
    modules = [
        ("learn_pmf", print_pmf_education),
        ("learn_wpa3", print_wpa3_education),
        ("learn_beacon_protection", print_beacon_protection_education),
        ("learn_owe", print_owe_education),
        ("learn_6ghz", print_6ghz_education),
    ]
    for attribute, function in modules:
        if getattr(args, attribute, False):
            function()
            return True
    return False


def run_list_interfaces() -> int:
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        return EXIT_ERROR
    print("Available wireless interfaces:")
    for interface in interfaces:
        print(f"  - {interface:<16} mode: {get_interface_mode(interface) or 'unknown'}")
    return EXIT_OK


def run_update(args: argparse.Namespace, check_only: bool) -> int:
    _print_banner(args)
    updater = SelfUpdater(verbose=args.verbose)
    if check_only:
        new_version = updater.check_update()
        if updater.last_error:
            return EXIT_ERROR
        return EXIT_UPDATE_AVAILABLE if new_version else EXIT_OK
    return EXIT_OK if updater.run_update(verbose=args.verbose) else EXIT_ERROR


def run_scan_command(args: argparse.Namespace) -> int:
    _print_banner(args)
    try:
        interface = select_interface(args)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return EXIT_ERROR

    mode = get_interface_mode(interface) or "unknown"
    print(f"[*] Interface: {interface} (mode: {mode})")
    with monitor_mode(interface, enabled=not args.no_monitor and HAVE_SCAPY,
                      restore=not args.keep_monitor) as active:
        if not args.no_monitor:
            if not HAVE_SCAPY:
                print("[!] Scapy not installed; using managed-mode system scan.")
            else:
                print(f"[*] Monitor mode: {'enabled' if active else 'unavailable'}")
        try:
            networks = _run_scan(args, interface)
        except ValueError as exc:
            print(f"[!] {exc}")
            return EXIT_ERROR
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted.")
            return EXIT_OK

    networks = filter_networks(networks, args.ssid, args.min_signal,
                               args.hide_hidden, args.sort)
    if not networks:
        print("[!] No networks found.")
        return EXIT_ERROR
    print(f"[*] Found {len(networks)} network(s).\n")
    return emit_scan_results(networks, args)


def _run_attack(args: argparse.Namespace, interface: str, bssid: str,
                ssid: str, channel: int) -> int:
    from sting.deauth import DeauthEngine

    global keep_running
    keep_running = True
    install_signal_handlers()

    try:
        engine = DeauthEngine(
            interface=interface,
            ap_bssid=bssid,
            ap_ssid=ssid,
            target_mac=args.station,
            channel=channel,
            reason_code=args.reason,
            verbose=args.verbose,
            dry_run=args.dry_run,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"[!] {exc}")
        return EXIT_ERROR

    try:
        engine.run_loop(
            count=args.count,
            delay=args.delay,
            duration=args.duration,
            stop_flag=lambda: not keep_running,
        )
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as exc:
        print(f"\n[!] Error: {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        engine.print_stats()
    return EXIT_OK


def run_direct(args: argparse.Namespace) -> int:
    _print_banner(args)
    if not args.channel:
        print("[!] --channel is required with --bssid.")
        return EXIT_ERROR

    if args.dry_run:
        # A dry run only builds packets and reports statistics, so it can be
        # demonstrated without any wireless hardware.
        interface = args.interface or "wlan0"
        if not args.interface:
            print("[*] DRY RUN: no wireless interface required (using wlan0).")
    else:
        try:
            interface = select_interface(args)
        except RuntimeError as exc:
            print(f"[!] {exc}")
            return EXIT_ERROR
        if not HAVE_SCAPY:
            print("[!] Scapy is required for packet injection.")
            print("    Install with: pip install scapy")
            return EXIT_ERROR

    print(f"[*] Deauth on {args.bssid} CH:{args.channel}")
    with monitor_mode(interface, enabled=not args.no_monitor and not args.dry_run,
                      restore=not args.keep_monitor) as active:
        if not args.no_monitor and not args.dry_run and not active:
            print("[!] Could not enable monitor mode; injection may fail.")
        return _run_attack(args, interface, args.bssid, f"<{args.bssid}>",
                           args.channel)


def run_interactive(args: argparse.Namespace) -> int:
    _print_banner(args)
    try:
        interface = select_interface(args)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return EXIT_ERROR

    mode = get_interface_mode(interface) or "unknown"
    print(f"[*] Interface: {interface} (mode: {mode})")
    with monitor_mode(interface, enabled=not args.no_monitor and HAVE_SCAPY,
                      restore=not args.keep_monitor) as active:
        if not args.no_monitor:
            if not HAVE_SCAPY:
                print("[!] Scapy not installed; using managed-mode system scan.")
            else:
                print(f"[*] Monitor mode: {'enabled' if active else 'unavailable'}")
        print(f"[*] Scanning for WiFi networks ({args.scan_time:g}s)...")
        try:
            networks = _run_scan(args, interface)
        except ValueError as exc:
            print(f"[!] {exc}")
            return EXIT_ERROR
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted.")
            return EXIT_OK

        networks = filter_networks(networks, args.ssid, args.min_signal,
                                   args.hide_hidden, args.sort)
        if not networks:
            print("[!] No networks found.")
            return EXIT_ERROR

        print(f"\n[*] Found {len(networks)} networks:")
        print(render_table(networks))
        if args.output and emit_scan_results(networks, args,
                                             interactive=False) != EXIT_OK:
            return EXIT_ERROR

        while True:
            try:
                choice = input("[>] Select network (or 'q' to quit): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return EXIT_OK
            if choice.lower() in ("q", "quit", "exit"):
                return EXIT_OK
            try:
                index = int(choice) - 1
            except ValueError:
                print(f"[!] Choose 1-{len(networks)}")
                continue
            if 0 <= index < len(networks):
                break
            print(f"[!] Choose 1-{len(networks)}")

        target = networks[index]
        channel = args.channel or target.get("channel") or 0
        if not channel:
            print("[!] Could not determine the target channel; use --channel.")
            return EXIT_ERROR

        print(f"\n[*] Target: {target['ssid']} ({target['bssid']})")
        if target.get("pmf_required"):
            print("[!] WARNING: PMF is REQUIRED - deauth frames will be rejected.")
        elif target.get("pmf_capable"):
            print("[!] Note: PMF is supported - deauth may fail for PMF clients.")
        station = args.station
        print(f"[*] Deauth target: "
              f"{'ALL clients' if is_broadcast_mac(station) else station}")

        if not args.yes:
            try:
                confirm = input("[>] Start? (y/N): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return EXIT_OK
            if confirm not in ("y", "yes"):
                print("[*] Aborted.")
                return EXIT_OK

        print(f"[*] Deauth: {target['ssid']} | CH:{channel} | "
              f"Code:{args.reason}")
        return _run_attack(args, interface, target["bssid"], target["ssid"],
                           channel)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (ValueError, OSError):
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if run_education(args):
            return EXIT_OK
        if args.list_interfaces:
            return run_list_interfaces()
        if args.check_updates:
            return run_update(args, check_only=True)
        if args.update:
            return run_update(args, check_only=False)

        if args.scan:
            return run_scan_command(args)

        if not is_valid_mac(args.station):
            print(f"[!] Invalid station MAC: {args.station}")
            return EXIT_ERROR
        if args.bssid and not is_valid_mac(args.bssid):
            print(f"[!] Invalid AP BSSID: {args.bssid}")
            return EXIT_ERROR

        if args.bssid:
            return run_direct(args)
        return run_interactive(args)

    except KeyboardInterrupt:
        print("\n[*] Exiting.")
        return EXIT_OK
    except EOFError:
        print("\n[*] Exiting.")
        return EXIT_OK
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
