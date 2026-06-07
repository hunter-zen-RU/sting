"""
STING Command-Line Interface
"""
import argparse
import signal
import sys
from sting import BANNER, __version__, __github_url__
from sting.scanner import scan_networks, get_wireless_interfaces
from sting.deauth import DeauthEngine
from sting.updater import SelfUpdater
from sting.security_features import (
    print_pmf_education, print_wpa3_education,
    print_beacon_protection_education,
    print_6ghz_education, print_owe_education,
)

keep_running = True

def signal_handler(sig, frame):
    global keep_running
    if keep_running:
        print("\n[!] Interrupt received. Gracefully shutting down...")
        keep_running = False
    else:
        print("\n[!] Force exit.")
        sys.exit(1)

def build_parser():
    parser = argparse.ArgumentParser(
        prog="sting",
        description="STING - Security Testing & Investigation of Networks & Gateways",
        epilog="For educational purposes only. Use only on networks you own"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--interface", type=str, default=None, help="Interface")
    parser.add_argument("-c", "--channel", type=int, default=None, help="Channel")
    parser.add_argument("-r", "--reason", type=int, default=7, choices=[0,1,2,3,4,5,6,7,8,9,10], help="Reason")
    parser.add_argument("-n", "--count", type=int, default=3, help="Packet count")
    parser.add_argument("-d", "--delay", type=float, default=0.1, help="Delay")
    parser.add_argument("-b", "--bssid", type=str, default=None, help="AP BSSID")
    parser.add_argument("-s", "--station", type=str, default="ff:ff:ff:ff:ff:ff", help="Station")
    parser.add_argument("--update", action="store_true", help="Self-update")
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces")
    parser.add_argument("--no-banner", action="store_true", help="No banner")
    parser.add_argument("--version", action="store_true", help="Show version")
    parser.add_argument("--learn-pmf", action="store_true", help="PMF education")
    parser.add_argument("--learn-wpa3", action="store_true", help="WPA3 education")
    parser.add_argument("--learn-beacon-protection", action="store_true", help="Beacon education")
    parser.add_argument("--learn-owe", action="store_true", help="OWE education")
    parser.add_argument("--learn-6ghz", action="store_true", help="6GHz education")
    parser.add_argument("--learn-all", action="store_true", help="All education")
    return parser

def run_scan_and_deauth(args):
    global keep_running
    if not args.no_banner:
        print(BANNER)
        print(f"  v{__version__} | {__github_url__}")
        print(f"  {'=' * 55}")
        print()
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print("[!] No wireless interfaces found.")
        return 1
    iface = args.interface or interfaces[0]
    if args.interface and args.interface not in interfaces:
        print(f"[!] Interface '{args.interface}' not found.")
        return 1
    print(f"[*] Using interface: {iface}")
    print()
    print("[*] Scanning for WiFi networks (5 seconds)...")
    networks = scan_networks(iface, scan_time=5, verbose=args.verbose)
    if not networks:
        print("[!] No networks found.")
        return 1
    print(f"\n[*] Found {len(networks)} networks:")
    print(f"    {'#':<4} {'SSID':<32} {'BSSID':<18} {'CH':<4} {'SIG':<7} {'ENCR':<8} {'PMF':<5}")
    print(f"    {'-'*4} {'-'*32} {'-'*18} {'-'*4} {'-'*7} {'-'*8} {'-'*5}")
    for i, net in enumerate(networks, 1):
        pmf_str = "YES" if net.get("pmf", False) else "NO"
        print(f"    {i:<4} {net['ssid'][:31]:<32} {net['bssid']:<18} "
              f"{str(net.get('channel','?')):<4} {net.get('signal',-100)}dBm "
              f"{net.get('encryption','?'):<8} {pmf_str:<5}")
    print()
    print("[*] PMF = Protected Management Frames (802.11w)")
    print()
    while True:
        try:
            choice = input("[>] Select network (or 'q' to quit): ").strip()
            if choice.lower() in ('q','quit','exit'):
                return 0
            idx = int(choice) - 1
            if 0 <= idx < len(networks):
                break
            print(f"[!] Choose 1-{len(networks)}")
        except (ValueError, EOFError, KeyboardInterrupt):
            print()
            return 0
    target = networks[idx]
    print(f"\n[*] Target: {target['ssid']} ({target['bssid']})")
    if target.get("pmf"):
        print("[!] WARNING: PMF enabled - deauth may fail!")
    station_mac = args.station
    print(f"[*] Deauth target: {'ALL clients' if station_mac=='ff:ff:ff:ff:ff:ff' else station_mac}")
    try:
        confirm = input("[>] Start? (y/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 0
    if confirm not in ('y','yes'):
        print("[*] Aborted.")
        return 0
    channel = args.channel or target.get("channel")
    engine = DeauthEngine(interface=iface, ap_bssid=target['bssid'],
        ap_ssid=target['ssid'], target_mac=station_mac, channel=channel,
        reason_code=args.reason, verbose=args.verbose)
    print(f"[*] Deauth: {target['ssid']} | CH:{channel} | Code:{args.reason}")
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        engine.run_loop(count=args.count, delay=args.delay,
            stop_flag=lambda: not keep_running)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            import traceback; traceback.print_exc()
    engine.print_stats()
    return 0

def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    parser = build_parser()
    args = parser.parse_args()
    if args.version:
        print(f"STING v{__version__}"); print(__github_url__); return 0
    if args.learn_pmf or args.learn_all:
        print_pmf_education()
        if not args.learn_all: return 0
    if args.learn_wpa3 or args.learn_all:
        print_wpa3_education()
        if not args.learn_all: return 0
    if args.learn_beacon_protection or args.learn_all:
        print_beacon_protection_education()
        if not args.learn_all: return 0
    if args.learn_owe or args.learn_all:
        print_owe_education()
        if not args.learn_all: return 0
    if args.learn_6ghz or args.learn_all:
        print_6ghz_education(); return 0
    if args.learn_all: return 0
    if args.list_interfaces:
        ifaces = get_wireless_interfaces()
        if ifaces:
            print("Available interfaces:")
            for i in ifaces: print(f"  - {i}")
        else:
            print("No interfaces found.")
        return 0
    if args.update:
        if not args.no_banner: print(BANNER)
        print("[*] Checking for updates...")
        updater = SelfUpdater(verbose=args.verbose)
        return 0 if updater.run_update(verbose=args.verbose) else 1
    if args.bssid:
        if not args.channel:
            print("[!] --channel required with --bssid"); return 1
        global keep_running
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        ifaces = get_wireless_interfaces()
        iface = args.interface or (ifaces[0] if ifaces else None)
        if not iface:
            print("[!] No interface available."); return 1
        engine = DeauthEngine(interface=iface, ap_bssid=args.bssid,
            ap_ssid=f"<{args.bssid}>", target_mac=args.station,
            channel=args.channel, reason_code=args.reason,
            verbose=args.verbose)
        print(f"[*] Deauth on {args.bssid} CH:{args.channel}")
        try:
            engine.run_loop(count=args.count, delay=args.delay,
                stop_flag=lambda: not keep_running)
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        engine.print_stats(); return 0
    try:
        return run_scan_and_deauth(args) or 0
    except (KeyboardInterrupt, EOFError):
        print("\n[*] Exiting."); return 0

if __name__ == "__main__":
    sys.exit(main())
