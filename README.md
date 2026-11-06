# STING - Security Testing & Investigation of Networks & Gateways

**Version 1.1.0 | Educational WiFi Security Tool**

STING is a CLI-based WiFi security tool designed **exclusively for educational
purposes**. It demonstrates how deauthentication attacks work, how modern
security features (PMF/802.11w, WPA3) protect against them, and provides
detailed educational content about 2026-era WiFi security standards.

```
╔══════════════════════════════════════════════════════════════╗
║   ███████╗████████╗██╗███╗   ██╗ ██████╗                  ║
║   ██╔════╝╚══██╔══╝██║████╗  ██║██╔════╝                  ║
║   ███████╗   ██║   ██║██╔██╗ ██║██║  ███╗                 ║
║   ╚════██║   ██║   ██║██║╚██╗██║██║   ██║                 ║
║   ███████║   ██║   ██║██║ ╚████║╚██████╔╝                 ║
║   ╚══════╝   ╚═╝   ╚═╝╚═╝  ╚═══╝ ╚═════╝                  ║
║                                                            ║
║   Security Testing & Investigation of Networks & Gateways   ║
║                  Educational WiFi Security Tool              ║
╚══════════════════════════════════════════════════════════════╝
```

## ⚠️ Legal Notice

**Use STING ONLY on networks you own or have explicit written permission to test.**
Unauthorized use of deauthentication attacks is illegal in most jurisdictions.

This tool is provided for:

- Security researchers testing their own equipment
- Students learning about WiFi security
- Professionals conducting authorized penetration tests
- Demonstrating why PMF (802.11w) is important

## Features

### Scanning

- Detects nearby networks from beacon and probe-response frames
- Displays SSID, BSSID, channel, signal strength, encryption, PMF and WPS
- Correctly parses RSN/WPA information elements (WPA2, WPA3, WPA2/3 transition,
  WPA2/3-Enterprise, OWE, WPA and WEP)
- Detects PMF as **required**, **capable**, or not advertised
- Optional channel hopping across 2.4 GHz, 5 GHz and 6 GHz
- Automatic monitor-mode setup and restoration
- Filtering by SSID, minimum signal, and hidden networks
- Table, JSON and CSV output, including file export

### Deauthentication (authorised testing only)

- Sends 802.11 deauthentication frames to a selected network
- Interactive scan-and-select workflow or direct `--bssid` mode
- Configurable reason code, packet count, delay and channel
- Optional time limit (`--duration`) and graceful Ctrl+C handling
- **Dry-run mode** builds packets and reports statistics without transmitting
- Detailed packet structure and attack statistics

### Safety and maintenance

- Automatic monitor-mode restoration on exit
- SHA-256 verification of downloaded updates when GitHub provides a digest
- Zip-slip protection and backup/rollback during self-update
- Updates fall back to the newest git tag or the default branch when a
  repository has no GitHub Releases
- Input validation and clear error messages
- Unit tests and GitHub Actions CI

### Educational modules

- **PMF (802.11w)** - how protected management frames block deauth attacks
- **WPA3/SAE** - Simultaneous Authentication of Equals
- **Beacon Protection** - beacon integrity and fake-AP prevention
- **OWE (Enhanced Open)** - encryption for open networks
- **6 GHz Band Security** - WiFi 6E/7 mandatory security requirements

## Requirements

- **OS**: Linux (primary); Windows/macOS have limited scanning support
- **Python**: 3.8+
- **Hardware**: WiFi adapter supporting monitor mode and frame injection
- **Permissions**: Root/Administrator access for raw packet injection
- **Dependencies**: `scapy`, `requests`

## Installation

### From source

```bash
git clone https://github.com/hunter-zen-RU/sting.git
cd sting
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Run without installing

```bash
cd /path/to/sting
python -m sting
```

## Usage

### Interactive mode (recommended)

```bash
sudo sting
```

This will:

1. Detect your wireless interface
2. Enable monitor mode if needed
3. Scan for nearby networks
4. Display a table of found networks
5. Prompt you to select a target by number
6. Ask for confirmation before starting
7. Deauth continuously until Ctrl+C or `--duration` elapses

### Command-line options

```
usage: sting [-h] [-v] [-i INTERFACE] [-c CHANNEL] [-r REASON]
             [-n COUNT] [-d DELAY] [--duration DURATION] [-b BSSID]
             [-s STATION] [--dry-run] [-y] [--scan] [--scan-time SCAN_TIME]
             [--ssid SSID] [--min-signal MIN_SIGNAL] [--hide-hidden]
             [--sort {signal,ssid,channel}] [--band {2.4,5,6,2.4+5,all}]
             [--channels CHANNELS] [--dwell DWELL] [--no-hop]
             [--format {table,json,csv}] [--output OUTPUT]
             [--no-monitor] [--keep-monitor] [--update] [--check-updates]
             [--list-interfaces] [--no-banner] [--version]
             [--learn-pmf] [--learn-wpa3] [--learn-beacon-protection]
             [--learn-owe] [--learn-6ghz] [--learn-all]
```

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Verbose output with packet details |
| `-i, --interface` | Wireless interface (e.g. `wlan0`) |
| `-c, --channel` | Channel to operate on (also restricts the scan to it) |
| `-r, --reason` | Deauth reason code (default: 7) |
| `-n, --count` | Frames per cycle (default: 3) |
| `-d, --delay` | Delay between cycles in seconds (default: 0.1) |
| `--duration` | Stop the attack after this many seconds |
| `-b, --bssid` | Target AP BSSID (skips interactive selection) |
| `-s, --station` | Target station MAC (default: broadcast) |
| `--dry-run` | Build packets and report statistics without sending |
| `-y, --yes` | Skip the interactive confirmation prompt |
| `--scan` | Scan and print results, then exit |
| `--scan-time` | Total scan duration in seconds (default: 10) |
| `--ssid` | Only show SSIDs containing this text |
| `--min-signal` | Only show networks at or above this dBm value |
| `--hide-hidden` | Hide networks with an empty/hidden SSID |
| `--sort` | Sort by `signal`, `ssid` or `channel` (default: `signal`) |
| `--band` | Bands to hop: `2.4`, `5`, `6`, `2.4+5`, `all` (default: `2.4+5`) |
| `--channels` | Explicit channel list, e.g. `1-11,36,149` |
| `--dwell` | Seconds per channel while hopping (default: 0.25) |
| `--no-hop` | Do not hop between channels |
| `--format` | Scan output: `table`, `json`, or `csv` (default: `table`) |
| `--output` | Write scan results to a file |
| `--no-monitor` | Do not enable monitor mode automatically |
| `--keep-monitor` | Leave the interface in monitor mode on exit |
| `--update` | Check for and install updates from GitHub |
| `--check-updates` | Check only; exits `2` when an update is available |
| `--list-interfaces` | List wireless interfaces and their mode |
| `--no-banner` | Suppress startup banner |
| `--version` | Show version and repository URL |
| `--learn-pmf` | Learn about PMF (802.11w) |
| `--learn-wpa3` | Learn about WPA3/SAE |
| `--learn-beacon-protection` | Learn about beacon protection |
| `--learn-owe` | Learn about OWE |
| `--learn-6ghz` | Learn about 6 GHz security |
| `--learn-all` | Display all educational content |

## Examples

```bash
# Interactive scan and deauth
sudo sting

# Non-interactive scan (never transmits deauth frames)
sudo sting --scan

# Scan only 5 GHz, filter by SSID, export as JSON
sudo sting --scan --band 5 --ssid office --format json --output scan.json

# Scan selected channels only
sudo sting --scan --channels 1-11,36,149

# Verbose scan with per-network details
sudo sting --scan -v

# Direct attack on a specific AP
sudo sting -b AA:BB:CC:DD:EE:FF -c 6

# Target a specific client instead of broadcast
sudo sting -b AA:BB:CC:DD:EE:FF -c 6 -s 11:22:33:44:55:66

# Send 10 frames per cycle with 0.5s delay for 30 seconds
sudo sting -b AA:BB:CC:DD:EE:FF -c 6 -n 10 -d 0.5 --duration 30

# Demonstrate packet building without transmitting anything
sudo sting -b AA:BB:CC:DD:EE:FF -c 6 --dry-run

# List interfaces and modes
sting --list-interfaces

# Update check
sting --check-updates
sudo sting --update

# Learn about WiFi security features
sting --learn-all
sting --learn-pmf
```

## How scanning works

STING first tries to enable monitor mode using `iw`. It then captures beacon and
probe-response frames with Scapy while optionally hopping across the selected
channels. When Scapy is unavailable, it falls back to `iw dev <iface> scan`
(Linux) or `netsh wlan show networks` (Windows).

Channel hopping needs an interface in monitor mode. If monitor mode cannot be
enabled, STING continues scanning on the interface's current channel. Use
`--no-monitor` if you manage monitor mode yourself, or `--keep-monitor` to leave
it enabled when STING exits.

The **PMF** column shows:

| Label | Meaning |
|-------|---------|
| `REQ` | PMF required - unencrypted deauth frames are ignored |
| `CAP` | PMF capable - PMF clients ignore forged deauth frames |
| `NO` | PMF not advertised - legacy behaviour |

The **WPS** column shows `YES` when a WPS information element is present.

## Understanding deauthentication attacks

### How it works

1. **Packet crafting**: STING constructs a raw 802.11 deauthentication frame:
   - `RadioTap` - radio metadata header
   - `Dot11` - MAC header (type=management, subtype=deauth)
   - `Dot11Deauth` - frame body with a reason code
2. **Transmission**: frames are sent at layer 2 through a monitor-mode interface
3. **Effect**: clients receiving a valid deauth frame disconnect from the AP

### Why PMF blocks this

PMF (802.11w / Protected Management Frames) requires management frames to be:

- **Encrypted** using CCMP (AES) with the Pairwise Transient Key (PTK)
- **Authenticated** using BIP-CMAC with the Integrity GTK (IGTK)

Without the PTK (which requires the WiFi password), an attacker cannot forge
valid deauth frames. PMF-capable APs and clients ignore unencrypted deauth
frames.

### Reason codes

| Code | Meaning |
|------|---------|
| 0 | Reserved |
| 1 | Unspecified reason |
| 2 | Previous authentication no longer valid |
| 3 | Station leaving IBSS/ESS |
| 4 | Disassociated due to inactivity |
| 5 | AP unable to handle all stations |
| 6 | Class 2 frame from nonauthenticated station |
| 7 | Class 3 frame from nonassociated station |
| 8 | Station leaving BSS |

Additional reason codes (including WPA3/SAE failures) are listed in
`sting/__init__.py`.

## 2026 Security Landscape

### Protected Management Frames (802.11w)

- Protects deauth, disassoc, and other management frames
- **Mandatory** for WPA3 and all 6 GHz operation
- Renders traditional deauth attacks ineffective
- RSN capabilities use bit 6 (`0x0040`) for *required* and bit 7 (`0x0080`)
  for *capable*

### WPA3/SAE

- Dragonfly handshake replaces the WPA2 4-way handshake
- Forward secrecy - captured sessions cannot be decrypted later
- Dictionary-attack resistant - no offline brute force
- PMF is mandatory

### Beacon Protection

- Broadcast Integrity Protocol (BIP) protects beacon frames
- Prevents fake AP and downgrade attacks
- Required for WiFi 7 certification

### OWE (Enhanced Open)

- Diffie-Hellman key exchange for open networks
- Encrypts traffic without a password
- No authentication - still vulnerable to active MITM

### 6 GHz Band

- WPA3 only (no WPA2 fallback)
- PMF always enabled
- Deauth attacks are impossible by design

## Architecture

```
sting/
├── README.md                 # This file
├── setup.py                  # Package metadata and entry point
├── pyproject.toml            # Build system and pytest configuration
├── setup.cfg                 # Flake8 configuration
├── requirements.txt          # Runtime dependencies
├── sting/                    # Main package
│   ├── __init__.py           # Metadata, banner and reason codes
│   ├── __main__.py           # python -m sting entry point
│   ├── cli.py                # Argument parsing, workflows, output formats
│   ├── ieee80211.py          # Pure 802.11 parsing (RSN/WPA/channels/MACs)
│   ├── system.py             # Interface discovery, monitor mode, channels
│   ├── scanner.py            # Scapy scanner + iw/netsh fallback
│   ├── deauth.py             # Packet building, transmission, statistics
│   ├── updater.py            # GitHub self-update with integrity checks
│   └── security_features.py  # Educational content modules
├── tests/                    # Unit tests (unittest / pytest compatible)
└── .github/workflows/ci.yml  # GitHub Actions CI
```

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pip install -e ".[test]"

# Run tests
python -m pytest

# Lint
flake8 sting tests
```

The test suite covers RSN/WPA parsing, PMF detection, channel mapping, scan
output parsers, CLI filtering/output, updater version comparison, safe zip
extraction, and deauth dry-run statistics.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see the `LICENSE` file for details.

## Disclaimer

This tool is for **educational purposes only**. The authors are not responsible
for any misuse or damage caused by this tool. Users are responsible for
complying with all applicable local, state, and federal laws.

**Always obtain written permission before testing any network you do not own.**
