# STING - Security Testing & Investigation of Networks & Gateways

**Version 1.0.0 | Educational WiFi Security Tool**

STING is a CLI-based WiFi deauthentication tool designed **exclusively for educational purposes**. It demonstrates how deauth attacks work, how modern security features (PMF/802.11w, WPA3) protect against them, and provides detailed educational content about 2026-era WiFi security standards.

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

### Core Functionality
- **WiFi Network Scanner** - List nearby networks with SSID, BSSID, channel, signal strength, encryption type, and PMF status
- **Deauthentication Attack** - Send 802.11 deauth frames to target networks (selectable by interactive scanning or direct BSSID)
- **Continuous Loop** - Deauth runs in a loop until interrupted with Ctrl+C
- **Verbose Mode** - Detailed packet structure and transmission information

### Educational Modules
- **PMF (802.11w)** - Learn how Protected Management Frames block deauth attacks
- **WPA3/SAE** - Understand Simultaneous Authentication of Equals
- **Beacon Protection** - How beacon integrity prevents fake AP attacks
- **OWE (Enhanced Open)** - Opportunistic Wireless Encryption for open networks
- **6 GHz Band Security** - WiFi 6E/7 mandatory security requirements

### Advanced Features
- **Self-Update** - Check for and install updates from GitHub
- **Interactive Selection** - Scan, choose a target, and attack in one workflow
- **Direct Mode** - Target by BSSID without scanning (for scripting)
- **Customizable** - Adjustable reason codes, packet count, delay, and channel

## Requirements

- **OS**: Linux (primary), Windows/macOS (limited scanning support)
- **Python**: 3.8+
- **Hardware**: WiFi adapter supporting monitor mode (for deauth attacks)
- **Permissions**: Root/Administrator access required for raw packet injection

### Dependencies
- `scapy` - Packet crafting and injection
- `requests` - Self-update functionality

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sting-wifi/sting.git
cd sting

# Install dependencies
pip install -r requirements.txt

# Install STING
pip install -e .
```

### Direct Install

```bash
# Install from local directory
pip install -e /path/to/sting

# Or run without installation
cd /path/to/sting
python -m sting
```

## Usage

### Interactive Mode (Recommended)

Simply run STING without arguments to enter interactive mode:

```bash
sudo sting
```

This will:
1. Detect your wireless interface
2. Scan for nearby networks (5 seconds)
3. Display a table of found networks
4. Prompt you to select a target by number
5. Ask for confirmation before starting the attack
6. Deauth continuously until Ctrl+C

### Command-Line Options

```
usage: sting [-h] [-v] [-i INTERFACE] [-c CHANNEL] [-r REASON]
             [-n COUNT] [-d DELAY] [-b BSSID] [-s STATION]
             [--update] [--list-interfaces] [--no-banner]
             [--learn-pmf] [--learn-wpa3] [--learn-beacon-protection]
             [--learn-owe] [--learn-6ghz] [--learn-all]
```

| Option | Description |
|--------|-------------|
| `-v, --verbose` | Enable verbose output with packet details |
| `-i, --interface` | Wireless interface (e.g., wlan0) |
| `-c, --channel` | Channel to operate on |
| `-r, --reason` | Deauth reason code (1-10, default: 7) |
| `-n, --count` | Packets per cycle (default: 3) |
| `-d, --delay` | Delay between cycles in seconds (default: 0.1) |
| `-b, --bssid` | Target AP BSSID (skips interactive scan) |
| `-s, --station` | Target station MAC (default: broadcast) |
| `--update` | Check and apply updates from GitHub |
| `--list-interfaces` | List available wireless interfaces |
| `--no-banner` | Suppress startup banner |
| `--learn-pmf` | Learn about PMF (802.11w) |
| `--learn-wpa3` | Learn about WPA3/SAE |
| `--learn-beacon-protection` | Learn about Beacon Protection |
| `--learn-owe` | Learn about OWE |
| `--learn-6ghz` | Learn about 6 GHz security |
| `--learn-all` | Display all educational content |

### Examples

```bash
# Interactive scan and deauth
sudo sting

# Verbose mode (see packet details)
sudo sting -v

# Direct attack on a specific AP (requires channel)
sudo sting -b AA:BB:CC:DD:EE:FF -c 6

# Target a specific client instead of broadcast
sudo sting -b AA:BB:CC:DD:EE:FF -c 6 -s 11:22:33:44:55:66

# Use reason code 1 (unspecified)
sudo sting -r 1

# Send 10 packets per cycle with 0.5s delay
sudo sting -n 10 -d 0.5

# List interfaces without scanning
sting --list-interfaces

# Check for updates
sting --update

# Learn about WiFi security features
sting --learn-all
sting --learn-pmf
sting --learn-wpa3
```

## Understanding Deauth Attacks

### How It Works

1. **Packet Crafting**: STING constructs a raw 802.11 deauthentication frame:
   - `RadioTap` - Radio metadata header
   - `Dot11` - MAC header (type=management, subtype=deauth)
   - `Dot11Deauth` - Frame body with reason code

2. **Transmission**: Packets are sent at layer 2 using the wireless interface in monitor mode

3. **Effect**: Clients receiving a valid deauth frame immediately disconnect from the AP

### Why PMF Blocks This

PMF (802.11w / Protected Management Frames) requires management frames to be:
- **Encrypted** using CCMP (AES) with the Pairwise Transient Key (PTK)
- **Authenticated** using BIP-CMAC with the Integrity GTK (IGTK)

Without the PTK (which requires the WiFi password), an attacker cannot forge valid deauth frames. The AP and PMF-capable clients simply ignore unencrypted deauth frames.

### Reason Codes

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

## 2026 Security Landscape

STING educates on these modern WiFi security features:

### Protected Management Frames (802.11w)
- Encrypts deauth, disassoc, beacon, and probe frames
- **Mandatory** for WPA3 and all 6 GHz operation
- Renders traditional deauth attacks ineffective

### WPA3/SAE
- Dragonfly handshake replaces 4-way handshake
- Forward secrecy - captured handshakes can't be decrypted later
- Dictionary attack resistant - no offline brute force
- PMF is mandatory

### Beacon Protection
- Broadcase Integrity Protocol (BIP) protects beacon frames
- Prevents fake AP and downgrade attacks
- Required for WiFi 7 certification

### OWE (Enhanced Open)
- Diffie-Hellman key exchange for open networks
- Encrypts traffic without a password
- No authentication - still vulnerable to active MITM

### 6 GHz Band
- WPA3 only (no WPA2 fallback)
- PMF always enabled
- Deauth attacks impossible by design

## Architecture

```
sting/
├── README.md               # This file
├── setup.py                # Package installer
├── requirements.txt        # Python dependencies
├── sting/                  # Main package
│   ├── __init__.py         # Package metadata, constants, reason codes
│   ├── __main__.py         # python -m sting entry point
│   ├── cli.py              # CLI orchestration and argument parsing
│   ├── scanner.py          # WiFi network scanning (scapy + system fallback)
│   ├── deauth.py           # Deauth packet crafting and transmission
│   ├── updater.py          # GitHub self-update mechanism
│   └── security_features.py # Educational content modules
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is for **educational purposes only**. The authors are not responsible
for any misuse or damage caused by this tool. Users are responsible for
complying with all applicable local, state, and federal laws.

**Always obtain written permission before testing any network you do not own.**
