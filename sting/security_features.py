"""
WiFi Security Features Education Module (2026)

Comprehensive educational content about modern WiFi security mechanisms.
Explains how each feature works, why it matters, and how it affects
penetration testing.

Topics covered:
  - Protected Management Frames (PMF / 802.11w)
  - WPA3 / SAE (Simultaneous Authentication of Equals)
  - Beacon Protection (802.11-2016)
  - OWE (Opportunistic Wireless Encryption / Enhanced Open)
  - 6 GHz Band Security Requirements (WiFi 6E/7)
"""


def _print_header(title: str):
    """Print a formatted section header."""
    width = 68
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)
    print()


def _print_subsection(title: str):
    """Print a subsection title."""
    print(f"  [{title}]")
    print()


def print_pmf_education():
    """Protected Management Frames (802.11w) - Detailed Explanation."""
    _print_header("Protected Management Frames (PMF) - IEEE 802.11w")

    print("  OVERVIEW")
    print("  --------")
    print("  Before 802.11w, all 802.11 management frames were transmitted")
    print("  unencrypted and unauthenticated. This meant ANY device could")
    print("  forge management frames, including:")
    print("    - Deauthentication frames (the deauth attack)")
    print("    - Disassociation frames")
    print("    - Beacon frames (fake AP attacks)")
    print("    - Probe responses")
    print()
    print("  802.11w / PMF adds cryptographic protection to unicast and")
    print("  broadcast management frames using the same encryption keys")
    print("  established during the 4-way handshake.")
    print()

    _print_subsection("How PMF Works")
    print("  1. Association: During (re)association, the STA and AP negotiate")
    print("     PMF support via RSN capabilities in the Beacons/Probe Responses")
    print("     and Association Request/Response frames.")
    print()
    print("  2. Key Establishment: After the 4-way handshake, both parties")
    print("     have the Pairwise Transient Key (PTK) and Group Temporal Key (GTK).")
    print()
    print("  3. Protected Frames: Management frames are encrypted using:")
    print("     - Unicast: CCMP (AES-CTR) or BIP-CMAC-256 using PTK")
    print("     - Broadcast: BIP (Broadcast Integrity Protocol) using IGTK")
    print()
    print("  4. Deauthentication: With PMF, a deauth frame must include a")
    print("     valid Message Integrity Code (MIC). Without the PTK, an")
    print("     attacker cannot forge valid deauth frames.")
    print()

    _print_subsection("PMF Modes")
    print("  PMF Capable (Optional):  AP supports PMF but doesn't require it.")
    print("    - Clients CAN use PMF if they support it")
    print("    - Clients MAY still connect without PMF")
    print("    - Deauth attack: MAY work against non-PMF clients")
    print()
    print("  PMF Required (Mandatory): AP REQUIRES PMF for all clients.")
    print("    - ALL clients MUST support 802.11w")
    print("    - Clients without PMF are rejected (Reason code 48)")
    print("    - Deauth attack: FAILS - frames without MIC are dropped")
    print()

    _print_subsection("Impact on Deauth Attacks")
    print("  Legacy AP (No PMF):  Deauth attack works. AP accepts plaintext")
    print("    deauth as valid. [VULNERABLE]")
    print()
    print("  PMF Capable (Optional): Deauth attack may work against older")
    print("    clients that don't support PMF. PMF-capable clients will")
    print("    ignore the forged deauth. [PARTIALLY PROTECTED]")
    print()
    print("  PMF Required: Deauth attack blocked. The AP and all clients")
    print("    require encrypted management frames. [PROTECTED]")
    print()

    _print_subsection("PMF and WPA3")
    print("  WPA3 MANDATES PMF. All WPA3-certified devices must support and")
    print("  enable PMF. This means:")
    print("    - WPA3 networks are inherently protected against deauth")
    print("    - Deauth attacks against WPA3 networks will always fail")
    print("    - This is by design - not a bypass to discover")
    print()

    _print_subsection("2026 Update: PMF Evolution")
    print("  - IEEE 802.11-2024/2026 standard revisions expand PMF requirements")
    print("  - All new WiFi CERTIFIED 7 (802.11be) devices require PMF")
    print("  - 6 GHz band (WiFi 6E/7) mandates PMF for all connections")
    print("  - Enhanced BIP (BIP-CMAC-256, BIP-GMAC-256) for stronger integrity")
    print("  - PMF is now considered a baseline security requirement")
    print()

    _print_subsection("Testing Guidance")
    print("  To test if a network has PMF enabled:")
    print("    1. Use STING to scan - PMF column shows YES/NO")
    print("    2. Look for RSN capabilities in beacon frames:")
    print("       - Bit 6 (0x20) = MFP Capable")
    print("       - Bit 7 (0x40) = MFP Required")
    print("    3. Try a deauth attack - if it fails, PMF is likely active")
    print("    4. For educational demos, use legacy APs or disable PMF")
    print()


def print_wpa3_education():
    """WPA3 / SAE Authentication - Detailed Explanation."""
    _print_header("WPA3 / SAE (Simultaneous Authentication of Equals)")

    print("  OVERVIEW")
    print("  --------")
    print("  WPA3, introduced in 2018 and mandatory for WiFi CERTIFIED since")
    print("  2020, replaces WPA2-PSK with SAE (Simultaneous Authentication of")
    print("  Equals), also known as the Dragonfly handshake.")
    print()

    _print_subsection("Key Improvements over WPA2")
    print("  1. SAE Handshake: Replaces the 4-way handshake with a password-")
    print("     authenticated key exchange based on Dragonfly (RFC 7664 / RFC 5931)")
    print()
    print("  2. Forward Secrecy: Even if the password is later compromised,")
    print("     previously recorded sessions cannot be decrypted.")
    print()
    print("  3. Offline Dictionary Attack Resistance: SAE uses a Password-")
    print("     Authenticated Key Exchange (PAKE). An attacker cannot brute-force")
    print("     the password offline from captured handshakes.")
    print()
    print("  4. PMF Mandatory: All WPA3 connections require PMF (802.11w).")
    print()
    print("  5. SAE Anti-Clogging: Prevents denial-of-service via rate limiting")
    print("     of SAE commit frames with anti-clogging tokens.")
    print()

    _print_subsection("SAE Handshake Flow")
    print("  [1] Commit Phase (two-way):")
    print("      STA -> AP: SAE Commit (scalar, element, anti-clogging token)")
    print("      AP -> STA: SAE Commit (scalar, element, anti-clogging token)")
    print("      - Uses password to derive a finite cyclic group element")
    print("      - Each side generates a random scalar and element")
    print("      - Anti-clogging tokens used when rate-limited")
    print()
    print("  [2] Confirm Phase (two-way):")
    print("      STA -> AP: SAE Confirm (confirmation key, scalar, element)")
    print("      AP -> STA: SAE Confirm (confirmation key, scalar, element)")
    print("      - Each side proves knowledge of the shared password")
    print("      - Confirmation values computed using the exchanged values")
    print()
    print("  [3] Key Derivation:")
    print("      Both sides derive the same Pairwise Master Key (PMK)")
    print("      - PMK = HKDF-extract(salt=0, ikm=shared_secret)")
    print("      - Followed by standard 4-way handshake for PTK derivation")
    print()

    _print_subsection("WPA3 Variants")
    print("  WPA3-Personal (SAE):")
    print("    - Pre-shared key (password) used in SAE handshake")
    print("    - No authentication server needed")
    print("    - Suitable for home/small office")
    print()
    print("  WPA3-Enterprise:")
    print("    - Uses 802.1X with EAP authentication")
    print("    - Requires RADIUS authentication server")
    print("    - Offers Suite B cryptographic profiles (192-bit)")
    print()
    print("  WPA3-Transition (Mixed Mode):")
    print("    - Supports both WPA2 and WPA3 clients")
    print("    - Beacons include both RSN and WPA IEs")
    print("    - Vulnerable to downgrade attacks (capture WPA2 handshake)")
    print()

    _print_subsection("2026 Update: WPA3 Evolution")
    print("  - WPA3 is now the MINIMUM standard for WiFi CERTIFIED devices")
    print("  - WPA2-only devices are no longer certifiable (since 2024)")
    print("  - 6 GHz band REQUIRES WPA3 - WPA2 not allowed")
    print("  - Enhanced SAE with stronger groups (ECP 521, BP256/384/512)")
    print("  - Wi-Fi Enhanced Open (OWE) is the standard for open networks")
    print()

    _print_subsection("Penetration Testing Relevance")
    print("  - WPA3 handshake capture is still possible (for PMKID)")
    print("  - Offline password cracking is INFEAISIBLE (SAE is immune)")
    print("  - Downgrade attacks target WPA3-Transition mode")
    print("  - PMKID capture works on some WPA3 implementations (weak)")
    print("  - Deauth attacks on WPA3 are BLOCKED by PMF")
    print("  - Focus on: WPS, management interface, client-side attacks")
    print()


def print_beacon_protection_education():
    """Beacon Protection - Detailed Explanation."""
    _print_header("Beacon Protection (IEEE 802.11-2016)")

    print("  OVERVIEW")
    print("  --------")
    print("  Beacon frames advertise network presence and carry critical")
    print("  information (SSID, supported rates, capabilities, etc.).")
    print("  Without protection, an attacker can forge beacons to:")
    print("    - Create fake APs (Evil Twin attacks)")
    print("    - Broadcast malicious capabilities (downgrade attacks)")
    print("    - Flood the airspace with beacon frames (DoS)")
    print()

    _print_subsection("How Beacon Protection Works")
    print("  1. The AP includes a Beacon Protection IE in beacon frames")
    print("  2. A Beacon Protection MIC is appended using BIP (Broadcast")
    print("     Integrity Protocol) with the Integrity GTK (IGTK)")
    print("  3. Clients verify the MIC before processing beacon contents")
    print("  4. Forged or modified beacons are silently discarded")
    print()

    _print_subsection("Impact on Security Testing")
    print("  - Evil Twin attacks require the IGTK (not shared with clients)")
    print("  - Beacon flooding is still possible but tampered beacons")
    print("    are ignored by PMF-capable clients")
    print("  - Downgrade attacks via modified beacon capabilities fail")
    print("  - Clients without PMF support remain vulnerable")
    print()

    _print_subsection("2026 Update")
    print("  - Beacon Protection is MANDATORY for WiFi 7 certification")
    print("  - All 6 GHz APs must implement Beacon Protection")
    print("  - Enhanced BIP uses 256-bit keys (BIP-CMAC-256)")
    print()


def print_owe_education():
    """Opportunistic Wireless Encryption (OWE / Enhanced Open) - Explanation."""
    _print_header("Opportunistic Wireless Encryption (OWE) - RFC 8110")

    print("  OVERVIEW")
    print("  --------")
    print("  OWE (also called Enhanced Open or Wi-Fi CERTIFIED Enhanced Open)")
    print("  provides encryption for OPEN networks without requiring a password.")
    print("  It uses Diffie-Hellman key exchange to derive a unique encryption")
    print("  key for each client session.")
    print()

    _print_subsection("How OWE Works")
    print("  1. Client sends Association Request to OWE AP")
    print("  2. AP responds with its Diffie-Hellman public key in the")
    print("     Association Response (via OWE DH IE)")
    print("  3. Client generates its own DH key pair and computes the shared")
    print("     secret from AP's public key and client's private key")
    print("  4. Both sides derive a PMK from the shared secret")
    print("  5. Standard 4-way handshake follows for PTK derivation")
    print()

    _print_subsection("Security Properties")
    print("  - Protects against passive eavesdropping (each session is unique)")
    print("  - Does NOT provide authentication (no password)")
    print("  - Vulnerable to: active MITM attacks (no server authentication)")
    print("  - Prevents: open network sniffing, session hijacking")
    print()

    _print_subsection("2026 Update")
    print("  - OWE is now the STANDARD for all open/public WiFi networks")
    print("  - Legacy open networks (no encryption) are deprecated")
    print("  - OWE Transition Mode allows mixed OWE/legacy operation")
    print()


def print_6ghz_education():
    """6 GHz Band (WiFi 6E/7) Security Requirements - Explanation."""
    _print_header("6 GHz Band Security (WiFi 6E / WiFi 7)")

    print("  OVERVIEW")
    print("  --------")
    print("  The 6 GHz band (5925-7125 MHz) opened for unlicensed use brings")
    print("  strict security REQUIREMENTS that differ from 2.4/5 GHz bands.")
    print()

    _print_subsection("Mandatory Security for 6 GHz")
    print("  1. WPA3 MANDATORY: No WPA2 or WPA3-Transition allowed")
    print("  2. PMF MANDATORY: Protected Management Frames required")
    print("  3. Beacon Protection REQUIRED")
    print("  4. FILS (Fast Initial Link Setup) or SAE for authentication")
    print("  5. 6 GHz client must validate AP is legitimate before connecting")
    print()

    _print_subsection("6 GHz Discovery: FILS and Fast Roaming")
    print("  - FILS (Fast Initial Link Setup, 802.11ai): Reduces connection")
    print("    time from ~100ms to under 10ms using FILS authentication")
    print("  - FILS uses public key cryptography (ECDSA) for authentication")
    print("  - Unsolicited Probe Responses in 6 GHz are prohibited")
    print("  - Clients discover networks via: Beacons, FILS Discovery frames,")
    print("    or previously cached information")
    print()

    _print_subsection("Penetration Testing on 6 GHz")
    print("  - Deauth attacks are COMPLETELY BLOCKED (PMF always enabled)")
    print("  - Traditional deauth tools (aireplay-ng, mdk4) DON'T work on 6 GHz")
    print("  - WPA2 handshake capture is impossible (no WPA2 on 6 GHz)")
    print("  - WPA3 SAE handshake capture is still possible")
    print("  - PMKID capture may work on some implementations")
    print("  - Focus areas: OWE transition mode flaws, FILS authentication bugs")
    print()

    _print_subsection("2026 Landscape")
    print("  - WiFi 7 (802.11be) devices fully operational in 6 GHz")
    print("  - MLO (Multi-Link Operation) creates new attack surfaces")
    print("  - 320 MHz channels in 6 GHz for ultra-high throughput")
    print("  - Security testing tools are still evolving for 6 GHz")
    print("  - Software-defined radio (SDR) approaches are emerging")
    print()
