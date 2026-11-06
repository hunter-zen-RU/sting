"""
STING - Security Testing & Investigation of Networks & Gateways
A CLI-based WiFi deauthentication tool for educational purposes.

Learn how deauth attacks work, how PMF (802.11w) protects against them,
and understand modern WiFi security mechanisms.
"""

__title__ = "STING"
__version__ = "1.1.0"
__author__ = "STING Open Source Contributors"
__license__ = "MIT"
__description__ = "WiFi Security Testing & Education Tool"
__github_url__ = "https://github.com/hunter-zen-RU/sting"

BANNER = r"""
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
"""

DEAUTH_REASON_CODES = {
    0: "Reserved",
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Leaving IBSS/ESS",
    4: "Disassociated due to inactivity",
    5: "AP unable to handle all associated stations",
    6: "Class 2 frame from nonauthenticated station",
    7: "Class 3 frame from nonassociated station",
    8: "Leaving BSS",
    9: "Station not authenticated",
    10: "Unacceptable Power Capability element",
    11: "Unacceptable Supported Channels element",
    12: "BSS Transition Management",
    13: "Invalid element (not supported in this context)",
    14: "MIC failure",
    15: "4-Way Handshake timeout",
    16: "Group Key Handshake timeout",
    17: "Handshake element differs from (Re)Asc Req/Probe Resp/Beacon",
    18: "Invalid group cipher",
    19: "Invalid pairwise cipher",
    20: "Invalid AKMP",
    21: "Unsupported RSNE version",
    22: "Invalid RSNE capabilities",
    23: "IEEE 802.1X authentication failed",
    33: "SAE authentication failure (WPA3)",
    34: "SAE anti-clogging token required (WPA3)",
    35: "SAE commitment error (WPA3)",
    36: "SAE group mismatch (WPA3)",
    37: "SAE confirmation mismatch (WPA3)",
    45: "STA doesn't support BSS Transition Mgmt Extended Capability",
    48: "STA does not support PMF (802.11w) - required by AP",
}
