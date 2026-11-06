"""Tests for the system-command scanner parsers."""

import unittest

from sting.scanner import HAVE_SCAPY, _parse_iw_scan_output, _parse_netsh_output

IW_OUTPUT = """\
BSS aa:bb:cc:dd:ee:01 (on wlan0)
\tfreq: 5180
\tsignal: -42.00 dBm
\tcapability: ESS Privacy (0x0011)
\tSSID: TestNet
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: PSK SAE
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x0080)
\tWPS:\t * Version: 1.0
BSS aa:bb:cc:dd:ee:02 (on wlan0)
\tfreq: 2412
\tsignal: -70.00 dBm
\tcapability: ESS Privacy (0x0011)
\tSSID:
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x0040)
"""

NETSH_OUTPUT = """\
SSID 1 : Office
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 80%
         Channel            : 36
SSID 2 :
    Network type            : Infrastructure
    Authentication          : Open
    BSSID 1                 : 11:22:33:44:55:77
         Signal             : 40%
         Channel            : 6
"""


class IwParserTests(unittest.TestCase):
    def test_parse_networks(self):
        networks = {net["bssid"]: net for net in _parse_iw_scan_output(IW_OUTPUT, True)}
        self.assertEqual(len(networks), 2)

        first = networks["aa:bb:cc:dd:ee:01"]
        self.assertEqual(first["ssid"], "TestNet")
        self.assertEqual(first["channel"], 36)
        self.assertEqual(first["frequency"], 5180)
        self.assertEqual(first["signal"], -42)
        self.assertEqual(first["encryption"], "WPA2/3")
        self.assertTrue(first["pmf_capable"])
        self.assertFalse(first["pmf_required"])
        self.assertTrue(first["wps"])
        self.assertFalse(first["hidden"])

        second = networks["aa:bb:cc:dd:ee:02"]
        self.assertEqual(second["ssid"], "<hidden>")
        self.assertTrue(second["hidden"])
        self.assertEqual(second["channel"], 1)
        self.assertEqual(second["encryption"], "WPA3")
        self.assertTrue(second["pmf_required"])

    def test_exclude_hidden(self):
        networks = _parse_iw_scan_output(IW_OUTPUT, include_hidden=False)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["bssid"], "aa:bb:cc:dd:ee:01")


class NetshParserTests(unittest.TestCase):
    def test_parse_networks(self):
        networks = {net["bssid"]: net for net in _parse_netsh_output(NETSH_OUTPUT, True)}
        self.assertEqual(len(networks), 2)
        self.assertEqual(networks["11:22:33:44:55:66"]["encryption"], "WPA3")
        self.assertEqual(networks["11:22:33:44:55:66"]["channel"], 36)
        self.assertGreater(networks["11:22:33:44:55:66"]["signal"], -70)
        self.assertTrue(networks["11:22:33:44:55:77"]["hidden"])


@unittest.skipUnless(HAVE_SCAPY, "scapy is not installed")
class ScapyBeaconTests(unittest.TestCase):
    @staticmethod
    def make_rsn(akms, capabilities=0):
        data = b"\x01\x00"
        data += b"\x00\x0f\xac\x04"                  # group CCMP
        data += (1).to_bytes(2, "little")
        data += b"\x00\x0f\xac\x04"                  # pairwise CCMP
        data += len(akms).to_bytes(2, "little")
        for akm in akms:
            data += b"\x00\x0f\xac" + bytes([akm])
        data += int(capabilities).to_bytes(2, "little")
        return data

    def test_beacon_processing(self):
        from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

        from sting.scanner import _load_scapy, _process_packet

        self.assertTrue(_load_scapy())
        bssid = "aa:bb:cc:dd:ee:ff"
        packet = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                    addr2=bssid, addr3=bssid)
            / Dot11Beacon(cap=0x0011)
            / Dot11Elt(ID=0, info=b"ScapyNet")
            / Dot11Elt(ID=3, info=b"\x06")
            / Dot11Elt(ID=48, info=self.make_rsn([8], capabilities=0x0040))
        )
        networks = {}
        _process_packet(packet, networks, verbose=False, include_hidden=True)
        self.assertIn(bssid, networks)
        network = networks[bssid]
        self.assertEqual(network["ssid"], "ScapyNet")
        self.assertEqual(network["channel"], 6)
        self.assertEqual(network["encryption"], "WPA3")
        self.assertTrue(network["pmf_required"])
        self.assertTrue(network["pmf"])


if __name__ == "__main__":
    unittest.main()
