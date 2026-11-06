"""Tests for pure IEEE 802.11 parsing helpers."""

import unittest

from sting.ieee80211 import (
    BROADCAST_MAC,
    channel_from_frequency,
    channels_for_bands,
    classify_security,
    is_broadcast_mac,
    is_valid_mac,
    normalize_mac,
    parse_bands,
    parse_channel_spec,
    parse_rsn_ie,
    parse_wpa_ie,
    pmf_label,
)


def make_rsn(akms, pairwise=(4,), capabilities=0):
    """Build a minimal RSN information element body."""
    data = b"\x01\x00"                          # version 1
    data += b"\x00\x0f\xac" + bytes([4])        # group cipher: CCMP
    data += len(pairwise).to_bytes(2, "little")
    for cipher in pairwise:
        data += b"\x00\x0f\xac" + bytes([cipher])
    data += len(akms).to_bytes(2, "little")
    for akm in akms:
        data += b"\x00\x0f\xac" + bytes([akm])
    data += int(capabilities).to_bytes(2, "little")
    return data


def make_wpa(akms=(2,), pairwise=(4,)):
    """Build a minimal WPA vendor information element body."""
    data = b"\x00\x50\xf2\x01"                  # Microsoft OUI + type
    data += b"\x01\x00"                         # version 1
    data += b"\x00\x50\xf2" + bytes([2])        # group cipher: TKIP
    data += len(pairwise).to_bytes(2, "little")
    for cipher in pairwise:
        data += b"\x00\x50\xf2" + bytes([cipher])
    data += len(akms).to_bytes(2, "little")
    for akm in akms:
        data += b"\x00\x50\xf2" + bytes([akm])
    return data


class MacTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_valid(self):
        self.assertTrue(is_valid_mac("00:11:22:33:44:55"))
        self.assertTrue(is_valid_mac(BROADCAST_MAC))
        self.assertFalse(is_valid_mac("00:11:22:33:44"))
        self.assertFalse(is_valid_mac("zz:11:22:33:44:55"))
        self.assertFalse(is_valid_mac(None))

    def test_broadcast(self):
        self.assertTrue(is_broadcast_mac(BROADCAST_MAC.upper()))
        self.assertFalse(is_broadcast_mac("00:11:22:33:44:55"))

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            normalize_mac("not-a-mac")


class RsnTests(unittest.TestCase):
    def test_wpa2_psk(self):
        rsn = parse_rsn_ie(make_rsn([2]))
        self.assertEqual(rsn["akms"], ["PSK"])
        self.assertEqual(rsn["group_cipher"], "CCMP")
        self.assertFalse(rsn["pmf"])
        self.assertEqual(classify_security(rsn, None), "WPA2")

    def test_pmf_required(self):
        rsn = parse_rsn_ie(make_rsn([2], capabilities=0x0040))
        self.assertTrue(rsn["pmf_required"])
        self.assertFalse(rsn["pmf_capable"])
        self.assertTrue(rsn["pmf"])

    def test_pmf_capable_is_not_required(self):
        rsn = parse_rsn_ie(make_rsn([2], capabilities=0x0080))
        self.assertFalse(rsn["pmf_required"])
        self.assertTrue(rsn["pmf_capable"])
        self.assertTrue(rsn["pmf"])

    def test_regression_old_offset_bug(self):
        # The old parser read the group-cipher OUI as a count, so it never
        # reached the capabilities field.  Capabilities must now parse.
        rsn = parse_rsn_ie(make_rsn([2], pairwise=(4,), capabilities=0x00C0))
        self.assertEqual(rsn["capabilities"], 0x00C0)
        self.assertTrue(rsn["pmf_required"])

    def test_wpa3_sae(self):
        self.assertEqual(classify_security(parse_rsn_ie(make_rsn([8])), None), "WPA3")

    def test_wpa2_wpa3_transition(self):
        self.assertEqual(
            classify_security(parse_rsn_ie(make_rsn([2, 8])), None), "WPA2/3"
        )

    def test_owe(self):
        self.assertEqual(classify_security(parse_rsn_ie(make_rsn([18])), None), "OWE")

    def test_enterprise(self):
        self.assertEqual(
            classify_security(parse_rsn_ie(make_rsn([1])), None), "WPA2-ENT"
        )
        self.assertEqual(
            classify_security(parse_rsn_ie(make_rsn([5])), None), "WPA3-ENT"
        )

    def test_malformed_ie_does_not_raise(self):
        for payload in (b"", b"\x01", b"\x01\x00\x00\x0f", b"\x01\x00" + b"\xff" * 4):
            result = parse_rsn_ie(payload)
            self.assertIn("akms", result)

    def test_wpa_ie(self):
        wpa = parse_wpa_ie(make_wpa())
        self.assertEqual(wpa["akms"], ["PSK"])
        self.assertEqual(classify_security(None, wpa), "WPA")

    def test_legacy_classification(self):
        self.assertEqual(classify_security(None, None, privacy=True), "WEP")
        self.assertEqual(classify_security(None, None, privacy=False), "OPEN")

    def test_pmf_label(self):
        self.assertEqual(pmf_label(True, True), "REQ")
        self.assertEqual(pmf_label(False, True), "CAP")
        self.assertEqual(pmf_label(False, False), "NO")


class ChannelTests(unittest.TestCase):
    def test_frequency_to_channel(self):
        self.assertEqual(channel_from_frequency(2412), 1)
        self.assertEqual(channel_from_frequency(2484), 14)
        self.assertEqual(channel_from_frequency(5180), 36)
        self.assertEqual(channel_from_frequency(5955), 1)
        self.assertEqual(channel_from_frequency(0), 0)
        self.assertEqual(channel_from_frequency(None), 0)

    def test_channel_spec(self):
        self.assertEqual(parse_channel_spec("1-3,36,36"), [1, 2, 3, 36])
        self.assertEqual(parse_channel_spec("6-4"), [4, 5, 6])
        with self.assertRaises(ValueError):
            parse_channel_spec("")
        with self.assertRaises(ValueError):
            parse_channel_spec("abc")
        with self.assertRaises(ValueError):
            parse_channel_spec("0")

    def test_bands(self):
        self.assertEqual(parse_bands("all"), ["2.4", "5", "6"])
        self.assertEqual(parse_bands("2.4+5"), ["2.4", "5"])
        channels = channels_for_bands(["2.4", "5"])
        self.assertEqual(channels[0], 1)
        self.assertIn(36, channels)
        self.assertEqual(channels.count(1), 1)


if __name__ == "__main__":
    unittest.main()
