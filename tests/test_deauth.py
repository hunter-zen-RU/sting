"""Tests for the deauthentication engine's dry-run mode and validation."""

import unittest
from unittest.mock import patch

from sting.deauth import DeauthEngine, HAVE_SCAPY


class DeauthEngineTests(unittest.TestCase):
    def make_engine(self, **overrides):
        options = dict(
            interface="wlan0",
            ap_bssid="AA:BB:CC:DD:EE:FF",
            ap_ssid="TestNet",
            target_mac="ff:ff:ff:ff:ff:ff",
            channel=0,
            reason_code=7,
            dry_run=True,
        )
        options.update(overrides)
        return DeauthEngine(**options)

    def test_normalizes_mac(self):
        engine = self.make_engine()
        self.assertEqual(engine.ap_bssid, "aa:bb:cc:dd:ee:ff")

    def test_invalid_mac_rejected(self):
        with self.assertRaises(ValueError):
            self.make_engine(ap_bssid="not-a-mac")

    def test_invalid_reason_rejected(self):
        with self.assertRaises(ValueError):
            self.make_engine(reason_code=70000)

    def test_dry_run_loop_statistics(self):
        engine = self.make_engine()
        calls = {"count": 0}

        def stop():
            calls["count"] += 1
            return calls["count"] > 3

        engine.run_loop(count=2, delay=0, stop_flag=stop)
        self.assertEqual(engine.cycles, 3)
        self.assertEqual(engine.packets_sent, 6)
        self.assertEqual(engine.errors, 0)

        stats = engine.to_dict()
        self.assertTrue(stats["dry_run"])
        self.assertEqual(stats["packets_sent"], 6)
        self.assertEqual(stats["reason"], "Class 3 frame from nonassociated station")

    def test_invalid_count_and_delay(self):
        engine = self.make_engine()
        with self.assertRaises(ValueError):
            engine.run_loop(count=0)
        with self.assertRaises(ValueError):
            engine.run_loop(count=1, delay=-1)

    def test_duration_stops_loop(self):
        engine = self.make_engine()
        engine.run_loop(count=1, delay=0.01, duration=0.03)
        self.assertGreater(engine.cycles, 0)
        self.assertIsNotNone(engine.end_time)
        self.assertLess(engine._elapsed(), 2)

    def test_dry_run_does_not_tune_channel(self):
        engine = self.make_engine(channel=6)
        with patch("sting.deauth.set_channel") as set_channel:
            engine.run_loop(count=1, delay=0.0, duration=0.01)
        set_channel.assert_not_called()

    @unittest.skipUnless(HAVE_SCAPY, "scapy is not installed")
    def test_packet_structure(self):
        from scapy.all import Dot11, Dot11Deauth

        engine = self.make_engine(channel=6, dry_run=False)
        packet = engine._build_packet()
        self.assertTrue(packet.haslayer(Dot11))
        self.assertTrue(packet.haslayer(Dot11Deauth))
        self.assertEqual(packet[Dot11Deauth].reason, 7)
        self.assertEqual(packet[Dot11].addr2, "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
