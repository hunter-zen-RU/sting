"""Tests for CLI filtering, formatting and argument parsing."""

import json
import unittest
from argparse import Namespace

from sting.cli import (
    _scan_channels,
    build_parser,
    filter_networks,
    render_csv,
    render_json,
    render_table,
)


def make_network(**overrides):
    network = {
        "ssid": "TestNet",
        "hidden": False,
        "bssid": "aa:bb:cc:dd:ee:ff",
        "channel": 6,
        "frequency": 2437,
        "signal": -45,
        "encryption": "WPA2",
        "pmf": False,
        "pmf_required": False,
        "pmf_capable": False,
        "wps": False,
        "last_seen": 0.0,
    }
    network.update(overrides)
    return network


class FilterTests(unittest.TestCase):
    def setUp(self):
        self.networks = [
            make_network(ssid="Bravo", bssid="00:00:00:00:00:02", channel=36, signal=-80),
            make_network(ssid="Alpha", bssid="00:00:00:00:00:01", channel=6, signal=-40),
            make_network(ssid="<hidden>", hidden=True, bssid="00:00:00:00:00:03",
                         channel=1, signal=-60),
        ]

    def test_sort_by_signal(self):
        result = filter_networks(self.networks, sort_by="signal")
        self.assertEqual([net["ssid"] for net in result], ["Alpha", "<hidden>", "Bravo"])

    def test_sort_by_ssid(self):
        result = filter_networks(self.networks, sort_by="ssid")
        self.assertEqual(result[0]["ssid"], "<hidden>")
        self.assertEqual(result[-1]["ssid"], "Bravo")

    def test_filter_ssid_case_insensitive(self):
        result = filter_networks(self.networks, ssid="alph")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["ssid"], "Alpha")

    def test_filter_min_signal(self):
        result = filter_networks(self.networks, min_signal=-50)
        self.assertEqual([net["ssid"] for net in result], ["Alpha"])

    def test_hide_hidden(self):
        result = filter_networks(self.networks, hide_hidden=True)
        self.assertNotIn("<hidden>", [net["ssid"] for net in result])


class RenderTests(unittest.TestCase):
    def test_table_marks_pmf_and_wps(self):
        network = make_network(pmf_required=True, wps=True)
        table = render_table([network])
        self.assertIn("TestNet", table)
        self.assertIn("REQ", table)
        self.assertIn("YES", table)

    def test_json_round_trip(self):
        network = make_network()
        parsed = json.loads(render_json([network]))
        self.assertEqual(parsed[0]["bssid"], network["bssid"])
        self.assertEqual(parsed[0]["encryption"], "WPA2")

    def test_csv_header_and_row(self):
        rendered = render_csv([make_network()])
        lines = rendered.strip().splitlines()
        self.assertIn("ssid", lines[0])
        self.assertIn("bssid", lines[0])
        self.assertIn("TestNet", lines[1])


class ParserTests(unittest.TestCase):
    def test_defaults(self):
        args = build_parser().parse_args([])
        self.assertEqual(args.station, "ff:ff:ff:ff:ff:ff")
        self.assertEqual(args.count, 3)
        self.assertEqual(args.scan_time, 10.0)
        self.assertEqual(args.format, "table")
        self.assertEqual(args.band, "2.4+5")

    def test_invalid_count_rejected(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["-n", "0"])

    def test_channel_selection(self):
        args = Namespace(channels="1-3,36", channel=None, no_hop=False, band="2.4+5")
        self.assertEqual(_scan_channels(args), [1, 2, 3, 36])

        args = Namespace(channels=None, channel=6, no_hop=False, band="2.4+5")
        self.assertEqual(_scan_channels(args), [6])

        args = Namespace(channels=None, channel=None, no_hop=True, band="2.4+5")
        self.assertIsNone(_scan_channels(args))

        args = Namespace(channels=None, channel=None, no_hop=False, band="2.4")
        self.assertEqual(_scan_channels(args), list(range(1, 14)))


if __name__ == "__main__":
    unittest.main()
