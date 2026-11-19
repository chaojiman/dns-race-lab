"""CLI-level checks: the offline self-check, zone loading and argument validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dnsrace import cli, wire


class SelfcheckTests(unittest.TestCase):
    def test_selfcheck_passes_offline(self) -> None:
        self.assertEqual(cli.main(["selfcheck"]), 0)


class ArgumentTests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_race_requires_a_resolver(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            cli.main(["race", "--qname", "example.com"])
        self.assertNotEqual(caught.exception.code, 0)

    def test_unknown_command(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["nonsense"])


class RcodeParsingTests(unittest.TestCase):
    def test_names_and_numbers(self) -> None:
        self.assertEqual(cli._parse_rcode("NXDOMAIN"), wire.RCODE_NXDOMAIN)
        self.assertEqual(cli._parse_rcode("nxdomain"), wire.RCODE_NXDOMAIN)
        self.assertEqual(cli._parse_rcode("2"), wire.RCODE_SERVFAIL)

    def test_unknown_name(self) -> None:
        with self.assertRaises(SystemExit):
            cli._parse_rcode("nope")


class ZoneLoadingTests(unittest.TestCase):
    def test_zone_json(self) -> None:
        document = {
            "example.com": {"A": ["192.0.2.10"], "AAAA": ["2001:db8::10"]},
            "www.example.com": {"CNAME": "example.com"},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "zone.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            zone = cli._load_zone(str(path))

        self.assertEqual(zone.records[("example.com", wire.QTYPE_A)], ["192.0.2.10"])
        self.assertEqual(zone.records[("example.com", wire.QTYPE_AAAA)], ["2001:db8::10"])
        self.assertEqual(zone.records[("www.example.com", wire.QTYPE_CNAME)], ["example.com"])

    def test_missing_zone_file_is_empty(self) -> None:
        self.assertEqual(cli._load_zone(None).records, {})