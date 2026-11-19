"""Heuristic tests: reserved answers, TTL anomalies, broken chains, impossible rcodes."""

from __future__ import annotations

import unittest

from dnsrace import wire
from dnsrace.pollution import analyze, analyze_all, reserved_reason
from dnsrace.transports import QueryResult


def message_with(records: list[tuple[str, int, int, bytes]], *, rcode: int = wire.RCODE_NOERROR) -> wire.Message:
    query = wire.parse_message(wire.build_query("example.com")[0])
    answers = [wire.encode_rr(name, rtype, ttl, rdata) for name, rtype, ttl, rdata in records]
    return wire.parse_message(wire.encode_response(query, answers, rcode=rcode))


def result_of(records: list[tuple[str, int, int, bytes]], *, qtype: int = wire.QTYPE_A, rcode: int = 0) -> QueryResult:
    return QueryResult(
        resolver="test",
        transport="udp",
        qname="example.com",
        qtype=qtype,
        rtt_ms=1.0,
        message=message_with(records, rcode=rcode),
    )


class ReservedAddressTests(unittest.TestCase):
    def test_reserved_reason(self) -> None:
        self.assertEqual(reserved_reason("10.1.2.3"), "10.0.0.0/8")
        self.assertEqual(reserved_reason("192.168.1.1"), "192.168.0.0/16")
        self.assertEqual(reserved_reason("127.0.0.1"), "127.0.0.0/8")
        self.assertEqual(reserved_reason("fe80::1"), "fe80::/10")
        self.assertIsNone(reserved_reason("1.1.1.1"))
        self.assertIsNone(reserved_reason("not-an-ip"))

    def test_private_answer_is_flagged(self) -> None:
        result = result_of([("example.com", wire.QTYPE_A, 60, wire.encode_a("10.1.2.3"))])
        kinds = [finding.kind for finding in analyze(result)]
        self.assertIn("reserved-address", kinds)

    def test_known_local_is_exempt(self) -> None:
        result = result_of([("example.com", wire.QTYPE_A, 60, wire.encode_a("10.1.2.3"))])
        self.assertEqual(analyze(result, known_local=["10.1.2.3"]), [])

    def test_public_answer_is_clean(self) -> None:
        result = result_of([("example.com", wire.QTYPE_A, 60, wire.encode_a("203.0.114.5"))])
        self.assertEqual([finding.kind for finding in analyze(result)], [])


class TtlTests(unittest.TestCase):
    def test_low_ttl_is_flagged(self) -> None:
        result = result_of([("example.com", wire.QTYPE_A, 3, wire.encode_a("192.0.2.1"))])
        kinds = [finding.kind for finding in analyze(result)]
        self.assertIn("low-ttl", kinds)
        self.assertNotIn("low-ttl", [finding.kind for finding in analyze(result, min_ttl=1)])


class ChainTests(unittest.TestCase):
    def test_unresolved_cname_is_flagged_for_address_queries(self) -> None:
        result = result_of(
            [("example.com", wire.QTYPE_CNAME, 60, wire.encode_name("edge.example.net"))],
            qtype=wire.QTYPE_A,
        )
        findings = analyze(result)
        self.assertEqual([finding.kind for finding in findings], ["cname-unresolved"])
        self.assertIn("edge.example.net", findings[0].detail)

    def test_cname_is_not_flagged_for_cname_queries(self) -> None:
        result = result_of(
            [("example.com", wire.QTYPE_CNAME, 60, wire.encode_name("edge.example.net"))],
            qtype=wire.QTYPE_CNAME,
        )
        self.assertEqual(analyze(result), [])


class RcodeTests(unittest.TestCase):
    def test_answers_with_nxdomain_are_flagged(self) -> None:
        result = result_of(
            [("example.com", wire.QTYPE_A, 60, wire.encode_a("192.0.2.1"))],
            rcode=wire.RCODE_NXDOMAIN,
        )
        kinds = [finding.kind for finding in analyze(result)]
        self.assertIn("rcode-with-answers", kinds)


class AggregateTests(unittest.TestCase):
    def test_failed_results_produce_no_findings(self) -> None:
        failed = QueryResult(
            resolver="dead", transport="udp", qname="example.com", qtype=wire.QTYPE_A, rtt_ms=0.0, error="timeout"
        )
        self.assertEqual(analyze_all([failed]), [])

    def test_findings_carry_their_resolver(self) -> None:
        result = result_of([("example.com", wire.QTYPE_A, 2, wire.encode_a("10.0.0.1"))])
        findings = analyze_all([result])
        self.assertTrue(findings)
        for finding in findings:
            self.assertEqual(finding.resolver, "test")
            self.assertIn("resolver", finding.to_dict())