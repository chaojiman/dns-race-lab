"""Race ordering and answer-consistency classification."""

from __future__ import annotations

import unittest

from dnsrace import wire
from dnsrace.consistency import classify
from dnsrace.mock import MockDnsServer, MockZone
from dnsrace.race import race
from dnsrace.transports import QueryResult, TcpResolver, UdpResolver, make_resolvers


def response_message(addresses: list[str], *, rcode: int = wire.RCODE_NOERROR, ttl: int = 60) -> wire.Message:
    query = wire.parse_message(wire.build_query("example.com")[0])
    answers = [wire.encode_rr("example.com", wire.QTYPE_A, ttl, wire.encode_a(address)) for address in addresses]
    return wire.parse_message(wire.encode_response(query, answers, rcode=rcode))


def result_for(resolver: str, addresses: list[str], *, rcode: int = wire.RCODE_NOERROR, ttl: int = 60) -> QueryResult:
    return QueryResult(
        resolver=resolver,
        transport="udp",
        qname="example.com",
        qtype=wire.QTYPE_A,
        rtt_ms=1.0,
        message=response_message(addresses, rcode=rcode, ttl=ttl),
    )


def failed_result(resolver: str, error: str = "timeout") -> QueryResult:
    return QueryResult(
        resolver=resolver,
        transport="udp",
        qname="example.com",
        qtype=wire.QTYPE_A,
        rtt_ms=0.0,
        error=error,
    )


class ClassifyTests(unittest.TestCase):
    def test_agree(self) -> None:
        report = classify([result_for("a", ["192.0.2.1"]), result_for("b", ["192.0.2.1"])])
        self.assertEqual(report.verdict, "agree")
        self.assertIsNotNone(report.majority)
        self.assertEqual(report.dissent, [])
        self.assertEqual(len(report.groups), 1)

    def test_majority_and_dissent(self) -> None:
        report = classify(
            [
                result_for("a", ["192.0.2.1"]),
                result_for("b", ["192.0.2.1"]),
                result_for("c", ["198.51.100.7"]),
            ]
        )
        self.assertEqual(report.verdict, "disagree")
        self.assertEqual(report.dissent, ["c"])
        self.assertEqual(report.majority.answers, frozenset({"192.0.2.1"}))

    def test_tie_has_no_majority(self) -> None:
        report = classify([result_for("a", ["192.0.2.1"]), result_for("b", ["192.0.2.2"])])
        self.assertIsNone(report.majority)
        self.assertEqual(sorted(report.dissent), ["a", "b"])

    def test_overlapping_answers_are_partial(self) -> None:
        report = classify(
            [
                result_for("a", ["192.0.2.1", "192.0.2.2"]),
                result_for("b", ["192.0.2.2", "192.0.2.3"]),
            ]
        )
        self.assertEqual(report.verdict, "partial")
        self.assertEqual(len(report.overlap), 1)

    def test_rcode_mismatch_is_disagreement(self) -> None:
        report = classify(
            [
                result_for("a", ["192.0.2.1"]),
                result_for("b", [], rcode=wire.RCODE_NXDOMAIN),
            ]
        )
        self.assertEqual(report.verdict, "disagree")
        self.assertEqual(len(report.groups), 2)

    def test_all_failures_are_unreachable(self) -> None:
        report = classify([failed_result("a"), failed_result("b", "connection refused")])
        self.assertEqual(report.verdict, "unreachable")
        self.assertIsNone(report.majority)
        self.assertEqual(len(report.failures), 2)

    def test_failures_are_reported_alongside_successes(self) -> None:
        report = classify([result_for("a", ["192.0.2.1"]), failed_result("b")])
        self.assertEqual(report.verdict, "agree")
        self.assertEqual(report.failures, [("b", "timeout")])

    def test_to_dict_shape(self) -> None:
        payload = classify([result_for("a", ["192.0.2.1"])]).to_dict()
        self.assertEqual(payload["verdict"], "agree")
        self.assertEqual(payload["majority"]["answers"], ["192.0.2.1"])
        self.assertEqual(payload["groups"][0]["resolvers"], ["a"])


class RaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.fast = await MockDnsServer(MockZone(ttl=60).add_a("example.com", "192.0.2.10")).start()
        self.slow = await MockDnsServer(MockZone(ttl=60).add_a("example.com", "192.0.2.10")).start()
        self.slow.delay_ms = 120

    async def asyncTearDown(self) -> None:
        await self.fast.stop()
        await self.slow.stop()

    async def test_fastest_resolver_is_the_winner(self) -> None:
        resolvers = make_resolvers([self.slow.udp_spec, self.fast.udp_spec])
        result = await race(resolvers, "example.com")
        self.assertIsNotNone(result.winner)
        self.assertEqual(result.winner.resolver, self.fast.udp_spec)
        self.assertEqual(len(result.results), 2)
        self.assertEqual(result.order[0].resolver, self.fast.udp_spec)

    async def test_mixed_transports_agree(self) -> None:
        resolvers = [UdpResolver(self.fast.udp_spec, self.fast.host, self.fast.port), TcpResolver(self.fast.tcp_spec, self.fast.host, self.fast.port)]
        result = await race(resolvers, "example.com")
        report = classify(result.results)
        self.assertEqual(report.verdict, "agree")
        self.assertEqual(result.winner.addresses(), frozenset({"192.0.2.10"}))

    async def test_every_resolver_failing_yields_no_winner(self) -> None:
        resolvers = [
            TcpResolver("tcp://127.0.0.1:1", "127.0.0.1", 1),
            TcpResolver("tcp://127.0.0.1:2", "127.0.0.1", 2),
        ]
        result = await race(resolvers, "example.com", timeout=0.5)
        self.assertIsNone(result.winner)
        self.assertEqual(classify(result.results).verdict, "unreachable")
        self.assertEqual(len(result.order), 2)

    async def test_empty_resolver_list_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            await race([], "example.com")