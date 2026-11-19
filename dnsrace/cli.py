"""Command line interface.

Every subcommand works offline against the built-in mock server, which is what
`dnsrace selfcheck` exercises in CI and in the container's smoke test.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import pathlib
import sys
from typing import Sequence

from . import __version__, wire
from .bench import BenchReport, benchmark
from .consistency import ConsistencyReport, classify
from .mock import MockDnsServer, MockZone
from .pollution import DEFAULT_MIN_TTL, Finding, analyze_all
from .race import RaceResult, race
from .transports import DEFAULT_TIMEOUT, make_resolvers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsrace",
        description="Race DNS resolvers over UDP/TCP/DoT/DoH, diff their answers and flag suspicious records.",
    )
    parser.add_argument("--version", action="version", version=f"dns-race-lab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    race_cmd = sub.add_parser("race", help="ask every resolver the same question, report who won")
    race_cmd.add_argument("--qname", required=True, help="name to resolve")
    race_cmd.add_argument("--qtype", default="A", help="record type name or number (default: A)")
    race_cmd.add_argument(
        "--resolver",
        action="append",
        required=True,
        metavar="SPEC",
        help="udp://1.1.1.1 | tcp://1.1.1.1 | dot://host | doh:https://host/dns-query (repeatable)",
    )
    race_cmd.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-resolver timeout in seconds")
    race_cmd.add_argument("--min-ttl", type=int, default=DEFAULT_MIN_TTL, help="TTL below this is reported")
    race_cmd.add_argument("--known-local", action="append", default=[], metavar="ADDR", help="private address expected in answers")
    race_cmd.add_argument("--json", action="store_true", help="machine-readable output")

    probe = sub.add_parser("probe", help="benchmark resolvers over a name list")
    probe.add_argument("--names", metavar="FILE", help="file with one name per line")
    probe.add_argument("--name", action="append", default=[], metavar="NAME", help="name to include (repeatable)")
    probe.add_argument("--resolver", action="append", required=True, metavar="SPEC")
    probe.add_argument("--qtype", default="A")
    probe.add_argument("--concurrency", type=int, default=16)
    probe.add_argument("--repeat", type=int, default=1, help="how many times to query each name")
    probe.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    probe.add_argument("--json", action="store_true")

    mock_cmd = sub.add_parser("mock", help="serve a JSON zone over UDP and TCP")
    mock_cmd.add_argument("--zone", metavar="FILE", help="zone JSON (see README)")
    mock_cmd.add_argument("--host", default="127.0.0.1")
    mock_cmd.add_argument("--port", type=int, default=5353)
    mock_cmd.add_argument("--delay-ms", type=float, default=0.0)
    mock_cmd.add_argument("--truncated", action="store_true", help="force TC over UDP, answer over TCP")
    mock_cmd.add_argument("--rcode", default=None, help="force a response code (name or number)")

    sub.add_parser("selfcheck", help="run an offline end-to-end check (mock server, no network)")

    return parser


def _print_race(result: RaceResult, report: ConsistencyReport, findings: list[Finding]) -> None:
    qtype = wire.QTYPE_NAMES.get(result.qtype, result.qtype)
    print(f"{result.qname} {qtype} — {result.elapsed_ms} ms, timeout {int(result.timeout * 1000)} ms")
    print()
    width = max((len(entry.resolver) for entry in result.results), default=8)
    print(f"{'resolver'.ljust(width)}  transport  rtt        result")
    for entry in result.results:
        winner = " < first" if result.winner is not None and entry.resolver == result.winner.resolver else ""
        print(
            f"{entry.resolver.ljust(width)}  {entry.transport.ljust(9)}  "
            f"{f'{entry.rtt_ms:.3f} ms'.ljust(10)} {entry.summary()}{winner}"
        )
    print()
    print(f"consistency: {report.verdict}")
    for key, members in report.groups:
        print(f"  {key.label()}  ←  {', '.join(members)}")
    if report.dissent:
        print(f"  dissent: {', '.join(report.dissent)}")
    for resolver, error in report.failures:
        print(f"  unreachable: {resolver} ({error})")
    if report.overlap:
        for left, right in report.overlap:
            print(f"  overlapping but different: {left} ~ {right}")
    if findings:
        print()
        print("findings:")
        for finding in findings:
            print(f"  [{finding.kind}] {finding.resolver}: {finding.detail}")
    else:
        print()
        print("findings: none")


def _print_bench(report: BenchReport) -> None:
    qtype = wire.QTYPE_NAMES.get(report.qtype, report.qtype)
    print(
        f"{report.names} names × {report.repeat} ({qtype}), concurrency {report.concurrency}, "
        f"{report.total_queries} queries in {report.elapsed_ms / 1000:.2f} s"
    )
    print()
    print(f"{'resolver':<28} {'tp':<5} {'qps':>9} {'p50':>9} {'p95':>9} {'p99':>9} {'errors':>7}")
    for stats in report.per_resolver:
        print(
            f"{stats.resolver:<28} {stats.transport:<5} {stats.qps:>9.1f} "
            f"{stats.p50_ms:>7.2f}ms {stats.p95_ms:>7.2f}ms {stats.p99_ms:>7.2f}ms "
            f"{stats.errors:>7}"
        )
        if stats.error_samples:
            print(f"  errors: {', '.join(stats.error_samples)}")


def _load_names(args: argparse.Namespace) -> list[str]:
    names = list(args.name)
    if args.names:
        path = pathlib.Path(args.names)
        if not path.is_file():
            raise SystemExit(f"names file not found: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                names.append(stripped)
    if not names:
        raise SystemExit("probe needs --names FILE or at least one --name")
    return names


def _load_zone(path: str | None) -> MockZone:
    zone = MockZone()
    if path is None:
        return zone
    document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    for name, entries in document.items():
        for type_name, values in entries.items():
            qtype = wire.qtype_from_name(type_name)
            if isinstance(values, str):
                values = [values]
            if qtype == wire.QTYPE_CNAME:
                zone.add_cname(name, values[0])
            elif qtype == wire.QTYPE_A:
                zone.add_a(name, *values)
            elif qtype == wire.QTYPE_AAAA:
                zone.add_aaaa(name, *values)
            else:
                zone.records.setdefault((wire.normalize_name(name), qtype), []).extend(values)
    return zone


async def _cmd_race(args: argparse.Namespace) -> int:
    qtype = wire.qtype_from_name(args.qtype)
    resolvers = make_resolvers(args.resolver)
    result = await race(resolvers, args.qname, qtype, timeout=args.timeout)
    report = classify(result.results)
    findings = analyze_all(result.results, min_ttl=args.min_ttl, known_local=args.known_local)

    if args.json:
        payload = result.to_dict()
        payload["consistency"] = report.to_dict()
        payload["findings"] = [finding.to_dict() for finding in findings]
        print(json.dumps(payload, indent=2))
    else:
        _print_race(result, report, findings)
    return 0 if result.winner is not None else 1


async def _cmd_probe(args: argparse.Namespace) -> int:
    qtype = wire.qtype_from_name(args.qtype)
    names = _load_names(args)
    report = await benchmark(
        make_resolvers(args.resolver),
        names,
        qtype,
        concurrency=args.concurrency,
        timeout=args.timeout,
        repeat=args.repeat,
    )
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        _print_bench(report)
    return 0 if any(stats.ok for stats in report.per_resolver) else 1


async def _cmd_mock(args: argparse.Namespace) -> int:
    zone = _load_zone(args.zone)
    server = await MockDnsServer(zone).start(args.host, args.port)
    server.delay_ms = args.delay_ms
    server.truncated = args.truncated
    if args.rcode is not None:
        server.forced_rcode = _parse_rcode(args.rcode)
    print(f"listening on {server.udp_spec} (udp) and {server.tcp_spec} (tcp)", flush=True)
    if server.truncated:
        print("udp replies carry TC; tcp replies are complete", flush=True)
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:  # pragma: no cover - Ctrl-C path
        pass
    finally:
        await server.stop()
    return 0


def _parse_rcode(text: str) -> int:
    if text.isdigit():
        return int(text)
    reversed_names = {name.lower(): value for value, name in wire.RCODE_NAMES.items()}
    lowered = text.lower()
    if lowered in reversed_names:
        return reversed_names[lowered]
    raise SystemExit(f"unknown rcode {text!r}")


async def _selfcheck() -> int:
    """Offline end-to-end: mock zone → race → classify → heuristics → truncation fallback."""
    zone = (
        MockZone()
        .add_a("example.com", "192.0.2.10")
        .add_cname("www.example.com", "example.com")
        .add_a("polluted.example.com", "10.1.2.3", "192.0.2.99")
        .add_a("lowttl.example.com", "192.0.2.20")
    )
    zone.records[("lowttl.example.com", wire.QTYPE_A)] = ["192.0.2.20"]
    zone.ttl = 2

    truncated_zone = MockZone().add_a("big.example.com", "192.0.2.30")

    server = await MockDnsServer(zone).start()
    truncated = await MockDnsServer(truncated_zone).start()
    truncated.truncated = True
    failures = 0

    def check(label: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        status = "PASS" if condition else "FAIL"
        if not condition:
            failures += 1
        print(f"{status}  {label}{f' — {detail}' if detail else ''}")

    try:
        resolvers = make_resolvers([server.udp_spec, server.tcp_spec])
        result = await race(resolvers, "example.com")
        report = classify(result.results)
        check("race returns a winner", result.winner is not None)
        check("both transports agree", report.verdict == "agree", report.verdict)
        check("addresses parsed", result.winner is not None and "192.0.2.10" in result.winner.addresses())

        alias = await race(resolvers, "www.example.com")
        check(
            "cname chain resolved",
            alias.winner is not None and "192.0.2.10" in alias.winner.addresses(),
        )

        polluted = await race(make_resolvers([server.udp_spec]), "polluted.example.com")
        findings = analyze_all(polluted.results)
        check(
            "reserved address flagged",
            any(finding.kind == "reserved-address" for finding in findings),
            ", ".join(finding.kind for finding in findings) or "none",
        )

        low = await race(make_resolvers([server.udp_spec]), "lowttl.example.com", timeout=1.0)
        low_findings = analyze_all(low.results, min_ttl=5)
        check(
            "low ttl flagged",
            any(finding.kind == "low-ttl" for finding in low_findings),
        )

        fallback = await race(make_resolvers([truncated.udp_spec]), "big.example.com")
        entry = fallback.results[0]
        check(
            "truncated UDP retried over TCP",
            entry.transport == "udp+tcp" and entry.ok,
            f"{entry.transport} ok={entry.ok}",
        )

        benchmark_report = await benchmark(make_resolvers([server.udp_spec]), ["example.com"], repeat=20, concurrency=4)
        stats = benchmark_report.per_resolver[0]
        check("benchmark completes", stats.ok == 20 and stats.errors == 0, f"{stats.ok}/{stats.sent}")
    finally:
        await server.stop()
        await truncated.stop()

    print()
    print(f"selfcheck: {'ok' if failures == 0 else f'{failures} failure(s)'}")
    return 0 if failures == 0 else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "race":
            return asyncio.run(_cmd_race(args))
        if args.command == "probe":
            return asyncio.run(_cmd_probe(args))
        if args.command == "mock":
            return asyncio.run(_cmd_mock(args))
        if args.command == "selfcheck":
            return asyncio.run(_selfcheck())
    except KeyboardInterrupt:
        return 130
    except (ValueError, wire.DnsFormatError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())