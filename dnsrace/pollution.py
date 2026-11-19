"""Heuristics for replies that look like forged or hijacked answers.

These checks are evidence, not verdicts. A keyword-based heuristic that says
"this looks tampered" is wrong often enough that it should never be the only
thing presented: every finding names the record it came from, and the README is
explicit about what each heuristic does and does not prove.

What the four checks detect, in order of precision:

* `reserved-address` — an answer pointing into RFC 1918 / TEST-NET / loopback
  space for a public name. Extremely rare in legitimate DNS, common in
  interception ("DNS 污染" style) answers.
* `rcode-with-answers` — NXDOMAIN/FORMERR carrying answer records, which a
  correctly behaving server never produces.
* `cname-unresolved` — a CNAME chain that stops without the queried address
  type. Can be legitimate (the authoritative zone is broken) but usually means
  the reply was assembled by something that only understands aliases.
* `low-ttl` — addresses served with a TTL of a few seconds. Legitimate for
  active failover, suspicious for static infrastructure.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Sequence

from . import wire
from .transports import QueryResult

_RESERVED_V4 = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)

_RESERVED_V6 = tuple(
    ipaddress.ip_network(network)
    for network in (
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "2001:db8::/32",
        "ff00::/8",
    )
)

DEFAULT_MIN_TTL = 5


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    resolver: str
    detail: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "resolver": self.resolver, "detail": self.detail}


def reserved_reason(address: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    networks = _RESERVED_V4 if parsed.version == 4 else _RESERVED_V6
    for network in networks:
        if parsed in network:
            return str(network)
    return None


def analyze(
    result: QueryResult,
    *,
    min_ttl: int = DEFAULT_MIN_TTL,
    known_local: Sequence[str] = (),
) -> list[Finding]:
    """Inspect one reply. `known_local` lists addresses that are expected to be private."""
    message = result.message
    if message is None:
        return []

    findings: list[Finding] = []
    resolver = result.resolver
    expected_local = set(known_local)

    for record in message.answers:
        if record.rtype not in (wire.QTYPE_A, wire.QTYPE_AAAA):
            continue
        value = wire.rdata_text(message, record)
        if value.startswith("<unparsed"):
            continue
        reason = reserved_reason(value)
        if reason is not None and value not in expected_local:
            findings.append(
                Finding(
                    kind="reserved-address",
                    resolver=resolver,
                    detail=f"{record.name} → {value} (inside {reason})",
                )
            )
        if record.ttl <= min_ttl:
            findings.append(
                Finding(
                    kind="low-ttl",
                    resolver=resolver,
                    detail=f"{record.name} → {value} with ttl {record.ttl}s",
                )
            )

    if message.answers and message.rcode in (
        wire.RCODE_NXDOMAIN,
        wire.RCODE_SERVFAIL,
    ):
        findings.append(
            Finding(
                kind="rcode-with-answers",
                resolver=resolver,
                detail=f"{message.rcode_name()} but {len(message.answers)} answer record(s) present",
            )
        )

    if result.qtype in (wire.QTYPE_A, wire.QTYPE_AAAA):
        has_alias = any(record.rtype == wire.QTYPE_CNAME for record in message.answers)
        has_address = any(record.rtype == result.qtype for record in message.answers)
        if has_alias and not has_address:
            aliases = wire.cname_targets(message)
            findings.append(
                Finding(
                    kind="cname-unresolved",
                    resolver=resolver,
                    detail=f"chain ends at {aliases[-1] if aliases else '?'} without a {wire.QTYPE_NAMES[result.qtype]} record",
                )
            )

    return findings


def analyze_all(results: Sequence[QueryResult], **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        findings.extend(analyze(result, **kwargs))
    return findings