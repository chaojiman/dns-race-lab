"""dns-race-lab — race resolvers, diff answers, flag suspicious replies."""

from __future__ import annotations

__version__ = "0.2.0"

from .bench import BenchReport, ResolverStats, benchmark  # noqa: E402
from .consistency import ConsistencyReport, GroupKey, classify  # noqa: E402
from .mock import MockDnsServer, MockZone  # noqa: E402
from .pollution import Finding, analyze, analyze_all, reserved_reason  # noqa: E402
from .race import RaceResult, race  # noqa: E402
from .transports import (  # noqa: E402
    DohResolver,
    DotResolver,
    QueryResult,
    Resolver,
    TcpResolver,
    UdpResolver,
    make_resolver,
    make_resolvers,
)
from .wire import (  # noqa: E402
    CLASS_IN,
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_CNAME,
    DnsFormatError,
    Message,
    Question,
    RR,
    build_query,
    parse_message,
    qtype_from_name,
)

__all__ = [
    "__version__",
    "BenchReport",
    "ConsistencyReport",
    "DnsFormatError",
    "DohResolver",
    "DotResolver",
    "Finding",
    "GroupKey",
    "Message",
    "MockDnsServer",
    "MockZone",
    "QTYPE_A",
    "QTYPE_AAAA",
    "QTYPE_CNAME",
    "CLASS_IN",
    "QueryResult",
    "Question",
    "RR",
    "RaceResult",
    "Resolver",
    "ResolverStats",
    "TcpResolver",
    "UdpResolver",
    "analyze",
    "analyze_all",
    "benchmark",
    "build_query",
    "classify",
    "make_resolver",
    "make_resolvers",
    "parse_message",
    "qtype_from_name",
    "race",
    "reserved_reason",
]