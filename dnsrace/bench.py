"""Throughput and latency benchmarks for one or more resolvers.

Latency percentiles are computed over individual round-trip times, not over
aggregate wall time, because an average hides exactly the tails that make a
resolver feel slow.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Sequence

from . import wire
from .transports import DEFAULT_TIMEOUT, QueryResult, Resolver


@dataclass(slots=True)
class ResolverStats:
    resolver: str
    transport: str
    sent: int
    ok: int
    errors: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    mean_ms: float
    qps: float
    error_samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "resolver": self.resolver,
            "transport": self.transport,
            "sent": self.sent,
            "ok": self.ok,
            "errors": self.errors,
            "error_rate": round(self.errors / self.sent, 4) if self.sent else 0.0,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
            "mean_ms": self.mean_ms,
            "qps": self.qps,
            "error_samples": self.error_samples,
        }


@dataclass(slots=True)
class BenchReport:
    qtype: int
    names: int
    repeat: int
    concurrency: int
    timeout: float
    elapsed_ms: float
    per_resolver: list[ResolverStats] = field(default_factory=list)

    @property
    def total_queries(self) -> int:
        return sum(stats.sent for stats in self.per_resolver)

    def to_dict(self) -> dict:
        return {
            "qtype": wire.QTYPE_NAMES.get(self.qtype, self.qtype),
            "names": self.names,
            "repeat": self.repeat,
            "concurrency": self.concurrency,
            "timeout_ms": int(self.timeout * 1000),
            "elapsed_ms": self.elapsed_ms,
            "total_queries": self.total_queries,
            "total_qps": round(self.total_queries / (self.elapsed_ms / 1000), 1) if self.elapsed_ms else 0.0,
            "resolvers": [stats.to_dict() for stats in self.per_resolver],
        }


def percentile(sorted_values: Sequence[float], ratio: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(len(sorted_values) * ratio))
    return sorted_values[index]


def summarize(resolver: Resolver, results: list[QueryResult], wall_ms: float) -> ResolverStats:
    latencies = sorted(result.rtt_ms for result in results if result.ok)
    errors = [result.error or "unknown" for result in results if not result.ok]
    sent = len(results)
    ok = len(latencies)
    return ResolverStats(
        resolver=resolver.spec,
        transport=resolver.transport,
        sent=sent,
        ok=ok,
        errors=sent - ok,
        p50_ms=round(percentile(latencies, 0.50), 3),
        p95_ms=round(percentile(latencies, 0.95), 3),
        p99_ms=round(percentile(latencies, 0.99), 3),
        mean_ms=round(sum(latencies) / ok, 3) if ok else 0.0,
        qps=round(ok / (wall_ms / 1000), 1) if wall_ms else 0.0,
        error_samples=sorted(set(errors))[:3],
    )


async def benchmark(
    resolvers: Sequence[Resolver],
    names: Sequence[str],
    qtype: int = wire.QTYPE_A,
    *,
    concurrency: int = 16,
    timeout: float = DEFAULT_TIMEOUT,
    repeat: int = 1,
) -> BenchReport:
    if not names:
        raise ValueError("benchmark needs at least one name")
    if not resolvers:
        raise ValueError("benchmark needs at least one resolver")

    questions = [name for name in names for _ in range(max(1, repeat))]
    semaphore = asyncio.Semaphore(max(1, concurrency))
    started = time.perf_counter()

    async def ask(resolver: Resolver, qname: str) -> QueryResult:
        async with semaphore:
            return await resolver.query(qname, qtype, timeout=timeout)

    per_resolver: list[ResolverStats] = []
    for resolver in resolvers:
        resolver_started = time.perf_counter()
        results = await asyncio.gather(*(ask(resolver, qname) for qname in questions))
        wall_ms = (time.perf_counter() - resolver_started) * 1000
        per_resolver.append(summarize(resolver, list(results), wall_ms))

    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    return BenchReport(
        qtype=qtype,
        names=len(names),
        repeat=max(1, repeat),
        concurrency=max(1, concurrency),
        timeout=timeout,
        elapsed_ms=elapsed_ms,
        per_resolver=per_resolver,
    )