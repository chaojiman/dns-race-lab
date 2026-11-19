"""Fire the same question at every resolver at once and report who answered first."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Sequence

from . import wire
from .transports import DEFAULT_TIMEOUT, QueryResult, Resolver


@dataclass(slots=True)
class RaceResult:
    qname: str
    qtype: int
    timeout: float
    elapsed_ms: float
    results: list[QueryResult] = field(default_factory=list)
    """One entry per resolver, in the order the resolvers were supplied."""
    order: list[QueryResult] = field(default_factory=list)
    """Completion order — what a race actually looks like."""

    @property
    def winner(self) -> QueryResult | None:
        for result in self.order:
            if result.ok:
                return result
        return None

    def by_resolver(self) -> dict[str, QueryResult]:
        return {result.resolver: result for result in self.results}

    def to_dict(self) -> dict:
        return {
            "qname": self.qname,
            "qtype": wire.QTYPE_NAMES.get(self.qtype, self.qtype),
            "timeout_ms": int(self.timeout * 1000),
            "elapsed_ms": self.elapsed_ms,
            "winner": None if self.winner is None else self.winner.resolver,
            "results": [
                {
                    "resolver": result.resolver,
                    "transport": result.transport,
                    "ok": result.ok,
                    "rtt_ms": result.rtt_ms,
                    "attempts": result.attempts,
                    "rcode": None if result.message is None else result.message.rcode_name(),
                    "answers": sorted(result.addresses()),
                    "error": result.error,
                }
                for result in self.results
            ],
            "order": [result.resolver for result in self.order],
        }


async def _guarded(
    resolver: Resolver, qname: str, qtype: int, timeout: float
) -> QueryResult:
    try:
        return await resolver.query(qname, qtype, timeout=timeout)
    except asyncio.CancelledError:
        raise
    except Exception as error:  # transports should not raise, but a race must survive it
        return QueryResult(
            resolver=resolver.spec,
            transport=resolver.transport,
            qname=qname,
            qtype=qtype,
            rtt_ms=0.0,
            error=f"{type(error).__name__}: {error}",
        )


async def race(
    resolvers: Sequence[Resolver],
    qname: str,
    qtype: int = wire.QTYPE_A,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> RaceResult:
    """Query every resolver concurrently; each result carries its own RTT.

    Tasks are created before the first await, so no resolver gets a head start —
    important when the difference between two upstreams is under a millisecond.
    """
    if not resolvers:
        raise ValueError("at least one resolver is required")

    started = time.perf_counter()
    tasks = [asyncio.create_task(_guarded(resolver, qname, qtype, timeout)) for resolver in resolvers]
    order: list[QueryResult] = []
    for completed in asyncio.as_completed(tasks):
        order.append(await completed)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)

    results = [task.result() for task in tasks]
    return RaceResult(
        qname=wire.normalize_name(qname),
        qtype=qtype,
        timeout=timeout,
        elapsed_ms=elapsed_ms,
        results=results,
        order=order,
    )