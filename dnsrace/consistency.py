"""Compare the answers a set of resolvers returned for the same question.

The comparison is deliberately structural: resolvers are grouped by
`(rcode, answer set)`, the largest group is the majority, and everything else
is reported as dissent. Overlapping-but-different answers are called out
separately because that is the interesting case for CDN and geo-DNS setups —
two resolvers legitimately return different A records for the same name.

Nothing here decides that a resolver is *wrong*; it reports who disagrees with
the majority and lets the caller decide (see `pollution` for the heuristics that
do flag suspicious records).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from . import wire
from .transports import QueryResult


@dataclass(frozen=True, slots=True)
class GroupKey:
    rcode: int
    answers: frozenset[str]

    def label(self) -> str:
        rcode = wire.RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")
        return f"{rcode} {','.join(sorted(self.answers))}" if self.answers else rcode

    def to_dict(self) -> dict:
        return {
            "rcode": wire.RCODE_NAMES.get(self.rcode, self.rcode),
            "answers": sorted(self.answers),
        }


@dataclass(slots=True)
class ConsistencyReport:
    verdict: str
    """`agree` | `partial` | `disagree` | `unreachable`."""
    majority: GroupKey | None
    groups: list[tuple[GroupKey, list[str]]] = field(default_factory=list)
    dissent: list[str] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    """(resolver, error) for resolvers that never produced a reply."""
    overlap: list[tuple[str, str]] = field(default_factory=list)
    """Pairs of disagreeing resolver groups that share at least one address."""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "majority": None if self.majority is None else self.majority.to_dict(),
            "groups": [
                {"key": key.to_dict(), "resolvers": members}
                for key, members in self.groups
            ],
            "dissent": self.dissent,
            "failures": [{"resolver": name, "error": error} for name, error in self.failures],
            "overlap": [{"left": left, "right": right} for left, right in self.overlap],
        }


def key_for(result: QueryResult) -> GroupKey:
    if result.message is None:
        return GroupKey(rcode=-1, answers=frozenset())
    return GroupKey(rcode=result.message.rcode, answers=result.addresses())


def classify(results: Sequence[QueryResult]) -> ConsistencyReport:
    successful = [result for result in results if result.ok]
    failures = [(result.resolver, result.error or "unknown") for result in results if not result.ok]

    if not successful:
        return ConsistencyReport(verdict="unreachable", majority=None, failures=failures)

    buckets: dict[GroupKey, list[str]] = {}
    for result in successful:
        buckets.setdefault(key_for(result), []).append(result.resolver)

    groups = sorted(buckets.items(), key=lambda item: (-len(item[1]), item[0].label()))
    largest_key, largest_members = groups[0]
    majority: GroupKey | None = largest_key if len(largest_members) > len(successful) / 2 else None

    if len(groups) == 1:
        verdict = "agree"
    else:
        verdict = "partial" if _has_overlap(groups) else "disagree"

    dissent = [
        resolver
        for key, members in groups
        if majority is None or key != majority
        for resolver in members
    ]

    overlap = [
        (left[0].label(), right[0].label())
        for left_index, left in enumerate(groups)
        for right in groups[left_index + 1 :]
        if left[0].answers & right[0].answers
    ]

    return ConsistencyReport(
        verdict=verdict,
        majority=majority,
        groups=groups,
        dissent=dissent,
        failures=failures,
        overlap=overlap,
    )


def _has_overlap(groups: list[tuple[GroupKey, list[str]]]) -> bool:
    for index, (left, _) in enumerate(groups):
        for right, _ in groups[index + 1 :]:
            if left.answers & right.answers:
                return True
    return False