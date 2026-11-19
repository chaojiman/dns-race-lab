# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-19

### Added

- `race` — concurrent fan-out over any mix of `udp://`, `tcp://`, `dot://` and
  `doh:https://` resolvers, with per-resolver RTT and completion order.
- `probe` — concurrency-limited benchmark over a name list with p50/p95/p99.
- `mock` — programmable UDP+TCP DNS server driven by a JSON zone, with
  artificial delay, TC truncation and forced rcodes.
- `selfcheck` — offline end-to-end path (mock → race → classify → heuristics →
  TCP fallback → benchmark) so CI and containers can prove the stack works.
- Consistency verdicts: `agree` / `partial` / `disagree` / `unreachable`,
  including overlapping answer sets.
- Heuristics for reserved addresses, rcodes carrying answers, broken CNAME
  chains and low TTLs, all reported as findings with their record.

### Changed

- UDP, TCP and DoT now share one connection per resolver and dispatch replies by
  transaction id. Opening a socket per query capped loopback throughput at
  ~2 k qps and made the tool measure its own client (now ~9 k qps, p50 1.5 ms).
- UDP truncation is retried over TCP and reported as `transport: udp+tcp`
  instead of surfacing as a failure.

### Fixed

- Compression pointers that point forward are rejected (they could otherwise
  loop the parser).
- The mock server closes tracked writers before `wait_closed()`; since Python
  3.12 that call waits for every open connection, which hung the test-suite.
- A transient `WinError 10013` on UDP bind (Windows reserved ephemeral ranges)
  is retried instead of failing the lookup.

### Known limitations

- DoH is HTTP/1.1 with one connection per query: no HTTP/2 multiplexing.
- No cache; every call is a fresh query.
- `selfcheck` does not cover DoH/DoT; the test-suite does, against local servers.

## [0.1.0] - 2026-11-18

- Internal prototype: UDP query, one resolver, ad-hoc printing.