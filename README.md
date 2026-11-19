# dns-race-lab

Ask several DNS resolvers the same question at the same time, see who answers first, whether they agree, and whether any reply looks forged.

Everything runs on the Python standard library: the wire format, the mock server, the HTTP/1.1 client used for DoH and the TLS path for DoT are all in-tree, so a resolver comparison never drags in `dnspython`, `httpx` or a crypto dependency.

```
$ dnsrace race --qname example.com \
    --resolver udp://223.5.5.5 \
    --resolver doh:https://dns.alidns.com/dns-query \
    --resolver dot://223.5.5.5

example.com A — 219.587 ms, timeout 6000 ms

resolver                              transport  rtt        result
udp://223.5.5.5                       udp        33.843 ms  172.66.147.243,104.20.23.154 < first
doh:https://dns.alidns.com/dns-query  doh        219.213 ms 172.66.147.243,104.20.23.154
dot://223.5.5.5                       dot        108.740 ms 104.20.23.154,172.66.147.243

consistency: agree
  NOERROR 104.20.23.154,172.66.147.243  ←  udp://223.5.5.5, doh:https://dns.alidns.com/dns-query, dot://223.5.5.5

findings: none
```

## What it answers

| Question | Command |
| --- | --- |
| Who answers first, and how far apart? | `dnsrace race` |
| Do these resolvers return the same answer set? | `dnsrace race` (consistency block) |
| Which replies contain impossible or suspicious records? | `dnsrace race` (findings block) |
| How fast is resolver X over N names? | `dnsrace probe` |
| How do my own rules behave, offline? | `dnsrace mock` + `dnsrace race` |
| Does the whole stack still work with no network? | `dnsrace selfcheck` |

## Install

```bash
pip install .          # or: pipx install .
dnsrace --help
```

Python 3.11+. No runtime dependencies.

## Resolver specs

| Spec | Transport | Default port |
| --- | --- | --- |
| `udp://1.1.1.1:53` (or bare `1.1.1.1`) | Do53 over UDP | 53 |
| `tcp://1.1.1.1` | Do53 over TCP | 53 |
| `dot://1.1.1.1` | DNS-over-TLS | 853 |
| `doh:https://dns.google/dns-query` | DoH, RFC 8484 POST | 443 |

`udp://` replies that come back with TC set are retried over TCP automatically; the result reports `transport: udp+tcp` and the attempt count, which is how truncation shows up instead of being silently swallowed.

UDP, TCP and DoT keep one connection per resolver and dispatch replies by DNS transaction id. An earlier design opened a socket per lookup and capped the loopback benchmark at ~2k qps — the client was measuring itself. DoH opens one connection per query (HTTP/1.1, no multiplexing), so its RTT honestly includes a TLS handshake.

## Consistency, not "most specific wins"

Resolvers are grouped by `(rcode, answer set)`. The largest group is the majority; anything else is reported as dissent. Two different-but-overlapping answer sets are called `partial` — CDN and geo-DNS setups legitimately return different A records for the same name, and calling that a failure would be wrong.

```
agree        every reachable resolver returned the same rcode and the same set
partial      multiple groups, at least two of them share an address
disagree     multiple groups with disjoint answers
unreachable  no resolver produced a reply
```

Order inside an answer set is ignored: `36.152.44.132,36.152.44.93` and `36.152.44.93,36.152.44.132` are the same answer.

## Suspicious-reply heuristics

These are evidence, not verdicts. Each finding names the resolver and the record it came from; the CLI never prints "this resolver is lying".

| Kind | Trigger | What it usually means | Where it can mislead |
| --- | --- | --- | --- |
| `reserved-address` | A/AAAA inside RFC 1918, loopback, CGNAT, TEST-NET, link-local, multicast | interception/forgery | split-horizon setups answer private IPs on purpose — pass `--known-local 10.0.0.5` |
| `rcode-with-answers` | NXDOMAIN/SERVFAIL that still carries answer records | reply assembled by something that ignored the rcode | broken authoritative zone |
| `cname-unresolved` | CNAME chain that stops without the queried address type | alias-only interception | genuinely misconfigured zone |
| `low-ttl` | ttl ≤ `--min-ttl` (default 5) | fast-changing forged records | active failover does this legitimately |

## Benchmark (loopback, mock server)

Measured 2026-11-19, Intel i5-12600KF / 16 threads, 32 GiB RAM, Windows 11, Python 3.14.0. 200 names × 10 repeats = 2000 queries per resolver, against the in-tree mock server on `127.0.0.1`, so these numbers describe *this client*, not an upstream.

| concurrency | transport | qps | p50 | p95 | p99 | errors |
| --- | --- | --- | --- | --- | --- | --- |
| 16 | udp | 9044 | 1.54 ms | 2.01 ms | 2.19 ms | 0 |
| 16 | tcp | 13297 | 0.96 ms | 1.31 ms | 1.44 ms | 0 |
| 64 | udp | 9147 | 6.63 ms | 7.56 ms | 8.20 ms | 0 |
| 64 | tcp | 23063 | 2.03 ms | 2.61 ms | 4.24 ms | 0 |

Reproduce with `dnsrace selfcheck` for correctness, or start `dnsrace mock` and point `dnsrace probe` at it.

UDP p50 grows with concurrency because every datagram is a separate task on the mock side; TCP barely moves because one stream carries all requests. Neither number is a claim about upstream performance.

## Mock server

```bash
dnsrace mock --zone examples/zone.json --port 5353 [--delay-ms 100] [--truncated] [--rcode SERVFAIL]
```

Zone format (JSON, one record type per alias is enough):

```json
{
  "example.com": {"A": ["192.0.2.10"], "AAAA": ["2001:db8::10"]},
  "www.example.com": {"CNAME": "example.com"},
  "ads.example.com": {"A": ["10.0.0.66"]}
}
```

`--truncated` makes UDP replies carry TC and TCP replies complete, which is how the TCP fallback is tested without mocking the transport away.

## Architecture

```
dnsrace/
  wire.py          DNS message codec: names, compression, EDNS0, rdata rendering
  transports.py    udp / tcp / dot / doh clients, one connection per resolver
  mock.py          programmable UDP+TCP server (delay, TC, forced rcode)
  race.py          concurrent fan-out, per-result RTT, completion order
  consistency.py   answer-set grouping and verdicts
  pollution.py     reserved-address / rcode / chain / ttl heuristics
  bench.py         concurrency-limited throughput and latency percentiles
  cli.py           race, probe, mock, selfcheck
tests/             73 tests, all offline (mock servers + a self-signed DoT cert)
```

Design notes worth knowing before changing things:

* `decode_name` rejects forward-pointing compression pointers and caps the hop count, so a hostile reply cannot loop the parser or make it read outside the buffer.
* `build_query` always sends an EDNS0 OPT record with a 1232-byte payload (the DNS Flag Day 2020 default).
* Transaction ids are allocated from a rotating counter that skips ids still in flight, not from `randbelow` per query — with 64 concurrent lookups a collision would be a real possibility.
* The mock server closes its tracked writers in `stop()`: since Python 3.12 `Server.wait_closed()` waits for every open connection, and a test that forgets this hangs.

## Live sanity check

Both commands below were run against public resolvers on 2026-11-19 from a residential line:

```
udp://223.5.5.5                       udp   33.843 ms
dot://223.5.5.5                       dot  108.740 ms
doh:https://dns.alidns.com/dns-query  doh  219.213 ms     (all agree)
```

The DoH figure is dominated by the TLS handshake; that is the cost of a dependency-free HTTP/1.1 client and is stated rather than benchmarked away.

## Limitations

* One query per transport call — there is no cache and no negative-answer reuse.
* DoH is HTTP/1.1 only: no HTTP/2 multiplexing, no connection pool.
* DoT uses the system trust store; `DotResolver(ssl_context=…)` exists because test and lab resolvers use private CAs.
* `selfcheck` covers UDP/TCP/truncation/consistency/heuristics; DoH and DoT are covered by the test-suite (both against local servers) rather than by `selfcheck`.
* Windows frequently reserves ephemeral port ranges; the UDP client retries a bind up to three times because `WinError 10013` otherwise surfaces as a random failure.

## Development

```bash
python -m unittest discover -s tests -t .   # 73 tests, no network needed
dnsrace selfcheck                           # end-to-end smoke, ~0.3 s
```

CI runs the suite on Python 3.11/3.12/3.13, runs `selfcheck`, and builds the image:

```bash
docker build -t dns-race-lab .
docker run --rm dns-race-lab selfcheck
docker compose up mock
```

## License

MIT