"""A programmable DNS server used by the test-suite, the CLI self-check and benchmarks.

It speaks plain Do53 over UDP and TCP on the same port, which is what lets the
tests exercise real truncation behaviour: with `truncated=True` the UDP path
returns TC and no answers while the TCP path returns the full set, so the
resolver's TCP fallback is verified end to end instead of being mocked away.

The zone supports CNAME chains (A query on an alias follows the target) and
explicit negative answers, which is all the comparison logic needs.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Iterable

from . import wire

DEFAULT_TTL = 60
MAX_CNAME_DEPTH = 8


@dataclass(slots=True)
class MockZone:
    """`records[("example.com", wire.QTYPE_A)] = ["192.0.2.10"]`."""

    records: dict[tuple[str, int], list[str]] = field(default_factory=dict)
    ttl: int = DEFAULT_TTL

    def add_a(self, name: str, *addresses: str) -> "MockZone":
        self.records.setdefault((wire.normalize_name(name), wire.QTYPE_A), []).extend(addresses)
        return self

    def add_aaaa(self, name: str, *addresses: str) -> "MockZone":
        self.records.setdefault((wire.normalize_name(name), wire.QTYPE_AAAA), []).extend(addresses)
        return self

    def add_cname(self, name: str, target: str) -> "MockZone":
        self.records[(wire.normalize_name(name), wire.QTYPE_CNAME)] = [wire.normalize_name(target)]
        return self

    def names(self) -> Iterable[str]:
        seen: list[str] = []
        for name, _ in self.records:
            if name not in seen:
                seen.append(name)
        return seen


def _encode_value(qtype: int, value: str) -> bytes:
    if qtype == wire.QTYPE_A:
        return wire.encode_a(value)
    if qtype == wire.QTYPE_AAAA:
        return wire.encode_aaaa(value)
    if qtype == wire.QTYPE_CNAME:
        return wire.encode_name(value)
    return value.encode()


class MockDnsServer:
    def __init__(self, zone: MockZone) -> None:
        self.zone = zone
        self.delay_ms: float = 0.0
        self.truncated: bool = False
        self.forced_rcode: int | None = None
        self.host = "127.0.0.1"
        self.port = 0
        self.udp_queries = 0
        self.tcp_queries = 0
        self.udp_fallbacks: int = 0

        self._tcp_server: asyncio.AbstractServer | None = None
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    # -- lifecycle ---------------------------------------------------------

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> "MockDnsServer":
        loop = asyncio.get_running_loop()
        self.host = host
        self._tcp_server = await asyncio.start_server(self._handle_tcp, host, port)
        bound = self._tcp_server.sockets[0].getsockname()
        self.port = bound[1]

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(self),
            local_addr=(host, self.port),
        )
        self._udp_transport = transport
        return self

    async def stop(self) -> None:
        # Python 3.12+ makes `wait_closed()` wait for every active connection, so
        # long-lived client connections must be closed here or shutdown hangs.
        for writer in list(self._writers):
            writer.close()
        self._writers.clear()
        if self._udp_transport is not None:
            self._udp_transport.close()
            self._udp_transport = None
        if self._tcp_server is not None:
            self._tcp_server.close()
            try:
                await asyncio.wait_for(self._tcp_server.wait_closed(), 5)
            except asyncio.TimeoutError:  # pragma: no cover - defensive
                pass
            self._tcp_server = None
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
            self._tasks.clear()

    async def __aenter__(self) -> "MockDnsServer":
        return await self.start()

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()

    @property
    def udp_spec(self) -> str:
        return f"udp://{self.host}:{self.port}"

    @property
    def tcp_spec(self) -> str:
        return f"tcp://{self.host}:{self.port}"

    # -- protocol handling -------------------------------------------------

    def _track(self, coroutine) -> None:
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        try:
            while True:
                header = await reader.readexactly(2)
                (length,) = struct.unpack("!H", header)
                payload = await reader.readexactly(length)
                self.tcp_queries += 1
                reply = self._reply(payload, over_udp=False)
                if self.delay_ms:
                    await asyncio.sleep(self.delay_ms / 1000)
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    # -- response construction ---------------------------------------------

    def _resolve(self, name: str, qtype: int) -> tuple[list[bytes], int]:
        """Return (encoded answer RRs, rcode) for a (name, qtype) pair."""
        answers: list[bytes] = []
        current = wire.normalize_name(name)
        for _ in range(MAX_CNAME_DEPTH):
            direct = self.zone.records.get((current, qtype))
            if direct:
                for value in direct:
                    answers.append(
                        wire.encode_rr(current, qtype, self.zone.ttl, _encode_value(qtype, value))
                    )
                return answers, wire.RCODE_NOERROR

            alias = self.zone.records.get((current, wire.QTYPE_CNAME))
            if not alias:
                break
            target = alias[0]
            answers.append(
                wire.encode_rr(current, wire.QTYPE_CNAME, self.zone.ttl, wire.encode_name(target))
            )
            current = target
            continue

        if answers:
            # CNAME chain that ends nowhere: NOERROR with only the aliases.
            return answers, wire.RCODE_NOERROR
        return [], wire.RCODE_NXDOMAIN

    def _reply(self, payload: bytes, *, over_udp: bool) -> bytes:
        try:
            query = wire.parse_message(payload)
        except wire.DnsFormatError:
            return _raw_format_error(payload)
        if not query.questions:
            return _raw_format_error(payload)

        question = query.questions[0]
        answers, rcode = self._resolve(question.name, question.qtype)
        if self.forced_rcode is not None:
            answers, rcode = [], self.forced_rcode
        if self.truncated and over_udp:
            answers = []

        additional: list[bytes] = []
        if any(record.rtype == wire.QTYPE_OPT for record in query.additional):
            additional.append(wire.encode_rr(".", wire.QTYPE_OPT, 0, b"", rclass=1232))

        return wire.encode_response(
            query,
            answers,
            rcode=rcode,
            truncated=self.truncated and over_udp,
            additional=additional,
        )

    async def _send_udp(self, data: bytes, addr, transport: asyncio.DatagramTransport) -> None:
        self.udp_queries += 1
        reply = self._reply(data, over_udp=True)
        if self.delay_ms:
            await asyncio.sleep(self.delay_ms / 1000)
        transport.sendto(reply, addr)


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: MockDnsServer) -> None:
        self.server = server
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr) -> None:
        if self.transport is None:
            return
        self.server._track(self.server._send_udp(data, addr, self.transport))


def _raw_format_error(payload: bytes) -> bytes:
    ident = payload[:2] if len(payload) >= 2 else b"\x00\x00"
    flags = wire.FLAG_RESPONSE | 1  # FORMERR
    return ident + struct.pack("!HHHHH", flags, 0, 0, 0, 0)