"""Transport tests over real sockets: UDP, TCP, TC fallback, DoH, DoT, spec parsing."""

from __future__ import annotations

import asyncio
import pathlib
import ssl
import struct
import unittest

from dnsrace import wire
from dnsrace.mock import MockDnsServer, MockZone
from dnsrace.transports import (
    DohResolver,
    DotResolver,
    Resolver,
    TcpResolver,
    UdpResolver,
    make_resolver,
)

DATA = pathlib.Path(__file__).parent / "data"


def zone(ttl: int = 60) -> MockZone:
    mock = MockZone(ttl=ttl)
    mock.add_a("example.com", "192.0.2.10")
    mock.add_aaaa("example.com", "2001:db8::10")
    mock.add_cname("www.example.com", "example.com")
    return mock


class ResolverCase(unittest.IsolatedAsyncioTestCase):
    """Closes every resolver it hands out, so no socket survives a test."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._resolvers: list[Resolver] = []

    async def asyncTearDown(self) -> None:
        for resolver in self._resolvers:
            await resolver.aclose()
        await asyncio.sleep(0)
        self._resolvers.clear()

    def track(self, resolver: Resolver) -> Resolver:
        self._resolvers.append(resolver)
        return resolver


class UdpTransportTests(ResolverCase):
    async def asyncSetUp(self) -> None:
        self.server = await MockDnsServer(zone()).start()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        await self.server.stop()

    def udp(self, **kwargs) -> UdpResolver:
        return self.track(UdpResolver(self.server.udp_spec, self.server.host, self.server.port, **kwargs))

    async def test_udp_answer(self) -> None:
        result = await self.udp().query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.transport, "udp")
        self.assertEqual(result.addresses(), frozenset({"192.0.2.10"}))
        self.assertGreater(result.rtt_ms, 0)

    async def test_nxdomain_is_not_an_error(self) -> None:
        result = await self.udp().query("absent.example.com")
        self.assertTrue(result.ok)
        self.assertEqual(result.rcode, wire.RCODE_NXDOMAIN)
        self.assertEqual(result.addresses(), frozenset())

    async def test_timeout_after_retries(self) -> None:
        self.server.delay_ms = 500
        result = await self.udp(max_attempts=1).query("example.com", timeout=0.08)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "timeout")

    async def test_many_queries_share_one_socket(self) -> None:
        resolver = self.udp()
        results = await asyncio.gather(*(resolver.query(f"n{i}.example.com") for i in range(50)))
        self.assertTrue(all(result.ok for result in results))
        self.assertEqual(self.server.udp_queries, 50)


class TcpTransportTests(ResolverCase):
    async def asyncSetUp(self) -> None:
        self.server = await MockDnsServer(zone()).start()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        await self.server.stop()

    async def test_tcp_answer(self) -> None:
        resolver = self.track(TcpResolver(self.server.tcp_spec, self.server.host, self.server.port))
        result = await resolver.query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.transport, "tcp")
        self.assertEqual(result.addresses(), frozenset({"192.0.2.10"}))
        self.assertEqual(self.server.tcp_queries, 1)

    async def test_persistent_connection_is_reused(self) -> None:
        resolver = self.track(TcpResolver(self.server.tcp_spec, self.server.host, self.server.port))
        results = await asyncio.gather(*(resolver.query(f"n{i}.example.com") for i in range(25)))
        self.assertTrue(all(result.ok for result in results))
        # One connection handled every query; the server saw 25 requests on it.
        self.assertEqual(self.server.tcp_queries, 25)

    async def test_truncated_udp_falls_back_to_tcp(self) -> None:
        self.server.truncated = True
        resolver = self.track(UdpResolver(self.server.udp_spec, self.server.host, self.server.port))
        result = await resolver.query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.transport, "udp+tcp")
        self.assertEqual(result.addresses(), frozenset({"192.0.2.10"}))
        self.assertGreaterEqual(result.attempts, 2)
        self.assertEqual(self.server.tcp_queries, 1)

    async def test_connection_refused_is_reported(self) -> None:
        resolver = self.track(TcpResolver("tcp://127.0.0.1:1", "127.0.0.1", 1))
        result = await resolver.query("example.com", timeout=0.5)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)


class DohTransportTests(ResolverCase):
    async def asyncSetUp(self) -> None:
        self.reply_style = "content-length"
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        self.server.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            self.assertIn(b"POST ", request_line)
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            query = wire.parse_message(await reader.readexactly(length))
            reply = wire.encode_response(
                query,
                [wire.encode_rr("example.com", wire.QTYPE_A, 60, wire.encode_a("192.0.2.77"))],
            )
            if self.reply_style == "chunked":
                head = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                    b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                half = len(reply) // 2
                writer.write(head)
                writer.write(f"{half:x}\r\n".encode() + reply[:half] + b"\r\n")
                writer.write(f"{len(reply) - half:x}\r\n".encode() + reply[half:] + b"\r\n")
                writer.write(b"0\r\n\r\n")
            else:
                head = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                    + f"Content-Length: {len(reply)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                )
                writer.write(head + reply)
            await writer.drain()
        finally:
            writer.close()

    def doh(self, url: str) -> DohResolver:
        return self.track(DohResolver("doh:test", url))

    async def test_doh_post(self) -> None:
        result = await self.doh(f"http://127.0.0.1:{self.port}/dns-query").query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.transport, "doh")
        self.assertEqual(result.addresses(), frozenset({"192.0.2.77"}))

    async def test_doh_chunked_response(self) -> None:
        self.reply_style = "chunked"
        result = await self.doh(f"http://127.0.0.1:{self.port}/dns-query").query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.addresses(), frozenset({"192.0.2.77"}))

    async def test_doh_connection_error(self) -> None:
        result = await self.doh("http://127.0.0.1:1/dns-query").query("example.com", timeout=0.5)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)


class DotTransportTests(ResolverCase):
    async def asyncSetUp(self) -> None:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(str(DATA / "dot.crt"), str(DATA / "dot.key"))
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=server_context)
        self.port = self.server.sockets[0].getsockname()[1]
        self.client_context = ssl.create_default_context(cafile=str(DATA / "dot.crt"))

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        self.server.close()
        await asyncio.wait_for(self.server.wait_closed(), 5)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                prefix = await reader.readexactly(2)
                (length,) = struct.unpack("!H", prefix)
                query = wire.parse_message(await reader.readexactly(length))
                reply = wire.encode_response(
                    query,
                    [wire.encode_rr("example.com", wire.QTYPE_A, 60, wire.encode_a("192.0.2.88"))],
                )
                writer.write(struct.pack("!H", len(reply)) + reply)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def test_dot_answer_over_tls(self) -> None:
        resolver = self.track(
            DotResolver(
                "dot:test",
                "127.0.0.1",
                self.port,
                server_hostname="localhost",
                ssl_context=self.client_context,
            )
        )
        result = await resolver.query("example.com")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.transport, "dot")
        self.assertEqual(result.addresses(), frozenset({"192.0.2.88"}))


class SpecParsingTests(unittest.TestCase):
    def test_udp_spec(self) -> None:
        resolver = make_resolver("udp://1.1.1.1:5353")
        self.assertIsInstance(resolver, UdpResolver)
        self.assertEqual((resolver.host, resolver.port), ("1.1.1.1", 5353))

    def test_bare_host_defaults_to_udp_53(self) -> None:
        resolver = make_resolver("9.9.9.9")
        self.assertIsInstance(resolver, UdpResolver)
        self.assertEqual(resolver.port, 53)

    def test_tcp_spec(self) -> None:
        resolver = make_resolver("tcp://9.9.9.9")
        self.assertIsInstance(resolver, TcpResolver)
        self.assertEqual(resolver.port, 53)

    def test_dot_spec(self) -> None:
        resolver = make_resolver("dot://1.1.1.1")
        self.assertIsInstance(resolver, DotResolver)
        self.assertEqual(resolver.port, 853)

    def test_doh_spec(self) -> None:
        resolver = make_resolver("doh:https://cloudflare-dns.com/dns-query")
        self.assertIsInstance(resolver, DohResolver)
        self.assertEqual(resolver.port, 443)
        self.assertEqual(resolver.path, "/dns-query")

    def test_doh_plain_url(self) -> None:
        resolver = make_resolver("http://127.0.0.1:8053/q")
        self.assertIsInstance(resolver, DohResolver)
        self.assertEqual(resolver.port, 8053)

    def test_invalid_specs(self) -> None:
        for spec in ("", "quic://1.1.1.1", "doh:not-a-url"):
            with self.assertRaises(ValueError):
                make_resolver(spec)