"""Resolver transports: plain Do53 over UDP/TCP, DoT and DoH.

Every transport returns the same `QueryResult`, including the round-trip time
measured from before the first byte is sent, so a mixed race compares like with
like.

UDP replies that come back truncated are retried over TCP automatically —
without that, every 1232-byte answer would look like a two-attempt failure.

UDP, TCP and DoT all multiplex a single connection and dispatch replies by DNS
transaction id. Opening a socket (or a TLS session) per lookup cost more than
the lookup itself: it capped the loopback benchmark at ~2k qps and made the
tool measure its own client rather than the upstream.
"""

from __future__ import annotations

import abc
import asyncio
import secrets
import socket
import ssl
import struct
import time
import urllib.parse
from dataclasses import dataclass

from . import wire

DEFAULT_TIMEOUT = 2.0
DEFAULT_DOH_PATH = "/dns-query"
USER_AGENT = "dns-race-lab/0.2"


@dataclass(frozen=True, slots=True)
class QueryResult:
    resolver: str
    transport: str
    qname: str
    qtype: int
    rtt_ms: float
    message: wire.Message | None = None
    error: str | None = None
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None and self.message is not None

    @property
    def rcode(self) -> int | None:
        return None if self.message is None else self.message.rcode

    def addresses(self) -> frozenset[str]:
        return frozenset() if self.message is None else wire.answer_addresses(self.message)

    def summary(self) -> str:
        if not self.ok:
            return f"error({self.error})"
        message = self.message
        assert message is not None
        values = wire.data_records(message, self.qtype)
        if values:
            return ",".join(value for _, value, _ in values)
        return message.rcode_name()


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 3)


def _describe(error: BaseException) -> str:
    if isinstance(error, asyncio.TimeoutError):
        return "timeout"
    text = str(error).strip()
    return f"{type(error).__name__}: {text}" if text else type(error).__name__


class Resolver(abc.ABC):
    """One upstream. `spec` is the CLI/`make_resolver` form of its address."""

    spec: str
    transport: str

    @abc.abstractmethod
    async def query(self, qname: str, qtype: int = wire.QTYPE_A, *, timeout: float = DEFAULT_TIMEOUT) -> QueryResult:
        raise NotImplementedError

    async def aclose(self) -> None:
        """Release pooled connections."""


# --------------------------------------------------------------------------
# UDP
# --------------------------------------------------------------------------


class _UdpSocket(asyncio.DatagramProtocol):
    """One connected UDP socket shared by every in-flight query."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.pending: dict[int, asyncio.Future[wire.Message]] = {}
        self.closed = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def connection_lost(self, _exc: Exception | None) -> None:
        self.closed = True
        for future in self.pending.values():
            if not future.done():
                future.set_exception(ConnectionError("udp socket closed"))

    def datagram_received(self, data: bytes, _addr) -> None:
        try:
            message = wire.parse_message(data)
        except wire.DnsFormatError:
            return  # junk datagram; the caller keeps waiting for its id
        if not message.is_response:
            return
        future = self.pending.get(message.ident)
        if future is not None and not future.done():
            future.set_result(message)

    def error_received(self, exc: Exception) -> None:
        for future in self.pending.values():
            if not future.done():
                future.set_exception(exc)


class UdpResolver(Resolver):
    def __init__(self, spec: str, host: str, port: int = 53, max_attempts: int = 2) -> None:
        self.spec = spec
        self.host = host
        self.port = port
        self.max_attempts = max_attempts
        self.transport = "udp"
        self._socket: _UdpSocket | None = None
        self._connect_lock = asyncio.Lock()
        self._next_id = secrets.randbelow(0x10000)

    async def _shared_socket(self) -> _UdpSocket:
        current = self._socket
        if current is not None and not current.closed and current.transport is not None:
            return current
        async with self._connect_lock:
            current = self._socket
            if current is not None and not current.closed and current.transport is not None:
                return current
            loop = asyncio.get_running_loop()
            protocol = _UdpSocket()
            last_error: OSError | None = None
            for _ in range(3):
                try:
                    await loop.create_datagram_endpoint(lambda: protocol, remote_addr=(self.host, self.port))
                    self._socket = protocol
                    return protocol
                except PermissionError as error:
                    # Windows reserves ephemeral ranges (WinError 10013); a retry
                    # normally lands outside the excluded block.
                    last_error = error
                    await asyncio.sleep(0)
            raise last_error if last_error is not None else OSError("udp socket unavailable")

    def _reserve_id(self, pending: dict[int, object]) -> int:
        for _ in range(0x10000):
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id not in pending:
                return self._next_id
        raise RuntimeError("no free DNS transaction id")

    async def query(self, qname: str, qtype: int = wire.QTYPE_A, *, timeout: float = DEFAULT_TIMEOUT) -> QueryResult:
        loop = asyncio.get_running_loop()
        started = time.perf_counter()
        try:
            protocol = await self._shared_socket()
        except OSError as error:
            return QueryResult(
                resolver=self.spec,
                transport="udp",
                qname=qname,
                qtype=qtype,
                rtt_ms=_elapsed_ms(started),
                error=_describe(error),
            )

        deadline = loop.time() + timeout
        attempts = 0
        last_error = "timeout"
        while attempts < self.max_attempts:
            attempts += 1
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            ident = self._reserve_id(protocol.pending)
            payload, _ = wire.build_query(qname, qtype, ident=ident)
            future: asyncio.Future[wire.Message] = loop.create_future()
            protocol.pending[ident] = future
            attempt_started = time.perf_counter()
            try:
                if protocol.transport is None:
                    raise ConnectionError("udp socket closed")
                protocol.transport.sendto(payload)
                message = await asyncio.wait_for(future, remaining)
            except (asyncio.TimeoutError, OSError, ConnectionError) as error:
                last_error = _describe(error)
                continue
            finally:
                protocol.pending.pop(ident, None)

            if message.is_truncated:
                tcp = TcpResolver(f"{self.spec}?tcp", self.host, self.port)
                try:
                    fallback = await tcp.query(qname, qtype, timeout=max(0.05, deadline - loop.time()))
                finally:
                    await tcp.aclose()
                return QueryResult(
                    resolver=self.spec,
                    transport="udp+tcp",
                    qname=qname,
                    qtype=qtype,
                    rtt_ms=_elapsed_ms(attempt_started),
                    message=fallback.message,
                    error=fallback.error,
                    attempts=attempts + 1,
                )

            return QueryResult(
                resolver=self.spec,
                transport="udp",
                qname=qname,
                qtype=qtype,
                rtt_ms=_elapsed_ms(attempt_started),
                message=message,
                attempts=attempts,
            )

        return QueryResult(
            resolver=self.spec,
            transport="udp",
            qname=qname,
            qtype=qtype,
            rtt_ms=_elapsed_ms(started),
            error=last_error,
            attempts=attempts,
        )

    async def aclose(self) -> None:
        socket = self._socket
        self._socket = None
        if socket is not None and socket.transport is not None:
            socket.transport.close()


# --------------------------------------------------------------------------
# TCP / DoT: length-prefixed DNS streams
# --------------------------------------------------------------------------


class _StreamConnection:
    """A length-prefixed DNS stream (TCP or TLS) shared by many queries."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self.pending: dict[int, asyncio.Future[wire.Message]] = {}
        self.closed = False
        self._write_lock = asyncio.Lock()
        self._reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                prefix = await self.reader.readexactly(2)
                (length,) = struct.unpack("!H", prefix)
                body = await self.reader.readexactly(length)
                try:
                    message = wire.parse_message(body)
                except wire.DnsFormatError:
                    continue
                future = self.pending.pop(message.ident, None)
                if future is not None and not future.done():
                    future.set_result(message)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            self._fail(ConnectionError("stream closed"))

    def _fail(self, error: BaseException) -> None:
        self.closed = True
        for future in self.pending.values():
            if not future.done():
                future.set_exception(error)
        self.pending.clear()

    async def request(self, payload: bytes, ident: int, timeout: float) -> wire.Message:
        future: asyncio.Future[wire.Message] = asyncio.get_running_loop().create_future()
        self.pending[ident] = future
        try:
            async with self._write_lock:
                if self.closed:
                    raise ConnectionError("stream closed")
                self.writer.write(struct.pack("!H", len(payload)) + payload)
                await asyncio.wait_for(self.writer.drain(), timeout)
            return await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(ident, None)

    def close(self) -> None:
        self.closed = True
        self._reader_task.cancel()
        self.writer.close()


class _StreamResolver(Resolver):
    """Shared plumbing for TCP and DoT; subclasses only supply the connection."""

    def __init__(self, spec: str, host: str, port: int) -> None:
        self.spec = spec
        self.host = host
        self.port = port
        self._connection: _StreamConnection | None = None
        self._connect_lock = asyncio.Lock()
        self._next_id = secrets.randbelow(0x10000)

    async def _open(self, timeout: float) -> _StreamConnection:
        raise NotImplementedError

    async def _stream(self, timeout: float) -> _StreamConnection:
        current = self._connection
        if current is not None and not current.closed:
            return current
        async with self._connect_lock:
            current = self._connection
            if current is not None and not current.closed:
                return current
            connection = await self._open(timeout)
            self._connection = connection
            return connection

    def _reserve_id(self) -> int:
        pending = self._connection.pending if self._connection is not None else {}
        for _ in range(0x10000):
            self._next_id = (self._next_id + 1) & 0xFFFF
            if self._next_id not in pending:
                return self._next_id
        raise RuntimeError("no free DNS transaction id")

    async def query(self, qname: str, qtype: int = wire.QTYPE_A, *, timeout: float = DEFAULT_TIMEOUT) -> QueryResult:
        started = time.perf_counter()
        try:
            connection = await self._stream(timeout)
            ident = self._reserve_id()
            payload, _ = wire.build_query(qname, qtype, ident=ident)
            message = await connection.request(payload, ident, timeout)
        except (asyncio.TimeoutError, OSError, ssl.SSLError, ConnectionError, asyncio.IncompleteReadError) as error:
            return QueryResult(
                resolver=self.spec,
                transport=self.transport,
                qname=qname,
                qtype=qtype,
                rtt_ms=_elapsed_ms(started),
                error=_describe(error),
            )
        return QueryResult(
            resolver=self.spec,
            transport=self.transport,
            qname=qname,
            qtype=qtype,
            rtt_ms=_elapsed_ms(started),
            message=message,
        )

    async def aclose(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            connection.close()


class TcpResolver(_StreamResolver):
    def __init__(self, spec: str, host: str, port: int = 53) -> None:
        super().__init__(spec, host, port)
        self.transport = "tcp"

    async def _open(self, timeout: float) -> _StreamConnection:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), timeout)
        return _StreamConnection(reader, writer)


class DotResolver(_StreamResolver):
    """DNS-over-TLS: the same framing, wrapped in TLS on port 853."""

    def __init__(
        self,
        spec: str,
        host: str,
        port: int = 853,
        server_hostname: str | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        super().__init__(spec, host, port)
        self.transport = "dot"
        self._server_hostname = server_hostname or (None if _is_ip_literal(host) else host)
        self._context = ssl_context

    async def _open(self, timeout: float) -> _StreamConnection:
        context = self._context if self._context is not None else ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.host,
                self.port,
                ssl=context,
                server_hostname=self._server_hostname,
            ),
            timeout,
        )
        return _StreamConnection(reader, writer)


# --------------------------------------------------------------------------
# DoH
# --------------------------------------------------------------------------


class DohResolver(Resolver):
    """RFC 8484 POST over HTTP/1.1.

    One connection per query: a race sends a single query per upstream, and
    HTTP/2 multiplexing (what removes the handshake from real DoH traffic) is
    out of scope for a dependency-free client. The handshake therefore shows up
    in DoH RTT, which is honest and worth seeing when comparing transports.
    """

    def __init__(self, spec: str, url: str) -> None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"DoH URL must be http(s), got {url!r}")
        if not parts.hostname:
            raise ValueError(f"DoH URL has no host: {url!r}")
        self.spec = spec
        self.url = url
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.path = parts.path or DEFAULT_DOH_PATH
        if parts.query:
            self.path = f"{self.path}?{parts.query}"
        self.transport = "doh"

    async def query(self, qname: str, qtype: int = wire.QTYPE_A, *, timeout: float = DEFAULT_TIMEOUT) -> QueryResult:
        payload, _ident = wire.build_query(qname, qtype)
        started = time.perf_counter()
        try:
            body = await asyncio.wait_for(self._post(payload), timeout)
            message = wire.parse_message(body)
        except (asyncio.TimeoutError, OSError, ssl.SSLError, ValueError, asyncio.IncompleteReadError) as error:
            return QueryResult(
                resolver=self.spec,
                transport="doh",
                qname=qname,
                qtype=qtype,
                rtt_ms=_elapsed_ms(started),
                error=_describe(error),
            )
        return QueryResult(
            resolver=self.spec,
            transport="doh",
            qname=qname,
            qtype=qtype,
            rtt_ms=_elapsed_ms(started),
            message=message,
        )

    async def _post(self, payload: bytes) -> bytes:
        context = ssl.create_default_context() if self.scheme == "https" else None
        host_header = self.host if self.port in (80, 443) else f"{self.host}:{self.port}"
        reader, writer = await asyncio.open_connection(
            self.host,
            self.port,
            ssl=context,
            server_hostname=self.host if context is not None else None,
        )
        try:
            head = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                "Accept: application/dns-message\r\n"
                "Content-Type: application/dns-message\r\n"
                f"Content-Length: {len(payload)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            writer.write(head + payload)
            await writer.drain()

            status_line = await reader.readline()
            if not status_line:
                raise ValueError("empty DoH response")
            try:
                status = int(status_line.split(b" ")[1])
            except (IndexError, ValueError) as error:
                raise ValueError(f"malformed status line {status_line!r}") from error
            if status != 200:
                raise ValueError(f"DoH status {status}")

            content_length: int | None = None
            chunked = False
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                lowered = name.strip().lower()
                if lowered == "content-length":
                    content_length = int(value.strip())
                elif lowered == "transfer-encoding" and "chunked" in value.lower():
                    chunked = True

            if chunked:
                return await self._read_chunked(reader)
            if content_length is not None:
                return await reader.readexactly(content_length)
            return await reader.read()
        finally:
            writer.close()

    @staticmethod
    async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
        body = bytearray()
        while True:
            size_line = await reader.readline()
            if not size_line:
                break
            size = int(size_line.split(b";")[0].strip(), 16)
            if size == 0:
                await reader.readline()
                break
            body.extend(await reader.readexactly(size))
            await reader.readexactly(2)
        return bytes(body)


def _is_ip_literal(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def make_resolver(spec: str) -> Resolver:
    """`udp://1.1.1.1`, `tcp://1.1.1.1:53`, `dot://1.1.1.1`, `doh:https://…`."""
    text = spec.strip()
    if not text:
        raise ValueError("empty resolver spec")

    if text.startswith("doh:"):
        return DohResolver(spec, text[len("doh:") :])
    if text.startswith(("https://", "http://")):
        return DohResolver(spec, text)

    parsed = urllib.parse.urlsplit(text if "://" in text else f"udp://{text}")
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        raise ValueError(f"resolver spec has no host: {spec!r}")

    if scheme == "udp":
        return UdpResolver(spec, host, parsed.port or 53)
    if scheme == "tcp":
        return TcpResolver(spec, host, parsed.port or 53)
    if scheme in ("dot", "tls"):
        return DotResolver(spec, host, parsed.port or 853)
    raise ValueError(f"unsupported resolver scheme {scheme!r} in {spec!r}")


def make_resolvers(specs: list[str]) -> list[Resolver]:
    resolvers: list[Resolver] = []
    for spec in specs:
        resolvers.append(make_resolver(spec))
    return resolvers