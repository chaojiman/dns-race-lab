"""DNS wire format: encode queries, decode replies, build canned responses.

Only the record types this project actually reasons about are decoded to text
(A, AAAA, CNAME, NS, PTR, MX, TXT, SOA); everything else keeps its raw rdata,
which is all a resolver comparison needs.

Name compression is decoded defensively: a pointer must point strictly backwards
and the hop count is capped, so a hostile reply cannot spin the parser or make
it read outside the buffer.
"""

from __future__ import annotations

import ipaddress
import secrets
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33
QTYPE_OPT = 41
QTYPE_ANY = 255

CLASS_IN = 1

QTYPE_NAMES: dict[int, str] = {
    QTYPE_A: "A",
    QTYPE_NS: "NS",
    QTYPE_CNAME: "CNAME",
    QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR",
    QTYPE_MX: "MX",
    QTYPE_TXT: "TXT",
    QTYPE_AAAA: "AAAA",
    QTYPE_SRV: "SRV",
    QTYPE_OPT: "OPT",
    QTYPE_ANY: "ANY",
}

QTYPE_BY_NAME: dict[str, int] = {name: value for value, name in QTYPE_NAMES.items()}

RCODE_NAMES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3

FLAG_RESPONSE = 0x8000
FLAG_AUTHORITATIVE = 0x0400
FLAG_TRUNCATED = 0x0200
FLAG_RECURSION_DESIRED = 0x0100
FLAG_RECURSION_AVAILABLE = 0x0080

MAX_NAME_LENGTH = 255
MAX_LABEL_LENGTH = 63
MAX_POINTER_HOPS = 64


class DnsFormatError(ValueError):
    """Raised when a message cannot be encoded or decoded."""


@dataclass(frozen=True, slots=True)
class Question:
    name: str
    qtype: int
    qclass: int = CLASS_IN

    def display(self) -> str:
        return f"{self.name} {QTYPE_NAMES.get(self.qtype, self.qtype)}"


@dataclass(frozen=True, slots=True)
class RR:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    offset: int
    """Absolute offset of the rdata inside `Message.raw` (needed for compressed names)."""


@dataclass(frozen=True, slots=True)
class Message:
    raw: bytes
    ident: int
    flags: int
    questions: tuple[Question, ...]
    answers: tuple[RR, ...]
    authority: tuple[RR, ...]
    additional: tuple[RR, ...]

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_RESPONSE)

    @property
    def is_truncated(self) -> bool:
        return bool(self.flags & FLAG_TRUNCATED)

    @property
    def is_authoritative(self) -> bool:
        return bool(self.flags & FLAG_AUTHORITATIVE)

    @property
    def recursion_available(self) -> bool:
        return bool(self.flags & FLAG_RECURSION_AVAILABLE)

    def rcode_name(self) -> str:
        return RCODE_NAMES.get(self.rcode, f"RCODE{self.rcode}")


def _label_to_wire(label: str) -> bytes:
    try:
        raw = label.encode("ascii")
    except UnicodeEncodeError:
        try:
            raw = label.encode("idna")
        except UnicodeError as error:  # pragma: no cover - exotic input
            raise DnsFormatError(f"cannot encode label {label!r}: {error}") from error
    if not raw:
        raise DnsFormatError("empty label")
    if len(raw) > MAX_LABEL_LENGTH:
        raise DnsFormatError(f"label {label!r} exceeds {MAX_LABEL_LENGTH} bytes")
    return raw


def encode_name(name: str) -> bytes:
    """Encode a dotted name without compression."""
    text = name.strip()
    if text in ("", "."):
        return b"\x00"
    text = text.rstrip(".")
    out = bytearray()
    for label in text.lower().split("."):
        raw = _label_to_wire(label)
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    if len(out) > MAX_NAME_LENGTH:
        raise DnsFormatError(f"name {name!r} exceeds {MAX_NAME_LENGTH} bytes")
    return bytes(out)


def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed name; returns (name, offset after the name)."""
    labels: list[str] = []
    position = offset
    consumed: int | None = None
    hops = 0

    while True:
        if position >= len(buf):
            raise DnsFormatError(f"name runs past end of message at {position}")
        length = buf[position]

        if length == 0:
            position += 1
            if consumed is None:
                consumed = position
            break

        kind = length & 0xC0
        if kind == 0xC0:
            if position + 1 >= len(buf):
                raise DnsFormatError("truncated compression pointer")
            target = ((length & 0x3F) << 8) | buf[position + 1]
            if consumed is None:
                consumed = position + 2
            hops += 1
            if hops > MAX_POINTER_HOPS:
                raise DnsFormatError("compression pointer loop")
            if target >= position:
                raise DnsFormatError(f"compression pointer at {position} points forward to {target}")
            position = target
            continue

        if kind != 0x00:
            raise DnsFormatError(f"reserved label type 0x{kind:02x} at {position}")

        position += 1
        if position + length > len(buf):
            raise DnsFormatError("label runs past end of message")
        labels.append(buf[position : position + length].decode("ascii", "replace").lower())
        position += length

    name = ".".join(labels) if labels else "."
    if len(name) > MAX_NAME_LENGTH:
        raise DnsFormatError("decoded name too long")
    return name, consumed if consumed is not None else position


def build_query(
    qname: str,
    qtype: int = QTYPE_A,
    *,
    ident: int | None = None,
    recursion_desired: bool = True,
    edns: bool = True,
    edns_payload: int = 1232,
    edns_flags: int = 0,
) -> tuple[bytes, int]:
    """Build a query message. Returns (wire bytes, transaction id)."""
    transaction_id = secrets.randbelow(0x10000) if ident is None else ident & 0xFFFF
    flags = FLAG_RECURSION_DESIRED if recursion_desired else 0
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 1 if edns else 0)

    body = bytearray(header)
    body.extend(encode_name(qname))
    body.extend(struct.pack("!HH", qtype, CLASS_IN))

    if edns:
        # OPT pseudo-record: root name, type 41, class = advertised UDP payload.
        body.extend(b"\x00")
        body.extend(struct.pack("!HHIH", QTYPE_OPT, edns_payload, edns_flags, 0))

    return bytes(body), transaction_id


def encode_rr(name: str, rtype: int, ttl: int, rdata: bytes, rclass: int = CLASS_IN) -> bytes:
    return encode_name(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def encode_a(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def encode_aaaa(address: str) -> bytes:
    return ipaddress.IPv6Address(address).packed


def encode_response(
    query: Message,
    answers: Sequence[bytes],
    *,
    rcode: int = RCODE_NOERROR,
    truncated: bool = False,
    authoritative: bool = True,
    recursion_available: bool = True,
    additional: Sequence[bytes] = (),
) -> bytes:
    """Build a reply to `query` from pre-encoded RRs (use `encode_rr`)."""
    flags = FLAG_RESPONSE
    if authoritative:
        flags |= FLAG_AUTHORITATIVE
    if truncated:
        flags |= FLAG_TRUNCATED
    if query.flags & FLAG_RECURSION_DESIRED:
        flags |= FLAG_RECURSION_DESIRED
    if recursion_available:
        flags |= FLAG_RECURSION_AVAILABLE
    flags |= rcode & 0x000F

    header = struct.pack(
        "!HHHHHH",
        query.ident,
        flags,
        len(query.questions),
        len(answers),
        0,
        len(additional),
    )
    body = bytearray(header)
    for question in query.questions:
        body.extend(encode_name(question.name))
        body.extend(struct.pack("!HH", question.qtype, question.qclass))
    for record in answers:
        body.extend(record)
    for record in additional:
        body.extend(record)
    return bytes(body)


def parse_message(buf: bytes) -> Message:
    if len(buf) < 12:
        raise DnsFormatError("message shorter than a DNS header")
    ident, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
    position = 12

    questions: list[Question] = []
    for _ in range(qdcount):
        name, position = decode_name(buf, position)
        if position + 4 > len(buf):
            raise DnsFormatError("truncated question")
        qtype, qclass = struct.unpack("!HH", buf[position : position + 4])
        position += 4
        questions.append(Question(name=name, qtype=qtype, qclass=qclass))

    sections: list[tuple[RR, ...]] = []
    for count in (ancount, nscount, arcount):
        records: list[RR] = []
        for _ in range(count):
            name, position = decode_name(buf, position)
            if position + 10 > len(buf):
                raise DnsFormatError("truncated resource record")
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", buf[position : position + 10])
            position += 10
            if position + rdlength > len(buf):
                raise DnsFormatError("rdata runs past end of message")
            records.append(
                RR(
                    name=name,
                    rtype=rtype,
                    rclass=rclass,
                    ttl=ttl,
                    rdata=buf[position : position + rdlength],
                    offset=position,
                )
            )
            position += rdlength
        sections.append(tuple(records))

    return Message(
        raw=buf,
        ident=ident,
        flags=flags,
        questions=tuple(questions),
        answers=sections[0],
        authority=sections[1],
        additional=sections[2],
    )


def rdata_text(message: Message, record: RR) -> str:
    """Human/compare-friendly rendering of a record's rdata."""
    try:
        if record.rtype == QTYPE_A:
            return str(ipaddress.IPv4Address(record.rdata))
        if record.rtype == QTYPE_AAAA:
            return str(ipaddress.IPv6Address(record.rdata))
        if record.rtype in (QTYPE_CNAME, QTYPE_NS, QTYPE_PTR):
            return decode_name(message.raw, record.offset)[0]
        if record.rtype == QTYPE_MX:
            preference = struct.unpack("!H", record.rdata[:2])[0]
            target = decode_name(message.raw, record.offset + 2)[0]
            return f"{preference} {target}"
        if record.rtype == QTYPE_TXT:
            return _decode_txt(record.rdata)
        if record.rtype == QTYPE_SOA:
            mname, position = decode_name(message.raw, record.offset)
            rname, position = decode_name(message.raw, position)
            serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", message.raw[position : position + 20])
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        if record.rtype == QTYPE_OPT:
            return f"payload={record.rclass} flags=0x{record.ttl:08x}"
    except (DnsFormatError, struct.error, ValueError) as error:
        return f"<unparsed {QTYPE_NAMES.get(record.rtype, record.rtype)}: {error}>"
    return record.rdata.hex()


def _decode_txt(rdata: bytes) -> str:
    parts: list[str] = []
    position = 0
    while position < len(rdata):
        length = rdata[position]
        position += 1
        parts.append(rdata[position : position + length].decode("utf-8", "replace"))
        position += length
    return "".join(parts)


def data_records(message: Message, qtype: int) -> list[tuple[str, str, int]]:
    """Address records of `qtype` in the answer section: (owner, value, ttl)."""
    out: list[tuple[str, str, int]] = []
    for record in message.answers:
        if record.rtype != qtype or record.rclass != CLASS_IN:
            continue
        value = rdata_text(message, record)
        if value.startswith("<unparsed"):
            continue
        out.append((record.name, value, record.ttl))
    return out


def answer_addresses(message: Message) -> frozenset[str]:
    """Every A/AAAA value in the answer section, regardless of the queried type."""
    values: set[str] = set()
    for record in message.answers:
        if record.rtype in (QTYPE_A, QTYPE_AAAA) and record.rclass == CLASS_IN:
            text = rdata_text(message, record)
            if not text.startswith("<unparsed"):
                values.add(text)
    return frozenset(values)


def cname_targets(message: Message) -> list[str]:
    out: list[str] = []
    for record in message.answers:
        if record.rtype == QTYPE_CNAME:
            out.append(rdata_text(message, record))
    return out


def normalize_name(name: str) -> str:
    text = name.strip().rstrip(".").lower()
    return text or "."


def qtype_from_name(text: str) -> int:
    upper = text.strip().upper()
    if upper.isdigit():
        value = int(upper)
        if 0 < value <= 0xFFFF:
            return value
    if upper in QTYPE_BY_NAME:
        return QTYPE_BY_NAME[upper]
    raise DnsFormatError(f"unknown record type {text!r}")


def iter_records(message: Message) -> Iterable[RR]:
    yield from message.answers
    yield from message.authority
    yield from message.additional