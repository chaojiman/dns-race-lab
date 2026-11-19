"""Wire-format tests: name codec, compression, headers, rdata rendering."""

from __future__ import annotations

import struct
import unittest

from dnsrace import wire


class NameCodecTests(unittest.TestCase):
    def test_encode_plain(self) -> None:
        self.assertEqual(wire.encode_name("Example.COM."), b"\x07example\x03com\x00")

    def test_encode_root(self) -> None:
        self.assertEqual(wire.encode_name("."), b"\x00")
        self.assertEqual(wire.encode_name(""), b"\x00")

    def test_decode_roundtrip(self) -> None:
        buffer = wire.encode_name("api.example.com")
        name, offset = wire.decode_name(buffer, 0)
        self.assertEqual(name, "api.example.com")
        self.assertEqual(offset, len(buffer))

    def test_decode_compression_pointer(self) -> None:
        buffer = wire.encode_name("example.com") + b"\x03www\xc0\x00"
        name, offset = wire.decode_name(buffer, 13)
        self.assertEqual(name, "www.example.com")
        self.assertEqual(offset, 19)

    def test_forward_pointer_rejected(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.decode_name(b"\xc0\x05\x00\x00\x00\x00", 0)

    def test_self_pointer_rejected(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.decode_name(b"\xc0\x00", 0)

    def test_reserved_label_type_rejected(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.decode_name(b"\x40abc\x00", 0)

    def test_label_too_long(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.encode_name("a" * 64 + ".com")

    def test_name_truncated(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.decode_name(b"\x07exam", 0)

    def test_idn_label_is_punycoded(self) -> None:
        encoded = wire.encode_name("例子.example.com")
        name, _ = wire.decode_name(encoded, 0)
        self.assertEqual(name, "xn--fsqu00a.example.com")


class QueryTests(unittest.TestCase):
    def test_build_query_roundtrip_with_edns(self) -> None:
        payload, ident = wire.build_query("example.com", wire.QTYPE_AAAA, ident=0x1234)
        message = wire.parse_message(payload)
        self.assertEqual(message.ident, ident)
        self.assertFalse(message.is_response)
        self.assertEqual(len(message.questions), 1)
        self.assertEqual(message.questions[0].name, "example.com")
        self.assertEqual(message.questions[0].qtype, wire.QTYPE_AAAA)
        self.assertEqual(len(message.additional), 1)
        opt = message.additional[0]
        self.assertEqual(opt.rtype, wire.QTYPE_OPT)
        self.assertEqual(opt.rclass, 1232)

    def test_build_query_without_edns(self) -> None:
        payload, _ = wire.build_query("example.com", edns=False)
        message = wire.parse_message(payload)
        self.assertEqual(message.additional, ())

    def test_random_ids_differ(self) -> None:
        ids = {wire.build_query("example.com")[1] for _ in range(16)}
        self.assertGreater(len(ids), 1)


class ResponseTests(unittest.TestCase):
    def _respond(self, answers: list[bytes], **kwargs) -> wire.Message:
        query = wire.parse_message(wire.build_query("example.com")[0])
        return wire.parse_message(wire.encode_response(query, answers, **kwargs))

    def test_a_record_roundtrip(self) -> None:
        message = self._respond([wire.encode_rr("example.com", wire.QTYPE_A, 60, wire.encode_a("192.0.2.1"))])
        self.assertTrue(message.is_response)
        self.assertEqual(message.rcode, wire.RCODE_NOERROR)
        self.assertEqual(wire.answer_addresses(message), frozenset({"192.0.2.1"}))
        self.assertEqual(wire.data_records(message, wire.QTYPE_A), [("example.com", "192.0.2.1", 60)])

    def test_aaaa_record_roundtrip(self) -> None:
        message = self._respond(
            [wire.encode_rr("example.com", wire.QTYPE_AAAA, 30, wire.encode_aaaa("2001:db8::1"))]
        )
        self.assertEqual(wire.answer_addresses(message), frozenset({"2001:db8::1"}))

    def test_cname_resolution(self) -> None:
        message = self._respond(
            [wire.encode_rr("example.com", wire.QTYPE_CNAME, 60, wire.encode_name("edge.example.net"))]
        )
        record = message.answers[0]
        self.assertEqual(wire.rdata_text(message, record), "edge.example.net")
        self.assertEqual(wire.cname_targets(message), ["edge.example.net"])

    def test_txt_and_mx_rendering(self) -> None:
        txt = self._respond([wire.encode_rr("example.com", wire.QTYPE_TXT, 60, b"\x05hello\x05world")])
        self.assertEqual(wire.rdata_text(txt, txt.answers[0]), "helloworld")

        mx_rdata = struct.pack("!H", 10) + wire.encode_name("mail.example.com")
        mx = self._respond([wire.encode_rr("example.com", wire.QTYPE_MX, 60, mx_rdata)])
        self.assertEqual(wire.rdata_text(mx, mx.answers[0]), "10 mail.example.com")

    def test_soa_rendering(self) -> None:
        rdata = (
            wire.encode_name("ns.example.com")
            + wire.encode_name("hostmaster.example.com")
            + struct.pack("!IIIII", 2026111901, 7200, 3600, 1209600, 300)
        )
        message = self._respond([wire.encode_rr("example.com", wire.QTYPE_SOA, 60, rdata)])
        self.assertEqual(
            wire.rdata_text(message, message.answers[0]),
            "ns.example.com hostmaster.example.com 2026111901 7200 3600 1209600 300",
        )

    def test_truncated_flag_and_rcode(self) -> None:
        message = self._respond([], truncated=True, rcode=wire.RCODE_SERVFAIL)
        self.assertTrue(message.is_truncated)
        self.assertEqual(message.rcode, wire.RCODE_SERVFAIL)
        self.assertEqual(message.rcode_name(), "SERVFAIL")

    def test_malformed_message_rejected(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.parse_message(b"\x00" * 4)

    def test_truncated_rdata_rejected(self) -> None:
        query = wire.build_query("example.com")[0]
        reply = bytearray(query)
        # Turn the query into a reply claiming one answer with no rdata behind it.
        struct.pack_into("!H", reply, 2, 0x8180)
        struct.pack_into("!H", reply, 6, 1)
        with self.assertRaises(wire.DnsFormatError):
            wire.parse_message(bytes(reply))


class TypeTests(unittest.TestCase):
    def test_qtype_lookup(self) -> None:
        self.assertEqual(wire.qtype_from_name("A"), wire.QTYPE_A)
        self.assertEqual(wire.qtype_from_name("aaaa"), wire.QTYPE_AAAA)
        self.assertEqual(wire.qtype_from_name("28"), wire.QTYPE_AAAA)

    def test_unknown_qtype(self) -> None:
        with self.assertRaises(wire.DnsFormatError):
            wire.qtype_from_name("NOPE")
        with self.assertRaises(wire.DnsFormatError):
            wire.qtype_from_name("70000")

    def test_normalize_name(self) -> None:
        self.assertEqual(wire.normalize_name("Example.COM."), "example.com")
        self.assertEqual(wire.normalize_name("."), ".")