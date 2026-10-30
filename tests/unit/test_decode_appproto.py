from __future__ import annotations

import struct

import lab_builder as lab

from packetstory.appproto import parse_dns, parse_http, parse_tls_sni
from packetstory.capture import RawPacket
from packetstory.decode import TCP_ACK, TCP_SYN, decode


def raw(frame: bytes, link: int = 1) -> RawPacket:
    return RawPacket(1, 5, link, frame, len(frame))


def test_ethernet_ipv4_tcp() -> None:
    d = decode(
        raw(
            lab.eth(
                lab.ipv4(
                    "192.0.2.1", "192.0.2.2", 6, lab.tcp(1234, 443, 7, 9, lab.SYN | lab.ACK, b"hi")
                )
            )
        )
    )
    assert (d.proto, d.src, d.dst, d.sport, d.dport) == ("tcp", "192.0.2.1", "192.0.2.2", 1234, 443)
    assert d.flags == TCP_SYN | TCP_ACK and d.seq == 7 and d.ack == 9 and d.payload == b"hi"


def test_vlan_tag_is_skipped() -> None:
    inner = lab.ipv4("192.0.2.1", "192.0.2.2", 17, lab.udp(1, 2, b"x"))
    frame = lab.MAC_B + lab.MAC_A + struct.pack("!HHH", 0x8100, 5, 0x0800) + inner
    d = decode(raw(frame))
    assert d.proto == "udp" and d.payload == b"x"


def test_ipv6_with_extension_header_and_icmpv6() -> None:
    hop = bytes([58, 0]) + bytes(6)  # hop-by-hop header then ICMPv6
    pkt = lab.ipv6("2001:db8::1", "2001:db8::2", 0, hop + lab.icmp(128, 0))
    d = decode(raw(lab.eth(pkt, 0x86DD)))
    assert d.proto == "icmpv6" and d.icmp_type == 128 and d.src == "2001:db8::1"


def test_ipv6_fragment_is_flagged() -> None:
    frag = bytes([17, 0]) + struct.pack("!HI", 8 << 3, 1) + b"data"
    d = decode(raw(lab.eth(lab.ipv6("2001:db8::1", "2001:db8::2", 44, frag), 0x86DD)))
    assert d.fragment and d.unsupported == "non-first IP fragment"


def test_ipv4_fragments() -> None:
    first = lab.ipv4("192.0.2.1", "192.0.2.2", 17, lab.udp(1, 2, b"abc"), flags_frag=0x2000)
    later = lab.ipv4("192.0.2.1", "192.0.2.2", 17, b"zzzz", flags_frag=0x0001)
    d1, d2 = decode(raw(lab.eth(first))), decode(raw(lab.eth(later)))
    assert d1.fragment and d1.proto == "udp"
    assert d2.fragment and d2.unsupported


def test_arp_sll_raw_and_null_links() -> None:
    arp = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + bytes(6)
        + bytes([192, 0, 2, 1])
        + bytes(6)
        + bytes([192, 0, 2, 9])
    )
    d = decode(raw(lab.eth(arp, 0x0806)))
    assert d.proto == "arp" and (d.src, d.dst, d.icmp_type) == ("192.0.2.1", "192.0.2.9", 1)
    ip = lab.ipv4("192.0.2.1", "192.0.2.2", 1, lab.icmp(8, 0))
    sll = bytes(14) + struct.pack("!H", 0x0800) + ip
    assert decode(raw(sll, 113)).proto == "icmp"
    assert decode(raw(ip, 101)).proto == "icmp"
    assert decode(raw(b"\x02\x00\x00\x00" + ip, 0)).proto == "icmp"


def test_unsupported_and_malformed_are_reported_not_raised() -> None:
    assert decode(raw(b"x", 147)).unsupported == "link type 147"
    assert "ethertype" in decode(raw(lab.eth(b"payload", 0x88CC))).unsupported
    assert (
        decode(raw(lab.ipv4("192.0.2.1", "192.0.2.2", 47, b"gre"), 101)).unsupported
        == "IP protocol 47"
    )
    for frame in (
        b"",
        b"\x00" * 10,
        lab.eth(b"\x45\x00"),
        lab.eth(lab.ipv4("192.0.2.1", "192.0.2.2", 6, b"\x00" * 5)),
    ):
        assert decode(raw(frame)).malformed
    bad_ihl = bytearray(lab.ipv4("192.0.2.1", "192.0.2.2", 6, lab.tcp(1, 2, 0, 0, 0)))
    bad_ihl[0] = 0x4F  # claims a 60-byte header in a 40-byte packet
    assert decode(raw(bytes(bad_ihl), 101)).malformed
    bad_off = bytearray(lab.tcp(1, 2, 0, 0, 0))
    bad_off[12] = 0xF0  # TCP data offset beyond the segment
    assert decode(raw(lab.eth(lab.ipv4("192.0.2.1", "192.0.2.2", 6, bytes(bad_off))))).malformed


def test_udp_length_field_is_bounded() -> None:
    seg = bytearray(lab.udp(1, 2, b"abcd"))
    struct.pack_into("!H", seg, 4, 9999)  # lies about its length
    assert decode(raw(lab.ipv4("192.0.2.1", "192.0.2.2", 17, bytes(seg)), 101)).payload == b"abcd"


# -- application protocols -------------------------------------------------------------------


def test_dns_query_and_response() -> None:
    q = parse_dns(lab.dns_query(7, "Example.test", 28))
    assert q and not q.is_response and q.questions == (("Example.test", "AAAA"),)
    r = parse_dns(lab.dns_response(7, "example.test", ["203.0.113.7", "203.0.113.8"]))
    assert r and r.is_response and r.rcode == "NOERROR"
    assert [a[2] for a in r.answers] == ["203.0.113.7", "203.0.113.8"]
    nx = parse_dns(lab.dns_response(9, "nope.invalid", [], rcode=3))
    assert nx and nx.rcode == "NXDOMAIN" and nx.answers == ()


def test_dns_rejects_hostile_messages() -> None:
    assert parse_dns(b"") is None and parse_dns(bytes(11)) is None
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert parse_dns(loop) is None  # a compression pointer that points at itself
    long_name = b"".join(bytes([63]) + b"a" * 63 for _ in range(6)) + b"\x00"
    big = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + long_name + struct.pack("!HH", 1, 1)
    assert parse_dns(big) is None  # names longer than 255 bytes
    assert parse_dns(struct.pack("!HHHHHH", 1, 0x0100, 5000, 0, 0, 0) + bytes(20)) is None
    assert (
        parse_dns(struct.pack("!HHHHHH", 1, 0x2800, 1, 0, 0, 0) + bytes(20)) is None
    )  # not a query
    cut = lab.dns_response(7, "example.test", ["203.0.113.7"])[:-2]
    msg = parse_dns(cut)
    assert msg is not None and msg.answers == ()  # answer cut short: keep the question only


def test_http_request_never_keeps_the_credential() -> None:
    m = parse_http(
        lab.http_request("GET", "h.test", "/p?q=1", "Authorization: Bearer SECRETTOKEN\r\n")
    )
    assert m and m.is_request and m.method == "GET" and m.host == "h.test"
    assert m.path == "/p" and m.query_omitted
    assert m.auth_scheme == "Bearer" and "SECRETTOKEN" not in repr(m)
    r = parse_http(lab.http_response(404))
    assert r and not r.is_request and r.status == 404
    assert parse_http(b"\x16\x03\x01garbage") is None and parse_http(b"GET nothing") is None


def test_tls_sni() -> None:
    assert parse_tls_sni(lab.tls_client_hello("secure.example.test")) == "secure.example.test"
    hello = lab.tls_client_hello("x.test")
    for cut in range(0, len(hello), 7):
        assert parse_tls_sni(hello[:cut]) in (None, "x.test")  # never raises on a truncated hello
    assert parse_tls_sni(b"\x17\x03\x03" + bytes(80)) is None


def test_http_target_drops_query_fragment_params_and_url_credentials() -> None:
    def parse(path: str):  # type: ignore[no-untyped-def]
        return parse_http(lab.http_request("GET", "h.test", path))

    m = parse("/reset?token=TEST_SECRET#frag")
    assert m and m.path == "/reset" and m.query_omitted and "TEST_SECRET" not in repr(m)
    m = parse("/a;jsessionid=TEST_SECRET/b")
    assert m and m.path == "/a/b" and m.query_omitted and "TEST_SECRET" not in repr(m)
    m = parse("http://user:TEST_SECRET@proxy.test:8080/x?k=TEST_SECRET")
    assert m and m.path == "/x" and m.host == "h.test" and "TEST_SECRET" not in repr(m)
    raw = b"GET http://user:TEST_SECRET@proxy.test/x HTTP/1.1\r\n\r\n"
    m = parse_http(raw)
    assert m and m.host == "proxy.test" and m.path == "/x" and "TEST_SECRET" not in repr(m)
    assert parse("/plain") and not parse("/plain").query_omitted  # type: ignore[union-attr]
