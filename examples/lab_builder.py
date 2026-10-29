"""Build synthetic packets and capture files by hand, for the lab example and the tests.

Nothing here is captured from a real network. Addresses come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24); names end in .test or .invalid.
"""

from __future__ import annotations

import ipaddress
import random
import struct

Frame = tuple[int, bytes]  # (timestamp in ns, Ethernet frame)
MAC_A, MAC_B = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


def eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes, *, flags_frag: int = 0) -> bytes:
    total = 20 + len(payload)
    head = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, flags_frag, 64, proto, 0)
    return head + ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes) -> bytes:
    head = struct.pack("!IHBB", 6 << 28, len(payload), nxt, 64)
    return head + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, data: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data


def udp(sport: int, dport: int, data: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


def icmp(kind: int, code: int, rest: bytes = b"\x00\x01\x00\x01") -> bytes:
    return struct.pack("!BBH", kind, code, 0) + rest


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(ident: int, name: str, qtype: int = 1) -> bytes:
    return (
        struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
        + dns_name(name)
        + struct.pack("!HH", qtype, 1)
    )


def dns_response(
    ident: int, name: str, answers: list[str], rcode: int = 0, qtype: int = 1
) -> bytes:
    head = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1, len(answers), 0, 0)
    body = dns_name(name) + struct.pack("!HH", qtype, 1)
    for addr in answers:
        body += (
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ipaddress.IPv4Address(addr).packed
        )
    return head + body


def tls_client_hello(sni: str) -> bytes:
    name = sni.encode()
    ext_sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(ext_sni)) + ext_sni
    body = b"\x03\x03" + bytes(32) + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def http_request(method: str, host: str, path: str, extra: str = "") -> bytes:
    return f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: lab-client/1.0\r\n{extra}\r\n".encode()


def http_response(status: int, body: bytes = b"ok") -> bytes:
    return f"HTTP/1.1 {status} OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


class Sim:
    """Collects frames; every helper advances time by a small, fixed step."""

    def __init__(self, start_ns: int) -> None:
        self.frames: list[Frame] = []
        self.now = start_ns

    def at(self, seconds: float) -> None:
        self.now += int(seconds * 1e9)

    def add(self, frame: bytes, gap: float = 0.001) -> None:
        self.frames.append((self.now, frame))
        self.at(gap)

    def tcp_pkt(
        self,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        flags: int,
        seq: int,
        ack: int,
        data: bytes = b"",
    ) -> None:
        self.add(eth(ipv4(src, dst, 6, tcp(sport, dport, seq, ack, flags, data))))

    def session(
        self, client: str, cport: int, server: str, sport: int,
        sends: list[bytes], replies: list[bytes], close: str = "fin",
    ) -> None:  # fmt: skip
        c, s = 1000, 9000
        self.tcp_pkt(client, cport, server, sport, SYN, c, 0)
        self.tcp_pkt(server, sport, client, cport, SYN | ACK, s, c + 1)
        c, s = c + 1, s + 1
        self.tcp_pkt(client, cport, server, sport, ACK, c, s)
        for out, back in zip(sends, replies, strict=False):
            self.tcp_pkt(client, cport, server, sport, PSH | ACK, c, s, out)
            c += len(out)
            self.tcp_pkt(server, sport, client, cport, PSH | ACK, s, c, back)
            s += len(back)
        if close == "fin":
            self.tcp_pkt(client, cport, server, sport, FIN | ACK, c, s)
            self.tcp_pkt(server, sport, client, cport, FIN | ACK, s, c + 1)
        elif close == "rst":
            self.tcp_pkt(server, sport, client, cport, RST, s, c)

    def refused(self, client: str, cport: int, server: str, sport: int) -> None:
        self.tcp_pkt(client, cport, server, sport, SYN, 500, 0)
        self.tcp_pkt(server, sport, client, cport, RST | ACK, 0, 501)

    def unanswered(self, client: str, cport: int, server: str, sport: int) -> None:
        self.tcp_pkt(client, cport, server, sport, SYN, 700, 0)

    def dns(
        self,
        client: str,
        cport: int,
        resolver: str,
        ident: int,
        name: str,
        answers: list[str],
        rcode: int = 0,
    ) -> None:
        self.add(eth(ipv4(client, resolver, 17, udp(cport, 53, dns_query(ident, name)))))
        self.add(
            eth(
                ipv4(
                    resolver, client, 17, udp(53, cport, dns_response(ident, name, answers, rcode))
                )
            ),
            0.02,
        )


def pcap_bytes(
    frames: list[Frame], *, linktype: int = 1, nano: bool = False, big: bool = False
) -> bytes:
    order = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    parts = [struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype)]
    for ts, data in frames:
        sec, rest = divmod(ts, 1_000_000_000)
        frac = rest if nano else rest // 1000
        parts.append(struct.pack(order + "IIII", sec, frac, len(data), len(data)) + data)
    return b"".join(parts)


def _block(kind: int, body: bytes, order: str) -> bytes:
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return (
        struct.pack(order + "II", kind, total)
        + body
        + b"\x00" * pad
        + struct.pack(order + "I", total)
    )


def pcapng_bytes(
    frames: list[Frame], *, linktype: int = 1, big: bool = False, tsresol: int = 9
) -> bytes:
    order = ">" if big else "<"
    shb = _block(0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1), order)
    opt = struct.pack(order + "HHBxxx", 9, 1, tsresol) + struct.pack(order + "HH", 0, 0)
    idb = _block(1, struct.pack(order + "HHI", linktype, 0, 65535) + opt, order)
    parts = [shb, idb]
    ticks = 10**tsresol
    for ts, data in frames:
        t = ts * ticks // 1_000_000_000
        body = struct.pack(order + "IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data
        parts.append(_block(6, body, order))
    return b"".join(parts)


START_NS = 1_793_293_200 * 1_000_000_000  # 2026-10-29T17:00:00Z


def build_lab() -> list[Frame]:
    """The lab: a workstation browses, a scanner probes a jump host, and a few oddities."""
    rng = random.Random(7)  # noqa: S311 - deterministic test data
    sim = Sim(START_NS)
    ws, resolver, gateway = "192.0.2.10", "192.0.2.53", "192.0.2.1"
    web, api, jump, scanner = "203.0.113.7", "203.0.113.20", "192.0.2.50", "198.51.100.77"

    sim.add(eth(ipv4(ws, gateway, 1, icmp(8, 0))))
    sim.add(eth(ipv4(gateway, ws, 1, icmp(0, 0))), 0.5)
    sim.dns(ws, 40001, resolver, 0x1001, "example.test", [web])
    sim.session(ws, 50001, web, 443, [tls_client_hello("example.test"), b"\x17\x03\x03" + bytes(300)],
                [b"\x16\x03\x03" + bytes(1200), b"\x17\x03\x03" + bytes(4000)])  # fmt: skip
    sim.at(1.0)
    sim.dns(ws, 40002, resolver, 0x1002, "api.example.test", [api])
    sim.session(ws, 50002, api, 80,
                [http_request("GET", "api.example.test", "/v1/status", "Authorization: Basic ZGVtbzpkZW1v\r\n")],
                [http_response(200, b'{"status":"ok"}')])  # fmt: skip
    sim.at(2.0)
    for i, label in enumerate(["xk3f9a", "q8w2pz", "m7d4tt", "zz91ab", "r5n0cc", "b2k8yy"]):
        sim.dns(ws, 41000 + i, resolver, 0x2000 + i, f"{label}.invalid", [], rcode=3)
    sim.add(eth(ipv4(ws, "198.51.100.123", 17, udp(50123, 123, bytes(48)))), 1.0)

    sim.at(5.0)
    for port in range(1, 31):  # the scanner walks ports 1..30 on the jump host
        if port in (22, 25):
            sim.tcp_pkt(scanner, 60000 + port, jump, port, SYN, 100, 0)
            sim.tcp_pkt(jump, port, scanner, 60000 + port, SYN | ACK, 200, 101)
            sim.tcp_pkt(scanner, 60000 + port, jump, port, RST, 101, 0)
        elif port % 3 == 0:
            sim.unanswered(scanner, 60000 + port, jump, port)
        else:
            sim.refused(scanner, 60000 + port, jump, port)
    sim.at(3.0)
    sim.refused(ws, 52000, jump, 23)  # one stray refused connection, not a scan
    sim.at(2.0)
    sim.session(ws, 50010, jump, 22, [b"SSH-2.0-OpenSSH_9.6\r\n" + bytes(rng.randrange(0, 255) for _ in range(40))],
                [b"SSH-2.0-OpenSSH_8.9\r\n" + bytes(80)], close="rst")  # fmt: skip
    return sim.frames


def lab_pcap() -> bytes:
    return pcap_bytes(build_lab())
