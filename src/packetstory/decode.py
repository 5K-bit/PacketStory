"""Decode link, network and transport layers into a flat record.

Nothing here raises on bad input: a packet that cannot be decoded comes back with
``malformed`` set, so a hostile capture can lose packets but cannot stop the analysis.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from .capture import RawPacket

LINK_NULL, LINK_ETHERNET, LINK_RAW, LINK_SLL = 0, 1, 101, 113
TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10
_ETH_IPV4, _ETH_IPV6, _ETH_ARP, _ETH_VLAN, _ETH_QINQ = 0x0800, 0x86DD, 0x0806, 0x8100, 0x88A8
_V6_SKIP = {0, 43, 60}  # hop-by-hop, routing, destination options
_V6_FRAGMENT = 44


@dataclass(frozen=True)
class Decoded:
    number: int
    ts_ns: int
    frame_len: int
    proto: str = "other"  # tcp udp icmp icmpv6 arp other
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    flags: int = 0
    seq: int = 0
    ack: int = 0
    icmp_type: int = -1
    icmp_code: int = -1
    payload: bytes = b""
    fragment: bool = False
    malformed: str = ""
    unsupported: str = ""


def decode(raw: RawPacket) -> Decoded:
    base = Decoded(raw.number, raw.ts_ns, raw.orig_len)
    try:
        return _decode(raw, base)
    except (struct.error, IndexError, ValueError):
        return _with(base, malformed="truncated or inconsistent headers")


def _with(base: Decoded, **changes: object) -> Decoded:
    values = {f: getattr(base, f) for f in base.__dataclass_fields__}
    values.update(changes)
    return Decoded(**values)


def _decode(raw: RawPacket, base: Decoded) -> Decoded:
    data, link = raw.data, raw.linktype
    if link == LINK_ETHERNET:
        if len(data) < 14:
            return _with(base, malformed="shorter than an Ethernet header")
        ethertype = struct.unpack("!H", data[12:14])[0]
        pos = 14
        for _ in range(2):
            if ethertype in (_ETH_VLAN, _ETH_QINQ):
                ethertype = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
                pos += 4
        return _network(base, ethertype, data[pos:])
    if link == LINK_SLL:
        if len(data) < 16:
            return _with(base, malformed="shorter than a Linux cooked header")
        return _network(base, struct.unpack("!H", data[14:16])[0], data[16:])
    if link == LINK_RAW:
        return _network(base, _ip_ethertype(data), data)
    if link == LINK_NULL:
        if len(data) < 4:
            return _with(base, malformed="shorter than a loopback header")
        return _network(base, _ip_ethertype(data[4:]), data[4:])
    return _with(base, unsupported=f"link type {link}")


def _ip_ethertype(data: bytes) -> int:
    version = data[0] >> 4 if data else 0
    return {4: _ETH_IPV4, 6: _ETH_IPV6}.get(version, 0)


def _network(base: Decoded, ethertype: int, data: bytes) -> Decoded:
    if ethertype == _ETH_IPV4:
        return _ipv4(base, data)
    if ethertype == _ETH_IPV6:
        return _ipv6(base, data)
    if ethertype == _ETH_ARP:
        return _arp(base, data)
    return _with(base, unsupported=f"ethertype 0x{ethertype:04x}")


def _arp(base: Decoded, data: bytes) -> Decoded:
    if len(data) < 28:
        return _with(base, proto="arp", malformed="short ARP packet")
    op = struct.unpack("!H", data[6:8])[0]
    src = str(ipaddress.IPv4Address(data[14:18]))
    dst = str(ipaddress.IPv4Address(data[24:28]))
    return _with(base, proto="arp", src=src, dst=dst, icmp_type=op)  # icmp_type carries the opcode


def _ipv4(base: Decoded, data: bytes) -> Decoded:
    if len(data) < 20 or data[0] >> 4 != 4:
        return _with(base, malformed="bad IPv4 header")
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack("!H", data[2:4])[0]
    frag = struct.unpack("!H", data[6:8])[0]
    proto = data[9]
    if ihl < 20 or len(data) < ihl:
        return _with(base, malformed="bad IPv4 header length")
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    end = min(len(data), total) if total >= ihl else len(data)
    fragmented = bool(frag & 0x2000) or bool(frag & 0x1FFF)
    first = not (frag & 0x1FFF)
    return _transport(
        _with(base, src=src, dst=dst, fragment=fragmented), proto, data[ihl:end], first
    )


def _ipv6(base: Decoded, data: bytes) -> Decoded:
    if len(data) < 40 or data[0] >> 4 != 6:
        return _with(base, malformed="bad IPv6 header")
    plen = struct.unpack("!H", data[4:6])[0]
    nxt = data[6]
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    end = min(len(data), 40 + plen)
    pos, fragmented, first = 40, False, True
    for _ in range(8):
        if nxt in _V6_SKIP:
            nxt, length = data[pos], (data[pos + 1] + 1) * 8
            pos += length
        elif nxt == _V6_FRAGMENT:
            offset = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
            nxt = data[pos]
            fragmented, first = True, not (offset >> 3)
            pos += 8
        else:
            break
    if pos > end:
        return _with(base, malformed="IPv6 extension headers run past the packet")
    return _transport(_with(base, src=src, dst=dst, fragment=fragmented), nxt, data[pos:end], first)


def _transport(base: Decoded, proto: int, data: bytes, first_fragment: bool) -> Decoded:
    if not first_fragment:
        return _with(base, proto="other", unsupported="non-first IP fragment")
    if proto == 6:
        if len(data) < 20:
            return _with(base, proto="tcp", malformed="short TCP header")
        sport, dport, seq, ack, off = struct.unpack("!HHIIB", data[:13])
        header = (off >> 4) * 4
        if header < 20 or header > len(data):
            return _with(base, proto="tcp", malformed="bad TCP header length")
        return _with(
            base, proto="tcp", sport=sport, dport=dport, seq=seq, ack=ack,
            flags=data[13] & 0x3F, payload=data[header:],
        )  # fmt: skip
    if proto == 17:
        if len(data) < 8:
            return _with(base, proto="udp", malformed="short UDP header")
        sport, dport, length = struct.unpack("!HHH", data[:6])
        end = length if 8 <= length <= len(data) else len(data)
        return _with(base, proto="udp", sport=sport, dport=dport, payload=data[8:end])
    if proto in (1, 58):
        if len(data) < 4:
            return _with(base, proto="icmp" if proto == 1 else "icmpv6", malformed="short ICMP")
        return _with(
            base, proto="icmp" if proto == 1 else "icmpv6", icmp_type=data[0], icmp_code=data[1],
            payload=data[4:],
        )  # fmt: skip
    return _with(base, unsupported=f"IP protocol {proto}")
