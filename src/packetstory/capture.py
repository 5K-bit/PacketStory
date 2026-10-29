"""Read classic pcap and pcapng files into raw packets.

Captures are hostile input. Every length is checked against what remains, loops are bounded,
and a damaged tail ends the read with a warning instead of an exception.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field

from .errors import PacketStoryError

MAX_CAPTURE_BYTES = 256 * 1024 * 1024
MAX_PACKETS = 5_000_000
MAX_PACKET_BYTES = 262_144

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),  # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),
}
_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


@dataclass(frozen=True)
class RawPacket:
    number: int  # 1-based position in the capture, as Wireshark numbers them
    ts_ns: int
    linktype: int
    data: bytes
    orig_len: int


@dataclass
class Capture:
    """Result of opening a capture. Iterate ``packets()``; ``warnings`` fills as you go."""

    format: str
    data: bytes = field(repr=False)
    warnings: list[str] = field(default_factory=list)
    truncated_packets: int = 0

    def packets(self) -> Iterator[RawPacket]:
        if self.format == "pcap":
            yield from _read_pcap(self)
        else:
            yield from _read_pcapng(self)


def open_capture(data: bytes) -> Capture:
    if len(data) > MAX_CAPTURE_BYTES:
        raise PacketStoryError(f"capture is larger than {MAX_CAPTURE_BYTES // 2**20} MiB")
    if data[:4] in _PCAP_MAGICS:
        if len(data) < 24:
            raise PacketStoryError("pcap file is shorter than its header")
        return Capture("pcap", data)
    if data[:4] == _PCAPNG_SHB:
        return Capture("pcapng", data)
    if data[:2] == b"\x1f\x8b":
        raise PacketStoryError("this looks gzip-compressed; decompress it first")
    raise PacketStoryError("not a pcap or pcapng capture (unrecognised file header)")


def _read_pcap(cap: Capture) -> Iterator[RawPacket]:
    data = cap.data
    order, unit = _PCAP_MAGICS[data[:4]]
    _vmaj, _vmin, _zone, _sig, snaplen, linktype = struct.unpack(order + "HHiIII", data[4:24])
    pos, number = 24, 0
    while pos < len(data):
        if len(data) - pos < 16:
            cap.warnings.append(f"capture ends inside a packet header after packet {number}")
            return
        sec, frac, incl, orig = struct.unpack(order + "IIII", data[pos : pos + 16])
        pos += 16
        if incl > MAX_PACKET_BYTES or (snaplen and incl > max(snaplen, 65_535) * 4):
            cap.warnings.append(f"implausible packet length {incl} after packet {number}; stopped")
            return
        if len(data) - pos < incl:
            cap.warnings.append(f"capture is truncated inside packet {number + 1}; stopped")
            cap.truncated_packets += 1
            return
        number += 1
        if number > MAX_PACKETS:
            cap.warnings.append(f"more than {MAX_PACKETS} packets; the rest were not read")
            return
        yield RawPacket(
            number, sec * 1_000_000_000 + frac * unit, linktype, data[pos : pos + incl], orig
        )
        pos += incl


def _tsresol_to_ticks_per_second(raw: int) -> int | None:
    base, exp = (10, raw & 0x7F) if not raw & 0x80 else (2, raw & 0x7F)
    if exp > 63:
        return None
    return int(base**exp)


def _idb_resolution(options: bytes, order: str) -> int:
    ticks = 1_000_000
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(order + "HH", options[pos : pos + 4])
        pos += 4
        if code == 0:
            break
        value = options[pos : pos + length]
        if code == 9 and length == 1:
            parsed = _tsresol_to_ticks_per_second(value[0])
            if parsed:
                ticks = parsed
        pos += (length + 3) & ~3
    return ticks


def _read_pcapng(cap: Capture) -> Iterator[RawPacket]:
    data = cap.data
    order = "<"
    interfaces: list[tuple[int, int]] = []  # (linktype, ticks per second)
    pos, number = 0, 0
    while pos < len(data):
        if len(data) - pos < 12:
            cap.warnings.append("capture ends inside a block header")
            return
        btype = data[pos : pos + 4]
        if btype == _PCAPNG_SHB:
            magic = data[pos + 8 : pos + 12]
            if magic == b"\x4d\x3c\x2b\x1a":
                order = "<"
            elif magic == b"\x1a\x2b\x3c\x4d":
                order = ">"
            else:
                cap.warnings.append("section header has an unknown byte-order marker; stopped")
                return
            interfaces = []
        (blen,) = struct.unpack(order + "I", data[pos + 4 : pos + 8])
        if blen < 12 or blen % 4 or blen > len(data) - pos:
            cap.warnings.append(f"bad block length {blen} after packet {number}; stopped")
            return
        (kind,) = struct.unpack(order + "I", btype)
        body = data[pos + 8 : pos + blen - 4]
        pos += blen
        if kind == 1 and len(body) >= 8:  # interface description
            linktype = struct.unpack(order + "H", body[0:2])[0]
            ticks = _idb_resolution(body[8:], order)
            interfaces.append((linktype, ticks))
        elif kind == 6 and len(body) >= 20:  # enhanced packet
            iface, hi, lo, caplen, orig = struct.unpack(order + "IIIII", body[:20])
            if iface >= len(interfaces) or caplen > len(body) - 20 or caplen > MAX_PACKET_BYTES:
                cap.warnings.append("packet block refers to a missing interface or is oversized")
                continue
            number += 1
            if number > MAX_PACKETS:
                cap.warnings.append(f"more than {MAX_PACKETS} packets; the rest were not read")
                return
            linktype, ticks = interfaces[iface]
            ts_ns = ((hi << 32) | lo) * 1_000_000_000 // ticks
            yield RawPacket(number, ts_ns, linktype, body[20 : 20 + caplen], orig)
        elif kind == 3 and len(body) >= 4 and interfaces:  # simple packet, no timestamp
            (orig,) = struct.unpack(order + "I", body[:4])
            number += 1
            yield RawPacket(
                number, 0, interfaces[0][0], body[4 : 4 + min(orig, len(body) - 4)], orig
            )
