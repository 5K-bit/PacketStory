from __future__ import annotations

import struct

import lab_builder as lab
import pytest

from packetstory.capture import MAX_CAPTURE_BYTES, open_capture
from packetstory.errors import PacketStoryError

FRAMES = [(1_793_293_200_123_456_789, b"\x01" * 60), (1_793_293_201_000_000_000, b"\x02" * 70)]


def read(data: bytes):  # type: ignore[no-untyped-def]
    cap = open_capture(data)
    return cap, list(cap.packets())


@pytest.mark.parametrize("big", [False, True])
def test_pcap_microseconds(big: bool) -> None:
    cap, pkts = read(lab.pcap_bytes(FRAMES, big=big))
    assert cap.format == "pcap" and [p.number for p in pkts] == [1, 2]
    assert pkts[0].ts_ns == 1_793_293_200_123_456_000  # microsecond precision
    assert pkts[1].data == b"\x02" * 70 and pkts[0].linktype == 1


@pytest.mark.parametrize("big", [False, True])
def test_pcap_nanoseconds(big: bool) -> None:
    _, pkts = read(lab.pcap_bytes(FRAMES, nano=True, big=big))
    assert pkts[0].ts_ns == FRAMES[0][0]


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("tsresol", [6, 9])
def test_pcapng(big: bool, tsresol: int) -> None:
    cap, pkts = read(lab.pcapng_bytes(FRAMES, big=big, tsresol=tsresol))
    assert cap.format == "pcapng" and len(pkts) == 2 and not cap.warnings
    expected = FRAMES[0][0] if tsresol == 9 else FRAMES[0][0] // 1000 * 1000
    assert pkts[0].ts_ns == expected and pkts[1].data == b"\x02" * 70


def test_pcapng_simple_packet_block_and_unknown_blocks() -> None:
    base = lab.pcapng_bytes([])
    spb = lab._block(3, struct.pack("<I", 4) + b"\xaa\xbb\xcc\xdd", "<")
    other = lab._block(0x40000001, b"custom", "<")
    _, pkts = read(base + other + spb)
    assert len(pkts) == 1 and pkts[0].data == b"\xaa\xbb\xcc\xdd" and pkts[0].ts_ns == 0


def test_truncated_pcap_keeps_what_it_can() -> None:
    data = lab.pcap_bytes(FRAMES)
    cap, pkts = read(data[:-10])
    assert len(pkts) == 1 and any("truncated inside packet 2" in w for w in cap.warnings)
    cap, pkts = read(data[: 24 + 16 + 60 + 5])
    assert len(pkts) == 1 and any("packet header" in w for w in cap.warnings)


def test_implausible_length_stops_the_read() -> None:
    data = bytearray(lab.pcap_bytes(FRAMES))
    struct.pack_into("<I", data, 24 + 8, 0x7FFFFFFF)
    cap, pkts = read(bytes(data))
    assert pkts == [] and any("implausible" in w for w in cap.warnings)


def test_pcapng_bad_blocks_stop_the_read() -> None:
    data = bytearray(lab.pcapng_bytes(FRAMES))
    shb_len = struct.unpack("<I", data[4:8])[0]
    idb_len = struct.unpack("<I", data[shb_len + 4 : shb_len + 8])[0]
    struct.pack_into("<I", data, shb_len + idb_len + 4, 0x7FFFFFF0)
    cap, pkts = read(bytes(data))
    assert pkts == [] and any("bad block length" in w for w in cap.warnings)
    cap, pkts = read(lab.pcapng_bytes(FRAMES)[:-3])
    assert len(pkts) <= 1 and cap.warnings


def test_pcapng_packet_for_missing_interface_is_skipped() -> None:
    shb = lab.pcapng_bytes([])[:28]  # section header only
    epb = lab._block(6, struct.pack("<IIIII", 0, 0, 1, 4, 4) + b"abcd", "<")
    cap, pkts = read(shb + epb)
    assert pkts == [] and any("missing interface" in w for w in cap.warnings)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "not a pcap"),
        (b"hello world, not a capture", "not a pcap"),
        (b"\x1f\x8b\x08\x00" + bytes(20), "gzip"),
        (b"\xd4\xc3\xb2\xa1\x02\x00", "shorter than its header"),
    ],
)
def test_not_a_capture(data: bytes, message: str) -> None:
    with pytest.raises(PacketStoryError, match=message):
        open_capture(data)


def test_size_cap() -> None:
    with pytest.raises(PacketStoryError, match="larger than"):
        open_capture(b"\xd4\xc3\xb2\xa1" + bytes(MAX_CAPTURE_BYTES))
