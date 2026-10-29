from __future__ import annotations

import json
import os
import random
import struct
from pathlib import Path

import lab_builder as lab

from packetstory.analyze import analyze
from packetstory.errors import PacketStoryError
from packetstory.render import to_html, to_json, to_markdown

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def check_golden(name: str, text: str) -> None:
    path = FIXTURES / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


def test_markdown_golden(lab_bytes: bytes) -> None:
    check_golden("lab.story.md", to_markdown(analyze(lab_bytes, "lab.pcap")))


def test_json_golden_and_shape(lab_bytes: bytes) -> None:
    text = to_json(analyze(lab_bytes, "lab.pcap"))
    check_golden("lab.story.json", text)
    doc = json.loads(text)
    assert doc["capture"]["packets"] == 95 and sum(e["notable"] for e in doc["events"]) == 3


def test_html_golden(lab_bytes: bytes) -> None:
    check_golden("lab.story.html", to_html(analyze(lab_bytes, "lab.pcap")))


def hostile_capture() -> bytes:
    """DNS names and HTTP fields that try to break out of Markdown and HTML."""
    sim = lab.Sim(lab.START_NS)
    evil = "<script>alert(1)</script>"
    sim.dns("192.0.2.1", 4000, "192.0.2.53", 1, f"a`b*c_d|e[f]({evil}).test", ["203.0.113.9"])
    sim.session("192.0.2.1", 5000, "203.0.113.9", 80,
                [lab.http_request("GET", evil, f"/{evil}", "Authorization: Basic eA==\r\n")],
                [lab.http_response(200)])  # fmt: skip
    return lab.pcap_bytes(sim.frames)


def test_hostile_text_is_neutralised_in_every_format() -> None:
    report = analyze(hostile_capture(), "<img src=x onerror=alert(1)>.pcap")
    html_text = to_html(report)
    assert "<script>" not in html_text and "<img" not in html_text
    assert "&lt;script&gt;" in html_text
    md = to_markdown(report)
    assert "<script>" not in md and "<img" not in md
    assert "\\|" in md and "\\`" in md  # table and code characters are escaped
    assert json.loads(to_json(report))["events"]  # still valid JSON


def test_max_events_truncates_with_a_note(lab_bytes: bytes) -> None:
    md = to_markdown(analyze(lab_bytes, "lab.pcap"), max_events=3)
    assert "more event(s)" in md
    assert "more event(s)" in to_html(analyze(lab_bytes, "lab.pcap"), max_events=3)


def test_quality_section_reports_damage(lab_bytes: bytes) -> None:
    report = analyze(lab_bytes[:-20], "cut.pcap")
    md = to_markdown(report)
    assert "truncated inside packet" in md
    clean = to_markdown(analyze(lab_bytes, "lab.pcap"))
    assert "No problems found reading the capture." in clean


def test_event_free_capture_says_so() -> None:
    md = to_markdown(analyze(lab.pcap_bytes([]), "empty.pcap"))
    assert "Nothing to tell" in md and "Nothing stood out" in md


def mutate(data: bytes, rng: random.Random) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randrange(1, 9)):
        buf[rng.randrange(len(buf))] = rng.randrange(256)
    if rng.random() < 0.3:
        del buf[rng.randrange(len(buf)) :]
    if rng.random() < 0.1:
        pos = rng.randrange(max(1, len(buf) - 4))
        buf[pos : pos + 4] = struct.pack("<I", rng.choice([0, 1, 0x7FFFFFFF, 0xFFFFFFFF]))
    return bytes(buf)


def test_mutated_captures_never_crash(lab_frames: list[lab.Frame]) -> None:
    rng = random.Random(1234)  # noqa: S311 - deterministic fuzzing
    seeds = [
        lab.pcap_bytes(lab_frames),
        lab.pcapng_bytes(lab_frames),
        lab.pcap_bytes(lab_frames, big=True),
    ]
    clean = rejected = 0
    for i in range(400):
        data = mutate(seeds[i % 3], rng)
        try:
            report = analyze(data, "fuzz.pcap")
        except PacketStoryError:
            rejected += 1
            continue
        to_markdown(report)
        to_html(report)
        to_json(report)
        clean += 1
    assert clean > 200  # most mutations leave a readable capture; none may raise anything else
    assert clean + rejected == 400
