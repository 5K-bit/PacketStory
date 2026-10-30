from __future__ import annotations

import lab_builder as lab
import pytest

from packetstory.analyze import analyze
from packetstory.capture import RawPacket
from packetstory.decode import decode
from packetstory.flows import build
from packetstory.story import Narrator, duration_text, size_text

START = lab.START_NS


def analysis(frames: list[lab.Frame]):  # type: ignore[no-untyped-def]
    return build(
        decode(RawPacket(i + 1, ts, 1, data, len(data))) for i, (ts, data) in enumerate(frames)
    )


def events(frames: list[lab.Frame]):  # type: ignore[no-untyped-def]
    return Narrator(analysis(frames)).events()


def test_handshake_states() -> None:
    sim = lab.Sim(START)
    sim.session("192.0.2.1", 1000, "192.0.2.2", 80, [b"x"], [b"y"])
    sim.refused("192.0.2.1", 1001, "192.0.2.2", 81)
    sim.unanswered("192.0.2.1", 1002, "192.0.2.2", 82)
    ok, refused, silent = analysis(sim.frames).flows
    assert (
        ok.established
        and ok.fin
        and ok.client == ("192.0.2.1", 1000)
        and ok.server == ("192.0.2.2", 80)
    )
    assert refused.refused and not refused.unanswered and refused.rst_by == "server"
    assert silent.unanswered and not silent.refused


def test_client_is_whoever_sent_the_syn_even_if_the_synack_came_first() -> None:
    sim = lab.Sim(START)
    sim.tcp_pkt("192.0.2.2", 80, "192.0.2.1", 1000, lab.SYN | lab.ACK, 5, 1)  # capture starts late
    (flow,) = analysis(sim.frames).flows
    assert flow.client == ("192.0.2.1", 1000) and flow.synack and not flow.midstream


def test_midstream_capture() -> None:
    sim = lab.Sim(START)
    sim.tcp_pkt("192.0.2.1", 5000, "192.0.2.2", 22, lab.PSH | lab.ACK, 10, 10, b"data")
    sim.tcp_pkt("192.0.2.2", 22, "192.0.2.1", 5000, lab.ACK, 10, 14)
    (flow,) = analysis(sim.frames).flows
    assert flow.midstream and flow.established
    assert "began mid-connection" in Narrator(analysis(sim.frames)).events()[0].text


def test_port_reuse_after_close_starts_a_new_flow() -> None:
    sim = lab.Sim(START)
    sim.session("192.0.2.1", 1000, "192.0.2.2", 80, [b"a"], [b"b"])
    sim.session("192.0.2.1", 1000, "192.0.2.2", 80, [b"c"], [b"d"])
    assert len(analysis(sim.frames).flows) == 2


def test_dns_answers_name_the_hosts() -> None:
    sim = lab.Sim(START)
    sim.dns("192.0.2.1", 4000, "192.0.2.53", 1, "files.example.test", ["203.0.113.9"])
    sim.session("192.0.2.1", 5000, "203.0.113.9", 8080, [b"hello"], [b"world"])
    text = " ".join(e.text for e in events(sim.frames))
    assert "files.example.test (203.0.113.9)" in text


def test_dns_query_without_reply_and_pairing_by_id() -> None:
    sim = lab.Sim(START)
    sim.add(
        lab.eth(
            lab.ipv4("192.0.2.1", "192.0.2.53", 17, lab.udp(4000, 53, lab.dns_query(1, "a.test")))
        )
    )
    sim.add(
        lab.eth(
            lab.ipv4("192.0.2.1", "192.0.2.53", 17, lab.udp(4000, 53, lab.dns_query(2, "b.test")))
        )
    )
    sim.add(
        lab.eth(
            lab.ipv4(
                "192.0.2.53",
                "192.0.2.1",
                17,
                lab.udp(53, 4000, lab.dns_response(2, "b.test", ["203.0.113.2"])),
            )
        )
    )
    texts = sorted(e.text for e in events(sim.frames))
    assert any("a.test (A); no reply was seen" in t for t in texts)
    assert any("b.test (A) and got 203.0.113.2" in t for t in texts)


@pytest.mark.parametrize(("targets", "scan"), [(9, False), (10, True)])
def test_scan_threshold(targets: int, scan: bool) -> None:
    sim = lab.Sim(START)
    for port in range(1, targets + 1):
        sim.refused("198.51.100.77", 60000 + port, "192.0.2.50", port)
    found = [e for e in events(sim.frames) if e.kind == "scan"]
    assert bool(found) is scan
    if scan:
        assert found[0].notable and "does not prove intent" in found[0].text
        assert not [
            e for e in events(sim.frames) if e.kind == "tcp-refused"
        ]  # folded into the scan
    else:
        assert [e for e in events(sim.frames) if e.kind == "tcp-refused"]


def test_many_successful_connections_are_not_a_scan() -> None:
    sim = lab.Sim(START)
    for port in range(1, 21):
        sim.session("192.0.2.1", 7000 + port, "192.0.2.2", port, [b"x"], [b"y"])
    assert not [e for e in events(sim.frames) if e.kind == "scan"]


def test_nxdomain_threshold() -> None:
    def run(n: int) -> list[str]:
        sim = lab.Sim(START)
        for i in range(n):
            sim.dns("192.0.2.1", 4000 + i, "192.0.2.53", i + 1, f"n{i}.invalid", [], rcode=3)
        return [e.kind for e in events(sim.frames)]

    assert "dns-failures" not in run(4) and "dns-failures" in run(5)


def test_cleartext_credentials_are_flagged_but_never_printed() -> None:
    sim = lab.Sim(START)
    request = lab.http_request(
        "GET", "h.test", "/", "Authorization: Basic c2VjcmV0OnNlY3JldA==\r\n"
    )
    sim.session("192.0.2.1", 5000, "192.0.2.2", 80, [request], [lab.http_response(200)])
    evs = events(sim.frames)
    assert any(e.kind == "cleartext-auth" and e.notable for e in evs)
    assert "c2VjcmV0" not in " ".join(e.text for e in evs)


def test_tls_is_not_mistaken_for_http() -> None:
    sim = lab.Sim(START)
    sim.session(
        "192.0.2.1",
        5000,
        "192.0.2.2",
        443,
        [lab.tls_client_hello("s.test")],
        [b"\x16\x03\x03" + bytes(50)],
    )
    (flow,) = analysis(sim.frames).flows
    assert flow.sni == "s.test" and not flow.http


def test_icmp_and_udp_narration() -> None:
    sim = lab.Sim(START)
    sim.add(lab.eth(lab.ipv4("192.0.2.1", "192.0.2.2", 1, lab.icmp(8, 0))))
    sim.add(lab.eth(lab.ipv4("192.0.2.2", "192.0.2.1", 1, lab.icmp(3, 1))))
    sim.add(lab.eth(lab.ipv4("192.0.2.1", "192.0.2.9", 17, lab.udp(5000, 9999, b"data"))))
    texts = [e.text for e in events(sim.frames)]
    assert any("pinged 192.0.2.2: 1 request(s), 0 reply" in t for t in texts)
    assert any("1 UDP packet(s)" in t and "no reply" in t for t in texts)


def test_events_are_sorted_and_cite_real_packets(lab_bytes: bytes) -> None:
    report = analyze(lab_bytes, "lab.pcap")
    stamps = [e.ts_ns for e in report.events]
    assert stamps == sorted(stamps)
    total = report.analysis.packets
    assert all(1 <= e.first_pkt <= e.last_pkt <= total for e in report.events)


def test_lab_findings(lab_bytes: bytes) -> None:
    report = analyze(lab_bytes, "lab.pcap")
    kinds = sorted(e.kind for e in report.events if e.notable)
    assert kinds == ["cleartext-auth", "dns-failures", "scan"]
    assert report.analysis.names["203.0.113.7"] == "example.test"
    assert report.analysis.malformed == 0 and not report.warnings


def test_empty_capture() -> None:
    report = analyze(lab.pcap_bytes([]), "empty.pcap")
    assert report.events == [] and report.analysis.packets == 0


def test_formatting_helpers() -> None:
    assert duration_text(10) == "under a millisecond" and duration_text(5_000_000) == "5 ms"
    assert duration_text(2_500_000_000) == "2.5 s" and duration_text(180_000_000_000) == "3.0 min"
    assert (
        size_text(10) == "10 B"
        and size_text(2048) == "2.0 KiB"
        and size_text(3 * 1024**2) == "3.0 MiB"
    )


def test_http_story_never_prints_the_query_string() -> None:
    sim = lab.Sim(START)
    sim.session(
        "192.0.2.1", 1000, "192.0.2.2", 80,
        [lab.http_request("GET", "h.test", "/reset?token=TEST_SECRET")], [lab.http_response(200)],
    )  # fmt: skip
    text = " ".join(e.text for e in events(sim.frames))
    assert "TEST_SECRET" not in text and "/reset?…" in text


def test_response_only_dns_does_not_invent_a_query() -> None:
    frames = [
        (START, lab.eth(lab.ipv4("192.0.2.53", "192.0.2.1", 17, lab.udp(
            53, 4000, lab.dns_response(7, "x.example.test", ["203.0.113.9"]))))),
    ]  # fmt: skip
    (flow,) = analysis(frames).flows
    assert flow.client == ("192.0.2.1", 4000) and flow.server == ("192.0.2.53", 53)
    (event,) = events(frames)
    assert "asked" not in event.text and "query was not captured" in event.text
    assert event.text.startswith("192.0.2.53 sent 192.0.2.1 a DNS response")


def test_tcp_close_wording_claims_only_what_was_seen() -> None:
    sim = lab.Sim(START)
    sim.session("192.0.2.1", 1000, "192.0.2.2", 80, [b"x"], [b"y"])
    sim.tcp_pkt("192.0.2.1", 2000, "192.0.2.2", 80, lab.SYN, 1, 0)
    sim.tcp_pkt("192.0.2.2", 80, "192.0.2.1", 2000, lab.SYN | lab.ACK, 5, 2)
    sim.tcp_pkt("192.0.2.1", 2000, "192.0.2.2", 80, lab.ACK, 2, 6)
    sim.tcp_pkt("192.0.2.1", 2000, "192.0.2.2", 80, lab.FIN | lab.ACK, 2, 6)
    sim.session("192.0.2.1", 3000, "192.0.2.2", 81, [b"x"], [b"y"])
    sim.tcp_pkt("192.0.2.1", 4000, "192.0.2.2", 82, lab.SYN, 1, 0)
    sim.tcp_pkt("192.0.2.2", 82, "192.0.2.1", 4000, lab.SYN | lab.ACK, 5, 2)
    sim.tcp_pkt("192.0.2.1", 4000, "192.0.2.2", 82, lab.ACK, 2, 6)
    text = "\n".join(e.text for e in events(sim.frames))
    assert "closed normally" not in text and "still open" not in text
    assert "FIN observed from both sides" in text
    assert "FIN observed from the client only" in text
    assert "no closing packets observed" in text
