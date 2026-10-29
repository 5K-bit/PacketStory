from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import lab_builder as lab
import pytest

from packetstory import __version__
from packetstory.cli import main

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "examples" / "lab" / "lab.pcap"


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_summary_flows_story(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "summary", str(LAB))
    assert code == 0 and "95 packets" in out and "3 worth a look" in out
    code, out, _ = run(capsys, "flows", str(LAB), "--limit", "3")
    assert code == 0 and "more (raise --limit)" in out and out.count("\n") == 4
    code, out, _ = run(capsys, "story", str(LAB))
    assert code == 0 and "Possible port scan" in out and "## Worth a look" in out


def test_story_to_files(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    for fmt, marker in (("md", "# PacketStory"), ("html", "<!doctype html>"), ("json", '"events"')):
        target = tmp_path / f"out.{fmt}"
        code, out, _ = run(capsys, "story", str(LAB), "--format", fmt, "--out", str(target))
        assert code == 0 and "Wrote" in out and marker in target.read_text(encoding="utf-8")


def test_errors_exit_1(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    code, _, err = run(capsys, "summary", str(tmp_path / "missing.pcap"))
    assert code == 1 and "cannot read" in err
    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"this is not a capture at all")
    code, _, err = run(capsys, "story", str(junk))
    assert code == 1 and "not a pcap or pcapng" in err


def test_strict_flags_a_damaged_capture(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(LAB.read_bytes()[:-30])
    assert run(capsys, "story", str(cut))[0] == 0
    code, out, _ = run(capsys, "story", str(cut), "--strict")
    assert code == 2 and "truncated" in out
    code, out, _ = run(capsys, "summary", str(cut))
    assert "warning:" in out


def test_pcapng_gives_the_same_story(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ng = tmp_path / "lab.pcapng"
    ng.write_bytes(lab.pcapng_bytes(lab.build_lab()))
    _, a, _ = run(capsys, "story", str(LAB))
    _, b, _ = run(capsys, "story", str(ng))
    assert a == b.replace("lab.pcapng", "lab.pcap").replace("(pcapng)", "(pcap)")


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert f"packetstory {__version__}" in capsys.readouterr().out


def load_acceptance():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "ps_acceptance", ROOT / "examples" / "acceptance.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["ps_acceptance"] = module
    spec.loader.exec_module(module)
    return module


def test_checked_in_capture_matches_the_builder() -> None:
    assert LAB.read_bytes() == lab.lab_pcap()


@pytest.mark.skipif(os.name == "nt", reason="recorded transcript uses POSIX path separators")
def test_transcript_and_reports_match_the_recorded_evidence(tmp_path: Path) -> None:
    text = load_acceptance().run_scenario(tmp_path)
    evidence = ROOT / "docs" / "evidence"
    assert text == (evidence / "acceptance-transcript.txt").read_text(encoding="utf-8")
    for name in ("story.md", "story.html", "story.json"):
        assert (tmp_path / name).read_text(encoding="utf-8") == (evidence / name).read_text(
            encoding="utf-8"
        )
