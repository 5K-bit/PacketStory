"""Rough scale check: build a large synthetic capture, then time the analysis.

    python examples/scale.py --out docs/evidence

One machine, one run; not a benchmark.
"""

from __future__ import annotations

import argparse
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "examples"))

import lab_builder as lb  # noqa: E402

from packetstory.analyze import analyze  # noqa: E402
from packetstory.render import to_markdown  # noqa: E402

CONVERSATIONS = 20_000


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    sim = lb.Sim(lb.START_NS)
    for i in range(CONVERSATIONS):
        server = f"203.0.113.{1 + i % 200}"
        sim.session("192.0.2.10", 1024 + i % 60000, server, 443,
                    [lb.tls_client_hello("host.example.test"), b"\x17\x03\x03" + bytes(200)],
                    [b"\x16\x03\x03" + bytes(600), b"\x17\x03\x03" + bytes(1200)])  # fmt: skip
    data = lb.pcap_bytes(sim.frames)
    del sim
    start = time.perf_counter()
    report = analyze(data, "scale.pcap")
    analysed = time.perf_counter() - start
    start = time.perf_counter()
    to_markdown(report, max_events=200)
    rendered = time.perf_counter() - start
    peak_mib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux reports KiB
    lines = [
        f"synthetic capture: {report.analysis.packets} packets, {len(data) / 2**20:.1f} MiB, "
        f"{len(report.analysis.flows)} conversations; one machine, one run",
        f"analysis: {analysed:.1f} s ({report.analysis.packets / analysed:,.0f} packets/s)",
        f"report: {rendered:.2f} s",
        f"peak memory of the whole process (including building the capture): {peak_mib:.0f} MiB",
    ]
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "scale.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
