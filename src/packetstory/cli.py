"""Command-line interface. Thin: parsing and printing only."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyze import Report, analyze
from .capture import MAX_CAPTURE_BYTES
from .errors import PacketStoryError
from .render import stamp, to_html, to_json, to_markdown
from .story import PORT_NAMES, duration_text, size_text

EXIT_OK, EXIT_ERROR, EXIT_DAMAGED = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="packetstory", description="Turn a packet capture into a story. By OBEOS."
    )
    p.add_argument("--version", action="version", version=f"packetstory {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("story", help="the timeline, in plain words, with packet citations")
    s.add_argument("capture")
    s.add_argument("--format", choices=("md", "html", "json"), default="md")
    s.add_argument("--out", help="write to a file instead of standard output")
    s.add_argument("--max-events", type=int, default=200)
    s.add_argument("--strict", action="store_true", help="exit 2 if any packet could not be read")

    s = sub.add_parser("summary", help="a short overview: size, protocols, busiest hosts")
    s.add_argument("capture")

    s = sub.add_parser("flows", help="one line per conversation")
    s.add_argument("capture")
    s.add_argument("--limit", type=int, default=100)
    return p


def load(path: str) -> Report:
    target = Path(path)
    try:
        size = target.stat().st_size
    except OSError as exc:
        raise PacketStoryError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if size > MAX_CAPTURE_BYTES:
        raise PacketStoryError(f"{path} is larger than {MAX_CAPTURE_BYTES // 2**20} MiB")
    try:
        data = target.read_bytes()
    except OSError as exc:
        raise PacketStoryError(f"cannot read {path}: {exc.strerror or exc}") from exc
    return analyze(data, target.name)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except PacketStoryError as exc:
        print(f"packetstory: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


def _run(args: argparse.Namespace) -> int:
    report = load(args.capture)
    if args.command == "story":
        render = {"md": to_markdown, "html": to_html}.get(args.format)
        text = render(report, max_events=args.max_events) if render else to_json(report)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8", newline="\n")
            print(f"Wrote {args.out}")
        else:
            sys.stdout.write(text)
        damaged = report.analysis.malformed or report.warnings
        return EXIT_DAMAGED if args.strict and damaged else EXIT_OK
    if args.command == "summary":
        _summary(report)
    else:
        _flows(report, args.limit)
    return EXIT_OK


def _summary(r: Report) -> None:
    a = r.analysis
    span = duration_text(max(0, a.last_ts - a.first_ts))
    print(f"{r.name}: {r.format}, {a.packets} packets over {span}")
    print(f"first {stamp(a.first_ts)}  last {stamp(a.last_ts)}")
    print("protocols: " + (", ".join(f"{k} {v}" for k, v in sorted(a.protocols.items())) or "none"))
    print(f"conversations: {len(a.flows)}  hosts: {len(a.hosts)}  events: {len(r.events)} "
          f"({sum(e.notable for e in r.events)} worth a look)")  # fmt: skip
    for addr, s in sorted(a.hosts.items(), key=lambda kv: (-kv[1].bytes, kv[0]))[:5]:
        print(f"  {addr:<40} {s.packets:>7} packets  {size_text(s.bytes):>10}")
    if a.malformed:
        print(f"unreadable packets: {a.malformed}")
    for line in r.warnings:
        print(f"warning: {line}")


def _flows(r: Report, limit: int) -> None:
    for f in r.analysis.flows[:limit]:
        svc = PORT_NAMES.get(f.server[1], "")
        state = (
            "refused" if f.refused else "no-answer" if f.unanswered
            else "midstream" if f.midstream else "ok" if f.proto != "tcp" or f.established
            else "incomplete"
        )  # fmt: skip
        print(
            f"#{f.id:<4} {f.proto:<6} {f.client[0]}:{f.client[1]} -> {f.server[0]}:{f.server[1]} "
            f"{svc:<8} {state:<10} out {size_text(f.bytes_out):>9} in {size_text(f.bytes_in):>9} "
            f"pkts {f.first_pkt}-{f.last_pkt}"
        )
    if len(r.analysis.flows) > limit:
        print(f"... {len(r.analysis.flows) - limit} more (raise --limit)")
