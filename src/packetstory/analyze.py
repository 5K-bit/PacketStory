"""One call from capture bytes to a finished analysis."""

from __future__ import annotations

from dataclasses import dataclass

from .capture import open_capture
from .decode import decode
from .flows import Analysis, build
from .story import Event, Narrator


@dataclass
class Report:
    name: str
    format: str
    analysis: Analysis
    events: list[Event]
    warnings: list[str]


def analyze(data: bytes, name: str) -> Report:
    cap = open_capture(data)
    analysis = build(decode(raw) for raw in cap.packets())
    events = Narrator(analysis).events()
    return Report(name, cap.format, analysis, events, cap.warnings)
