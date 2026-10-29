from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples"))

import lab_builder as lab  # noqa: E402


@pytest.fixture(scope="session")
def lab_frames() -> list[lab.Frame]:
    return lab.build_lab()


@pytest.fixture(scope="session")
def lab_bytes() -> bytes:
    return lab.lab_pcap()
