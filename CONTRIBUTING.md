# Contributing

Thanks for your interest in PacketStory.

## Ways to help

- Report captures that are misread (send a **synthetic or heavily sanitised** reproduction: link type, writing tool, protocols involved).
- Add a protocol reader (see [docs/architecture.md](docs/architecture.md#adding-a-protocol)) or a carefully worded finding.
- Improve the report wording and docs.

## Development

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
python -m pytest --cov                            # must pass before you open a PR
python examples/acceptance.py --out /tmp/evidence # the lab story end to end
```

## Guidelines

- The core uses only the Python standard library.
- No network calls, including DNS. PacketStory reads a file and writes a report.
- Treat every capture as hostile: check each length against what remains, bound each loop, never trust a count field.
- Never keep or print a credential. Record only that one was present.
- A finding needs a named threshold, wording that says it is a heuristic, and tests on both sides of its threshold.
- Changing report text on purpose? Regenerate the golden files with `UPDATE_GOLDEN=1 python -m pytest tests/unit/test_render_fuzz.py` and the evidence with `python examples/acceptance.py --out docs/evidence`, and review the diff.
- Test captures must be synthetic: build them with `examples/lab_builder.py` using the documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.test` / `.invalid` names. Never commit a real capture.
- Do not add claims (performance, platform support, security) that a test or recorded evidence does not back up.
- Use clear commit messages and keep pull requests focused.
