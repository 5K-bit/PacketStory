# Evidence

Recorded on 2026-10-29 in the project's Linux test environment (Python 3.13).

- `test-run.txt`: the full test run with coverage.
- `acceptance-transcript.txt`, `story.md`, `story.html`, `story.json`: `examples/acceptance.py` run on the synthetic lab capture. A test regenerates all four and fails if any differs from the recorded file.
- `scale.txt`: `examples/scale.py`, a synthetic 180,000-packet capture. One machine, one run, not a benchmark.

The capture itself, `examples/lab/lab.pcap`, is built by `examples/lab_builder.py` from documentation-range addresses; a test checks the checked-in file equals what the builder produces. Nothing was captured from a real network.

What this does not show: real-world captures from other tools, very large files, checksums or reassembly (not implemented), Windows, or CI. GitHub Actions had not been run when this was written.
