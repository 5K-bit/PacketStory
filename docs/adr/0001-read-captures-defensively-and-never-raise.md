# 1. Read captures defensively; damaged input is data, not an exception

**Status:** accepted

**Context.** Captures come from the network. They are truncated by full disks, written by buggy tools and, sometimes, crafted. One bad packet should not hide the other 100,000.

**Decision.** Readers check every length against what remains and stop with a warning on a damaged tail. The decoder returns a record flagged `malformed` or `unsupported` instead of raising. The report counts both. `--strict` converts them into exit code 2.

**Consequences.** Analysis always finishes on a readable file. The cost is that callers must look at the counts to know whether the story is complete, which is why *Capture quality* is part of every report.
