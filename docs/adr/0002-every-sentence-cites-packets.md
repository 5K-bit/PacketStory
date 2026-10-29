# 2. Every sentence cites the packets it rests on

**Status:** accepted

**Context.** A story generated from packets is only useful if it can be checked. Analysts will open the capture in a packet viewer to confirm anything surprising.

**Decision.** Each event records the first and last packet number it was built from, numbered from 1 in file order, and the renderers show it.

**Consequences.** Summaries can be verified in seconds. Events that merge many packets (a scan, a DNS failure run) show a range rather than a list.
