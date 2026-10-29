# 3. Findings are heuristics with named thresholds, and say so

**Status:** accepted

**Context.** "Port scan" and "suspicious DNS" are judgements. A tool that states them as fact trains people to trust it too much, or to ignore it after the first false alarm.

**Decision.** Each finding is a named rule with constants at the top of `story.py` (`SCAN_MIN_TARGETS`, `SCAN_MIN_FAIL_RATIO`, `NXDOMAIN_MIN_NAMES`). The wording says "possible" or states a fact without a motive. Each rule is tested on both sides of its threshold, and notable lines are listed separately from the narrative.

**Consequences.** The rules are easy to argue with and tune. There are few of them, deliberately.
