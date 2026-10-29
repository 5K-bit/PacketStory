# 4. No network access, not even DNS

**Status:** accepted

**Context.** Resolving addresses in a capture would tell whoever runs the resolver which hosts the analyst is looking at.

**Decision.** PacketStory opens the named file and nothing else. Names appear only when the capture itself contains a DNS answer for the address.

**Consequences.** Some addresses stay bare. That is honest: the capture does not say what they are called.
