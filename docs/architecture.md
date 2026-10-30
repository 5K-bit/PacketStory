# Architecture

PacketStory is a pipeline with no state between runs. Each stage can only make the next one's input smaller or safer.

```
 file ─► capture ─► decode ─► flows ─► story ─► render
        pcap/pcapng  L2–L4    conversations  events    Markdown
        raw packets  + malformed  + app fields  + citations HTML · JSON
                     / unsupported
```

| Module | Responsibility |
|---|---|
| `capture.py` | Read pcap and pcapng into `RawPacket`s (number, time, link type, bytes). Bounds every length; warns instead of raising on a damaged tail. |
| `decode.py` | Link, network and transport headers into one flat `Decoded` record. Never raises: a bad packet is returned with `malformed` or `unsupported` set. |
| `appproto.py` | DNS, HTTP/1.x and TLS ClientHello readers. Return `None` unless sure. Keep only named fields; never a credential value, query string or URL password. |
| `flows.py` | Group packets into conversations keyed by protocol and the two endpoints; track TCP state; learn names from DNS answers. |
| `story.py` | `Narrator` turns conversations into `Event`s: one plain sentence, the packet range it rests on, and whether it is notable. Heuristic thresholds are named constants. |
| `render.py` | Markdown, HTML and JSON. Text from the capture is escaped. |
| `analyze.py`, `cli.py` | Glue and printing. |

## Design points

- **Citations.** Every event carries the first and last packet number it rests on, numbered as Wireshark numbers them, so any sentence can be checked in a packet viewer.
- **Direction.** The client is whoever sent the first SYN (or the destination of a first SYN-ACK). A capture that starts mid-connection says so rather than guessing.
- **Names.** Addresses are labelled with names only when the same capture contains a DNS answer for them. There are no lookups.
- **Failure is data.** Malformed, unsupported and truncated input is counted and shown under *Capture quality*; `--strict` turns it into an exit code.

## Adding a protocol

1. Write a reader in `appproto.py` that returns a small frozen dataclass or `None`, checks every offset, and keeps no secrets.
2. Call it from `flows.py` where the transport payload is available and store the result on `Flow`.
3. Describe it in `story.py` with one sentence per conversation. Add a notable finding only with a named threshold and wording that calls it a heuristic.
4. Add tests for well-formed, truncated and hostile input, and extend the lab in `examples/lab_builder.py` if the story should show it.

## Exit codes

`0` ok · `1` error (unreadable file, not a capture) · `2` the capture had damaged or undecodable parts and `--strict` was given.
