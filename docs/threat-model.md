# Threat model

PacketStory opens files that someone else's traffic produced, so the file is the attacker.

## Assets

The analyst's machine, the privacy of the captured traffic, and the trustworthiness of the story.

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Crafted capture crashes or hangs the tool | All lengths checked against what remains; loops (IPv6 extension headers, DNS pointers, VLAN tags) bounded; limits on packets (5 M), packet size (256 KiB) and file size (256 MiB); a 400-case mutation test | A very large, valid capture still needs memory in proportion to its conversations |
| Compression bombs | None accepted: pcap and pcapng are not compressed, and a gzip file is refused with a message | None known |
| Markup or script injected through names, paths or the file name | Markdown escaping, HTML escaping, JSON from the standard library; tested with hostile names | A viewer with its own bugs |
| Credentials leak into reports | Only the scheme of `Authorization` is kept, never the value; tested | Credentials in other places (URLs, bodies) are not read, so they are not printed, but they remain in the capture |
| Analyst is misled by a heuristic | Thresholds are named, wording says "possible", findings are separated from the plain narrative, every sentence cites packets | A skilled sender can look innocent or look like a scan; a quiet report is not proof of anything |
| Spoofed or forged traffic in the capture | Not addressed. PacketStory describes what the packets say, not who really sent them | Treat the story as what the capture claims |
| Private data in the report | Reports contain addresses, names and paths from the capture | Handle reports like the capture |

## Out of scope

Decryption, reassembly of fragmented IP or out-of-order TCP streams, validating checksums, live capture, and attributing traffic to people.
