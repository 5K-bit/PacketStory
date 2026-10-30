# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- Reports no longer print HTTP query strings, fragments, `;param` segments or URL credentials; a dropped query shows as `?…`. The README no longer claims a report can never contain sensitive data, and says paths and names are printed as seen.
- A DNS response with no captured query is now described as a response from the server ("the query was not captured") instead of the server having "asked" the client. Roles come from message direction.
- TCP endings now say only what was seen: "FIN observed from both sides", "FIN observed from the client only" or "no closing packets observed", instead of "closed normally" and "still open".

## [0.1.0] - 2026-10-29

First working version.

### Added

- Readers for classic pcap (both byte orders, microsecond and nanosecond) and pcapng (section, interface and packet blocks, timestamp resolution); damaged tails end the read with a warning.
- Decoding of Ethernet (with VLAN tags), Linux cooked, raw IP and loopback links; IPv4, IPv6 (extension headers, fragments flagged), ARP, TCP, UDP, ICMP and ICMPv6.
- Light readers for DNS (with compression-pointer and length bounds), plain HTTP/1.x requests and responses, and the TLS ClientHello server name. Credentials are never kept.
- Conversations with TCP state (handshake, refused, unanswered, reset, mid-connection capture) and names learned from DNS answers in the same capture.
- A timeline in plain words where every line cites its packets, plus "worth a look" notes for possible port scans, repeated failed DNS lookups and credentials sent over cleartext HTTP.
- `packetstory summary`, `flows` and `story` (`--format md|html|json`, `--out`, `--max-events`, `--strict`). Exit codes: 0 ok, 1 error, 2 damaged capture with `--strict`.
