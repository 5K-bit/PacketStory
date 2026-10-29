# Security Policy

## Intended use

PacketStory reads capture files you are **entitled to analyse**: traffic from networks you own or have written permission to monitor. It only reads the file you name. It makes no network connections, does no reverse DNS lookups and sends nothing anywhere.

## What PacketStory protects, and what it does not

- **A capture is private data.** It holds addresses, names, and often content. PacketStory prints a few fields (addresses, ports, DNS names, TLS server names, HTTP method, host and path, user agent) and the *scheme* of an `Authorization` header, never the credential. Reports can still reveal who talked to whom; treat them like the capture.
- **Capture files are hostile input.** Every length is checked against what remains, loops and DNS compression pointers are bounded, decompression is not involved, files over 256 MiB are refused, and a damaged packet is counted and skipped rather than crashing the analysis. A 400-case mutation test feeds corrupted captures through every report format.
- **Reports are escaped.** Names from the capture are escaped for Markdown and HTML; JSON is serialised by the standard library.
- **Notes are heuristics.** "Worth a look" comes from simple rules (many unanswered or refused connection attempts, failed DNS lookups, credentials in cleartext HTTP). They can be wrong in both directions. A quiet report is not a clean bill of health.
- **It does not decrypt anything.** For TLS it reads the server name in the ClientHello, nothing more.

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Reporting a vulnerability

If you find a way to make a crafted capture crash or stall PacketStory, exhaust its memory, inject markup into a report, or make it print a credential, please report it privately through GitHub's **Security → Report a vulnerability** on this repository rather than a public issue.

Include the PacketStory version (`packetstory --version`), your OS and Python version, and the smallest capture that reproduces it. Use synthetic data only; never attach real traffic. Expect an initial response within a few days.
