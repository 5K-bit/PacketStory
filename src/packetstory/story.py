"""Turn an analysis into events: a timeline in plain words, with the packets that back each line."""

from __future__ import annotations

from dataclasses import dataclass

from .appproto import DnsMessage
from .flows import Analysis, Flow

PORT_NAMES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    80: "http", 110: "pop3", 123: "ntp", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 8080: "http-alt", 8443: "https-alt",
}  # fmt: skip

# Heuristic thresholds. They are deliberately conservative and named, so they can be argued with.
SCAN_MIN_TARGETS = 10  # distinct (host, port) targets tried by one client
SCAN_MIN_FAIL_RATIO = 0.7  # share of those that got no answer or a reset
NXDOMAIN_MIN_NAMES = 5  # distinct names failing to resolve for one client


@dataclass(frozen=True)
class Event:
    ts_ns: int
    first_pkt: int
    last_pkt: int
    kind: str
    text: str
    notable: bool = False


def duration_text(ns: int) -> str:
    if ns < 1_000_000:
        return "under a millisecond"
    if ns < 1_000_000_000:
        return f"{ns // 1_000_000} ms"
    seconds = ns / 1e9
    if seconds < 120:
        return f"{seconds:.1f} s"
    return f"{seconds / 60:.1f} min"


def size_text(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KiB"
    return f"{n / 1024**2:.1f} MiB"


class Narrator:
    def __init__(self, analysis: Analysis) -> None:
        self.a = analysis

    def host(self, addr: str) -> str:
        name = self.a.names.get(addr)
        return f"{name} ({addr})" if name else addr

    def service(self, port: int, proto: str = "tcp") -> str:
        name = PORT_NAMES.get(port)
        return f"{port}/{proto}" + (f" ({name})" if name else "")

    def events(self) -> list[Event]:
        out: list[Event] = []
        consumed: set[int] = set()
        out.extend(self._scans(consumed))
        out.extend(self._dns())
        out.extend(self._failed_connections(consumed))
        for flow in self.a.flows:
            if flow.id in consumed or flow.proto == "tcp" and (flow.refused or flow.unanswered):
                continue
            if flow.proto == "tcp":
                out.append(self._tcp(flow))
                out.extend(self._cleartext_auth(flow))
            elif flow.proto == "udp" and 53 not in (flow.server[1], flow.client[1]):
                out.append(self._udp(flow))
            elif flow.proto in ("icmp", "icmpv6"):
                out.append(self._icmp(flow))
        return sorted(out, key=lambda e: (e.ts_ns, e.first_pkt, e.kind))

    # -- TCP ------------------------------------------------------------------------------
    def _tcp(self, flow: Flow) -> Event:
        who, where = self.host(flow.client[0]), self.host(flow.server[0])
        port = self.service(flow.server[1])
        detail = ""
        if flow.sni:
            detail = f", TLS to {flow.sni}"
        elif flow.http:
            req = flow.http[0]
            status = f" → {flow.http_status[0]}" if flow.http_status else ""
            detail = f", {req.method} {req.host}{req.path}{status}"
        if flow.midstream:
            lead = f"{who} and {where} port {port}: the capture began mid-connection{detail}"
        elif flow.established:
            lead = f"{who} connected to {where} port {port}{detail}"
        else:
            lead = f"{who} started a connection to {where} port {port} that never completed"
        end = (
            f"reset by the {flow.rst_by}" if flow.rst_by
            else "closed normally" if flow.fin
            else "still open when the capture ended"
        )  # fmt: skip
        text = (
            f"{lead}; {size_text(flow.bytes_out)} sent, {size_text(flow.bytes_in)} received over "
            f"{duration_text(flow.last_ts - flow.first_ts)}; {end}."
        )
        return Event(flow.first_ts, flow.first_pkt, flow.last_pkt, "tcp", text)

    def _cleartext_auth(self, flow: Flow) -> list[Event]:
        seen: set[str] = set()
        events = []
        for req in flow.http:
            if req.auth_scheme and req.auth_scheme not in seen:
                seen.add(req.auth_scheme)
                events.append(
                    Event(
                        flow.first_ts,
                        flow.first_pkt,
                        flow.last_pkt,
                        "cleartext-auth",
                        f"{self.host(flow.client[0])} sent an HTTP request to "
                        f"{req.host or self.host(flow.server[0])} with an Authorization header "
                        f"({req.auth_scheme}) over an unencrypted connection. The value is not "
                        "shown here.",
                        notable=True,
                    )  # fmt: skip
                )
        return events

    def _failed_connections(self, consumed: set[int]) -> list[Event]:
        groups: dict[tuple[str, str, str], list[Flow]] = {}
        for f in self.a.flows:
            if f.id in consumed or f.proto != "tcp" or not (f.refused or f.unanswered):
                continue
            kind = "refused" if f.refused else "unanswered"
            groups.setdefault((f.client[0], f.server[0], kind), []).append(f)
        events = []
        for (client, server, kind), flows in groups.items():
            ports = sorted({f.server[1] for f in flows})
            shown = ", ".join(f"{p}{_nm(p)}" for p in ports[:8])
            more = f" and {len(ports) - 8} more" if len(ports) > 8 else ""
            how = (
                "was refused (the host answered with a reset)" if kind == "refused"
                else "got no answer"
            )  # fmt: skip
            noun = "port" if len(ports) == 1 else "ports"
            plural = "connection attempt" if len(flows) == 1 else "connection attempts"
            text = (
                f"{self.host(client)} made {len(flows)} {plural} to {self.host(server)} "
                f"on {noun} {shown}{more}; each {how}."
            )
            events.append(Event(
                min(f.first_ts for f in flows), min(f.first_pkt for f in flows),
                max(f.last_pkt for f in flows), f"tcp-{kind}", text,
            ))  # fmt: skip
        return events

    def _scans(self, consumed: set[int]) -> list[Event]:
        by_client: dict[str, list[Flow]] = {}
        for f in self.a.flows:
            if f.proto == "tcp" and f.syn:
                by_client.setdefault(f.client[0], []).append(f)
        events = []
        for client, flows in by_client.items():
            targets = {f.server for f in flows}
            failed = [f for f in flows if f.refused or f.unanswered]
            failed_targets = {f.server for f in failed}
            if len(targets) < SCAN_MIN_TARGETS:
                continue
            if len(failed_targets) / len(targets) < SCAN_MIN_FAIL_RATIO:
                continue
            answered = sorted({f.server[1] for f in flows if f.synack})
            hosts = {t[0] for t in targets}
            consumed.update(f.id for f in failed)
            consumed.update(f.id for f in flows if f.synack and not f.established)  # half-open
            span = max(f.last_ts for f in flows) - min(f.first_ts for f in flows)
            open_text = (
                f" Ports that answered: {', '.join(str(p) for p in answered[:10])}."
                if answered
                else " No port answered."
            )
            text = (
                f"Possible port scan: {self.host(client)} tried {len(targets)} ports on "
                f"{len(hosts)} host(s) within {duration_text(span)}; {len(failed_targets)} got no "
                f"answer or were refused.{open_text} (A heuristic: it looks like a scan, it does "
                "not prove intent.)"
            )
            events.append(Event(
                min(f.first_ts for f in flows), min(f.first_pkt for f in flows),
                max(f.last_pkt for f in flows), "scan", text, notable=True,
            ))  # fmt: skip
        return events

    # -- UDP, ICMP ------------------------------------------------------------------------
    def _udp(self, flow: Flow) -> Event:
        who, where = self.host(flow.client[0]), self.host(flow.server[0])
        port = self.service(flow.server[1], "udp")
        reply = f", and got {flow.pkts_in} back" if flow.pkts_in else ", with no reply seen"
        text = (
            f"{who} sent {flow.pkts_out} UDP packet(s) ({size_text(flow.bytes_out)}) to {where} "
            f"port {port}{reply}."
        )
        return Event(flow.first_ts, flow.first_pkt, flow.last_pkt, "udp", text)

    def _icmp(self, flow: Flow) -> Event:
        who, where = self.host(flow.client[0]), self.host(flow.server[0])
        t = flow.icmp_types
        echo_req = t.get(8, 0) + t.get(128, 0)
        echo_rep = t.get(0, 0) + t.get(129, 0)
        other = {k: v for k, v in t.items() if k not in (0, 8, 128, 129)}
        if echo_req or echo_rep:
            text = (
                f"{who} pinged {where}: {echo_req} request(s), {echo_rep} reply(ies)."
                if echo_req
                else f"{where} sent {echo_rep} ping reply(ies) to {who}."
            )
        else:
            kinds = ", ".join(f"type {k} ×{v}" for k, v in sorted(other.items()))
            text = f"ICMP between {who} and {where}: {kinds}."
        return Event(flow.first_ts, flow.first_pkt, flow.last_pkt, "icmp", text)

    # -- DNS ------------------------------------------------------------------------------
    def _dns(self) -> list[Event]:
        events: list[Event] = []
        failures: dict[str, dict[str, tuple[int, int]]] = {}
        for flow in self.a.flows:
            if flow.proto != "udp" or not flow.dns:
                continue
            who, resolver = self.host(flow.client[0]), self.host(flow.server[0])
            pending: dict[int, tuple[int, int, DnsMessage]] = {}
            for number, ts, msg in flow.dns:
                if not msg.is_response:
                    pending[msg.ident] = (number, ts, msg)
                    continue
                q_pkt, q_ts, _ = pending.pop(msg.ident, (number, ts, msg))
                name, qtype = msg.questions[0] if msg.questions else ("?", "?")
                if msg.rcode == "NOERROR":
                    result = "got " + (
                        ", ".join(v for _n, _t, v in msg.answers[:4]) or "no records"
                    )
                elif msg.rcode == "NXDOMAIN":
                    result = "got NXDOMAIN (no such name)"
                    failures.setdefault(flow.client[0], {})[name] = (q_pkt, number)
                else:
                    result = f"got {msg.rcode}"
                text = f"{who} asked {resolver} for {name} ({qtype}) and {result}."
                events.append(Event(q_ts, q_pkt, number, "dns", text))
            for number, ts, msg in pending.values():
                name, qtype = msg.questions[0] if msg.questions else ("?", "?")
                text = f"{who} asked {resolver} for {name} ({qtype}); no reply was seen."
                events.append(Event(ts, number, number, "dns", text))
        for client, names in failures.items():
            if len(names) < NXDOMAIN_MIN_NAMES:
                continue
            shown = ", ".join(sorted(names)[:3])
            first = min(v[0] for v in names.values())
            last = max(v[1] for v in names.values())
            first_ts = min(e.ts_ns for e in events if e.first_pkt == first)
            events.append(
                Event(
                    first_ts, first, last, "dns-failures",
                    f"{self.host(client)} had {len(names)} different names fail to resolve "
                    f"(for example {shown}). Misconfiguration and malware both cause this; "
                    "the capture alone cannot say which.",
                    notable=True,
                )
            )  # fmt: skip
        return events


def _nm(port: int) -> str:
    name = PORT_NAMES.get(port)
    return f" ({name})" if name else ""
