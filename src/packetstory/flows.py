"""Group decoded packets into conversations (flows) and keep what a story needs."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .appproto import DnsMessage, HttpMessage, parse_dns, parse_http, parse_tls_sni
from .decode import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Decoded

Endpoint = tuple[str, int]
FlowKey = tuple[str, Endpoint, Endpoint]


@dataclass
class Flow:
    id: int
    proto: str
    client: Endpoint
    server: Endpoint
    first_ts: int
    last_ts: int
    first_pkt: int
    last_pkt: int
    midstream: bool = False
    pkts_out: int = 0  # client to server
    pkts_in: int = 0
    bytes_out: int = 0  # payload bytes
    bytes_in: int = 0
    syn: bool = False
    synack: bool = False
    established: bool = False
    fin: bool = False
    fin_client: bool = False
    fin_server: bool = False
    rst_by: str = ""  # "client" or "server"
    sni: str = ""
    http: list[HttpMessage] = field(default_factory=list)
    http_status: list[int] = field(default_factory=list)
    dns: list[tuple[int, int, DnsMessage]] = field(default_factory=list)  # (packet, ts, message)
    icmp_types: dict[int, int] = field(default_factory=dict)

    @property
    def closed(self) -> bool:
        return self.fin or bool(self.rst_by)

    @property
    def refused(self) -> bool:
        return self.proto == "tcp" and self.syn and not self.synack and self.rst_by == "server"

    @property
    def unanswered(self) -> bool:
        return self.proto == "tcp" and self.syn and not self.synack and not self.rst_by


@dataclass
class HostStats:
    packets: int = 0
    bytes: int = 0


@dataclass
class Analysis:
    flows: list[Flow]
    hosts: dict[str, HostStats]
    names: dict[str, str]  # address -> name learned from DNS answers in this capture
    protocols: dict[str, int]
    packets: int = 0
    first_ts: int = 0
    last_ts: int = 0
    malformed: int = 0
    unsupported: dict[str, int] = field(default_factory=dict)
    fragments: int = 0
    arp: int = 0


def build(decoded: Iterable[Decoded]) -> Analysis:
    flows: list[Flow] = []
    live: dict[FlowKey, Flow] = {}
    hosts: dict[str, HostStats] = {}
    names: dict[str, str] = {}
    protocols: dict[str, int] = {}
    out = Analysis(flows, hosts, names, protocols)
    for pkt in decoded:
        out.packets += 1
        out.first_ts = pkt.ts_ns if out.packets == 1 else min(out.first_ts, pkt.ts_ns)
        out.last_ts = max(out.last_ts, pkt.ts_ns)
        if pkt.malformed:
            out.malformed += 1
            continue
        if pkt.unsupported:
            out.unsupported[pkt.unsupported] = out.unsupported.get(pkt.unsupported, 0) + 1
            continue
        protocols[pkt.proto] = protocols.get(pkt.proto, 0) + 1
        for addr in (pkt.src,):
            stats = hosts.setdefault(addr, HostStats())
            stats.packets += 1
            stats.bytes += pkt.frame_len
        if pkt.fragment:
            out.fragments += 1
        if pkt.proto == "arp":
            out.arp += 1
            continue
        if pkt.proto in ("tcp", "udp", "icmp", "icmpv6"):
            _add(pkt, flows, live, names)
    return out


def _key(pkt: Decoded) -> FlowKey:
    a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
    if pkt.proto in ("icmp", "icmpv6"):
        a, b = (pkt.src, 0), (pkt.dst, 0)
    return (pkt.proto, min(a, b), max(a, b))


def _add(pkt: Decoded, flows: list[Flow], live: dict[FlowKey, Flow], names: dict[str, str]) -> None:
    key = _key(pkt)
    flow = live.get(key)
    plain_syn = pkt.proto == "tcp" and pkt.flags & TCP_SYN and not pkt.flags & TCP_ACK
    if flow is None or (plain_syn and flow.closed):
        src: Endpoint = (pkt.src, pkt.sport if pkt.proto in ("tcp", "udp") else 0)
        dst: Endpoint = (pkt.dst, pkt.dport if pkt.proto in ("tcp", "udp") else 0)
        synack = pkt.proto == "tcp" and pkt.flags & TCP_SYN and pkt.flags & TCP_ACK
        client, server = (dst, src) if synack or _dns_response_first(pkt) else (src, dst)
        midstream = pkt.proto == "tcp" and not (plain_syn or synack)
        flow = Flow(len(flows) + 1, pkt.proto, client, server, pkt.ts_ns, pkt.ts_ns, pkt.number,
                    pkt.number, midstream=midstream)  # fmt: skip
        flows.append(flow)
        live[key] = flow
    flow.last_ts = max(flow.last_ts, pkt.ts_ns)
    flow.last_pkt = pkt.number
    from_client = (pkt.src, pkt.sport if pkt.proto in ("tcp", "udp") else 0) == flow.client
    size = len(pkt.payload)
    if from_client:
        flow.pkts_out += 1
        flow.bytes_out += size
    else:
        flow.pkts_in += 1
        flow.bytes_in += size
    if pkt.proto == "tcp":
        _tcp_state(flow, pkt, from_client)
        if pkt.payload:
            _tcp_payload(flow, pkt, from_client)
    elif pkt.proto == "udp":
        if 53 in (pkt.sport, pkt.dport) and pkt.payload:
            msg = parse_dns(pkt.payload)
            if msg is not None:
                flow.dns.append((pkt.number, pkt.ts_ns, msg))
                if msg.is_response:
                    for _name, rtype, value in msg.answers:
                        if rtype in ("A", "AAAA"):
                            names.setdefault(value, _name)
    else:
        flow.icmp_types[pkt.icmp_type] = flow.icmp_types.get(pkt.icmp_type, 0) + 1


def _dns_response_first(pkt: Decoded) -> bool:
    """True when a UDP packet is a DNS response, so its sender is the server, not the client."""
    if pkt.proto != "udp" or 53 not in (pkt.sport, pkt.dport) or not pkt.payload:
        return False
    msg = parse_dns(pkt.payload)
    return msg is not None and msg.is_response


def _tcp_state(flow: Flow, pkt: Decoded, from_client: bool) -> None:
    f = pkt.flags
    if f & TCP_SYN and not f & TCP_ACK and from_client:
        flow.syn = True
    elif f & TCP_SYN and f & TCP_ACK and not from_client:
        flow.synack = True
    elif f & TCP_ACK and from_client and flow.syn and flow.synack:
        flow.established = True
    if flow.midstream and f & TCP_ACK and not f & TCP_SYN:
        flow.established = True
    if f & TCP_FIN:
        flow.fin = True
        if from_client:
            flow.fin_client = True
        else:
            flow.fin_server = True
    if f & TCP_RST and not flow.rst_by:
        flow.rst_by = "client" if from_client else "server"


def _tcp_payload(flow: Flow, pkt: Decoded, from_client: bool) -> None:
    if from_client:
        if not flow.sni and (sni := parse_tls_sni(pkt.payload)):
            flow.sni = sni
        elif len(flow.http) < 20 and (msg := parse_http(pkt.payload)) and msg.is_request:
            flow.http.append(msg)
    elif len(flow.http_status) < 20 and (msg := parse_http(pkt.payload)) and not msg.is_request:
        flow.http_status.append(msg.status)
