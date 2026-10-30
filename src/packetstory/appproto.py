"""Small, defensive parsers for DNS, plain HTTP/1.x and the TLS ClientHello's server name.

Each parser returns ``None`` for anything it cannot read with confidence. None of them
keeps payload beyond the few fields named below. None keeps a credential's value, a query
string or a URL password.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_MAX_NAME = 255
_MAX_JUMPS = 16


@dataclass(frozen=True)
class DnsMessage:
    ident: int
    is_response: bool
    rcode: str
    questions: tuple[tuple[str, str], ...]  # (name, type)
    answers: tuple[tuple[str, str, str], ...]  # (name, type, value) for A, AAAA and CNAME


def _read_name(msg: bytes, pos: int) -> tuple[str, int] | None:
    labels: list[str] = []
    jumps, end, total = 0, -1, 0
    while True:
        if pos >= len(msg):
            return None
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                return None
            if end < 0:
                end = pos + 2
            jumps += 1
            if jumps > _MAX_JUMPS:
                return None
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            continue
        if length & 0xC0 or pos + 1 + length > len(msg):
            return None
        total += length + 1
        if total > _MAX_NAME:
            return None
        labels.append(msg[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    return (".".join(labels) or "."), (end if end >= 0 else pos)


def parse_dns(payload: bytes) -> DnsMessage | None:
    if len(payload) < 12:
        return None
    ident, flags, qd, an = struct.unpack("!HHHH", payload[:8])
    if flags & 0x7800 or qd > 16 or an > 64:  # only standard queries; sane counts
        return None
    pos, questions = 12, []
    for _ in range(qd):
        parsed = _read_name(payload, pos)
        if parsed is None or parsed[1] + 4 > len(payload):
            return None
        name, pos = parsed
        qtype = struct.unpack("!H", payload[pos : pos + 2])[0]
        questions.append((name, DNS_TYPES.get(qtype, f"TYPE{qtype}")))
        pos += 4
    answers: list[tuple[str, str, str]] = []
    for _ in range(an):
        parsed = _read_name(payload, pos)
        if parsed is None or parsed[1] + 10 > len(payload):
            break
        name, pos = parsed
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[pos : pos + 10])
        pos += 10
        rdata = payload[pos : pos + rdlen]
        if len(rdata) < rdlen:
            break
        value = ""
        if rtype == 1 and rdlen == 4:
            value = str(ipaddress.IPv4Address(rdata))
        elif rtype == 28 and rdlen == 16:
            value = str(ipaddress.IPv6Address(rdata))
        elif rtype == 5:
            target = _read_name(payload, pos)
            value = target[0] if target else ""
        if value:
            answers.append((name, DNS_TYPES.get(rtype, f"TYPE{rtype}"), value))
        pos += rdlen
    return DnsMessage(
        ident, bool(flags & 0x8000), RCODES.get(flags & 0xF, f"RCODE{flags & 0xF}"),
        tuple(questions), tuple(answers),
    )  # fmt: skip


@dataclass(frozen=True)
class HttpMessage:
    is_request: bool
    method: str = ""
    path: str = ""
    status: int = 0
    host: str = ""
    auth_scheme: str = ""  # "Basic", "Bearer", ... — never the credential itself
    user_agent: str = ""
    query_omitted: bool = False  # the request target had a query string or fragment; not kept


_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def _safe_target(target: str) -> tuple[str, str, bool]:
    """Split a request target into (authority host, path, query_omitted).

    Query strings and fragments are dropped because they often carry tokens. For an
    absolute-form target (``http://user:pw@host/p``) the scheme and any ``user:pw@`` are dropped
    too. The path itself is kept and can still be sensitive; the docs say so.
    """
    authority = ""
    if target.lower().startswith(("http://", "https://")):
        rest = target.split("://", 1)[1]
        end = min((i for i in (rest.find(c) for c in "/?#") if i >= 0), default=len(rest))
        authority, target = rest[:end], rest[end:] or "/"
        authority = authority.rsplit("@", 1)[-1]
    cut = min((i for i in (target.find(c) for c in "?#") if i >= 0), default=-1)
    omitted = cut >= 0
    if omitted:
        target = target[:cut]
    # Path parameters such as ``;jsessionid=...`` are session tokens by convention.
    if ";" in target:
        target = "/".join(seg.split(";", 1)[0] for seg in target.split("/"))
        omitted = True
    return authority, target or "/", omitted


def parse_http(payload: bytes) -> HttpMessage | None:
    head = payload[:8192]
    first, _, rest = head.partition(b"\r\n")
    if first.startswith(b"HTTP/1.") and len(first) >= 12 and first[9:12].isdigit():
        return HttpMessage(False, status=int(first[9:12]))
    if not first.startswith(_METHODS) or b" HTTP/1." not in first:
        return None
    method, _, tail = first.partition(b" ")
    target = tail.rsplit(b" HTTP/", 1)[0].decode("ascii", "replace")
    url_host, path, query_omitted = _safe_target(target)
    host = scheme = agent = ""
    for line in rest.split(b"\r\n"):
        if not line:
            break
        name, _, value = line.partition(b":")
        key = name.strip().lower()
        if key == b"host":
            host = value.strip().decode("ascii", "replace")[:255]
        elif key == b"authorization":
            scheme = value.strip().split(b" ", 1)[0].decode("ascii", "replace")[:32]
        elif key == b"user-agent":
            agent = value.strip().decode("ascii", "replace")[:120]
    return HttpMessage(
        True, method=method.decode("ascii", "replace"), path=path[:200],
        host=(host or url_host).rsplit("@", 1)[-1][:255], auth_scheme=scheme, user_agent=agent,
        query_omitted=query_omitted,
    )  # fmt: skip


def parse_tls_sni(payload: bytes) -> str | None:
    """The server name from a TLS ClientHello, or None. Bounds-checked at every step."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[1] != 3 or payload[5] != 1:
            return None
        record_end = min(len(payload), 5 + struct.unpack("!H", payload[3:5])[0])
        pos = 5 + 4 + 2 + 32  # handshake header, version, random
        pos += 1 + payload[pos]  # session id
        pos += 2 + struct.unpack("!H", payload[pos : pos + 2])[0]  # cipher suites
        pos += 1 + payload[pos]  # compression methods
        ext_end = pos + 2 + struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 2
        ext_end = min(ext_end, record_end)
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[pos : pos + 4])
            pos += 4
            if etype == 0 and elen >= 5:
                nlen = struct.unpack("!H", payload[pos + 3 : pos + 5])[0]
                name = payload[pos + 5 : pos + 5 + nlen]
                if len(name) == nlen and 0 < nlen <= _MAX_NAME:
                    return name.decode("ascii", "replace")
                return None
            pos += elen
    except (struct.error, IndexError):
        return None
    return None
