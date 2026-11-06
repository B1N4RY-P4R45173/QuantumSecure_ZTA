"""Why decryption happens at all.

A Gateway that only forwards ciphertext can enforce reachability and nothing
more: it sees a source address, a destination port and an opaque stream. The
SPA knock and the session table already answer "may this host reach this
port"; neither can answer "and is what it is sending an attack on the
resource behind me". That second question needs the plaintext, which is the
entire justification for terminating TLS here and re-forwarding. The
decryption buys inspection - so if nothing inspects, the decryption is pure
added risk and the MITM should not exist.

This module is therefore the part that pays for the terminate-inspect-forward
design, and the rules in it are deliberately few. A real WAF carries
thousands of signatures, a tuning process and a false-positive budget;
imitating one with a handful of regexes would be worse than having nothing,
because it would invite trust the rules cannot carry. What is here is the
subset that is cheap, unambiguous on this data path, and defensible in three
families:

  structure  A request the Gateway cannot parse exactly one way must not be
             re-forwarded. Disagreement between the two legs about where one
             request ends IS request smuggling, and it is introduced by
             proxies that guess.
  size       The resource behind this Gateway serves one small JSON endpoint.
             A request line or header block far past what any real client
             sends is a probe or a memory-pressure attempt, and buffering it
             to find out is itself the damage.
  content    Markers in the request target with no benign reading here:
             traversal above the document root, SQL control syntax, and
             HTML/JS injection.

Scope, stated plainly so nobody over-reads a verdict:

  * Only the request HEAD is inspected, and the content rules look only at
    the request target. Scanning every header value and every body byte at
    this altitude is where false positives live, and a Gateway that blocks
    real traffic gets switched off.
  * Every rule blocks. There is no "warn" tier, because a verdict nobody
    acts on is noise in a log file.
  * A clean verdict means "none of these rules fired" - never "safe".
  * Who may reach what is policy (the session ACL), not inspection. This
    module never reads the Authorization header.

Finding details carry an excerpt of whatever matched, for the audit log only.
Never echo one back to the client: that turns a blocked injection into a
reflected one.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field

# Terminator of an HTTP head. Exported so the connection reader and the rules
# agree on where a head ends instead of each deciding for itself.
END_OF_HEAD = b"\r\n\r\n"

# Limits. Generous next to a real request to this resource (a GET carrying a
# bearer token is well under 2 KiB) and far below anything that costs the
# Gateway memory.
MAX_REQUEST_LINE_BYTES = 8192
MAX_HEADER_BLOCK_BYTES = 16384
MAX_HEADER_COUNT = 64
MAX_BODY_BYTES = 65536
# What the connection reader may buffer while looking for the blank line. A
# head that does not fit is reported as incomplete rather than parsed.
MAX_HEAD_BYTES = MAX_REQUEST_LINE_BYTES + MAX_HEADER_BLOCK_BYTES

# Origin-form targets only. HTTP/2 and /3 never arrive: the proxy negotiates
# http/1.1 over ALPN.
_HTTP_VERSIONS = ("HTTP/1.0", "HTTP/1.1")

# What a request target may never contain. A NUL truncates C-side parsers,
# CR/LF splits a response or forges a log line, and a bare control character
# has no legitimate place in a URI at all (RFC 3986: it must be
# percent-encoded).
_TARGET_CONTROL = re.compile("[\x00-\x1f\x7f]")

# -- content rules ---------------------------------------------------------- #
# One regex per rule, each narrow enough to say out loud what it means. The
# price of a loose rule is a blocked real client, so none of these fire on a
# keyword in isolation: every one needs the syntax around it.

_TRAVERSAL_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # A dot-dot path segment, not the two characters: "/api/v1..2" is fine,
    # "/api/../../etc/passwd" is not.
    ("path-traversal", re.compile(r"(?:^|[/\\])\.\.(?:[/\\]|$)")),
)

_SQLI_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # ' OR '1'='1 - a quote closing the server's own literal, then a
    # comparison that is always true.
    ("sqli-quoted-tautology",
     re.compile(r"['\"]\s*(?:or|and)\s+['\"]?[\w%]+['\"]?\s*(?:=|like)\s*['\"]?[\w%]+", re.I)),
    # OR 1=1 - the unquoted form, pinned with a back-reference so that
    # "or 1=2", which is not a tautology, does not match.
    ("sqli-numeric-tautology", re.compile(r"\b(?:or|and)\s+(\d{1,4})\s*=\s*\1\b", re.I)),
    # UNION SELECT - appending a second result set, the standard way to read
    # a table the endpoint never meant to expose.
    ("sqli-union", re.compile(r"\bunion\b(?:\s+all)?\s+\bselect\b", re.I)),
    # ; DROP TABLE - a stacked statement. A URL has no reason to carry one.
    ("sqli-stacked-statement",
     re.compile(r";\s*(?:drop|delete|truncate|insert|update|alter)\s+\w", re.I)),
)

_XSS_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # An opening tag for an element that executes or fetches. The "<" is
    # required, so a path segment merely named "script" is untouched.
    ("xss-tag", re.compile(r"<\s*/?\s*(?:script|iframe|svg|img|object|embed|body)\b", re.I)),
    # onerror= / onload= - an inline event handler being smuggled into an
    # attribute position.
    ("xss-event-handler",
     re.compile(r"\bon(?:error|load|click|focus|mouseover|animationstart)\s*=", re.I)),
    # javascript: / vbscript: in a URI the resource might reflect into an
    # href. Deliberately narrower than a "data:" rule, which collides with
    # real paths.
    ("xss-script-scheme", re.compile(r"\b(?:javascript|vbscript)\s*:", re.I)),
)

_CONTENT_RULES = _TRAVERSAL_RULES + _SQLI_RULES + _XSS_RULES

_EXCERPT_LIMIT = 48


def _printable(text: str, limit: int = _EXCERPT_LIMIT) -> str:
    """Escape and truncate text that came off the wire.

    Everything in a Finding detail was written by whoever opened the
    connection, and it ends up in a log line an operator reads. Escaping it
    at the source means no consumer has to remember to.
    """
    clipped = text[:limit] + ("..." if len(text) > limit else "")
    return clipped.encode("unicode_escape").decode("ascii")


@dataclass(frozen=True)
class Finding:
    """One rule that fired, and the evidence for it."""

    rule: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.rule}[{self.detail}]" if self.detail else self.rule


@dataclass(frozen=True)
class Verdict:
    """The result of inspecting one request head.

    Carries the parsed head as well as the decision, so the router can
    re-forward from the same parse the rules were applied to. Re-parsing
    downstream is exactly how a proxy ends up forwarding something other than
    what it inspected.
    """

    allowed: bool
    findings: tuple[Finding, ...] = ()
    method: str = ""
    target: str = ""
    version: str = ""
    headers: tuple[tuple[str, str], ...] = field(default=())
    content_length: int = 0

    @property
    def rules(self) -> tuple[str, ...]:
        """Just the rule names - the only part safe to put in a response."""
        return tuple(f.rule for f in self.findings)

    @property
    def reason(self) -> str:
        """Rules with their evidence, for the audit log only."""
        return "; ".join(str(f) for f in self.findings)

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for header_name, value in self.headers:
            if header_name.lower() == wanted:
                return value
        return None


def inspect(head: bytes) -> Verdict:
    """Inspect one decrypted HTTP request head.

    `head` is everything the client sent up to and including the blank line.
    Nothing raises: a head too mangled to parse comes back as a blocking
    verdict, because an exception here would be indistinguishable from a
    Gateway fault and would cost the audit log its record.
    """
    findings: list[Finding] = []

    block, separator, _ = head.partition(END_OF_HEAD)
    if not separator:
        # Either the client never finished its headers (slowloris) or the head
        # ran past MAX_HEAD_BYTES. Both are refusals and neither can be parsed
        # safely, so it is recorded before anything is read out of it.
        findings.append(Finding("head-incomplete", f"{len(head)}B, no blank line"))

    lines = block.split(b"\r\n")
    raw_request_line = lines[0] if lines else b""
    raw_headers = [line for line in lines[1:] if line]

    _check_size(raw_request_line, raw_headers, findings)
    method, target, version = _parse_request_line(raw_request_line, findings)
    headers = _parse_headers(raw_headers, findings)
    content_length = _body_length(headers, findings)
    _scan_target(target, findings)

    return Verdict(
        allowed=not findings,
        findings=tuple(findings),
        method=method,
        target=target,
        version=version,
        headers=headers,
        content_length=content_length,
    )


# -- the three families ----------------------------------------------------- #


def _check_size(request_line: bytes, header_lines: list[bytes],
                findings: list[Finding]) -> None:
    if len(request_line) > MAX_REQUEST_LINE_BYTES:
        findings.append(Finding("request-line-too-long",
                                f"{len(request_line)}B > {MAX_REQUEST_LINE_BYTES}B"))
    # +2 per line for the CRLF the split removed: the cap is on what the
    # Gateway had to hold, not on what survived parsing.
    header_bytes = sum(len(line) + 2 for line in header_lines)
    if header_bytes > MAX_HEADER_BLOCK_BYTES:
        findings.append(Finding("headers-too-large",
                                f"{header_bytes}B > {MAX_HEADER_BLOCK_BYTES}B"))
    if len(header_lines) > MAX_HEADER_COUNT:
        findings.append(Finding("too-many-headers",
                                f"{len(header_lines)} > {MAX_HEADER_COUNT}"))


def _parse_request_line(raw: bytes, findings: list[Finding]) -> tuple[str, str, str]:
    """Split "GET /api/data HTTP/1.1" into its three fields.

    latin-1 because an HTTP head is bytes with no declared charset; it is the
    one codec that round-trips every byte, so a hostile head is reported
    rather than raising UnicodeDecodeError on the way in.
    """
    line = raw.decode("latin-1")
    parts = line.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    version = parts[2] if len(parts) > 2 else ""

    if len(parts) != 3 or not version:
        findings.append(Finding("request-line-malformed",
                                f"{len(parts)} fields: {_printable(line)}"))
        return method, target, version
    if version not in _HTTP_VERSIONS:
        findings.append(Finding("request-line-malformed", f"version {_printable(version)}"))
    if not target.startswith("/"):
        # Origin-form only. An absolute-form target ("GET http://host/x") is a
        # forward-proxy request, and this Gateway is the origin as far as the
        # client is concerned - honouring one would make it an open relay.
        findings.append(Finding("request-line-malformed",
                                f"non origin-form target {_printable(target)}"))
    if _TARGET_CONTROL.search(target):
        findings.append(Finding("request-target-control-char", _printable(target)))
    return method, target, version


def _parse_headers(raw_headers: list[bytes],
                   findings: list[Finding]) -> tuple[tuple[str, str], ...]:
    headers: list[tuple[str, str]] = []
    for raw in raw_headers:
        line = raw.decode("latin-1")
        if line[:1] in (" ", "\t"):
            # Obsolete line folding, deprecated by RFC 7230. Two parsers
            # unfold it differently, which is a smuggling primitive.
            findings.append(Finding("header-malformed",
                                    f"folded continuation {_printable(line)}"))
            continue
        name, separator, value = line.partition(":")
        if not separator or not name or name.strip() != name:
            findings.append(Finding("header-malformed", _printable(line)))
            continue
        headers.append((name, value.strip()))
    return tuple(headers)


def _body_length(headers: tuple[tuple[str, str], ...],
                 findings: list[Finding]) -> int:
    """How many body bytes follow, or 0. Ambiguity here is always a refusal.

    Both refusals below are the classic smuggling setups: a chunked body this
    proxy would re-forward without having parsed it, and two Content-Lengths
    for the two legs to disagree over.
    """
    lengths = [value for name, value in headers if name.lower() == "content-length"]
    encodings = [value for name, value in headers if name.lower() == "transfer-encoding"]

    if encodings:
        # Refused rather than implemented: a proxy that re-forwards a chunked
        # body it has not de-chunked is the textbook TE.CL vector, and this
        # data path has no use for streaming uploads.
        findings.append(Finding("transfer-encoding-unsupported",
                                _printable(",".join(encodings))))
    if not lengths:
        return 0
    if len(set(lengths)) > 1:
        findings.append(Finding("content-length-ambiguous", _printable(",".join(lengths))))
        return 0
    try:
        length = int(lengths[0])
    except ValueError:
        findings.append(Finding("content-length-ambiguous", _printable(lengths[0])))
        return 0
    if length < 0:
        findings.append(Finding("content-length-ambiguous", str(length)))
        return 0
    if length > MAX_BODY_BYTES:
        findings.append(Finding("body-too-large", f"{length}B > {MAX_BODY_BYTES}B"))
        return 0
    return length


def _scan_target(target: str, findings: list[Finding]) -> None:
    """Run the content rules over the request target.

    Each rule sees the raw target and its percent-decoded forms. Raw alone
    misses "%2e%2e%2f"; one decode alone misses "%252e%252e" aimed at a
    resource that decodes twice. Two passes is where it stops - a third buys
    nothing real and costs false positives.
    """
    if not target:
        return
    candidates = [target]
    decoded = target
    for _ in range(2):
        decoded = urllib.parse.unquote(decoded, errors="replace")
        if decoded not in candidates:
            candidates.append(decoded)

    for rule, pattern in _CONTENT_RULES:
        for candidate in candidates:
            match = pattern.search(candidate)
            if match is not None:
                findings.append(Finding(rule, _printable(match.group(0))))
                break  # one finding per rule: the detail is evidence, not a tally
