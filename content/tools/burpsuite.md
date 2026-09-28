---
title: "Tool - Burp Suite"
category: web
subcategory: proxy
type: tool
tags: [burpsuite, burp, proxy, intercept, repeater, intruder, decoder, comparer, turbo-intruder, extensions, bapp, certificate, scope, match-and-replace, web]
summary: "The intercepting HTTP proxy: see, modify and replay every request; Repeater and Intruder are where most web CTF work happens."
related: [web-triage, ffuf, sqlmap, jwt-tool]
---

## What it is

Burp Suite sits between your browser and the target, letting you inspect and modify every HTTP request and response. The Community Edition is free and includes everything a CTF needs: Proxy, Repeater, Intruder (rate-limited), Decoder, Comparer, and the extension ecosystem. Professional adds the scanner and an unthrottled Intruder.

## Install

```sh
# Debian/Kali
sudo apt install burpsuite
# macOS
brew install --cask burp-suite
# Otherwise: download the Community Edition installer from the official PortSwigger site.
# It is a Java application; a bundled JRE ships with the installer.
```

Browser setup (one of):
- Use Burp's **built-in Chromium**: Proxy -> Intercept -> Open Browser. No certificate work needed. Easiest.
- Or point your browser at `127.0.0.1:8080` and install the CA: visit `http://burp` -> "CA Certificate" -> import into the browser as a trusted authority.
- For CLI tools: `curl -x http://127.0.0.1:8080 -k https://target`, `ffuf -x http://127.0.0.1:8080`, `sqlmap --proxy=http://127.0.0.1:8080`.

## The invocations that matter

These are workflows, not commands.

1. **Set the scope first.** Target -> Scope -> add the challenge host. Then in Proxy -> Options tick "and URL is in target scope" for logging, and in the HTTP history filter tick "Show only in-scope items". Without this the history is unusable noise.

2. **Browse the whole application by hand** with the proxy on. Every feature. The site map (Target tab) becomes your endpoint inventory.

3. **Repeater is the main tool.** Right-click any request -> Send to Repeater (`Ctrl+R`), then edit and `Ctrl+Space`/`Ctrl+Enter` to send. Keep one tab per idea. Rename the tabs.

4. **Intruder for anything repetitive.** Send to Intruder (`Ctrl+I`), clear the auto-markers with the Clear button, select the value to vary, then press Add to wrap it in payload markers. Attack types:
   - **Sniper**: one payload set, one position at a time.
   - **Battering ram**: the same payload in every position.
   - **Pitchfork**: parallel payload sets, index-matched.
   - **Cluster bomb**: every combination - use for user x password.

5. **Decoder** (`Ctrl+Shift+D` style workflow): paste any blob, then Decode as URL/HTML/Base64/ASCII hex/Gzip. Chain them. Smart Decode guesses.

6. **Comparer**: send two responses, diff them by words or bytes. This is how you spot a one-character difference in a blind injection oracle.

7. **Match and Replace** (Proxy -> Options -> Match and Replace): auto-rewrite a header on every request, e.g. always add `X-Forwarded-For: 127.0.0.1`, or replace a stale CSRF token.

8. **Save and reuse a raw request**: right-click -> Copy to file, then `sqlmap -r request.txt` or `ffuf -request request.txt`.

9. **Extensions** (Extender -> BApp Store), the ones that earn their place in CTF:
   - **Turbo Intruder** - scriptable, extremely fast; the tool for race conditions (single-packet attack).
   - **HTTP Request Smuggler** - automated smuggling detection.
   - **Param Miner** - finds unkeyed headers and hidden parameters (cache poisoning).
   - **JSON Web Tokens / JWT Editor** - decode, edit, re-sign, and test `alg:none` / key confusion.
   - **Autorize** - replays every request with a second user's session to find IDOR/authz gaps.
   - **Logger++** - a searchable log across all tools.
   - **Hackvertor** - inline encoding/encryption tags inside requests.
   - **Collaborator Everywhere** (Pro) - injects OOB payloads automatically.

10. **Turbo Intruder for races** - the pattern for limit-overrun bugs:
```python
# Turbo Intruder script: send 30 identical requests in one TCP burst
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=1,
                           pipeline=False)
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Keyboard shortcuts worth memorising: `Ctrl+R` send to Repeater, `Ctrl+I` send to Intruder, `Ctrl+Shift+U` URL-decode selection, `Ctrl+Shift+B` base64-decode selection, `Ctrl+U` URL-encode selection, `Ctrl+Enter` send request in Repeater, `Ctrl+F` search in the message editor.

## Gotchas

- **Community Edition throttles Intruder** to roughly one request per second. For brute forcing use `ffuf`, `hydra` or Turbo Intruder (which is not throttled) instead.
- Burp's browser and your system browser have separate cookie jars. Pick one and stay in it.
- Intercept-on blocks every request including from other tools; leave it off and work from HTTP history unless you specifically need to edit in flight.
- `Content-Length` is auto-corrected by Repeater by default. For request smuggling, turn that off (Repeater -> Options -> Update Content-Length).
- If a request body changed but the app rejects it, check for a CSRF token, an HMAC over the body, or a `Content-Length` mismatch.
- Burp is a Java app and will eat several GB of RAM on a large site map. Keep the scope tight and clear history between challenges.
- Project files: use a temporary project for CTF (Community cannot save projects anyway).
- HTTP/2: Burp speaks it, but some parser-differential tests require forcing HTTP/1.1 (Repeater -> Options -> HTTP/1).
- Upstream proxy chains (Burp -> another proxy) are configured under User options -> Connections, not per-project.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You prefer open source / scripting | **mitmproxy** (`mitmproxy`, `mitmdump`, Python addons) |
| Free and Java-free | **Caido** (modern, freemium), **ZAP** (fully free, OWASP) |
| Pure CLI replay | `curl` with `-H`, `--data-raw`, `-b`, `-x` |
| High-volume fuzzing | `ffuf`, `feroxbuster`, `wfuzz` |
| Race conditions | Turbo Intruder, or a Python script with `threading.Barrier` |
| Automated SQLi | `sqlmap -r request.txt` |
| Traffic from a mobile app | mitmproxy + the device's proxy settings, or Frida for pinning bypass |
