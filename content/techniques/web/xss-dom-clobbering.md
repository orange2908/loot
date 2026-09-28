---
title: "DOM XSS - Sources, Sinks, postMessage and DOM Clobbering"
category: web
subcategory: xss
type: technique
tags: [dom-xss, xss, dom-clobbering, postmessage, message-event, location-hash, innerhtml, outerhtml, document-write, eval, settimeout, insertadjacenthtml, srcdoc, named-access, htmlcollection, taint-analysis, source-sink, dom-invader, burp, window-name]
difficulty: medium
summary: "The server never sees it: the flaw is a path from an attacker-controlled DOM source to a sink, or a global the markup can redefine."
when_to_use:
  - "The payload never appears in the HTTP response but still executes"
  - "The page reads `location.hash`, `window.name`, or listens for `message` events"
  - "Client-side code checks a global (`window.config`, `window.CONFIG.url`) before using it"
  - "You need to trace which line of JavaScript turned your input into markup"
related: [xss-contexts, xss-sanitizer-bypass, xss-csp-bypass, proto-pollution]
tools: [burp, dom-invader]
---

## TL;DR

DOM XSS is a dataflow bug inside the page. Attacker-controlled input enters at a **source** (something the
DOM exposes that you influence), travels through JavaScript, and reaches a **sink** (something that parses
strings as markup or code). DOM clobbering is the same bug from the other end: instead of supplying a value
to existing code, you inject markup that **creates a global** the code reads, so a variable the developer
assumed was theirs comes from your HTML.

## Recognise it

- The payload does not appear in the raw HTTP response, but it executes. Fetch the page with `curl` and grep -
  absence there plus execution in the browser is the signature.
- The URL fragment is never sent to the server, so anything driven by `location.hash` is DOM-only by
  construction.
- `window.addEventListener('message', ...)` in the page source, especially without an `event.origin` check.
- Code of the shape `var x = window.SOMETHING || 'default'` - a clobberable global with a fallback.
- Single-page apps that route on `location.hash` or `history.pushState` and render from it.
- Sinks in a bundled file: search the JS for `innerHTML`, `document.write`, `eval`, `new Function`.

## Theory

### Sources and sinks

A **source** is any DOM value an attacker can influence:

| Source | Controlled by |
|--------|---------------|
| `location.href` / `.search` / `.hash` / `.pathname` | the URL you get the victim to visit |
| `document.referrer` | the page you navigate from |
| `window.name` | a window you opened, persisting across navigations |
| `document.cookie` | a cookie you can set (including from a sibling subdomain) |
| `event.data` on a `message` listener | any page that can get a handle to the window |
| `localStorage` / `sessionStorage` | a previous same-origin injection |
| `document.baseURI` | a `<base>` element, which clobbering can inject |

A **sink** is anything that turns a string into markup or code:

| Sink | Parses as |
|------|-----------|
| `innerHTML`, `outerHTML`, `insertAdjacentHTML` | HTML |
| `document.write` / `writeln` | HTML, into the parser |
| `eval`, `new Function`, `setTimeout`/`setInterval` with a string | JavaScript |
| `element.src` / `href` / `action` / `formaction` | a URL, so `javascript:` |
| `iframe.srcdoc` | a whole HTML document |
| jQuery `$(x)`, `.html()`, `.append()` | HTML if the string starts with `<` |
| `element.setAttribute('on...', x)` | an event handler |
| `Range.createContextualFragment` | HTML |

`innerHTML` deserves one clarification that saves a lot of wasted effort: HTML inserted with `innerHTML`
**does not execute `<script>` elements**. The parser creates the element but the "already started" flag
prevents execution. So the working primitives there are event handlers on elements that fire without
interaction - `<img src=x onerror=...>`, `<svg onload=...>`, `<iframe srcdoc=...>` - not a script tag.

### postMessage handlers

`postMessage` crosses origins by design, so the receiving handler is responsible for deciding whether to
trust the sender. The failures are all variations on not doing that:

- **No origin check at all.** Any page that holds a reference to the window (via `window.open`, or by
  framing it) can send it data.
- **A substring check.** `if (event.origin.indexOf('example.com') !== -1)` passes for
  `example.com.attacker.net` and for `notexample.com`.
- **A `startsWith` check without the separator.** `origin.startsWith('https://example.com')` passes for
  `https://example.com.attacker.net`.
- **Checking `event.source` instead of `event.origin`** - identity of the window, not of the origin.
- **The sending side leaking.** `postMessage(secret, '*')` delivers to whatever origin currently occupies
  that frame, which an attacker can change by navigating it.

The correct check is a strict equality against a full origin: `if (event.origin !== 'https://example.com') return;`

A handler is reachable if you can get a window reference: open the target with `window.open`, or embed it in
an iframe if `X-Frame-Options`/`frame-ancestors` permits. That framing question is often the real gate.

### DOM clobbering

Two legacy HTML behaviours combine into the primitive:

1. **Named access on `window`.** An element with an `id` (or, for some elements, a `name`) becomes a property
   of `window` and of `document`. `<a id=config>` makes `window.config` refer to that element.
2. **`HTMLCollection` named traversal.** Two elements sharing an `id` produce a collection, and a `name` on a
   member is reachable as a property of it. `<a id=x><a id=x name=y>` makes `window.x.y` resolve to the second
   anchor.

That gives you one-level and two-level property paths built purely from HTML, with no script at all. Which
matters because it works **under a CSP that blocks all script execution** - you are not running code, you are
changing what existing code reads.

The values you can produce are DOM elements, not strings, which is the main constraint. Two things narrow the
gap:

- **Anchor stringification.** An `<a>` element's `toString()` returns its `href`. So
  `<a id=cfg href="https://attacker.example/x">` makes `window.cfg` stringify to that URL wherever the code
  does string concatenation or passes it somewhere that coerces.
- **`document.cookie`, `document.domain`, `document.forms`** and similar `document` properties can be
  shadowed by a form or an element with the matching name, which is how checks like `if (document.cookie)`
  get subverted.

The classic vulnerable shape is the defaulting pattern:

```js
var url = window.CONFIG && window.CONFIG.endpoint || '/default';
```

Inject `<a id=CONFIG><a id=CONFIG name=endpoint href="javascript:...">` and the "default" is yours. Any
sanitiser that permits `id` and `name` attributes on anchors - which many do, since they look harmless -
leaves this open.

### Tracing a sink back

The efficient order, roughly fastest-first:

1. **Grep the bundle** for the sink list above. In a minified bundle, search for `.innerHTML` and
   `document.write` specifically; they survive minification as property names.
2. **Break on DOM changes.** In DevTools, right-click the element that ends up containing your payload ->
   Break on -> subtree modifications. The debugger stops on the line that wrote it, with the call stack
   showing the path back to the source.
3. **Set a logpoint on the handler.** For `message` flows, `addEventListener('message', e => console.log(e.origin, e.data))`
   from the console tells you the shape the page expects.
4. **Use DOM Invader.** Burp's browser instruments the sinks directly and reports the source-to-sink path,
   which collapses steps 1-3 for the common cases. It also has a dedicated DOM-clobbering scan.
5. **Check `window` for surprises.** `Object.keys(window).filter(k => document.getElementById(k))` shows
   which globals are actually elements - a quick clobbering check on any page.

## Attack

1. Establish the flow is client-side: fetch with `curl`, confirm the payload is absent from the response.
2. Identify the source. Fragment? `message`? `window.name`? Each has a different delivery.
3. Find the sink by breaking on the DOM mutation rather than reading minified code.
4. Determine what transformation sits between them - a `JSON.parse`, a regex, a prefix check. That constrains
   the payload more than the sink does.
5. Choose a primitive that fires without interaction if the flow goes through `innerHTML`, remembering that a
   `<script>` element inserted this way will not run.
6. For clobbering, find a global the code reads and an injection point that permits `id`/`name`.

## Code

An offline source-to-sink scanner for a JavaScript snippet, plus a clobbering-shape detector. It is a static
reasoning aid - the same triage you would do by eye on a bundle, made explicit and testable.

```python
#!/usr/bin/env python3
"""Flag DOM-XSS source/sink pairs and clobberable globals in a JS snippet.

A deliberately simple lexical scanner: it reports lines containing sources,
lines containing sinks, weak postMessage origin checks, and the
`window.X && window.X.y || default` shape that DOM clobbering targets.

Static analysis over text. No browser, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

SOURCES = {
    "location.hash": "URL fragment - never sent to the server, so this flow is DOM-only",
    "location.search": "query string",
    "location.href": "whole URL",
    "location.pathname": "path",
    "document.referrer": "the page navigated from",
    "window.name": "persists across navigations in a window you opened",
    "document.cookie": "settable from a sibling subdomain",
    "event.data": "postMessage payload - check the origin guard",
    "localStorage": "requires a prior same-origin write",
    "sessionStorage": "requires a prior same-origin write",
    "document.baseURI": "influenced by an injected <base> element",
}

SINKS = {
    "innerHTML": "parses HTML; <script> will NOT run, event handlers will",
    "outerHTML": "parses HTML",
    "insertAdjacentHTML": "parses HTML",
    "document.write": "parses HTML into the document parser",
    "document.writeln": "parses HTML into the document parser",
    "eval": "parses JavaScript",
    "new Function": "parses JavaScript",
    "setTimeout": "parses JavaScript when passed a string",
    "setInterval": "parses JavaScript when passed a string",
    "srcdoc": "a whole HTML document",
    "createContextualFragment": "parses HTML",
    ".html(": "jQuery - parses HTML",
    ".append(": "jQuery - parses HTML when the string starts with '<'",
}

WEAK_ORIGIN_CHECKS = [
    (re.compile(r"origin\.indexOf\("), "substring match - 'example.com.attacker.net' passes"),
    (re.compile(r"origin\.startsWith\("), "prefix match - 'example.com.attacker.net' passes"),
    (re.compile(r"origin\.match\("), "regex match - anchor it, or it matches anywhere"),
    (re.compile(r"origin\.includes\("), "substring match - same problem as indexOf"),
    (re.compile(r"event\.source\s*==="), "checks window identity, not origin"),
]

STRICT_ORIGIN = re.compile(r"origin\s*!==?\s*['\"]https?://[^'\"]+['\"]")
# window.X && window.X.y || 'default'  - the clobbering-friendly defaulting shape
CLOBBER_SHAPE = re.compile(r"window\.(\w+)\s*(?:&&\s*window\.\1\.(\w+)\s*)?\|\|")


@dataclass
class Issue:
    line_no: int
    kind: str
    detail: str
    text: str

    def __str__(self) -> str:
        return f"  L{self.line_no:<3} [{self.kind:<12}] {self.detail}\n        {self.text.strip()[:90]}"


def scan(js: str) -> list[Issue]:
    issues: list[Issue] = []
    lines = js.splitlines()
    has_listener = "addEventListener('message'" in js or 'addEventListener("message"' in js
    has_strict = bool(STRICT_ORIGIN.search(js))

    for n, line in enumerate(lines, 1):
        for name, why in SOURCES.items():
            if name in line:
                issues.append(Issue(n, "source", f"{name}: {why}", line))
        for name, why in SINKS.items():
            if name in line:
                issues.append(Issue(n, "sink", f"{name}: {why}", line))
        for pattern, why in WEAK_ORIGIN_CHECKS:
            if pattern.search(line):
                issues.append(Issue(n, "weak-origin", why, line))
        match = CLOBBER_SHAPE.search(line)
        if match:
            path = f"window.{match.group(1)}"
            if match.group(2):
                path += f".{match.group(2)}"
                shape = f'<a id={match.group(1)}><a id={match.group(1)} name={match.group(2)} href="...">'
            else:
                shape = f'<a id={match.group(1)} href="...">'
            issues.append(Issue(n, "clobberable", f"{path} defaults with || - inject {shape}", line))

    if has_listener and not has_strict:
        issues.append(Issue(0, "no-origin", "message listener with no strict origin equality check", ""))
    return issues


def summarise(issues: list[Issue]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for issue in issues:
        counts[issue.kind] = counts.get(issue.kind, 0) + 1
    return counts


VULNERABLE = """
window.addEventListener('message', function (event) {
  if (event.origin.indexOf('example.com') !== -1) {
    document.getElementById('out').innerHTML = event.data.html;
  }
});
var target = window.CONFIG && window.CONFIG.endpoint || '/api/default';
var page = location.hash.slice(1);
document.write('<h1>' + page + '</h1>');
"""

FIXED = """
window.addEventListener('message', function (event) {
  if (event.origin !== 'https://example.com') return;
  document.getElementById('out').textContent = event.data.html;
});
var target = '/api/default';
var page = location.hash.slice(1);
document.getElementById('h').textContent = page;
"""


if __name__ == "__main__":
    print("== vulnerable snippet ==")
    bad = scan(VULNERABLE)
    for issue in bad:
        print(issue)
    counts = summarise(bad)
    print(f"\n  {counts}")

    assert counts.get("source", 0) >= 2, "location.hash and event.data are both sources"
    assert counts.get("sink", 0) >= 2, "innerHTML and document.write are both sinks"
    assert counts.get("weak-origin", 0) == 1, "indexOf origin check should be flagged"
    assert counts.get("no-origin", 0) == 1, "no strict equality anywhere in the snippet"
    assert counts.get("clobberable", 0) == 1, "the window.CONFIG.endpoint default is clobberable"

    clob = next(i for i in bad if i.kind == "clobberable")
    assert "id=CONFIG" in clob.detail and "name=endpoint" in clob.detail, \
        "two-level path needs the HTMLCollection shape"
    print(f"\n  suggested markup: {clob.detail.split('inject ')[1]}")

    print("\n== fixed snippet ==")
    good = scan(FIXED)
    for issue in good:
        print(issue)
    counts = summarise(good)
    print(f"\n  {counts}")

    assert counts.get("weak-origin", 0) == 0, "strict equality is not a weak check"
    assert counts.get("no-origin", 0) == 0, "strict origin check present"
    assert counts.get("clobberable", 0) == 0, "no defaulting global left"
    assert counts.get("sink", 0) == 0, "textContent is not a sink - it does not parse"
    # Sources remain, and that is correct: a source is only a problem if it reaches a sink.
    assert counts.get("source", 0) >= 1, "location.hash is still read, but now only into textContent"

    print("\nself-test ok")
```

## Variants & pitfalls

- **`<script>` does not run via `innerHTML`.** Use an element with an auto-firing event handler instead.
  Missing this wastes a lot of time.
- **A source is not a bug.** Reading `location.hash` into `textContent` is fine. Only a source that reaches a
  sink matters, which is why the scanner above reports both and leaves the join to you.
- **`textContent` versus `innerHTML`** is the whole difference between safe and not, on the same line.
- **Framing may be required.** A `message` handler you cannot reach because of `frame-ancestors` is not
  exploitable through an iframe; `window.open` may still work.
- **Clobbering yields elements, not strings.** Plan for coercion - anchors stringify to their `href`.
- **Clobbering works under a script-blocking CSP**, which is what makes it valuable where normal XSS is dead.
- **Sanitisers that allow `id` and `name`** leave clobbering open even when they correctly block script.
- **Single-page routers re-render.** A payload can be wiped by a re-render immediately after firing; check
  whether it executed rather than whether it is still in the DOM.
- **`document.domain` shadowing** is a legacy trick and largely moot in modern browsers, which have been
  deprecating `document.domain` outright.

### Defence / what closes this

Write to `textContent` rather than `innerHTML` when the value is text - that one substitution removes most of
this class. Where HTML genuinely must be rendered, run it through a maintained sanitiser (DOMPurify) and
configure it to strip `id` and `name` so clobbering is closed alongside script. Use Trusted Types
(`require-trusted-types-for 'script'` in CSP) to make the dangerous sinks refuse plain strings, which turns
every missed sink into a console error instead of an execution. In `message` handlers, compare `event.origin`
with strict equality to a full expected origin, and validate the message shape before using it; never send
sensitive data with a `'*'` target origin. Avoid the `window.X || default` pattern - read configuration from
a `<script type="application/json">` island parsed with `JSON.parse`, or from a module-scoped constant that
no markup can define. Set `frame-ancestors` so the page cannot be framed by an attacker.

## Tools

- Burp DOM Invader - instruments sources and sinks in-browser and reports the path; has a dedicated
  DOM-clobbering mode.
- Chrome DevTools "Break on subtree modifications" - the fastest way from a rendered payload to the guilty line.
- DOMPurify - both the defence and, reading its release notes, a good catalogue of what sanitisers must handle.
- `curl` plus grep - proves a flow is client-side in one command.

## References

- PortSwigger, DOM-based vulnerabilities: https://portswigger.net/web-security/dom-based
- PortSwigger, DOM clobbering: https://portswigger.net/web-security/dom-based/dom-clobbering
- PortSwigger, DOM Invader: https://portswigger.net/burp/documentation/desktop/tools/dom-invader
- OWASP DOM based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- MDN, `Window.postMessage()` security concerns: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage
- HTML Standard, named access on the Window object: https://html.spec.whatwg.org/multipage/nav-history-apis.html#named-access-on-the-window-object
- DOMPurify: https://github.com/cure53/DOMPurify
- W3C Trusted Types: https://w3c.github.io/trusted-types/dist/spec/
