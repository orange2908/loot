---
title: "XSS - Deriving the Escape from the Injection Context"
category: web
subcategory: xss
type: technique
tags: [xss, cross-site-scripting, reflected-xss, stored-xss, injection-context, html-parsing, attribute-context, javascript-string, template-literal, rawtext, tokenizer, html-encoding, javascript-uri, css-injection, innerhtml, context-aware-escaping, burp, dom-invader]
difficulty: easy
summary: "Find which parser state your reflection lands in, list the characters that terminate that state, test which survive - the payload follows mechanically."
when_to_use:
  - "Your input appears in the response but a generic payload does nothing"
  - "You need to work out why `<script>` is useless where your marker landed"
  - "The reflection is inside an attribute, a JS string, a template literal or a URL"
  - "You are deciding whether a given encoding is the right defence for a given sink"
tools: [burp, dom-invader, curl]
related: [xss-dom-clobbering, xss-csp-bypass, xss-sanitizer-bypass, xss-exfiltration-and-bots]
---

## TL;DR

There is no such thing as "an XSS payload". There is a **parser state** your input lands in, and a set of
characters that leave that state. Identify the state, enumerate its exits, test which exits survive the
filter, then build the shortest thing that works. Done this way, XSS is a two-minute derivation rather than
a payload-list lottery - and the same reasoning tells you exactly which encoding the defence should have used.

## Recognise it

- Your marker appears in the response body. Search for it in **view-source**, not the rendered page, because
  the rendered DOM has already resolved entities and hidden the context.
- A distinctive, filter-neutral marker makes this reliable: something like `zqxj1` rather than `test` or
  `<script>`, so you can find every reflection including ones inside JavaScript and comments.
- More than one reflection is common, and they are often in *different* contexts. Number them
  (`zqxj1`, `zqxj2`, ...) rather than assuming they behave alike.
- Reflections inside `<script>` blocks, `data-*` attributes, `href`/`src` values, and inline `style` are the
  four that most often get missed by a page-level glance.

## Theory

### The HTML tokeniser has states, and each has exits

The browser parses a document with a state machine. Your input sits in exactly one state, and only the
characters that transition *out* of that state matter. Everything else is inert text no matter how
threatening it looks.

| Context | Exits (the characters that matter) | What you build |
|---------|-----------------------------------|----------------|
| HTML text | `<` | a new element |
| Attribute value, double-quoted | `"` then whitespace | close the value, add an attribute |
| Attribute value, single-quoted | `'` then whitespace | same |
| Attribute value, unquoted | whitespace, `>` | add an attribute with **no quote needed** |
| Attribute *name* position | whitespace | you are already inside the tag |
| Inside `<script>` (script data) | none needed | it is already JavaScript |
| JS string literal | the matching quote, or `</script` | break the string, or break the element |
| JS template literal | `${ }` | expression substitution, no quote break required |
| HTML comment | `-->` | close the comment first |
| `<style>` / `style=` | CSS syntax | a CSS-level sink |
| URL-valued attribute | the scheme | `javascript:` - the value *is* the sink |

Three consequences worth stating explicitly, because they are where most time gets lost:

**Unquoted attribute values are the softest context in HTML.** No quote character is needed at all; a space
ends the value and begins a new attribute. A filter that blocks `"` and `'` and leaves the value unquoted
has achieved nothing.

**Inside `<script>`, `<` is not special.** Script data is not parsed as HTML, so injecting `<img>` there is
inert text inside JavaScript - a syntax error at best. Conversely the literal sequence `</script` ends the
element from *anywhere* inside it, including from inside a JavaScript string, which is why that one string is
the universal exit from script context.

**Template literals do not require breaking the quote.** `${...}` is evaluated inside a backtick string. If
your reflection is inside a template literal and the filter blocks quotes, the filter is looking at the wrong
character set entirely.

### Double decoding: the event-handler case

An event-handler attribute is decoded **twice**, by two different decoders in sequence:

1. The HTML parser decodes entities in the attribute value.
2. The JavaScript engine parses the result as code.

So `onclick="&#97;lert(1)"` runs `alert(1)`: the HTML decode turns `&#97;` into `a` before JavaScript ever
sees it. This is why HTML-encoding alone is not sufficient inside an event handler, and why a filter that
scans the raw attribute for the string `alert` can be sidestepped without any of the characters it blocks.

The general rule: **count the decoders between your input and the sink**. Each one is a layer you can encode
through, and each one is a place a check might have been performed on the wrong string. This is the same
normalisation-order reasoning as in `sqli-waf-bypass` and `lfi-path-traversal`.

### RCDATA contexts

`<textarea>` and `<title>` are RCDATA: entities are decoded but tags are not parsed. Inside them, `<` is
inert, and the only exit is the matching close tag (`</textarea`). A reflection there needs the close tag
first, and a sanitiser that fails to account for the state leaves a gap - see `xss-sanitizer-bypass`.

### URL context is its own thing

When the reflection is the whole value of `href`, `src`, `action` or `formaction`, you do not need to escape
anything - the value is already a sink. The question is only whether the scheme is controllable:

- `javascript:` executes on navigation (not in `src` of an `img`, which does not navigate).
- `data:text/html,...` executes in a navigated frame or window, subject to browser restrictions - modern
  browsers block top-level `data:` navigation.
- A protocol-relative or absolute URL gets you an open redirect rather than script execution.

HTML-encoding does nothing here, because `&#106;avascript:` still decodes to `javascript:`. The correct
defence is scheme allowlisting, not encoding - a good illustration that "escaping" is context-specific and
the wrong escape is no escape.

### The encoding that closes each context

This table is the defence side of the same analysis, and it is worth knowing in both directions:

| Context | Correct output encoding |
|---------|------------------------|
| HTML text | HTML entity-encode `< > &` |
| Attribute value | HTML entity-encode **and always quote** the attribute |
| JS string literal | JavaScript string escaping (`\xHH`), or better, `JSON.stringify` into a data island |
| URL attribute | scheme allowlist (`http`, `https`, relative), then URL-encode |
| CSS value | CSS escaping, and prefer not to interpolate at all |
| Event handler | do not interpolate; attach the handler in code instead |

## Attack

1. **Inject a unique, inert marker.** Not a payload - a marker. `zqxj1`.
2. **Find every occurrence in the raw response.** Grep the source, not the DOM.
3. **Classify the context of each.** Read backwards from the marker to the nearest unclosed tag, quote, or
   `<script>`.
4. **List the exits for that context** from the table above.
5. **Test each exit character individually**, still with no payload: send `zqxj1"` and look at the raw output.
   Is it present, entity-encoded, backslash-escaped, or removed? One character per request, so the answer is
   unambiguous.
6. **Build the minimum** using only the exits that survived. If none survive, the context is correctly
   encoded and you should go look at another reflection.
7. **Confirm execution**, not just injection - a payload that renders as an element but does not fire is a
   different problem (see `xss-csp-bypass`).

## Code

An offline context classifier. It implements enough of the HTML tokeniser to report which parser state a
marker landed in, and prints the exits for that state. The point is the state machine: the classification is
the technique, and the payload is a lookup afterwards.

```python
#!/usr/bin/env python3
"""Classify the parser context of a reflected marker in an HTML document.

Implements a simplified HTML tokeniser - enough to distinguish the contexts that
change which characters matter. Given a document and a marker, reports the state
each occurrence landed in and the characters that exit that state.

Offline; operates on strings only.
"""
from __future__ import annotations

from dataclasses import dataclass

RAWTEXT_TAGS = {"script", "style"}
RCDATA_TAGS = {"textarea", "title"}
URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "cite"}

EXITS = {
    "html-text":        ("<", "start a new element"),
    "comment":          ("-->", "close the comment, then start an element"),
    "tag-name":         (" ", "whitespace moves you to attribute-name position"),
    "attr-name":        (" ", "you are already inside the tag; add an attribute"),
    "attr-value-dq":    ('"', "close the value, whitespace, then a new attribute"),
    "attr-value-sq":    ("'", "close the value, whitespace, then a new attribute"),
    "attr-value-unq":   (" ", "whitespace alone ends the value - no quote needed"),
    "attr-value-url":   (":", "the value IS a URL sink; control the scheme"),
    "script-data":      ("", "already JavaScript - no escape required"),
    "script-string-dq": ('"', 'close the string, or use </script to leave the element'),
    "script-string-sq": ("'", "close the string, or use </script to leave the element"),
    "script-template":  ("${", "expression substitution - no quote break needed"),
    "script-comment":   ("\\n", "a newline ends a // comment"),
    "style-data":       ("", "CSS context - a CSS-level sink, not an HTML one"),
    "rcdata":           ("</", "tags are not parsed here; the close tag is the only exit"),
}


@dataclass
class Reflection:
    index: int
    context: str
    tag: str = ""
    attr: str = ""

    def describe(self) -> str:
        exit_chars, advice = EXITS[self.context]
        where = f"<{self.tag}>" if self.tag else "-"
        attr = f" @{self.attr}" if self.attr else ""
        shown = repr(exit_chars) if exit_chars else "(none)"
        return f"  @{self.index:<5} {self.context:<18} {where:<12}{attr:<14} exit={shown:<8} {advice}"


def classify(html: str, marker: str) -> list[Reflection]:
    """Walk the document, recording the tokeniser state at each marker occurrence."""
    found: list[Reflection] = []
    state, tag, attr, quote = "html-text", "", "", ""
    js_state = ""          # "", 'dq', 'sq', 'tpl', 'line', 'block'
    raw_tag = ""
    closing = False        # is the tag being read a close tag?
    i, n = 0, len(html)

    def after_tag(name: str) -> tuple[str, str]:
        """State and rawtext-tag to adopt once a start tag is closed by '>'."""
        low = name.lower()
        if closing:
            return "html-text", ""
        if low == "script":
            return "script-data", low
        if low == "style":
            return "style-data", low
        if low in RCDATA_TAGS:
            return "rcdata", low
        return "html-text", ""

    while i < n:
        if html.startswith(marker, i):
            ctx = state
            # A marker starting immediately after `=` is the first character of an
            # unquoted value; the tokeniser has not had a character to commit on yet.
            if state == "before-value":
                ctx = state = "attr-value-unq"
            if ctx in ("attr-value-dq", "attr-value-sq", "attr-value-unq") and attr.lower() in URL_ATTRS:
                ctx = "attr-value-url"
            if state == "script-data":
                ctx = {"dq": "script-string-dq", "sq": "script-string-sq",
                       "tpl": "script-template", "line": "script-comment",
                       "block": "script-comment"}.get(js_state, "script-data")
            if state == "style-data":
                ctx = "style-data"
            found.append(Reflection(i, ctx, tag, attr))
            i += len(marker)
            continue

        c = html[i]

        if state == "html-text":
            if html.startswith("<!--", i):
                state, i = "comment", i + 4
                continue
            if c == "<" and i + 1 < n and (html[i + 1].isalpha() or html[i + 1] == "/"):
                state, tag, i = "tag-name", "", i + 1
                closing = html[i] == "/"
                if closing:
                    i += 1
                continue

        elif state == "comment":
            if html.startswith("-->", i):
                state, i = "html-text", i + 3
                continue

        elif state == "tag-name":
            if c.isalnum() or c == "-":
                tag += c
            elif c in " \t\n\r":
                state, attr = "attr-name", ""
            elif c == ">":
                state, raw_tag = after_tag(tag)
                js_state = ""

        elif state == "attr-name":
            if c == "=":
                state = "before-value"
            elif c == ">":
                state, raw_tag = after_tag(tag)
                js_state = ""
            elif c in " \t\n\r":
                attr = ""
            else:
                attr += c

        elif state == "before-value":
            if c == '"':
                state, quote = "attr-value-dq", '"'
            elif c == "'":
                state, quote = "attr-value-sq", "'"
            elif c == ">":
                state, raw_tag = after_tag(tag)
                js_state = ""
            elif c not in " \t\n\r":
                state, quote = "attr-value-unq", ""

        elif state in ("attr-value-dq", "attr-value-sq"):
            if c == quote:
                state, attr = "attr-name", ""

        elif state == "attr-value-unq":
            if c in " \t\n\r":
                state, attr = "attr-name", ""
            elif c == ">":
                state, raw_tag = after_tag(tag)
                js_state = ""

        elif state in ("script-data", "style-data", "rcdata"):
            # Only the matching close tag leaves a rawtext/RCDATA element.
            if raw_tag and html[i:i + 2 + len(raw_tag)].lower() == "</" + raw_tag:
                state, tag, i = "tag-name", "", i + 2
                closing, js_state = True, ""
                continue
            if state == "script-data":
                if js_state == "":
                    if c in "\"'`":
                        js_state = {'"': "dq", "'": "sq", "`": "tpl"}[c]
                    elif html.startswith("//", i):
                        js_state = "line"
                    elif html.startswith("/*", i):
                        js_state = "block"
                elif js_state in ("dq", "sq", "tpl"):
                    if c == "\\":
                        i += 2
                        continue
                    if c == {"dq": '"', "sq": "'", "tpl": "`"}[js_state]:
                        js_state = ""
                elif js_state == "line" and c == "\n":
                    js_state = ""
                elif js_state == "block" and html.startswith("*/", i):
                    js_state, i = "", i + 2
                    continue
        i += 1
    return found


if __name__ == "__main__":
    M = "zqxj1"
    doc = f"""<html><body>
<p>Hello {M}</p>
<div class="{M}">x</div>
<div class='{M}'>x</div>
<input value={M} >
<a href="{M}">link</a>
<!-- note: {M} -->
<textarea>{M}</textarea>
<script>
  var a = "{M}";
  var b = '{M}';
  var c = `{M}`;
  // comment {M}
  var d = {M};
</script>
<style>.a {{ color: {M} }}</style>
</body></html>"""

    hits = classify(doc, M)
    print(f"{len(hits)} reflections\n")
    for hit in hits:
        print(hit.describe())

    got = [h.context for h in hits]
    expected = [
        "html-text",         # <p>
        "attr-value-dq",     # class="..."
        "attr-value-sq",     # class='...'
        "attr-value-unq",    # value=... unquoted
        "attr-value-url",    # href="..." - a URL sink, not a normal attribute
        "comment",
        "rcdata",            # <textarea>
        "script-string-dq",
        "script-string-sq",
        "script-template",
        "script-comment",
        "script-data",       # bare expression position
        "style-data",
    ]
    assert got == expected, f"\n got={got}\n want={expected}"

    # The classifications that most often surprise people:
    by_ctx = {h.context: h for h in hits}
    assert by_ctx["attr-value-unq"].tag == "input", "unquoted value needs no quote to escape"
    assert by_ctx["attr-value-url"].attr == "href", "href is a sink regardless of encoding"
    assert EXITS[by_ctx["script-template"].context][0] == "${", "template literal needs no quote break"
    assert EXITS[by_ctx["script-string-dq"].context][0] == '"'

    # Inside script data, '<' is inert - an HTML payload there is just text.
    inert = classify('<script>var x = "<img src=x onerror=1>' + M + '";</script>', M)
    assert inert[0].context == "script-string-dq", \
        "still inside the JS string: the <img> did not open an element"

    # ...but the literal close-tag sequence leaves the element from anywhere.
    escaped = classify('<script>var x = "</script>' + M + '";</script>', M)
    assert escaped[0].context == "html-text", "</script closes the element even inside a string"

    print("\nself-test ok")
```

## Variants & pitfalls

- **Look at the source, not the DOM.** DevTools shows you the parsed tree with entities resolved, which hides
  exactly the information you need.
- **Multiple reflections behave differently.** Number your markers.
- **A reflection can be in two contexts at once** - inside a quoted attribute that is itself inside a
  `<script>` written by the server, for instance. Count decoders carefully.
- **Length limits shape the payload more than filters do.** Short contexts favour `onerror` over `<script>`.
- **`<` inside script data is inert; `</script` is not.** These two facts explain most confusion about
  script-context injections.
- **Encoded exits sometimes survive.** If `"` is entity-encoded in an attribute but the attribute is an event
  handler, the HTML decode happens before JavaScript parses it - so the encoding did not help.
- **Unquoted attributes need no quote at all.** Do not conclude a context is safe because quotes are filtered.
- **Some contexts have no exploitable exit.** Correctly-encoded HTML text is genuinely closed; move on rather
  than grinding.
- **`javascript:` in `img src` does not fire** - the attribute must cause a navigation.

### Defence / what closes this

Encode on output, according to the context, using the table above - and let a template engine do it rather
than hand-rolling. Modern engines (React JSX, Angular interpolation, Jinja2 with autoescape, Go
`html/template`) apply HTML-context encoding automatically; the bugs cluster in the escape hatches
(`dangerouslySetInnerHTML`, `|safe`, `v-html`, `innerHTML`). Always quote attribute values, so the unquoted
context never exists. Never interpolate into an event handler or a `<script>` block - pass data through
`JSON.stringify` into a `<script type="application/json">` island and read it with `JSON.parse`, which has no
code path. Allowlist URL schemes rather than encoding them. Add a strict CSP with nonces as a second layer so
that a missed encoding is not automatically an execution, and set `HttpOnly` on session cookies so that a
successful XSS does not directly yield the session.

## Tools

- Burp Suite - Repeater for one-character-at-a-time exit testing; the response search finds every reflection.
- Burp DOM Invader - for the client-side half, where the context is built at runtime.
- `curl -s ... | grep -n zqxj1` - fastest way to see raw reflections with line numbers.
- Browser view-source - deliberately not the DevTools element inspector.

## References

- PortSwigger, cross-site scripting: https://portswigger.net/web-security/cross-site-scripting
- PortSwigger, XSS contexts: https://portswigger.net/web-security/cross-site-scripting/contexts
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- OWASP DOM based XSS Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- HTML Standard, tokenization: https://html.spec.whatwg.org/multipage/parsing.html#tokenization
- PayloadsAllTheThings, XSS injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
