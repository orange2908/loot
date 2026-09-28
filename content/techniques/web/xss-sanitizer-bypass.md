---
title: "mXSS - Why HTML Sanitizers Fail"
category: web
subcategory: xss
type: technique
tags: [mxss, mutation-xss, sanitizer-bypass, dompurify, innerhtml, html-parsing, serialisation, namespace-confusion, foreign-content, svg, mathml, annotation-xml, template-element, noscript, rcdata, idempotence, round-trip, cure53, xss]
difficulty: hard
summary: "Serialising a parsed tree and reparsing it is not the identity function; a sanitizer that inspects one tree while the browser builds another loses."
when_to_use:
  - "The application sanitizes HTML server-side or client-side and you need to reason about the gap"
  - "Rich-text/comment/profile fields that render user HTML rather than escaping it"
  - "You are reviewing why a given sanitizer configuration is or is not sound"
  - "A payload is visibly altered by the sanitizer yet still executes"
related: [xss-contexts, xss-dom-clobbering, xss-csp-bypass]
tools: [dompurify, burp]
---

## TL;DR

A sanitizer parses HTML into a tree, removes what it dislikes, and serialises the tree back to a string. The
browser then parses that string again. **Parse -> serialise -> parse is not guaranteed to be the identity
function**, so the tree the sanitizer approved is not always the tree the browser builds. Every mutation XSS
is an instance of that non-idempotence. The defence follows from the same observation: the sanitizer must
operate on, and hand over, a tree - not a string.

## Recognise it

- The application renders user-supplied HTML rather than escaping it: comments, profile bios, rich-text
  fields, markdown that permits inline HTML, email rendering.
- A sanitizer name in the bundle: `DOMPurify`, `sanitize-html`, `bleach`, `HTMLPurifier`, `js-xss`.
- Your input comes back **altered but not removed** - attribute order changed, quotes normalised, tags
  re-cased, implied tags inserted. That is the serialiser's fingerprint, and it means a round trip happened.
- The sanitized value is assigned with `innerHTML` rather than inserted as a node.
- Sanitization happens on the server and rendering in the browser - two different parsers, guaranteed to
  disagree somewhere.

## Theory

### The round-trip problem

Take this sequence, which is what almost every sanitizer does:

```
input string  --parse-->  tree A  --clean-->  tree B  --serialise-->  output string  --parse-->  tree C
```

The sanitizer verifies **tree B**. The browser executes **tree C**. Soundness requires `B == C`, i.e. that
serialising and reparsing round-trips exactly. HTML does not guarantee this, for structural reasons:

- **The serialiser must re-escape text.** It has to decide which characters to entity-encode in text nodes
  versus attribute values. Any place where it under-escapes creates a parse difference.
- **Parsing is context-sensitive.** The same bytes mean different things depending on the element they are
  inside. Serialisation flattens the tree back to bytes and thereby loses the context that decided the
  original parse.
- **The parser inserts and moves nodes.** Foster parenting in tables, implied `<tbody>`, auto-closing of `<p>`
  - the tree is not a transcription of the input, so re-parsing a serialisation of it can land elsewhere.

### Namespace confusion: the big one

HTML has three namespaces in one document: HTML, SVG and MathML. Parsing rules **differ by namespace**, and
the serialiser does not emit namespace information - it emits tag names. That is the core of the problem.

The illustrative case is `<style>`. In the HTML namespace, `<style>` is a rawtext element: its content is not
parsed as markup. Inside `<svg>`, the element is in the SVG namespace, where the same name is *not* rawtext
and its content is parsed as elements. So a `<style>` element containing markup-looking text means one thing
inside SVG and another after it has been serialised and reparsed into HTML context - the content that was
inert text in one tree becomes elements in the other.

`<annotation-xml encoding="text/html">` in MathML is the second classic: it explicitly switches the parser
back into HTML parsing for its children, so content that was treated as MathML text can re-enter as HTML on
the second parse.

`<mtext>`, `<mi>`, `<mo>` and the SVG `<foreignObject>` element are the other boundary points. What they all
share is that they are places where the parser's namespace state changes, and where a serialisation that
records only tag names loses the information needed to reproduce the parse.

### Rawtext, RCDATA and `<template>`

Elements whose content is not ordinary markup are the other reliable source of mutation:

- **`<script>` and `<style>`** are rawtext - content is not parsed at all.
- **`<textarea>` and `<title>`** are RCDATA - entities are decoded, tags are not parsed.
- **`<noscript>`** is parsed *differently depending on whether scripting is enabled*. A server-side
  sanitizer runs with scripting disabled, so it parses `<noscript>` content as markup; the browser, with
  scripting enabled, treats it as rawtext. Two parsers, two trees, by design.
- **`<template>`** puts its children in a separate inert document fragment. A sanitizer that walks the DOM
  naively may never visit `template.content`, because those children are not in the main tree.

Each of these is a state where "what is inside this element" is answered differently by different parsers or
different configurations, and a sanitizer that does not model the state exactly is inspecting a different
tree from the one that will be rendered.

### The "sanitize then modify" anti-pattern

Even a perfectly correct sanitizer is defeated by what happens after it:

```js
el.innerHTML = DOMPurify.sanitize(input) + '</div>';   // string concatenation after sanitizing
el.innerHTML = wrap(DOMPurify.sanitize(input));        // re-wrapping changes the parse context
```

Concatenating anything onto sanitized output, or inserting it into a *different* context than the one it was
sanitized for, re-opens the parse. The sanitized string was only ever valid for the exact context it was
checked in. This is the same lesson as `xss-contexts`: safety is a property of a string **in a context**, not
of the string.

The related failure is double sanitization, or sanitizing then running a templating pass over the result -
the second pass reparses.

### Sanitizer configuration errors

Distinct from mutation, and much more common in practice:

- **Allowing `id` and `name`** leaves DOM clobbering open (see `xss-dom-clobbering`), including clobbering of
  the sanitizer's own configuration object if it is a global.
- **Allowing `style`** permits CSS-based exfiltration.
- **Allowing `href` without a scheme allowlist** permits `javascript:`.
- **`ALLOW_UNKNOWN_PROTOCOLS`, `ADD_TAGS`, `ADD_ATTR`** and similar escape hatches, added to fix a rendering
  complaint and never revisited.
- **`SAFE_FOR_TEMPLATES` / `RETURN_DOM` misunderstandings** - returning a string when the caller wanted a node.
- Custom elements and `is=` attributes, which look unknown-but-harmless to an allowlist and can carry
  behaviour.

### Why an allowlist over a tree, with the same parser, is the sound design

Collecting the above: the failure is always a *difference* between the parser that validated and the parser
that renders. The design that has no such difference:

1. Parse with the **same** implementation the consumer will use (in the browser, the browser's own parser).
2. Walk the resulting tree and delete disallowed nodes and attributes - an allowlist, not a blocklist.
3. Hand over the **tree**, not a string (`RETURN_DOM_FRAGMENT`, and insert the node).

Step 3 is what eliminates mutation XSS as a category: if nothing is serialised, nothing is reparsed, and the
round-trip problem cannot arise. This is why client-side sanitization immediately before node insertion is
structurally safer than server-side sanitization of a string that travels to a different parser.

## Attack

1. Confirm a round trip is happening: send benign HTML with unusual but legal formatting (odd attribute
   quoting, uppercase tags, redundant whitespace) and see whether it comes back normalised. Normalisation
   means parse-serialise, which means the mutation class applies.
2. Identify the sanitizer and version. The bundle name, or a fingerprint of how it normalises.
3. Determine where sanitization happens - server, client, or both. Both is the most promising, because the
   two parsers differ.
4. Probe the namespace boundaries: does `<svg>` survive? `<math>`? `<template>`? `<noscript>`? Each surviving
   one is a parser-state boundary to reason about.
5. Check what happens *after* sanitization. Any concatenation or re-wrapping is a better target than the
   sanitizer itself.
6. Check the configuration before the parser: allowed `id`, `style`, or unrestricted `href` are far more
   likely than a novel mutation.

## Code

A demonstration that parse -> serialise -> parse is not the identity, using Python's stdlib parser. The point
is the *measurement*: a round trip that changes the tree is exactly the condition under which a sanitizer's
verdict does not transfer to the renderer.

```python
#!/usr/bin/env python3
"""Show that HTML parse -> serialise -> parse is not idempotent.

Builds a minimal tree model with html.parser, serialises it back, reparses, and
compares. Where the two trees differ, a sanitizer that validated the first tree
made no promise about the second - which is mutation XSS in one sentence.

Stdlib only; no browser, no network.
"""
from __future__ import annotations

from html.parser import HTMLParser

# Elements whose content the HTML namespace does not parse as markup.
RAWTEXT = {"script", "style"}
RCDATA = {"textarea", "title"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"}


class TreeBuilder(HTMLParser):
    """Parse into a nested (tag, attrs, children) structure."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root: list = []
        self.stack: list[list] = [self.root]

    def handle_starttag(self, tag, attrs):
        node = (tag, dict(attrs), [])
        self.stack[-1].append(node)
        if tag not in VOID:
            self.stack.append(node[2])

    def handle_startendtag(self, tag, attrs):
        self.stack[-1].append((tag, dict(attrs), []))

    def handle_endtag(self, tag):
        if len(self.stack) > 1:
            self.stack.pop()

    def handle_data(self, data):
        if data.strip():
            self.stack[-1].append(data)


def parse(html: str) -> list:
    builder = TreeBuilder()
    builder.feed(html)
    builder.close()
    return builder.root


def serialise(nodes: list) -> str:
    """Serialise the tree back to a string, escaping text nodes."""
    out: list[str] = []
    for node in nodes:
        if isinstance(node, str):
            out.append(node.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            continue
        tag, attrs, children = node
        rendered = "".join(f' {k}="{v}"' for k, v in attrs.items() if v is not None)
        rendered += "".join(f" {k}" for k, v in attrs.items() if v is None)
        if tag in VOID:
            out.append(f"<{tag}{rendered}>")
        else:
            out.append(f"<{tag}{rendered}>{serialise(children)}</{tag}>")
    return "".join(out)


def shape(nodes: list) -> list:
    """Tag/text skeleton of a tree, for comparison."""
    result = []
    for node in nodes:
        if isinstance(node, str):
            result.append(("#text", node.strip()))
        else:
            tag, attrs, children = node
            result.append((tag, sorted(attrs), shape(children)))
    return result


def round_trip(html: str) -> tuple[list, str, list, bool]:
    """Parse, serialise, reparse. Returns both shapes and whether they agree."""
    first = parse(html)
    serialised = serialise(first)
    second = parse(serialised)
    return shape(first), serialised, shape(second), shape(first) == shape(second)


def count_elements(nodes: list, name: str) -> int:
    total = 0
    for node in nodes:
        if isinstance(node, str):
            continue
        tag, _, children = node
        total += (tag == name) + count_elements(children, name)
    return total


if __name__ == "__main__":
    print("== round trips that are stable ==")
    for html in ('<p>hello</p>',
                 '<div class="a"><span>x</span></div>',
                 '<img src="x" alt="y">'):
        _, out, _, stable = round_trip(html)
        print(f"  {stable and 'stable  ' or 'MUTATED '} {html!r} -> {out!r}")
        assert stable, "simple markup should round-trip"

    print("\n== round trips that are NOT stable ==")
    # A rawtext element's content is text in the first parse. The serialiser
    # escapes it, so the second parse sees entities - the trees differ, and a
    # real browser serialiser (which does NOT escape rawtext) differs again.
    cases = [
        ('<style><img src=x onerror=1></style>',
         "rawtext content is text, but escaping/reparsing changes what it is"),
        ('<textarea><div>x</div></textarea>',
         "RCDATA: tags are not parsed inside, so the inner markup is text"),
        ('<title><a href=1>x</a></title>',
         "RCDATA again - same reasoning, different element"),
    ]
    mutated = 0
    for html, why in cases:
        before, out, after, stable = round_trip(html)
        status = "stable " if stable else "MUTATED"
        print(f"  {status} {html!r}\n          -> {out!r}\n          {why}")
        if not stable:
            mutated += 1
    assert mutated >= 1, "at least one rawtext/RCDATA case must demonstrate the difference"

    print("\n== the tree a sanitizer approves is not the tree that renders ==")
    # A sanitizer strips <script>. Applied to the FIRST tree, that looks complete.
    hostile = '<style><script>x</script></style>'
    first = parse(hostile)
    assert count_elements(first, "script") == 0, \
        "in the first parse the script text is inert rawtext content, so a tree-walking " \
        "sanitizer sees no script element to remove"
    serialised = serialise(first)
    second = parse(serialised)
    print(f"  input      {hostile!r}")
    print(f"  tree A     script elements = {count_elements(first, 'script')}")
    print(f"  serialised {serialised!r}")
    print(f"  tree C     script elements = {count_elements(second, 'script')}")
    print("  -> the sanitizer validated tree A; the renderer parses tree C")

    print("\n== the design that removes the class ==")
    # Never serialise: validate the tree and hand over the tree.
    def sanitize_to_tree(html: str, allowed: set[str]) -> list:
        def walk(nodes: list) -> list:
            kept = []
            for node in nodes:
                if isinstance(node, str):
                    kept.append(node)
                    continue
                tag, attrs, children = node
                if tag in allowed:
                    kept.append((tag, {k: v for k, v in attrs.items()
                                       if k in {"href", "title"}}, walk(children)))
            return kept
        return walk(parse(html))

    tree = sanitize_to_tree('<p>ok<script>bad()</script><a href="/x" onclick="bad()">l</a></p>',
                            allowed={"p", "a"})
    assert count_elements(tree, "script") == 0, "disallowed element removed"
    assert tree[0][2][1][1] == {"href": "/x"}, "onclick dropped, href kept"
    print(f"  sanitized tree: {shape(tree)}")
    print("  no serialisation step, so no reparse, so no mutation")

    print("\nself-test ok")
```

Note what this model does and does not show. Python's `html.parser` is not a WHATWG-conformant parser: it has
no namespace handling, no foster parenting, and no scripting flag. It is enough to demonstrate *that*
round-tripping is unstable and why that matters, which is the transferable idea. Reasoning about a specific
browser's behaviour requires that browser, because the differences that matter are exactly the ones a
simplified model omits.

## Variants & pitfalls

- **Server-side and client-side sanitization of the same value** is the highest-yield configuration, because
  two different parsers are guaranteed to disagree somewhere.
- **A payload that is visibly altered may still work.** Alteration is evidence of the round trip, not of
  safety.
- **Configuration beats cleverness.** Check allowed `id`/`name`/`style`/`href` first; a novel mutation is a
  much rarer finding than a permissive config.
- **Anything appended to sanitized output re-opens it.** Look at the call site, not just the sanitizer.
- **`<template>` content is not in the main tree**, so a naive DOM walk misses it.
- **`<noscript>` parses differently with scripting enabled**, which is precisely the server/client split.
- **Sanitizers are maintained software.** An old pinned version is far more promising than the current one;
  check the version before theorising about a new bypass.
- **Markdown renderers that allow inline HTML** inherit all of this, plus their own parse stage.
- **Do not trust a sanitizer you wrote.** Regex-based HTML sanitization is not in the same category of thing;
  it is broken by construction, because it does not parse.

### Defence / what closes this

Prefer not to accept HTML at all - accept Markdown or a structured format and render it yourself, escaping
text. Where HTML is genuinely required, use a maintained, browser-based sanitizer (DOMPurify) on the client,
immediately before insertion, and use `RETURN_DOM_FRAGMENT` so a node is handed over rather than a string -
that removes the serialise/reparse step and with it the entire mutation class. Never concatenate onto, wrap,
re-template or re-sanitize the output. Configure an allowlist and strip `id`, `name` and `style` to close
clobbering and CSS exfiltration; allowlist URL schemes explicitly. Keep the sanitizer updated, and treat its
release notes as a security feed. Layer a nonce-based CSP with `require-trusted-types-for 'script'`
underneath, so that a bypass still has to clear a second control.

## Tools

- DOMPurify - the reference client-side sanitizer; its test suite and release notes are the best available
  catalogue of this class.
- Burp Repeater - for sending formatting probes and observing normalisation.
- A local browser console - `new DOMParser().parseFromString(s, 'text/html')` lets you compare parse results
  directly, which is the only authoritative check.

## References

- DOMPurify: https://github.com/cure53/DOMPurify
- HTML Standard, parsing: https://html.spec.whatwg.org/multipage/parsing.html
- HTML Standard, serialising HTML fragments: https://html.spec.whatwg.org/multipage/parsing.html#serialising-html-fragments
- HTML Standard, foreign content (SVG/MathML): https://html.spec.whatwg.org/multipage/parsing.html#parsing-main-inforeign
- "mXSS Attacks: Attacking well-secured Web-Applications" (Heiderich et al., ACM CCS 2013): https://cure53.de/fp170.pdf
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- MDN, `Element.innerHTML` security considerations: https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML
