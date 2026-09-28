---
title: "XXE - External Entities, Parameter-Entity Chains and Parser Defaults"
category: web
subcategory: xxe
type: technique
tags: [xxe, xml-external-entity, external-entity, parameter-entity, external-dtd, doctype, xinclude, billion-laughs, entity-expansion, svg-upload, ooxml, docx, soap, libxml2, defusedxml, lxml, documentbuilderfactory, secure-processing, libxml-disable-entity-loader, oob-exfiltration]
difficulty: medium
summary: "Whether XXE works is decided by the parser's defaults, not by the payload; modern parsers disable external entities and old ones do not."
when_to_use:
  - "An endpoint accepts XML, or a format that is XML underneath (SVG, DOCX, XLSX, SOAP, RSS)"
  - "You need to know whether a given parser and version is exploitable at all"
  - "The response does not reflect content, so exfiltration has to be out-of-band or error-based"
  - "Reviewing XML parsing code for which hardening flags actually matter"
related: [ssrf-fundamentals, upload-to-rce, upload-image-processing]
tools: [burp, interactsh, curl]
---

## TL;DR

XML has a macro system - entities - and the specification allows an entity's value to come from a URI. A
parser that resolves those URIs will read local files and make network requests on behalf of whoever supplied
the document. Whether it does so is a **parser configuration question**, and the defaults have shifted
decisively toward "no" over the last decade. So the productive first step is identifying the parser, not
crafting a payload.

## Recognise it

- A request body that is XML, or an endpoint accepting `application/xml`, `text/xml`,
  `application/soap+xml`.
- File uploads of formats that are XML inside: SVG, DOCX/XLSX/PPTX (a zip of XML parts), RSS/Atom, SAML
  assertions, XML sitemaps, GPX, KML, `.xspf`.
- A JSON endpoint that also accepts XML when you change `Content-Type` - a surprisingly common configuration.
- Errors naming a parser: `org.xml.sax.SAXParseException`, `lxml.etree.XMLSyntaxError`,
  `DOCTYPE is not allowed`, `Start tag expected`.
- An endpoint that processes a document and returns any part of it - a transformation, a preview, a
  validation report.

## Theory

### Entities

An entity is a named substitution. Declared in the document's internal subset:

```xml
<!DOCTYPE d [ <!ENTITY name "value"> ]>
<d>&name;</d>
```

The specification also permits an **external** entity, whose replacement text is fetched from a URI:

```xml
<!ENTITY ext SYSTEM "file:///etc/hostname">
```

When the parser expands `&ext;`, it retrieves that URI. Two capabilities fall out at once: reading local
files, and making requests from the parser's network position - which is server-side request forgery, with
everything that implies (see `ssrf-fundamentals`).

Which URI schemes work depends on the parser's underlying library. `file://` and `http://` are the common
pair; PHP's stream wrappers historically made `php://filter` available inside XXE, and Java supported a
wider set including `jar:` and `netdoc:`.

### In-band versus blind

**In-band** requires the expanded entity to appear in the response - the document is echoed, or one field is
rendered back. This is the easy case and increasingly rare.

**Blind** means nothing comes back, and you need another channel. This is where parameter entities become
necessary, and understanding *why* is the part worth internalising.

### Why parameter entities, and why an external DTD

Parameter entities (`%name;`) are entities usable **within the DTD itself** rather than in document content.
The reason they matter: you want to build an entity declaration whose *value* contains the file you just
read, so the file contents end up inside a URI that the parser then requests - carrying the data to you.

That construction requires nesting one entity's value inside another declaration. And the XML specification
**forbids parameter-entity references inside markup declarations in the internal subset**. Well-formedness
rules prevent it. But the same construction is permitted in an **external** DTD subset.

So the structure is forced by the specification, not chosen for stealth:

1. The document declares a parameter entity pointing at a DTD on your server, and references it.
2. The parser fetches your DTD.
3. Your DTD declares a parameter entity that reads the target file, and a second whose value embeds the first
   into a URL.
4. Referencing the second causes the parser to request that URL, with the file contents in it.

The requirement for an external DTD is therefore structural. A blind XXE where the parser can read files but
cannot make outbound requests is genuinely much harder, because this chain needs both.

### Error-based exfiltration

When outbound HTTP is blocked but the application returns parser errors, the error message itself is the
channel. The trick is to construct a URI from the file contents that cannot resolve - the parser then reports
the failure, and the report includes the malformed URI, which includes the data. This requires verbose errors
to reach the user, which is its own misconfiguration.

### XInclude

Sometimes you control only a *fragment* of XML that the server embeds into a larger document - so you cannot
declare a DOCTYPE at all. XInclude is the answer, when the parser has it enabled:

```xml
<x xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</x>
```

This needs no DOCTYPE and no entity declarations. It is a separate parser feature with a separate switch,
which means a parser hardened against entities may still process XInclude - worth testing independently
rather than assuming the hardening covers both.

### Entry points that do not look like XML

- **SVG** is XML. An SVG upload that is parsed, rasterised or sanitised server-side is an XXE entry point.
- **OOXML** (DOCX, XLSX, PPTX) is a zip containing XML parts. Modifying `word/document.xml` or
  `[Content_Types].xml` inside the archive puts your DTD in front of the parser.
- **SOAP** is XML by definition, and SOAP stacks are frequently old.
- **SAML** assertions are XML, processed before authentication - an unusually attractive position.
- **Content-type juggling**: send XML to an endpoint that normally takes JSON. Many frameworks content-negotiate.

### Denial of service: billion laughs

Nested entity definitions expand exponentially:

```xml
<!ENTITY a "dosdosdosdos">
<!ENTITY b "&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;">
```

Ten levels of four-fold nesting is roughly a million expansions from a tiny document. This requires no
external entities at all, so it works against parsers that have disabled them but not entity expansion.
Modern parsers impose expansion limits by default; `defusedxml` blocks it explicitly. The quadratic-blowup
variant (one large entity referenced many times) evades naive depth counting while achieving similar effect.

### Parser defaults: the table that actually decides it

| Parser / stack | External entities by default | Notes |
|----------------|------------------------------|-------|
| libxml2 >= 2.9.0 | **off** | `XML_PARSE_NOENT` must be set explicitly; this change closed most PHP/Python XXE |
| Python `xml.etree.ElementTree` | off | does not resolve external entities |
| Python `lxml` | off for external; resolves internal | `resolve_entities=False`, `no_network=True` defaults; an explicit permissive parser re-enables |
| Python `xml.sax` / `minidom` | varies by build | `defusedxml` is the correct answer |
| Java `DocumentBuilderFactory` | **on** historically | the classic vulnerable default; needs `FEATURE_SECURE_PROCESSING` plus explicit `disallow-doctype-decl` |
| Java (JDK 8u121+) | restricted | `jdk.xml.entityExpansionLimit` and related properties added |
| PHP (libxml2-backed) | off since libxml 2.9 | `libxml_disable_entity_loader` was the old control; deprecated in PHP 8.0 as unnecessary |
| .NET `XmlReaderSettings` | off since .NET 4.5.2 | `DtdProcessing = Prohibit` is the explicit form |
| Go `encoding/xml` | not supported at all | no external entity support, by design |
| Node (`libxmljs`, `fast-xml-parser`) | mostly not supported | `libxmljs` can enable it explicitly |

The headline: **most modern defaults are safe**. Finding XXE today usually means an old runtime, a pinned
dependency, or code that explicitly opted into a permissive parser - often to make a legitimate feature work.
That makes "which parser and which version" the highest-value question, and it is frequently answerable from
an error message alone.

## Attack

1. **Confirm XML is parsed.** Send malformed XML and look for a parser error - that error usually names the
   library.
2. **Test whether DOCTYPE is permitted.** A document with a harmless internal entity distinguishes "DTD
   rejected outright" from "DTD processed".
3. **Test internal entity expansion** before external. If internal entities do not expand, external certainly
   will not.
4. **Test external entity resolution** with a URI pointing at a host you control - an interaction proves
   resolution without needing anything to come back in the response.
5. **If nothing reflects, go out-of-band** with the parameter-entity chain and an external DTD.
6. **If outbound is blocked**, try error-based, then XInclude, then reconsider whether the endpoint is worth
   it.

## Code

A parser-behaviour demonstrator. It builds each payload variant and runs them against the parsers available
locally, reporting what each does - which is the empirical version of the defaults table. It guards the
`lxml` import so it runs on a stdlib-only environment.

```python
#!/usr/bin/env python3
"""What XML parsers actually do with entities, measured rather than assumed.

Builds the payload variants (internal entity, external entity, parameter-entity
chain, billion laughs, XInclude) and reports how each locally available parser
handles them. Demonstrates that modern defaults are closed and that opening
them is an explicit act.

Uses a file:// URI pointing at a fixture this script creates. No network: the
'external' URIs are local paths, so a resolving parser proves resolution
without any traffic leaving the machine.
"""
from __future__ import annotations

import os
import tempfile
import xml.etree.ElementTree as ET
from xml.parsers import expat

try:
    from lxml import etree as lxml_etree
    HAVE_LXML = True
except ImportError:
    HAVE_LXML = False

SECRET = "canary-value-12345"


def payloads(fixture: str) -> dict[str, str]:
    """One document per variant, all referencing the local fixture."""
    uri = "file://" + fixture
    return {
        "internal entity": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE d [ <!ENTITY e "inline-expansion"> ]>'
            "<d>&e;</d>"
        ),
        "external entity": (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE d [ <!ENTITY e SYSTEM "{uri}"> ]>'
            "<d>&e;</d>"
        ),
        "parameter entity": (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE d [ <!ENTITY % p SYSTEM "{uri}"> %p; ]>'
            "<d>x</d>"
        ),
        "billion laughs": (
            '<?xml version="1.0"?>'
            '<!DOCTYPE d ['
            '<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            '<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">'
            "]>"
            "<d>&d;</d>"
        ),
        "xinclude": (
            '<?xml version="1.0"?>'
            '<d xmlns:xi="http://www.w3.org/2001/XInclude">'
            f'<xi:include parse="text" href="{uri}"/>'
            "</d>"
        ),
    }


def describe(text: str | None) -> str:
    if text is None:
        return "no text"
    if SECRET in text:
        return f"RESOLVED - fixture contents present ({SECRET!r})"
    if len(text) > 500:
        return f"expanded to {len(text)} chars"
    return f"inert: {text.strip()[:60]!r}"


def try_elementtree(document: str) -> str:
    try:
        root = ET.fromstring(document)
        return describe("".join(root.itertext()))
    except ET.ParseError as exc:
        return f"refused: {str(exc)[:70]}"
    except expat.ExpatError as exc:  # pragma: no cover - defensive
        return f"refused: {str(exc)[:70]}"


def try_lxml(document: str, *, permissive: bool) -> str:
    if not HAVE_LXML:
        return "lxml not installed"
    parser = lxml_etree.XMLParser(
        resolve_entities=permissive,
        no_network=not permissive,
        load_dtd=permissive,
        huge_tree=False,
    )
    try:
        root = lxml_etree.fromstring(document.encode(), parser)
        if "xi:include" in document or "XInclude" in document:
            if permissive:
                root.getroottree().xinclude()
        return describe("".join(root.itertext()))
    except Exception as exc:
        return f"refused: {type(exc).__name__}: {str(exc)[:60]}"


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        fixture = os.path.join(tmp, "canary.txt")
        with open(fixture, "w", encoding="utf-8") as handle:
            handle.write(SECRET + "\n")

        docs = payloads(fixture)

        print("== xml.etree.ElementTree (stdlib default) ==")
        results_et = {}
        for name, document in docs.items():
            outcome = try_elementtree(document)
            results_et[name] = outcome
            print(f"  {name:<18} {outcome}")

        # The stdlib parser expands internal entities but resolves nothing external.
        assert "inline-expansion" in results_et["internal entity"] or \
            "inert" in results_et["internal entity"]
        assert "RESOLVED" not in results_et["external entity"], \
            "ElementTree must not resolve external entities"
        assert "RESOLVED" not in results_et["xinclude"], \
            "XInclude is a separate feature and is not applied here"

        if HAVE_LXML:
            print("\n== lxml, default parser (hardened) ==")
            results_safe = {}
            for name, document in docs.items():
                outcome = try_lxml(document, permissive=False)
                results_safe[name] = outcome
                print(f"  {name:<18} {outcome}")
            assert "RESOLVED" not in results_safe["external entity"], \
                "resolve_entities=False is the safe default"

            print("\n== lxml, explicitly permissive parser (opted in) ==")
            results_open = {}
            for name, document in docs.items():
                outcome = try_lxml(document, permissive=True)
                results_open[name] = outcome
                print(f"  {name:<18} {outcome}")
            # Opting in is what makes it exploitable - the payload never changed.
            assert "RESOLVED" in results_open["external entity"], \
                "resolve_entities=True resolves the external entity"
            assert "RESOLVED" not in results_safe["external entity"]
            print("\n  -> identical payload; only the parser configuration differs")

            # Even fully permissive, the parameter-entity form is refused in the
            # INTERNAL subset: the specification forbids that construction. This
            # is why the blind chain must live in an external DTD.
            assert "refused" in results_open["parameter entity"], \
                "a parameter entity in the internal subset is not well-formed"
            print("  -> note the parameter-entity row: refused even with everything enabled,")
            print("     because the spec forbids it in the internal subset. Hence the external DTD.")

            # XInclude is a separate feature from entity resolution.
            assert "RESOLVED" in results_open["xinclude"], "XInclude resolved once applied"
            assert "RESOLVED" not in results_safe["xinclude"]
            print("  -> XInclude is a separate switch; test it independently of entities")
        else:
            print("\n  (lxml not installed - stdlib results above still make the point)")

        print("\n== billion laughs needs no external entities at all ==")
        outcome = try_elementtree(docs["billion laughs"])
        print(f"  ElementTree: {outcome}")
        print("  -> disabling external entities does not address entity expansion;")
        print("     that needs a separate expansion limit (or defusedxml).")

    print("\nself-test ok")
```

## Variants & pitfalls

- **Identify the parser first.** The defaults table decides exploitability more than any payload does.
- **libxml2 2.9.0 closed most of this** in 2012 for the PHP and Python ecosystems. Old runtimes are the
  target.
- **Java's historical `DocumentBuilderFactory` defaults were permissive**, which is why Java XXE persisted
  longer.
- **XInclude is a separate switch** from entity resolution. Test both.
- **An external DTD is structurally required** for the blind parameter-entity chain - the specification
  forbids the equivalent in the internal subset.
- **A file containing characters that are not valid XML** breaks entity expansion; text files work, binaries
  often do not. Wrapping in a CDATA-producing chain or using `php://filter` to base64 is the workaround where
  available.
- **OOXML is a zip.** Edit the XML part inside, rezip, upload.
- **SVG is the most common modern entry point** because image uploads are everywhere.
- **Content-type juggling** turns a JSON endpoint into an XML one surprisingly often.
- **Billion laughs works on parsers hardened against external entities**, because it is a different feature.
- **`defusedxml` blocks all of it** - if you see it imported, move on.

### Defence / what closes this

Disable DTD processing entirely; almost no application legitimately needs it. In Java, set
`disallow-doctype-decl` to true on the factory, plus `external-general-entities` and
`external-parameter-entities` to false and `FEATURE_SECURE_PROCESSING` on. In Python, use `defusedxml` in
place of the stdlib parsers, and never construct an `lxml` parser with `resolve_entities=True` or
`no_network=False`. In .NET, set `DtdProcessing = DtdProcessing.Prohibit`. In PHP, stay on a libxml2 of 2.9
or later and do not re-enable the entity loader. Keep XInclude disabled separately, since it is a distinct
feature. Where XML is genuinely required, prefer a parser with no external-entity support at all (Go's
`encoding/xml`) or, better, accept JSON instead. Apply entity-expansion and document-size limits to address
the denial-of-service variants, which hardening against external entities does not cover. Do not return
parser errors to users, which removes the error-based channel. Finally, apply the SSRF defences from
`ssrf-fundamentals` to the parser's host, since a resolving parser is an SSRF primitive.

## Tools

- Burp Suite - Repeater for payload variants; Collaborator for the out-of-band channel.
- `interactsh` - self-hosted interaction collector for blind confirmation.
- `defusedxml` - reading its documentation is the fastest summary of what each stdlib parser does.
- A local container per runtime - the only reliable way to check a specific version's defaults.

## References

- OWASP, XML external entity processing: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing
- OWASP XXE Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- OWASP Testing Guide, testing for XML injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection
- PortSwigger, XXE injection: https://portswigger.net/web-security/xxe
- PortSwigger, blind XXE: https://portswigger.net/web-security/xxe/blind
- W3C XML 1.0, physical structures (entities): https://www.w3.org/TR/xml/#sec-physical-struct
- W3C XInclude 1.0: https://www.w3.org/TR/xinclude/
- Python `defusedxml`: https://github.com/tiran/defusedxml
- lxml FAQ, parser security: https://lxml.de/FAQ.html
- PayloadsAllTheThings, XXE injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
