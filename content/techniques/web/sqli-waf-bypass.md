---
title: "SQL Injection - Why Input Filters Fail"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, waf, waf-bypass, filter-bypass, blacklist, preg-replace, strip-once, normalisation, parser-differential, versioned-comment, url-encoding, double-encoding, whitespace, scientific-notation, libinjection, modsecurity, sqlmap, tamper-scripts]
difficulty: medium
summary: "Input filters and the SQL parser disagree about what a token is; every evasion class is one instance of that disagreement, which is why blacklists lose."
when_to_use:
  - "A payload that should work returns a block page, a 403, or a silently empty result"
  - "You need to explain why a keyword blacklist is not a control"
  - "You are working out which specific token in a request is being rejected"
  - "You are deciding whether a filter in challenge source code is bypassable in principle"
tools: [burp, sqlmap, curl]
related: [sqli-union-based, sqli-blind-boolean, xss-sanitizer-bypass, cmdi-injection-and-bypass]
---

## TL;DR

Every filter bypass is the same bug wearing different clothes: the filter and the database parse the input
with **different grammars**. The filter looks for a string; the SQL parser tokenises a language. Anywhere
those two disagree - about whitespace, about comments, about case, about what counts as one token - there is
a gap. Learning the gap is worth far more than learning a payload list, because the list is just an
enumeration of one engine's disagreements.

## Recognise it

- A syntactically valid payload returns 403, a block page, a WAF-branded error, or a reset connection, while
  a benign value on the same parameter returns 200.
- The response changes on the *presence of a substring* rather than on SQL validity - `1 union` blocks but
  `1 unio` does not.
- A payload works with one whitespace character and not another.
- The application returns its normal "no results" page rather than an error, which suggests the input was
  mangled before it reached the query rather than rejected outright.
- Challenge source contains `preg_replace`, `str_replace`, `strip_tags`, or a keyword array - and applies it
  **once**.

## Theory

### The parser differential

An application that tries to make input safe by inspecting it must model the database's grammar. It never
does, because that grammar is large, engine-specific and version-specific. Concretely:

- The SQL tokeniser treats `/**/`, newline, tab, vertical tab, form feed and carriage return as token
  separators. A filter that splits on the ASCII space sees one token where the database sees two.
- MySQL's versioned comments `/*!50000SELECT*/` are *executed* by MySQL and look like comments to everything
  else. A filter that strips comments before checking keywords removes the disguise; one that does not, never
  sees the keyword.
- SQL keywords are case-insensitive; a case-sensitive filter compares bytes.
- The tokeniser does not require whitespace between a token and a following punctuation character, so
  `UNION(SELECT(1))` has no spaces at all and is still two keywords to the database.
- Numeric literals in scientific notation (`1e0`) end where the exponent ends, so `1e0union` is a number
  followed by a keyword to MySQL, and one unrecognised word to a filter splitting on non-alphanumerics.

None of these are clever. They are all just "the filter's notion of a token is not SQL's notion of a token".

### Normalisation order is the second half

Even a filter with a correct keyword list fails if it runs at the wrong point in the pipeline. Two orderings,
two very different outcomes:

- **decode then filter** - the filter sees what the database will see. Correct order.
- **filter then decode** - the filter sees `%55NION` and finds no keyword; a later `urldecode` turns it into
  `UNION`. The check was performed on a string that never reaches the query.

Layers multiply this. A CDN decodes once, the framework decodes again, and the application decodes a third
time for its own reasons. Each decode is an opportunity for a check performed before it to have been looking
at the wrong string. This is exactly the class of bug that makes double encoding (`%2555` -> `%55` -> `U`)
work, and it is the same shape as the normalisation-order bugs in `lfi-path-traversal`.

### Strip-once is not a filter

The single most common mistake in challenge source is a removal-based filter applied once:

```php
$in = preg_replace('/select/i', '', $in);
```

Removal is not idempotent. Applying it to a string that *contains the pattern split across itself*
reconstructs the pattern in the output. `selselectect` contains `select` once, in the middle; removing that
occurrence joins `sel` to `ect` and yields `select`. The filter's output is the thing the filter exists to
prevent.

The fix is not a better pattern. It is to **reject** rather than remove, or to loop to a fixed point - and if
you loop to a fixed point, you have a denial-of-service consideration and still no security property, because
the keyword was never the vulnerability. The vulnerability was concatenating input into a query.

### Equivalence classes worth knowing

These exist to illustrate the differential, not as a payload list:

| Constraint | Mechanism that routes around it |
|-----------|-------------------------------|
| No spaces | other whitespace bytes (`%09 %0a %0b %0c %0d`), `/**/`, parentheses |
| No comments | newline terminates a `--` comment; the rest of the line is fine |
| Keyword blacklist, case-sensitive | mixed case, since SQL keywords are case-insensitive |
| Keyword blacklist, strip-once | the split-keyword reconstruction above |
| No quotes | hex literals (`0x61`), `CHAR()`, `UNHEX()`, Postgres dollar-quoting |
| No commas | `SUBSTRING(x FROM 1 FOR 1)`, `LIMIT 1 OFFSET 1`, `JOIN` in place of a column list |
| Keyword must not be adjacent to a digit | scientific notation absorbs the boundary |

Each row is one grammar disagreement. If you understand the row, you can regenerate its contents for an
engine the table does not cover.

### Finding which token is blocked, methodically

Guessing is slow. Bisect instead, and be disciplined about the oracle:

1. **Establish a baseline.** Send a benign value. Record status, length, and timing. Without this you cannot
   tell a block from an empty result set.
2. **Confirm the block is content-triggered**, not rate-based. Send the blocked payload twice with a gap; a
   consistent block on content and a 200 on benign input means content.
3. **Bisect the payload string.** Cut it in half and send each half embedded in an otherwise-benign request.
   Only one half should block. Recurse into that half. Roughly `log2(n)` requests gets you to the token.
4. **Isolate the token from its context.** A blocked half may be blocked because of a two-token sequence
   rather than one word. Test the token alone and the sequence separately.
5. **Classify what kind of rule it is.** Does the same token block in a different parameter? In a header? In
   the body? That distinguishes a request-wide WAF rule from application-level validation, and they have very
   different bypass surfaces.

Doing this by hand in Repeater is usually faster than automating it, because step 4 needs judgement.

## Attack

1. Confirm injection exists at all with a payload containing no blacklisted-looking words
   (`1 AND 1=1` versus `1 AND 1=2` - no `UNION`, no `SELECT`).
2. Establish the baseline and confirm the block is content-triggered.
3. Bisect to the token.
4. Identify which disagreement is available: is it whitespace handling, decode order, case, or a strip-once
   removal? Read the challenge source if you have it - this step is a five-second read with source and a
   twenty-request experiment without.
5. Rebuild the minimum payload that avoids that one token, and re-verify. Changing several things at once
   means you will not know which mattered.

## Code

A demonstration of the two failure modes that make blacklists unsound: strip-once non-idempotence and
filter-before-decode. It operates entirely on strings, with no database and no network, and asserts the
failure rather than asserting a bypass.

```python
#!/usr/bin/env python3
"""Why removal-based and mis-ordered input filters are not security controls.

Two demonstrations:
  1. Removal filters are not idempotent - their output can contain the pattern
     they remove, so one pass is unsound by construction.
  2. Filtering before decoding inspects a string that is not the one the
     database will parse.

Strings only. No database, no network.
"""
from __future__ import annotations

import re
from urllib.parse import unquote


def strip_once(text: str, word: str) -> str:
    """The common anti-pattern: remove every match, one pass, case-insensitive."""
    return re.sub(re.escape(word), "", text, flags=re.IGNORECASE)


def strip_to_fixpoint(text: str, word: str, limit: int = 100) -> str:
    """Loop until the output stops changing. Terminates, but still not a control."""
    for _ in range(limit):
        nxt = strip_once(text, word)
        if nxt == text:
            return text
        text = nxt
    return text


def reconstructs(word: str) -> str:
    """Build a string whose strip_once output is exactly `word`.

    Split the word in half and nest a copy between the halves: removing the
    inner occurrence rejoins the outer halves into the word itself.
    """
    mid = len(word) // 2
    return word[:mid] + word + word[mid:]


def filter_then_decode(raw: str, blocked: list[str]) -> tuple[bool, str]:
    """Wrong order: inspect the raw bytes, decode afterwards."""
    lowered = raw.lower()
    if any(b in lowered for b in blocked):
        return False, ""
    return True, unquote(raw)


def decode_then_filter(raw: str, blocked: list[str]) -> tuple[bool, str]:
    """Right order: decode to what the database sees, then inspect."""
    decoded = unquote(raw)
    if any(b in decoded.lower() for b in blocked):
        return False, ""
    return True, decoded


def decode_to_fixpoint(raw: str, limit: int = 10) -> str:
    """Percent-decode repeatedly until stable - models a multi-layer pipeline."""
    for _ in range(limit):
        nxt = unquote(raw)
        if nxt == raw:
            return raw
        raw = nxt
    return raw


if __name__ == "__main__":
    print("== 1. removal filters are not idempotent ==")
    for word in ("select", "union", "or"):
        payload = reconstructs(word)
        once = strip_once(payload, word)
        print(f"  strip_once({payload!r:<24}, {word!r:<8}) -> {once!r}")
        assert once.lower() == word, "one pass reconstructs the keyword it removes"
    # Looping to a fixed point does remove it - at the cost of unbounded work,
    # and it still grants no security property.
    assert strip_to_fixpoint(reconstructs("select"), "select") == ""
    print("  fixpoint removes it, but the query is still built by concatenation")

    print("\n== 2. filter order decides what was actually inspected ==")
    blocked = ["union", "select"]
    singly = "%55NION"          # one decode away from UNION
    doubly = "%2555NION"        # two decodes away

    passed, decoded = filter_then_decode(singly, blocked)
    print(f"  filter_then_decode({singly!r}) -> passed={passed} decoded={decoded!r}")
    assert passed, "the raw bytes contain no blocked word..."
    assert "union" in decoded.lower(), "...but the decoded string does"

    passed, _ = decode_then_filter(singly, blocked)
    print(f"  decode_then_filter({singly!r}) -> passed={passed}")
    assert not passed, "decoding first inspects the right string"

    # A single decode is not enough when the pipeline decodes more than once.
    passed, decoded = decode_then_filter(doubly, blocked)
    print(f"  decode_then_filter({doubly!r}) -> passed={passed} decoded={decoded!r}")
    assert passed, "one decode leaves %55NION, which contains no blocked word"
    assert "union" in decode_to_fixpoint(doubly).lower(), \
        "a second decode downstream restores the keyword"
    print("  -> matching the number of decodes to the pipeline is guesswork")

    print("\n== 3. tokenisation: the filter's idea of a separator is not SQL's ==")
    # A filter splitting on ASCII space sees one opaque token; SQL sees two,
    # because it separates on any of these bytes.
    sql_whitespace = ["\t", "\n", "\x0b", "\x0c", "\r"]
    sample = "UNION" + "\x0b" + "SELECT"
    assert " " not in sample, "contains no space at all"
    assert len(sample.split(" ")) == 1, "space-splitting filter sees one token"
    for ws in sql_whitespace:
        assert len(("UNION" + ws + "SELECT").split()) == 2, \
            "str.split() with no argument splits on all of them, like SQL does"
    print(f"  {len(sql_whitespace)} non-space bytes separate tokens for SQL but not for split(' ')")

    print("\nself-test ok - every assertion above is a filter failing, not a payload working")
```

## Variants & pitfalls

- **A block is not proof of a vulnerability.** WAFs match patterns, not exploitability. A 403 on `' OR 1=1`
  can happen on a parameter that never reaches a query.
- **Changing several things at once wastes the experiment.** One variable per request, or you will not know
  which change mattered.
- **Normalisation differs between layers.** The CDN, the framework and the application may each decode. A
  bypass that works against the edge can still be stopped by the app, and vice versa.
- **Length limits and character-set handling** are filters too, and frequently the real obstacle rather than
  the keyword list.
- **`libinjection`-style tokenisers** (used by ModSecurity and others) actually do tokenise SQL rather than
  string-match, so the naive whitespace and case tricks do not apply; they have their own, narrower
  differentials.
- **Blocking can be stateful.** Some WAFs raise sensitivity after a suspicious request, so an early crude
  probe can poison the session and make later measurements meaningless. Start with benign probes.
- **Automated tamper scripts obscure the oracle.** `sqlmap --tamper=...` is fine once you know the gap, but
  running it first makes it much harder to learn what is actually being blocked.

### Defence / what closes this

Parameterised queries (prepared statements with bound variables) end this entire category, because the query
structure is sent to the database separately from the data and no amount of encoding in the data changes the
parse. Where an identifier genuinely must be dynamic - a column name in an ORDER BY - use a hard-coded
allowlist mapping user input to known-good identifiers, never string interpolation. Use the ORM or query
builder's binding API rather than its raw-SQL escape hatch. Treat a WAF as telemetry and defence in depth,
not as the control: it buys time against automated scanning and should never be the reason a query is safe.
If validation must exist, reject invalid input rather than sanitising it, decode fully before inspecting, and
apply least privilege to the database account so that a bypass reaches as little as possible.

## Tools

- Burp Repeater and Intruder - the bisection above is a handful of manual requests.
- `sqlmap --tamper=<script>` - the built-in tamper scripts are a readable catalogue of the equivalence classes.
- `libinjection` - reading its tokeniser is the fastest way to understand what a real SQL-aware filter does.
- ModSecurity + the OWASP Core Rule Set - a local instance to test against is far more instructive than
  guessing at a remote WAF.

## References

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Testing Guide, testing for SQL injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- PortSwigger, SQL injection: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings, SQL injection: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- libinjection: https://github.com/libinjection/libinjection
- OWASP ModSecurity Core Rule Set: https://github.com/coreruleset/coreruleset
- MySQL manual, comment syntax (versioned comments): https://dev.mysql.com/doc/refman/8.0/en/comments.html
