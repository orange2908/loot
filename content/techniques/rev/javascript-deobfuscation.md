---
title: "JavaScript Deobfuscation - obfuscator.io, AST Transforms and pkg Binaries"
category: rev
subcategory: javascript
type: technique
tags: [javascript, nodejs, deobfuscation, obfuscator-io, babel, ast, jsvmp, source-maps, pkg, nexe, v8-bytecode, webpack, eval, unpacker, beautifier, electron, asar]
difficulty: medium
summary: "Undo string-array rotation, control-flow flattening and hex identifiers with Babel AST transforms, and pull JS out of pkg/nexe/Electron bundles."
when_to_use:
  - "The challenge ships minified or obfuscated .js, or a webpack bundle"
  - "You see a big array of hex strings plus a rotating IIFE at the top of the file"
  - "The binary is a Node single-executable (pkg/nexe) or an Electron app"
  - "You need to recover original sources from a .map file"
tools: [babel, nodejs, prettier, webcrack, deobfuscator-io, asar, pkg, chrome-devtools]
related: [python-bytecode-pyinstaller, webassembly-reversing, obfuscation-deobfuscation, dotnet-reversing, crackme-patterns]
---

## TL;DR

JavaScript obfuscation is source-to-source, so it is always reversible: parse to an AST,
constant-fold, inline the string array, flatten the control flow, rename, print. Babel gives
you all of that in ~100 lines. For packaged Node/Electron binaries, the JS is either plain
text inside an archive or V8 bytecode with the source stripped - different problem, handled
at the end.

## Recognise it

| Signal | Obfuscation |
|---|---|
| `var _0x1a2b = ['\x68\x65...', ...];` plus an IIFE doing `push(shift())` | obfuscator.io string array + rotation |
| `_0x4f3a('0x1')` everywhere | string-array accessor function |
| `while(!![]){switch(_0x2c[_0x1++]){case'0':...}}` | control-flow flattening |
| `['log']` instead of `.log` | member-expression obfuscation |
| `!![]`, `[]['filter']['constructor']` | boolean/constructor obfuscation |
| `eval(function(p,a,c,k,e,d){...}('...'))` | Dean Edwards packer |
| all names are `a`, `b`, `aa`, `ab` | terser/uglify minification (not obfuscation) |
| `jjencode` / `aaencode` (only `$`, `_`, or emoji-like katakana) | joke encoders - just eval them |
| a giant array + a `switch` interpreter over opcodes | JSVMP (a custom VM - see `custom-vm-bytecode`) |
| `//# sourceMappingURL=app.js.map` | source map available - game over |

```sh
# First moves, in order
npx prettier --write chall.js          # beautify: makes everything readable
node -e "console.log(require('fs').readFileSync('chall.js','utf8').length)"
grep -o "sourceMappingURL=.*" chall.js  # a .map file gives you the original sources
```

## Source maps - always check first

```sh
# If app.js.map exists, the original sources are inside it verbatim
python3 - <<'PY'
import json, os, pathlib
m = json.load(open("app.js.map"))
for name, content in zip(m["sources"], m.get("sourcesContent") or []):
    if content is None:
        continue
    out = pathlib.Path("recovered") / name.replace("../", "").lstrip("/")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(content)
    print("[+]", out)
PY
```

Even without `sourcesContent`, the map gives you original file names and identifier names,
which is most of the battle. Chrome DevTools loads maps automatically - open the page, go to
Sources, and read the original files.

## The obfuscator.io shape

```javascript
// a typical head of an obfuscator.io output
var _0x3f2a = ['\x63\x6f\x6e\x73\x6f\x6c\x65', 'log', 'Correct!', 'Wrong'];
(function (arr, rounds) {                 // the rotation IIFE
    var rotate = function (n) {
        while (--n) { arr['push'](arr['shift']()); }
    };
    rotate(++rounds);
}(_0x3f2a, 0x1a3));
var _0x4b1c = function (idx, _key) {      // the accessor
    idx = idx - 0x0;
    return _0x3f2a[idx];
};
if (_0x4b1c('0x2') === input) {           // the real code, obscured
    window[_0x4b1c('0x0')][_0x4b1c('0x1')](_0x4b1c('0x2'));
}
```

The decode strategy, in order:

1. **Run the string array and the rotation** in a sandbox to get the final array.
2. **Replace every accessor call** `_0x4b1c('0x2')` with its literal string.
3. **Constant-fold** what that exposes (`'a' + 'b'` -> `'ab'`, `!![]` -> `true`).
4. **Un-flatten** the `while/switch` dispatcher into a linear statement list.
5. **Convert** `obj['prop']` to `obj.prop` and rename `_0x...` identifiers.
6. **Beautify** and read.

Off-the-shelf tools that do all six: **webcrack** (`npx webcrack chall.js -o out/`),
**obfuscator-io-deobfuscator**, **synchrony** (`npx deobfuscate chall.js`), and the
`deobfuscate.io` web UI. Try these first; write your own transform only when they choke.

## Code - a Babel deobfuscator you can extend

```sh
npm install @babel/core @babel/parser @babel/traverse @babel/generator
```

```javascript
// deob.js - node deob.js chall.js > clean.js
// Handles: string-array inlining, constant folding, member-expression normalisation,
// dead-branch removal, and identifier renaming.
const fs = require('fs');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

const src = fs.readFileSync(process.argv[2], 'utf8');
const ast = parser.parse(src, { sourceType: 'unambiguous', errorRecovery: true });

// --- Pass 1: evaluate the string array + rotation in a throwaway context ----
// We re-run only the top-level array declaration and the rotation IIFE, then capture
// the accessor function so we can call it for any index.
let accessorName = null;
let accessor = null;
traverse(ast, {
  VariableDeclarator(path) {
    const init = path.node.init;
    // the accessor is `function (idx, key) { ... return arr[idx]; }`
    if (t.isFunctionExpression(init) && init.params.length >= 1) {
      const code = generate(path.parentPath.node).code;
      if (/\[\s*\w+\s*\]/.test(code) && /return/.test(code)) {
        try {
          // eslint-disable-next-line no-eval
          const fn = eval(`(${generate(init).code})`);
          if (typeof fn === 'function') { accessorName = path.node.id.name; accessor = fn; }
        } catch (e) { /* not the accessor */ }
      }
    }
  },
});

// A more reliable approach for obfuscator.io: evaluate the whole prelude.
// Take everything up to (and including) the rotation IIFE and eval it in this scope.
const preludeMatch = src.match(/^[\s\S]*?\}\(\s*_0x[0-9a-f]+\s*,\s*0x[0-9a-f]+\s*\)\);/);
if (preludeMatch) {
  try {
    // eslint-disable-next-line no-eval
    eval(preludeMatch[0]);
    const decl = src.match(/var\s+(_0x[0-9a-f]+)\s*=\s*function\s*\(/);
    if (decl) {
      // eslint-disable-next-line no-eval
      const fn = eval(decl[1]);
      if (typeof fn === 'function') { accessorName = decl[1]; accessor = fn; }
    }
  } catch (e) {
    console.error('[!] prelude eval failed:', e.message);
  }
}

// --- Pass 2: replace accessor calls with their literal result ---------------
if (accessor) {
  traverse(ast, {
    CallExpression(path) {
      if (!t.isIdentifier(path.node.callee, { name: accessorName })) return;
      const args = path.node.arguments.map((a) => (t.isLiteral(a) ? a.value : undefined));
      if (args.some((a) => a === undefined)) return;
      try {
        const value = accessor(...args);
        if (typeof value === 'string') path.replaceWith(t.stringLiteral(value));
      } catch (e) { /* leave it */ }
    },
  });
}

// --- Pass 3: constant folding (handles '\x41'+'B', !![], 0x1a, 1+2) --------
traverse(ast, {
  'BinaryExpression|UnaryExpression|LogicalExpression': {
    exit(path) {
      const result = path.evaluate();
      if (result.confident && ['string', 'number', 'boolean'].includes(typeof result.value)) {
        path.replaceWith(t.valueToNode(result.value));
      }
    },
  },
});

// --- Pass 4: obj['prop'] -> obj.prop --------------------------------------
traverse(ast, {
  MemberExpression(path) {
    const prop = path.node.property;
    if (path.node.computed && t.isStringLiteral(prop) &&
        /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(prop.value)) {
      path.node.property = t.identifier(prop.value);
      path.node.computed = false;
    }
  },
});

// --- Pass 5: delete branches with a constant condition --------------------
traverse(ast, {
  IfStatement(path) {
    const test = path.get('test').evaluate();
    if (!test.confident) return;
    path.replaceWith(test.value ? path.node.consequent
                                : (path.node.alternate || t.emptyStatement()));
  },
});

// --- Pass 6: rename _0xdeadbeef identifiers to readable names -------------
let counter = 0;
traverse(ast, {
  Scopable(path) {
    for (const name of Object.keys(path.scope.bindings)) {
      if (/^_0x[0-9a-f]+$/i.test(name)) path.scope.rename(name, `v${counter++}`);
    }
  },
});

process.stdout.write(generate(ast, { comments: false, compact: false }).code);
```

Run `node deob.js chall.js | npx prettier --parser babel > clean.js`. Iterate: each pass
exposes more constants for the next run, so running the script two or three times often
helps.

## Control-flow un-flattening

```javascript
// before
var order = '3|1|4|0|2'['split']('|'), i = 0;
while (!![]) {
    switch (order[i++]) {
        case '0': var b = a * 2; continue;
        case '1': var a = input.length; continue;
        case '2': return b;
        case '3': console.log('start'); continue;
        case '4': if (a > 5) { a = 5; } continue;
    }
    break;
}
```

The `'3|1|4|0|2'.split('|')` literal *is* the execution order. Emit the case bodies in that
order and the function becomes linear. A Babel transform: find a `WhileStatement` whose body
is a single `SwitchStatement` discriminating on `arr[i++]`, read the sibling array literal,
then replace the whole loop with the concatenated case bodies in the listed order.

## Other encodings

```sh
# Dean Edwards packer: eval(function(p,a,c,k,e,d){...})
# Just replace `eval` with `console.log` and run it
sed 's/^eval(/console.log(/' packed.js | node

# jjencode / aaencode / JSFuck: pure-symbol encodings that evaluate to source.
# Same trick, but be careful - this EXECUTES the payload. Use a sandboxed container.
node -e "const s=require('fs').readFileSync('enc.js','utf8'); console.log(eval(s.replace(/^eval/,'String')))"

# A safer approach for any eval-based packing: run under Node's inspector and
# read the compiled script instead of evaluating blindly
node --inspect-brk -e "$(cat enc.js)"     # then attach chrome://inspect
```

**Always run untrusted JS in a container or a VM** - `eval` of a CTF payload can touch your
filesystem and network.

For anything eval-driven, a hook is the cleanest capture:

```javascript
// evalhook.js - node -r ./evalhook.js chall.js
// Logs everything passed to eval/Function before it runs.
const realEval = global.eval;
global.eval = function (code) {
  console.error('===== eval =====\n' + code + '\n================');
  return realEval(code);
};
const RealFunction = global.Function;
global.Function = function (...args) {
  console.error('===== new Function =====\n' + args.join(', ') + '\n========');
  return RealFunction.apply(this, args);
};
global.Function.prototype = RealFunction.prototype;
```

## Node single-file executables

### pkg

```sh
# `pkg` appends a V8 snapshot + the project files. Sometimes the sources are plain text.
strings -a app | grep -a 'sourceMappingURL\|function ' | head
# The bundled files live in a virtual fs rooted at /snapshot/<project>
strings -a app | grep -ao '/snapshot/[^"]*' | sort -u | head
# Extraction: pkg stores entries in a payload after the Node binary. Carve it:
binwalk -e app
# If the source was compiled to V8 bytecode (`pkg --public-packages` off / default in
# newer versions), you get .jsc-like blobs. Recover behaviour by running under the
# inspector instead of decompiling:
node --inspect-brk app            # then attach chrome://inspect and read Sources
```

The reliable trick for any pkg/nexe binary: **run it under the Node inspector**. The V8
debugger reconstructs source text (or at least the function bodies) for everything that
executes, even for bytecode-only builds. Set a breakpoint at the entry, then browse Sources.

### nexe

```sh
# nexe appends a tar-like resource blob with a trailing footer containing its length
tail -c 32 app | xxd
binwalk -e app
strings -a app | grep -a '<nexe~~sentinel>' -A2
```

### Electron

```sh
# All the JS is in a plain asar archive - no obfuscation at all in most cases
find . -name '*.asar'
npx asar extract app.asar app_extracted/
ls app_extracted/            # package.json, main.js, renderer bundles
# Repack after patching
npx asar pack app_extracted/ app.asar
# If asar is unavailable, it is a simple JSON-header + blob format; 7z can list it
```

## V8 bytecode (.jsc) and JSVMP

`bytenode`-compiled `.jsc` files contain a V8 code cache. There is no public decompiler, and
the cache is tied to the exact V8 version. Options: run it with the matching Node under
`--inspect-brk` and read the functions in DevTools, or use `v8-disasm`-style tooling from a
custom Node build (`node --print-bytecode`). For CTFs, the inspector route is the answer.

A **JSVMP** (a JS-implemented VM interpreting a custom opcode array) is a different problem:
treat it as a custom VM - dump the opcode array, reverse the dispatcher, write a
disassembler. See `custom-vm-bytecode`.

## Dynamic analysis in the browser

```javascript
// Paste into DevTools Console before triggering the check.
// 1. Break whenever a specific string is compared
const realIncludes = String.prototype.includes;
String.prototype.includes = function (needle) {
  console.log('[includes]', JSON.stringify(this), JSON.stringify(needle));
  return realIncludes.call(this, needle);
};

// 2. Log every crypto call (very common in web crackmes)
const realDigest = crypto.subtle.digest.bind(crypto.subtle);
crypto.subtle.digest = async (alg, data) => {
  console.log('[digest]', alg, new TextDecoder().decode(data));
  return realDigest(alg, data);
};

// 3. Catch the flag comparison generically: trap on any long string equality
//    by setting a conditional breakpoint in Sources instead:
//       condition:  arguments[0] && arguments[0].length > 20
```

DevTools features worth knowing: **Pretty print** (`{}` at the bottom of the Sources pane),
**Local Overrides** (edit the served JS and persist it across reloads - the fastest way to
patch a client-side check), **XHR/fetch breakpoints**, **Event Listener Breakpoints**, and
`debug(fn)` in the console to break on a named function.

## Variants & pitfalls

- **Anti-debug in JS**: a `setInterval` that calls `debugger;` or measures
  `Date.now()` around a `debugger` statement. In DevTools, right-click the line and
  "Never pause here", or deactivate breakpoints (Ctrl+F8), or strip the statement with a
  Babel transform.
- **`Function.prototype.toString` checks**: obfuscators detect beautification by hashing
  their own source. Patch `toString` or work on a copy that the runtime never inspects.
- **Domain/self-host locks**: `location.hostname !== 'ctf.example'`. Override with a Local
  Override or by running the page from the expected origin via `/etc/hosts`.
- **`eval` of a decoded buffer** hides the real payload: hook `eval` (above) rather than
  statically decoding.
- **Webpack bundles**: look for the module map at the bottom (`{ 123: function(module,
  exports, __webpack_require__) {...} }`). `webcrack` splits them back into files.
- **Minified is not obfuscated**: prettier + a source map is usually all you need.
- **Never trust a "deobfuscated" output you did not diff-test**: run both versions on the
  same input and compare results.

## Tools

- `prettier` / `js-beautify` - formatting.
- `webcrack`, `synchrony`, `obfuscator-io-deobfuscator` - ready-made unpackers.
- `@babel/parser` + `@babel/traverse` + `@babel/generator` - custom AST transforms.
- `asar` - Electron archives.
- Chrome DevTools - Sources, Local Overrides, conditional breakpoints, `debug()`.
- `node --inspect-brk` - works on pkg/nexe/bytenode binaries.
- `binwalk` - carving appended payloads out of packaged executables.

## References

- Babel documentation: `@babel/traverse` visitor API and `path.evaluate()`.
- Chrome DevTools documentation: Local Overrides and JavaScript breakpoint types.
- The Source Map Revision 3 specification (`sources`, `sourcesContent` fields).
