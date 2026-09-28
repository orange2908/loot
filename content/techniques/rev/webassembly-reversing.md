---
title: "WebAssembly Reversing - wat, wasm2c and Debugging in the Browser"
category: rev
subcategory: wasm
type: technique
tags: [webassembly, wasm, wat, wabt, wasm2wat, wasm-decompile, wasm2c, emscripten, binaryen, ghidra-wasm, browser-devtools, stack-machine, linear-memory, rust-wasm, wasmtime, wasm-objdump]
difficulty: medium
summary: "Convert .wasm to .wat, read the stack machine, dump linear memory for the string data, and hook exports in the browser or in wasmtime."
when_to_use:
  - "A web challenge loads a .wasm module and validates the flag client-side"
  - "You have a standalone .wasm to run under wasmtime/wasmer"
  - "The C/Rust source was compiled with emscripten and you need to find the checker"
  - "strings shows nothing because the data lives in the module's data segments"
tools: [wabt, wasm2wat, wasm-decompile, wasm-objdump, wasm2c, binaryen, wasmtime, ghidra, chrome-devtools]
related: [javascript-deobfuscation, custom-vm-bytecode, rust-binaries, crackme-patterns, z3-constraint-solving, triage-unknown-binary]
---

## TL;DR

`.wasm` is a compact binary format for a typed stack machine with a single linear memory.
`wasm2wat` gives you readable text, `wasm-decompile` gives you something close to C, and
`wasm-objdump -x` gives you the imports/exports/data segments. Most CTF wasm challenges are
solved by dumping the data section (the expected flag is usually right there) or by calling
the exported check function in a loop from JS or wasmtime.

## Recognise it

```sh
file chall.wasm                       # -> "WebAssembly (wasm) binary module version 0x1"
xxd -l 8 chall.wasm                   # 00 61 73 6d 01 00 00 00   = "\0asm" + version 1
# In a web challenge, grep the page for the loader
grep -rn 'WebAssembly.instantiate\|\.wasm' ./site/
# Emscripten output comes as a pair: chall.js (glue) + chall.wasm
ls *.wasm *.js
```

## First look

```sh
# Install: apt install wabt   (or build from source: WebAssembly/wabt)

# --- Text format: the ground truth ----------------------------------------
wasm2wat chall.wasm -o chall.wat
wasm2wat --fold-exprs chall.wasm -o chall.folded.wat   # nested s-expressions, easier to read
wasm2wat --generate-names chall.wasm -o named.wat      # invent $names for unnamed things

# --- A C-like decompilation: usually where to start -----------------------
wasm-decompile chall.wasm -o chall.dcmp

# --- Structure: sections, imports, exports, data segments -----------------
wasm-objdump -h chall.wasm            # section headers
wasm-objdump -x chall.wasm | less     # full details: types, imports, exports, elements
wasm-objdump -d chall.wasm | less     # disassembly with byte offsets
wasm-objdump -x chall.wasm | grep -A40 'Data\['     # the data segments (strings live here)

# --- Round-trip and optimisation (binaryen) -------------------------------
wasm-dis chall.wasm -o chall.binaryen.wat
wasm-opt -O3 chall.wasm -o opt.wasm   # simplifying before reading can help a lot
wasm-opt --flatten --simplify-locals chall.wasm -o flat.wasm

# --- Convert to C, then use your normal tooling ---------------------------
wasm2c chall.wasm -o chall.c          # compiles with the wabt runtime headers
gcc -c chall.c -I /usr/include/wabt   # then read it, or compile+debug it natively
```

## Reading .wat

```wat
(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (import "env" "memory" (memory (;0;) 256))
  (func $check (type 0) (param $ptr i32) (param $len i32) (result i32)
    (local $i i32) (local $acc i32)
    i32.const 0
    local.set $i                       ;; i = 0
    block $exit
      loop $top
        local.get $i
        local.get $len
        i32.ge_s
        br_if $exit                    ;; if (i >= len) break
        local.get $ptr
        local.get $i
        i32.add
        i32.load8_u                    ;; load s[i] from linear memory
        i32.const 42
        i32.xor                        ;; ^ 42
        local.get $acc
        i32.add
        local.set $acc                 ;; acc += (s[i] ^ 42)
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $top
      end
    end
    local.get $acc
    i32.const 1337
    i32.eq                             ;; return acc == 1337
  )
  (export "check" (func $check))
  (data (;0;) (i32.const 1024) "Correct!\00Wrong\00CTF{...}\00")
)
```

The mental model:

- **Stack machine, typed**: every instruction pops fixed types and pushes fixed types.
  `i32.add` pops two i32 and pushes one. There are only four value types that matter:
  `i32`, `i64`, `f32`, `f64`.
- **`local.get`/`local.set`/`local.tee`** access parameters and locals by index; there are no
  registers.
- **`global.get`/`global.set`** - global 0 is almost always the stack pointer in
  emscripten/clang output.
- **Structured control flow**: `block`/`loop`/`if`/`end` with `br N`, `br_if N`, `br_table`.
  `br` inside a `block` jumps *forward* to its end; `br` inside a `loop` jumps *back* to its
  start. The number is a relative label depth, not an address.
- **One linear memory** (`i32.load`, `i32.store`, `i32.load8_u`, ...), addressed by a plain
  i32 offset. All "pointers" are indices into that array.
- **Function calls**: `call N` (direct) and `call_indirect` (through the table, the wasm
  equivalent of a function pointer - the index is on the stack).
- **No strings**: literals live in `data` segments copied into linear memory at instantiation.

## Getting the strings

```sh
# The data segments hold every literal. wasm-objdump prints them as escaped bytes:
wasm-objdump -x chall.wasm | sed -n '/^Data\[/,$p' | head -60
# Quick and dirty: strings works too because data segments are stored raw
strings -a -n 4 chall.wasm
```

Programmatic extraction, so you can map a pointer constant (e.g. `i32.const 1024`) to the
string it refers to:

```python
#!/usr/bin/env python3
"""wasmdata.py - parse a .wasm module and dump its sections, exports and data segments.

Pure stdlib. Prints each data segment's memory offset so you can resolve the i32.const
pointers you see in the .wat back to actual strings.

Usage: python3 wasmdata.py chall.wasm [--strings]
"""
import sys

SECTION_NAMES = {
    0: "custom", 1: "type", 2: "import", 3: "function", 4: "table", 5: "memory",
    6: "global", 7: "export", 8: "start", 9: "element", 10: "code", 11: "data",
    12: "datacount",
}
EXTERNAL_KIND = {0: "func", 1: "table", 2: "memory", 3: "global"}


def uleb(data: bytes, off: int) -> tuple[int, int]:
    result, shift = 0, 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7


def sleb(data: bytes, off: int) -> tuple[int, int]:
    result, shift = 0, 0
    while True:
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40:
                result -= 1 << shift
            return result, off


def read_name(data: bytes, off: int) -> tuple[str, int]:
    length, off = uleb(data, off)
    return data[off:off + length].decode("utf-8", errors="replace"), off + length


def const_expr(data: bytes, off: int) -> tuple[int, int]:
    """Parse a tiny init_expr of the form (i32.const N) end."""
    opcode = data[off]
    off += 1
    value = 0
    if opcode == 0x41:                       # i32.const
        value, off = sleb(data, off)
    elif opcode == 0x23:                     # global.get
        value, off = uleb(data, off)
        value = -1                           # unknown until instantiation
    while data[off] != 0x0B:                 # skip to `end`
        off += 1
    return value, off + 1


def parse(path: str, show_strings: bool) -> int:
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:4] != b"\x00asm":
        print("[-] not a wasm module")
        return 1
    version = int.from_bytes(data[4:8], "little")
    print(f"[*] wasm version {version}, {len(data)} bytes")

    off = 8
    while off < len(data):
        sec_id = data[off]
        off += 1
        size, off = uleb(data, off)
        body = data[off:off + size]
        name = SECTION_NAMES.get(sec_id, f"id{sec_id}")
        extra = ""
        if sec_id == 0:
            cname, _ = read_name(body, 0)
            extra = f" ({cname})"
        print(f"  section {name:<10}{extra} size={size}")

        if sec_id == 2:                      # imports
            count, p = uleb(body, 0)
            for _ in range(count):
                mod, p = read_name(body, p)
                field, p = read_name(body, p)
                kind = body[p]
                p += 1
                print(f"      import {EXTERNAL_KIND.get(kind, kind):<7} {mod}.{field}")
                if kind == 0:
                    _, p = uleb(body, p)
                elif kind == 1:
                    p += 1
                    flags, p = uleb(body, p)
                    _, p = uleb(body, p)
                    if flags:
                        _, p = uleb(body, p)
                elif kind == 2:
                    flags, p = uleb(body, p)
                    _, p = uleb(body, p)
                    if flags:
                        _, p = uleb(body, p)
                elif kind == 3:
                    p += 2

        elif sec_id == 7:                    # exports
            count, p = uleb(body, 0)
            for _ in range(count):
                ename, p = read_name(body, p)
                kind = body[p]
                p += 1
                index, p = uleb(body, p)
                print(f"      export {EXTERNAL_KIND.get(kind, kind):<7} {ename} -> #{index}")

        elif sec_id == 11:                   # data
            count, p = uleb(body, 0)
            for seg in range(count):
                flags, p = uleb(body, p)
                addr = 0
                if flags == 0:
                    addr, p = const_expr(body, p)
                elif flags == 2:
                    _, p = uleb(body, p)     # memory index
                    addr, p = const_expr(body, p)
                length, p = uleb(body, p)
                payload = body[p:p + length]
                p += length
                print(f"      data[{seg}] @ {addr:#x} len={length}")
                if show_strings:
                    for piece in payload.split(b"\x00"):
                        if len(piece) >= 3 and all(32 <= c < 127 for c in piece):
                            rel = payload.find(piece)
                            print(f"        {addr + rel:#08x}  {piece.decode()!r}")
        off += size
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: wasmdata.py chall.wasm [--strings]")
        return 1
    return parse(sys.argv[1], "--strings" in sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
```

## Running and hooking it

### Standalone, from Node

```javascript
// run.js - node run.js  (works for a module with no imports, or with a stub env)
const fs = require('fs');

(async () => {
  const bytes = fs.readFileSync('chall.wasm');
  const memory = new WebAssembly.Memory({ initial: 256 });
  const imports = {
    env: {
      memory,
      // stub anything the module imports; log the arguments - this is often the flag
      emscripten_resize_heap: () => 0,
      abort: () => { throw new Error('abort'); },
      printf: (fmt, args) => { console.log('[printf]', fmt, args); return 0; },
    },
    wasi_snapshot_preview1: { proc_exit: () => {}, fd_write: () => 0 },
  };
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  const mem = new Uint8Array((instance.exports.memory || memory).buffer);
  console.log('exports:', Object.keys(instance.exports));

  // Write a candidate string into linear memory and call the checker
  const write = (str, ptr) => {
    for (let i = 0; i < str.length; i++) mem[ptr + i] = str.charCodeAt(i);
    mem[ptr + str.length] = 0;
    return ptr;
  };
  const PTR = 0x10000;
  const cand = 'CTF{testtesttest}';
  console.log('check ->', instance.exports.check(write(cand, PTR), cand.length));
})();
```

Byte-by-byte brute forcing from this harness is trivial and fast (millions of calls per
second), which is why most wasm crackmes fall to a simple loop rather than to static
analysis. Combine with an instruction/time oracle if the checker exits early - see
`side-channel-instruction-counting`.

### Standalone runtimes

```sh
# wasmtime (WASI modules with a _start or an exported main)
wasmtime run chall.wasm
wasmtime run --invoke check chall.wasm 65536 16      # call an arbitrary export
# wasmer is equivalent
wasmer run chall.wasm
# iwasm (WAMR) and wasm3 are small interpreters useful for tracing
wasm3 --func check chall.wasm 65536 16
```

### In the browser

Chrome and Firefox DevTools both disassemble wasm to `.wat` and support **breakpoints,
stepping and memory inspection** in it:

1. Open DevTools -> Sources. The module appears under `wasm://`.
2. Click a line number in the disassembly to set a breakpoint.
3. When it hits, the Scope pane shows locals and the stack; the Memory inspector
   (right-click a memory object -> "Reveal in Memory Inspector") shows linear memory.
4. From the Console you can reach the instance if the page kept a reference, then read
   memory directly:

```javascript
// In DevTools, after the module is instantiated (adjust to the page's variable names)
const mem = new Uint8Array(wasmInstance.exports.memory.buffer);
// Dump 64 bytes at a pointer you saw as an i32.const in the .wat
console.log(new TextDecoder().decode(mem.slice(1024, 1088)));
// Call an export directly
wasmInstance.exports.check(1024, 16);
```

You can also **patch the module before instantiation** by hooking the loader:

```javascript
// Paste before the page loads the module (a DevTools "Local Override" on the loader JS)
const realInstantiate = WebAssembly.instantiate;
WebAssembly.instantiate = async function (bytes, imports) {
  console.log('[wasm] module size', bytes.byteLength);
  const result = await realInstantiate.call(this, bytes, imports);
  const inst = result.instance || result;
  for (const [name, fn] of Object.entries(inst.exports)) {
    if (typeof fn === 'function') {
      inst.exports[name] = new Proxy(fn, {
        apply(t, thisArg, args) {
          const out = Reflect.apply(t, thisArg, args);
          console.log(`[wasm] ${name}(${args}) = ${out}`);
          return out;
        },
      });
    }
  }
  return result;
};
```

(Export objects are frozen in some engines; if the assignment throws, wrap the *imports*
instead, or intercept at the call sites in the glue JS.)

## Ghidra and other disassemblers

- **Ghidra**: install the `ghidra-wasm-plugin` (a community WebAssembly processor module) to
  get a wasm loader and decompiler output. Quality varies; `wasm-decompile` is often better
  for straightforward modules.
- **wasm2c + native tooling** is the most reliable "decompiler": convert to C, compile with
  `-O0 -g`, and then use Ghidra/gdb on a normal native binary that has identical semantics.
- **JEB** and **Binary Ninja** (with the wasm plugin) also load wasm.

## Emscripten-specific notes

- The `.js` glue file contains the export names, the memory layout constants
  (`STATIC_BASE`, `STACK_MAX`), and often the original C function names in
  `_malloc`, `_main`, `_check_flag` form (leading underscore).
- `-g`/`--profiling-funcs` builds keep a **name section**: `wasm-objdump -x` then shows real
  function names. Check for it before doing anything hard.
- Emscripten's `EM_ASM`/`emscripten_run_script` calls appear as imports into `env` - reading
  those import names tells you what the module does.
- `--closure 1` minifies the glue JS; deobfuscate it with the techniques in
  `javascript-deobfuscation`.

## Variants & pitfalls

- **Missing name section** means functions are `$func12`. Use `wasm2wat --generate-names`
  and rename as you learn what each does; `wasm-decompile` output is easier to annotate.
- **`br` depth arithmetic** trips everyone: `br 0` targets the innermost enclosing
  block/loop, `br 1` the next one out. `--fold-exprs` output makes the nesting explicit.
- **`call_indirect`** targets come from the table section (`wasm-objdump -x`, `Elem[]`);
  resolve the index to a function to recover the call graph.
- **Memory growth** invalidates any `Uint8Array` view you kept; re-create the view after a
  call that may `memory.grow`.
- **The flag is rarely a literal**: expect per-byte transforms compared against a data
  segment. Extract the expected array from the data section and invert it - see
  `crackme-patterns`.
- **Constraint-heavy checkers** translate cleanly to z3: the wat is already a small
  straight-line arithmetic program. See `z3-constraint-solving`.
- **A custom VM inside wasm** is not unheard of; the playbook is `custom-vm-bytecode`.

## Tools

- `wabt`: `wasm2wat`, `wat2wasm`, `wasm-objdump`, `wasm-decompile`, `wasm2c`, `wasm-strip`.
- `binaryen`: `wasm-dis`, `wasm-opt`, `wasm-metadce`.
- `wasmtime` / `wasmer` / `wasm3` - standalone execution and `--invoke`.
- Chrome / Firefox DevTools - wasm disassembly, breakpoints, memory inspector.
- `ghidra-wasm-plugin` - loader and decompiler for Ghidra.

## References

- The WebAssembly Core Specification (binary format section layout, instruction encodings,
  and the structured control-flow semantics described above).
- WABT tool documentation for `wasm2wat`, `wasm-objdump` and `wasm-decompile` flags.
- MDN documentation for `WebAssembly.instantiate` and `WebAssembly.Memory`.
