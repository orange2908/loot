---
title: "C++ RE - Vtables, RTTI and STL Layouts"
category: rev
subcategory: cpp
type: technique
tags: [cpp, itanium-abi, name-mangling, cxxfilt, undname, vtable, rtti, virtual-call, constructor, destructor, stl, std-string, sso, std-vector, std-map, shared-ptr, exceptions, cxa-throw, ghidra, gdb]
difficulty: medium
summary: "Demangle Itanium/MSVC symbols, read vtables and RTTI out of .data.rel.ro, and decode std::string/vector/map layouts so C++ decompilation stops being pointer soup."
when_to_use:
  - "`nm` shows `_ZN...` or `?name@Class@@QEAA...@Z` symbols"
  - "Indirect calls of the form `mov rax,[rdi]; call qword [rax+0x10]`"
  - "The decompiler shows 32-byte stack objects whose first field points 16 bytes into itself"
  - "You need to know which concrete subclass a `Base*` actually holds"
  - "Functions are fragmented by `__cxa_throw` / landing-pad blocks you cannot follow"
tools: [ghidra, ida, gdb, cxxfilt, undname, pyelftools, radare2, python]
related: [triage-unknown-binary, ghidra-workflow, ida-r2-binja-workflow, go-binaries, rust-binaries, windows-pe-reversing, crackme-patterns]
---

## TL;DR

C++ leaves three gifts in the binary: mangled names that encode full signatures, vtables that
enumerate every virtual method of every class, and RTTI that names the classes outright. Read
them and you can reconstruct the class hierarchy; then apply the fixed STL layouts and the
"random pointer arithmetic" in the decompiler turns into `s.size()` and `v[i]`.

## Recognise it

| Signal | Check |
|---|---|
| Mangled names | `nm -C ./bin` gives `foo::bar(int)`; MSVC instead shows `?bar@foo@@QEAAHH@Z` |
| Vtables | `.data.rel.ro` (PIE) or `.rodata` full of `_ZTV*` symbols |
| RTTI | `_ZTI*` / `_ZTS*` symbols, or the literal strings `3foo`, `N3foo3barE` |
| Virtual calls | `mov rax,[rdi]; call qword [rax+0x10]` |
| Exceptions | imports of `__cxa_throw`, `__cxa_begin_catch`, `_Unwind_Resume`; section `.gcc_except_table` |
| STL | calls to `_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE...` |

```sh
# Demangle everything; -n stops c++filt from stripping a leading underscore (macOS/PE)
nm ./bin | c++filt -n | grep '::'
# List every vtable and its symbol size (size/8 - 2 = number of virtual slots)
readelf -sW ./bin | grep ' OBJECT ' | grep _ZTV
# The RTTI type-name strings, unmangled
strings -a ./bin | grep -E '^N?[0-9]+[A-Za-z]' | c++filt -t
# MSVC, on Windows or under wine
undname "?bar@foo@@QEAAHH@Z"
```

## How it works

### Itanium mangling

```text
_ZN3foo3barEi
 ^^ ^  ^   ^`-- i          = parameter list: int
 |  |  |   `--- E          = end of nested name
 |  |  `------- 3bar       = member "bar"
 |  `---------- 3foo       = class/namespace "foo"
 `------------- _ZN        = mangled, nested name follows
                            => foo::bar(int)
```

| Fragment | Meaning |
|---|---|
| `_Z` | prefix; `_ZN...E` = nested (namespace/class) name |
| `<len><name>` | length-prefixed component, repeated |
| `C1`/`C2` | complete / base-object **constructor** |
| `D0`/`D1`/`D2` | deleting / complete / base-object **destructor** |
| `v i c a s l x j m y f d` | void, int, char, signed char, short, long, long long, unsigned int, unsigned long, unsigned long long, float, double |
| `Pi`, `PKc` | `int*`, `const char*`; `K` before a component = `const` member fn |
| `S_`, `S0_`, `St` | back-references to earlier substitutions; `St` = `std::` |
| `_ZTV3foo` | **vtable** for `foo`; `_ZTI3foo` = typeinfo; `_ZTS3foo` = typeinfo name string |
| `_ZThn16_N...` | non-virtual **thunk**, this-adjustment -16 (multiple inheritance) |

MSVC is a different scheme entirely:

```text
?bar@foo@@QEAAHH@Z
 ^   ^    ^^^^ ^^ ^-- Z  = end
 |   |    ||||  `----- H  = parameter: int
 |   |    ||||`------- H  = return type: int
 |   |    |||`-------- A  = no special modifiers
 |   |    ||`--------- E  = __cdecl (64-bit)
 |   |    |`---------- A  = near
 |   |    `----------- Q  = public, non-static member
 |   `---------------- foo@@ = class foo
 `-------------------- ?bar = method name     => public: int __cdecl foo::bar(int)
```

`undname.exe` (ships with MSVC) decodes these; note that MSVC puts the class *after* the method.

### Vtable layout (Itanium, x86-64)

For a class with virtual methods, `_ZTV3foo` in `.data.rel.ro` is:

```text
offset  content
-0x10   offset-to-top   (0 for the primary vtable; negative for secondary bases)
-0x08   typeinfo*       (-> _ZTI3foo)
+0x00   &foo::method0   <-- the *vptr* stored in each object points HERE
+0x08   &foo::method1
+0x10   &foo::method2
```

The symbol `_ZTV3foo` addresses the offset-to-top word, so the vptr value stored in an object is
`&_ZTV3foo + 0x10`. A virtual call is therefore:

```asm
mov  rax, qword [rdi]        ; load vptr from this+0
call qword [rax + 0x10]      ; slot 2 -> the third virtual method
```

Slot index = displacement / 8. Match that against the vtable dump to name the callee. With
multiple inheritance you also see `_ZThn<N>_` thunks that subtract from `this` before jumping.

### RTTI

| Symbol | Meaning |
|---|---|
| `_ZTS3foo` | the type *name* string, e.g. `"3foo"` (mangled, feed to `c++filt -t`) |
| `_ZTI3foo` | `std::type_info` object: `{ vptr-to-__class_type_info, name_ptr }` |
| `__class_type_info` | no base classes |
| `__si_class_type_info` | exactly one public non-virtual base: adds `base_type*` |
| `__vmi_class_type_info` | virtual/multiple inheritance: flags, base_count, then `(base, offset_flags)[]` |

Follow `typeinfo -> __si_class_type_info -> base_type` repeatedly for the inheritance chain.
MSVC uses a **Complete Object Locator** at `vtable[-1]` instead: signature, offset, cdOffset,
`TypeDescriptor*` (whose `.name` is `.?AVfoo@@`) and a `ClassHierarchyDescriptor*` listing every
base. Ghidra's **RTTI Analyzer** (*Analyze All*, GCC and MSVC) populates *Symbol Tree -> Classes*;
IDA does the same with its RTTI parsing plus **HexRaysPyTools** (`Shift+F9`, "Reconstruct type").

### Rebuilding a class in Ghidra

1. Dump the vtable (`vtable_dump.py` below, or the RTTI analyser) to get the slot list.
2. *Data Type Manager* -> New -> Structure `foo_vftable`, one `void *` per slot, renamed to the
   demangled method names.
3. New Structure `foo`: field 0 is `foo_vftable *vptr`, then the data members you discover.
4. On each method: *Edit Function Signature*, first parameter `foo * this`, convention
   `__thiscall`. Apply `foo *` at the call site and Ghidra resolves `[rax+0x10]` to the slot.

### Constructors and destructors

A constructor is recognisable because it **stores a vtable pointer into `this+0`** and is
usually called right after an allocation:

```asm
call operator new(unsigned long)      ; _Znwm
mov  rdi, rax
lea  rax, [rip+0x2f10]                ; &_ZTV3foo + 0x10
mov  qword [rdi], rax                 ; <-- vptr store = ctor (or dtor) body
```

Destructors store the vptr too (to disable virtual dispatch during destruction), then call member
destructors in reverse declaration order. If a function stores a vptr and calls `operator delete`
(`_ZdlPv`), it is `D0`; if it stores a vptr and destroys sub-objects without freeing, `D1`/`D2`.

### libstdc++ STL layouts (x86-64, `_GLIBCXX_USE_CXX11_ABI=1`)

| Type | Size | Layout |
|---|---|---|
| `std::string` | 32 | `{ char *ptr; size_t size; union { char buf[16]; size_t capacity; }; }` |
| `std::vector<T>` | 24 | `{ T *begin; T *end; T *cap_end; }` - `size() == (end-begin)/sizeof(T)` |
| `std::map`/`set` | 48 | `{ cmp; _Rb_tree_header{ _Rb_tree_node_base header; size_t node_count; } }` |
| RB-tree node | 32+T | `{ int color; node *parent; node *left; node *right; T value; }` |
| `std::unordered_map` | 56 | `{ bucket **buckets; size_t bucket_count; node *before_begin; size_t element_count; float max_load_factor; ...}` |
| `std::shared_ptr<T>` | 16 | `{ T *ptr; __shared_count { _Sp_counted_base *ctrl } }`; ctrl = `{vptr, use_count u32, weak_count u32}` |
| `std::unique_ptr<T>` | 8 | just the pointer (stateless deleter) |
| `std::list` | 24 | `{ prev; next; size_t }` sentinel node; `std::deque` is 80 (map-of-blocks + 4 iterators) |

**SSO is the killer detail.** `std::string` is 32 bytes; for strings <= 15 chars, `ptr` points at
`this+16` (its own inline buffer) and the union holds the characters. For longer strings `ptr` is
heap and the union holds the capacity. So:

```c
// Ghidra shows this; it means "the string is short, data is inline"
if (*(char **)obj == obj + 0x10) { /* SSO active */ }
```

MSVC differs: `std::string` is 32 bytes as `{ union { char buf[16]; char *ptr; }; size_t size;
size_t capacity; }` - the buffer comes **first** and the SSO threshold is 15 chars with
`capacity < 16` as the test. MSVC `std::vector` is also 24 bytes `{first, last, end}` but the
debug build adds an iterator-debug list, changing the size.

### Reading them in gdb

```sh
# libstdc++ pretty-printers are usually already loaded by the gdb that ships with the distro
gdb -q ./bin -ex 'break main' -ex run
```

```text
(gdb) set print object on          # show the *dynamic* type behind a Base* (uses RTTI)
(gdb) set print pretty on
(gdb) p *base_ptr                  # prints "(Derived) { ... }" instead of "(Base) { ... }"
(gdb) p s                          # pretty printer: $1 = "hello"
(gdb) x/4gx &s                     # manual: ptr, size, then the 16-byte SSO union
(gdb) p *(unsigned long *)((char*)&s + 8)     # the length, read by hand
(gdb) p v                          # $2 = std::vector of length 3, capacity 4 = {1, 2, 3}
(gdb) x/3gx &v                     # begin, end, cap_end
(gdb) p (*(long*)((char*)&v+8) - *(long*)&v) / 4    # size() of a vector<int>, by hand
(gdb) info vtbl base_ptr           # dump the object's vtable with resolved symbols
(gdb) p /a *(void ***)base_ptr     # the raw vptr value
```

### Exceptions fragment functions

`throw X{}` becomes:

```asm
mov  edi, 8
call __cxa_allocate_exception
mov  rdi, rax
lea  rsi, [rip+0x...]     ; &_ZTI1X  (typeinfo of the thrown type)
lea  rdx, [rip+0x...]     ; destructor for the exception object, or 0
call __cxa_throw          ; noreturn
```

The unwinder reads `.eh_frame` and `.gcc_except_table` (an LSDA per function: call-site table,
action table, and a type-info table listing the `catch` types). Consequences for you:

* Functions get split into a "normal" path and cold **landing pads** that the decompiler shows as
  separate, unreachable-looking blocks. Ghidra marks them `catch` / `LAB_...`; IDA shows them
  after the function's `retn`.
* `__cxa_throw` is `noreturn`, so the decompiler truncates the block right there - follow the
  LSDA or just break on `__cxa_throw` at runtime.
* A check written as "throw on failure" has **no comparison in the success path**: the
  `__cxa_throw` call sites are the validation logic. `catch (...)` appears as an
  `__cxa_begin_catch` / `__cxa_end_catch` pair.

```sh
# Where can this binary throw from, and what types does it catch?
objdump -d ./bin | grep -n '__cxa_throw' | head
readelf -x .gcc_except_table ./bin | head -20
# Break on every throw and print the typeinfo name
gdb -q ./bin -ex 'break __cxa_throw' -ex run -ex 'p (char*)*(long*)((long)$rsi+8)'
```

## Workflow

1. `nm -C ./bin | grep -E ' [TW] ' | grep '::'` - the class list falls out of the symbol names.
2. Let Ghidra's RTTI analyser run, check *Symbol Tree -> Classes*, then dump each vtable with
   `vtable_dump.py` and name the slots.
3. Build `<Class>_vftable` and `<Class>` structs; set `this` as parameter 1 on every method.
4. Retype STL locals: 32-byte blob -> `std::string`, 24-byte triple-pointer -> `std::vector`.
5. At runtime, `set print object on` and `info vtbl obj` to learn the concrete subclass.
6. If the logic hides behind exceptions, break on `__cxa_throw` and read the typeinfo.

## Code

### Source and its vtable

```cpp
struct Check {                       // _ZTV5Check: [-0x10]=0, [-0x8]=&_ZTI5Check
    virtual ~Check();                //   +0x00 -> _ZN5CheckD1Ev   (complete dtor)
    virtual bool test(const char*);  //   +0x08 -> _ZN5CheckD0Ev   (deleting dtor)
    int key;                         //   +0x10 -> _ZN5Check4testEPKc
};                                   //   +0x18 -> _ZN5Check6finishEv
struct Xor : Check {                 // _ZTV3Xor: same shape, test/finish overridden
    bool test(const char*) override; //   +0x10 -> _ZN3Xor4testEPKc
};
```

Both destructor variants take the first two slots (GCC emits `D1` then `D0`), so the first
*real* method of a polymorphic class is usually at `+0x10`.

### Dump a vtable and resolve every slot

```python
#!/usr/bin/env python3
"""Dump C++ vtables from an ELF and resolve each slot to a symbol name.

Needs pyelftools:  pip install pyelftools
Usage: python3 vtable_dump.py ./bin [_ZTV5Check | Check | --all]
"""
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def load(path):
    """-> (elf, {func_addr: name}, [(vtable_name, addr, size)])."""
    elf = ELFFile(open(path, "rb"))
    addr2sym, vtables = {}, []
    for sec in elf.iter_sections():
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            val, size = sym["st_value"], sym["st_size"]
            if not sym.name or not val:
                continue
            if sym["st_info"]["type"] == "STT_FUNC" or sym.name.startswith("_ZTI"):
                addr2sym.setdefault(val, sym.name)      # funcs + typeinfo objects
            if sym.name.startswith("_ZTV"):
                vtables.append((sym.name, val, size))
    return elf, addr2sym, vtables


def read_vaddr(elf, vaddr, n):
    """Read n bytes at a virtual address by walking the PT_LOAD segments."""
    for seg in elf.iter_segments():
        lo, hi = seg["p_vaddr"], seg["p_vaddr"] + seg["p_filesz"]
        if seg["p_type"] == "PT_LOAD" and lo <= vaddr and vaddr + n <= hi:
            return seg.data()[vaddr - lo: vaddr - lo + n]
    return None


def demangle(names):
    """Batch-demangle through c++filt; fall back to the raw names if it is missing."""
    if not names:
        return {}
    try:
        out = subprocess.run(["c++filt", "-n"], input="\n".join(names),
                             capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return {n: n for n in names}
    return dict(zip(names, out.splitlines()))


def relocations(elf):
    """{offset: symbol_or_addend} from RELA sections - PIE vtables are filled by relocs."""
    out = {}
    for sec in elf.iter_sections():
        if sec.header["sh_type"] != "SHT_RELA":
            continue
        for rel in sec.iter_relocations():
            out[rel["r_offset"]] = rel["r_addend"]
    return out


def dump_one(elf, addr2sym, relocs, name, addr, size):
    print("\n== %s  @0x%x  (%d bytes)" % (name, addr, size))
    raw = read_vaddr(elf, addr, size)
    if raw is None:
        print("   (not in a PT_LOAD segment)")
        return
    words = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, len(raw) - 7, 8)]
    if len(words) >= 2:
        top = words[0] - (1 << 64) if words[0] >> 63 else words[0]
        print("   -0x10 offset-to-top = %d" % top)
        print("   -0x08 typeinfo      = 0x%x %s"
              % (words[1] or relocs.get(addr + 8, 0),
                 addr2sym.get(words[1] or relocs.get(addr + 8, 0), "")))
    slots = words[2:]
    targets = []
    for i, w in enumerate(slots):
        if w == 0:                                   # PIE: value lives in the relocation
            w = relocs.get(addr + 16 + i * 8, 0)
        targets.append(w)
    pretty = demangle([addr2sym.get(t, "") for t in targets if addr2sym.get(t)])
    for i, t in enumerate(targets):
        sym = addr2sym.get(t, "")
        print("   +0x%02x  0x%012x  %s" % (i * 8, t, pretty.get(sym, sym or "<unknown>")))


def main(argv):
    path = argv[1] if len(argv) > 1 else "./bin"
    want = argv[2] if len(argv) > 2 else "--all"
    elf, addr2sym, vtables = load(path)
    relocs = relocations(elf)
    if not vtables:
        print("no _ZTV* symbols (stripped? use the Ghidra RTTI analyser instead)")
        return 1
    hits = [v for v in vtables if want == "--all" or want in v[0]]
    for name, addr, size in sorted(hits, key=lambda v: v[1]):
        dump_one(elf, addr2sym, relocs, name, addr, size)
    print("\n# %d vtable(s)" % len(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

```text
== _ZTV5Check  @0x3d90  (48 bytes)     <- expected output shape
   -0x10 offset-to-top = 0
   -0x08 typeinfo      = 0x3dc0 _ZTI5Check
   +0x00  0x000000001520  Check::~Check()
   +0x10  0x0000000013a0  Check::test(char const*)
```

## Variants & pitfalls

* **`c++filt -n`** does *not* strip a leading underscore - needed for Mach-O and PE symbols.
* **PIE binaries have empty vtables on disk** - the slots are zero and the real addresses live in
  `R_X86_64_RELATIVE` relocations, which is why the script consults the RELA table.
* **`-fno-rtti`** removes typeinfo but keeps vtables: slot lists without class names. With
  `final`/LTO the compiler may devirtualise, so a slot can have no call site anywhere.
* **The old libstdc++ ABI** (`_GLIBCXX_USE_CXX11_ABI=0`) makes `std::string` an **8-byte**
  COW pointer to `{length, capacity, refcount, chars...}`. If a "string" is one word, that is it.
* **Multiple inheritance** gives an object several vptrs at different offsets; `_ZThn16_` thunks
  adjust `this` before forwarding. Ghidra's `this` typing breaks here - fix it manually.
* **Pure virtual** slots point at `__cxa_pure_virtual` - a vtable full of them is abstract.
* **MSVC vtables** live in `.rdata` with the COL at `vtable[-1]`, and pass `this` in **RCX**
  (ECX on x86) rather than RDI.
* **`std::map` iterates in sorted key order**, so a `map<char,int>` built from a flag loses the
  original ordering - recover it from the values, not the traversal.
* **Inlined STL**: at `-O2` `std::vector::operator[]` disappears into `[base + idx*4]`; you must
  recognise the three-pointer header yourself.
* **Lambdas / `std::function`** become a heap closure plus a manager function pointer; the body
  is a separate `operator()` symbol carrying `$_0`.

## Tools

* **`c++filt` / `nm -C` / `objdump -Cd`** - Itanium demangling throughout binutils;
  **`undname.exe`** (MSVC) or `demumble` for MSVC symbols.
* **Ghidra** RTTI Analyzer + *Data Type Manager* structures; *Symbol Tree -> Classes*.
* **IDA** + **HexRaysPyTools** - vtable-driven struct reconstruction, `this` typing.
* **gdb**: `set print object on`, `info vtbl`, libstdc++ pretty printers.
* **pyelftools** - scripted section/symbol/relocation access, as used above.

## References

- Itanium C++ ABI specification (mangling, vtable layout, RTTI, `__cxa_*`):
  itanium-cxx-abi.github.io/cxx-abi/abi.html
- libstdc++ headers `bits/basic_string.h`, `bits/stl_vector.h`, `bits/stl_tree.h` - the exact
  field order quoted above; `libsupc++/eh_throw.cc` for the throw path.
- pyelftools: github.com/eliben/pyelftools
