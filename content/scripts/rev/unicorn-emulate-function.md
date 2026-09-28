---
title: "Unicorn - Emulate One Function Out of a Binary"
category: rev
subcategory: unicorn
type: script
tags: [unicorn, emulation, unicorn-engine, capstone, elf, pt-load, sysv-abi, shellcode, oracle, brute-force, side-channel, plt, libc, aarch64, arm-thumb, disassembler, python, instruction-counting, hooks]
summary: "Dependency-light Unicorn harness: stdlib ELF loader, SysV argument setup, sentinel return, libc stubs, capstone tracer and a brute-force oracle, with a shellcode self-test."
tools: [unicorn, capstone, python, ghidra]
related: [unicorn-qiling-emulation, side-channel-instruction-counting, angr-template, z3-flagsolver-template, crackme-patterns, custom-vm-bytecode, shellcode-analysis, triage-unknown-binary]
---

## What this is

A checker function you can read but not easily invert, in a binary you cannot
run (wrong arch, wrong libc, anti-debug in `main`). Emulate just that function:
map its segments, set up a stack, put the arguments in the right registers, give
it a fake return address, run a few hundred instructions - then use it as an
oracle. `pip install unicorn capstone`; ELF parsing is stdlib `struct`, so no
pyelftools and no binutils are needed.

## Usage

```bash
# Prove the harness works with no target at all (hand-assembled shellcode)
python3 ucemu.py

# check(buf, out, len) at a symbol, feeding it a candidate flag
python3 ucemu.py ./chal --func check --input "CTF{aaaa}" --args in,out,len --out-len 32

# By address, signature f(buf, len); constants work too (--args in,len,0x1337).
# --trace adds a full capstone instruction trace - pipe it to a file.
python3 ucemu.py ./chal --func 0x401230 --args in,len --input AAAABBBB --trace
```

## The harness

```python
#!/usr/bin/env python3
"""Emulate one function out of an ELF with Unicorn. Self-test: python3 ucemu.py"""
import argparse
import struct
import sys

from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED,
                     UC_MODE_64, UC_PROT_ALL, Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RAX,
                               UC_X86_REG_RBP, UC_X86_REG_RCX, UC_X86_REG_RDI,
                               UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RSP)

PAGE, MASK64 = 0x1000, (1 << 64) - 1
STACK, STACK_SIZE = 0x7FF00000, 0x00100000        # stack
SCRATCH, SCRATCH_SIZE = 0x10000000, 0x00010000    # input/output buffers
HEAP, HEAP_SIZE = 0x20000000, 0x00100000          # malloc arena
CODE_BASE, MAGIC_RET = 0x00400000, 0x00BE0000     # shellcode base, ret sentinel
PT_LOAD, SHT_SYMTAB, SHT_DYNSYM = 1, 2, 11

# SysV AMD64: integer/pointer args in this order, return value in RAX.
ARG_REGS = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
            UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
REGS = {"rax": UC_X86_REG_RAX, "rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI,
        "rdx": UC_X86_REG_RDX, "rcx": UC_X86_REG_RCX, "rsp": UC_X86_REG_RSP,
        "rbp": UC_X86_REG_RBP, "rip": UC_X86_REG_RIP}


def parse_elf(data):
    """Minimal stdlib ELF reader: PT_LOAD segments plus the symbol table."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    w = 8 if data[4] == 2 else 4                     # 64- or 32-bit
    e = "<" if data[5] == 1 else ">"                 # endianness
    if w == 8:   # Elf64_Phdr: type flags offset vaddr paddr filesz memsz
        pfmt, pick = e + "IIQQQQQ", (0, 2, 3, 5, 6)  # -> type offset vaddr f m
        shfmt, sfmt, ssz = e + "IIQQQQII", e + "I4xQ", 24
    else:        # Elf32_Phdr: type offset vaddr paddr filesz memsz flags
        pfmt, pick = e + "IIIIIII", (0, 1, 2, 4, 5)
        shfmt, sfmt, ssz = e + "IIIIIIII", e + "II", 16
    q = "Q" if w == 8 else "I"
    entry, phoff, shoff = struct.unpack_from(e + q * 3, data, 0x18)
    phentsize, phnum, shentsize, shnum = struct.unpack_from(
        e + "HHHH", data, 0x36 if w == 8 else 0x2A)

    segments = []
    for i in range(phnum):
        v = struct.unpack_from(pfmt, data, phoff + i * phentsize)
        t, off, va, fsz, msz = (v[k] for k in pick)
        if t == PT_LOAD:
            segments.append((va, msz, data[off:off + fsz]))

    syms = {}
    for i in range(shnum):   # Shdr: name type flags addr offset size link info
        v = struct.unpack_from(shfmt, data, shoff + i * shentsize)
        if v[1] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        stroff = struct.unpack_from(shfmt, data, shoff + v[6] * shentsize)[4]
        for j in range(v[5] // ssz):     # Sym: name .. value (see sfmt above)
            name, val = struct.unpack_from(sfmt, data, v[4] + j * ssz)
            if name and val:
                z = data.index(b"\x00", stroff + name)
                syms[data[stroff + name:z].decode("utf-8", "replace")] = val
    return {"bits": w * 8, "entry": entry, "segments": segments, "symbols": syms}


# libc replacements: real Python, run instead of the PLT stub.
def stub_strlen(e):
    e.w("rax", len(e.cstring(e.r("rdi"))))


def stub_memcpy(e):
    d, s, n = e.r("rdi"), e.r("rsi"), e.r("rdx")
    e.uc.mem_write(d, bytes(e.uc.mem_read(s, n)))
    e.w("rax", d)


def stub_puts(e):
    s = e.cstring(e.r("rdi"))
    e.stdout += s + b"\n"
    e.w("rax", len(s) + 1)


def stub_malloc(e):
    e.w("rax", e.brk)                      # bump allocator, never freed
    e.brk += max((e.r("rdi") + 15) & ~15, 16)


LIBC = {"strlen": stub_strlen, "memcpy": stub_memcpy,
        "puts": stub_puts, "malloc": stub_malloc}


class Emu(object):
    def __init__(self, trace=False, max_insns=2000000):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.trace, self.max_insns = trace, max_insns
        self.icount, self.stdout, self.brk = 0, b"", HEAP
        self.stubs, self.symbols = {}, {}
        self._resume = self._abort = self.cs = None
        if trace:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        for base, size in ((STACK, STACK_SIZE), (SCRATCH, SCRATCH_SIZE),
                           (HEAP, HEAP_SIZE), (MAGIC_RET, PAGE)):
            self.map(base, size)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

    def r(self, name):
        return self.uc.reg_read(REGS[name])

    def w(self, name, val):
        self.uc.reg_write(REGS[name], val & MASK64)

    def map(self, addr, size):
        """Align the base down and the length up - mem_map insists on both."""
        base = addr & ~(PAGE - 1)
        size = (size + (addr - base) + PAGE - 1) & ~(PAGE - 1)
        try:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            pass                                   # already mapped; harmless

    def write(self, addr, data):
        self.map(addr, len(data))
        self.uc.mem_write(addr, bytes(data))
        return addr

    def cstring(self, addr, limit=4096):
        out = bytearray()
        while len(out) < limit and self.uc.mem_read(addr + len(out), 1)[0]:
            out += self.uc.mem_read(addr + len(out), 1)
        return bytes(out)

    def load_elf(self, path):
        """Map every PT_LOAD at its p_vaddr, then wire the libc stubs onto any
        matching symbol so calls land in Python."""
        with open(path, "rb") as fh:
            elf = parse_elf(fh.read())
        for vaddr, memsz, blob in elf["segments"]:
            self.map(vaddr, max(memsz, len(blob)))
            self.uc.mem_write(vaddr, blob)
        self.symbols = elf["symbols"]
        for name, fn in LIBC.items():
            for cand in (name, name + "@plt", "_" + name):
                if cand in self.symbols:
                    self.stubs[self.symbols[cand]] = fn
        return elf

    def _hook_unmapped(self, uc, access, address, size, value, user):
        """Lazy mapping: map on demand, return True to retry the access.
        Return False instead and emulation aborts - what you want when you
        are hunting a real null-pointer dereference."""
        self.map(address, PAGE * 4)
        return True

    def _hook_code(self, uc, address, size, user):
        self.icount += 1
        if self.icount > self.max_insns:
            self._abort = "instruction budget of %d exceeded" % self.max_insns
            uc.emu_stop()
            return
        fn = self.stubs.get(address)
        if fn is not None:
            # PLT dispatch: run the Python model, then SKIP the call by popping
            # the return address off the stack and resuming there.
            fn(self)
            sp = uc.reg_read(UC_X86_REG_RSP)
            self._resume = struct.unpack("<Q", uc.mem_read(sp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, sp + 8)
            uc.emu_stop()
            return
        if self.trace:
            for ins in self.cs.disasm(bytes(uc.mem_read(address, size)), address):
                print("%#010x  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))

    def call(self, addr, *args, **kw):
        """Run one function to completion: args into RDI/RSI/RDX/RCX/R8/R9,
        MAGIC_RET pushed as the return address, emu_start stopping the instant
        RIP reaches it. The loop resumes after each dispatched libc stub."""
        for i, a in enumerate(args):
            self.uc.reg_write(ARG_REGS[i], a & MASK64)
        sp = STACK + STACK_SIZE - 0x1000 - 8
        self.uc.mem_write(sp, struct.pack("<Q", MAGIC_RET))
        self.w("rsp", sp)
        self.w("rbp", sp)
        self.icount, self._abort, pc = 0, None, addr
        while True:
            self._resume = None
            try:
                self.uc.emu_start(pc, MAGIC_RET, timeout=kw.get("timeout", 10000000))
            except UcError as exc:
                raise RuntimeError("fault at %#x after %d insns: %s"
                                   % (self.r("rip"), self.icount, exc))
            if self._abort:
                raise RuntimeError(self._abort)
            if self._resume is None:
                return self.r("rax")
            pc = self._resume


def brute_force(emu, func, key_ptr, n, charset=None):
    """Byte-by-byte attack using the emulated function as an oracle. `func`
    must leak partial progress - here, the matching prefix length."""
    charset, buf = charset or bytes(range(0x20, 0x7F)), bytearray(n)
    for i in range(n):
        for c in charset:
            buf[i] = c
            emu.write(SCRATCH, bytes(buf))
            if emu.call(func, SCRATCH, n, key_ptr) > i:
                break
        else:
            raise RuntimeError("no candidate byte at offset %d" % i)
    return bytes(buf)


# self-test shellcode - no external binary needed.
# unsigned long sum_xor(char *buf, unsigned long n) -> sum of buf[i] ^ i
# xor eax,eax / xor ecx,ecx / L: cmp rcx,rsi / jae out / movzx edx,[rdi+rcx] /
# xor edx,ecx / add eax,edx / inc rcx / jmp L / out: ret
SUM_XOR = bytes.fromhex("31c031c94839f1730d0fb6140f31ca01d048ffc1ebeec3")
# unsigned long lcp(char *a, unsigned long n, char *key) -> matching prefix len
# xor eax,eax / L: cmp rax,rsi / jae out / mov cl,[rdi+rax] / cmp cl,[rdx+rax] /
# jne out / inc rax / jmp L / out: ret
LCP = bytes.fromhex("31c04839f0730d8a0c073a0c02750548ffc0ebeec3")
SECRET = b"CTF{un1c0rn_0racle}"


def self_test(trace=False):
    emu = Emu(trace=trace)

    # 1. Call a function with a buffer argument and read the return value.
    data, code = b"Hello, Unicorn!", emu.write(CODE_BASE, SUM_XOR)
    emu.write(SCRATCH, data)
    got = emu.call(code, SCRATCH, len(data)) & 0xFFFFFFFF
    assert got == sum(b ^ i for i, b in enumerate(data)) & 0xFFFFFFFF
    print("[*] sum_xor        -> %#x in %d instructions" % (got, emu.icount))

    # 2. PLT dispatch: sub rsp,8 / call strlen / add rsp,8 / ret, strlen stubbed
    plt = emu.write(CODE_BASE + 0x2000, b"\x00")
    emu.stubs[plt] = stub_strlen
    body = b"\x48\x83\xec\x08"
    body += b"\xe8" + struct.pack("<i", plt - (CODE_BASE + 0x100 + len(body) + 5))
    caller = emu.write(CODE_BASE + 0x100, body + b"\x48\x83\xc4\x08\xc3")
    emu.write(SCRATCH + 0x100, b"twelve chars\x00")
    n = emu.call(caller, SCRATCH + 0x100)
    assert n == 12
    print("[*] stubbed strlen -> %d" % n)

    # 3. Oracle-driven brute force against the emulated comparison function.
    lcp = emu.write(CODE_BASE + 0x1000, LCP)
    key = emu.write(SCRATCH + 0x800, SECRET)
    found = brute_force(emu, lcp, key, len(SECRET))
    assert found == SECRET
    print("[*] brute force    -> %r" % found)
    print("[+] self-test OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Unicorn single-function emulator")
    ap.add_argument("binary", nargs="?", help="ELF to load (omit to self-test)")
    ap.add_argument("--func", help="symbol name or 0xADDR")
    ap.add_argument("--input", default="AAAA", help="bytes written to scratch")
    ap.add_argument("--args", default="in,out,len", help="in|out|len|<number>")
    ap.add_argument("--out-len", type=int, default=0, help="dump N bytes of out")
    ap.add_argument("--trace", action="store_true", help="capstone trace")
    args = ap.parse_args(argv)
    if args.binary is None:
        return self_test(trace=args.trace)
    emu = Emu(trace=args.trace)
    elf = emu.load_elf(args.binary)
    if args.func is None:
        addr = elf["entry"]
    else:
        addr = (int(args.func, 16) if args.func.startswith("0x")
                else emu.symbols[args.func])
    buf = args.input.encode()
    emu.write(SCRATCH, buf + b"\x00")
    out = emu.write(SCRATCH + 0x1000, b"\x00" * 0x100)   # result buffer
    table = {"in": SCRATCH, "out": out, "len": len(buf)}
    call_args = [table[t.strip()] if t.strip() in table else int(t, 0)
                 for t in args.args.split(",")]
    ret = emu.call(addr, *call_args)
    print("[+] %s(%s) = %#x in %d insns" % (args.func or "entry",
          ", ".join("%#x" % a for a in call_args), ret, emu.icount))
    if emu.stdout:
        print("[+] stdout : %r" % emu.stdout)
    if args.out_len:
        print("[+] out buf: %r" % bytes(emu.uc.mem_read(out, args.out_len)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## How the pieces fit

- **`parse_elf`** reads `PT_LOAD` headers and `.symtab`/`.dynsym`, 64- and
  32-bit. A stripped binary yields an empty symbol dict - use `--func 0xADDR`.
- **Memory map**: segments at their real vaddrs, plus stack, scratch and a
  `malloc` heap placed far apart so a wild pointer faults loudly. Anything else
  is mapped lazily by the `UC_HOOK_MEM_UNMAPPED` hook.
- **`MAGIC_RET`** is the whole trick: `emu_start(pc, MAGIC_RET)` stops the
  instant RIP reaches it and we push it as the return address, so `ret` ends
  the run cleanly. It must be mapped and unreachable any other way.
- **Stub dispatch** is `{address: python_function}` consulted in `UC_HOOK_CODE`:
  run the model, pop the return address, resume there. Aim it at the PLT stub
  for an import or the function itself in a static binary; `emu_stop()` plus the
  resume loop in `call()` beats writing RIP from inside a hook.
- **`brute_force`** is the payoff: 19 bytes from 19*95 emulated calls, well under
  a second. Record `icount` per candidate instead of the return value and you
  have an instruction-count side channel.

## AArch64 and ARM/Thumb

Same harness, different constants.

```python
#!/usr/bin/env python3
"""Runnable: python3 armemu.py - add-and-return on AArch64 and ARM Thumb."""
from unicorn import (UC_ARCH_ARM, UC_ARCH_ARM64, UC_MODE_ARM, UC_MODE_THUMB,
                     UC_PROT_ALL, Uc)
from unicorn.arm64_const import (UC_ARM64_REG_LR, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1)
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

CODE, STACK, RETADDR = 0x00400000, 0x7FF00000, 0x00BE0000
# (code, arch, mode, (sp, lr, arg0, arg1), thumb_bit)
# AAPCS64: args X0-X7, return in X0, `ret` branches to LR.
A64 = (bytes.fromhex("0000018bc0035fd6"), UC_ARCH_ARM64, UC_MODE_ARM,
       (UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X1), 0)
# AAPCS32: args R0-R3, return in R0. The low bit of an address is the Thumb bit
# - OR it into the start address AND into LR, or you fault immediately.
T32 = (bytes.fromhex("40187047"), UC_ARCH_ARM, UC_MODE_THUMB,
       (UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1), 1)


def run(spec, a, b):
    code, arch, mode, (sp, lr, r0, r1), thumb = spec
    uc = Uc(arch, mode)
    for base, size in ((CODE, 0x1000), (STACK, 0x10000), (RETADDR, 0x1000)):
        uc.mem_map(base, size, UC_PROT_ALL)
    uc.mem_write(CODE, code), uc.reg_write(sp, STACK + 0x8000)
    uc.reg_write(lr, RETADDR | thumb)       # the return address lives in LR
    uc.reg_write(r0, a), uc.reg_write(r1, b)
    uc.emu_start(CODE | thumb, RETADDR)     # note the | thumb on the start pc
    return uc.reg_read(r0)


if __name__ == "__main__":
    assert run(A64, 0x1000, 0x337) == run(T32, 0x1000, 0x337) == 0x1337
    print("[+] arm64 and thumb both return 0x1337")
```

32-bit x86: `Uc(UC_ARCH_X86, UC_MODE_32)`, `UC_X86_REG_ESP/EAX`, cdecl args on
the stack in reverse order. MIPS: `UC_ARCH_MIPS` with `UC_MODE_MIPS32 +
UC_MODE_BIG_ENDIAN` and args in `$a0-$a3`.

## Pitfalls

- **`mem_map` needs a page-aligned base and length**; a second map over an
  existing region raises `UC_ERR_MAP`, so catch it.
- **`emu_start(begin, until)` stops *before* executing `until`**, so a function
  that can legitimately jump to your sentinel ends the run early.
- **A Python exception raised inside a hook may be swallowed** by the C layer:
  record it on `self`, call `emu_stop()`, re-raise outside.
- **Always set a timeout or an instruction budget**, or a bad argument becomes
  an infinite loop that Unicorn happily runs forever.
- **`mem_read` returns a `bytearray`** - wrap it in `bytes()`. And
  **uninitialised memory reads zero**, not garbage, so code that depends on
  stack junk behaves differently under emulation than natively.
- **No syscalls and no relocations.** `UC_HOOK_INTR` catches `int 0x80` and
  `syscall` but you model `write`/`read`/`exit` yourself, and a PIE binary's
  GOT-indirect call lands on a zero - stub the PLT entry or use a static
  binary. Many syscalls means reach for qiling instead.
- **The trace hook costs easily 50x** - trace a short run, then use `icount`.

## References

- Unicorn Engine - unicorn-engine.org, github.com/unicorn-engine/unicorn
  (`bindings/python/sample_*.py`: canonical per-arch examples)
- Capstone - capstone-engine.org. `man 5 elf` for every struct field above.
