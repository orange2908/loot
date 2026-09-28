---
title: "Unicorn & Qiling - Emulating a Fragment of a Binary"
category: rev
subcategory: emulation
type: technique
tags: [unicorn, qiling, emulation, unicorn-engine, cpu-emulator, mem-map, emu-start, hooks, syscall, plt, thumb, arm, mips, firmware, windows-pe, instruction-counting, x86, python, angr]
difficulty: medium
summary: "Run one function of a foreign binary on your own machine: Unicorn for pure computation, Qiling for anything that needs an OS underneath."
when_to_use:
  - "You need the output of one decompiled function but reimplementing it in Python is error-prone"
  - "The binary is for another architecture (ARM/MIPS/PPC) or another OS (Windows PE, firmware blob)"
  - "You want to brute-force an input byte-by-byte using an instruction-count side channel"
  - "A custom VM interpreter or an unpacker stub needs to be run, but the whole program will not"
  - "angr is too slow because the logic is concrete -- you only need execution, not solving"
tools: [unicorn, qiling, capstone, keystone, binwalk, ghidra]
related: [unicorn-emulate-function, angr-symbolic-execution, z3-constraint-solving, angr-z3-cheatsheet, custom-vm-bytecode, side-channel-instruction-counting]
---

## TL;DR

Unicorn is a raw CPU emulator (QEMU's TCG core, no OS): you map memory, set registers, and
`emu_start(begin, end)`. Nothing else exists - no syscalls, no libc, no loader. Qiling sits
on top of Unicorn and adds a loader, a fake filesystem (`rootfs`) and syscall/API emulation,
so a whole ELF/PE/firmware image actually runs. Pick by the question you are asking:

| Need | Tool |
|---|---|
| Pure computation, no syscalls, one function | Unicorn |
| Program calls `open`/`read`/`malloc`/`printf`, or you want `main` to run | Qiling |
| You need to *solve* for an unknown input | angr / z3 |

## Recognise it

- A `transform()` / `decrypt()` / `vm_step()` function with no external calls, called once
  per input byte. Perfect Unicorn target.
- An ARM/MIPS ELF from a router firmware image, no matching hardware to run it on. Qiling.
- A Windows PE with a `CheckLicense()` export and you are on Linux/macOS. Qiling with a
  Windows rootfs, or Unicorn if the function is self-contained.
- A shellcode blob or an unpacker stub extracted with `binwalk`/`dd`: raw bytes at a known
  load address. Unicorn.
- You already reimplemented the function in Python twice and both times got the wrong
  answer. Stop and emulate it.

## Theory

Unicorn exposes a `Uc(arch, mode)` object with a flat, explicitly-managed address space:

- `uc.mem_map(addr, size, perms)` - `addr` and `size` must be 4 KiB aligned.
- `uc.mem_write(addr, data)` / `uc.mem_read(addr, n)` - `mem_read` returns a `bytearray`.
- `uc.reg_write(UC_X86_REG_RSP, v)` / `uc.reg_read(...)`.
- `uc.emu_start(begin, until, timeout=0, count=0)` - `timeout` is **microseconds**,
  `count` is a maximum instruction count (`0` = unlimited). Emulation stops when `RIP`
  reaches `until`, a bound is hit, or an unhandled fault raises `UcError`.

Because there is no OS, a `call` into the PLT jumps into an unmapped GOT entry and faults.
The fix is to intercept: register a `UC_HOOK_CODE` hook, and when the instruction pointer
equals a PLT stub address, run a Python implementation of that libc function, write the
result to `RAX`, pop the saved return address off the stack and set `RIP` to it.

Key hook types:

| Hook | Fires on |
|---|---|
| `UC_HOOK_CODE` | every instruction (address, size). Instruction counting, PLT dispatch, tracing |
| `UC_HOOK_BLOCK` | every basic block. Cheaper coarse tracing |
| `UC_HOOK_MEM_UNMAPPED` | access to an unmapped page. Return `True` after `mem_map` to retry |
| `UC_HOOK_MEM_READ` / `_WRITE` | data accesses; use to log a key schedule being built |
| `UC_HOOK_INTR` | `int 0x80`, `svc`, software interrupts |
| `UC_HOOK_INSN` + `UC_X86_INS_SYSCALL` | the x86-64 `syscall` instruction specifically |

Returning to the caller: push a sentinel address (e.g. `0xdead0000`) as the return address
and pass it as `until`. When the function's `ret` pops it, emulation stops cleanly.

Qiling instead emulates the OS. `Qiling([path, "arg1"], rootfs)` loads the binary the way
the real loader would, maps the interpreter and libraries out of `rootfs`, and implements
syscalls in Python. `ql.run(begin=, end=)` optionally runs only a slice. `ql.os.set_api`
replaces a library function by name, `ql.os.set_syscall` replaces a syscall,
`ql.hook_address(cb, addr)` fires at an address. `ql.mem.read/write` and `ql.arch.regs`
give the same primitives as Unicorn.

## Workflow

1. Get the function's address range from Ghidra (`f` start, and the address after the
   final `ret`). Write both down.
2. Decide: does the function call anything external? `objdump -d --start-address=... | grep call`.
   No calls -> Unicorn. Calls libc -> Unicorn plus PLT stubs, or Qiling.
3. Unicorn path: map the ELF's `PT_LOAD` segments at their `p_vaddr`, map a stack, map a
   scratch heap for your input buffer, set the SysV argument registers, `emu_start`.
4. Verify against a known-good input first. If the real binary prints `check("AAAA") = 3`,
   your emulator must also return 3 before you trust anything else.
5. Qiling path: build a rootfs (`git clone https://github.com/qilingframework/rootfs`),
   then `ql = Qiling([bin], rootfs); ql.run()`. Add hooks only once the plain run works.
6. For brute force, snapshot: Unicorn has no snapshot API, so re-create the `Uc` object per
   attempt (cheap, ~1 ms) or `ql.save()` / `ql.restore()` under Qiling.

Useful pre-flight commands:

```sh
# architecture, endianness, static/dynamic -- decides arch/mode constants
file ./chal
# program headers: the vaddr/filesz/memsz you must mem_map
readelf -lW ./chal
# every external call inside the function of interest
objdump -d --start-address=0x401136 --stop-address=0x4011f0 -M intel ./chal | grep -E 'call|ret'
# PLT stub addresses to replace with Python implementations
objdump -d -j .plt.sec -M intel ./chal | grep '>:'
```

## Code

### 1. Unicorn: emulate one function of an x86-64 ELF

Loads `PT_LOAD` segments with a 60-line ELF parser (no pwntools/lief dependency), sets up a
stack, calls `long func(char *buf, size_t len)`, lazily maps faulting pages, counts
instructions, and can replace PLT calls with Python.

```python
#!/usr/bin/env python3
"""Emulate one function of an x86-64 ELF with Unicorn.

Usage: python3 emulate_function.py ./chal 0x401000 "AAAABBBB"

Maps the ELF's PT_LOAD segments, builds a stack, calls
    long func(char *buf, size_t len)
with buf pointing at the input, then prints the return value, the mutated
buffer and the executed instruction count.
"""
import struct
import sys

from unicorn import (UC_ARCH_X86, UC_HOOK_CODE, UC_HOOK_INTR,
                     UC_HOOK_MEM_UNMAPPED, UC_MODE_64, Uc, UcError)
from unicorn.x86_const import (UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RDX,
                               UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RSP)

PAGE = 0x1000
STACK_BASE = 0x7FFF_0000_0000
STACK_SIZE = 0x40000
HEAP_BASE = 0x1000_0000          # scratch region for our own buffers
HEAP_SIZE = 0x10000
MAGIC_RET = 0xDEAD_0000_0000     # sentinel return address = emu_start's `until`


def align_down(x, a=PAGE):
    return x & ~(a - 1)


def align_up(x, a=PAGE):
    return (x + a - 1) & ~(a - 1)


def load_elf64_segments(path):
    """Return ([(vaddr, bytes)], entry) for every PT_LOAD in a 64-bit LE ELF."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise ValueError("not a 64-bit ELF")
    e_entry, e_phoff = struct.unpack_from("<QQ", blob, 0x18)
    e_phentsize, e_phnum = struct.unpack_from("<HH", blob, 0x36)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _flags, p_offset, p_vaddr = struct.unpack_from("<IIQQ", blob, off)
        p_filesz, p_memsz = struct.unpack_from("<QQ", blob, off + 0x20)
        if p_type != 1:                      # PT_LOAD
            continue
        data = blob[p_offset:p_offset + p_filesz]
        data += b"\x00" * (p_memsz - p_filesz)   # .bss
        segs.append((p_vaddr, data))
    return segs, e_entry


class Emu:
    def __init__(self, path, verbose=False):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.count = 0
        self.verbose = verbose
        self.plt_stubs = {}                  # addr -> python callable(emu)

        segs, self.entry = load_elf64_segments(path)
        for vaddr, data in segs:
            base = align_down(vaddr)
            size = align_up(vaddr + len(data)) - base
            self.uc.mem_map(base, size)      # addr and size must be page aligned
            self.uc.mem_write(vaddr, data)

        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE)

        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        self.uc.hook_add(UC_HOOK_INTR, self._hook_intr)

    # ---- hooks -------------------------------------------------------
    def _hook_code(self, uc, address, size, user_data):
        """Instruction counter plus PLT dispatcher."""
        self.count += 1
        if self.verbose:
            print(f"    {address:#x}  ({size} bytes)")
        fn = self.plt_stubs.get(address)
        if fn is not None:
            fn(self)
            # Emulate the `ret` we skipped: pop the saved address, jump there.
            rsp = uc.reg_read(UC_X86_REG_RSP)
            ret = struct.unpack("<Q", uc.mem_read(rsp, 8))[0]
            uc.reg_write(UC_X86_REG_RSP, rsp + 8)
            uc.reg_write(UC_X86_REG_RIP, ret)

    def _hook_unmapped(self, uc, access, address, size, value, user_data):
        """Lazily map any page the code touches. Return True to retry the access."""
        if address < PAGE:
            print("[!] NULL-page dereference -- real bug, not a mapping gap")
            return False
        base = align_down(address)
        uc.mem_map(base, PAGE)
        if self.verbose:
            print(f"[~] lazily mapped {base:#x}")
        return True

    def _hook_intr(self, uc, intno, user_data):
        """int 0x80 and friends. The x86-64 `syscall` insn needs UC_HOOK_INSN instead."""
        rax = uc.reg_read(UC_X86_REG_RAX)
        print(f"[!] interrupt {intno:#x}, rax={rax:#x} -- stubbed, returning 0")
        uc.reg_write(UC_X86_REG_RAX, 0)

    # ---- python replacements for libc --------------------------------
    def hook_plt(self, addr, fn):
        """Emulate a libc function in Python instead of executing its PLT/GOT path."""
        self.plt_stubs[addr] = fn

    @staticmethod
    def libc_strlen(emu):
        p = emu.uc.reg_read(UC_X86_REG_RDI)
        n = 0
        while emu.uc.mem_read(p + n, 1)[0] != 0 and n < 0x10000:
            n += 1
        emu.uc.reg_write(UC_X86_REG_RAX, n)

    @staticmethod
    def libc_puts(emu):
        p = emu.uc.reg_read(UC_X86_REG_RDI)
        out = bytearray()
        while True:
            c = emu.uc.mem_read(p + len(out), 1)[0]
            if c == 0:
                break
            out.append(c)
        print("[puts]", out.decode(errors="replace"))
        emu.uc.reg_write(UC_X86_REG_RAX, len(out) + 1)

    # ---- driving -----------------------------------------------------
    def call(self, addr, args=(), data=b"", timeout=10_000_000, count=0):
        """Call func(*args) SysV-style. Returns (rax, contents of the scratch buffer)."""
        self.uc.mem_write(HEAP_BASE, data + b"\x00")
        rsp = STACK_BASE + STACK_SIZE - 0x1000
        rsp -= 8
        self.uc.mem_write(rsp, struct.pack("<Q", MAGIC_RET))
        self.uc.reg_write(UC_X86_REG_RSP, rsp)

        for reg, val in zip((UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX), args):
            self.uc.reg_write(reg, val)

        self.count = 0
        try:
            # timeout is in MICROseconds; count=0 means unlimited instructions.
            self.uc.emu_start(addr, MAGIC_RET, timeout=timeout, count=count)
        except UcError as exc:
            print(f"[!] UcError {exc} at rip={self.uc.reg_read(UC_X86_REG_RIP):#x}")
        return (self.uc.reg_read(UC_X86_REG_RAX),
                bytes(self.uc.mem_read(HEAP_BASE, max(len(data), 1))))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    func = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x401000
    text = (sys.argv[3] if len(sys.argv) > 3 else "AAAABBBB").encode()

    emu = Emu(path)
    # If the function calls strlen@plt at 0x401030, uncomment to replace it:
    #   emu.hook_plt(0x401030, Emu.libc_strlen)
    rax, buf = emu.call(func, args=(HEAP_BASE, len(text)), data=text)
    print(f"[+] return value : {rax:#x}")
    print(f"[+] output buffer: {buf.hex()}")
    print(f"[+] instructions : {emu.count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Against a test ELF whose function is
`for (i=0;i<len;i++){ buf[i]=(buf[i]^0x5a)+i; sum+=buf[i]; } return (uint8_t)sum;`
this prints `return value : 0xe8`, `output buffer: 1b1c1d1e1c1d1e1f`, `instructions : 77`
- identical to the reference Python implementation.

### 2. Unicorn: Thumb-mode ARM

The Thumb bit is bit 0 of the address you pass to `emu_start`, not a CPSR write.

```python
#!/usr/bin/env python3
"""Unicorn: run a Thumb-mode ARM snippet.

The Thumb state is requested by setting bit 0 of emu_start's begin address.
For ARM mode use UC_MODE_ARM and a clean address. For big-endian MIPS use
Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_BIG_ENDIAN).
"""
from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_SP

BASE = 0x1000
STACK = 0x20000
# movs r0, #0x10 ; adds r0, #5 ; lsls r0, r0, #2   -> r0 = (0x10 + 5) << 2 = 0x54
THUMB = bytes.fromhex("1020" "0530" "8000")


def main():
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(BASE, 0x1000)
    uc.mem_map(STACK, 0x1000)
    uc.mem_write(BASE, THUMB)
    uc.reg_write(UC_ARM_REG_SP, STACK + 0x800)
    uc.emu_start(BASE | 1, BASE + len(THUMB))   # | 1 == decode as Thumb
    print("r0 =", hex(uc.reg_read(UC_ARM_REG_R0)))
    assert uc.reg_read(UC_ARM_REG_R0) == 0x54
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### 3. Unicorn: instruction-count side channel

If the checker returns early on the first wrong byte, the instruction count leaks how many
bytes are correct. Re-create the `Uc` per attempt; construction is about a millisecond.

```python
#!/usr/bin/env python3
"""Brute-force a flag byte-by-byte using Unicorn's instruction count as an oracle.

Usage: python3 count_oracle.py ./chal 0x401000 32
Requires emulate_function.py (the Emu class above) on PYTHONPATH.
"""
import string
import sys

from emulate_function import HEAP_BASE, Emu

ALPHABET = (string.ascii_letters + string.digits + "_{}!?-").encode()


def instructions_for(path, func, guess):
    """Fresh emulator per attempt: Unicorn has no snapshot/restore."""
    emu = Emu(path)
    emu.call(func, args=(HEAP_BASE, len(guess)), data=guess)
    return emu.count


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    func = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x401000
    length = int(sys.argv[3]) if len(sys.argv) > 3 else 32

    flag = bytearray(b"A" * length)
    for pos in range(length):
        best, best_count = None, -1
        for cand in ALPHABET:
            flag[pos] = cand
            n = instructions_for(path, func, bytes(flag))
            # More instructions executed == got further before bailing out.
            if n > best_count:
                best, best_count = cand, n
        flag[pos] = best
        print(f"[{pos:02d}] {best_count:6d}  {bytes(flag).decode(errors='replace')}")
    print("[+]", bytes(flag).decode(errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### 4. Qiling: run the whole binary, hook APIs and syscalls

Qiling needs a rootfs matching the target OS/arch:
`git clone --depth 1 https://github.com/qilingframework/rootfs` then point at e.g.
`rootfs/x8664_linux`, `rootfs/mips32_linux`, `rootfs/x8664_windows` (the Windows rootfs
needs real DLLs dropped in, see the Qiling docs).

```python
#!/usr/bin/env python3
"""Qiling: run a foreign-arch or foreign-OS binary, hook APIs and syscalls.

Usage: python3 qrun.py ./chal ./rootfs/x8664_linux
"""
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE

FLAG_ADDR = 0x0                       # filled in below if the binary is non-PIE


def hook_printf(ql, *args):
    """ql.os.set_api replaces a named libc/Win32 function entirely."""
    fmt_ptr = ql.arch.regs.rdi
    print("[printf]", ql.os.utils.read_cstring(fmt_ptr))
    ql.arch.regs.rax = 0
    return 0


def hook_time(ql, *args):
    """Defeat a time-based anti-debug check by pinning the clock."""
    ql.arch.regs.rax = 0x6500_0000
    return 0


def on_check(ql):
    """ql.hook_address fires when RIP reaches this address."""
    buf = ql.arch.regs.rdi
    data = ql.mem.read(buf, 32)
    print("[check] buffer =", bytes(data).hex())


def syscall_getrandom(ql, buf, buflen, flags, *rest):
    """Deterministic randomness so a keygen challenge is reproducible."""
    ql.mem.write(buf, b"\x41" * buflen)
    return buflen


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./chal"
    rootfs = sys.argv[2] if len(sys.argv) > 2 else "./rootfs/x8664_linux"

    # argv[0] must be the guest path; extra elements become the program's argv.
    ql = Qiling([path, "AAAABBBBCCCCDDDD"], rootfs, verbose=QL_VERBOSE.OFF)

    # Replace library functions by name (works for ELF imports and PE IAT entries).
    ql.os.set_api("printf", hook_printf)
    ql.os.set_api("time", hook_time)
    # Replace a Linux syscall by name.
    ql.os.set_syscall("getrandom", syscall_getrandom)

    # Address hook. For a PIE binary add ql.loader.load_address to the file offset.
    base = ql.loader.load_address if ql.loader.load_address else 0
    ql.hook_address(on_check, base + 0x1189)

    # Snapshot before the interesting part so a brute force can rewind.
    snap = ql.save(reg=True, mem=True)

    ql.run()

    # Rewind and run only a slice: begin/end are absolute addresses.
    ql.restore(snap)
    ql.run(begin=base + 0x1189, end=base + 0x1240)

    # Read results straight out of guest memory.
    print("[+] stack top:", bytes(ql.mem.read(ql.arch.regs.rsp, 16)).hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Same script shape for other targets, only the constructor changes:

```python
#!/usr/bin/env python3
"""Qiling target matrix: the only thing that changes is the rootfs (and argv)."""
from qiling import Qiling
from qiling.const import QL_VERBOSE


def mips_router_binary():
    """Big-endian MIPS firmware binary extracted with binwalk -- no hardware needed."""
    return Qiling(["./squashfs-root/usr/sbin/httpd"], "./rootfs/mips32_linux",
                  verbose=QL_VERBOSE.OFF)


def windows_pe_on_linux():
    """Windows PE without Windows. Needs real DLLs under rootfs/x8664_windows/Windows."""
    return Qiling(["./crackme.exe"], "./rootfs/x8664_windows", verbose=QL_VERBOSE.OFF)


def bare_firmware_blob():
    """Raw Cortex-M image: no OS at all, so Qiling runs it as a bare-metal MCU profile."""
    return Qiling(["./firmware.bin"], "./rootfs/mcu", profile="stm32f429.ql",
                  verbose=QL_VERBOSE.OFF)


if __name__ == "__main__":
    print("pick one of:", [f.__name__ for f in
                           (mips_router_binary, windows_pe_on_linux, bare_firmware_blob)])
```

## Variants & pitfalls

- **Alignment.** `mem_map` requires 4 KiB-aligned address and size. `align_down(vaddr)` /
  `align_up(end)`. An unaligned call raises `UC_ERR_ARG`.
- **Overlapping maps.** Two `PT_LOAD` segments can share a page after alignment; the second
  `mem_map` then raises `UC_ERR_MAP`. Merge the ranges, or wrap each `mem_map` in a
  try/except and fall back to `mem_write` only.
- **`timeout` is microseconds.** `timeout=10` means 10 us and your emulation stops
  immediately with no error. Use `timeout=10_000_000` for 10 seconds.
- **Emulation ends silently.** If `emu_start` returns without reaching `until`, check
  `RIP` - a `count` or `timeout` bound fired. Always print `RIP` after the call.
- **No stack = instant fault.** Unicorn does not create one. Map a stack and set
  `RSP`/`ESP`/`SP` well inside it (not at the very top; `push` needs headroom below and
  red-zone accesses need headroom above).
- **Forgetting the sentinel return address.** Without it the function's `ret` pops garbage
  and you get `UC_ERR_FETCH_UNMAPPED` at a random address.
- **TLS / FS-base accesses.** Stack-protector code reads `fs:0x28`. Under Unicorn that
  faults. Fix with `uc.reg_write(UC_X86_REG_FS_BASE, some_mapped_addr)` and map that page,
  or pick a function compiled without `-fstack-protector`.
- **PIE binaries.** Segment `p_vaddr` values start near 0. Either map them as-is and use
  offsets directly, or add a chosen base to every `p_vaddr` and to the function address.
  Under Qiling use `ql.loader.load_address` as the base.
- **`mem_read` returns a `bytearray`.** `bytes(uc.mem_read(a, n))` before hashing or
  comparing with a `bytes` literal.
- **Hook callback signatures differ per hook type** and are positional. A wrong arity
  raises a `TypeError` inside the emulator, which surfaces as a confusing `UcError`. Copy
  the signatures from the script above.
- **`UC_HOOK_CODE` is slow.** It calls back into Python for every instruction, roughly a
  100x slowdown. Use `UC_HOOK_BLOCK` for coarse tracing, and register `UC_HOOK_CODE` with
  an address range (`hook_add(UC_HOOK_CODE, cb, begin=lo, end=hi)`) so it only fires in the
  region you care about.
- **x86-64 `syscall` is not an interrupt.** `UC_HOOK_INTR` will not fire. Use
  `uc.hook_add(UC_HOOK_INSN, cb, arg1=UC_X86_INS_SYSCALL)`.
- **Qiling rootfs is mandatory** for dynamically linked targets - it is where the guest's
  `ld.so` and `libc.so` come from. A missing rootfs shows up as "cannot find interpreter".
- **Qiling Windows needs real DLLs.** The public rootfs ships stubs; for anything beyond
  the basics you must copy `kernel32.dll`, `ntdll.dll`, `msvcrt.dll` etc. from a real
  Windows install into `rootfs/x8664_windows/Windows/System32`.
- **Qiling is much slower than Unicorn** (full OS emulation in Python). For a brute force
  of 64 x 96 attempts, use Unicorn, or use `ql.save()`/`ql.restore()` around the hot part.
- **Choosing the tool.** Unicorn when you know the inputs and want outputs. Qiling when the
  code needs an OS or you do not know where the interesting function starts. angr when you
  know the output and want the input. They compose: emulate with Unicorn to build a
  ciphertext table, then invert it with z3.

## Tools

- `unicorn` (`pip install unicorn`) - the CPU emulator; `unicorn.__version__`.
- `qiling` (`pip install qiling`) - OS/loader layer; rootfs from the qilingframework repo.
- `capstone` - disassemble the bytes you are about to emulate, to sanity-check the address.
- `keystone` - assemble test snippets to feed Unicorn.
- `binwalk`, `dd` - extract the firmware blob or unpacker stub you want to run.
- `readelf -lW`, `objdump -d` - get segment vaddrs and PLT stub addresses.

## References

- Unicorn Engine project site and Python bindings (unicorn-engine.org,
  github.com/unicorn-engine/unicorn) - `bindings/python/sample_*.py` covers every arch.
- Qiling Framework documentation and rootfs repository
  (qiling.io, github.com/qilingframework/qiling, github.com/qilingframework/rootfs).
- See also: `unicorn-emulate-function`, `angr-symbolic-execution`, `z3-constraint-solving`,
  `side-channel-instruction-counting`, `custom-vm-bytecode`.
