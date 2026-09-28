---
title: "Custom VM and Bytecode Interpreters - Recover the ISA"
category: rev
subcategory: custom-vm
type: technique
tags: [custom-vm, virtual-machine, bytecode, interpreter, dispatch-loop, opcode, disassembler, isa-recovery, vmprotect, virtualisation, switch-dispatch, computed-goto, emulator, angr, unicorn, z3]
difficulty: hard
summary: "A switch over bytecode[pc] means the real program is data, not code: map the handlers to an ISA, write a disassembler, then attack the recovered program."
when_to_use:
  - "The decompiler shows a while loop with a big switch on a byte from an array"
  - "There is a large opaque byte blob in .rodata with no obvious structure"
  - "You see a struct with fields that look like pc, sp, registers and a stack array"
  - "The binary is VMProtect/Themida-protected and dumping gives you a VM, not code"
tools: [ghidra, ida, radare2, python, unicorn, angr, z3, capstone]
related: [obfuscation-deobfuscation, crackme-patterns, unicorn-qiling-emulation, z3-constraint-solving, packers-and-unpacking, angr-symbolic-execution]
---

## TL;DR

A VM challenge has three parts: the **bytecode** (a blob in `.rodata` or embedded in the
binary), the **interpreter** (a fetch-decode-execute loop), and the **VM state** (pc, stack
or registers, memory). Reverse the interpreter once to learn the ISA, write a disassembler
for the blob, read the resulting program, and solve *that*. You are doing RE of a program
written in a language you have to discover first.

## Recognise it

```c
/* the canonical shape: fetch, decode, execute, repeat */
while (vm->running) {
    uint8_t op = code[vm->pc++];
    switch (op) {
    case 0x01: vm->stack[vm->sp++] = code[vm->pc++];        break;  /* PUSH imm */
    case 0x02: vm->sp--;                                     break;  /* POP */
    case 0x03: vm->stack[vm->sp-2] += vm->stack[vm->sp-1]; vm->sp--; break;  /* ADD */
    case 0x04: vm->stack[vm->sp-2] ^= vm->stack[vm->sp-1]; vm->sp--; break;  /* XOR */
    case 0xFF: vm->running = 0;                              break;  /* HALT */
    }
}
```

Concrete signals:

- A `switch` with 10-60 cases inside a loop, where the switched value comes from an array
  indexed by an incrementing variable.
- A **jump table** in `.rodata` whose entries are all addresses inside one function
  (`objdump -s -j .rodata` shows a run of near-identical pointers).
- A struct passed to every handler with 2-8 integer fields - that is the VM context.
- A large `const unsigned char[]` with no strings in it, referenced exactly once.
- Threaded/computed-goto dispatch: `goto *handlers[code[pc++]];` - in the disassembly this
  is `jmp qword [rax*8 + table]` repeated at the end of every handler (no central switch).
- Handler-function-pointer table: `void (*ops[256])(VM*)` and a call `ops[op](vm)`.

```sh
# Find the jump table and the handlers it points to
objdump -s -j .rodata ./chall | head -40
# A tight range of addresses repeated 32+ times is a dispatch table
rabin2 -z ./chall | wc -l           # very few strings is typical for VM challenges
# In radare2: find the switch and let it resolve the table
r2 -A -q -c 'afl; pdf @ main' ./chall | grep -i -A3 'jmp.*\['
```

## Step 1 - find the pieces

1. **The interpreter loop.** Usually the biggest function. In Ghidra, sort the Functions
   window by size.
2. **The VM context struct.** Look at what the loop indexes off a single pointer. Create a
   Ghidra struct (`VM`) with the fields you identify - `pc`, `sp`, `regs[8]`, `stack[256]`,
   `mem[...]`, `running` - and retype the loop's parameter to `VM *`. The decompilation
   becomes readable immediately. See `ghidra-workflow`.
3. **The bytecode blob.** Find what the loop reads with `pc`. It is either a global array
   (note its address and length) or a buffer filled at runtime (break after the fill and dump
   it). Extract it:

```sh
# Dump a .rodata blob at a known virtual address and length
objcopy --dump-section .rodata=rodata.bin ./chall
# Or with gdb at runtime, which also works for runtime-decrypted bytecode
gdb -q -ex 'break *0x401337' -ex run \
    -ex 'dump binary memory code.bin 0x404060 0x4040e0' -ex quit ./chall
```

4. **The entry conditions**: initial pc (often 0), initial stack/registers, where the user
   input is placed (a `mem` region or preloaded registers), and where the verdict is read
   from (a register at HALT, or a global).

## Step 2 - recover the ISA

For each `case` in the switch, write down: opcode value, mnemonic you invent, operand
encoding (how many extra bytes it consumes from `code[]`, and their meaning), and semantics.
Build a table like this:

| Op | Mnemonic | Operands | Semantics |
|---|---|---|---|
| 0x01 | `PUSH imm8` | 1 byte | `stack[sp++] = imm` |
| 0x02 | `POP` | - | `sp--` |
| 0x03 | `ADD` | - | `b=pop(); a=pop(); push(a+b)` |
| 0x04 | `XOR` | - | `b=pop(); a=pop(); push(a^b)` |
| 0x05 | `LOAD idx` | 1 byte | `push(mem[idx])` |
| 0x06 | `STORE idx` | 1 byte | `mem[idx] = pop()` |
| 0x07 | `JMP rel8` | 1 signed | `pc += rel` |
| 0x08 | `JZ rel8` | 1 signed | `if (pop()==0) pc += rel` |
| 0x09 | `CMP` | - | `push(pop()==pop())` |
| 0xFF | `HALT` | - | stop |

Getting the **operand widths** right is the whole game: one wrong width desynchronises the
rest of the disassembly, exactly like a misaligned x86 stream. Cross-check by disassembling
and looking for nonsense (jumps into the middle of instructions, unknown opcodes) - if you
see any, an earlier width is wrong.

Two accelerators:

- **Instrument the real interpreter** rather than reading it: patch a `printf("%02x %d\n",
  op, pc)` into the loop (or set a gdb breakpoint at the top of the loop that logs `pc` and
  `op` and continues). The execution trace tells you the operand widths empirically, because
  you see exactly how far `pc` advances per opcode.

```
(gdb) break *0x401234          # top of the dispatch loop
(gdb) commands
>silent
>printf "pc=%d op=%02x sp=%d\n", *(int*)($rbx+0), *(unsigned char*)($rdi + *(int*)($rbx+0)), *(int*)($rbx+4)
>continue
>end
(gdb) run
```

- **Differential testing**: once your Python emulator exists, run it and the real binary on
  the same input and compare traces. The first divergence points at the handler you got
  wrong.

## Step 3 - write the disassembler

```python
#!/usr/bin/env python3
"""vmdisasm.py - a template disassembler for a custom stack VM.

Edit ISA to match the handlers you recovered, then:
    python3 vmdisasm.py code.bin
    python3 vmdisasm.py code.bin --base 0

Each ISA entry is (mnemonic, operand_spec) where operand_spec is a string of
format characters consumed from the stream after the opcode byte:
    'b' unsigned byte   'B' signed byte
    'h' unsigned u16 LE 'H' signed i16 LE
    'i' unsigned u32 LE
    'r' signed byte, printed as a pc-relative target
"""
import struct
import sys

ISA: dict[int, tuple[str, str]] = {
    0x01: ("PUSH", "b"),
    0x02: ("POP", ""),
    0x03: ("ADD", ""),
    0x04: ("XOR", ""),
    0x05: ("LOAD", "b"),
    0x06: ("STORE", "b"),
    0x07: ("JMP", "r"),
    0x08: ("JZ", "r"),
    0x09: ("CMP", ""),
    0x0A: ("SUB", ""),
    0x0B: ("MUL", ""),
    0x0C: ("IN", ""),
    0x0D: ("OUT", ""),
    0xFF: ("HALT", ""),
}

SIZES = {"b": 1, "B": 1, "r": 1, "h": 2, "H": 2, "i": 4}
FORMATS = {"b": "<B", "B": "<b", "r": "<b", "h": "<H", "H": "<h", "i": "<I"}


def decode_one(code: bytes, pc: int) -> tuple[int, str, list[int], list[str]]:
    """Return (new_pc, mnemonic, raw_operands, formatted_operands)."""
    op = code[pc]
    pc += 1
    if op not in ISA:
        return pc, f".byte {op:#04x}", [], ["<unknown opcode>"]
    mnem, spec = ISA[op]
    raw, shown = [], []
    for ch in spec:
        size = SIZES[ch]
        (val,) = struct.unpack_from(FORMATS[ch], code, pc)
        pc += size
        raw.append(val)
        shown.append(f"{pc + val:#06x}" if ch == "r" else f"{val:#x}")
    return pc, mnem, raw, shown


def disassemble(code: bytes, base: int = 0) -> list[str]:
    out, pc = [], 0
    targets = set()
    # first pass: collect jump targets so we can emit labels
    scan = 0
    while scan < len(code):
        nxt, mnem, raw, _ = decode_one(code, scan)
        if mnem in ("JMP", "JZ", "JNZ", "CALL") and raw:
            targets.add(nxt + raw[0])
        scan = nxt
    # second pass: print
    while pc < len(code):
        here = pc
        nxt, mnem, _raw, shown = decode_one(code, pc)
        label = f"L_{here + base:04x}:" if (here in targets) else ""
        rawbytes = code[here:nxt].hex(" ")
        out.append(f"{here + base:#06x}  {rawbytes:<14} {label:<10} {mnem} {', '.join(shown)}")
        pc = nxt
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    base = 0
    if "--base" in sys.argv:
        base = int(sys.argv[sys.argv.index("--base") + 1], 0)
    with open(sys.argv[1], "rb") as fh:
        code = fh.read()
    for line in disassemble(code, base):
        print(line)
    return 0


if __name__ == "__main__":
    # self-test: PUSH 5; PUSH 3; ADD; HALT
    sample = bytes([0x01, 0x05, 0x01, 0x03, 0x03, 0xFF])
    listing = disassemble(sample)
    assert "PUSH" in listing[0] and "HALT" in listing[-1], listing
    if len(sys.argv) < 2:
        print("\n".join(listing))
        print("[+] self-test OK; pass a .bin to disassemble a real blob")
        raise SystemExit(0)
    raise SystemExit(main())
```

## Step 4 - write the emulator

Once you can disassemble, write an emulator. It is the fastest way to (a) confirm your ISA
is right, (b) instrument the program (trace every comparison), and (c) brute force or
symbolically execute the VM program.

```python
#!/usr/bin/env python3
"""vmemu.py - reference emulator for the same stack VM, with tracing.

    python3 vmemu.py code.bin --input "CTF{...}" --trace

The trace is the point: every CMP tells you what the VM expects, which usually hands you
the flag without any further analysis.
"""
import sys


class VM:
    def __init__(self, code: bytes, stdin: bytes = b"", trace: bool = False):
        self.code = code
        self.pc = 0
        self.stack: list[int] = []
        self.mem = [0] * 256
        self.input = list(stdin)
        self.inptr = 0
        self.output = bytearray()
        self.trace = trace
        self.running = True
        self.steps = 0

    def push(self, v: int) -> None:
        self.stack.append(v & 0xFF)

    def pop(self) -> int:
        return self.stack.pop() if self.stack else 0

    def fetch(self) -> int:
        v = self.code[self.pc]
        self.pc += 1
        return v

    def fetch_signed(self) -> int:
        v = self.fetch()
        return v - 256 if v > 127 else v

    def step(self) -> None:
        here = self.pc
        op = self.fetch()
        if self.trace:
            print(f"pc={here:#06x} op={op:#04x} stack={self.stack[-6:]}", file=sys.stderr)
        if op == 0x01:
            self.push(self.fetch())
        elif op == 0x02:
            self.pop()
        elif op == 0x03:
            b, a = self.pop(), self.pop()
            self.push(a + b)
        elif op == 0x04:
            b, a = self.pop(), self.pop()
            self.push(a ^ b)
        elif op == 0x05:
            self.push(self.mem[self.fetch()])
        elif op == 0x06:
            self.mem[self.fetch()] = self.pop()
        elif op == 0x07:
            self.pc += self.fetch_signed()
        elif op == 0x08:
            rel = self.fetch_signed()
            if self.pop() == 0:
                self.pc += rel
        elif op == 0x09:
            b, a = self.pop(), self.pop()
            if self.trace:
                print(f"    CMP {a:#04x} vs {b:#04x}"
                      f" ({chr(a) if 32 <= a < 127 else '.'} vs "
                      f"{chr(b) if 32 <= b < 127 else '.'})", file=sys.stderr)
            self.push(1 if a == b else 0)
        elif op == 0x0A:
            b, a = self.pop(), self.pop()
            self.push(a - b)
        elif op == 0x0B:
            b, a = self.pop(), self.pop()
            self.push(a * b)
        elif op == 0x0C:
            ch = self.input[self.inptr] if self.inptr < len(self.input) else 0
            self.inptr += 1
            self.push(ch)
        elif op == 0x0D:
            self.output.append(self.pop())
        elif op == 0xFF:
            self.running = False
        else:
            raise ValueError(f"unknown opcode {op:#04x} at {here:#06x}")
        self.steps += 1

    def run(self, max_steps: int = 1_000_000) -> "VM":
        while self.running and self.pc < len(self.code) and self.steps < max_steps:
            self.step()
        return self


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    with open(sys.argv[1], "rb") as fh:
        code = fh.read()
    data = b""
    if "--input" in sys.argv:
        data = sys.argv[sys.argv.index("--input") + 1].encode()
    vm = VM(code, data, trace="--trace" in sys.argv).run()
    print(f"[+] halted after {vm.steps} steps, stack={vm.stack}")
    if vm.output:
        print("[+] output:", vm.output.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    # self-test: PUSH 5; PUSH 3; ADD; OUT; HALT  -> output byte 8
    demo = bytes([0x01, 0x05, 0x01, 0x03, 0x03, 0x0D, 0xFF])
    vm = VM(demo).run()
    assert vm.output == bytes([8]), vm.output
    if len(sys.argv) < 2:
        print("[+] emulator self-test OK (5 + 3 = 8)")
        raise SystemExit(0)
    raise SystemExit(main())
```

## Step 5 - solve the recovered program

With a disassembly in hand the challenge is usually trivial:

- **The listing contains the expected bytes.** A run of `PUSH 0x43; LOAD 0; CMP; JZ` is the
  flag, byte by byte. Read it off.
- **Tracing the CMPs.** Run the emulator with any input and log every comparison: the
  *expected* operand is the flag byte. This is the single highest-value trick in VM
  challenges, and it works even if your ISA understanding is incomplete, because it only
  needs the comparison handler to be right.
- **Constraint solving.** If bytes are mixed (`flag[i] ^ flag[i+1]`), re-implement the VM
  with z3 BitVecs instead of Python ints - the emulator above becomes symbolic by swapping
  `int` for `BitVec` and `if` for `If`/path forking. See `z3-constraint-solving`.
- **Symbolic execution of the native binary.** angr on the *interpreter* works when the
  bytecode program is short, but state explosion is severe because the dispatch loop
  multiplies paths. Hooking the dispatch to concretise `pc` helps. Usually writing your own
  emulator is faster than fighting angr.
- **Brute force per byte** using your emulator: it is pure Python, so 95 candidates times 40
  positions is instant.

```python
#!/usr/bin/env python3
"""vmsolve.py - byte-by-byte recovery using the emulator's step count as an oracle.

Same idea as instruction counting on a native binary: the VM executes more steps the
longer the correct prefix is.
"""
import string
import sys

from vmemu import VM        # the emulator above, importable as a module


def solve(code: bytes, length: int) -> str:
    known = ""
    for pos in range(length):
        best, best_steps = "", -1
        for ch in string.printable[:95]:
            cand = (known + ch).ljust(length, ".").encode()
            steps = VM(code, cand).run().steps
            if steps > best_steps:
                best, best_steps = ch, steps
        known += best
        print(f"[{pos:02d}] {best!r} steps={best_steps} -> {known}")
    return known


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: vmsolve.py code.bin <flag_length>")
        return 1
    with open(sys.argv[1], "rb") as fh:
        code = fh.read()
    print("[+] flag:", solve(code, int(sys.argv[2])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## VM shapes you will meet

| Shape | Signal | Note |
|---|---|---|
| Stack machine | `sp` increment/decrement in most handlers | easiest; maps to RPN |
| Register machine | operands are indices into `regs[16]` | read the operand nibbles carefully |
| Accumulator machine | one implicit register in every op | very small ISAs |
| Threaded / computed goto | no central switch; `jmp [table + op*8]` at each handler end | the table IS the ISA list |
| Handler function pointers | `ops[op](ctx)` | each handler is a separate function - easiest to reverse |
| Encrypted bytecode | the fetch does `code[pc] ^ key` or a rolling key | decrypt in your disassembler too |
| Self-modifying bytecode | a handler writes into `code[]` | you must emulate, not statically disassemble |
| Opcode remapping per run | a permutation table applied at startup | dump the table at runtime |
| Nested VMs | a handler is itself a dispatch loop | recover the inner ISA the same way |
| VMProtect / Themida | thousands of handlers, RISC-like, obfuscated | use VMAttack/VTIL-style tooling; usually out of CTF scope |

## Variants & pitfalls

- **Opcode remapping**: the switch cases are not the raw bytes; a translation table maps
  `code[pc]` to a handler index. Dump that table (it is a 256-byte array) and apply it in
  your disassembler.
- **Variable-length operands** that depend on a flag bit inside the opcode byte (e.g. the
  top two bits select the addressing mode). Decode the byte as bitfields, not as a value.
- **Signed vs unsigned relative jumps** - the classic source of a disassembly that "works"
  for the first 30 bytes and then falls apart.
- **The blob is decrypted at startup**; dumping it statically gives ciphertext. Break after
  the decryption loop and dump from memory (see `packers-and-unpacking`).
- **Word-sized bytecode**: some VMs fetch `uint16` or `uint32` per instruction. If every
  other byte in the blob is zero, you are looking at 16-bit code.
- **Your emulator must match the VM's integer width**: mask to 8/16/32 bits everywhere, or
  a `MUL` will diverge silently.
- **Do not fully reverse every handler** before testing. Implement the handlers that appear
  in the blob (count opcode frequencies first), and stub the rest with an exception.

```python
#!/usr/bin/env python3
"""opcount.py - histogram of opcode bytes in a blob, to prioritise handler reversing."""
import collections
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: opcount.py code.bin")
        return 1
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    counts = collections.Counter(data)
    print(f"{'byte':>6} {'count':>7}  bar")
    for byte, n in counts.most_common(24):
        print(f"  {byte:#04x} {n:>7}  {'#' * min(n, 60)}")
    print(f"\n[+] {len(counts)} distinct byte values in {len(data)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Note this is a heuristic: operand bytes pollute the histogram. Still, the top few values are
almost always the most common opcodes (PUSH/LOAD/CMP), which is where to start.

## Tools

- `Ghidra` struct editor - retyping the VM context is worth 30 minutes of reading.
- `gdb` breakpoint commands - trace `pc`/`op` with no patching.
- `capstone` - if the VM's "bytecode" turns out to be a real ISA (some challenges embed
  MIPS or Thumb and hand-roll an interpreter).
- `z3` - for the symbolic version of your emulator.
- `unicorn` - emulate the *native* interpreter instead of rewriting it, when the handlers
  are too hairy to transcribe.

## References

- Ghidra help: "Structure Editor" and "Auto Create Structure" (for the VM context).
- Capstone documentation, if the embedded bytecode turns out to be a standard ISA.
