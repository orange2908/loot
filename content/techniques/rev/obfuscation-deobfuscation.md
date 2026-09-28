---
title: "Obfuscation - Flattening, Opaque Predicates, MBA, and How to Undo Them"
category: rev
subcategory: obfuscation
type: technique
tags: [obfuscation, deobfuscation, control-flow-flattening, opaque-predicates, mba, mixed-boolean-arithmetic, string-encryption, ollvm, tigress, triton, miasm, symbolic-execution, angr, z3, taint-analysis, simplification, bogus-control-flow, instruction-substitution]
difficulty: hard
summary: "Recognise OLLVM-style flattening, opaque predicates and MBA expressions, then peel them with symbolic execution, z3 simplification and a rewritten CFG."
when_to_use:
  - "The decompiler shows one giant while(1) with a switch on a state variable"
  - "Branches on expressions like ((x*x) % 2 == 0) that are always true"
  - "Arithmetic is absurdly long: chains of and/or/xor/not/add that compute something trivial"
  - "All strings are decrypted at runtime by a small helper called from everywhere"
tools: [triton, miasm, angr, z3, ghidra, binaryninja, ida, souper, msynth]
related: [custom-vm-bytecode, angr-symbolic-execution, z3-constraint-solving, binary-patching, packers-and-unpacking, unicorn-qiling-emulation]
---

## TL;DR

Four obfuscations cover nearly every CTF: control-flow flattening (a dispatcher loop plus a
state variable), opaque predicates (branches whose outcome is constant but not obviously so),
MBA expressions (huge arithmetic that equals `x ^ y`), and string encryption. All four are
undone the same way: get a symbolic or concrete model of the code, evaluate/simplify it, and
write a patched binary or a recovered CFG back out.

## Recognise it

| Symptom | Obfuscation |
|---|---|
| One `while (1) { switch (state) { case 0x4a2b...: } }` covering the whole function | control-flow flattening |
| Branch conditions using globals or `x*(x+1)%2`, both edges look reachable but only one runs | opaque predicate |
| 40 lines of `&`, `|`, `^`, `~`, `+`, `-` producing one value | MBA |
| Blocks that are never entered but contain plausible code | bogus control flow |
| `a + b` compiled as `(a ^ b) + 2*(a & b)` | instruction substitution |
| Every string is `decrypt(0x4030a0, 17)` | string encryption |
| Functions inlined into a single 20k-instruction blob | function merging / inlining |
| `call $+5; pop rax; add rax, N; jmp rax` | position-obfuscated jumps |
| Byte array + `switch` on `bytecode[pc]` | virtualisation - see `custom-vm-bytecode` |

Tooling fingerprints: OLLVM (Obfuscator-LLVM) produces `-fla`/`-bcf`/`-sub` patterns with a
characteristic `switch` on a 32-bit state and `%x = alloca` promoted state variables; Tigress
adds explicit dispatch types (`switch`, `indirect`, `call`, `ifnest`); VMProtect and Themida
virtualise; commercial .NET/Java obfuscators are covered in their own files.

## 1. Control-flow flattening

The original function:

```c
int check(int x) {
    int r = 0;
    if (x > 10) r = x * 2;
    else        r = x + 7;
    return r ^ 0x5a;
}
```

After flattening, every basic block becomes a `switch` case and the control flow is carried
in a state variable:

```c
int check_flat(int x) {
    unsigned state = 0x9B2F1A4C;     /* entry label */
    int r = 0;
    while (1) {
        switch (state) {
        case 0x9B2F1A4C: state = (x > 10) ? 0x11C4D0A2 : 0x7E3B9012; break;
        case 0x11C4D0A2: r = x * 2;  state = 0xA0FF3311; break;
        case 0x7E3B9012: r = x + 7;  state = 0xA0FF3311; break;
        case 0xA0FF3311: return r ^ 0x5a;
        }
    }
}
```

The structure is always: a **dispatcher** (the `switch`/jump table), **relevant blocks** (the
real code), a **pre-dispatcher** (a block that jumps back to the dispatcher), and the state
variable. Deflattening means recovering, for each relevant block, its real successors.

### Deflattening recipe (symbolic execution)

1. Identify the state variable: it is the one compared in the dispatcher and assigned at the
   end of every relevant block. In the decompiler it is usually a `uint32` local.
2. Enumerate the relevant blocks: every `case` target that is not the pre-dispatcher.
3. For each relevant block, symbolically execute *only that block* starting from a fresh
   state, then read the resulting state value:
   - if it is a single constant -> unconditional successor,
   - if it is `ITE(cond, A, B)` -> conditional successor with condition `cond`.
4. Rebuild a CFG from those edges and patch the binary: replace each block's tail with a
   direct `jmp` (unconditional) or with the original comparison plus two `jmp`s.

```python
#!/usr/bin/env python3
"""deflatten.py - recover the real successors of a flattened function with angr.

Strategy: run each relevant block in isolation with a blank state, then inspect the
symbolic value written to the state variable.

Usage:
    python3 deflatten.py ./obf 0x401150 0x401156 --blocks 0x401180 0x4011a0 0x4011c0

  0x401150 = function start, 0x401156 = address of the dispatcher's switch,
  --blocks = addresses of the relevant blocks (from the jump table).
"""
import argparse
import sys

import angr
import claripy


def successors_of(proj: "angr.Project", block_addr: int, state_reg: str) -> list[int]:
    """Symbolically run one block and report the constant state values it can produce."""
    state = proj.factory.blank_state(
        addr=block_addr,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    simgr = proj.factory.simulation_manager(state)
    simgr.step()                       # one basic block
    out = []
    for succ in simgr.active:
        val = getattr(succ.regs, state_reg)
        if val.concrete:
            out.append(succ.solver.eval(val))
        else:
            # ITE: enumerate up to 4 feasible concrete values
            for cand in succ.solver.eval_upto(val, 4):
                out.append(cand)
    return sorted(set(out))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("func", type=lambda s: int(s, 0))
    parser.add_argument("dispatcher", type=lambda s: int(s, 0))
    parser.add_argument("--blocks", nargs="+", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--state-reg", default="eax",
                        help="register holding the state at the end of a block")
    args = parser.parse_args()

    proj = angr.Project(args.binary, auto_load_libs=False)
    print(f"[*] function {args.func:#x}, dispatcher {args.dispatcher:#x}")
    edges: dict[int, list[int]] = {}
    for blk in args.blocks:
        try:
            edges[blk] = successors_of(proj, blk, args.state_reg)
        except Exception as exc:          # unmapped memory, unsupported instruction
            print(f"[-] {blk:#x}: {exc}", file=sys.stderr)
            edges[blk] = []
        kind = {0: "dead-end", 1: "unconditional", 2: "conditional"}.get(
            len(edges[blk]), "multi-way")
        vals = " ".join(f"{v:#x}" for v in edges[blk])
        print(f"  block {blk:#x} -> [{vals}]  ({kind})")

    print("\n[*] dot graph (pipe into: dot -Tpng -o cfg.png)")
    print("digraph deflattened {")
    for src, dsts in edges.items():
        for dst in dsts:
            print(f'  "{src:#x}" -> "state_{dst:#x}";')
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Notes on making this practical:

- Map the state value back to the block address by reading the dispatcher's jump table
  (`switch` on the state) - in Ghidra the table is decoded for you; in radare2 use
  `pdj` at the dispatcher and read the `jmptbl` metadata.
- Once you have the edge list, patch the binary: each relevant block's tail becomes
  `jmp <real target>` (see `binary-patching`). After patching, the decompiler produces
  readable output because the dispatcher is now dead code.
- Known open-source implementations to read: `deflat.py` (angr-based, cra0kee/ollvm-breaker
  lineage), Tim Blazytko's `miasm`-based deflattening, and Binary Ninja plugin variants.

## 2. Opaque predicates

An opaque predicate is a condition the obfuscator knows the answer to but the analyst does
not, at a glance:

```c
/* x*(x+1) is always even, so this is always false; the else branch is dead */
if (((x * (x + 1)) % 2) == 1) junk();
else                          real();

/* 7*y*y - 1 == z*z has no integer solutions => always false */
if (7 * y * y - 1 == z * z) junk();
```

Detect them by asking a solver whether *both* edges are satisfiable. If one edge is unsat
for all inputs, the branch is opaque and can be replaced by an unconditional jump.

```python
#!/usr/bin/env python3
"""opaque.py - prove (or disprove) that a branch condition is constant, with z3."""
from z3 import And, BitVec, Solver, sat, unsat


def is_opaque(make_condition, width: int = 32, nvars: int = 2) -> str:
    """Return 'always-true', 'always-false' or 'genuine' for a predicate builder."""
    vars_ = [BitVec(f"v{i}", width) for i in range(nvars)]
    cond = make_condition(*vars_)

    s_true = Solver()
    s_true.add(cond)
    s_false = Solver()
    s_false.add(cond == False)          # noqa: E712 - z3 needs the explicit comparison

    t = s_true.check()
    f = s_false.check()
    if t == unsat:
        return "always-false"
    if f == unsat:
        return "always-true"
    return "genuine"


if __name__ == "__main__":
    # x*(x+1) is always even -> the ==1 test can never hold
    assert is_opaque(lambda x, _y: (x * (x + 1)) % 2 == 1) == "always-false"
    # 7*y*y - 1 == z*z is unsatisfiable over the integers, but NOT over 32-bit wraparound:
    print("7y^2-1==z^2 over BV32:", is_opaque(lambda y, z: 7 * y * y - 1 == z * z))
    # a genuine branch
    assert is_opaque(lambda x, y: And(x > 10, y < 5)) == "genuine"
    print("[+] opaque predicate classifier OK")
```

Important subtlety visible in that self-test: predicates that are unsatisfiable over the
integers may be satisfiable modulo 2^32. Always model with `BitVec` of the *machine* width,
not `Int`, or you will "prove" the wrong thing. For predicates that depend on globals or on
values the obfuscator seeded earlier, use angr instead: run to the branch and check
`state.satisfiable(extra_constraints=(cond != 0,))` for each edge.

Once classified, patch: `always-true` -> `jmp taken`, `always-false` -> NOP the conditional
jump so execution falls through.

## 3. MBA (mixed boolean-arithmetic) expressions

MBA rewrites simple operations as long identities that are true for all inputs:

| Identity | Equals |
|---|---|
| `(x ^ y) + 2*(x & y)` | `x + y` |
| `(x | y) + (x & y)` | `x + y` |
| `(x + y) - 2*(x & y)` | `x ^ y` |
| `(x | y) - (x & y)` | `x ^ y` |
| `-(~x) - 1` | `x` |
| `(x & ~y) | (~x & y)` | `x ^ y` |
| `(x + y) - (x | y)` | `x & y` |
| `~(x - y) - 1` | `y - x` |
| `2*(x | y) - (x ^ y)` | `x + y` |

Two ways to simplify:

**(a) Prove equivalence with z3** - guess the simple form, then prove it equal for all inputs.

```python
#!/usr/bin/env python3
"""mba_simplify.py - prove an MBA expression equals a candidate simple form,
and search a small library of candidates automatically.
"""
import itertools

from z3 import BitVec, BitVecVal, Solver, simplify, unsat


def equivalent(f, g, width: int = 32, nvars: int = 2) -> bool:
    """True iff f(vars) == g(vars) for every possible input (proof by refutation)."""
    vars_ = [BitVec(f"x{i}", width) for i in range(nvars)]
    s = Solver()
    s.add(f(*vars_) != g(*vars_))
    return s.check() == unsat


CANDIDATES = {
    "x + y": lambda x, y: x + y,
    "x - y": lambda x, y: x - y,
    "y - x": lambda x, y: y - x,
    "x ^ y": lambda x, y: x ^ y,
    "x & y": lambda x, y: x & y,
    "x | y": lambda x, y: x | y,
    "x": lambda x, _y: x,
    "y": lambda _x, y: y,
    "~x": lambda x, _y: ~x,
    "0": lambda x, _y: BitVecVal(0, x.size()),
}


def identify(expr) -> str | None:
    """Return the name of the first library entry provably equal to `expr`."""
    for name, cand in CANDIDATES.items():
        if equivalent(expr, cand):
            return name
    return None


if __name__ == "__main__":
    obfuscated = lambda x, y: (x ^ y) + 2 * (x & y)          # noqa: E731
    assert identify(obfuscated) == "x + y"
    assert identify(lambda x, y: (x | y) - (x & y)) == "x ^ y"
    assert identify(lambda x, y: (x + y) - (x | y)) == "x & y"
    assert identify(lambda x, _y: -(~x) - 1) == "x"
    a, b = BitVec("a", 32), BitVec("b", 32)
    print("z3 simplify:", simplify((a ^ b) + 2 * (a & b)))
    print("[+] MBA identification OK for", len(list(itertools.repeat(0, 4))), "cases")
```

**(b) Program synthesis** - when you cannot guess the simple form, sample the obfuscated
function on random inputs and search for the smallest expression matching the I/O behaviour.
This is what `msynth`, `Syntia` and `QSynthesis` do; `souper` does the LLVM-IR equivalent.
The cheap DIY version: evaluate the expression on many random `(x, y)` pairs and compare the
output table against every candidate - identical tables over a few thousand random inputs is
strong evidence, and z3 then proves it.

## 4. String encryption

```c
/* every literal becomes a call to a decryptor over an encrypted blob */
static char *dec(const unsigned char *p, int n, unsigned char k) {
    static char buf[256];
    for (int i = 0; i < n; i++) buf[i] = p[i] ^ (k + i);
    buf[n] = 0;
    return buf;
}
puts(dec(blob_0x4030a0, 17, 0x5a));
```

Three approaches, in order of effort:

1. **Reimplement the decryptor in Python** and run it over every blob. Find the blobs by
   cross-referencing the decryptor's first argument (`axt` in r2, `Ctrl+X`/References in
   Ghidra) and reading the constant arguments at each call site.
2. **Emulate the decryptor** with Unicorn for each `(ptr, len, key)` triple you scraped from
   the call sites - no transcription bugs. See `unicorn-qiling-emulation`.
3. **Run and dump**: set a breakpoint on the decryptor's `ret`, log the return buffer and the
   caller address, and let the program run. In gdb:

```
(gdb) break *0x4011d0
(gdb) commands
>silent
>printf "%s\n", (char*)$rax
>continue
>end
(gdb) run
```

Then annotate the binary: write each recovered string as a comment at its call site
(a Ghidra script doing this is in `ghidra-headless-scripts`).

## 5. Instruction substitution and bogus control flow

OLLVM's `-sub` replaces `a + b` with `a - (-b)`, `(a ^ b) + 2*(a & b)`, etc. `-bcf` inserts
clone blocks guarded by opaque predicates. Both are handled by the tools above: classify the
predicates to delete the bogus edges, then simplify the arithmetic. After that, the decompiler
usually recovers the original function outright.

## Tool-driven workflows

```sh
# --- Triton: build a symbolic expression for a range and simplify it ---------
# (Triton is a dynamic binary analysis framework with an AST layer + z3 backend)
python3 - <<'PY'
from triton import ARCH, TritonContext, Instruction
ctx = TritonContext(ARCH.X86_64)
ctx.setConcreteRegisterValue(ctx.registers.rax, 0)
for code in (b"\x48\x31\xd8", b"\x48\x01\xd8"):      # xor rax,rbx ; add rax,rbx
    inst = Instruction(code)
    ctx.processing(inst)
    print(inst.getDisassembly(), "->", inst.getSymbolicExpressions())
PY

# --- miasm: lift to IR and run the expression simplifier --------------------
python3 - <<'PY'
from miasm.analysis.machine import Machine
from miasm.expression.simplifications import expr_simp
from miasm.core.locationdb import LocationDB
loc_db = LocationDB()
machine = Machine("x86_64")
mdis = machine.dis_engine(bytes.fromhex("4831d84801d8"), loc_db=loc_db)
# lift a block to IR and simplify each assignment with expr_simp
PY

# --- Binary Ninja: HLIL already folds most MBA and dead branches -------------
# Open in Binary Ninja, switch the view to "High Level IL"; its dataflow removes
# opaque-predicate edges automatically when the condition is provably constant.
```

Ghidra's decompiler also constant-folds aggressively: if an opaque predicate depends only on
constants it already knows, the dead branch disappears. When it does not, help it by
retyping/defining the relevant globals as constants (`Ctrl+L`, then mark the data as
read-only in the Memory Map so the decompiler may fold it).

## Attack - end-to-end order of operations

1. Unpack first if packed (`packers-and-unpacking`). Obfuscation on top of packing is common.
2. Dump strings by running the decryptor - this immediately tells you what the program does.
3. Classify every branch: kill the opaque ones, patch them out, re-decompile.
4. Deflatten: recover the edges, patch the tails, re-decompile.
5. Simplify the arithmetic (z3 or Binary Ninja HLIL).
6. If what remains is a `switch` over a byte array, it is a VM - switch to
   `custom-vm-bytecode`.
7. Only now solve the actual challenge (usually a constraint system - `z3-constraint-solving`).

## Variants & pitfalls

- **Do not deobfuscate what you can emulate.** If the goal is "what does this function
  compute", emulate it with Unicorn on many inputs and infer the behaviour. Obfuscation
  protects readability, not semantics.
- **State variable in memory, not a register**: OLLVM often keeps it in a stack slot. Track
  the stack offset instead of a register in the deflattening script.
- **Multiple dispatchers** (nested flattening) or a state that is itself computed by an MBA
  expression. Simplify the MBA first, then deflatten.
- **Anti-tamper checksums** over `.text` will trip when you patch. Find and neutralise them
  first (see `anti-debug-bypass`).
- **z3 over Int instead of BitVec** gives wrong answers for wraparound - always BitVec.
- **angr in deflattening can wander** out of the block. Step exactly one basic block
  (`simgr.step(num_inst=...)` or a single `step()`), never `run()`.
- **Virtualisation is not flattening**: if the `switch` dispatches on a byte fetched from a
  data array with a program counter, you have a VM. Different playbook.
- **Timeboxing**: in a CTF, fully deobfuscating is rarely the fastest path. Side-channel
  (`side-channel-instruction-counting`) or symbolic execution on the *obfuscated* binary
  often wins.

## Tools

- `angr` - symbolic execution; the standard base for deflattening scripts.
- `Triton` - dynamic symbolic execution with an AST simplifier and a z3 backend.
- `miasm` - IR lifting, `expr_simp`, symbolic execution, and a re-assembler for patching.
- `z3-solver` - predicate classification and MBA equivalence proofs.
- `msynth` / `Syntia` / `QSynthesis` - program synthesis for MBA you cannot guess.
- `Binary Ninja` HLIL, `Ghidra` decompiler - free dataflow-based simplification.
- `souper` - superoptimiser over LLVM IR, useful when you can lift to IR.

## References

- Obfuscator-LLVM documentation: the `-fla`, `-bcf` and `-sub` passes described above.
- Tigress documentation (transformation catalogue: flatten, opaque, encodeArithmetic, virtualize).
- Tim Blazytko's public writing and talks on automated deobfuscation and program synthesis.
