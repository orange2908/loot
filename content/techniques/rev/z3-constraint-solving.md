---
title: "z3 - Constraint Solving for Reverse Engineering"
category: rev
subcategory: z3
type: technique
tags: [z3, smt, constraint-solving, bitvector, bitvec, symbolic-execution, claripy, keygen, flag-checker, lshr, extract, concat, zeroext, signext, feistel, xor, decompiler, python, angr]
difficulty: medium
summary: "Translate a decompiled checker into BitVec constraints and let z3 invert it: widths, LShR vs >>, unsigned ops, tables, and enumerating every solution."
when_to_use:
  - "You have decompiled a flag checker and can write its math as equations over input bytes"
  - "angr blew up on state explosion but the per-byte arithmetic is easy to transcribe"
  - "The check is a system of linear equations, a matrix multiply, or a sum/product over bytes"
  - "You need every valid serial (a keygen), not just one, or you need to prove the flag is unique"
  - "Custom block cipher / Feistel / rotate-xor-add rounds with a small block size"
tools: [z3, z3-solver, python, ghidra, ida]
related: [z3-flagsolver-template, angr-symbolic-execution, angr-z3-cheatsheet, custom-vm-bytecode, unicorn-qiling-emulation, side-channel-instruction-counting]
---

## TL;DR

z3 is an SMT solver. You declare the flag as a list of 8-bit bitvectors, restate the
decompiled checker's arithmetic as constraints over them, call `s.check()`, and read the
flag out of `s.model()`. It is faster and far more predictable than angr whenever you can
read the math off the decompiler. The single biggest bug source is using `>>` (arithmetic
shift) where the C code did a logical shift - use `LShR`.

Install: `pip install z3-solver`. Import: `from z3 import *`.

## Recognise it

- Ghidra output is pure arithmetic on `buf[i]`: `^`, `+`, `*`, `<<`, `>>`, `&`, `%`.
- A fixed comparison table: `local_38 = {0xa8, 0xe1, 0xc5, ...}` compared byte by byte.
- A system of sums: `if (s[0]+s[1]+s[2] != 0x1a4) return 0;` repeated N times.
- A rotate/xor/add round function run a fixed small number of times.
- A table lookup `sbox[buf[i]]` with a 256-byte table in `.rodata`.
- Sudoku/nonogram-style "misc" challenges where the flag is a puzzle solution.

## Theory

### Why `BitVec`, never `Int`

`Int` is a mathematical integer: unbounded, no wraparound, and `^`/`<<`/`>>` are not even
defined on it. C arithmetic on `unsigned char`/`uint32_t` wraps modulo 2^n. A `BitVec(name, n)`
models exactly that: fixed width, two's complement, wrapping `+`/`*`, real bitwise ops.

| C type | z3 |
|---|---|
| `unsigned char` / `uint8_t` | `BitVec(name, 8)` |
| `int` / `unsigned int` / `uint32_t` | `BitVec(name, 32)` |
| `long` / `uint64_t` | `BitVec(name, 64)` |
| literal constant | `BitVecVal(0x41, 8)` |

Width must match on both sides of an operator or z3 raises
`sort mismatch`. Widen with `ZeroExt(k, bv)` (unsigned, pads zeros) or
`SignExt(k, bv)` (signed, replicates the top bit). Narrow with `Extract(hi, lo, bv)`
(inclusive bit indices, `Extract(7, 0, x)` is the low byte). Join with
`Concat(hi, ..., lo)` - **first argument is the most significant**.

### Signedness

z3's default operators are signed: `>>` is arithmetic, `/` is `sdiv`, `%` is `srem`, `<`
is `slt`. For C `unsigned` semantics use `LShR`, `UDiv`, `URem`, `ULT`, `ULE`, `UGT`, `UGE`.
Getting this wrong silently produces a wrong (or unsat) answer, never an error.

### Solvers

`Solver()` is the general solver. `SolverFor("QF_BV")` selects the quantifier-free
bitvector tactic directly and is typically 2-10x faster on pure flag-checker models.
Use `s.set("timeout", 60000)` (milliseconds) so a bad model fails fast instead of hanging.

## Workflow

1. Decompile the checker. Write down, in C, exactly what happens to each input byte.
2. Note every integer width and every cast. `(char)` vs `(unsigned char)` changes the model.
3. Declare `flag = [BitVec(f"f_{i}", 8) for i in range(N)]`.
4. Add printable constraints **first** - they prune massively and stop garbage answers.
5. Transcribe the loop body, replacing `>>` with `LShR` on unsigned values.
6. `s.check()`. On `sat`, read `m[flag[i]].as_long()`. On `unsat`, one constraint is wrong:
   comment out half of them and bisect.
7. Verify by running the recovered flag through the real binary.

## Code

### Worked example: a rotate-xor-add checker

The decompiled function, straight out of Ghidra with variables renamed:

```c
/* target: ./rotchk, check() at 0x4011b6 */
static const unsigned char enc[16] = {
    0xa8, 0xe1, 0xc5, 0xed, 0xfe, 0x1b, 0xe0, 0xe1,
    0x1a, 0xb8, 0x1e, 0x03, 0x24, 0xf3, 0x10, 0x19
};

int check(const char *s)
{
    if (strlen(s) != 16)
        return 0;
    for (int i = 0; i < 16; i++) {
        unsigned char c = (unsigned char)s[i];
        c = (unsigned char)((c << 3) | (c >> 5));  /* rol 3 -- LOGICAL >> on uchar */
        c ^= (unsigned char)(0x5a + i);
        c = (unsigned char)(c + 0x1f);
        if (c != enc[i])
            return 0;
    }
    return 1;
}
```

The z3 model. Note `(c << 3) | (c >> 5)` on an 8-bit value becomes
`(c << 3) | LShR(c, 5)` - the truncation to 8 bits is automatic because `c` is a
`BitVec(_, 8)`, so no masking is needed.

```python
#!/usr/bin/env python3
"""Invert the rol3/xor/add checker from ./rotchk with z3.

Self-testing: recomputes the ciphertext from the recovered flag and asserts a match.
Run: python3 solve_rotchk.py
"""
from z3 import And, BitVec, BitVecVal, LShR, Or, SolverFor, sat

ENC = [0xA8, 0xE1, 0xC5, 0xED, 0xFE, 0x1B, 0xE0, 0xE1,
       0x1A, 0xB8, 0x1E, 0x03, 0x24, 0xF3, 0x10, 0x19]
N = len(ENC)


def build_solver():
    """Return (solver, flag_bitvecs) with the checker encoded as constraints."""
    s = SolverFor("QF_BV")       # quantifier-free bitvector logic: fastest path
    s.set("timeout", 60000)      # milliseconds; never hang forever
    flag = [BitVec(f"f_{i}", 8) for i in range(N)]

    for i, ch in enumerate(flag):
        # Printable ASCII. Without this, z3 happily returns control characters.
        s.add(And(ch >= 0x20, ch <= 0x7E))

        c = (ch << 3) | LShR(ch, 5)              # rol 3 on 8 bits; LShR, not >>
        c = c ^ BitVecVal((0x5A + i) & 0xFF, 8)  # widths must match: 8-bit constant
        c = c + BitVecVal(0x1F, 8)               # wraps mod 256 automatically
        s.add(c == ENC[i])                       # int literal is coerced to 8-bit here
    return s, flag


def model_to_bytes(model, flag):
    return bytes(model[b].as_long() for b in flag)


def reference_impl(buf):
    """Concrete reimplementation of check(), used as the self-test oracle."""
    out = []
    for i, c in enumerate(buf):
        c = ((c << 3) | (c >> 5)) & 0xFF
        c ^= (0x5A + i) & 0xFF
        c = (c + 0x1F) & 0xFF
        out.append(c)
    return out


def main():
    s, flag = build_solver()
    if s.check() != sat:
        print("[-] unsat -- a constraint is wrong")
        return 1

    solution = model_to_bytes(s.model(), flag)
    print("[+] flag:", solution.decode())
    assert reference_impl(solution) == ENC, "self-test failed"

    # Uniqueness: forbid this exact assignment and re-solve.
    s.add(Or([b != v for b, v in zip(flag, solution)]))
    print("[+] unique" if s.check() != sat else "[!] more than one solution exists")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Output: `[+] flag: z3_r0t4t3_s0lv3r` and `[+] unique`.

### Linear system from a decompiled checker

```c
/* 8 equations, 8 unknowns, all arithmetic in 32-bit unsigned */
static const unsigned int M[8][8] = {
    {21, 10, 26, 42,  4,  5, 35,  7},
    {24, 38,  4, 33, 14,  3,  6, 28},
    {27,  5, 16,  6, 36, 28,  4, 37},
    { 8, 15, 41, 41, 38,  4, 37, 38},
    {26,  4, 15,  3, 36,  9, 19, 27},
    {10, 35,  8, 37, 20, 36, 44, 12},
    { 7, 38, 37, 41, 13, 24,  7, 36},
    {46,  5, 37,  4, 40, 14, 32, 44},
};
static const unsigned int T[8] = {
    0x2bef, 0x2097, 0x2b00, 0x3a70, 0x2502, 0x3996, 0x35d9, 0x3e97
};

int check(const unsigned char *s)   /* s is 8 bytes */
{
    for (int r = 0; r < 8; r++) {
        unsigned int acc = 0;
        for (int c = 0; c < 8; c++)
            acc += M[r][c] * (unsigned int)s[c];
        if (acc != T[r])
            return 0;
    }
    return 1;
}
```

```python
#!/usr/bin/env python3
"""Solve an 8x8 linear system over 32-bit words with z3."""
from z3 import BitVec, Or, Solver, Sum, ZeroExt, sat

M = [
    [21, 10, 26, 42, 4, 5, 35, 7],
    [24, 38, 4, 33, 14, 3, 6, 28],
    [27, 5, 16, 6, 36, 28, 4, 37],
    [8, 15, 41, 41, 38, 4, 37, 38],
    [26, 4, 15, 3, 36, 9, 19, 27],
    [10, 35, 8, 37, 20, 36, 44, 12],
    [7, 38, 37, 41, 13, 24, 7, 36],
    [46, 5, 37, 4, 40, 14, 32, 44],
]
T = [0x2BEF, 0x2097, 0x2B00, 0x3A70, 0x2502, 0x3996, 0x35D9, 0x3E97]


def main():
    s = Solver()
    f = [BitVec(f"f_{i}", 8) for i in range(8)]
    for b in f:
        s.add(b >= 0x20, b <= 0x7E)

    for r in range(8):
        # ZeroExt(24, b) widens the 8-bit byte to 32 bits UNSIGNED, matching
        # the C promotion of `unsigned char` to `unsigned int`. SignExt here
        # would be wrong for bytes >= 0x80 (there are none after the printable
        # constraint, but be correct anyway).
        acc = Sum([ZeroExt(24, f[c]) * M[r][c] for c in range(8)])
        s.add(acc == T[r])

    if s.check() != sat:
        print("[-] unsat")
        return 1
    m = s.model()
    out = bytes(m[b].as_long() for b in f)
    print("[+] flag part:", out.decode())

    s.add(Or([b != v for b, v in zip(f, out)]))
    print("[+] unique" if s.check() != sat else "[!] non-unique")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Output: `L1n34rZ!`, unique.

### Feistel / rotate network, and Extract/Concat

```c
/* 4-round Feistel on a 32-bit block, 16-bit halves */
static const unsigned short KEYS[4] = {0x1234, 0x9abc, 0x5555, 0xf00d};

unsigned int encrypt(unsigned int v)
{
    unsigned short l = v & 0xffff, r = v >> 16;
    for (int i = 0; i < 4; i++) {
        unsigned short t = r;
        r = l ^ (unsigned short)(((r << 3) | (r >> 13)) + KEYS[i]);
        l = t;
    }
    return ((unsigned int)r << 16) | l;
}
/* check(): encrypt(*(unsigned int *)s) == 0xde897be4 */
```

```python
#!/usr/bin/env python3
"""Invert a 4-round 32-bit Feistel with z3 using Extract/Concat."""
from z3 import BitVec, BitVecVal, Concat, Extract, LShR, Solver, sat

# NOTE: do not name this list `K`. `from z3 import *` exports z3's own K()
# (constant-array constructor) and it will shadow your variable.
KEYS = [0x1234, 0x9ABC, 0x5555, 0xF00D]
TARGET = 0xDE897BE4


def main():
    s = Solver()
    b = [BitVec(f"b{i}", 8) for i in range(4)]
    for x in b:
        s.add(x >= 0x20, x <= 0x7E)

    # Little-endian *(uint32_t *)s -> most significant byte first in Concat.
    v = Concat(b[3], b[2], b[1], b[0])
    lo = Extract(15, 0, v)   # v & 0xffff
    hi = Extract(31, 16, v)  # v >> 16

    for i in range(4):
        t = hi
        # (r << 3) | (r >> 13) on a 16-bit unsigned -> LShR, and both halves
        # stay 16 bits so the OR is well-sorted.
        hi = lo ^ (((hi << 3) | LShR(hi, 13)) + BitVecVal(KEYS[i], 16))
        lo = t

    s.add(Concat(hi, lo) == BitVecVal(TARGET, 32))

    if s.check() != sat:
        print("[-] unsat")
        return 1
    m = s.model()
    print("[+] block:", bytes(m[x].as_long() for x in b).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Output: `F31s`.

### Table lookups, If/Sum/Distinct, and enumerating every solution

```python
#!/usr/bin/env python3
"""z3 patterns: Array/Select/Store tables, If/Sum/Distinct, all-solution enumeration."""
from z3 import (Array, BitVec, BitVecSort, BitVecVal, Distinct, If, Or, Select,
                Solver, Store, Sum, sat, set_param, simplify)

SBOX = [(i * 7 + 13) & 0xFF for i in range(256)]


def sbox_lookup_demo():
    """Model `if (sbox[x] != 0x42) return 0;` without unrolling 256 If()s."""
    s = Solver()
    tbl = Array("sbox", BitVecSort(8), BitVecSort(8))
    for i, v in enumerate(SBOX):
        tbl = Store(tbl, BitVecVal(i, 8), BitVecVal(v, 8))
    x = BitVec("x", 8)
    s.add(Select(tbl, x) == 0x42)
    assert s.check() == sat
    return s.model()[x].as_long()


def puzzle_demo():
    """If / Sum / Distinct: four distinct digits 1..9 whose members >5 sum to 15."""
    s = Solver()
    ns = [BitVec(f"n{i}", 16) for i in range(4)]
    for n in ns:
        s.add(n >= 1, n <= 9)
    s.add(Distinct(ns))
    s.add(Sum([If(n > 5, n, 0) for n in ns]) == 15)
    assert s.check() == sat
    m = s.model()
    return [m[n].as_long() for n in ns]


def all_solutions(limit=8):
    """Keygen pattern: block each model and re-solve until unsat or limit hit."""
    s = Solver()
    a, b = BitVec("a", 8), BitVec("b", 8)
    s.add(a >= 0x30, a <= 0x39, b >= 0x30, b <= 0x39)
    s.add((a ^ b) == 0x05)          # many serials satisfy this
    out = []
    while len(out) < limit and s.check() == sat:
        m = s.model()
        av, bv = m[a].as_long(), m[b].as_long()
        out.append((av, bv))
        # Block exactly this assignment; anything different is still allowed.
        s.add(Or(a != av, b != bv))
    return out


def main():
    # Use every core on a hard QF_BV instance. Harmless on easy ones.
    set_param("parallel.enable", True)
    set_param("parallel.threads.max", 8)

    print("[+] sbox preimage of 0x42:", hex(sbox_lookup_demo()))
    print("[+] puzzle digits:", puzzle_demo())
    print("[+] serials:", [(chr(x), chr(y)) for x, y in all_solutions()])
    # simplify() collapses an AST before you print or re-use it.
    print("[+] simplified:", simplify(BitVecVal(0xF0, 8) & BitVecVal(0x3C, 8)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Variants & pitfalls

- **`>>` is arithmetic.** `BitVec("x", 8) >> 5` sign-extends. For C `unsigned char c; c >> 5`
  you must write `LShR(c, 5)`. This is the number one cause of "z3 says unsat but I read the
  decompiler correctly". Symptom: works for inputs < 0x80, fails for the rest.
- **`==` builds a constraint, not a bool.** `if bv == 5:` is always truthy because
  `BoolRef.__bool__` is not what you think. Use `s.add(bv == 5)`, and for concrete checks
  use `is_true(simplify(bv == 5))`.
- **Python `int` does not wrap.** `(c << 3) | (c >> 5)` in plain Python needs `& 0xFF`;
  inside z3 on an 8-bit BitVec the truncation is automatic. If you mix the two while
  writing a reference implementation, mask in the Python side only.
- **Sort mismatch.** `BitVec("x", 8) + BitVecVal(1, 32)` throws. Widen deliberately:
  `ZeroExt(24, x) + BitVecVal(1, 32)`. A bare Python `int` is auto-coerced to the other
  operand's width, which is convenient but hides width bugs - prefer explicit `BitVecVal`.
- **`ZeroExt` vs `SignExt`.** C promotes `unsigned char` with zero extension and `char`
  (signed on x86 Linux) with sign extension. Ghidra shows `(int)(char)buf[i]` for the
  signed case. Get this wrong and bytes >= 0x80 solve incorrectly.
- **Unsigned comparisons.** `x < 100` is signed-less-than. If the C is
  `if ((unsigned)x < 100)`, write `ULT(x, 100)`. Same for `UDiv`/`URem` versus `/`/`%`.
- **`/` and `%` on BitVecs are signed.** `BitVecVal(-8, 8) / 3` is not `0xf8 // 3`.
- **Forgetting printable constraints.** You get a "flag" full of `\x00` and `\x8f`. Add
  `0x20 <= c <= 0x7e`, or the tighter `[a-zA-Z0-9_{}]` set when the flag format is known.
- **Off-by-one index -> unsat.** `enc[i]` vs `enc[i+1]`, or a loop that runs `i < len`
  where `len` came from `strlen` and excludes the terminator. When unsat, remove the
  constraints one index at a time; the first index that makes it sat is your bug.
- **Name shadowing from `from z3 import *`.** z3 exports `K`, `Q`, `Int`, `Array`, `If`,
  `Sum`, `Not`, `And`, `Or`, `Select`, `Store`, `Extract`, `Concat`. A local variable named
  `K` or `Sum` breaks in a confusing way. Prefer explicit imports, as the scripts above do.
- **Unknown instead of sat/unsat.** Your timeout fired, or the model has multiplication of
  two symbolic variables (nonlinear BV is hard). Reduce: fix some bytes concretely, split
  the problem, or switch to `SolverFor("QF_BV")`.
- **Huge unrolled tables.** Do not emit 256 `If()` branches per lookup; use
  `Array` + `Store`/`Select`, or if the table is a permutation, invert it in Python and
  constrain the inverse instead.
- **Push/pop for what-if queries.** `s.push()` / `s.add(...)` / `s.check()` / `s.pop()`
  lets you test an extra hypothesis without rebuilding the model.
- **z3 is not a brute forcer.** If the "constraint" is `sha256(flag) == H`, z3 will never
  finish. Hash preimages, big-modulus RSA, and AES key recovery are out of scope.
- **Cross-check with angr.** If you distrust your transcription, run
  `angr-symbolic-execution` on a shortened version of the binary and compare.

## Tools

- `z3-solver` (`pip install z3-solver`) - the Python bindings; `z3.get_version_string()`.
- `claripy` - angr's frontend over z3; same BitVec semantics, `claripy.BVS/BVV/LShR`.
- `python-constraint` / OR-Tools CP-SAT - better than z3 for pure combinatorial puzzles.
- SageMath - better for linear algebra over a field (`Matrix(GF(2), rows).solve_right(vector(GF(2), target))`).
- Ghidra / IDA - where you read the arithmetic off in the first place.

## References

- Microsoft Research z3 project and its Python API docs (github.com/Z3Prover/z3), including
  the Programming Z3 guide.
- z3 `BitVec` operator semantics: signed by default; `LShR`, `UDiv`, `URem`, `ULT`, `ULE`,
  `UGT`, `UGE` for unsigned variants.
- See also: `z3-flagsolver-template`, `angr-symbolic-execution`, `angr-z3-cheatsheet`.
