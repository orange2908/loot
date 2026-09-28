---
title: "z3 Flag Solver Template - byte arrays, charsets and all_solutions"
category: rev
subcategory: z3
type: script
tags: [z3, z3-solver, smt, constraint-solving, satisfiability, bitvector, flag-checker, crackme, keygen, lshr, zeroext, signext, udiv, urem, popcount, sbox, linear-system, python, symbolic-execution]
summary: "Runnable z3 skeleton for byte-array flag constraints: charset helpers, bitvector modelling cookbook, all_solutions generator, uniqueness check and a self-test."
tools: [z3, python]
related: [z3-constraint-solving, angr-template, angr-symbolic-execution, angr-z3-cheatsheet, crackme-patterns, custom-vm-bytecode, side-channel-instruction-counting]
---

## What this is

You read a checker in Ghidra, you can write down what it does to each byte, and
you want the input back. That is z3's home turf and it takes about 20 lines.
This file is the 20 lines plus every modelling idiom you will reach for.
Install with `pip install z3-solver` (the import is still `z3`).

Every solve has the same shape:

1. One 8-bit `BitVec` per flag byte.
2. Domain constraints: printable / charset / known prefix and suffix / length.
3. The checker, transcribed operation-for-operation into z3 expressions.
4. `s.check()`, read the model, join the bytes.
5. Block the model and re-check - if it is still `sat`, your model is
   under-constrained and the "flag" you got is probably garbage.

## The template

```python
#!/usr/bin/env python3
"""z3 flag-solver skeleton. Runs its own self-test: python3 flagsolver.py"""
import string
import sys

from z3 import (And, Array, BitVec, BitVecSort, BitVecVal, Distinct, Extract,
                If, LShR, Not, Or, RotateLeft, RotateRight, Select, SignExt,
                Solver, Store, Sum, UDiv, UGE, ULE, ULT, URem, ZeroExt,
                set_param, sat)

# Narrowing the domain is the cheapest speed-up there is.
HEX = string.hexdigits[:16] + "ABCDEF"
B64 = string.ascii_letters + string.digits + "+/="
FLAGCHARS = string.ascii_letters + string.digits + "_{}-!?@#$%^&*().,"


def flag_vars(n, name="f"):
    """One 8-bit BitVec per byte: readable constraints, printable partials."""
    return [BitVec("%s_%02d" % (name, i), 8) for i in range(n)]


def printable(fs, lo=0x20, hi=0x7E):
    """UGE/ULE, not >=/<=. BitVec comparison operators in z3 are SIGNED, so
    `f <= 0x7e` silently also allows 0x80..0xff (they are negative)."""
    return [And(UGE(f, lo), ULE(f, hi)) for f in fs]


def in_charset(fs, charset=FLAGCHARS):
    """One disjunction per byte: slower to build than a range, much faster to
    solve when the alphabet is small."""
    return [Or([f == ord(c) for c in charset]) for f in fs]


def fix_prefix(fs, prefix=b"CTF{"):
    """Pin the wrapper. Each fixed byte is one fewer free variable."""
    return [fs[i] == prefix[i] for i in range(len(prefix))]


def fix_suffix(fs, suffix=b"}"):
    return [fs[len(fs) - len(suffix) + i] == suffix[i] for i in range(len(suffix))]


def solve(fs, cons, timeout_ms=60000):
    """Flag as bytes, or None on unsat/timeout. model_completion=True yields 0
    for bytes no constraint mentions, so you can see which positions are free."""
    s = Solver()
    s.set("timeout", timeout_ms)
    s.add(cons)
    if s.check() != sat:
        return None
    m = s.model()
    return bytes(m.eval(f, model_completion=True).as_long() for f in fs)


def all_solutions(fs, cons, limit=16, timeout_ms=60000):
    """Yield every distinct solution, blocking each model as it is found: the
    blocking clause says 'at least one byte differs from last time'."""
    s = Solver()
    s.set("timeout", timeout_ms)
    s.add(cons)
    found = 0
    while found < limit and s.check() == sat:
        m = s.model()
        vals = [m.eval(f, model_completion=True).as_long() for f in fs]
        yield bytes(vals)
        found += 1
        s.add(Or([f != v for f, v in zip(fs, vals)]))


def is_unique(fs, cons, timeout_ms=60000):
    """True if exactly one solution exists. Always run this: a second solution
    means you under-modelled the checker and the first answer may be junk."""
    sols = list(all_solutions(fs, cons, limit=2, timeout_ms=timeout_ms))
    return len(sols) == 1


# --- modelling cookbook -----------------------------------------------------

def rol(x, n):
    """Rotate left - one SMT op. Prefer these two."""
    return RotateLeft(x, n)


def ror(x, n):
    return RotateRight(x, n)


def rol_manual(x, n, width=8):
    """The form the decompiler actually shows you. LShR, not >>: the C idiom
    `(c << 3) | (c >> 5)` on an unsigned char is a LOGICAL right shift."""
    return (x << n) | LShR(x, width - n)


def popcount(x, width=8):
    """__builtin_popcount / the classic SWAR loop. Sum the extracted bits."""
    return Sum([ZeroExt(width - 1, Extract(i, i, x)) for i in range(width)])


def table_array(name, values):
    """A 256-entry lookup table (sbox, charmap, scrambled alphabet) as a z3
    Array: Store to build, Select to index with a symbolic byte. Correct, but
    a 256-deep Store chain is murder on the solver - see table_if below."""
    arr = Array(name, BitVecSort(8), BitVecSort(8))
    for i, v in enumerate(values):
        arr = Store(arr, BitVecVal(i, 8), BitVecVal(v & 0xFF, 8))
    return arr


def table_if(values, x, lo=0x20, hi=0x7E):
    """The same lookup as a nested If chain, built only over the bytes the
    domain constraints already allow. On a 4x4 sbox+matrix system this solved
    in 0.1s where the Array/Store version had not finished in 60s. Always
    restrict the table to the reachable domain before you hand it to z3."""
    e = BitVecVal(values[hi] & 0xFF, 8)
    for i in range(lo, hi):
        e = If(x == BitVecVal(i, 8), BitVecVal(values[i] & 0xFF, 8), e)
    return e


# --- self-test --------------------------------------------------------------

SECRET = b"CTF{z3_1s_4_b1g_hamm3r}"
KEY = [0x5A, 0x1D, 0xC3, 0x77]


def obfuscate(buf):
    """The 'checker' in plain python, so the self-test has ground truth.
    rol 3, xor a repeating key, add the index, xor the previous output."""
    out = []
    prev = 0xAB
    for i, b in enumerate(buf):
        c = ((b << 3) | (b >> 5)) & 0xFF
        c ^= KEY[i % 4]
        c = (c + i) & 0xFF
        c ^= prev
        prev = c
        out.append(c)
    return bytes(out)


def model_checker(fs, expected):
    """The same transform, transcribed into z3. Note there is no `& 0xFF`:
    8-bit BitVec arithmetic already wraps mod 256, exactly like `unsigned char`."""
    cons = []
    prev = BitVecVal(0xAB, 8)
    for i, f in enumerate(fs):
        c = rol(f, 3)
        c = c ^ BitVecVal(KEY[i % 4], 8)
        c = c + BitVecVal(i, 8)
        c = c ^ prev
        prev = c
        cons.append(c == BitVecVal(expected[i], 8))
    return cons


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    n = len(SECRET)
    expected = obfuscate(SECRET)
    print("[*] target ciphertext: %s" % expected.hex())

    fs = flag_vars(n)
    cons = []
    cons += printable(fs)                       # domain
    cons += in_charset(fs)                      # tighter domain
    cons += fix_prefix(fs, b"CTF{")             # known wrapper
    cons += fix_suffix(fs, b"}")
    cons += model_checker(fs, expected)         # the checker itself

    flag = solve(fs, cons)
    print("[+] recovered: %r" % flag)
    assert flag == SECRET, "self-test failed: %r != %r" % (flag, SECRET)

    uniq = is_unique(fs, cons)
    print("[+] unique solution: %s" % uniq)
    assert uniq, "model is under-constrained"

    # all_solutions on a deliberately loose system: 4 distinct bytes with a
    # fixed sum. Distinct() is z3's 'all different' - good for permutations.
    xs = flag_vars(4, "x")
    total = Sum([ZeroExt(8, x) for x in xs])        # widen first: 4*0x64 > 255
    loose = printable(xs, 0x61, 0x64) + [Distinct(xs), total == 0x18A]
    print("[*] loose system solutions: %s" % [s for s in all_solutions(xs, loose, limit=3)])

    if argv and argv[0] == "--bench":
        set_param("parallel.enable", True)      # let z3 use several threads
        set_param("parallel.threads.max", 8)
    print("[+] self-test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Modelling cookbook

Transcribing C into z3, operator by operator. The traps are all about signedness
and width.

```python
from z3 import (Array, BitVec, BitVecSort, BitVecVal, Concat, Distinct, Extract,
                If, LShR, RotateLeft, Select, SignExt, Store, Sum, UDiv, UGT,
                ULT, URem, ZeroExt)

x = BitVec("x", 8)
y = BitVec("y", 32)

#  C: x >> 2   on an UNSIGNED char  ->  logical shift
logical = LShR(x, 2)
#  C: x >> 2   on a SIGNED char     ->  arithmetic shift (z3's >> is arithmetic)
arith = x >> 2

widened_u = ZeroExt(24, x)                # C: (unsigned int)x
widened_s = SignExt(24, x)                # C: (int)(signed char)x
narrowed = Extract(7, 0, y)               # C: (unsigned char)y

#  C: y / 3 and y % 3 on an UNSIGNED int. z3's / and % are SIGNED.
udiv, umod = UDiv(y, 3), URem(y, 3)
unsigned_lt = ULT(y, 0x80000000)          # C: if (a < b) on unsigned

#  Build a 32-bit word out of 4 flag bytes, little-endian like x86 does.
b0, b1, b2, b3 = (BitVec("b%d" % i, 8) for i in range(4))
word_le = Concat(b3, b2, b1, b0)

#  C: out[i] = sbox[in[i]]  -> an Array indexed by a symbolic byte
#  (correct, but see table_if in the template: much faster in practice)
sbox = Array("sbox", BitVecSort(8), BitVecSort(8))
for i in range(256):
    sbox = Store(sbox, BitVecVal(i, 8), BitVecVal((i * 167 + 13) & 0xFF, 8))
substituted = Select(sbox, x)

#  C: c = (a > b) ? a : b   -> If(cond, then, else) is an EXPRESSION
maxab = If(UGT(x, BitVecVal(0x40, 8)), x, BitVecVal(0x40, 8))
#  Checksum: widen before summing or the sum wraps at 255.
chk = Sum([ZeroExt(24, b) for b in (b0, b1, b2, b3)]) == 0x1F4
#  Permutation / "no repeated character".
all_diff = Distinct([b0, b1, b2, b3])
#  Rotations: the builtin is one SMT op instead of three.
rotated = RotateLeft(x, 5)
#  popcount, the way an obfuscator writes it.
pc = Sum([ZeroExt(7, Extract(i, i, x)) for i in range(8)])
```

## Worked example 1 - a per-byte checker

Straight out of the decompiler:

```c
/* enc[] is 24 bytes lifted straight out of .rodata - see ENC in the model. */
unsigned char enc[24];
unsigned char key[4] = { 0x13, 0x37, 0xBE, 0xEF };

int check(char *s) {
    if (strlen(s) != 24) return 0;
    for (int i = 0; i < 24; i++) {
        unsigned char c = (unsigned char)s[i];
        c = (c << 3) | (c >> 5);        /* rol 3 */
        c ^= key[i & 3];
        c = (unsigned char)(c + i * 7);
        if (c != enc[i]) return 0;
    }
    return 1;
}
```

The model. Note `s[i]` is a *signed* char in C but is immediately cast to
`unsigned char`, so 8-bit BitVec semantics match exactly:

```python
from z3 import BitVecVal, RotateLeft

from flagsolver import fix_prefix, flag_vars, in_charset, is_unique, solve

# The 24 bytes of `enc` as they appear in .rodata (this set really is solvable;
# run the block and it prints the flag).
ENC = bytes.fromhex("099c9a49acd15746383b63c33d19877efab3a3a97549d9a5")
KEY = [0x13, 0x37, 0xBE, 0xEF]

fs = flag_vars(24)
cons = in_charset(fs) + fix_prefix(fs, b"CTF{")
for i, f in enumerate(fs):
    c = RotateLeft(f, 3)
    c = c ^ BitVecVal(KEY[i & 3], 8)
    c = c + BitVecVal((i * 7) & 0xFF, 8)
    cons.append(c == BitVecVal(ENC[i], 8))

print(solve(fs, cons), is_unique(fs, cons))
```

Every byte is independent here, so z3 answers instantly - but so would a 24x256
brute force. Reach for z3 when the bytes are *coupled*, as in example 2.

## Worked example 2 - table lookup plus a linear system

The coupled case: each output depends on four inputs, so you cannot solve one
byte at a time.

```c
unsigned char T[256];               /* an sbox, in .rodata */
unsigned char M[4][4] = {{2,3,1,1},{1,2,3,1},{1,1,2,3},{3,1,1,2}};

/* for each 4-byte group: t[j] = T[in[j]], then out = M * t (mod 256) */
```

```python
from z3 import BitVecVal, Sum

from flagsolver import (fix_prefix, fix_suffix, flag_vars, printable, solve,
                        table_if)

T = [(i * 167 + 13) & 0xFF for i in range(256)]      # the real one comes from .rodata
M = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
OUT = bytes.fromhex("10e3e76ab735e8dd3c3f2184f53eff17")   # 16 bytes from the binary

fs = flag_vars(16)
cons = printable(fs) + fix_prefix(fs, b"CTF{") + fix_suffix(fs, b"}")
for g in range(4):                                   # 4 groups of 4 bytes
    # table_if, not Select on a 256-Store Array: the domain is already pinned
    # to printable bytes, so only 95 If arms are ever needed.
    t = [table_if(T, fs[g * 4 + j]) for j in range(4)]
    for r in range(4):
        # 8-bit BitVec arithmetic wraps, matching the C `unsigned char` maths.
        acc = Sum([BitVecVal(M[r][c], 8) * t[c] for c in range(4)])
        cons.append(acc == BitVecVal(OUT[g * 4 + r], 8))

print(solve(fs, cons))        # -> b'CTF{m1x_c0lumn5}' in about 0.1s
```

If the matrix were over GF(2^8) (real AES MixColumns) you would model the xtime
multiply explicitly instead of `*`; see `z3-constraint-solving`.

## Performance

```python
from z3 import BitVec, Solver, UGE, ULE, set_param, sat

# Global knobs - set them before building the solver.
set_param("parallel.enable", True)        # several cores on hard instances
set_param("parallel.threads.max", 8)
set_param("verbose", 0)                   # 2 = live progress on a long solve

s = Solver()
s.set("timeout", 120000)                  # MILLISECONDS; check() returns unknown
s.set("random_seed", 1)                   # flip it if a run gets stuck

# Push/pop tries an extra assumption without rebuilding everything.
x = BitVec("x", 8)
s.add(UGE(x, 0x20), ULE(x, 0x7E))
s.push()
s.add(x == 0x41)                          # the speculative assumption
r = s.check()
s.pop()                                   # back to just the domain constraints
print(r == sat)
```

Ordering matters: add the cheap domain constraints (charset, prefix) *before*
the expensive checker constraints. z3 propagates them and prunes early.

## Pitfalls

- **`>` `<` `>=` `<=` `/` `%` on BitVecs are SIGNED.** Use `ULT/ULE/UGT/UGE`,
  `UDiv`, `URem` for `unsigned`. This is the number-one source of wrong flags.
- **`>>` is arithmetic.** `LShR` is the logical shift. `unsigned char c = x >> 3`
  in C is `LShR`.
- **Widths must match.** `BitVec("a", 8) + BitVec("b", 32)` raises; you meant
  `ZeroExt(24, a) + b`.
- **Wrapping is free.** 8-bit BitVec arithmetic already wraps mod 256; `& 0xFF`
  just makes the formula bigger.
- **`m[f]` vs `m.eval(f, model_completion=True)`.** If a variable appears in no
  constraint, `m[f]` returns `None` and your `.as_long()` throws. Completion
  gives 0 and tells you that byte is free.
- **Always check uniqueness.** One `sat` proves the constraints are satisfiable,
  not that you transcribed the checker correctly.
- **`BitVecVal(-1, 8)` is 0xFF.** `x == -1` and `x == 0xFF` are the same
  constraint; do not "fix" it with a mask.
- **`Array` + a 256-deep `Store` chain is a trap.** It is the obvious encoding
  for an sbox and it is dramatically slower than a nested `If` chain built only
  over the bytes your domain constraints allow (0.1s vs >60s in example 2).
- **Do not use z3 for hashes.** MD5/SHA/AES preimages are not going to solve.
  If the checker hashes, you want a brute force or the maths, not an SMT solver.
- **`Sum` of 8-bit vars overflows at 255.** Widen with `ZeroExt` first.
- **A timeout returns `unknown`, not `unsat`.** `if s.check() == sat` is right;
  `if s.check() != unsat` is a bug.

## References

- z3 Python API docs ship with the package - `help(z3.BitVec)` in a REPL is the
  fastest reference you have offline
- The Z3 Guide - tutorial maintained at microsoft.github.io/z3guide
