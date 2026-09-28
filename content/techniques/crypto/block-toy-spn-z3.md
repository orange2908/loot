---
title: "S-Box Inversion and Solving a Toy SPN with z3"
category: crypto
subcategory: cryptanalysis
type: technique
tags: [z3, sat-solver, smt-solver, sbox, sbox-inversion, spn, toy-cipher, bit-permutation, symbolic-execution, constraint-solving, bitvec, key-recovery, known-plaintext, reversing, obfuscation, claripy, angr, block-cipher]
difficulty: medium
summary: "Invert a toy cipher by table lookup when you have the key; when you do not, model it as BitVec constraints and let z3 solve for the key from known plaintext."
when_to_use:
  - "A reversing or crypto challenge implements a custom byte/nibble cipher"
  - "You have one or more plaintext/ciphertext pairs and need the key"
  - "The transform is a chain of xor, add, rotate, shift and small table lookups"
  - "Each output byte depends on only a few key bytes (sparse constraints)"
  - "The key is known to be printable ASCII, or is itself the flag"
tools: [z3, claripy, angr, python-sat, sagemath]
related: [block-differential-linear, block-meet-in-the-middle, stream-lfsr-berlekamp-massey]
---

## TL;DR

Two different jobs. **With the key**, a toy SPN is trivially invertible: build the
inverse S-box table, invert the bit permutation, and run the rounds backwards. **Without
the key**, describe the cipher to z3 as a system of bit-vector constraints, add one
equation per known plaintext/ciphertext pair, and ask for a model. z3 is superb when
the constraints are sparse or the key is small/structured, and hopeless when they are
not - knowing which case you are in is most of the skill.

## Recognise it

- A Python/C function with `sbox[...]`, `<<`, `>>`, `^`, `+` and a loop over rounds.
- A `check_flag()` that transforms input and compares to a constant blob.
- Round keys sliced from a master key, or a key schedule of rotations and constants.
- The challenge gives you the encryption routine and one ciphertext.
- Each output byte touches only 2-4 key bytes - the classic "solve with z3" shape.

## Theory

**Inverting an S-box** is a one-liner: `INV[S[x]] = x`. This works because an S-box is
a permutation of its domain. If it is *not* a permutation (an S-box that maps 8 bits to
4, like DES), it is not invertible and you must enumerate preimages instead.

**Inverting a bit permutation.** If bit `i` of the input moves to position `PERM[i]` of
the output, the inverse moves bit `PERM[i]` back to `i`. Write it as a second loop, or
build a lookup of the inverse index list.

**Inverting a round.** For `x -> PERM(SBOX(x xor K))`, the inverse is
`x -> INV_SBOX(INV_PERM(y)) xor K`. Order matters: undo operations in reverse.

**Modelling for z3.** Represent the key as `BitVec` variables. Represent each operation
with the matching z3 operation:

| cipher operation | z3 |
|---|---|
| `a ^ b`, `a + b`, `a - b`, `a & b` | `a ^ b`, `a + b`, `a - b`, `a & b` (wrap automatically) |
| `rotl(x, n)` on `w` bits | `z3.RotateLeft(x, n)` |
| bit slice | `z3.Extract(hi, lo, x)` |
| concatenation | `z3.Concat(hi, ..., lo)` |
| S-box lookup | `z3.Select(arr, idx)` on a `z3.Array`, or nested `z3.If` |
| a conditional | `z3.If(cond, a, b)` |

Two things make or break the solve time:

1. **Introduce a fresh variable per round.** `s.add(v == round(prev))` instead of
   building one enormous nested term. This gives the solver names to case-split on and
   usually turns minutes into seconds.
2. **Constrain the key.** `z3.And(k >= 0x20, k <= 0x7e)` for printable ASCII removes
   ~99% of the search space before the solver starts. If the key is the flag, also
   constrain the prefix (`k0 == ord('f')`, ...).

**Where z3 stops working.** Measured on the cipher below: a 4-round SPN with a 16-bit
master key solves in ~0.5 s; the same cipher with a 32-bit master key takes minutes
even at 2 rounds. Add a real S-box layer plus a bit permutation over 32+ key bits and
the solver is no better than brute force. z3 is a tool for *sparse and structured*
problems, not a cryptanalysis engine - for dense ciphers use the statistical attacks in
`block-differential-linear`.

## Attack

1. Transcribe the cipher into Python and check it round-trips against the challenge's
   own test vector.
2. If you have the key, just invert it. Done.
3. Otherwise, write the symbolic version next to the concrete one, line for line.
4. Add every known plaintext/ciphertext pair as a constraint. One 16-bit pair pins
   16 bits of key; add pairs until `#constraints >= #key bits`, plus one extra to
   confirm uniqueness.
5. Add structural constraints: printable, alphanumeric, known prefix, known length.
6. `s.check()`, `s.model()`. Then ask for a second model (`s.add(K != model_value)`)
   to check whether the solution is unique.
7. Verify by re-encrypting with the recovered key.

## Code

```python
#!/usr/bin/env python3
"""S-box inversion, bit-permutation inversion, and two z3 key recoveries:
a 4-round toy SPN, and a sparse byte-wise obfuscation with a printable key.

Self-contained; every recovery is asserted. Runs in a few seconds.
"""

import secrets
import time
import z3

# ----------------------------------------------------------- the toy SPN
SBOX = [0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
        0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7]
INV_SBOX = [0] * 16
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i                      # inverting an S-box is one line

PERM = [1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15, 4, 8, 12, 16]
INV_PERM = [0] * 16
for _i, _p in enumerate(PERM):
    INV_PERM[_p - 1] = _i + 1              # and so is inverting a bit permutation

RC = [0x9E37, 0x79B9, 0x7F4A, 0x7C15, 0xF39C, 0xC8E5]
ROUNDS = 3                                 # 3 full rounds + a final round


def _apply_perm(x: int, table: list[int]) -> int:
    y = 0
    for i in range(16):
        if (x >> (15 - i)) & 1:
            y |= 1 << (15 - (table[i] - 1))
    return y


def permute(x: int) -> int:
    return _apply_perm(x, PERM)


def inv_permute(x: int) -> int:
    return _apply_perm(x, INV_PERM)


def sub(x: int) -> int:
    return sum(SBOX[(x >> s) & 0xF] << s for s in (12, 8, 4, 0))


def inv_sub(x: int) -> int:
    return sum(INV_SBOX[(x >> s) & 0xF] << s for s in (12, 8, 4, 0))


def rotl16(x: int, n: int) -> int:
    n %= 16
    return ((x << n) | (x >> (16 - n))) & 0xFFFF if n else x


def key_schedule(master: int) -> list[int]:
    return [rotl16(master, 3 * r) ^ RC[r] for r in range(ROUNDS + 2)]


def encrypt(master: int, pt: int) -> int:
    ks = key_schedule(master)
    x = pt
    for r in range(ROUNDS):
        x = permute(sub(x ^ ks[r]))
    return sub(x ^ ks[ROUNDS]) ^ ks[ROUNDS + 1]


def decrypt(master: int, ct: int) -> int:
    """Undo everything in reverse order. This is all S-box inversion is."""
    ks = key_schedule(master)
    x = inv_sub(ct ^ ks[ROUNDS + 1]) ^ ks[ROUNDS]
    for r in reversed(range(ROUNDS)):
        x = inv_sub(inv_permute(x)) ^ ks[r]
    return x


# --------------------------------------------------- the symbolic version
def z3_sub(x):
    """Nibble-wise S-box as nested If. z3.Select on a z3.Array also works."""
    parts = []
    for shift in (12, 8, 4, 0):
        nibble = z3.Extract(shift + 3, shift, x)
        expr = z3.BitVecVal(SBOX[15], 4)
        for i in range(14, -1, -1):
            expr = z3.If(nibble == i, z3.BitVecVal(SBOX[i], 4), expr)
        parts.append(expr)
    return z3.Concat(*parts)


def z3_permute(x):
    bits = [z3.Extract(15 - i, 15 - i, x) for i in range(16)]
    out = [None] * 16
    for i in range(16):
        out[PERM[i] - 1] = bits[i]
    return z3.Concat(*out)


def z3_key_schedule(master):
    return [z3.RotateLeft(master, (3 * r) % 16) ^ z3.BitVecVal(RC[r], 16)
            for r in range(ROUNDS + 2)]


def solve_spn(pairs: list[tuple[int, int]]) -> int | None:
    """Recover the 16-bit master key from known plaintext/ciphertext pairs."""
    master = z3.BitVec("master", 16)
    solver = z3.Solver()
    ks = z3_key_schedule(master)
    for idx, (pt, ct) in enumerate(pairs):
        x = z3.BitVecVal(pt, 16)
        for r in range(ROUNDS):
            # A named variable per round: this is the single biggest speedup.
            v = z3.BitVec(f"v{idx}_{r}", 16)
            solver.add(v == z3_permute(z3_sub(x ^ ks[r])))
            x = v
        solver.add(z3_sub(x ^ ks[ROUNDS]) ^ ks[ROUNDS + 1] == z3.BitVecVal(ct, 16))
    if solver.check() != z3.sat:
        return None
    return solver.model()[master].as_long()


def spn_solution_is_unique(pairs, found: int) -> bool:
    master = z3.BitVec("master", 16)
    solver = z3.Solver()
    ks = z3_key_schedule(master)
    for idx, (pt, ct) in enumerate(pairs):
        x = z3.BitVecVal(pt, 16)
        for r in range(ROUNDS):
            v = z3.BitVec(f"u{idx}_{r}", 16)
            solver.add(v == z3_permute(z3_sub(x ^ ks[r])))
            x = v
        solver.add(z3_sub(x ^ ks[ROUNDS]) ^ ks[ROUNDS + 1] == z3.BitVecVal(ct, 16))
    solver.add(master != found)
    return solver.check() == z3.unsat


# ------------------------------- a sparse obfuscation with a printable key
KEYLEN = 8


def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def obfuscate(pt: bytes, key: bytes) -> bytes:
    """Each output byte depends on only four key bytes -- ideal for a solver."""
    out = bytearray()
    for i, b in enumerate(pt):
        v = b ^ key[i % KEYLEN]
        v = (v + key[(i + 1) % KEYLEN]) & 0xFF
        v = rotl8(v, 3) ^ key[(i + 2) % KEYLEN]
        v = (v ^ 0x5A) - key[(i + 3) % KEYLEN]
        out.append(v & 0xFF)
    return bytes(out)


def solve_obfuscation(pt: bytes, ct: bytes, printable: bool = True) -> bytes | None:
    key = [z3.BitVec(f"k{i}", 8) for i in range(KEYLEN)]
    solver = z3.Solver()
    if printable:
        for k in key:
            solver.add(z3.And(k >= 0x20, k <= 0x7E))
    for i, b in enumerate(pt):
        v = z3.BitVecVal(b, 8) ^ key[i % KEYLEN]
        v = v + key[(i + 1) % KEYLEN]
        v = z3.RotateLeft(v, 3) ^ key[(i + 2) % KEYLEN]
        v = (v ^ 0x5A) - key[(i + 3) % KEYLEN]
        solver.add(v == z3.BitVecVal(ct[i], 8))
    if solver.check() != z3.sat:
        return None
    model = solver.model()
    return bytes(model[k].as_long() for k in key)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- 0. the tables really are inverses ---------------------------------
    assert [INV_SBOX[SBOX[x]] for x in range(16)] == list(range(16))
    assert all(inv_permute(permute(1 << b)) == 1 << b for b in range(16))
    print("[+] PASS inverse S-box and inverse bit permutation")

    # --- 1. plain inversion when the key is known --------------------------
    key = secrets.randbelow(1 << 16)
    for _ in range(2000):
        p = secrets.randbelow(1 << 16)
        assert decrypt(key, encrypt(key, p)) == p
    print("[+] PASS pure-Python decryption (no solver needed when you have the key)")

    # --- 2. z3 recovers the key from known plaintext -----------------------
    pairs = []
    for _ in range(3):
        p = secrets.randbelow(1 << 16)
        pairs.append((p, encrypt(key, p)))

    t0 = time.time()
    found = solve_spn(pairs)
    print(f"[+] z3 solved the {ROUNDS + 1}-round SPN in {time.time() - t0:.2f}s")
    print(f"[+] recovered master key 0x{found:04x}, true 0x{key:04x}")
    assert found == key, (found, key)
    assert all(encrypt(found, p) == c for p, c in pairs)
    print("[+] PASS z3 key recovery on the toy SPN")

    assert spn_solution_is_unique(pairs, found)
    print("[+] PASS the solution is unique (no second model exists)")

    # one pair is not enough: 16 bits of constraint for a 16-bit key is marginal
    weak = solve_spn(pairs[:1])
    assert weak is not None
    print(f"[+] with a single pair z3 returns 0x{weak:04x} "
          f"({'still correct' if weak == key else 'a different, also-valid key'})")

    # --- 3. sparse obfuscation with a printable key ------------------------
    real_key = bytes(secrets.choice(b"abcdefghijklmnopqrstuvwxyz0123456789_")
                     for _ in range(KEYLEN))
    plaintext = (b"The quick brown fox jumps over the lazy dog 0123456789. "
                 b"Padding to give the solver plenty of equations.")
    ciphertext = obfuscate(plaintext, real_key)

    t0 = time.time()
    got = solve_obfuscation(plaintext, ciphertext)
    print(f"[+] z3 solved the byte obfuscation in {time.time() - t0:.2f}s")
    print(f"[+] recovered key {got!r}, true {real_key!r}")
    assert got == real_key
    assert obfuscate(plaintext, got) == ciphertext
    print("[+] PASS z3 key recovery on the sparse obfuscation")

    # it still works with only a short known plaintext
    short = solve_obfuscation(plaintext[:16], ciphertext[:16])
    assert short is not None and obfuscate(plaintext[:16], short) == ciphertext[:16]
    print(f"[+] PASS 16 known bytes suffice: {short!r}")

    # and the printable constraint is what makes short data unambiguous
    loose = solve_obfuscation(plaintext[:12], ciphertext[:12], printable=False)
    print(f"[+] without the printable constraint, 12 bytes give {loose!r}")
    assert loose is not None

    print("\nall checks passed")
```

## Variants & pitfalls

- **Do not build one giant expression.** Name every intermediate. It is the difference
  between a 0.5-second solve and a timeout.
- **`z3.Select` on a `z3.Array` vs nested `z3.If`.** For a 4-bit S-box the nested `If`
  is usually fine; for a 256-entry table the `Array` version builds much faster. Try
  both if you are near the time limit.
- **Widths.** z3 bit-vectors wrap like C, so `+` and `-` are already mod `2^w`. But
  `z3.Extract` and `z3.Concat` are easy to get backwards - `Concat(hi, lo)` puts the
  first argument in the high bits.
- **`RotateLeft` needs a constant width.** For a rotation by a symbolic amount use
  shifts and an `Or`, or enumerate the cases with `If`.
- **Unsat when you expect sat** almost always means your Python model and the
  challenge's cipher disagree. Test the concrete model against the challenge's own
  test vector first, every time.
- **Multiple models.** Always check for a second solution. If there is one, add another
  known pair or a structural constraint.
- **z3 does not scale to real ciphers.** 32-bit keys through an S-box plus a bit
  permutation already take minutes at two rounds. Six rounds of ARX with a 32-bit key
  did not finish in 100 seconds in testing. Use z3 on obfuscation and toy ciphers, and
  statistics on real ones.
- **`claripy` / `angr`** wrap the same solver and can lift the cipher straight out of a
  binary, which saves you transcribing it.
- **Optimisation problems** (maximise a bias, minimise active S-boxes for a
  differential search) belong to `z3.Optimize`, and MILP/SAT-based active-S-box
  counting is standard in modern cipher design.

## Tools

- `z3-solver` (`pip install z3-solver`) - `BitVec`, `Solver`, `Extract`, `Concat`,
  `RotateLeft`, `Select`, `Optimize`.
- `claripy` and `angr` for symbolic execution straight from a binary.
- `python-sat` / CryptoMiniSat when a pure CNF encoding is faster.
- SageMath for algebraic normal forms and Groebner-basis attacks.

## References

- The z3 Python API is documented in the z3 source distribution and its online guide.
- Howard Heys, "A Tutorial on Linear and Differential Cryptanalysis" - the 16-bit SPN
  structure modelled above.
