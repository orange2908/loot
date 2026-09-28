---
title: "Crackme Patterns - Recognise the Check, Invert It"
category: rev
subcategory: crackme
type: technique
tags: [crackme, keygen, flag-checker, xor, substitution, sbox, crc32, hash-compare, checksum, serial-check, z3, constant-identification, tea, xtea, rc4, md5, sha256, aes-sbox, base64, reverse-engineering]
difficulty: easy
summary: "The dozen shapes every flag checker takes - plaintext strcmp, xor, per-byte arithmetic, table lookup, checksum, matrix, hash - and the inverse for each."
when_to_use:
  - "You have decompiled a checker and want to know which known pattern it is before writing code"
  - "You see magic constants (0x9E3779B9, 0x67452301, an AES sbox) and need to identify the algorithm"
  - "You need to decide between inverting by hand, brute forcing, z3, and angr"
  - "You must write a keygen rather than recover a single flag"
tools: [z3, ghidra, python, hashcat, findcrypt, capa]
related: [z3-constraint-solving, angr-symbolic-execution, side-channel-instruction-counting, custom-vm-bytecode, binary-patching, ghidra-workflow]
---

## TL;DR

Almost every CTF flag checker is one of about twelve shapes. Identify the shape from the
decompiled loop and the constants, then apply the standard inverse: read the constant,
xor back, build a reverse table, or hand the whole thing to z3. Only two shapes are
genuinely hard: a full cryptographic hash compare, and a checker whose bytes interact
non-linearly across the whole string.

## The decision table

| Signal in the decompilation | Pattern | Inverse |
|---|---|---|
| `strcmp(in, "...")` / `memcmp(in, arr, n)` | plaintext compare | read the constant |
| `in[i] ^ K` compared to a table | fixed-key XOR | xor the table with K |
| `in[i] ^ in[i-1]` chain | rolling XOR | prefix-xor the table |
| `(in[i] + i) ^ c`, `in[i] - i * 3` | per-byte arithmetic | algebraic inverse per byte |
| `tbl[in[i]] == exp[i]`, 256-byte array | substitution / S-box | build the reverse table |
| 64/65-char string constant, `<< 6`, `& 0x3f` | base64 (custom alphabet) | translate + b64decode |
| `0xEDB88320`, 256-entry u32 table | CRC32 | brute per chunk, or CRC-invert |
| `0x67452301 0xEFCDAB89` | MD5 | hashcat / rainbow / only if short |
| `0x6A09E667` + 64-entry K table | SHA-256 | hashcat, or the flag is elsewhere |
| `0x9E3779B9` | TEA / XTEA / XXTEA | implement the decrypt routine |
| 256-byte identity init + swap loop | RC4 | it is symmetric: re-run it |
| AES sbox begins `63 7c 77 7b f2 6b 6f c5` | AES | find the key, decrypt |
| sum/xor accumulator == constant | checksum constraint | z3 |
| nested loops, `acc += m[i][j]*in[j]` | matrix / linear system | z3 or sympy inverse |
| a `switch` in a loop over a byte array | custom VM | see `custom-vm-bytecode` |
| derived from a username string | keygenme | write a keygen |

## Pattern 1 - plaintext compare

```c
if (strcmp(input, "CTF{th1s_is_t00_easy}") == 0) puts("Correct");
```

Signal: a readable string in `.rodata` with an xref from the check. Solve with `strings`.
Variant: the constant is built on the stack byte by byte to defeat `strings`
(`mov byte [rbp-0x20], 0x43` ...). Read the immediates in order, or set a breakpoint after
the construction and dump the stack. Variant: `memcmp(in, buf, n)` where `buf` is filled at
runtime - just break on `memcmp` and print `rsi`:

```sh
# Dump both memcmp arguments every time it is called - solves a surprising number of crackmes
ltrace -e memcmp ./chall
gdb -q -ex 'break memcmp' -ex 'run' -ex 'x/s $rdi' -ex 'x/s $rsi' ./chall
```

## Pattern 2 - XOR (fixed key, rolling key, key from argv)

```c
/* fixed single-byte key */
for (int i = 0; i < n; i++) if ((in[i] ^ 0x42) != enc[i]) return 0;
/* rolling key derived from the previous byte */
for (int i = 1; i < n; i++) if ((in[i] ^ in[i-1]) != enc[i]) return 0;
/* multi-byte repeating key */
for (int i = 0; i < n; i++) if ((in[i] ^ key[i % 7]) != enc[i]) return 0;
```

```python
#!/usr/bin/env python3
"""xor_inverse.py - invert the three standard XOR checker shapes."""


def fixed_key(enc: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in enc)


def repeating_key(enc: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enc_enumerate(enc))


def enc_enumerate(data: bytes):
    return enumerate(data)


def rolling(enc: bytes, first: int) -> bytes:
    """in[0] = first; enc[i] = in[i] ^ in[i-1]  =>  in[i] = enc[i] ^ in[i-1]."""
    out = bytearray([first])
    for i in range(1, len(enc)):
        out.append(enc[i] ^ out[-1])
    return bytes(out)


def crack_single_byte(enc: bytes) -> list[tuple[int, bytes]]:
    """Score all 256 keys by printable-ASCII ratio; the real key floats to the top."""
    results = []
    for key in range(256):
        cand = fixed_key(enc, key)
        score = sum(1 for c in cand if 32 <= c < 127)
        results.append((score, key, cand))
    results.sort(reverse=True)
    return [(k, c) for _s, k, c in results[:5]]


if __name__ == "__main__":
    secret = b"CTF{x0r_1s_n0t_crypt0}"
    enc = fixed_key(secret, 0x42)
    assert fixed_key(enc, 0x42) == secret
    assert crack_single_byte(enc)[0][0] == 0x42
    rolled = bytearray([secret[0]])
    for i in range(1, len(secret)):
        rolled.append(secret[i] ^ secret[i - 1])
    assert rolling(bytes(rolled), secret[0]) == secret
    assert repeating_key(repeating_key(secret, b"key1234"), b"key1234") == secret
    print("[+] all xor inverses OK")
```

## Pattern 3 - per-byte arithmetic

```c
for (int i = 0; i < 16; i++) {
    unsigned char c = in[i];
    c = (unsigned char)(c + i);
    c = (unsigned char)((c << 3) | (c >> 5));   /* rol 3 */
    c ^= 0x5A;
    if (c != enc[i]) return 0;
}
```

Invert step by step in reverse order. `rol n` inverts to `ror n`, `+i` to `-i`, `^k` to
itself. Everything is mod 256.

```python
#!/usr/bin/env python3
"""perbyte_inverse.py - undo a chain of per-byte transforms, in reverse."""


def rol8(x: int, n: int) -> int:
    n &= 7
    return ((x << n) | (x >> (8 - n))) & 0xFF


def ror8(x: int, n: int) -> int:
    n &= 7
    return ((x >> n) | (x << (8 - n))) & 0xFF


def forward(c: int, i: int) -> int:
    return (rol8((c + i) & 0xFF, 3)) ^ 0x5A


def inverse(c: int, i: int) -> int:
    return (ror8(c ^ 0x5A, 3) - i) & 0xFF


if __name__ == "__main__":
    flag = b"CTF{arithmetic!}"
    enc = bytes(forward(c, i) for i, c in enumerate(flag))
    rec = bytes(inverse(c, i) for i, c in enumerate(enc))
    assert rec == flag, rec
    print("[+] recovered:", rec.decode())
```

If you cannot be bothered to invert by hand, brute force each byte independently - there are
only 256 candidates per position and the transform is per-byte:

```python
#!/usr/bin/env python3
"""bruteforce_perbyte.py - invert ANY per-byte transform by exhaustive search."""


def invert_table(forward, index: int) -> dict[int, int]:
    """Map output -> input for one position. Works for any 8-bit -> 8-bit function."""
    return {forward(c, index): c for c in range(256)}


def recover(enc: bytes, forward) -> bytes:
    out = bytearray()
    for i, e in enumerate(enc):
        table = invert_table(forward, i)
        out.append(table.get(e, ord("?")))
    return bytes(out)


if __name__ == "__main__":
    def f(c: int, i: int) -> int:
        return ((c * 17) ^ (i * 13) ^ 0xA5) & 0xFF   # note: *17 is invertible mod 256

    flag = b"CTF{brute_per_byte}"
    assert recover(bytes(f(c, i) for i, c in enumerate(flag)), f) == flag
    print("[+] per-byte brute force OK")
```

## Pattern 4 - substitution / S-box lookup

```c
static const unsigned char sbox[256] = { 0x8d, 0x41, 0x2a, /* ... */ };
for (i = 0; i < n; i++) if (sbox[(unsigned char)in[i]] != enc[i]) return 0;
```

Signal: a 256-byte `.rodata` array indexed by the input byte. Dump the array from the binary
and invert it. The array is a permutation iff every value appears exactly once - check that;
if not, several inputs map to one output and you need extra constraints.

```python
#!/usr/bin/env python3
"""sbox_inverse.py - dump a 256-byte table from a binary at a file offset and invert it."""
import sys


def read_table(path: str, offset: int, size: int = 256) -> bytes:
    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read(size)


def invert(sbox: bytes) -> dict[int, int]:
    if len(set(sbox)) != len(sbox):
        print("[!] not a permutation - ambiguous inverse", file=sys.stderr)
    return {v: i for i, v in enumerate(sbox)}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: sbox_inverse.py <binary> <file_offset> [enc_hex]")
        return 1
    sbox = read_table(sys.argv[1], int(sys.argv[2], 0))
    inv = invert(sbox)
    if len(sys.argv) > 3:
        enc = bytes.fromhex(sys.argv[3])
        print(bytes(inv.get(b, 63) for b in enc).decode(errors="replace"))
    else:
        print(sbox.hex(" "))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Pattern 5 - base64 with a custom alphabet

Signal: a 64- or 65-character string constant, shifts by 6/2/4, `& 0x3F`, and a `=` padding
character. Translate from the custom alphabet to the standard one and decode.

```python
#!/usr/bin/env python3
"""custom_b64.py - decode base64 that uses a non-standard alphabet."""
import base64

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def decode(data: str, alphabet: str) -> bytes:
    assert len(alphabet) == 64, "alphabet must be 64 chars (drop the pad char)"
    table = str.maketrans(alphabet, STD)
    return base64.b64decode(data.translate(table) + "===")


def encode(data: bytes, alphabet: str) -> str:
    table = str.maketrans(STD, alphabet)
    return base64.b64encode(data).decode().rstrip("=").translate(table)


if __name__ == "__main__":
    custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
    blob = encode(b"CTF{custom_alphabet}", custom)
    assert decode(blob, custom) == b"CTF{custom_alphabet}"
    print("[+] custom base64 round-trip OK:", blob)
```

## Pattern 6 - CRC32 / checksum compare

```c
if (crc32(input, len) != 0xDEADBEEF) return 0;
```

A single CRC32 over the whole flag is *not* invertible to a unique string, but CRC32 is
linear over GF(2): you can always append 4 bytes that force any target CRC. In CTFs the
usual shape is a CRC per 4-byte chunk, which is brute-forceable (4 printable bytes ~ 8.1e7
combinations, a few seconds in C, a few minutes in Python with a smaller charset).

```python
#!/usr/bin/env python3
"""crc_chunks.py - brute force printable chunks whose CRC32 matches given targets."""
import itertools
import string
import sys
import zlib

CHARSET = (string.ascii_letters + string.digits + "_{}!?-").encode()


def crack_chunk(target: int, width: int = 4) -> bytes | None:
    for tup in itertools.product(CHARSET, repeat=width):
        cand = bytes(tup)
        if zlib.crc32(cand) & 0xFFFFFFFF == target:
            return cand
    return None


def main() -> int:
    targets = [int(a, 0) for a in sys.argv[1:]]
    if not targets:
        demo = [zlib.crc32(b"CTF{") & 0xFFFFFFFF, zlib.crc32(b"crc_") & 0xFFFFFFFF]
        print("[*] no args, running self-test")
        targets = demo
    out = b""
    for t in targets:
        found = crack_chunk(t)
        print(f"{t:#010x} -> {found!r}")
        if found:
            out += found
    print("[+]", out.decode(errors="replace"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Pattern 7 - cryptographic hash compare

`md5(input) == "5f4dcc3b..."` or `sha256`. There is no inverse. Your options, in order:
look the hash up (many CTF authors hash a dictionary word), `hashcat -m 0 hash.txt rockyou.txt`,
brute force if the input space is tiny (a 6-digit PIN is 10^6 - instant), or conclude that the
flag is *not* the hashed value and the real flag is derived elsewhere (very common: the input
unlocks a decryption key, and the flag is `AES_decrypt(blob, input)`).

Identify the hash from its initialisation constants:

| Constants | Algorithm |
|---|---|
| `0x67452301 0xEFCDAB89 0x98BADCFE 0x10325476` | MD4 / MD5 (MD5 adds a 64-entry T table) |
| the above plus `0xC3D2E1F0` | SHA-1 |
| `0x6A09E667 0xBB67AE85 0x3C6EF372 0xA54FF53A` | SHA-256 |
| `0x9E3779B9` (delta) | TEA / XTEA / XXTEA |
| `0x243F6A88` (pi digits) | Blowfish P-array |
| sbox starting `63 7C 77 7B F2 6B 6F C5 30 01 67 2B` | AES |
| `0xEDB88320` | CRC32 (reflected polynomial) |
| `0x04C11DB7` | CRC32 (normal polynomial) |
| `0x5851F42D4C957F2D` | PCG / a common 64-bit LCG multiplier |
| `0x2545F4914F6CDD1D` | xorshift64star |
| `0x41C64E6D`, `0x3039` | glibc `rand()` LCG constants |

Automate this: Ghidra's `FindCrypt` / `findcrypt-yara` plugin, IDA's `FindCrypt2`, or
`capa -v ./chall` which reports "encrypt data using AES" style capabilities.

## Pattern 8 - TEA / XTEA / RC4 recognition

```c
/* XTEA: the 0x9E3779B9 delta is the giveaway */
void xtea_decrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1], delta = 0x9E3779B9, sum = delta * 32;
    for (int i = 0; i < 32; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}
```

RC4's signature is a 256-byte array initialised to `0,1,2,...,255` followed by a swap loop
using a key - and RC4 is symmetric, so re-running the *encrypt* routine on the ciphertext
gives the plaintext. Do not write a decryptor; reuse the binary's own code via Unicorn.

## Pattern 9 - sum / linear system / matrix -> z3

```c
/* Each equation mixes several input bytes: per-byte inversion is impossible */
if (in[0] + in[3] * 2 - in[7] != 0x145) return 0;
if ((in[1] ^ in[4]) + in[2] != 0x9A) return 0;
/* ... 20 more equations ... */
```

Transcribe every equation into z3 with 8-bit BitVecs, add printable constraints, solve, then
check uniqueness by blocking the model and re-solving. See `z3-constraint-solving` for the
full recipe. For a pure matrix multiply mod 256 you can also invert the matrix directly with
`sympy.Matrix(m).inv_mod(256)`.

## Pattern 10 - keygenme (serial derived from a username)

```c
int serial_for(const char *user) {
    int acc = 0x1505;
    for (const char *p = user; *p; p++)
        acc = acc * 33 + (unsigned char)*p;     /* djb2 */
    return (acc ^ 0xC0FFEE) & 0x7FFFFFFF;
}
```

You do not invert this - you *reimplement the forward direction* and print the serial for
any username. That is the deliverable of a keygenme. Check for extra constraints on the
serial (length, checksum digit, format `XXXX-XXXX-XXXX`) which are usually in a separate
validation function before the math.

```python
#!/usr/bin/env python3
"""keygen.py - reimplement the checker's forward function and emit a valid serial."""
import sys


def serial_for(user: str) -> str:
    acc = 0x1505
    for ch in user.encode():
        acc = (acc * 33 + ch) & 0xFFFFFFFF
    val = (acc ^ 0xC0FFEE) & 0x7FFFFFFF
    raw = f"{val:010d}"
    return "-".join(raw[i:i + 5] for i in range(0, 10, 5))


if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "ctfbrain"
    print(f"{name}: {serial_for(name)}")
```

## Pattern 11 - self-modifying / VM-based

A `switch` on a byte fetched from an array, with a program-counter variable, means a custom
bytecode VM - go to `custom-vm-bytecode`. Code that `mprotect`s its own `.text` and writes to
it means self-modifying code - break after the write and dump (see `packers-and-unpacking`).

## Pattern 12 - the check is in a constructor or a signal handler

Look at `.init_array` (`objdump -s -j .init_array ./chall`) and at
`signal`/`sigaction` registrations. A SIGSEGV or SIGTRAP handler that does the real work is
a classic obfuscation; set `handle SIGSEGV nostop noprint pass` in gdb and break on the
handler's address instead.

## Variants & pitfalls

- **Sign extension**: `char` is signed on x86 Linux. `in[i] + 0x80` in the decompiler may be
  arithmetic on a sign-extended value. Model with `SignExt` in z3 or mask with `& 0xFF` only
  when you are sure the C code used `unsigned char`.
- **Length check first**: always find the required length before anything else; most byte
  loops are bounded by it.
- **Endianness on 4-byte reads**: `*(int*)&in[0] == 0x7B465443` is `"CTF{"` little-endian.
  Use `struct.pack("<I", 0x7B465443)` to read it back.
- **Compiler-inserted division**: a `mul` by a magic constant followed by a shift is a
  division by a constant, not part of the algorithm. See `assembly-cheatsheet`.
- **The transform may not be a permutation**, so some positions have several valid bytes.
  Prefer the one that makes the flag readable, then verify against the binary.
- **Do not reimplement, reuse**: when the transform is long and fiddly, emulate the binary's
  own function with Unicorn rather than transcribing it and introducing bugs.

## Tools

- `capa`, `FindCrypt`/`findcrypt-yara` (Ghidra), `FindCrypt2` (IDA) - constant identification.
- `z3-solver` - anything with cross-byte constraints.
- `hashcat` / `john` - hash compares with a wordlist.
- `binwalk -R '\x63\x7c\x77\x7b'` - grep raw signatures inside a blob.
- `xortool` - repeating-key XOR key length recovery on a ciphertext blob.

## References

- Ghidra `FindCrypt` community plugin (constant-signature scanning).
- `capa` rules repository, "data-manipulation/encryption" category.
- The TEA/XTEA reference implementation in the original Wheeler-Needham papers.
