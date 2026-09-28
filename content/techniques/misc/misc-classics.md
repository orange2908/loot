---
title: "Misc Classics - CVE Hunting, Keygens, Custom Protocols, PRNG"
category: misc
subcategory: classics
type: technique
tags: [cve, searchsploit, version-banner, keygen, license-key, checksum, z3, custom-protocol, struct, pcap, mersenne-twister, prng-state-recovery, random, seed, brute-force]
difficulty: medium
summary: "The recurring non-category misc challenges: map a version to a CVE, solve a key checksum with z3, reverse a packet format, or recover a PRNG state."
when_to_use:
  - "The challenge names a specific software version and asks what is wrong with it"
  - "You must produce a valid licence key or serial number"
  - "A pcap or a client binary implies a custom binary protocol you have to speak"
  - "A service leaks random numbers and later uses one you must predict"
tools: [searchsploit, z3, python3, scapy, wireshark, struct, git]
related: [remote-interaction-and-pow, git-data-recovery, ctf-general-cheatsheet, esolangs, linux-privesc]
---

## TL;DR

Four families cover most "misc" challenges that are not jails or stego:

1. **Version -> CVE**: a banner names a version; find the vulnerability and the PoC.
2. **Keygen maths**: derive the constraint set from the validator and solve it (z3 or algebra).
3. **Custom protocols**: reverse the framing from a pcap or a client, then rewrite the client.
4. **PRNG prediction**: recover the generator state from its outputs and predict the next one.

## 1. Version to CVE

### Recognise it

- A banner: `Apache/2.4.49`, `OpenSSH_8.2p1`, `ProFTPD 1.3.5`, `Exim 4.87`.
- A `package.json` / `requirements.txt` / `go.mod` pinned to an old version.
- A binary whose `--version` output is the only hint.

### Workflow

```bash
# local exploit database (works offline once cloned)
searchsploit apache 2.4.49
searchsploit -w proftpd 1.3.5           # with links
searchsploit -m 50383                   # copy an exploit locally
searchsploit -x 50383                   # view it
searchsploit --update

# the version is in a file, not a banner
grep -RhoE '"version"\s*:\s*"[^"]+"' package.json
pip list --format=freeze
dpkg -l | grep -i <package>

# offline: read the project's own changelog/NEWS between your version and the next
git log --oneline v1.3.5..v1.3.5a
git log --oneline -- src/vulnerable_file.c
git show <fix-commit>                   # the patch tells you the bug and the trigger

# the CVE description is usually enough to find the primitive:
#  "path traversal in mod_alias when ... " -> ../ in a URL
#  "out of bounds write in the SSH_MSG_... handler" -> send that message oversized
```

### Reading a fix commit

The fastest path from "version X is vulnerable" to a working exploit is the **diff of the fix**.
Look for a newly added bounds check, a newly escaped variable, or a removed call. The exploit is
the input that the new check rejects.

## 2. Licence key / serial maths

### Recognise it

```python
def check(key):
    parts = key.split("-")
    if len(parts) != 4 or any(len(p) != 5 for p in parts):
        return False
    nums = [int(p, 36) for p in parts]
    if (nums[0] * 7 + nums[1]) % 1000003 != 424242:
        return False
    if nums[2] ^ nums[3] != nums[0] + nums[1]:
        return False
    return sum(nums) % 97 == 13
```

Signals: a fixed key shape, a checksum over the characters, modular arithmetic, an XOR chain,
or a CRC. The validator *is* the specification - read it and invert it.

### Approach

1. **Algebraic inversion** when the constraints are linear: solve for one unknown, pick the rest.
2. **Modular inverse** when the check is `a*x % m == b`: `x = b * pow(a, -1, m) % m`.
3. **z3** when the constraints are mixed arithmetic/bitwise - it handles them in seconds.
4. **Brute force** when the keyspace is small (a 4-digit block, a 2-character checksum).

## 3. Custom binary protocols

### From a pcap

```bash
# what talks to what
tshark -r cap.pcap -q -z conv,tcp
# follow one stream as hex
tshark -r cap.pcap -q -z follow,tcp,hex,0
# raw payload bytes of one stream, no headers
tshark -r cap.pcap -Y 'tcp.stream==0 && tcp.len>0' -T fields -e data | tr -d '\n'
```

Then look for the framing:

- A **length prefix**: the first 2 or 4 bytes equal the rest of the message length (try big and
  little endian, and +/- the header size).
- A **magic**: the same bytes start every message.
- A **type byte** that correlates with message size.
- A **sequence number** that increments by one.
- A **checksum**: the last 2 or 4 bytes change when anything changes; test CRC-16, CRC-32,
  sum-of-bytes, and XOR-of-bytes.

### Then write the client

`struct` is all you need. Define the header format once and reuse it. See the code below.

## 4. PRNG prediction

| Generator | Outputs needed | Method |
| --- | --- | --- |
| Python `random` (Mersenne Twister) | 624 consecutive 32-bit outputs | untemper each, rebuild the state |
| MT19937 with truncated output | more, plus a solver (z3 or linear algebra over GF(2)) | |
| glibc `rand()` (TYPE_3 additive feedback) | 31 outputs | `r[i] = (r[i-3] + r[i-31]) % 2^32`, output is `r[i] >> 1` |
| Java `Random` (48-bit LCG) | 2 consecutive `nextInt()` | brute the 16 unknown bits |
| `time()`-seeded anything | none | brute the seed over a window of timestamps |

**Untempering MT19937**: `random.getrandbits(32)` returns `temper(state[i])` where temper is a
sequence of invertible shift/xor/and steps. Invert them for 624 outputs and you have the full
state; feed it back with `random.setstate` and you predict every future output.

## Code

```python
#!/usr/bin/env python3
"""Misc classics toolkit: MT19937 state recovery, a z3-backed keygen solver,
a length-prefixed protocol client, and checksum identification.

  python3 misc_classics.py mt
  python3 misc_classics.py keygen
  python3 misc_classics.py --selftest
"""
from __future__ import annotations

import binascii
import random
import struct
import sys

# --------------------------------------------------------------------------- #
# MT19937 state recovery (stdlib only)
# --------------------------------------------------------------------------- #
N = 624


def _unshift_right(y: int, shift: int) -> int:
    """Invert y = x ^ (x >> shift) by iterating until it converges."""
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x & 0xFFFFFFFF


def _unshift_left(y: int, shift: int, mask: int) -> int:
    """Invert y = x ^ ((x << shift) & mask)."""
    x = y
    for _ in range(32 // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Invert MT19937's tempering transform (the four steps, in reverse order)."""
    y = _unshift_right(y, 18)
    y = _unshift_left(y, 15, 0xEFC60000)
    y = _unshift_left(y, 7, 0x9D2C5680)
    y = _unshift_right(y, 11)
    return y & 0xFFFFFFFF


def temper(y: int) -> int:
    """The forward tempering transform, for verifying untemper()."""
    y ^= y >> 11
    y ^= (y << 7) & 0x9D2C5680
    y ^= (y << 15) & 0xEFC60000
    y ^= y >> 18
    return y & 0xFFFFFFFF


def clone_mt(outputs: list[int]) -> random.Random:
    """Rebuild a random.Random from 624 consecutive getrandbits(32) outputs."""
    if len(outputs) < N:
        raise ValueError(f"need {N} outputs, got {len(outputs)}")
    state = tuple(untemper(o) for o in outputs[-N:])
    clone = random.Random()
    clone.setstate((3, state + (N,), None))
    return clone


# --------------------------------------------------------------------------- #
# keygen solving
# --------------------------------------------------------------------------- #
def modular_key(a: int, b: int, m: int) -> int:
    """Solve a*x == b (mod m) for x when gcd(a, m) == 1."""
    return (b * pow(a, -1, m)) % m


def solve_keygen_z3(nblocks: int = 4, bits: int = 32):
    """Solve a mixed arithmetic/bitwise key constraint set with z3, if it is installed."""
    try:
        import z3
    except ImportError:
        return None
    xs = [z3.BitVec(f"x{i}", bits) for i in range(nblocks)]
    s = z3.Solver()
    # the same constraints as the `check()` example in the prose above
    s.add((xs[0] * 7 + xs[1]) % 1000003 == 424242)
    s.add(xs[2] ^ xs[3] == xs[0] + xs[1])
    s.add(z3.URem(xs[0] + xs[1] + xs[2] + xs[3], 97) == 13)
    for x in xs:
        s.add(z3.UGT(x, 0), z3.ULT(x, 36 ** 5))     # 5 base-36 characters per block
    if s.check() != z3.sat:
        return None
    model = s.model()
    return [model[x].as_long() for x in xs]


def verify_keygen(nums: list[int]) -> bool:
    """The validator the solver targets - keep this and the constraints in sync."""
    if len(nums) != 4:
        return False
    if (nums[0] * 7 + nums[1]) % 1000003 != 424242:
        return False
    if nums[2] ^ nums[3] != nums[0] + nums[1]:
        return False
    return sum(nums) % 97 == 13


def solve_keygen_bruteforce() -> list[int] | None:
    """A z3-free fallback: pick x0, x1 to satisfy the first constraint, then search."""
    for x0 in range(1, 5000):
        # (x0*7 + x1) % 1000003 == 424242  ->  x1 is determined mod 1000003
        x1 = (424242 - x0 * 7) % 1000003
        if not 0 < x1 < 36 ** 5:
            continue
        for x2 in range(1, 4000):
            x3 = x2 ^ (x0 + x1)
            if not 0 < x3 < 36 ** 5:
                continue
            if (x0 + x1 + x2 + x3) % 97 == 13:
                return [x0, x1, x2, x3]
    return None


def to_base36(n: int, width: int = 5) -> str:
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    out = ""
    while n:
        out = digits[n % 36] + out
        n //= 36
    return out.rjust(width, "0")


def format_key(nums: list[int]) -> str:
    return "-".join(to_base36(n) for n in nums)


# --------------------------------------------------------------------------- #
# custom protocol client
# --------------------------------------------------------------------------- #
class LengthPrefixedProtocol:
    """A reusable framing helper: <magic><type:1><length:2><payload><checksum:4>."""

    MAGIC = b"\xCA\xFE"

    def pack(self, msg_type: int, payload: bytes) -> bytes:
        body = self.MAGIC + struct.pack(">BH", msg_type, len(payload)) + payload
        return body + struct.pack(">I", binascii.crc32(body) & 0xFFFFFFFF)

    def unpack(self, data: bytes) -> tuple[int, bytes, bytes]:
        """Return (type, payload, remaining). Raises on a bad magic or checksum."""
        if data[:2] != self.MAGIC:
            raise ValueError(f"bad magic {data[:2]!r}")
        msg_type, length = struct.unpack(">BH", data[2:5])
        end = 5 + length
        payload = data[5:end]
        if len(payload) != length:
            raise ValueError("truncated payload")
        (crc,) = struct.unpack(">I", data[end:end + 4])
        if crc != binascii.crc32(data[:end]) & 0xFFFFFFFF:
            raise ValueError("checksum mismatch")
        return msg_type, payload, data[end + 4:]


def guess_length_field(messages: list[bytes]) -> list[str]:
    """Which offset/width/endianness reproduces each message's length?"""
    hits = []
    for width, fmt in ((1, "B"), (2, ">H"), (2, "<H"), (4, ">I"), (4, "<I")):
        for off in range(0, 8):
            ok = True
            for m in messages:
                if len(m) < off + width:
                    ok = False
                    break
                (val,) = struct.unpack(fmt, m[off:off + width])
                if val not in (len(m), len(m) - off - width, len(m) - width, len(m) - off):
                    ok = False
                    break
            if ok:
                hits.append(f"offset {off}, {width} bytes, {'big' if '>' in fmt or width == 1 else 'little'} endian")
    return hits


CHECKSUMS = {
    "crc32": lambda d: binascii.crc32(d) & 0xFFFFFFFF,
    "sum8": lambda d: sum(d) & 0xFF,
    "sum16": lambda d: sum(d) & 0xFFFF,
    "xor8": lambda d: 0 if not d else __import__("functools").reduce(lambda a, b: a ^ b, d),
}


def identify_checksum(body: bytes, trailer: bytes) -> list[str]:
    """Which common checksum of `body` equals `trailer`?"""
    out = []
    for name, fn in CHECKSUMS.items():
        val = fn(body)
        for width in (1, 2, 4):
            if len(trailer) != width:
                continue
            for fmt in (">", "<"):
                packer = {1: "B", 2: "H", 4: "I"}[width]
                try:
                    if struct.pack(fmt + packer, val & ((1 << (width * 8)) - 1)) == trailer:
                        out.append(f"{name} ({'big' if fmt == '>' else 'little'} endian)")
                except struct.error:
                    pass
    return out


# --------------------------------------------------------------------------- #
def _selftest() -> None:
    # --- MT19937 ----------------------------------------------------------
    for v in (0, 1, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF):
        assert untemper(temper(v)) == v, hex(v)

    rng = random.Random(1337)
    outputs = [rng.getrandbits(32) for _ in range(N)]
    clone = clone_mt(outputs)
    expected = [rng.getrandbits(32) for _ in range(10)]
    predicted = [clone.getrandbits(32) for _ in range(10)]
    assert predicted == expected, (predicted[:3], expected[:3])

    # the clone also reproduces higher-level API calls
    rng2 = random.Random(2024)
    outs = [rng2.getrandbits(32) for _ in range(N)]
    c2 = clone_mt(outs)
    assert [c2.randrange(10 ** 6) for _ in range(5)] == [rng2.randrange(10 ** 6) for _ in range(5)]

    # --- modular inverse --------------------------------------------------
    x = modular_key(7, 424242, 1000003)
    assert (7 * x) % 1000003 == 424242

    # --- keygen -----------------------------------------------------------
    nums = solve_keygen_z3()
    if nums is None:
        nums = solve_keygen_bruteforce()
        z3_note = "z3 unavailable, brute-force fallback used"
    else:
        z3_note = "z3 solver used"
    assert nums is not None, "no key found"
    assert verify_keygen(nums), nums
    key = format_key(nums)
    assert len(key.split("-")) == 4 and all(len(p) == 5 for p in key.split("-")), key
    assert to_base36(0) == "00000" and to_base36(36) == "00010"

    # --- protocol ---------------------------------------------------------
    proto = LengthPrefixedProtocol()
    frame = proto.pack(3, b"hello world")
    typ, payload, rest = proto.unpack(frame)
    assert (typ, payload, rest) == (3, b"hello world", b"")
    two = proto.pack(1, b"a") + proto.pack(2, b"bb")
    t1, p1, rest = proto.unpack(two)
    t2, p2, rest2 = proto.unpack(rest)
    assert (t1, p1, t2, p2, rest2) == (1, b"a", 2, b"bb", b"")
    corrupted = bytearray(frame)
    corrupted[-1] ^= 0xFF
    try:
        proto.unpack(bytes(corrupted))
    except ValueError:
        pass
    else:
        raise AssertionError("checksum should have failed")

    # --- length-field inference ------------------------------------------
    msgs = [struct.pack(">H", len(p)) + p for p in (b"a" * 5, b"b" * 40, b"c" * 300)]
    hits = guess_length_field(msgs)
    assert any("offset 0, 2 bytes, big endian" == h for h in hits), hits

    # --- checksum identification -----------------------------------------
    body = b"protocol body"
    assert "crc32 (big endian)" in identify_checksum(
        body, struct.pack(">I", binascii.crc32(body) & 0xFFFFFFFF))
    assert "sum8 (big endian)" in identify_checksum(body, bytes([sum(body) & 0xFF]))

    print(f"selftest ok: MT19937 cloned and predicted 10 values, key {key} valid "
          f"({z3_note}), protocol round trip, length field and checksum identified")


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] == "--selftest":
        _selftest()
        return 0
    if sys.argv[1] == "mt":
        rng = random.Random()
        outs = [rng.getrandbits(32) for _ in range(N)]
        clone = clone_mt(outs)
        print("next from original:", rng.getrandbits(32))
        print("next from clone   :", clone.getrandbits(32))
    elif sys.argv[1] == "keygen":
        nums = solve_keygen_z3() or solve_keygen_bruteforce()
        print(format_key(nums) if nums else "no solution")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

## Variants and pitfalls

- **`random.setstate` needs the exact tuple shape** `(3, tuple_of_625_ints, None)` - 624 state
  words plus an index. Setting the index to 624 means "the state is exhausted, twist on the
  next call", which is what you want after consuming 624 outputs.
- **`random.random()` consumes 53 bits** (two 32-bit outputs), not 32. Count your outputs in
  32-bit units, not in calls.
- **Python's `random` is not the only MT19937.** PHP `mt_rand`, Ruby, and many others use the
  same core with different tempering or seeding; check before assuming.
- **`os.urandom`/`secrets` are not predictable.** If the challenge uses them, the bug is
  elsewhere.
- **Keygens with a CRC** are easier than they look: CRC is linear over GF(2), so you can solve
  for the bytes that produce a target CRC directly.
- **z3 is not always needed.** If the constraints are linear modulo something, a modular
  inverse is instant and has no dependency.
- **searchsploit is offline** once the repository is cloned - keep it updated before an event.
- **Read the patch, not the CVE text.** The diff of the fix commit tells you the exact input
  that triggers the bug.
- **For custom protocols, replay first.** Send the exact bytes from the pcap before trying to
  understand them; if the server accepts a replay, you only need to vary one field.
- **Endianness and alignment** are the two things that go wrong in a `struct` format string.
  Prefix with `>` or `<` explicitly - never use native `@` for a wire format.

## Tools

`searchsploit` (exploitdb), `z3-solver` (`pip install z3-solver`), `scapy`/`tshark`/Wireshark,
Python `struct`/`binascii`/`random`, `git log -p` on the upstream project, `crccalc`-style
CRC tables, `RsaCtfTool`-adjacent solvers for the number-theory variants.

## References

- Matsumoto and Nishimura, "Mersenne Twister: A 623-dimensionally equidistributed uniform
  pseudo-random number generator" (1998) - the tempering transform inverted above.
- CPython `Lib/random.py` and `Modules/_randommodule.c` for `getstate`/`setstate` semantics.
- Z3 Python API documentation: https://github.com/Z3Prover/z3
- Exploit-DB / searchsploit documentation for the offline workflow.
