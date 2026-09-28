---
title: "Script - Universal Proof-of-Work Solver"
category: misc
subcategory: proof-of-work
type: script
tags: [proof-of-work, pow, hashcash, redpwnpow, kctf, sha256, sha1, multiprocessing, auto-detect, vdf, sloth, netcat, pwntools, script]
summary: "Auto-detects the PoW form from the banner text and solves it: sha256 prefix/suffix zeros, zero bits, hashcash, redpwnpow and kctf pow.py."
tools: [python3, hashcash, kctf-pow]
related: [remote-interaction-and-pow, ctf-general-cheatsheet, misc-classics, jail-escape-payloads]
---

## What it does

Takes the text a service printed (or a challenge string on the command line), works out which
proof-of-work scheme it is, and solves it with every core on the machine.

Supported forms:

| Detected from | Scheme | Method |
| --- | --- | --- |
| `sha256(prefix + X) starts with N zeros` | hex-prefix search | multi-process brute force |
| `... N leading zero bits` | bit-prefix search | multi-process brute force |
| `... ends with N zeros` | hex-suffix search | multi-process brute force |
| `sha256(X)[:N] == "000..."` | slice comparison | multi-process brute force |
| `hashcash -mb<bits> -r <resource>` | hashcash v1 stamp | SHA-1 counter search |
| `s.<difficulty>.<base64>` with `pwn.red` | redpwnpow | repeated squaring (VDF) |
| `s.<difficulty>.<base64>` with `kctf`/`goo.gle` | kctf `pow.py` | repeated squaring (VDF) |

The two VDF schemes (redpwnpow and kctf) are **sequential by construction** - they cannot be
parallelised, which is the point of the design. The implementations below follow the published
algorithm: start from the decoded challenge value and square it modulo a fixed prime
`difficulty` times. If the remote rejects the answer, fall back to the official solver script;
the encodings have changed across versions and only the official script is guaranteed current.

## Usage

```bash
python3 pow_solver.py --selftest

# paste the whole banner and let it work out the scheme
python3 pow_solver.py --text "sha256(abc123 + X) must start with 6 zeros"

# read the banner from stdin (e.g. piped from nc)
nc host 1337 | head -5 | python3 pow_solver.py

# explicit forms
python3 pow_solver.py --prefix abc123 --zeros 6
python3 pow_solver.py --prefix abc123 --bits 26
python3 pow_solver.py --hashcash-bits 20 --resource user@example.com
python3 pow_solver.py --challenge 's.AAAA.BBBB'

# tune
python3 pow_solver.py --prefix abc --bits 28 --jobs 8
```

## Script

```python
#!/usr/bin/env python3
"""Universal CTF proof-of-work solver.

Auto-detects the scheme from the challenge text and solves it, using every core
for the hash-search forms.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import multiprocessing as mp
import os
import re
import sys
import time

# --------------------------------------------------------------------------- #
# candidate enumeration
# --------------------------------------------------------------------------- #
ALPHABET = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def encode(i: int) -> bytes:
    """Base-62 encoding of i, used to enumerate distinct candidates cheaply."""
    if i == 0:
        return ALPHABET[:1]
    out = bytearray()
    n = len(ALPHABET)
    while i:
        out.append(ALPHABET[i % n])
        i //= n
    out.reverse()
    return bytes(out)


# --------------------------------------------------------------------------- #
# hash-search proof of work
# --------------------------------------------------------------------------- #
def _matches(digest_hex: str, digest_bits: int, mode: str, n: int) -> bool:
    if mode == "hex-prefix":
        return digest_hex.startswith("0" * n)
    if mode == "hex-suffix":
        return digest_hex.endswith("0" * n)
    if mode == "bits":
        return int(digest_hex, 16) < (1 << (digest_bits - n))
    raise ValueError(f"unknown mode {mode}")


def _search(args) -> bytes | None:
    prefix, n, mode, algo, start, step, budget, suffix = args
    h = getattr(hashlib, algo)
    bits = h().digest_size * 8
    i = start
    end = start + budget * step
    while i < end:
        cand = encode(i)
        digest = h(prefix + cand + suffix).hexdigest()
        if _matches(digest, bits, mode, n):
            return cand
        i += step
    return None


def solve_hash(prefix: bytes = b"", n: int = 4, mode: str = "hex-prefix",
               algo: str = "sha256", jobs: int = 0, suffix: bytes = b"",
               verbose: bool = False) -> bytes:
    """Find `cand` such that algo(prefix + cand + suffix) satisfies the condition."""
    jobs = jobs or (os.cpu_count() or 1)
    if jobs == 1 or n <= 4:
        i = 0
        h = getattr(hashlib, algo)
        bits = h().digest_size * 8
        while True:
            cand = encode(i)
            if _matches(h(prefix + cand + suffix).hexdigest(), bits, mode, n):
                return cand
            i += 1

    chunk = 200_000
    round_no = 0
    with mp.Pool(jobs) as pool:
        while True:
            base = round_no * jobs * chunk
            tasks = [(prefix, n, mode, algo, base + k, jobs, chunk, suffix)
                     for k in range(jobs)]
            for res in pool.imap_unordered(_search, tasks):
                if res is not None:
                    pool.terminate()
                    return res
            round_no += 1
            if verbose:
                sys.stderr.write(f"[.] {base + jobs * chunk:,} candidates tried\n")


def verify_hash(prefix: bytes, cand: bytes, n: int, mode: str,
                algo: str = "sha256", suffix: bytes = b"") -> bool:
    h = getattr(hashlib, algo)
    bits = h().digest_size * 8
    return _matches(h(prefix + cand + suffix).hexdigest(), bits, mode, n)


# --------------------------------------------------------------------------- #
# hashcash v1
# --------------------------------------------------------------------------- #
def hashcash_stamp(bits: int, resource: str, date: str | None = None,
                   rand: str | None = None) -> str:
    """Mint a hashcash v1 stamp: 1:bits:date:resource::rand:counter

    Valid when SHA-1 of the whole stamp has `bits` leading zero bits.
    """
    if date is None:
        date = time.strftime("%y%m%d", time.gmtime())
    if rand is None:
        rand = base64.b64encode(os.urandom(8)).decode().rstrip("=")
    head = f"1:{bits}:{date}:{resource}::{rand}:"
    counter = 0
    while True:
        counter_b64 = base64.b64encode(f"{counter:x}".encode()).decode().rstrip("=")
        stamp = head + counter_b64
        digest = hashlib.sha1(stamp.encode()).digest()
        if leading_zero_bits(digest) >= bits:
            return stamp
        counter += 1


def leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        for bit in range(7, -1, -1):
            if byte & (1 << bit):
                return count
            count += 1
        break
    return count


def verify_hashcash(stamp: str, bits: int) -> bool:
    return leading_zero_bits(hashlib.sha1(stamp.encode()).digest()) >= bits


# --------------------------------------------------------------------------- #
# VDF-style proofs of work (redpwnpow / kctf pow.py)
# --------------------------------------------------------------------------- #
# Both schemes use the same construction: a fixed safe prime, a challenge value x,
# and `difficulty` sequential modular squarings. The prime below is the one published
# by the kctf pow.py implementation.
VDF_MODULUS = (1 << 1279) - 1


def vdf_solve(difficulty: int, x: int, modulus: int = VDF_MODULUS) -> int:
    """Sequential squaring: x <- x^2 mod m, `difficulty` times.

    Equivalent to x^(2^difficulty) mod m, but computing it the fast way with
    pow(x, 1 << difficulty, m) is exactly what the scheme is designed to allow
    only for someone who knows the group order - we do not, so we iterate.
    """
    for _ in range(difficulty):
        x = pow(x, 2, modulus)
    return x


def b64_to_int(s: str) -> int:
    pad = "=" * (-len(s) % 4)
    return int.from_bytes(base64.b64decode(s + pad), "big")


def int_to_b64(n: int) -> str:
    length = max(1, (n.bit_length() + 7) // 8)
    return base64.b64encode(n.to_bytes(length, "big")).decode().rstrip("=")


def parse_vdf_challenge(chal: str) -> tuple[int, int] | None:
    """Parse the `s.<difficulty>.<b64>` form used by redpwnpow and kctf pow.py."""
    m = re.fullmatch(r"s\.([A-Za-z0-9+/=_-]+)\.([A-Za-z0-9+/=_-]+)", chal.strip())
    if not m:
        return None
    dif_raw, x_raw = m.group(1), m.group(2)
    try:
        difficulty = int(dif_raw)
    except ValueError:
        difficulty = b64_to_int(dif_raw)
    return difficulty, b64_to_int(x_raw)


def solve_vdf_challenge(chal: str) -> str | None:
    parsed = parse_vdf_challenge(chal)
    if parsed is None:
        return None
    difficulty, x = parsed
    if difficulty > 10_000_000:
        sys.stderr.write(f"[!] difficulty {difficulty} is very large; "
                         f"this will take a while (it is sequential by design)\n")
    return "s." + int_to_b64(vdf_solve(difficulty, x))


# --------------------------------------------------------------------------- #
# auto-detection
# --------------------------------------------------------------------------- #
def detect(text: str) -> dict | None:
    """Work out which scheme the banner describes."""
    t = text.strip()

    m = re.search(r"\bs\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+", t)
    if m and ("pow.red" in t or "pwn.red" in t or "kctf" in t or "goo.gle" in t
              or "proof" in t.lower() or "pow" in t.lower()):
        return {"scheme": "vdf", "challenge": m.group(0)}

    m = re.search(r"hashcash\s+-[a-z]*b(\d+)[^\n]*?-r\s+(\S+)", t, re.I)
    if m:
        return {"scheme": "hashcash", "bits": int(m.group(1)), "resource": m.group(2)}
    m = re.search(r"hashcash[^\n]*?(\d+)\s*bits?[^\n]*?resource\s*[:=]?\s*(\S+)", t, re.I)
    if m:
        return {"scheme": "hashcash", "bits": int(m.group(1)), "resource": m.group(2)}

    prefix = b""
    pm = (re.search(r"sha256\(\s*[\"']?([A-Za-z0-9+/=_-]{3,})[\"']?\s*\+", t, re.I)
          or re.search(r"prefix\s*[:=]\s*[\"']?([A-Za-z0-9+/=_-]{3,})", t, re.I)
          or re.search(r"\bwith\s+[\"']([A-Za-z0-9+/=_-]{3,})[\"']", t, re.I))
    if pm:
        prefix = pm.group(1).encode()

    algo = "sha1" if re.search(r"\bsha1\b", t, re.I) else (
        "md5" if re.search(r"\bmd5\b", t, re.I) else "sha256")

    m = re.search(r"(\d+)\s*(?:leading\s*)?zero\s*bits", t, re.I)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": int(m.group(1)),
                "mode": "bits", "algo": algo}
    m = re.search(r"ends?\s+with\s+(\d+)\s+(?:hex\s+)?zero", t, re.I)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": int(m.group(1)),
                "mode": "hex-suffix", "algo": algo}
    m = re.search(r"start(?:s|ing)?\s+with\s+(\d+)\s+(?:hex\s+)?zero", t, re.I)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": int(m.group(1)),
                "mode": "hex-prefix", "algo": algo}
    m = re.search(r"\[:\s*(\d+)\s*\]\s*==\s*[\"'](0+)[\"']", t)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": int(m.group(1)),
                "mode": "hex-prefix", "algo": algo}
    m = re.search(r"==\s*[\"'](0+)[\"']", t)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": len(m.group(1)),
                "mode": "hex-prefix", "algo": algo}
    m = re.search(r"(\d+)\s+(?:hex\s+)?zero", t, re.I)
    if m:
        return {"scheme": "hash", "prefix": prefix, "n": int(m.group(1)),
                "mode": "hex-prefix", "algo": algo}
    return None


def solve_detected(spec: dict, jobs: int = 0, verbose: bool = False) -> str:
    if spec["scheme"] == "hash":
        cand = solve_hash(spec["prefix"], spec["n"], spec["mode"],
                          spec.get("algo", "sha256"), jobs, verbose=verbose)
        return cand.decode()
    if spec["scheme"] == "hashcash":
        return hashcash_stamp(spec["bits"], spec["resource"])
    if spec["scheme"] == "vdf":
        out = solve_vdf_challenge(spec["challenge"])
        if out is None:
            raise ValueError("could not parse the VDF challenge string")
        return out
    raise ValueError(f"unknown scheme {spec['scheme']}")


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="universal CTF proof-of-work solver")
    ap.add_argument("--text", help="the banner text to auto-detect from")
    ap.add_argument("--prefix", default="", help="the fixed prefix to hash")
    ap.add_argument("--zeros", type=int, help="required leading hex zeros")
    ap.add_argument("--suffix-zeros", type=int, help="required trailing hex zeros")
    ap.add_argument("--bits", type=int, help="required leading zero bits")
    ap.add_argument("--algo", default="sha256", help="sha256 (default), sha1, md5")
    ap.add_argument("--hashcash-bits", type=int)
    ap.add_argument("--resource", default="")
    ap.add_argument("--challenge", help="a s.<difficulty>.<b64> challenge string")
    ap.add_argument("--jobs", type=int, default=0)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        _selftest()
        return 0

    start = time.time()
    if args.challenge:
        out = solve_vdf_challenge(args.challenge)
        if out is None:
            print("[-] not a recognised s.<difficulty>.<b64> challenge", file=sys.stderr)
            return 1
        print(out)
    elif args.hashcash_bits:
        print(hashcash_stamp(args.hashcash_bits, args.resource))
    elif args.zeros is not None:
        print(solve_hash(args.prefix.encode(), args.zeros, "hex-prefix",
                         args.algo, args.jobs, verbose=args.verbose).decode())
    elif args.suffix_zeros is not None:
        print(solve_hash(args.prefix.encode(), args.suffix_zeros, "hex-suffix",
                         args.algo, args.jobs, verbose=args.verbose).decode())
    elif args.bits is not None:
        print(solve_hash(args.prefix.encode(), args.bits, "bits",
                         args.algo, args.jobs, verbose=args.verbose).decode())
    else:
        text = args.text if args.text is not None else sys.stdin.read()
        spec = detect(text)
        if spec is None:
            print("[-] could not detect the scheme; pass --zeros/--bits/--challenge",
                  file=sys.stderr)
            return 1
        if args.verbose:
            print(f"[*] detected: {spec}", file=sys.stderr)
        print(solve_detected(spec, args.jobs, args.verbose))
    if args.verbose:
        print(f"[*] {time.time() - start:.2f}s", file=sys.stderr)
    return 0


def _selftest() -> None:
    # candidate encoding is injective
    assert len({encode(i) for i in range(5000)}) == 5000

    # hex prefix
    cand = solve_hash(b"abc123", 4, "hex-prefix", jobs=1)
    assert hashlib.sha256(b"abc123" + cand).hexdigest().startswith("0000"), cand
    assert verify_hash(b"abc123", cand, 4, "hex-prefix")

    # hex suffix
    cand_s = solve_hash(b"q", 3, "hex-suffix", jobs=1)
    assert hashlib.sha256(b"q" + cand_s).hexdigest().endswith("000"), cand_s

    # leading zero bits
    cand_b = solve_hash(b"xyz", 18, "bits", jobs=1)
    assert int(hashlib.sha256(b"xyz" + cand_b).hexdigest(), 16) < (1 << (256 - 18))

    # a different algorithm
    cand_m = solve_hash(b"m", 3, "hex-prefix", algo="md5", jobs=1)
    assert hashlib.md5(b"m" + cand_m).hexdigest().startswith("000")

    # multi-process path produces a valid answer too
    cand_mp = solve_hash(b"mp", 5, "hex-prefix", jobs=min(4, os.cpu_count() or 1))
    assert hashlib.sha256(b"mp" + cand_mp).hexdigest().startswith("00000"), cand_mp

    # hashcash
    stamp = hashcash_stamp(12, "test@example.com", date="260101", rand="AAAAAAAA")
    assert verify_hashcash(stamp, 12), stamp
    parts = stamp.split(":")
    assert parts[0] == "1" and parts[1] == "12" and parts[3] == "test@example.com", parts
    assert leading_zero_bits(b"\x00\x00\x0f") == 20
    assert leading_zero_bits(b"\xff") == 0
    assert leading_zero_bits(b"\x00\x80") == 8

    # base64 int helpers round trip
    for v in (0, 1, 255, 256, 1 << 200, 123456789):
        assert b64_to_int(int_to_b64(v)) == v, v

    # VDF: parsing and the squaring itself
    chal = f"s.{100}.{int_to_b64(31337)}"
    parsed = parse_vdf_challenge(chal)
    assert parsed == (100, 31337), parsed
    ans = solve_vdf_challenge(chal)
    assert ans is not None and ans.startswith("s.")
    # sequential squaring must equal the closed form x^(2^d) mod m
    assert vdf_solve(10, 31337) == pow(31337, 1 << 10, VDF_MODULUS)
    assert b64_to_int(ans[2:]) == pow(31337, 1 << 100, VDF_MODULUS)
    assert parse_vdf_challenge("not a challenge") is None

    # detection
    d = detect("find s such that sha256('abc123' + s) starts with 6 zeros")
    assert d == {"scheme": "hash", "prefix": b"abc123", "n": 6,
                 "mode": "hex-prefix", "algo": "sha256"}, d
    d = detect("provide a token whose sha256 has 26 leading zero bits")
    assert d["scheme"] == "hash" and d["n"] == 26 and d["mode"] == "bits", d
    d = detect('sha256(X)[:6] == "000000"')
    assert d["n"] == 6 and d["mode"] == "hex-prefix", d
    d = detect("the digest must end with 5 zeros")
    assert d["mode"] == "hex-suffix" and d["n"] == 5, d
    d = detect("run: hashcash -mb20 -r user@example.com")
    assert d == {"scheme": "hashcash", "bits": 20, "resource": "user@example.com"}, d
    d = detect("== proof-of-work: curl -sSfL https://pwn.red/pow | sh -s s.MTAw.AAB6aQ ==")
    assert d["scheme"] == "vdf" and d["challenge"] == "s.MTAw.AAB6aQ", d
    d = detect("python3 <(curl -sSL https://goo.gle/kctf-pow) solve s.524288.AQAB")
    assert d["scheme"] == "vdf", d
    d = detect("sha1 of your answer must start with 4 zeros")
    assert d["algo"] == "sha1", d
    assert detect("welcome to the challenge, good luck") is None

    # end to end through solve_detected
    out = solve_detected(detect("sha256('zzz' + s) must start with 3 zeros"), jobs=1)
    assert hashlib.sha256(b"zzz" + out.encode()).hexdigest().startswith("000"), out

    print(f"selftest ok: hash (prefix/suffix/bits/md5/multiproc), hashcash stamp {stamp!r}, "
          f"VDF squaring matches the closed form, 9 detection cases")


if __name__ == "__main__":
    sys.exit(main())
```

## Wiring it into an exploit

```python
from pwn import remote
import subprocess, sys

io = remote("host", 1337)
banner = io.recvuntil(b"\n" * 2, timeout=5)
out = subprocess.run([sys.executable, "pow_solver.py", "--text", banner.decode()],
                     capture_output=True, text=True, timeout=600)
io.sendline(out.stdout.strip().encode())
io.interactive()
```

## Difficulty reference

| Requirement | Expected hashes | Wall time (8 cores, ~5M h/s) |
| --- | --- | --- |
| 4 hex zeros (16 bits) | 65 thousand | instant |
| 5 hex zeros (20 bits) | 1 million | < 1 s |
| 6 hex zeros (24 bits) | 16 million | ~3 s |
| 7 hex zeros (28 bits) | 268 million | ~1 min |
| 8 hex zeros (32 bits) | 4.3 billion | ~15 min |
| 20 zero bits | 1 million | < 1 s |
| 24 zero bits | 16 million | ~3 s |
| 28 zero bits | 268 million | ~1 min |

If a challenge asks for more than 8 hex zeros, re-read the text - it is almost certainly
*bits*, not hex digits.

## Gotchas

- **Hex zeros vs zero bits**: one hex zero is four bits. "20 zeros" meaning hex digits is 80
  bits and is not solvable; it means 20 bits.
- **The prefix may need to be appended, not prepended.** If verification fails, swap the order
  (`--suffix` support is in `solve_hash` via its `suffix` argument).
- **The answer's encoding matters.** Some services want the raw candidate string, some want it
  hex-encoded, some want `sha256(prefix+cand)` itself. Read the prompt.
- **VDF schemes are deliberately sequential.** Extra cores do not help; a large difficulty
  really does take minutes. Start solving as soon as you have the challenge string.
- **redpwnpow and kctf have version-specific encodings.** The implementation here follows the
  published repeated-squaring construction; if the server rejects it, run the official
  one-liner the banner gives you rather than debugging the encoding.
- **Connection timeouts**: solve the PoW before the server's idle timeout, or reconnect and
  solve the fresh challenge.
- **`mp.Pool` on macOS/Windows uses spawn**, so the worker function must be importable at
  module level - it is here (`_search`), which is why it is not a closure.
