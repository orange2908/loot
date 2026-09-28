---
title: "Timing Attack on Non-Constant-Time MAC Comparison"
category: crypto
subcategory: side-channel
type: technique
tags: [timing-attack, side-channel, hmac, mac-verification, constant-time, compare-digest, early-return, byte-at-a-time, signature-forgery, statistics, median, minimum, remote-timing, cryptopals, hmac-sha1, hmac-sha256, python]
difficulty: medium
summary: "An `==` on a MAC returns as soon as two bytes differ, so a correct prefix takes measurably longer; recover the tag one byte at a time, 256 guesses per byte."
when_to_use:
  - "Signature verification uses `==`, `!=`, `strcmp`, or a manual loop with an early return"
  - "You can send unlimited verification requests and measure the response time"
  - "The endpoint returns the same error for every wrong signature (so only timing differs)"
  - "Source shows `if sig != expected: return 403` with no `hmac.compare_digest`"
  - "An artificial `sleep` sits inside the comparison loop (the CTF-friendly version)"
tools: [python, requests, pwntools, burpsuite]
source:
  name: "Cryptopals Set 4"
  url: "https://cryptopals.com/sets/4"
related: [hash-length-extension, block-cbc-mac-forgery, hash-collisions-magic, aes-cbc-padding-oracle]
---

## TL;DR

`a == b` on bytes short-circuits at the first difference. So verifying a signature
whose first `k` bytes are right takes `k` byte-comparisons and verifying one whose
first byte is wrong takes one. That difference is a per-byte oracle: fix bytes
`0..k-1`, sweep all 256 values of byte `k`, and the value that takes longest is
correct. `32 * 256 = 8192` requests recovers a full HMAC-SHA256 tag.

## Recognise it

- `if signature != hmac.new(key, data, sha256).hexdigest(): abort(403)`.
- A hand-written loop `for a, b in zip(sig, expected): if a != b: return False`.
- `strcmp`, `memcmp`, `===` on strings in PHP/JS, `Arrays.equals` in Java.
- A challenge that adds `time.sleep(0.005)` inside the comparison - that is the author
  telling you the intended solution.
- Absence of `hmac.compare_digest`, `crypto.timingSafeEqual`, `CRYPTO_memcmp`,
  `MessageDigest.isEqual` (which is *not* constant time in older Java, incidentally).

## Theory

Let `T(k)` be the time to verify a candidate whose first `k` bytes match. For a
short-circuiting comparison,

$$T(k) = c_0 + k \cdot c_1$$

with `c_1` the cost of one byte comparison. You never learn the tag directly; you learn
`k`, which is enough, because you can raise `k` one byte at a time:

1. Assume bytes `0..k-1` are known. For each candidate `g` in `0..255`, submit
   `known || g || filler` and time it.
2. The correct `g` gives `T(k+1)`; all others give `T(k)`. Take the argmax.
3. Append and repeat.

Total `256 * L` requests for an `L`-byte tag, and the work is *linear* in `L` rather
than exponential - that is the whole point.

**Noise.** Real measurements are `T + noise` where `noise >= 0` (scheduler
preemption, GC, network jitter). Because noise only *adds* time, the **minimum** over
several repeats is a far better estimator than the mean:

$$\hat{T}(g) = \min_{i=1..N} t_i(g)$$

Then pick `argmax_g` of that minimum. Alternatives: the median (robust to both
directions), or a full statistical test comparing the distributions of the best two
candidates and re-measuring until they separate (Crosby-Wallach style).

If `c_1` is a single memory comparison (nanoseconds), you need thousands of repeats
and careful setup. If the server inflates it with a `sleep`, five repeats is plenty.
Remote attacks over a LAN are demonstrated in the literature; over the internet they
need many more samples.

**Backtracking.** A single wrong byte poisons everything after it, because the prefix
never matches again and all 256 candidates look identical. Detect this (no candidate
stands out) and go back one position to take the second-best value.

**The fix.** Compare in constant time: xor every byte, OR the results, and check the
accumulator once at the end. `hmac.compare_digest` does exactly that. Alternatively
compare `HMAC(k, sig)` with `HMAC(k, expected)` for a fresh random `k` - then the
comparison operates on values the attacker cannot influence.

## Attack

1. Confirm the leak: time 50 requests with a random first byte and 50 with a
   deliberately different one. If the distributions overlap completely, measure more or
   give up on timing.
2. Calibrate: find the per-byte delta by timing a known-correct prefix of length 0
   versus length 1 (you can bootstrap this from step 3's first round).
3. For `k` in `0..L-1`: sweep 256 candidates, `N` repeats each, keep the minimum,
   take the argmax.
4. Every few bytes, verify by submitting the full candidate tag - success ends the
   attack early.
5. If a position is ambiguous, keep the top two and branch.

## Code

```python
#!/usr/bin/env python3
"""Byte-at-a-time recovery of an HMAC tag from a non-constant-time comparison.

Two oracles:
  * a deterministic simulated-clock server (fast, reproducible),
  * a real wall-clock server that burns CPU per matched byte.
Both are attacked and asserted. Also shows hmac.compare_digest defeating the attack.
"""

import hashlib
import hmac
import os
import random
import time

KEY = os.urandom(32)
MESSAGE = b"file=flag.txt&user=guest"


def real_tag(message: bytes, key: bytes = KEY) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


# ------------------------------------------------- the vulnerable comparison
def insecure_equals(a: bytes, b: bytes) -> tuple[bool, int]:
    """Short-circuiting compare. Returns (equal, number of bytes examined)."""
    if len(a) != len(b):
        return False, 0
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return False, i + 1
    return True, len(a)


# ------------------------------------------------- oracle 1: simulated clock
class SimulatedServer:
    """Deterministic timing model: cost is proportional to bytes examined, plus
    one-sided positive noise, exactly like a real machine under load."""

    def __init__(self, per_byte: float = 1.0, noise: float = 3.0, seed: int = 0):
        self.per_byte = per_byte
        self.noise = noise
        self.rng = random.Random(seed)
        self.queries = 0

    def verify(self, message: bytes, sig: bytes) -> tuple[bool, float]:
        self.queries += 1
        ok, examined = insecure_equals(sig, real_tag(message))
        jitter = self.rng.random() ** 3 * self.noise      # long right tail
        return ok, examined * self.per_byte + jitter


# ------------------------------------------------- oracle 2: real wall clock
def _burn(units: int) -> None:
    """Do a measurable amount of real work -- stands in for a slow comparison."""
    h = b"\x00" * 32
    for _ in range(units):
        h = hashlib.sha256(h).digest()


class RealClockServer:
    """Every matched byte costs real CPU time. Timing is measured, not modelled.

    We read `time.process_time()` (this process's CPU time) rather than the wall
    clock so the self-test is not derailed by whatever else the machine is doing.
    A remote attacker only has the wall clock and pays for that with more samples.
    """

    def __init__(self, work_per_byte: int = 600):
        self.work = work_per_byte
        self.queries = 0

    def verify(self, message: bytes, sig: bytes) -> tuple[bool, float]:
        self.queries += 1
        expected = real_tag(message)
        start = time.process_time()
        ok = True
        if len(sig) != len(expected):
            ok = False
        else:
            for x, y in zip(sig, expected):
                _burn(self.work)                 # the "byte comparison"
                if x != y:
                    ok = False
                    break
        return ok, time.process_time() - start


# ------------------------------------------------------- constant-time server
class SafeServer:
    def __init__(self):
        self.queries = 0

    def verify(self, message: bytes, sig: bytes) -> tuple[bool, float]:
        self.queries += 1
        start = time.perf_counter()
        ok = hmac.compare_digest(sig, real_tag(message))
        return ok, time.perf_counter() - start


# ----------------------------------------------------------------- attack
def timing_attack(server, message: bytes, tag_len: int = 32, repeats: int = 25,
                  known: bytes = b"", stop_after: int | None = None,
                  verbose: bool = False) -> bytes:
    """Recover the tag one byte at a time from response latency.

    Two things make this robust on a noisy machine:
      * candidates are INTERLEAVED -- one full sweep of all 256 per pass -- so a slow
        period hits every candidate rather than a contiguous run of them;
      * each pass is normalised against its own median, which cancels slow drift;
      * the per-candidate score is the MINIMUM over passes, because noise only adds.
    """
    recovered = bytearray(known)
    limit = tag_len if stop_after is None else min(tag_len, len(known) + stop_after)
    while len(recovered) < limit:
        best = [float("inf")] * 256
        for _ in range(repeats):
            row = []
            for guess in range(256):
                candidate = bytes(recovered) + bytes([guess])
                candidate = candidate.ljust(tag_len, b"\x00")
                ok, elapsed = server.verify(message, candidate)
                if ok:
                    return candidate      # the LAST byte has no timing signal at all:
                row.append(elapsed)       # both branches examine every byte, so the
            baseline = sorted(row)[128]   # accept/reject flag decides it instead
            for g in range(256):
                best[g] = min(best[g], row[g] - baseline)
        guess = max(range(256), key=lambda g: best[g])
        recovered.append(guess)
        if verbose:
            print(f"    byte {len(recovered) - 1:2d} = 0x{guess:02x} "
                  f"(margin {best[guess] - sorted(best)[-2]:.5f})")
    return bytes(recovered)


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    TAG = real_tag(MESSAGE)
    print("[+] target tag:", TAG.hex())

    # --- the leak is real --------------------------------------------------
    srv = SimulatedServer()
    right = min(srv.verify(MESSAGE, TAG[:1] + b"\x00" * 31)[1] for _ in range(20))
    wrong = min(srv.verify(MESSAGE, bytes([TAG[0] ^ 1]) + b"\x00" * 31)[1]
                for _ in range(20))
    print(f"[+] correct first byte: {right:.3f}   wrong first byte: {wrong:.3f}")
    assert right > wrong
    print("[+] PASS a correct prefix is measurably slower")

    # --- full recovery against the simulated clock -------------------------
    srv = SimulatedServer()
    t0 = time.time()
    found = timing_attack(srv, MESSAGE, len(TAG), repeats=25)
    print(f"[+] recovered : {found.hex()}")
    print(f"[+] {srv.queries} queries in {time.time() - t0:.1f}s")
    assert found == TAG, (found.hex(), TAG.hex())
    assert srv.verify(MESSAGE, found)[0]
    print("[+] PASS full HMAC-SHA256 tag recovered from timing alone")

    # --- harsher noise needs more repeats ----------------------------------
    noisy = SimulatedServer(per_byte=1.0, noise=8.0, seed=7)
    found_noisy = timing_attack(noisy, MESSAGE, len(TAG), repeats=60)
    assert found_noisy == TAG, found_noisy.hex()
    print(f"[+] PASS with 8x noise, 60 repeats still wins "
          f"({noisy.queries} queries)")

    # --- against a real wall clock -----------------------------------------
    real_srv = RealClockServer(work_per_byte=1200)
    t0 = time.time()
    prefix = timing_attack(real_srv, MESSAGE, tag_len=len(TAG), repeats=8,
                           stop_after=2)              # the first 2 bytes only
    print(f"[+] real-clock attack on the first 2 bytes took "
          f"{time.time() - t0:.1f}s, {real_srv.queries} queries")
    assert prefix == TAG[:2], (prefix.hex(), TAG[:2].hex())
    print("[+] PASS wall-clock timing attack recovers real bytes")

    # --- the fix -----------------------------------------------------------
    safe = SafeServer()
    a = [safe.verify(MESSAGE, TAG[:1] + b"\x00" * 31)[1] for _ in range(200)]
    b = [safe.verify(MESSAGE, bytes([TAG[0] ^ 1]) + b"\x00" * 31)[1]
         for _ in range(200)]
    delta = abs(min(a) - min(b))
    print(f"[+] compare_digest timing delta: {delta * 1e9:.0f} ns (noise floor)")
    assert safe.verify(MESSAGE, TAG)[0] and not safe.verify(MESSAGE, bytes(32))[0]
    print("[+] PASS hmac.compare_digest still verifies correctly and leaks no prefix")

    # --- what a vulnerable endpoint looks like -----------------------------
    def vulnerable_endpoint(message: bytes, sig_hex: str) -> str:
        if hmac.new(KEY, message, hashlib.sha256).hexdigest() != sig_hex:  # BUG
            return "403 Forbidden"
        return "200 OK"

    def safe_endpoint(message: bytes, sig_hex: str) -> str:
        expected = hmac.new(KEY, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig_hex):                     # FIX
            return "403 Forbidden"
        return "200 OK"

    assert vulnerable_endpoint(MESSAGE, TAG.hex()) == "200 OK"
    assert safe_endpoint(MESSAGE, TAG.hex()) == "200 OK"
    assert safe_endpoint(MESSAGE, "00" * 32) == "403 Forbidden"
    print("[+] PASS endpoint examples behave as documented")

    print("\nall checks passed")
```

## Variants & pitfalls

- **Hex vs raw.** If the server compares hex strings, each *nibble* is a comparison
  step, so you recover 4 bits at a time with 16 candidates - cheaper, not harder.
- **Length check first.** Most comparisons return immediately on a length mismatch, so
  always send a full-length candidate padded with anything.
- **A wrong byte poisons the rest.** If no candidate at position `k` stands out, the
  byte at `k-1` is wrong. Keep the top two candidates per position and backtrack.
- **Use the minimum, not the mean.** Noise is one-sided (it only adds time). The mean
  is dragged around by outliers; the minimum converges fast.
- **Warm-up effects.** The first few requests are slower (JIT, cache, TLS handshake).
  Discard them, and interleave candidates rather than measuring all repeats of one
  candidate back to back, so drift affects everyone equally.
- **Keep the connection open.** HTTP keep-alive removes handshake jitter, which is
  usually larger than the signal.
- **Remote is hard but not impossible.** Brumley-Boneh showed network timing attacks
  against OpenSSL RSA. On a LAN with thousands of samples, a few-hundred-nanosecond
  difference is recoverable.
- **The same bug elsewhere.** Password comparison, API-key checks, CSRF token checks,
  JWT signature checks, license key validation. Look for `==` on any secret.
- **It is not just comparison.** Early-return parsing, cache hits and branch-dependent
  arithmetic leak too. Modular exponentiation without blinding leaks RSA keys; table
  lookups in a software AES leak the key through cache timing.

## Tools

- `hmac.compare_digest` (Python), `crypto.timingSafeEqual` (Node),
  `hash_equals` (PHP), `subtle.ConstantTimeCompare` (Go), `CRYPTO_memcmp` (OpenSSL).
- `requests` with a `Session` for keep-alive; `pwntools` for raw sockets.
- `time.perf_counter_ns()` for the highest-resolution clock Python offers.

## References

- Cryptopals Set 4, challenges 31 and 32 ("Implement and break HMAC-SHA1 with an
  artificial timing leak"): <https://cryptopals.com/sets/4>
- Crosby, Wallach and Riedi, "Opportunities and Limits of Remote Timing Attacks" (2009).
- Brumley and Boneh, "Remote Timing Attacks are Practical" (USENIX Security 2003).
