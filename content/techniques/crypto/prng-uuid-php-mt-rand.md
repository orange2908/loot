---
title: "Predicting UUIDv1/v4/v7 and Recovering PHP mt_rand / rand Seeds"
category: crypto
subcategory: prng
type: technique
tags: [uuid, uuidv1, uuidv4, uuidv7, guid, sandwich-attack, mac-address, php, mt-rand, mt-srand, php-mt-seed, uniqid, rand, mt19937, seed-recovery, password-reset-token, prng]
difficulty: medium
summary: "UUIDv1 and v7 are timestamps plus a MAC, so they are guessable; PHP's mt_rand is MT19937 shifted right by one bit, and php_mt_seed cracks its seed from a single output."
when_to_use:
  - "A password-reset or invite token is a UUID and you can trigger your own"
  - "UUIDs in responses have identical trailing 12 hex digits (a shared MAC node)"
  - "PHP source calls `mt_rand()`, `rand()`, `uniqid()`, `shuffle()` or `str_shuffle()`"
  - "You need to reproduce a PHP random sequence offline"
tools: [php, php_mt_seed, python, uuid]
related: [prng-mt19937-state-recovery, prng-mt19937-seed-bruteforce, prng-toolkit, prng-cheatsheet]
---

## TL;DR

**UUIDv1** = 60-bit timestamp (100 ns ticks since 1582-10-15) + 14-bit clock sequence
+ 48-bit node (usually the MAC). If you can make the server mint a UUID before and
after the one you want, the target's timestamp is bracketed - the "sandwich attack" -
and the node and clock sequence are constant, so you enumerate a few million ticks at
most. **UUIDv7** leaks a millisecond timestamp in the first 48 bits. **UUIDv4** is
only as good as the RNG behind it: from `os.urandom`/`SecureRandom` it is fine, from
`Math.random` or `mt_rand` it is not.

**PHP `mt_rand()`** is MT19937 with a right shift by one (31-bit output); older
versions used a *buggy* twist (`MT_RAND_PHP`). `rand()` has been an alias of
`mt_rand()` since PHP 7.1. `php_mt_seed` brute-forces the seed from as little as one
output.

## Recognise it

- UUID version nibble: `xxxxxxxx-xxxx-Vxxx-...` where `V` is `1`, `4` or `7`.
- All UUIDs from a service share their last 12 hex digits -> v1 with a fixed node.
- Token issued at a known time and the first 8 hex digits climb monotonically -> v1
  (`time_low`) or v7.
- PHP: `mt_rand`, `rand`, `mt_srand($seed)`, `uniqid()`, `uniqid('', true)`,
  `shuffle($arr)`, `str_shuffle()`, `array_rand()`. All of these ride the same
  MT19937 state.
- `random_int()` / `random_bytes()` / `bin2hex(random_bytes(16))` -> CSPRNG, stop.

## Theory

### UUIDv1 layout

```
 time_low        time_mid  time_hi_and_version  clock_seq_hi_and_reserved+low  node
 xxxxxxxx      - xxxx     - 1xxx               - Nxxx                         - xxxxxxxxxxxx
```
- 60-bit timestamp = 100 ns intervals since 1582-10-15 00:00:00 UTC, split across
  `time_low` (32), `time_mid` (16) and the low 12 bits of `time_hi_and_version`.
- Unix epoch offset: `0x01B21DD213814000` (122192928000000000) ticks.
- `clock_seq` is 14 bits, random at process start, then constant.
- `node` is 48 bits: the MAC address, or a random value with the multicast bit set.

**Sandwich attack.** Ask the service for a UUID (t0), trigger the victim's UUID
(unknown t), ask for another (t1). The victim's timestamp is in `[t0, t1]`. With the
node and clock sequence read straight off your own UUIDs, you enumerate every tick in
the window and test each candidate. A 1-second window is $10^7$ ticks; most
implementations do not actually have 100 ns resolution, so the real space is far
smaller (Python's `uuid1` uses a 100 ns counter fed from `time.time_ns()`, so
consecutive calls differ by small increments).

### UUIDv7 layout

48-bit big-endian **millisecond** Unix timestamp, then version/variant, then 74 random
bits. The timestamp is by design readable - it is only the 74 random bits that protect
it. Same sandwich idea, but you only need the milliseconds, and then the remaining
entropy decides whether it is attackable.

### UUIDv4

122 random bits (6 are fixed by version+variant). Secure if the source is a CSPRNG:
- Python `uuid.uuid4()` -> `os.urandom(16)`. Secure.
- Java `UUID.randomUUID()` -> `SecureRandom`. Secure.
- Node `crypto.randomUUID()` -> CSPRNG. Secure.
- PHP `Uuid::uuid4()` (ramsey/uuid) -> `random_bytes` on modern versions. Secure.
- **A hand-rolled `uuid4` built from `Math.random()` or `mt_rand()` is not** - that is
  the bug to look for. Grep the source for `Math.random` near `-4` and `-[89ab]`.

### PHP mt_rand

```
php_mt_initialize(seed):    s[0] = seed; s[i] = (1812433253 * (s[i-1] ^ (s[i-1]>>30)) + i)
php_mt_reload():            the MT19937 twist
php_mt_rand():              standard MT19937 tempering, full 32 bits
mt_rand():                  php_mt_rand() >> 1        <-- 31 bits
mt_rand($min, $max):        php_mt_rand() (full 32 bits) with rejection sampling
```

Two twist variants:
- `MT_RAND_MT19937` (default since PHP 7.1, and the only sane one): the correct
  `twist(m,u,v) = m ^ (mixBits(u,v)>>1) ^ (-(v & 1) & 0x9908b0df)`.
- `MT_RAND_PHP` (the pre-7.1 behaviour, deprecated in 8.3): uses `u & 1` instead of
  `v & 1` - a genuine off-by-one bug that produces a different, biased sequence.

**Seeding.** `mt_srand($seed)` uses the 32-bit `php_mt_initialize` (i.e.
`init_genrand`), *not* Python's `init_by_array`. Without `mt_srand`, PHP seeds from
the CSPRNG at first use (since 7.1), so unseeded `mt_rand` is not seed-brute-forceable
- but its *state* is still recoverable from enough outputs.

**State recovery from `mt_rand()`.** Each output gives 31 of 32 bits, so 624 outputs
give 19344 equations for 19937 unknowns - **not enough**. You need about 644 outputs
and a GF(2) linear solve (MT19937's twist and tempering are both linear), or use
`mt_rand(0, 2**32-1)`-style calls that expose full words. In practice: use
`php_mt_seed` if the seed is brute-forceable, otherwise collect 700+ outputs.

**`uniqid()`** is not random at all: it is the current microtime formatted as
`sprintf("%08x%05x", sec, usec)`. With `more_entropy=true` it appends
`sprintf("%.8F", lcg_value() * 10)`, where `lcg_value()` is a combined
Park-Miller LCG seeded from the PID and time. Treat `uniqid` as a timestamp.

## Attack

1. Read the UUID version nibble. v4 -> check what RNG produced it; v1/v7 -> timestamps.
2. For v1: collect your own UUIDs to learn `node` and `clock_seq`, sandwich the target,
   enumerate ticks, test each candidate against the application.
3. For v7: read the millisecond timestamp; if the remaining 74 bits come from a weak
   RNG, attack that RNG instead.
4. For PHP: if `mt_srand()` is called with a timestamp/PID, run `php_mt_seed`.
   If not, collect 700+ `mt_rand()` outputs and solve for the state.
5. Remember `shuffle()`, `str_shuffle()`, `array_rand()` all advance the same MT state -
   any one of them is an oracle for the others.

## Code

```python
#!/usr/bin/env python3
"""UUIDv1/v4/v7 analysis and the sandwich attack, plus an exact PHP mt_rand
reimplementation (both twist variants) and seed brute force.

PHP outputs verified against PHP 8:
    mt_srand(12345); mt_rand() x5 -> 1996335345 1911592690 679411342 280691776 394962642
    mt_srand(12345, MT_RAND_PHP)  -> 162946439 247161732 1463094264 1878061366 394962642
    mt_srand(42); mt_rand(1,100) x2 -> 43 68
"""
from __future__ import annotations

import uuid

# ------------------------------- UUID ---------------------------------------
UUID_EPOCH_OFFSET = 0x01B21DD213814000        # 100ns ticks between 1582 and 1970


def uuid_version(u) -> int:
    return uuid.UUID(str(u)).version


def v1_fields(u):
    """Return (ticks, clock_seq, node) for a UUIDv1."""
    x = uuid.UUID(str(u))
    if x.version != 1:
        raise ValueError(f"not a UUIDv1 (version {x.version})")
    return x.time, x.clock_seq, x.node


def v1_unix_seconds(u) -> float:
    return (v1_fields(u)[0] - UUID_EPOCH_OFFSET) / 1e7


def build_uuid1(ticks: int, clock_seq: int, node: int) -> uuid.UUID:
    """Reconstruct a UUIDv1 from its three components."""
    time_low = ticks & 0xFFFFFFFF
    time_mid = (ticks >> 32) & 0xFFFF
    time_hi_version = ((ticks >> 48) & 0x0FFF) | (1 << 12)
    clock_hi = ((clock_seq >> 8) & 0x3F) | 0x80
    clock_low = clock_seq & 0xFF
    value = (time_low << 96) | (time_mid << 80) | (time_hi_version << 64) \
        | (clock_hi << 56) | (clock_low << 48) | node
    return uuid.UUID(int=value)


def sandwich_candidates(before, after, clock_seq=None, node=None, limit=5_000_000):
    """Every UUIDv1 that could have been minted between `before` and `after`."""
    t0, cs0, node0 = v1_fields(before)
    t1, _, _ = v1_fields(after)
    if t1 < t0:
        t0, t1 = t1, t0
    cs = cs0 if clock_seq is None else clock_seq
    nd = node0 if node is None else node
    span = t1 - t0
    if span > limit:
        raise ValueError(f"window of {span} ticks is too wide (limit {limit}); "
                         f"sandwich the target more tightly")
    for ticks in range(t0, t1 + 1):
        yield build_uuid1(ticks, cs, nd)


def v7_unix_ms(u) -> int:
    """UUIDv7: the first 48 bits are a big-endian millisecond timestamp."""
    x = uuid.UUID(str(u))
    if x.version != 7:
        raise ValueError(f"not a UUIDv7 (version {x.version})")
    return x.int >> 80


def build_uuid7(unix_ms: int, rand_a: int, rand_b: int) -> uuid.UUID:
    value = ((unix_ms & ((1 << 48) - 1)) << 80)
    value |= (7 << 76)
    value |= ((rand_a & 0xFFF) << 64)
    value |= (0b10 << 62)
    value |= (rand_b & ((1 << 62) - 1))
    return uuid.UUID(int=value)


def looks_like_shared_node(uuids) -> bool:
    """All v1 UUIDs from one host share the trailing 12 hex digits."""
    nodes = {v1_fields(u)[2] for u in uuids}
    return len(nodes) == 1


# ----------------------------- PHP mt_rand -----------------------------------
N = 624
M = 397
UINT32 = 0xFFFFFFFF


class PhpMtRand:
    """PHP's Mt19937. mode='mt19937' (default since 7.1) or 'php' (the buggy twist)."""

    def __init__(self, seed: int, mode: str = "mt19937"):
        if mode not in ("mt19937", "php"):
            raise ValueError("mode must be 'mt19937' or 'php'")
        self.php = mode == "php"
        self.s = [0] * N
        self.s[0] = seed & UINT32
        for i in range(1, N):
            prev = self.s[i - 1]
            self.s[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & UINT32
        self._reload()

    def _twist(self, m: int, u: int, v: int) -> int:
        mixed = (u & 0x80000000) | (v & 0x7FFFFFFF)
        bit = (u if self.php else v) & 1      # <-- the PHP < 7.1 bug is `u`
        return m ^ (mixed >> 1) ^ (0x9908B0DF if bit else 0)

    def _reload(self) -> None:
        s = self.s
        for i in range(N - M):
            s[i] = self._twist(s[i + M], s[i], s[i + 1])
        for i in range(N - M, N - 1):
            s[i] = self._twist(s[i + M - N], s[i], s[i + 1])
        s[N - 1] = self._twist(s[M - 1], s[N - 1], s[0])
        self.i = 0

    def php_mt_rand(self) -> int:
        """The full 32-bit tempered output."""
        if self.i >= N:
            self._reload()
        y = self.s[self.i]
        self.i += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y &= UINT32
        y ^= y >> 18
        return y

    def mt_rand(self) -> int:
        """mt_rand() with no arguments: 31 bits, the low bit is thrown away."""
        return self.php_mt_rand() >> 1

    def mt_rand_range(self, mn: int, mx: int) -> int:
        """mt_rand($min, $max) in PHP 7.1+: full 32 bits with rejection sampling."""
        umax = mx - mn
        r = self.php_mt_rand()
        if umax == UINT32:
            return mn + r
        umax += 1
        if umax & (umax - 1) == 0:                      # power of two
            return mn + (r & (umax - 1))
        limit = UINT32 - (UINT32 % umax) - 1
        while r > limit:
            r = self.php_mt_rand()
        return mn + (r % umax)


def brute_force_php_seed(observed, candidates, mode: str = "mt19937",
                         call=lambda g: g.mt_rand()):
    """Find the mt_srand() seed that reproduces `observed`."""
    n = len(observed)
    for s in candidates:
        g = PhpMtRand(s, mode)
        if [call(g) for _ in range(n)] == list(observed):
            return s
    return None


def php_uniqid(unix_sec: int, usec: int) -> str:
    """uniqid() is just the clock: sprintf('%08x%05x', sec, usec)."""
    return f"{unix_sec:08x}{usec:05x}"


def parse_php_uniqid(value: str) -> tuple[int, int]:
    return int(value[:8], 16), int(value[8:13], 16)


if __name__ == "__main__":
    # --- UUIDv1 fields ------------------------------------------------------
    node = 0x0242AC110002
    clock_seq = 0x1ABC
    ticks = 0x01EF5A1B2C3D4E5F & ((1 << 60) - 1)
    u = build_uuid1(ticks, clock_seq, node)
    assert u.version == 1
    assert v1_fields(u) == (ticks, clock_seq, node), v1_fields(u)
    print(f"[ok] UUIDv1 built and parsed: {u}")

    # a real Python uuid1 round-trips through the same parser
    real = uuid.uuid1()
    t, cs, nd = v1_fields(real)
    assert build_uuid1(t, cs, nd) == real
    print(f"[ok] python uuid.uuid1() decomposed and rebuilt exactly")

    # --- the sandwich attack ------------------------------------------------
    before = build_uuid1(ticks, clock_seq, node)
    victim = build_uuid1(ticks + 137, clock_seq, node)
    after = build_uuid1(ticks + 400, clock_seq, node)
    cands = list(sandwich_candidates(before, after))
    assert victim in cands, len(cands)
    assert len(cands) == 401
    print(f"[ok] sandwich attack: victim UUID found among {len(cands)} candidates")

    assert looks_like_shared_node([before, victim, after])
    print(f"[ok] shared node detected: {node:012x}")

    try:
        list(sandwich_candidates(build_uuid1(ticks, clock_seq, node),
                                 build_uuid1(ticks + 10 ** 8, clock_seq, node)))
        raise AssertionError("should have refused a 10^8-tick window")
    except ValueError:
        print("[ok] refuses a window that is too wide to enumerate")

    # --- UUIDv7 -------------------------------------------------------------
    ms = 1_735_689_600_123
    u7 = build_uuid7(ms, 0xABC, 0x0123456789ABCDE)
    assert u7.version == 7
    assert v7_unix_ms(u7) == ms, v7_unix_ms(u7)
    print(f"[ok] UUIDv7 timestamp read back: {v7_unix_ms(u7)} ms -> {u7}")

    # --- UUIDv4 is only as good as its RNG ---------------------------------
    u4 = uuid.uuid4()
    assert u4.version == 4 and (u4.int >> 62) & 0b11 == 0b10
    print(f"[ok] uuid4 has version 4 and the RFC variant bits: {u4}")

    # --- PHP mt_rand known-answer tests ------------------------------------
    g = PhpMtRand(12345)
    got = [g.mt_rand() for _ in range(5)]
    assert got == [1996335345, 1911592690, 679411342, 280691776, 394962642], got
    print(f"[ok] mt_srand(12345); mt_rand() x5 == {got}")

    gp = PhpMtRand(12345, mode="php")
    gotp = [gp.mt_rand() for _ in range(5)]
    assert gotp == [162946439, 247161732, 1463094264, 1878061366, 394962642], gotp
    print(f"[ok] MT_RAND_PHP (the buggy twist) reproduced: {gotp[:3]}...")

    gr = PhpMtRand(42)
    assert [gr.mt_rand_range(1, 100) for _ in range(2)] == [43, 68]
    print("[ok] mt_rand(1, 100) rejection sampling matches PHP 8")

    # --- seed brute force ---------------------------------------------------
    secret = 1_735_689_600
    leaked = [PhpMtRand(secret).mt_rand()]
    found = brute_force_php_seed(leaked, range(secret - 3000, secret + 3000))
    assert found == secret, found
    print(f"[ok] recovered mt_srand(time()) seed {found} from ONE mt_rand() output")

    # a bounded output leaks far less - collect several
    secret2 = secret + 999
    g2 = PhpMtRand(secret2)
    obs2 = [g2.mt_rand_range(1, 6) for _ in range(12)]
    found2 = brute_force_php_seed(obs2, range(secret - 2000, secret + 2000),
                                  call=lambda g: g.mt_rand_range(1, 6))
    assert found2 == secret2, found2
    print(f"[ok] recovered the seed from 12 dice rolls: {found2}")

    # --- uniqid is a timestamp ---------------------------------------------
    uid = php_uniqid(0x6773_1A80, 0x12345)
    assert parse_php_uniqid(uid) == (0x67731A80, 0x12345)
    assert len(uid) == 13
    print(f"[ok] uniqid() decoded as a clock value: {uid} -> {parse_php_uniqid(uid)}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Python's `uuid1` is not 100 ns-accurate.** It keeps a counter to ensure
  monotonicity, so consecutive calls differ by 1 tick, not by thousands. That makes
  the sandwich window tiny - often a handful of candidates.
- **`clock_seq` changes on process restart** (and on a detected clock rollback). If
  your candidates all fail, re-collect your bracketing UUIDs.
- **Random node.** RFC 4122 allows a random 48-bit node with the multicast bit (the
  low bit of the first octet) set. Check `node & 0x010000000000`; if it is set, the
  node is random per process, not a MAC - but still constant within the process, so
  read it from your own UUID.
- **UUIDv6** is v1 with the timestamp reordered so it sorts - same attack.
- **UUIDv7 in a loop.** Some implementations add a monotonic counter in `rand_a`,
  which makes consecutive UUIDs from one process nearly sequential.
- **`mt_rand()` loses its low bit.** 624 outputs are *not* enough for state recovery
  (19344 < 19937 bits). Use `php_mt_seed` for a brute-forceable seed, or collect ~700
  outputs and do a GF(2) solve.
- **`MT_RAND_PHP` vs `MT_RAND_MT19937`.** Old code, old PHP, or an explicit second
  argument to `mt_srand` selects the buggy twist. `php_mt_seed` has flags for both.
- **`rand()` in PHP < 7.1** is libc `rand()`, not `mt_rand()`. Version matters.
- **`shuffle`/`str_shuffle`/`array_rand`** all pull from the same MT state. A page
  that shuffles a list and also issues a token gives you a free oracle.
- **`lcg_value()`** is a *combined* LCG (two Park-Miller generators) seeded from
  `getpid()` and the clock - a different, much weaker generator that `uniqid(more)`
  exposes.
- **`random_int` / `random_bytes` are CSPRNG-backed** (libsodium/`/dev/urandom`). If
  the token uses those, stop and look elsewhere.
- **UUID as a *secret*.** Even a perfect v4 is only 122 bits - fine. The bug is
  almost always the *version*, not the entropy.

## Tools

- **php_mt_seed** - <https://www.openwall.com/php_mt_seed/> - the standard mt_rand
  seed cracker; accepts ranged observations ("the 3rd output was between 10 and 20")
  and runs on GPU.
- **`php -r '...'`** - your ground truth for any PHP RNG question.
- **`uuid` (Python stdlib)** - parsing, `.time`, `.node`, `.clock_seq`, `.version`.
- **sandwich / `uuid-sandwich` scripts** - several public PoCs implement the v1 attack.
- **Burp + a repeater loop** - to bracket the victim's UUID tightly in time.

## References

- RFC 9562, "Universally Unique IDentifiers (UUIDs)" - <https://www.rfc-editor.org/rfc/rfc9562.html>
- php_mt_seed - <https://www.openwall.com/php_mt_seed/>
- PHP `mt_rand` documentation - <https://www.php.net/manual/en/function.mt-rand.php>
- PHP `uniqid` documentation - <https://www.php.net/manual/en/function.uniqid.php>
- Python `uuid` module - <https://docs.python.org/3/library/uuid.html>
