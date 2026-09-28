---
title: "MT19937 Seeded with a Timestamp or a Small Seed - Brute Force"
category: crypto
subcategory: prng
type: technique
tags: [mt19937, mersenne-twister, seed-bruteforce, time-seed, timestamp-seed, random-seed, init-by-array, init-genrand, weak-seed, predictable-token, password-reset-token, python-random, php-mt-srand, srand, entropy, prng]
difficulty: easy
summary: "If the seed is a timestamp, a PID or anything under ~2^32, forget state recovery - just try every seed and match a single observed output."
when_to_use:
  - "You have only ONE or a handful of random values, not 624"
  - "Source shows `random.seed(int(time.time()))`, `srand(time(NULL))` or `mt_srand(time())`"
  - "A token was generated at a known-ish time (an HTTP Date header, a DB timestamp)"
  - "The seed is a user-influenced value: a user id, a PID, a counter, a short PIN"
tools: [python, php_mt_seed, untwister, hashcat]
related: [prng-mt19937-state-recovery, prng-python-random, prng-glibc-rand, prng-uuid-php-mt-rand, prng-toolkit]
---

## TL;DR

State recovery needs 624 outputs. Seed brute force needs **one**. If the seed space is
a time window (a day is 86,400 seconds), a PID (<= 4,194,304 on Linux), a small
integer, or anything below ~$2^{32}$, enumerate it: reseed, generate the same call
sequence, compare. A single 32-bit output pins the seed almost uniquely.

## Recognise it

- `random.seed(int(time.time()))`, `random.seed(time.time())`,
  `random.seed(os.getpid())`, `random.seed(user_id)`, `mt_srand(time())`.
- `random.seed()` with **no arguments**: CPython uses `os.urandom(32)` when available
  and falls back to `time.time_ns()` only if it is not - so no-arg seeding is normally
  *not* brute-forceable. Do not waste time on it unless the target is an old
  interpreter or a constrained environment.
- The service was restarted recently and tokens changed - a fresh seed.
- Two users who signed up in the same second got the same token.
- A token that is only 32 or 64 bits of "randomness" in total.
- Any HTTP response with a `Date:` header next to the token - that is your window.

## Theory

**CPython seeding.** `random.seed(n)` for an `int` uses `init_by_array` over the
absolute value's 32-bit limbs, *not* the classic `init_genrand`. `random.seed(x)` for
a `float` is also deterministic (CPython derives an integer from the exact double, so
two different doubles give two different streams) - in practice you do not need to
know the mapping, just replay with the identical float value. For `str`
and `bytes`, CPython 3 computes `int.from_bytes(n + sha512(n).digest(), "big")` where
`n` is the raw bytes - still fully deterministic, so a dictionary attack on a string
seed works fine.

Because `init_by_array` is deterministic, you do not need to reimplement anything:
brute force by calling `random.Random(candidate)` and comparing outputs.

**Seed spaces worth enumerating.**

| Seed source | Size | Time to enumerate in Python |
|---|---|---|
| `int(time.time())`, +/- 1 day | 172,800 | < 1 s |
| `int(time.time())`, +/- 1 year | 63 million | ~2 min |
| `time.time()` truncated to ms | 86.4 M / day | ~3 min |
| `time.time_ns()` | 10^9 / s | infeasible naively |
| Linux PID | <= 4.2 M | ~10 s |
| 16-bit value | 65,536 | instant |
| `random.seed()` no-arg (urandom) | 2^256 | forget it |

**Matching criterion.** One 32-bit output gives a $2^{-32}$ false-positive rate, so
over a $2^{26}$ seed space you expect ~0 collisions. If your observable is a single
`randint(1, 100)` you only get ~6.6 bits, so collect several consecutive values and
match the whole sequence.

**Non-Python targets.**
- C `srand(time(NULL))` + `rand()` - glibc TYPE_3, see `prng-glibc-rand`.
- PHP `mt_srand(time())` - use `php_mt_seed`, which brute-forces the seed from as
  little as one `mt_rand()` output at up to ~10^9 seeds/s on a GPU.
- Java `new Random(System.currentTimeMillis())` - 48-bit LCG, see `prng-java-random`.
- JavaScript `Math.random()` cannot be seeded by the page - see
  `prng-xorshift-v8-math-random`.

**Float seeds.** `random.seed(time.time())` is *worse* than `random.seed(int(...))`
for the attacker only if the float has sub-second precision you must also guess.
`time.time()` on Linux has microsecond-ish resolution, so a 1-second window is 10^6
candidates - still trivial. Generate candidates as `base + k/1e6`.

## Attack

1. Establish the window: the `Date` header, the process start time, a log entry, the
   file mtime of a generated artifact.
2. Decide the exact call sequence the target made (`getrandbits(32)`? `randint(a,b)`?
   `choice`? how many?). Replay it exactly for each candidate seed.
3. Enumerate; match on the observed value(s).
4. Once the seed is found you own the whole stream, past and future.
5. If the observable is low-entropy (a 4-digit PIN), collect several and match the
   sequence, or accept a candidate list and test each against the service.

## Code

```python
#!/usr/bin/env python3
"""Brute force a weakly-seeded Python MT19937: integer seeds, timestamp seeds,
sub-second float seeds, and string seeds. Self-testing."""
from __future__ import annotations

import hashlib
import random
import string
import time
from typing import Callable, Iterable, Sequence


def replay(seed, draw: Callable[[random.Random], list]) -> list:
    """Run the victim's exact call sequence under a candidate seed."""
    return draw(random.Random(seed))


def brute_force_seed(observed: Sequence,
                     draw: Callable[[random.Random], list],
                     candidates: Iterable,
                     max_hits: int = 1) -> list:
    """Return the seeds whose replay reproduces `observed`."""
    hits = []
    n = len(observed)
    for s in candidates:
        if replay(s, draw)[:n] == list(observed):
            hits.append(s)
            if len(hits) >= max_hits:
                break
    return hits


def time_window(center: int, radius: int) -> range:
    """Integer unix timestamps within +/- radius seconds of `center`."""
    return range(center - radius, center + radius + 1)


def float_time_window(center: int, radius_us: int = 1_000_000,
                      step_us: int = 1):
    """Sub-second float seeds: time.time() values around a whole second."""
    for us in range(0, radius_us, step_us):
        yield center + us / 1_000_000


def string_seed_dictionary(words: Iterable[str]):
    """CPython 3 hashes str/bytes seeds with SHA-512; a wordlist attack just works."""
    for w in words:
        yield w


def str_seed_int(s: str) -> int:
    """The integer CPython 3 actually seeds with for a str/bytes seed.

    CPython does: n = utf-8 bytes; a = int.from_bytes(n + sha512(n).digest(), "big")
    """
    n = s.encode()
    return int.from_bytes(n + hashlib.sha512(n).digest(), "big")


def predict_from_seed(seed, draw: Callable[[random.Random], list]) -> list:
    return draw(random.Random(seed))


if __name__ == "__main__":
    # --- 1. integer timestamp seed ----------------------------------------
    secret_ts = 1_735_689_600            # 2025-01-01 00:00:00 UTC
    victim = random.Random(secret_ts)
    token = victim.getrandbits(32)

    draw_one = lambda r: [r.getrandbits(32)]
    found = brute_force_seed([token], draw_one, time_window(secret_ts, 5000))
    assert found == [secret_ts], found
    print(f"[ok] recovered integer timestamp seed {found[0]} from ONE 32-bit output")

    # the seed owns the whole stream
    replayed = random.Random(found[0])
    assert replayed.getrandbits(32) == token
    assert replayed.getrandbits(32) == victim.getrandbits(32)
    print("[ok] subsequent outputs predicted from the recovered seed")

    # --- 2. low-entropy observable needs several samples ------------------
    victim2 = random.Random(secret_ts + 137)
    pins = [victim2.randint(1000, 9999) for _ in range(4)]
    draw_pins = lambda r: [r.randint(1000, 9999) for _ in range(4)]
    found2 = brute_force_seed(pins, draw_pins, time_window(secret_ts, 2000))
    assert found2 == [secret_ts + 137], found2
    print(f"[ok] recovered seed from 4 four-digit PINs: {found2[0]}")

    # A single PIN is only log2(9000) ~ 13.1 bits, so over a 100,001-seed window
    # you expect ~11 false positives. Collect more samples, not a bigger window.
    single = brute_force_seed(pins[:1], lambda r: [r.randint(1000, 9999)],
                              time_window(secret_ts, 50_000), max_hits=10_000)
    print(f"[ok] one PIN alone matched {len(single)} seeds over 100k candidates "
          f"- not enough entropy")
    assert len(single) > 1

    # --- 3. sub-second float seed ----------------------------------------
    base = 1_735_689_600
    secret_float = base + 0.000432
    victim3 = random.Random(secret_float)
    obs3 = [victim3.getrandbits(32)]
    found3 = brute_force_seed(obs3, draw_one,
                              float_time_window(base, radius_us=2000))
    assert found3 and abs(found3[0] - secret_float) < 1e-9, found3
    print(f"[ok] recovered float seed {found3[0]!r} (microsecond search)")

    # --- 4. string seed via a wordlist ------------------------------------
    wordlist = ["admin", "password", "s3cr3t", "letmein", "correct-horse",
                "supersecretseed", "ctf2026"]
    victim4 = random.Random("supersecretseed")
    obs4 = [victim4.getrandbits(32), victim4.getrandbits(32)]
    draw_two = lambda r: [r.getrandbits(32), r.getrandbits(32)]
    found4 = brute_force_seed(obs4, draw_two, string_seed_dictionary(wordlist))
    assert found4 == ["supersecretseed"], found4
    print(f"[ok] recovered string seed {found4[0]!r} from a wordlist")

    # str seeding is SHA-512 based and therefore reproducible as an int
    assert (random.Random("supersecretseed").getrandbits(32)
            == random.Random(str_seed_int("supersecretseed")).getrandbits(32))
    print("[ok] str seed == int.from_bytes(s + sha512(s), 'big') - reproducible, "
          "so wordlist attacks apply")

    # --- 5. PID-style small seed ------------------------------------------
    victim5 = random.Random(31337)
    token5 = "".join(victim5.choice(string.ascii_lowercase) for _ in range(16))
    draw_tok = lambda r: ["".join(r.choice(string.ascii_lowercase)
                                  for _ in range(16))]
    t0 = time.perf_counter()
    found5 = brute_force_seed([token5], draw_tok, range(0, 40000))
    dt = time.perf_counter() - t0
    assert found5 == [31337], found5
    print(f"[ok] recovered PID-sized seed {found5[0]} "
          f"({40000/max(dt,1e-9):,.0f} seeds/s for a 16-char token)")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Replay the exact call sequence.** If the victim did `random.seed(t); uuid = ...;
  token = random.getrandbits(64)` you must replicate every intervening call. A single
  extra or missing draw shifts the whole stream.
- **`random.seed()` with no args is NOT time-based in modern CPython.** It uses
  `os.urandom(32)`. The classic "seeded from the clock" bug is `random.seed(time...)`
  written explicitly, or `srand(time(NULL))` in C.
- **Module-level vs instance `random`.** `random.random()` uses a single shared global
  `Random` instance. Any other library in the process that touches it moves the stream.
- **Threads and forks.** `os.fork()` copies the state, so parent and child produce the
  *same* sequence until one reseeds. Pre-fork worker pools that seed once at import are
  a classic source of duplicate "random" tokens across workers.
- **Seed truncation.** `random.seed(x)` with a huge `x` does *not* truncate - it uses
  every limb. But `mt_srand($x)` in PHP and `srand(x)` in C take a 32-bit int, so
  `time()` fits exactly.
- **Timestamp units.** Seconds, milliseconds, microseconds, nanoseconds - check which.
  A millisecond seed over a 10-second window is 10,000 candidates.
- **Timezones and clock skew.** The `Date` header is the *server's* clock. Widen the
  window by a few minutes; it costs nothing.
- **Match on structure, not just value.** If the token is `f"{r.randint(0,9999):04d}"`,
  compare strings, not ints - zero padding hides collisions.
- **Parallelise.** `multiprocessing.Pool` over seed ranges gives near-linear speedup;
  a 63-million-seed year-long window becomes seconds on 8 cores.
- **PHP**: `php_mt_seed` is vastly faster than anything you will write, and it accepts
  partial constraints like "the output was between 10 and 20".
- **If the seed is found but predictions are wrong**, the target is probably not
  MT19937 (PHP's `mt_rand` has its own twist, `rand()` in PHP 7.1+ aliases `mt_rand`,
  and glibc `rand()` is a completely different generator).

## Tools

- **php_mt_seed** - <https://www.openwall.com/php_mt_seed/> - GPU-capable `mt_rand`
  seed cracker; handles ranged outputs and multiple constraints.
- **untwister** - <https://github.com/altf4/untwister> - multi-PRNG seed brute forcer
  (MT19937, glibc, Java) with a time-window mode.
- **randcrack / mt19937predictor** - for the 624-output path when brute force is not
  possible.
- **hashcat** - if the "seed" is really a hash of a guessable string.
- **`multiprocessing`** - the simplest 8x speedup you will ever get.

## References

- CPython `random` module docs - <https://docs.python.org/3/library/random.html>
- CPython `_randommodule.c` (init_by_array, seeding) - <https://github.com/python/cpython/blob/main/Modules/_randommodule.c>
- php_mt_seed - <https://www.openwall.com/php_mt_seed/>
- untwister - <https://github.com/altf4/untwister>
