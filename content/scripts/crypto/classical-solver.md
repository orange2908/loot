---
title: "classical-solver.py - Auto-Detect and Solve Caesar, Affine, Vigenere, Substitution and Transposition"
category: crypto
subcategory: classical
type: script
tags: [classical-cipher, auto-solver, caesar, rot13, affine, atbash, vigenere, beaufort, substitution, hill-climbing, transposition, rail-fence, columnar, ngram, quadgram, index-of-coincidence, ioc, kasiski, cipher-identification, offline]
summary: "One self-contained Python script: measures IoC, decides the cipher family, and solves it with an embedded English n-gram model. No data files, no dependencies."
tools: [python]
related: [classical-caesar-affine, classical-vigenere, classical-substitution-hillclimb, classical-transposition, classical-ciphers-cheatsheet, cipher-identification]
---

## What it does

Reads ciphertext from a file path, `argv`, or stdin; measures the index of
coincidence and the per-period IoC table; decides between **shift/affine**,
**substitution**, **Vigenere/Beaufort** and **transposition**; runs the right solver;
prints ranked candidates with the recovered key.

The English model is a trigram+bigram table built at import time from an embedded
corpus, so the script runs anywhere with a bare Python 3.11+ and nothing else.

```sh
python3 classical_solver.py ct.txt
python3 classical_solver.py "WKH IODJ LV KHUH"
cat ct.txt | python3 classical_solver.py
python3 classical_solver.py --selftest
```

## Script

```python
#!/usr/bin/env python3
"""classical_solver.py - auto-detect and solve classical ciphers.

Families handled:
  * shift (Caesar/ROT-n), affine, Atbash
  * monoalphabetic substitution (frequency seed + systematic hill climbing)
  * Vigenere / Beaufort / Variant Beaufort (per-period IoC + chi-squared columns)
  * transposition (rail fence, scytale, columnar brute force, columnar Held-Karp)

Usage:
    python3 classical_solver.py [FILE | "CIPHERTEXT"]
    python3 classical_solver.py --selftest
"""
from __future__ import annotations

import itertools
import math
import os
import random
import string
import sys
from collections import Counter

ALPHA = string.ascii_uppercase
PAIRS = list(itertools.combinations(range(26), 2))
IOC_ENGLISH = 0.0667
IOC_RANDOM = 0.0385

ENGLISH_FREQ = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074,
]
ENGLISH_ORDER = "ETAOINSRHDLUCMFYWGPBVKXQJZ"

# ---------------------------------------------------------------------------
# Embedded English corpus. Only its letter statistics matter.
# ---------------------------------------------------------------------------
CORPUS = """
The history of the world is in many ways the history of the ordinary people who
lived through it, and not only of the kings and generals whose names are written
in the books that children read at school. In every village there were farmers who
watched the weather and the price of grain, women who carried water from the well
before the sun was high, and children who learned to count the days until the
harvest. They did not think of themselves as living in a period that would one day
be given a name by scholars. They thought about the rain, the road to the market,
and whether there would be enough bread in the house for the winter that was coming.
When a traveller came to such a village he brought news from the city, and the news
was often wrong, but it was the only news there was. He would sit by the fire in the
evening and tell of the great river that runs to the sea, of the ships that come
from the islands with salt and iron, and of the men who build walls of stone around
their houses because they are afraid of what may come out of the forest at night.
The children listened with open mouths and the old men said that in their own time
the stories had been better. This is what people have always said, and it is
probably what they will always say, because memory is a kind of story that we tell
ourselves about the years that are already gone.
A language is a strange thing to study. It is made of sounds that mean nothing at
all until a group of people agree that they mean something, and then the agreement
becomes so strong that it feels like a law of nature. A child does not learn the
rules of grammar before she learns to speak. She hears her mother and her father
and the other children in the street, and after a year or two she is able to make
sentences that no one has ever made before, and everyone understands her. No one
teaches her this. It happens in the same way that walking happens, a little at a
time, with many falls, until one day it is simply part of what she is.
Writing is different. Writing had to be invented, and it was invented more than
once, in places that were far apart and had no knowledge of each other. The first
writers were counting things: how many sheep, how many jars of oil, how much was
owed to the temple and how much had been paid. Only later did anyone think to use
these marks for a poem or a letter or a law. It took a long time before a person
could sit alone in a room and read without moving his lips, and for most of history
reading was something you did aloud, to other people, in a place where other people
could hear you and argue with you about what the words were supposed to mean.
The study of numbers begins in the same practical way. Someone has to know how much
land there is, and how to divide it between two brothers, and what happens when the
river moves and takes a part of the field away. Out of these questions came the
idea of proof, which is one of the strangest and most powerful ideas that anyone has
ever had. A proof does not tell you what is true about this field or that field. It
tells you what must be true about every field of that shape, for ever, whether or
not anyone ever measures one. Once you have seen a proof you cannot unsee it. The
thing is settled, and the whole weight of the argument rests on nothing more than
the agreement that certain simple statements are obvious and that certain ways of
moving from one statement to another are allowed.
There is a similar feeling in the study of machines. A machine is an argument made
out of metal. If you understand what each part does, and how the parts are joined,
then you can say what the machine will do before you turn it on, and you will be
right. When you are wrong it is because you have misunderstood a part, or because
the world has put something into the machine that you did not expect, such as dust,
or heat, or a person who uses it in a way that no one imagined. Most of the work of
an engineer is spent on the third kind of surprise. The first two can be found by
thinking. The third can only be found by watching what really happens over a long
period of time, in the hands of people who do not care how the thing was designed
and only want it to work.
Every one of these subjects, the history, the language, the numbers and the machines,
rests on the same habit of mind. You look at something that seems simple, you ask
why it is the way it is, and you keep asking until you reach a place where the
answer is no longer obvious to you. Then you have found the edge of what you know,
and that is the only place where anything new has ever been learned. Most people
stop before they get there, because the questions feel foolish and because there is
always something else that needs doing. The ones who do not stop are the ones whose
names end up in the books that the children read at school, which is where this
began.
"""


# ------------------------------ text utilities -----------------------------
def clean(text: str) -> str:
    return "".join(c for c in text.upper() if c in ALPHA)


def _build(corpus: str, n: int):
    s = clean(corpus)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    total, vocab = sum(c.values()), 26 ** n
    return ({g: math.log10((v + 1) / (total + vocab)) for g, v in c.items()},
            math.log10(1 / (total + vocab)))


TRI, TRI_FLOOR = _build(CORPUS, 3)
BI, BI_FLOOR = _build(CORPUS, 2)


def score(s: str) -> float:
    """Higher is more English-like. s should already be A-Z only."""
    if len(s) < 3:
        return -1e9
    return (sum(TRI.get(s[i:i + 3], TRI_FLOOR) for i in range(len(s) - 2))
            + 0.5 * sum(BI.get(s[i:i + 2], BI_FLOOR) for i in range(len(s) - 1)))


def ioc(text: str) -> float:
    s = clean(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


def chi_squared(s: str) -> float:
    n = len(s)
    if n == 0:
        return float("inf")
    c = Counter(s)
    return sum((c.get(ALPHA[i], 0) - n * ENGLISH_FREQ[i]) ** 2
               / (n * ENGLISH_FREQ[i]) for i in range(26))


def preserve_format(original: str, solved: str) -> str:
    """Re-insert the original spacing/punctuation around the solved letters."""
    out, i = [], 0
    for ch in original:
        if ch.upper() in ALPHA:
            p = solved[i]
            out.append(p if ch.isupper() else p.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------- shift -----------------------------------
def shift_decrypt(s: str, k: int) -> str:
    return "".join(ALPHA[(ord(c) - 65 - k) % 26] for c in s)


def solve_shift(s: str, top: int = 3):
    cands = [(chi_squared(shift_decrypt(s, k)), f"shift k={k}", shift_decrypt(s, k))
             for k in range(26)]
    cands.sort(key=lambda t: t[0])
    return [(-c[0], c[1], c[2]) for c in cands[:top]]


# --------------------------------- affine ----------------------------------
COPRIME26 = [a for a in range(1, 26) if math.gcd(a, 26) == 1]


def affine_decrypt(s: str, a: int, b: int) -> str:
    ai = pow(a, -1, 26)
    return "".join(ALPHA[(ai * (ord(c) - 65 - b)) % 26] for c in s)


def solve_affine(s: str, top: int = 3):
    cands = []
    for a in COPRIME26:
        for b in range(26):
            pt = affine_decrypt(s, a, b)
            cands.append((chi_squared(pt), f"affine a={a} b={b}", pt))
    cands.sort(key=lambda t: t[0])
    return [(-c[0], c[1], c[2]) for c in cands[:top]]


# ------------------------------- substitution ------------------------------
def frequency_seed(s: str) -> str:
    order = [c for c, _ in Counter(s).most_common()]
    order += [c for c in ALPHA if c not in order]
    key = ["A"] * 26
    for ct_ch, pt_ch in zip(order, ENGLISH_ORDER):
        key[ord(ct_ch) - 65] = pt_ch
    return "".join(key)


def apply_key(s: str, key: str) -> str:
    return s.translate(str.maketrans(ALPHA, key))


def _climb(letters: str, key: list[str]) -> float:
    best = score(apply_key(letters, "".join(key)))
    improved = True
    while improved:
        improved = False
        for i, j in PAIRS:
            key[i], key[j] = key[j], key[i]
            new = score(apply_key(letters, "".join(key)))
            if new > best:
                best, improved = new, True
            else:
                key[i], key[j] = key[j], key[i]
    return best


def solve_substitution(s: str, restarts: int = 8, seed=None):
    rng = random.Random(seed)
    best_key, best_score = None, -1e18
    for r in range(restarts):
        key = list(frequency_seed(s)) if r == 0 else list(ALPHA)
        if r:
            rng.shuffle(key)
        sc = _climb(s, key)
        if sc > best_score:
            best_score, best_key = sc, "".join(key)
    return [(best_score, f"substitution key={best_key}", apply_key(s, best_key))]


# --------------------------------- Vigenere --------------------------------
def columns(s: str, m: int):
    return ["".join(s[i::m]) for i in range(m)]


def avg_col_ioc(s: str, m: int) -> float:
    vals = [ioc(c) for c in columns(s, m) if len(c) > 1]
    return sum(vals) / len(vals) if vals else 0.0


def keylen_table(s: str, max_len: int = 30):
    return [(m, avg_col_ioc(s, m)) for m in range(1, min(max_len, len(s) // 3) + 1)]


def guess_keylen(s: str, max_len: int = 30, threshold: float = 0.058) -> int:
    table = keylen_table(s, max_len)
    spikes = [m for m, v in table if v >= threshold]
    return min(spikes) if spikes else max(table, key=lambda t: t[1])[0]


def best_shift(col: str) -> int:
    return min(range(26), key=lambda k: chi_squared(shift_decrypt(col, k)))


def solve_vigenere(s: str, max_len: int = 30, top: int = 3):
    """Try EVERY key length and score the result.

    The per-period IoC table is a good hint but it is noisy on short texts - a
    divisor of the true length can spike by accident. Solving all of them and
    ranking by n-gram score is cheap (3 * max_len decryptions) and does not get
    fooled; longer keys do not win by overfitting because each extra column has
    fewer letters and its chi-squared shift gets noisier.
    """
    out = []
    upper = max(1, min(max_len, len(s) // 8))
    for m in range(1, upper + 1):
        key = "".join(ALPHA[best_shift(c)] for c in columns(s, m))
        variants = (
            ("vigenere", [ALPHA[(ord(c) - 65 - (ord(key[i % m]) - 65)) % 26]
                          for i, c in enumerate(s)]),
            ("beaufort", [ALPHA[((ord(key[i % m]) - 65) - (ord(c) - 65)) % 26]
                          for i, c in enumerate(s)]),
            ("variant", [ALPHA[(ord(c) - 65 + (ord(key[i % m]) - 65)) % 26]
                         for i, c in enumerate(s)]),
        )
        for label, chars in variants:
            pt = "".join(chars)
            out.append((score(pt), f"{label} m={m} key={key}", pt))
    out.sort(key=lambda t: -t[0])
    return out[:top]


# ------------------------------ transposition ------------------------------
def rail_fence_decrypt(s: str, rails: int, offset: int = 0) -> str:
    if rails < 2:
        return s
    cyc = 2 * rails - 2
    pat = [(lambda p: p if p < rails else cyc - p)((i + offset) % cyc)
           for i in range(len(s))]
    counts = Counter(pat)
    pos, run = {}, 0
    for r in range(rails):
        pos[r] = run
        run += counts[r]
    out = []
    for r in pat:
        out.append(s[pos[r]])
        pos[r] += 1
    return "".join(out)


def columnar_decrypt(s: str, order, complete: bool = True) -> str:
    k, n = len(order), len(s)
    full, extra = divmod(n, k)
    lengths = [full] * k if complete else \
        [full + (1 if i < extra else 0) for i in range(k)]
    cols, at = {}, 0
    for c in order:
        cols[c] = s[at:at + lengths[c]]
        at += lengths[c]
    out = []
    for r in range(max(lengths)):
        for c in range(k):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def solve_columnar_adjacency(s: str, k: int):
    """Exact column ordering for a complete grid via Held-Karp on bigram affinity."""
    n = len(s)
    if n % k:
        return None
    h = n // k
    chunks = [s[i * h:(i + 1) * h] for i in range(k)]
    adj = [[0.0 if i == j else
            sum(BI.get(chunks[i][r] + chunks[j][r], BI_FLOOR) for r in range(h))
            for j in range(k)] for i in range(k)]
    NEG = float("-inf")
    dp = [[NEG] * k for _ in range(1 << k)]
    par = [[-1] * k for _ in range(1 << k)]
    for i in range(k):
        dp[1 << i][i] = 0.0
    for mask in range(1 << k):
        for last in range(k):
            if dp[mask][last] == NEG:
                continue
            for nxt in range(k):
                if mask >> nxt & 1:
                    continue
                nm = mask | (1 << nxt)
                v = dp[mask][last] + adj[last][nxt]
                if v > dp[nm][nxt]:
                    dp[nm][nxt] = v
                    par[nm][nxt] = last
    full = (1 << k) - 1
    last = max(range(k), key=lambda i: dp[full][i])
    perm, mask = [], full
    while last != -1:
        perm.append(last)
        prev = par[mask][last]
        mask ^= 1 << last
        last = prev
    perm.reverse()
    best = (-1e18, None)
    for shift in range(k):
        rot = perm[shift:] + perm[:shift]
        order = [rot.index(j) for j in range(k)]
        sc = score(columnar_decrypt(s, order))
        if sc > best[0]:
            best = (sc, order)
    return best[1]


def solve_transposition(s: str, top: int = 3):
    cands = []
    for r in range(2, min(20, len(s) - 1) + 1):
        for off in range(2 * r - 2):
            pt = rail_fence_decrypt(s, r, off)
            cands.append((score(pt), f"railfence rails={r} offset={off}", pt))
    n = len(s)
    for k in range(2, 9):
        if n % k:
            continue
        for order in itertools.permutations(range(k)):
            pt = columnar_decrypt(s, order, True)
            cands.append((score(pt), f"columnar k={k} order={order}", pt))
    for k in range(9, 15):
        if n % k:
            continue
        order = solve_columnar_adjacency(s, k)
        if order:
            pt = columnar_decrypt(s, order)
            cands.append((score(pt), f"columnar-heldkarp k={k} order={order}", pt))
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


# --------------------------------- driver ----------------------------------
# Simpler families win a near-tie: a Caesar that scores the same as a 26-letter
# substitution key IS the answer.
FAMILY_RANK = {
    "shift": 0, "affine": 1,
    "vigenere": 2, "beaufort": 2, "variant": 2,
    "railfence": 3, "columnar": 3, "columnar-heldkarp": 3,
    "substitution": 4,
}


def analyse(text: str) -> dict:
    s = clean(text)
    table = keylen_table(s)
    return {
        "length": len(s),
        "distinct": len(set(s)),
        "ioc": ioc(s),
        "keylen_table": table,
        "keylen_guess": guess_keylen(s) if s else 0,
    }


def solve(text: str, top: int = 3):
    """Return (diagnostics, [(score, description, plaintext)]) best-first."""
    s = clean(text)
    if len(s) < 8:
        raise ValueError("need at least 8 letters")
    diag = analyse(text)
    results = []
    v = diag["ioc"]

    # Shift and affine are cheap; always try them.
    results += solve_shift(s, top)
    results += solve_affine(s, top)

    if v >= 0.058:
        # Monoalphabetic OR transposition: both preserve the IoC.
        results += solve_substitution(s)
        results += solve_transposition(s, top)
    else:
        results += solve_vigenere(s, top=top)
        if diag["keylen_guess"] == 1:
            results += solve_substitution(s)

    # Re-score every candidate on the same scale, de-duplicate, then rank.
    ranked = sorted(((score(clean(pt)), label, pt) for _, label, pt in results),
                    key=lambda t: -t[0])
    seen, unique = set(), []
    for sc, label, pt in ranked:
        if pt in seen:
            continue
        seen.add(pt)
        unique.append((sc, label, pt))
    if unique:
        # Occam tie-break. A 26-letter hill climb can beat the TRUE plaintext by a
        # fraction of a percent by swapping two rare letters, so when several
        # families land within 0.5% of the best score, prefer the simplest one.
        best = unique[0][0]
        tol = 0.005 * abs(best)
        unique.sort(key=lambda t: (0 if t[0] >= best - tol else 1,
                                   FAMILY_RANK.get(t[1].split()[0], 9),
                                   -t[0]))
    return diag, unique[:top]


def main(argv) -> int:
    if "--selftest" in argv:
        return selftest()
    if len(argv) > 1:
        arg = argv[1]
        text = open(arg).read() if os.path.exists(arg) else arg
    else:
        text = "" if sys.stdin.isatty() else sys.stdin.read()
    if not clean(text):
        # Run bare with no input: behave as a self-test rather than doing nothing.
        print("no ciphertext supplied - running --selftest", file=sys.stderr)
        return selftest()
    diag, results = solve(text, top=5)
    print(f"letters={diag['length']}  distinct={diag['distinct']}  "
          f"IoC={diag['ioc']:.4f}  (English {IOC_ENGLISH}, random {IOC_RANDOM})")
    print(f"per-period IoC: "
          f"{[(m, round(x, 3)) for m, x in diag['keylen_table'][:12]]}")
    print(f"key-length guess: {diag['keylen_guess']}")
    print()
    for i, (sc, label, pt) in enumerate(results, 1):
        print(f"[{i}] {sc:10.1f}  {label}")
        print(f"      {preserve_format(text, pt)[:200]}")
    return 0


def selftest() -> int:
    plain = ("THE ART OF WAR TEACHES US TO RELY NOT ON THE LIKELIHOOD OF THE ENEMY "
             "NOT COMING BUT ON OUR OWN READINESS TO RECEIVE HIM NOT ON THE CHANCE "
             "OF HIS NOT ATTACKING BUT RATHER ON THE FACT THAT WE HAVE MADE OUR "
             "POSITION UNASSAILABLE AND SO IT IS THAT IN WAR THE VICTORIOUS "
             "STRATEGIST ONLY SEEKS BATTLE AFTER THE VICTORY HAS BEEN WON")
    p = clean(plain)
    ok = 0

    # --- shift -------------------------------------------------------------
    ct = "".join(ALPHA[(ord(c) - 65 + 7) % 26] for c in p)
    _, res = solve(ct)
    assert res[0][2] == p, res[0][1]
    assert "shift k=7" in res[0][1] or "affine a=1 b=7" in res[0][1], res[0][1]
    print(f"[ok] shift solved: {res[0][1]}")
    ok += 1

    # --- affine ------------------------------------------------------------
    ct = "".join(ALPHA[(5 * (ord(c) - 65) + 8) % 26] for c in p)
    _, res = solve(ct)
    assert res[0][2] == p, res[0][1]
    print(f"[ok] affine solved: {res[0][1]}")
    ok += 1

    # --- Atbash (affine a=25 b=25) ----------------------------------------
    ct = "".join(ALPHA[25 - (ord(c) - 65)] for c in p)
    _, res = solve(ct)
    assert res[0][2] == p, res[0][1]
    print(f"[ok] atbash solved: {res[0][1]}")
    ok += 1

    # --- Vigenere ----------------------------------------------------------
    key = "CRYPTOGRAM"
    ct = "".join(ALPHA[(ord(c) - 65 + ord(key[i % len(key)]) - 65) % 26]
                 for i, c in enumerate(p))
    diag, res = solve(ct)
    assert res[0][2] == p, (diag["keylen_guess"], res[0][1])
    assert f"key={key}" in res[0][1], res[0][1]
    print(f"[ok] vigenere solved: {res[0][1]}")
    ok += 1

    # --- substitution ------------------------------------------------------
    rng = random.Random(1337)
    enc = list(ALPHA)
    rng.shuffle(enc)
    ct = p.translate(str.maketrans(ALPHA, "".join(enc)))
    _, res = solve(ct)
    acc = sum(a == b for a, b in zip(res[0][2], p)) / len(p)
    assert acc >= 0.95, (acc, res[0][1])
    print(f"[ok] substitution solved to {acc*100:.1f}% accuracy")
    ok += 1

    # --- rail fence --------------------------------------------------------
    def rf_encrypt(s, rails):
        cyc = 2 * rails - 2
        rows = [[] for _ in range(rails)]
        for i, ch in enumerate(s):
            q = i % cyc
            rows[q if q < rails else cyc - q].append(ch)
        return "".join("".join(r) for r in rows)

    ct = rf_encrypt(p, 5)
    _, res = solve(ct)
    assert res[0][2] == p, res[0][1]
    print(f"[ok] rail fence solved: {res[0][1]}")
    ok += 1

    # --- columnar ----------------------------------------------------------
    order = [4, 2, 1, 3, 5, 0]                    # keyword ZEBRAS
    body = p[:len(p) - len(p) % 6]
    k = len(order)
    cols = ["".join(body[i::k]) for i in range(k)]
    ct = "".join(cols[c] for c in order)
    _, res = solve(ct)
    assert res[0][2] == body, res[0][1]
    print(f"[ok] columnar solved: {res[0][1]}")
    ok += 1

    # --- diagnostics -------------------------------------------------------
    assert abs(ioc(p) - IOC_ENGLISH) < 0.02, ioc(p)
    assert guess_keylen(p) == 1
    print(f"[ok] diagnostics: IoC(plain)={ioc(p):.4f}, key length guess 1")
    ok += 1

    print(f"all {ok} self-tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

## Notes

- **Ranking is uniform.** Every family's candidates are re-scored with the same
  trigram+bigram model before ranking, so a shift candidate and a transposition
  candidate are directly comparable.
- **IoC >= 0.058** routes to monoalphabetic *and* transposition, because both
  preserve letter frequencies. Below that it routes to Vigenere/Beaufort.
- **Substitution accuracy** is typically 95-100% on 200+ letters. Expect one or two
  rare letters (`J`, `Q`, `X`, `Z`) to be wrong - fix them by eye.
- **Transposition** covers rail fence (all rails and offsets), complete columnar up
  to `k = 8` by brute force, and `k = 9..14` by a Held-Karp column-adjacency solve.
  Irregular columnar grids are not searched - use `classical-transposition` for those.
- **Not covered here**: Playfair/Bifid/Hill/ADFGVX (see the dedicated techniques),
  and any non-English plaintext (swap `CORPUS`).
- **Speed**: substitution hill climbing is the slow part, ~2 s for 8 restarts on 300
  letters. Raise `restarts` if the result reads badly.
- To use a proper quadgram table instead, replace `_build(CORPUS, 3)` with a loader
  for `english_quadgrams.txt` and change `score` to sum 4-grams.
