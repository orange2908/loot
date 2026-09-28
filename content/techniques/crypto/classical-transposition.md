---
title: "Transposition Ciphers - Columnar, Rail Fence, Route, Scytale"
category: crypto
subcategory: classical
type: technique
tags: [transposition, columnar-transposition, double-transposition, rail-fence, zigzag-cipher, scytale, route-cipher, spiral-cipher, anagram, permutation-cipher, myszkowski, ioc, index-of-coincidence, ngram, dcode, cyberchef]
difficulty: easy
summary: "If the letter frequencies are perfect English but the text is unreadable, the letters were only reordered - brute force the permutation, not the alphabet."
when_to_use:
  - "IoC is ~0.066 (English) yet no substitution solver produces readable text"
  - "The ciphertext is an anagram of plausible English (same letter counts)"
  - "Length is a product of small factors, or padded with X/Z to a rectangle"
  - "Challenge mentions rails, a rod, a fence, a spiral, a grid, or a numeric key"
tools: [python, cyberchef, dcode, cryptool]
related: [classical-adfgvx-polybius, classical-substitution-hillclimb, classical-hill-cipher, cipher-identification]
---

## TL;DR

A transposition cipher permutes positions and leaves letters alone, so the unigram
statistics (and therefore the IoC) are *identical to plain English* while the text is
unreadable. That single observation identifies the whole family. Then: rail fence has
~`len-2` keys, scytale has `divisors(len)` keys, columnar with a key of length $k$ has
$k!$ keys (brute-forceable to $k \le 9$), and everything is confirmed by an n-gram
score.

## Recognise it

- **IoC ~0.066** but nothing readable. This is the tell. A substitution cipher with
  IoC 0.066 decrypts under *some* key; a transposition never will.
- Letter counts match English exactly: lots of `E`, `T`, `A`; very few `Z`, `Q`, `X`.
- Common English bigrams are *absent* (`TH`, `HE`, `IN` occur at random rates) -
  positions were shuffled, adjacency destroyed.
- Length is a nice rectangle: 100, 120, 144, or padded with a run of `X`/`Z`.
- If the text reads correctly when you take every $k$-th letter, it is a scytale /
  simple columnar with the identity key order.

## Theory

**Scytale.** Wrap the strip around a rod of circumference $k$: write the plaintext
into $k$ rows (or a grid of $k$ columns) and read out by the other axis. Equivalent to
a columnar transposition with the identity key. Keyspace = divisors of the length.

**Columnar transposition.** Write the plaintext row-wise into a grid of $k$ columns,
then read the columns out in the order given by the alphabetical rank of a keyword's
letters. `ZEBRAS` -> ranks `6 2 1 4 3 5`.
- *Complete/regular*: the grid is padded so every column is full.
- *Irregular*: no padding, so the last row is short and the columns have unequal
  lengths - **this is where implementations differ and decryptions break.** You must
  compute each column's length before filling.
- *Double columnar*: apply it twice with two keys. Historically strong; in CTFs
  the two keys are usually short.
- *Myszkowski*: repeated letters in the key share a rank and their columns are read
  off together, row by row.

**Rail fence (zigzag).** Write the text in a zigzag over $r$ rails and read rail by
rail. The cycle length is $2r - 2$. An *offset* variant starts partway down the
zigzag. Keyspace: $r \in [2, n-1]$ times $2r-2$ offsets - tiny.

**Route cipher.** Fill a grid row-wise, then read it along a route: spiral inward
clockwise, boustrophedon (snake), diagonals, columns bottom-up, etc. The "key" is the
route plus the grid dimensions.

**Why n-gram scoring works.** Any wrong permutation leaves the bigram distribution
near-random; the correct one restores `TH`, `HE`, `IN`. The score gap is enormous, so
even a weak model separates the right answer cleanly.

**Long keys: solve it as a path problem, not a hill climb.** For $k > 9$, $k!$ is
too big to enumerate, and naive swap-based hill climbing gets stuck badly on
transposition (swapping two columns changes many bigrams at once, so the landscape is
full of deceptive local maxima). The right move for a *complete* grid: the plaintext
is read row-wise, so grid columns $c$ and $c+1$ are adjacent. Score every ordered pair
of ciphertext chunks by the bigram log-probability of stacking them side by side, then
find the maximum-weight Hamiltonian path with Held-Karp DP - $O(2^k k^2)$, exact, and
instant for $k \le 14$. Beyond that, beam search or simulated annealing on the same
pairwise scores.

## Attack

1. Compute IoC. ~0.066 and unreadable -> transposition (or a transposition *on top of*
   a substitution - solve the substitution first, it will also have IoC 0.066).
2. Try **rail fence** for all $r$ in 2..20 - instant, and it is the most common CTF
   transposition.
3. Try **scytale / regular columnar with the identity key** for every divisor of the
   length.
4. Try **columnar** with $k = 2..9$, brute-forcing all $k!$ orders, both complete and
   irregular. Score with n-grams.
5. For longer keys (10-14), run the column-adjacency Held-Karp solver; beyond 14,
   beam search or anneal on the same pairwise scores.
6. Look for a **route**: fill the grid and read spiral/snake/diagonal for each factor
   pair of the length.
7. If a word of the plaintext is known, use it as an anagram anchor: find the column
   order that brings those letters adjacent.

## Code

```python
#!/usr/bin/env python3
"""Transposition ciphers: rail fence, scytale, columnar (regular + irregular),
route/spiral, plus brute-force and hill-climbing solvers. Self-testing."""
from __future__ import annotations

import math
import random
import string
from collections import Counter
from itertools import permutations

ALPHA = string.ascii_uppercase

_CORPUS = (
    "the history of the world is in many ways the history of the ordinary people "
    "who lived through it and not only of the kings and generals whose names are "
    "written in the books that children read at school in every village there were "
    "farmers who watched the weather and the price of grain women who carried water "
    "from the well before the sun was high and children who learned to count the "
    "days until the harvest they did not think of themselves as living in a period "
    "that would one day be given a name by scholars they thought about the rain the "
    "road to the market and whether there would be enough bread in the house for "
    "the winter that was coming when a traveller came to such a village he brought "
    "news from the city and the news was often wrong but it was the only news there "
    "was he would sit by the fire in the evening and tell of the great river that "
    "runs to the sea of the ships that come from the islands with salt and iron"
)


def clean(t: str) -> str:
    return "".join(c for c in t.upper() if c in ALPHA)


def _model(n: int):
    s = clean(_CORPUS)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    tot, vocab = sum(c.values()), 26 ** n
    return ({g: math.log10((v + 1) / (tot + vocab)) for g, v in c.items()},
            math.log10(1 / (tot + vocab)))


_TRI, _TRIF = _model(3)
_BI, _BIF = _model(2)


def eng_score(s: str) -> float:
    s = clean(s)
    if len(s) < 3:
        return -1e9
    return (sum(_TRI.get(s[i:i + 3], _TRIF) for i in range(len(s) - 2))
            + 0.5 * sum(_BI.get(s[i:i + 2], _BIF) for i in range(len(s) - 1)))


def ioc(text: str) -> float:
    s = clean(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


# ---------------------------- rail fence -----------------------------------
def rail_fence_encrypt(pt: str, rails: int, offset: int = 0) -> str:
    s = clean(pt)
    if rails < 2:
        return s
    rows = [[] for _ in range(rails)]
    cycle = 2 * rails - 2
    for i, ch in enumerate(s):
        p = (i + offset) % cycle
        rows[p if p < rails else cycle - p].append(ch)
    return "".join("".join(r) for r in rows)


def rail_fence_decrypt(ct: str, rails: int, offset: int = 0) -> str:
    s = clean(ct)
    if rails < 2:
        return s
    cycle = 2 * rails - 2
    pattern = []
    for i in range(len(s)):
        p = (i + offset) % cycle
        pattern.append(p if p < rails else cycle - p)
    counts = Counter(pattern)
    idx, pos = {}, 0
    for r in range(rails):
        idx[r] = pos
        pos += counts[r]
    out = []
    used = dict(idx)
    for r in pattern:
        out.append(s[used[r]])
        used[r] += 1
    return "".join(out)


def crack_rail_fence(ct: str, max_rails: int = 20, top: int = 3):
    cands = []
    for r in range(2, min(max_rails, len(clean(ct)) - 1) + 1):
        for off in range(2 * r - 2):
            pt = rail_fence_decrypt(ct, r, off)
            cands.append((eng_score(pt), r, off, pt))
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


# ------------------------------ scytale ------------------------------------
def scytale_encrypt(pt: str, circumference: int, pad: str = "X") -> str:
    """Pad to a full rectangle so the transform is exactly invertible."""
    s = clean(pt)
    if len(s) % circumference:
        s += pad * (circumference - len(s) % circumference)
    return "".join(s[i::circumference] for i in range(circumference))


def scytale_decrypt(ct: str, circumference: int) -> str:
    s = clean(ct)
    rows = math.ceil(len(s) / circumference)
    return "".join(s[i::rows] for i in range(rows))


def crack_scytale(ct: str, top: int = 3):
    n = len(clean(ct))
    cands = [(eng_score(scytale_decrypt(ct, k)), k, scytale_decrypt(ct, k))
             for k in range(2, n) if n % k == 0]
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


# -------------------------- columnar transposition -------------------------
def key_order(keyword: str) -> list[int]:
    """Read-out order: column indices sorted by their key letter (ties left-to-right).

    'ZEBRAS' -> [4, 2, 1, 3, 5, 0]  (A is column 4, B is column 2, ...)
    """
    k = clean(keyword)
    return [i for i, _ in sorted(enumerate(k), key=lambda t: (t[1], t[0]))]


def columnar_encrypt(pt: str, order, complete: bool = True, pad: str = "X") -> str:
    """order = read-out sequence of column indices (e.g. [2,0,1])."""
    s = clean(pt)
    k = len(order)
    if complete and len(s) % k:
        s += pad * (k - len(s) % k)
    cols = ["".join(s[i::k]) for i in range(k)]
    return "".join(cols[c] for c in order)


def columnar_decrypt(ct: str, order, complete: bool = True) -> str:
    s = clean(ct)
    k = len(order)
    n = len(s)
    full_rows, extra = divmod(n, k)
    # Column i holds full_rows+1 letters if i < extra (irregular grid), else full_rows.
    lengths = [full_rows + (1 if i < extra else 0) for i in range(k)]
    if complete:
        lengths = [n // k] * k
    cols: dict[int, str] = {}
    pos = 0
    for c in order:
        cols[c] = s[pos:pos + lengths[c]]
        pos += lengths[c]
    out = []
    for r in range(max(lengths)):
        for c in range(k):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def crack_columnar(ct: str, min_k: int = 2, max_k: int = 8, top: int = 3):
    """Brute force all k! column orders for k in range. k<=8 is instant-ish.

    A "complete" grid is only possible when k divides the length, so that mode is
    skipped otherwise - which also keeps every candidate the same length, so the
    (additive) n-gram scores stay comparable.
    """
    n = len(clean(ct))
    cands = []
    for k in range(min_k, max_k + 1):
        modes = (True, False) if n % k == 0 else (False,)
        for order in permutations(range(k)):
            for complete in modes:
                pt = columnar_decrypt(ct, order, complete)
                cands.append((eng_score(pt), k, order, complete, pt))
    cands.sort(key=lambda t: -t[0])
    return cands[:top]


def solve_columnar_adjacency(ct: str, k: int):
    """Exact solver for a COMPLETE grid: column ordering as a longest-path problem.

    In a complete columnar grid, plaintext is read row-wise, so grid columns c and
    c+1 are adjacent in the plaintext. Score every ordered pair of ciphertext chunks
    by the bigram log-probability of stacking them side by side, then find the
    maximum-weight Hamiltonian path with Held-Karp DP. Exact, and fast up to k ~ 14
    (O(2^k * k^2)). Naive swap-based hill climbing gets stuck here; this does not.
    """
    s = clean(ct)
    n = len(s)
    if n % k:
        raise ValueError("complete grid required: k must divide the length")
    h = n // k
    chunks = [s[i * h:(i + 1) * h] for i in range(k)]
    adj = [[0.0 if i == j else
            sum(_BI.get(chunks[i][r] + chunks[j][r], _BIF) for r in range(h))
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
    best = dp[full][last]
    perm, mask = [], full
    while last != -1:
        perm.append(last)
        prev = par[mask][last]
        mask ^= 1 << last
        last = prev
    perm.reverse()                      # perm[c] = which chunk sits at grid column c
    # The last column of a row is adjacent to the first column of the NEXT row, so
    # the adjacency graph is effectively cyclic and the path may start anywhere in
    # the cycle. Try all k rotations and keep the one that reads best overall.
    cands = []
    for shift in range(k):
        rot = perm[shift:] + perm[:shift]
        order = [rot.index(j) for j in range(k)]
        cands.append((eng_score(columnar_decrypt(ct, order)), order))
    cands.sort(key=lambda x: -x[0])
    return cands[0][1], cands[0][0]


def hill_climb_columnar(ct: str, k: int, restarts: int = 40, seed=None):
    """Fallback for k > ~14, where Held-Karp no longer fits. Random restarts plus
    pairwise swaps; needs many restarts because the swap landscape is deceptive."""
    rng = random.Random(seed)
    best = (-1e18, None)
    for _ in range(restarts):
        order = list(range(k))
        rng.shuffle(order)
        score = eng_score(columnar_decrypt(ct, order))
        improved = True
        while improved:
            improved = False
            for i in range(k):
                for j in range(i + 1, k):
                    order[i], order[j] = order[j], order[i]
                    s = eng_score(columnar_decrypt(ct, order))
                    if s > score:
                        score, improved = s, True
                    else:
                        order[i], order[j] = order[j], order[i]
        if score > best[0]:
            best = (score, list(order))
    return best[1], best[0]


# ------------------------------ route cipher -------------------------------
def to_grid(s: str, cols: int, pad: str = "X"):
    s = clean(s)
    rows = math.ceil(len(s) / cols)
    s = s.ljust(rows * cols, pad)
    return [list(s[r * cols:(r + 1) * cols]) for r in range(rows)]


def route_spiral_read(grid) -> str:
    """Read a filled grid clockwise inward, starting top-left."""
    g = [row[:] for row in grid]
    out = []
    while g:
        out += g.pop(0)
        if g and g[0]:
            for row in g:
                out.append(row.pop())
        if g:
            out += reversed(g.pop())
        if g and g[0]:
            for row in reversed(g):
                out.append(row.pop(0))
    return "".join(out)


def route_spiral_write(ct: str, cols: int) -> str:
    """Inverse: place ciphertext along the spiral, then read row-wise."""
    s = clean(ct)
    rows = math.ceil(len(s) / cols)
    grid = [[None] * cols for _ in range(rows)]
    # Replay the same spiral walk over coordinates instead of characters.
    order = []
    g = [[(r, c) for c in range(cols)] for r in range(rows)]
    while g:
        order += g.pop(0)
        if g and g[0]:
            for row in g:
                order.append(row.pop())
        if g:
            order += list(reversed(g.pop()))
        if g and g[0]:
            for row in reversed(g):
                order.append(row.pop(0))
    for ch, (r, c) in zip(s, order):
        grid[r][c] = ch
    return "".join("".join(x or "X" for x in row) for row in grid)


def route_boustrophedon_read(grid) -> str:
    """Snake: left-to-right, then right-to-left, alternating."""
    out = []
    for i, row in enumerate(grid):
        out += row if i % 2 == 0 else list(reversed(row))
    return "".join(out)


if __name__ == "__main__":
    plain = ("WEAREDISCOVEREDFLEEATONCEANDTAKETHEGOLDWITHYOUBEFORETHEGUARDS"
             "RETURNTOTHECASTLEATDAWN")

    # --- IoC is the family detector --------------------------------------
    rf = rail_fence_encrypt(plain, 4)
    assert abs(ioc(rf) - ioc(plain)) < 1e-9, "transposition must preserve IoC"
    print(f"[ok] IoC preserved by transposition: {ioc(rf):.4f}")

    # --- rail fence -------------------------------------------------------
    for r in range(2, 9):
        assert rail_fence_decrypt(rail_fence_encrypt(plain, r), r) == plain, r
    assert rail_fence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    best = crack_rail_fence(rf, max_rails=12)
    assert best[0][3] == plain, best[0][:3]
    print(f"[ok] rail fence cracked: rails={best[0][1]} offset={best[0][2]}")

    # --- scytale ----------------------------------------------------------
    sc = scytale_encrypt(plain, 5)
    assert scytale_decrypt(sc, 5).startswith(plain)
    hits = crack_scytale(sc)
    assert hits[0][2].startswith(plain), (hits[0][1], hits[0][2][:40])
    print(f"[ok] scytale cracked, best circumference={hits[0][1]}")

    # --- columnar ---------------------------------------------------------
    order = key_order("ZEBRAS")
    assert order == [4, 2, 1, 3, 5, 0], order      # A,B,E,R,S,Z column indices
    ct = columnar_encrypt(plain, order, complete=True)
    assert columnar_decrypt(ct, order, complete=True).startswith(plain[:40])
    ct_irr = columnar_encrypt(plain, order, complete=False)
    assert columnar_decrypt(ct_irr, order, complete=False) == plain
    print(f"[ok] columnar round trip, regular and irregular")

    found = crack_columnar(ct_irr, 2, 6)
    assert found[0][4] == plain, (found[0][1], found[0][2], found[0][3])
    print(f"[ok] columnar cracked: k={found[0][1]} order={found[0][2]} "
          f"complete={found[0][3]}")

    # --- exact solve of a 12-column key (12! = 479M, too many to enumerate) --
    long_order = [7, 2, 11, 0, 5, 9, 3, 1, 10, 4, 8, 6]
    body = plain + "THEENEMYISCLOSEBEHINDUSSOMOVEQUICKLYANDQUIETLYX"
    ct12 = columnar_encrypt(body * 2, long_order, complete=True)
    rec_order, sc12 = solve_columnar_adjacency(ct12, 12)
    assert rec_order == long_order, rec_order
    rec_pt = columnar_decrypt(ct12, rec_order)
    assert rec_pt.startswith("WEAREDISCOVERED"), rec_pt[:30]
    print(f"[ok] Held-Karp recovered the 12-column key exactly, score={sc12:.0f}")

    # --- route / spiral ---------------------------------------------------
    grid = to_grid(plain, 8)
    spiral = route_spiral_read(grid)
    assert route_spiral_write(spiral, 8).startswith(plain[:40])
    snake = route_boustrophedon_read(grid)
    assert len(snake) == len(spiral)
    print(f"[ok] spiral route round trip; snake route length {len(snake)}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Regular vs irregular columnar is the #1 source of wrong decryptions.** Always try
  both. The irregular form is the historically correct one; many CTF authors write the
  padded form.
- **Column length computation.** In an irregular grid, the first `n mod k` columns get
  one extra letter - *in grid order*, not in read-out order. Getting that backwards
  produces text that is right at the start and drifts.
- **Rail fence offsets.** Some implementations start on rail 0 going down; others start
  mid-zigzag. Brute force the offset, it is only `2r-2` values.
- **Double transposition.** If a single columnar brute force plateaus at a mediocre
  score, try `crack_columnar` on the output of each of the top candidates - a two-stage
  search. Keys of length 5 and 7 are common.
- **Myszkowski.** Repeated key letters share a rank; those columns are read off
  interleaved row by row. If a straight columnar with the obvious keyword fails and the
  keyword has repeated letters, this is why.
- **Transposition of words or of bytes, not letters.** Some challenges permute whole
  words, or permute bytes of a binary blob. The same brute force applies with a
  different token unit; score binary output by entropy or magic bytes instead.
- **Combined ciphers.** ADFGVX is a Polybius substitution *followed by* a columnar
  transposition; a "product cipher" of substitution + transposition has IoC 0.066 too,
  so solve the transposition first, then the substitution.
- **Padding letters leak the key length.** A tail of `XXXX` means `len % k == k - 4`.
- **Keep punctuation out of the grid.** If the original had spaces and the encoder kept
  them, the grid dimensions change; strip and re-try both ways.

## Tools

- **CyberChef**: `Rail Fence Cipher Decode`, `Columnar Transposition Cipher Decode`,
  `Rotate`, `Reverse`.
- **dcode.fr**: Transposition, Rail Fence, Scytale, Route cipher, Myszkowski, and a
  "Double Transposition" solver - most of them with automatic key search.
- **CrypTool 2** - transposition analyser with hill climbing and dictionary attacks.
- **`ngram_score.py`** from Practical Cryptography if you want a stronger score.

## References

- dcode.fr transposition cipher - <https://www.dcode.fr/transposition-cipher>
- dcode.fr rail fence cipher - <https://www.dcode.fr/rail-fence-cipher>
- Practical Cryptography, "Columnar Transposition Cipher" - <http://practicalcryptography.com/ciphers/columnar-transposition-cipher/>
- CyberChef - <https://gchq.github.io/CyberChef/>
