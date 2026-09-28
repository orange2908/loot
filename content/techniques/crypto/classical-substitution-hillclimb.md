---
title: "Monoalphabetic Substitution - Frequency Analysis + Hill Climbing"
category: crypto
subcategory: classical
type: technique
tags: [substitution-cipher, monoalphabetic, simple-substitution, frequency-analysis, hill-climbing, quadgram, ngram, trigram, quipqiup, aristocrat, patristocrat, keyword-cipher, cryptogram, simulated-annealing, index-of-coincidence, dcode]
difficulty: easy
summary: "26! keys but only 26 unknowns: seed the key from letter frequencies, then hill-climb on an English n-gram score until it stops improving."
when_to_use:
  - "Ciphertext is A-Z only, IoC ~= 0.066 (monoalphabetic) but no Caesar/affine shift works"
  - "Letter frequency histogram is English-shaped but scrambled, not rotated"
  - "Repeated short ciphertext words (THE, AND) appear at the expected rate"
  - "Challenge mentions 'cryptogram', 'aristocrat', 'patristocrat', or a keyword alphabet"
tools: [python, quipqiup, cyberchef, dcode]
related: [classical-caesar-affine, classical-vigenere, classical-solver, cipher-identification]
---

## TL;DR

A simple substitution key is one of $26! \approx 4 \times 10^{26}$ permutations, so you
cannot enumerate it - but you can *climb* to it. Score a candidate decryption with an
English n-gram log-probability, start from a frequency-matched key, and repeatedly
swap pairs of letters, keeping every swap that raises the score. Restart from random
keys a dozen times to escape local maxima. ~250 letters of ciphertext is plenty;
~100 letters usually works; below ~60 it becomes ambiguous.

## Recognise it

- **IoC ~= 0.066** (English) - the cipher preserves the letter-frequency *shape*.
- Unigram histogram is English-shaped but the peaks are on arbitrary letters.
- Doubled letters appear at English's rate (`LL`, `SS`, `EE`, `OO` patterns survive).
- Word lengths and spacing intact = "aristocrat"; stripped and grouped in 5s =
  "patristocrat". Aristocrats fall to word-pattern solvers instantly.
- A single one-letter word maps to `A` or `I`. A three-letter word appearing far more
  than any other is almost certainly `THE`.
- If the plaintext alphabet in the source is built from a keyword
  (`KEYWORDABCFGHIJ...`), the recovered key will show an alphabetical tail - that
  tail gives you the keyword, which is often the flag.

## Theory

**Why frequency analysis alone is not enough.** Unigram matching gets `E`, `T`, `A`
roughly right but the middle of the distribution (`D`,`L`,`U`,`C`,`M`,`F`) is flat and
noisy. You need *context*: n-grams.

**N-gram scoring.** Given an n-gram model $P$ trained on English, score text
$s = s_1 s_2 \ldots s_L$ as

$$S(s) = \sum_{i=1}^{L-n+1} \log_{10} P(s_i \ldots s_{i+n-1})$$

Quadgrams (n=4) are the classic choice (Practical Cryptography's
`english_quadgrams.txt`, 4^26 entries, ~5 MB). Offline and without that file, a
trigram+bigram model built from a few kilobytes of embedded English gets you 95%+ of
the way there, which is what the code below does.

**Smoothing matters.** An unseen n-gram must get a finite, bad score, not
$-\infty$. Add-one (Laplace) smoothing over a $26^n$ vocabulary is fine.

**Hill climbing.** The score surface over key-space is rugged but has a very strong
basin around the true key. The standard move set is *transpositions*: swap the
plaintext letters assigned to two ciphertext letters. Sweeping all
$\binom{26}{2} = 325$ pairs in order and accepting any improvement converges in a few
passes and is more reliable than random single swaps. Multiple random restarts fix
local maxima.

**Simulated annealing** (accept a worsening swap with probability
$e^{\Delta S / T}$, cooling $T$) is the usual upgrade when restarts are not enough -
it is what breaks short patristocrats.

## Attack

1. Normalise: uppercase, strip to `A-Z`, keep the original string for pretty output.
2. Compute IoC. If it is not ~0.066, stop - this is polyalphabetic or transposition.
3. If word boundaries survive, try a **word-pattern** attack first (quipqiup, or match
   each ciphertext word against a dictionary by its letter-repetition pattern). It is
   near-instant and gives an exact answer.
4. Otherwise: frequency-seed the key, hill-climb with an n-gram score, 10-20 restarts.
5. Read the output. It will have 1-3 wrong letters (usually rare ones: `J`, `Q`, `X`,
   `Z`); fix those by eye.
6. Check whether the recovered key is a keyword alphabet - if so, extract the keyword.

## Code

```python
#!/usr/bin/env python3
"""Monoalphabetic substitution solver: frequency seed + systematic hill climbing.

The English n-gram model is built at import time from an embedded corpus, so this
file needs no external data files. Run directly for a self-test.
"""
from __future__ import annotations

import itertools
import math
import random
import string
from collections import Counter

ALPHA = string.ascii_uppercase
PAIRS = list(itertools.combinations(range(26), 2))

# ---------------------------------------------------------------------------
# Embedded English corpus. Generic prose; only its letter statistics matter.
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

ENGLISH_ORDER = "ETAOINSRHDLUCMFYWGPBVKXQJZ"


def only_letters(text: str) -> str:
    return "".join(ch for ch in text.upper() if ch in ALPHA)


def _build_ngram_model(corpus: str, n: int):
    letters = only_letters(corpus)
    counts = Counter(letters[i:i + n] for i in range(len(letters) - n + 1))
    total = sum(counts.values())
    vocab = 26 ** n
    logs = {g: math.log10((c + 1) / (total + vocab)) for g, c in counts.items()}
    floor = math.log10(1 / (total + vocab))
    return logs, floor


TRI_LOGS, TRI_FLOOR = _build_ngram_model(CORPUS, 3)
BI_LOGS, BI_FLOOR = _build_ngram_model(CORPUS, 2)


def ngram_score(s: str) -> float:
    """Higher = more English-like. s must already be uppercase A-Z only."""
    if len(s) < 3:
        return -1e9
    tri = sum(TRI_LOGS.get(s[i:i + 3], TRI_FLOOR) for i in range(len(s) - 2))
    bi = sum(BI_LOGS.get(s[i:i + 2], BI_FLOOR) for i in range(len(s) - 1))
    return tri + 0.5 * bi


def index_of_coincidence(text: str) -> float:
    s = only_letters(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


def frequency_seed(ct: str) -> str:
    """Initial key: most frequent ciphertext letter -> E, next -> T, ..."""
    order = [c for c, _ in Counter(only_letters(ct)).most_common()]
    order += [c for c in ALPHA if c not in order]
    key = ["A"] * 26
    for ct_ch, pt_ch in zip(order, ENGLISH_ORDER):
        key[ord(ct_ch) - 65] = pt_ch
    return "".join(key)


def apply_key(text: str, key: str) -> str:
    """key[i] is the plaintext letter that ciphertext chr(65+i) decrypts to."""
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPHA:
            p = key[ord(up) - 65]
            out.append(p if ch.isupper() else p.lower())
        else:
            out.append(ch)
    return "".join(out)


def invert_key(key: str) -> str:
    inv = ["A"] * 26
    for i, ch in enumerate(key):
        inv[ord(ch) - 65] = chr(65 + i)
    return "".join(inv)


def _climb(letters: str, key: list[str]) -> float:
    """Sweep all 325 transpositions until a full pass yields no improvement."""
    score = ngram_score(letters.translate(str.maketrans(ALPHA, "".join(key))))
    improved = True
    while improved:
        improved = False
        for i, j in PAIRS:
            key[i], key[j] = key[j], key[i]
            new = ngram_score(letters.translate(str.maketrans(ALPHA, "".join(key))))
            if new > score:
                score, improved = new, True
            else:
                key[i], key[j] = key[j], key[i]
    return score


def solve_substitution(ct: str, restarts: int = 12, seed=None):
    """Return (key, score, plaintext). Restart 0 is the frequency seed."""
    rng = random.Random(seed)
    letters = only_letters(ct)
    best_key, best_score = None, -1e18
    for r in range(restarts):
        key = list(frequency_seed(ct)) if r == 0 else list(ALPHA)
        if r:
            rng.shuffle(key)
        s = _climb(letters, key)
        if s > best_score:
            best_score, best_key = s, "".join(key)
    return best_key, best_score, apply_key(ct, best_key)


def word_pattern(word: str) -> tuple[int, ...]:
    """CANONICAL pattern: 'HELLO' -> (0,1,2,2,3). Same pattern = possible match."""
    seen: dict[str, int] = {}
    return tuple(seen.setdefault(ch, len(seen)) for ch in word.upper())


def pattern_candidates(ct_word: str, dictionary) -> list[str]:
    """Dictionary words whose repetition pattern matches ct_word."""
    p = word_pattern(ct_word)
    return [w.upper() for w in dictionary
            if len(w) == len(ct_word) and word_pattern(w) == p]


def random_key(seed=None) -> str:
    rng = random.Random(seed)
    k = list(ALPHA)
    rng.shuffle(k)
    return "".join(k)


def keyword_alphabet(keyword: str) -> str:
    """Classic keyed alphabet: dedup(keyword) then the remaining letters in order."""
    seen, out = set(), []
    for ch in (keyword + ALPHA).upper():
        if ch in ALPHA and ch not in seen:
            seen.add(ch)
            out.append(ch)
    return "".join(out)


if __name__ == "__main__":
    plain = (
        "IT IS A TRUTH GENERALLY ACKNOWLEDGED THAT A SINGLE MAN IN POSSESSION OF A "
        "GOOD FORTUNE MUST BE IN WANT OF A WIFE HOWEVER LITTLE KNOWN THE FEELINGS OR "
        "VIEWS OF SUCH A MAN MAY BE ON HIS FIRST ENTERING A NEIGHBOURHOOD THIS TRUTH "
        "IS SO WELL FIXED IN THE MINDS OF THE SURROUNDING FAMILIES THAT HE IS "
        "CONSIDERED AS THE RIGHTFUL PROPERTY OF SOME ONE OR OTHER OF THEIR DAUGHTERS"
    )

    enc_key = random_key(seed=1337)          # plaintext letter i -> enc_key[i]
    ct = apply_key(plain, enc_key)
    print("CT :", ct[:64], "...")

    assert 0.055 < index_of_coincidence(ct) < 0.080, "not monoalphabetic?"

    key, score, rec = solve_substitution(ct, restarts=8, seed=7)
    a, b = only_letters(rec), only_letters(plain)
    acc = sum(x == y for x, y in zip(a, b)) / len(b)
    print(f"[ok] score={score:.1f} accuracy={acc:.3f}")
    print("PT :", rec[:64], "...")
    assert acc >= 0.95, f"hill climb failed, accuracy={acc}"

    # Word-pattern helper
    assert word_pattern("HELLO") == (0, 1, 2, 2, 3)
    assert word_pattern("LEVEL") == (0, 1, 2, 1, 0)
    dict_words = ["there", "these", "those", "level", "hello"]
    assert pattern_candidates("XYZZO", dict_words) == ["HELLO"]
    print("[ok] word-pattern matcher")

    # Keyed alphabet helper
    assert keyword_alphabet("CRYPTO") == "CRYPTOABDEFGHIJKLMNQSUVWXZ"
    print("[ok] keyword alphabet")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Keyword / keyed alphabets.** If the key was built as `keyword + rest-of-alphabet`,
  the recovered mapping has a long alphabetical run. Reconstruct the keyword - it is
  frequently the flag itself.
- **Homophonic substitution.** One plaintext letter maps to several ciphertext symbols
  (flattened frequencies, IoC drops toward 0.04, alphabet larger than 26, often
  2-digit numbers). Hill climbing on a fixed 26-letter key will not work; you need a
  many-to-one key and a much longer text, or the Zodiac-style solvers (AZdecrypt).
- **Nulls and nomenclators.** Historical ciphers insert meaningless symbols. IoC looks
  monoalphabetic-ish but solutions stall at ~70% accuracy with garbage at regular
  intervals - drop every k-th character and retry.
- **The plaintext is not English.** IoC is language-dependent (French ~0.078,
  German ~0.076, Spanish ~0.077). Rebuild the corpus in the right language.
- **Too little text.** Under ~60 letters, many keys score similarly. Use known
  plaintext (flag prefix) as constraints: pin `F->?`, `L->?`, ... before climbing.
- **Preserving case/punctuation in the score is a bug.** Score only `A-Z`, or spaces
  and digits pollute the n-gram counts.
- **Getting stuck at "almost English".** That means two letters are swapped. Raise the
  restart count, or run a short simulated-annealing pass on the best key.
- **Substitution *after* transposition.** If hill climbing plateaus at a score much
  better than random but the text is still unreadable, the plaintext may itself be a
  transposition (a "complete columnar + substitution" product cipher).

## Tools

- **quipqiup.com** - the best online substitution solver; accepts word boundaries and
  "clues" like `XY=TH`. Solves most aristocrats in under a second.
- **dcode.fr** "Mono-alphabetic Substitution" - automatic solver plus manual key editor.
- **CyberChef** `Substitute` operation - for applying a key you already know.
- **AZdecrypt** - Windows/mono tool built for homophonic and Zodiac-class ciphers.
- **`quipqiup`-style local solvers**: `python-ngram`, `cipher-solver` on PyPI.
- Practical Cryptography's `english_quadgrams.txt` - drop-in replacement for the
  embedded corpus when you want maximum accuracy on short texts.

## References

- quipqiup - <https://quipqiup.com/>
- dcode.fr mono-alphabetic substitution - <https://www.dcode.fr/monoalphabetic-substitution>
- Practical Cryptography, "Cryptanalysis of the Simple Substitution Cipher" - <http://practicalcryptography.com/cryptanalysis/stochastic-searching/cryptanalysis-simple-substitution-cipher/>
- CyberChef - <https://gchq.github.io/CyberChef/>
