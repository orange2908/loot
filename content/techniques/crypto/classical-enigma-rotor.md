---
title: "Enigma and Rotor Machines - How to Attack One in a CTF"
category: crypto
subcategory: classical
type: technique
tags: [enigma, enigma-machine, rotor-machine, rotor-cipher, wehrmacht-enigma, plugboard, steckerbrett, ringstellung, grundstellung, reflector, umkehrwalze, bombe, turing, index-of-coincidence, ngram, hill-climbing, py-enigma, crib-attack, cyberchef, dcode]
difficulty: hard
summary: "Enigma is a stepping polyalphabetic cipher with no fixed points; brute-force rotor order and start positions on an IoC score, then hill-climb the plugboard."
when_to_use:
  - "Ciphertext is A-Z only, groups of 5, and no letter ever encrypts to itself"
  - "Challenge mentions rotors, Walzen, Ringstellung, Grundstellung, Steckerbrett, or a reflector"
  - "You are given a partial key (rotor order or plugboard) and must find the rest"
  - "A crib is available - 'WETTERBERICHT', 'KEINEBESONDERENEREIGNISSE', or a flag prefix"
tools: [python, py-enigma, cyberchef, dcode, cryptool, enigma-suite]
related: [classical-vigenere, classical-substitution-hillclimb, cipher-identification]
---

## TL;DR

Enigma = plugboard -> 3 (or 4) stepping rotors -> reflector -> rotors back ->
plugboard. Full Wehrmacht keyspace is astronomically large only because of the
plugboard; **the rotor part is tiny**: 60 rotor orders (3 of 5) x 26^3 start
positions = 1,054,560, which a laptop enumerates. Score with index of coincidence,
then recover the plugboard by hill climbing one pair at a time. The reflector
guarantees **no letter ever encrypts to itself** - that single property both
identifies Enigma and powers the classic crib attack.

## Recognise it

- Pure `A-Z`, usually in groups of 5, message length often prefixed by an indicator
  group.
- **No fixed points**: line the ciphertext up against any candidate crib; if any
  position has the same letter in both, that alignment is impossible. This is *the*
  Enigma fingerprint.
- IoC around 0.038-0.045 (near random) for a long message - the key never repeats.
- German plaintext conventions: `X` for full stop, `Q` for `CH`, spelled-out numbers
  (`EINS`, `ZWO`, `DREI`), `WETTER`, `FEINDLICHE`.
- Source code with `ROTORS`, `notch`, `Ringstellung`, `UKW`, `Walzenlage`.

## Theory

**The machine.** For each keypress:
1. Step the rotors (the right rotor always; the middle when the right hits its notch;
   the left when the middle hits its notch - plus the **double-stepping anomaly**
   where the middle rotor steps itself and the left rotor together).
2. Signal enters the plugboard (an involution: up to 13 swapped pairs).
3. Through the right, middle, left rotors, each a fixed permutation offset by
   `position - ring setting`.
4. Through the reflector (a fixed derangement with no fixed points, made of 13 pairs).
5. Back through the rotors in reverse, then the plugboard again.

Because the reflector is an involution with no fixed points and the whole circuit is
symmetric, **encryption is self-inverse**: the same settings decrypt. And no letter
maps to itself.

**Keyspace.** Rotor order: $5 \cdot 4 \cdot 3 = 60$ (Army, 3 of 5; Navy M3 used 8
rotors, M4 added a thin 4th rotor + thin reflector). Start positions: $26^3$. Ring
settings: $26^3$, but two of the three rings have **no effect on the output** given a
free choice of start position - only the ring of a rotor that actually turns over
during the message matters. Plugboard with 10 cables: ~$1.5 \times 10^{14}$.

**The key insight for cryptanalysis.** The plugboard is *outside* the rotor stack, so
it does not disturb the statistics much. Decrypt with the correct rotors and start
positions but no plugboard, and the text is still wrong letter-by-letter - but its
**index of coincidence rises measurably above random**, because up to 6 letters are
un-steckered and pass straight through. So:
- Stage 1: brute force rotor order + start positions, rank by IoC. The true setting
  ranks at or near the top.
- Stage 2: fix the rotors, hill-climb the plugboard: try all 325 possible cable pairs,
  keep the one that raises the score most, repeat until nothing improves. Use bigram
  or trigram scoring here, not IoC.
- Stage 3: settle the ring setting of the fast rotor by sliding it and re-scoring.

This is the "Gillogly attack" (1995), and it is what every modern software Enigma
breaker does.

**Crib / Bombe approach.** With a known plaintext, slide the crib along the ciphertext
and discard every alignment with a fixed point. The survivors define a "menu" of
letter-to-letter constraints; Turing's Bombe tested rotor settings against the menu
and used the plugboard's self-consistency to reject them wholesale. In a CTF you
rarely need the Bombe - just use the crib to filter the IoC candidate list.

## Attack

1. Confirm no-fixed-point against any crib you have.
2. Implement or import a correct Enigma (double-stepping included - get this wrong and
   nothing works past the 26th character).
3. Brute force rotor order x start positions with IoC scoring. Keep the top ~100.
4. For each survivor, hill-climb the plugboard with a trigram score.
5. Adjust the fast rotor's ring setting (26 tries) and re-score.
6. Read the German (or the flag).
7. If the challenge fixes some parameters (very common - "rotors I II III, find the
   positions"), skip straight to that sub-search.

## Code

```python
#!/usr/bin/env python3
"""Enigma I / M3: correct stepping (including double-stepping), plugboard, ring
settings, plus an IoC brute force over start positions and a plugboard hill climb.

Verified against the standard test vector:
    rotors I II III, reflector B, rings AAA, positions AAA, no plugs
    'A' * 25  ->  BDZGOWCXLTKSBTMCDLPBMUQOF
"""
from __future__ import annotations

import math
import string
from collections import Counter
from itertools import permutations

A = string.ascii_uppercase

# (wiring, turnover notch) - historical Wehrmacht/Heer rotors
ROTORS = {
    "I":    ("EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"),
    "II":   ("AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"),
    "III":  ("BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"),
    "IV":   ("ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"),
    "V":    ("VZBRGITYUPSDNHLXAWMJQOFECK", "Z"),
}
REFLECTORS = {
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
}

_CORPUS = (
    "the history of the world is in many ways the history of the ordinary people "
    "who lived through it and not only of the kings and generals whose names are "
    "written in the books that children read at school in every village there were "
    "farmers who watched the weather and the price of grain and children who "
    "learned to count the days until the harvest they did not think of themselves "
    "as living in a period that would one day be given a name by scholars they "
    "thought about the rain and the road to the market and whether there would be "
    "enough bread in the house for the long winter that was coming very soon"
)


def clean(t: str) -> str:
    return "".join(c for c in t.upper() if c in A)


def _model(n: int):
    s = clean(_CORPUS)
    c = Counter(s[i:i + n] for i in range(len(s) - n + 1))
    tot, vocab = sum(c.values()), 26 ** n
    return ({g: math.log10((v + 1) / (tot + vocab)) for g, v in c.items()},
            math.log10(1 / (tot + vocab)))


_TRI, _TRIF = _model(3)


def tri_score(s: str) -> float:
    s = clean(s)
    if len(s) < 3:
        return -1e9
    return sum(_TRI.get(s[i:i + 3], _TRIF) for i in range(len(s) - 2))


def ioc(text: str) -> float:
    s = clean(text)
    n = len(s)
    if n < 2:
        return 0.0
    c = Counter(s)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


class Enigma:
    """Left-to-right rotor order, i.e. rotors=('I','II','III') means I is the
    slowest (leftmost) and III is the fast (rightmost) rotor."""

    def __init__(self, rotors=("I", "II", "III"), reflector="B",
                 rings="AAA", positions="AAA", plugboard=""):
        self.fwd = [[ord(c) - 65 for c in ROTORS[r][0]] for r in rotors]
        self.bwd = []
        for f in self.fwd:
            inv = [0] * 26
            for i, v in enumerate(f):
                inv[v] = i
            self.bwd.append(inv)
        self.notch = [ord(ROTORS[r][1]) - 65 for r in rotors]
        self.refl = [ord(c) - 65 for c in REFLECTORS[reflector]]
        self.ring = [ord(c) - 65 for c in rings]
        self.pos = [ord(c) - 65 for c in positions]
        self.plug = list(range(26))
        self.set_plugboard(plugboard)

    def set_plugboard(self, spec) -> None:
        """spec: 'AB CD EF' or an iterable of 2-char strings/tuples."""
        self.plug = list(range(26))
        pairs = spec.split() if isinstance(spec, str) else list(spec)
        for pair in pairs:
            a, b = ord(pair[0]) - 65, ord(pair[1]) - 65
            self.plug[a], self.plug[b] = b, a

    def reset(self, positions: str) -> None:
        self.pos = [ord(c) - 65 for c in positions]

    def _step(self) -> None:
        # Double-stepping: when the MIDDLE rotor sits on its notch it steps itself
        # and the left rotor, regardless of the right rotor.
        if self.pos[1] == self.notch[1]:
            self.pos[1] = (self.pos[1] + 1) % 26
            self.pos[0] = (self.pos[0] + 1) % 26
        elif self.pos[2] == self.notch[2]:
            self.pos[1] = (self.pos[1] + 1) % 26
        self.pos[2] = (self.pos[2] + 1) % 26

    def encrypt_char(self, ch: str) -> str:
        self._step()
        c = self.plug[ord(ch) - 65]
        for i in (2, 1, 0):
            off = self.pos[i] - self.ring[i]
            c = (self.fwd[i][(c + off) % 26] - off) % 26
        c = self.refl[c]
        for i in (0, 1, 2):
            off = self.pos[i] - self.ring[i]
            c = (self.bwd[i][(c + off) % 26] - off) % 26
        return chr(self.plug[c] + 65)

    def encrypt(self, text: str) -> str:
        """Self-inverse: the same settings decrypt."""
        return "".join(self.encrypt_char(c) for c in clean(text))


def decrypt_with(ct: str, rotors, positions, reflector="B", rings="AAA",
                 plugboard="") -> str:
    return Enigma(rotors, reflector, rings, positions, plugboard).encrypt(ct)


def crib_alignments(ct: str, crib: str):
    """Enigma never maps a letter to itself, so any offset where crib[i]==ct[i+o]
    is impossible. Returns the surviving offsets."""
    c, k = clean(ct), clean(crib)
    return [o for o in range(len(c) - len(k) + 1)
            if all(k[i] != c[o + i] for i in range(len(k)))]


def brute_force_positions(ct: str, rotors=("I", "II", "III"), reflector="B",
                          rings="AAA", top: int = 10):
    """26^3 start positions for a FIXED rotor order, ranked by IoC."""
    results = []
    e = Enigma(rotors, reflector, rings, "AAA")
    for a in range(26):
        for b in range(26):
            for c in range(26):
                e.reset(chr(65 + a) + chr(65 + b) + chr(65 + c))
                pt = e.encrypt(ct)
                results.append((ioc(pt), chr(65 + a) + chr(65 + b) + chr(65 + c), pt))
    results.sort(key=lambda t: -t[0])
    return results[:top]


def brute_force_rotor_order(ct: str, rotor_names=("I", "II", "III", "IV", "V"),
                            reflector="B", top: int = 5, sample: int = 200):
    """60 rotor orders x 26^3 positions. Use `sample` to cap the scored prefix."""
    best = []
    snippet = clean(ct)[:sample]
    for order in permutations(rotor_names, 3):
        cands = brute_force_positions(snippet, order, reflector, top=1)
        best.append((cands[0][0], order, cands[0][1], cands[0][2]))
    best.sort(key=lambda t: -t[0])
    return best[:top]


def hill_climb_plugboard(ct: str, rotors, positions, reflector="B", rings="AAA",
                         max_pairs: int = 10):
    """Gillogly stage 2: greedily add the single cable that helps the most."""
    plugs: list[str] = []
    used: set[str] = set()
    best_score = tri_score(decrypt_with(ct, rotors, positions, reflector, rings, ""))
    while len(plugs) < max_pairs:
        candidate, cand_score = None, best_score
        for i in range(26):
            for j in range(i + 1, 26):
                x, y = A[i], A[j]
                if x in used or y in used:
                    continue
                trial = plugs + [x + y]
                s = tri_score(decrypt_with(ct, rotors, positions, reflector,
                                           rings, " ".join(trial)))
                if s > cand_score:
                    cand_score, candidate = s, x + y
        if candidate is None:
            break
        plugs.append(candidate)
        used.update(candidate)
        best_score = cand_score
    return " ".join(plugs), best_score


if __name__ == "__main__":
    # --- known-answer test -------------------------------------------------
    e = Enigma(("I", "II", "III"), "B", "AAA", "AAA")
    out = e.encrypt("A" * 25)
    assert out == "BDZGOWCXLTKSBTMCDLPBMUQOF", out
    print(f"[ok] test vector: A*25 -> {out}")

    # --- self-inverse ------------------------------------------------------
    msg = "ATTACKATDAWNXTHEFLAGISHIDDENUNDERTHEBRIDGEXX"
    cfg = dict(rotors=("II", "IV", "V"), reflector="B", rings="BCD",
               positions="QWE", plugboard="AB CD EF GH IJ")
    ct = Enigma(**cfg).encrypt(msg)
    assert Enigma(**cfg).encrypt(ct) == msg
    print(f"[ok] self-inverse: {ct[:24]}...")

    # --- no letter encrypts to itself -------------------------------------
    assert all(p != c for p, c in zip(msg, ct))
    print("[ok] no fixed points (the Enigma fingerprint)")

    # --- crib alignment filter --------------------------------------------
    offsets = crib_alignments(ct, msg[:12])
    assert 0 in offsets
    print(f"[ok] crib filter kept {len(offsets)}/{len(ct)-11} alignments, 0 among them")

    # --- brute force start positions (rotors known, no plugboard) ----------
    plain2 = ("KEINEBESONDERENEREIGNISSEXDASWETTERISTRUHIGUNDDIESICHTGUTX"
              "WIRERWARTENKEINENANGRIFFVORDEMMORGENGRAUENX")
    cfg2 = dict(rotors=("I", "II", "III"), reflector="B", rings="AAA",
                positions="MCK")
    ct2 = Enigma(**cfg2).encrypt(plain2)
    hits = brute_force_positions(ct2, ("I", "II", "III"), "B", "AAA", top=5)
    assert hits[0][1] == "MCK", [h[1] for h in hits]
    assert hits[0][2] == plain2
    print(f"[ok] positions recovered by IoC: {hits[0][1]} (IoC {hits[0][0]:.4f})")

    # --- plugboard hill climb ----------------------------------------------
    # The trigram model here is English, so use an English plaintext; with a German
    # message you would swap the corpus (IoC above is language-independent).
    plain3 = ("THEENEMYPOSITIONSHAVENOTCHANGEDSINCELASTNIGHTANDTHEBRIDGE"
              "REMAINSOPENXWEWILLADVANCEATDAWNANDTAKETHERIVERCROSSING"
              "BEFORETHEWEATHERTURNSAGAINSTUSX")
    cfg3 = dict(rotors=("I", "II", "III"), reflector="B", rings="AAA",
                positions="MCK", plugboard="AB XY")
    ct3 = Enigma(**cfg3).encrypt(plain3)
    plugs, score = hill_climb_plugboard(ct3, ("I", "II", "III"), "MCK",
                                        max_pairs=3)
    rec = decrypt_with(ct3, ("I", "II", "III"), "MCK", "B", "AAA", plugs)
    assert set(plugs.split()) >= {"AB", "XY"}, (plugs, rec[:48])
    assert rec == plain3, rec[:48]
    print(f"[ok] plugboard hill climb found: {plugs!r}")
    print(f"     -> {rec[:48]}")
    print("all self-tests passed")
```

## Variants & pitfalls

- **Double stepping.** The middle rotor advances twice in two consecutive keypresses
  when it is sitting on its own notch. Implementations that step naively diverge from
  the real machine after the first middle-rotor turnover, so the first ~26 characters
  decrypt fine and then it all goes wrong. That symptom means exactly this bug.
- **Ring setting vs start position.** Only the ring of a rotor that turns over during
  the message matters; the other two are absorbed by the start position. Do not waste
  $26^3$ on rings - search $26$ on the fast rotor.
- **Rotor order convention.** Some libraries take rotors left-to-right, others
  right-to-left. If your test vector fails, reverse the tuple.
- **Naval M3/M4.** M3 has 8 rotors (VI, VII, VIII all have *two* notches, at Z and M).
  M4 adds a thin fourth rotor (Beta/Gamma) and a thin reflector (B-thin/C-thin); the
  fourth rotor never steps, so it multiplies the keyspace by 26 x 2 only.
- **Plugboard is an involution.** `AB` and `BA` are the same cable; a letter can be in
  at most one cable. Hill-climbing code that forgets this produces impossible keys.
- **IoC needs length.** Below ~100 letters the IoC ranking is noisy; use a crib or a
  trigram score instead and expect to check more candidates.
- **Non-German plaintext.** CTF Enigmas usually encrypt English or a flag. Swap the
  n-gram corpus accordingly; IoC works either way.
- **Uhr box / rewirable reflector (UKW-D).** Rare; if plugboard hill climbing plateaus
  at a good-but-not-readable score, suspect a non-standard reflector.
- **Not Enigma but "a rotor machine".** Typex, the SIGABA, Lorenz SZ40 (that one is a
  binary XOR stream cipher on Baudot, not a rotor substitution), Hebern, Kryha. Lorenz
  in particular is attacked completely differently (delta/chi-wheel statistics).
- **The challenge may be a *reimplementation*.** Read their source for the rotor
  wirings: CTF authors often invent their own rotors, which invalidates any online
  solver but makes your own brute force easier.

## Tools

- **py-enigma** (PyPI `py-enigma`) - faithful Enigma I/M3/M4 simulator with a CLI.
- **enigma-suite / `enigma-cuda`** - Gillogly-style breakers; the CUDA one chews
  through the full rotor+plugboard search in seconds.
- **CrypTool 2** - has an Enigma component *and* an Enigma analyser with the
  IoC/bigram/hill-climb pipeline built in.
- **CyberChef** `Enigma` operation - configure rotors, rings, plugboard, reflector.
  Great for verifying settings, no searching.
- **dcode.fr Enigma** - simulator with the standard rotor sets.
- **`crypto-enigma`** (PyPI) - another simulator, useful for cross-checking wiring.

## References

- CyberChef Enigma operation - <https://gchq.github.io/CyberChef/>
- dcode.fr Enigma machine - <https://www.dcode.fr/enigma-machine-cipher>
- py-enigma documentation - <https://py-enigma.readthedocs.io/>
- Practical Cryptography, "Cryptanalysis of the Enigma" - <http://practicalcryptography.com/ciphers/enigma-cipher/>
- CrypTool 2 - <https://www.cryptool.org/en/ct2/>
