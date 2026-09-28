---
title: "Rotor Rooter - CTF@CIT 2026"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "vigenere", "rotor", "rooter", "classical", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Value: 884 pts (117 solves)"
source:
  name: "CTFtime writeup #40729"
  url: "https://ctftime.org/writeup/40729"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Rotor Rooter"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Rotor Rooter
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40729>

---
# Rotor Rooter — Writeup

\- Category: Crypto  
\- Value: 884 pts (117 solves)  
\- Author: elemental

## Challenge

```text  
Spin it till it drains

KLEGCKRGGONTBNBVPIIZWXQQEZYAXXWQMGIZDNEWWUTOVZRWOMZKGWNKWZBQXOGZSTVCGU

FLAG FORMAT: CIT{underscore_between_each_word}  
```

70 characters, A–Z only. "Rotor Rooter" + "spin" → Enigma-class rotor cipher.

## Recon

Index of coincidence rules out short-period polyalphabetic (Vigenère):

```text  
period 1: 0.046 period 9: 0.060 period 13: 0.069  
period 2: 0.048 period 10: 0.052 period 14: 0.036  
period 3: 0.039 period 11: 0.052 period 15: 0.027  
```

No clean peak at 5/6/7 (the popular Vigenère key lengths). Letter frequency  
is suspiciously flat — `G`, `Z`, `W` tied at 10% each, `Z` impossible-high  
for English. Consistent with Enigma. Default unknowns to brute force:  
rotor ordering (60), reflector (B/C), and starting position (17576).

## Solution

Two stages.

### Stage 1 — find the rotor + start, ring = AAA

Brute Enigma M3 over **rotors ∈ Perm(I…V, 3)**, **reflector ∈ {B, C}**,  
**start ∈ A…Z³** with **ring AAA** and empty plugboard. Rank candidates by  
English letter-frequency + bigram score (no `CIT` bonus — it's only 70 chars,  
random "CIT" substrings dominate honest scoring).

Top hit (score 266.7):

```text  
rotors=(I, II, III) refl=B start=AAA  
WECANONLYSEEASHORTDNHTANCEAHEADBUTWECANSEEPLEIGYTHERETHATNEEDSTOBEDONE  
```

That's Turing's quote with **4 character errors** at positions 19, 20, 45, 46:

```text  
expected: ...WECANONLYSEEASHORTD I S TANCE...PLE N T YTHERE...  
got: ...WECANONLYSEEASHORTD N H TANCE...PLE I G YTHERE...  
```

Errors cluster, suggesting the *ring* (not plugboard) is off — a plugboard  
swap would scatter mismatches across the whole text wherever those letters  
appeared, but here they're concentrated in two windows.

### Stage 2 — recover the ring with a crib

Plug in Turing's quote (`WECANONLY…NEEDSTOBEDONE`) as a known-plaintext crib  
and sweep the right-rotor ring + all start positions. Exact match at:

```text  
rotors=(I, II, III) refl=B ring=AAC start=AAC plugboard=∅  
plaintext: WECANONLYSEEASHORTDISTANCEAHEADBUTWECANSEEPLENTYTHERETHATNEEDSTOBEDONE  
```

The "spin it till it drains" hint is literal: ring **C** = position 2, two  
clicks past `A`. The pun "Roto-Rooter" lands on **rotors I, II, III** — the  
default wartime starter set.

Word-segment, lowercase, underscore-join:

```text  
WE CAN ONLY SEE A SHORT DISTANCE AHEAD BUT WE CAN SEE PLENTY THERE THAT NEEDS TO BE DONE  
```

## Flag

```text  
CIT{we_can_only_see_a_short_distance_ahead_but_we_can_see_plenty_there_that_needs_to_be_done}  
```

(Quote: Alan Turing, *Computing Machinery and Intelligence*, 1950.)

## Files

\- [scripts/[solve.py](http://solve.py)](scripts/[solve.py](http://solve.py)) — direct decrypt with the recovered key  
\- [scripts/[bruteforce.py](http://bruteforce.py)](scripts/[bruteforce.py](http://bruteforce.py)) — full discovery pipeline (~3 min)  
\- [solution/flag.txt](solution/flag.txt) — recorded submission
