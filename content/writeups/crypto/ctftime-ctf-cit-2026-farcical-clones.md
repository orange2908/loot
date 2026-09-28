---
title: "Farcical Clones - CTF@CIT 2026"
category: "crypto"
subcategory: "classical"
type: "writeup"
tags: ["crypto", "xor", "one-time-pad", "vigenere", "farcical", "clones", "classical", "ctf-cit", "ctf-cit-2026", "2026", "ctf-writeup"]
summary: "\\- Value: 999 pts (2 solves)"
source:
  name: "CTFtime writeup #40730"
  url: "https://ctftime.org/writeup/40730"
ctf:
  name: "CTF@CIT 2026"
  year: 2026
  challenge: "Farcical Clones"
---

## Metadata

- **CTF:** CTF@CIT 2026
- **Task:** Farcical Clones
- **Author team:** Byte0xb105
- **CTFtime:** <https://ctftime.org/writeup/40730>

---
# Farcical Clones — Writeup

\- Category: Crypto  
\- Value: 999 pts (2 solves)  
\- Author: bootstrap

## Challenge

```text  
May the Force be with you, young padawan.

095 181 145 039 245 091 212 232 123 220 167 069 091 208 245 164 245 145 123 094, 062 150 094 172 083 135 096 153 002 208 096 172. 201 005 019 {131 091 090 053 095 218 238 211 091 004 201 182 135 245 167 074 090 145 096 238}  
```

## Cipher: `byte = 25 * clone + core`

Each decimal splits as `(clone, core) = divmod(byte, 25)`:

\- `clone ∈ [0..9]` — **random "farcical clone"**, carries no information, only inflates each letter to a 1–3 digit "byte".  
\- `core ∈ [0..24]` — the real payload, a letter in the 25-letter Latin alphabet (**no J**; J folds to I):

```text  
a b c d e f g h i k l m n o p q r s t u v w x y z  
```

The cipher on the cores is a **Beaufort one-time pad**:

```text  
core = (K - P) mod 25 ⇒ K = (core + P) mod 25  
P = (K - core) mod 25  
```

Key length equals plaintext length (55), so there is nothing to "recover" as a keystream — the solve is a crib problem.

## Why byte-level XOR / substitution was a dead end

The byte stream itself is not a substitution: the same byte maps to two different letters because each byte carries a random clone digit on top of the letter index.

```text  
245 → {h, i} (h at positions 4, 16, body-13; i at prefix-14)  
123 → {r, o} (r at position 8; o at position 18)  
```

That rules out every "recover an 8-bit key" cipher family — XOR, additive, Vigenère, Beaufort on bytes, Fibonacci, LFSR, RC4, multiplicative mod 257, etc. All of the earlier ~200 guesses at `CIT{...}` sat in that dead end.

The `(138, 76, 71)` triple from XOR-ing `CIT` with `201 005 019` is real but local: it only tells you that **under XOR** the key at positions 32–34 is `8A 4C 47`. No short key produces those three consecutive bytes via any linear recurrence over GF(256), so "XOR key of length < 35" is impossible — but we were looking at the wrong modulus all along (mod 25, not mod 256).

## Solve

### Prefix (35 bytes)

The intro sentence *is* the plaintext — spaces / punctuation are simply not encrypted:

```text  
MaytheForcebewithyou youngpadawan CIT  
(20 bytes) (12 bytes) (3 bytes)  
```

Derive key via `K = (core + P) mod 25`:

```text  
ggthcvsvpxwvvedhctmolookpzwgcewkdon  
```

### Flag body (20 bytes)

Apply the same mapping to the body ciphertext, using whichever letters the prefix crib already fixes. From positions 32–34 we know `201→C`, `005→I`, `019→T`. Re-used bytes fill in more:

```text  
131 091 090 053 095 218 238 211 091 004 201 182 135 245 167 074 090 145 096 238  
? e ? ? M ? ? ? e ? C ? p h e ? ? y a ?  
```

The repeated values `090 … 090` and `238 … 238` lock two more letters each. Reading the skeleton as a pair of title-cased English words gives:

```text  
J e d i M a s t e r C i p h e r D y a s  
```

= **JediMasterCipherDyas**.

The body key under Beaufort is `pvtmgtfevvdqzcwqttwf` — no English meaning; it is a random OTP suffix.

### Star Wars reference — Sifo-Dyas

"Farcical Clones" is **not** *Attack of the Clones*. It points to **Sifo-Dyas**, the Jedi Master who (per the official Databank) secretly commissioned the Kaminoan clone army. Swap **Sifo** → **Cipher** and the body reads *Jedi Master **Cipher**Dyas*.

\- <<https://www.starwars.com/databank/sifo-dyas>>

## Flag

```text  
CIT{JediMasterCipherDyas}  
```

## Solve script

See [`scripts/[solve.py](http://solve.py)`](scripts/[solve.py](http://solve.py)): derives the prefix + body Beaufort key from the crib, decrypts, prints the flag, and also prints the byte-level collisions that prove the cipher is not a byte→letter substitution.
