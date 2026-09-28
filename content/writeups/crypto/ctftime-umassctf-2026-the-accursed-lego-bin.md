---
title: "The Accursed Lego Bin - UMassCTF 2026"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "proof-of-work", "accursed", "lego", "bin", "umassctf", "umassctf-2026", "2026", "ctf-writeup"]
summary: "I dropped my message into the bin of Legos."
source:
  name: "CTFtime writeup #40692"
  url: "https://ctftime.org/writeup/40692"
original_source: "https://github.com/pnimtsovych/WriteUp/tree/main/The%20Accursed%20Lego%20Bin(UMassCTF%202026)"
ctf:
  name: "UMassCTF 2026"
  year: 2026
  challenge: "The Accursed Lego Bin"
---

## Metadata

- **CTF:** UMassCTF 2026
- **Task:** The Accursed Lego Bin
- **Author team:** LeetSh4d0ws
- **CTFtime:** <https://ctftime.org/writeup/40692>
- **Original writeup:** <https://github.com/pnimtsovych/WriteUp/tree/main/The%20Accursed%20Lego%20Bin(UMassCTF%202026)>

---
## The Accursed Lego Bin

Category: Crypto

I dropped my message into the bin of Legos. It's all scrambled up now. Please help.

[the-accursed-lego-bin.zip](<https://github.com/user-attachments/files/26668471/the-accursed-lego-bin.zip>)

![](<https://github.com/user-attachments/assets/4d4f9c79-294d-4a9b-8989-b1cbfc979db4>)

### There were 2 files in the archive:

#### [encoder.py](http://encoder.py) — the main Python script with the logic of the task.

#### output.txt — a file with the already generated encryption results.

#### What was important in [encoder.py](http://encoder.py):

variable `e = 7`   
function `RSA_enc(plain_text)`   
function `get_flag_bits(flag)`

#### calculation:

`enc_seed = pow(seed, e, n)`

writing to the file:

`seed = ...`   
`flag = ...`

### What was in output.txt:

large number `seed = ...`

encrypted/scrambled flag in hex:

`flag = a9fa3c5e51d4cea498554399848ad14aa0764e15a6a2110b6613f5dc87fa70f17fafbba7eb5a2a5179`

### How is the seed formed

#### Explain:

`I_LOVE_RNG` is converted to a number

this number is encrypted with RSA

the result becomes the seed

then the seed is encrypted again with `enc_seed`

### How is the flag encrypted

#### Explain:

the flag is converted to bits

the bits are shuffled 10 times

for each step `random.seed(seed * (i + 1))` is used

so if you restore the seed, you can repeat the permutations

## Recovering the seed

After computing the exact integer 49th root of `enc_seed`, we recover the original message:

`b'I_LOVE_RNG'`

Once `m` is known, the seed is easy to reconstruct:

`seed = m^7`

At this point, we have exactly the same seed that was used by the challenge script.

## Reversing the bit shuffling

Recovering the seed is only the first part of the solution.   
The next step is to undo the repeated `random.shuffle()` operations applied to the flag bits.

Since the flag bits were shuffled 10 times, we must:

1\. reproduce the same shuffle for each round,  
2\. build the inverse permutation,  
3\. apply the inverse permutations in reverse order.

This works because Python's shuffle is deterministic when the seed is known.

So for each round, we recreate the shuffled index order, then use it to move every bit back to its original position.

## Full solve script

The script (`[solve.py](http://solve.py)`) below:

1\. recovers the original message from `enc_seed`,  
2\. reconstructs the seed,  
3\. reverses all shuffle operations,  
4\. converts the recovered bitstream back into bytes,  
5\. prints the final flag.

```python  
import random

enc_seed = 27853968878118202600616227164274184566757028924504378904793832254042520819991144639702067205911203237440164930417495337197532501173607130020895075421529488925453640401673956438276491981209692168887241600331323119747563338336714474549971016558306628074198388772585672217715120627041791075104601103026751194857235765309608359123653353317678322176850235969280946203083455072140605141795053378439195293814791874092411691470992665912679118059266672118104677436338717139016415491690881114160151442145485980845723522027034166250144387200630948484934412980402141190370298072772878692178174395473352346736568834853932546775351591579301264010616662074516876263415244325179769805404580595987957830206775099221681479552297343673953519347816803686755315058241114932909715588571465125584675910868587612361307253375806962785674201551995414052898626175776112925401104907258409223265509906782478388392655489350014728299523474441953620142576405825798349964376116586305354010422094308152856531053593521850744465605649669069637606613192817098670399196448110611736116364403445860585755736974514672765253945103150765043635481842335038685418842068710568699703147745504514090439  
hex_flag = "a9fa3c5e51d4cea498554399848ad14aa0764e15a6a2110b6613f5dc87fa70f17fafbba7eb5a2a5179"

def iroot(n: int, k: int) -> int:  
"""Return the floor of the exact integer k-th root of n."""  
lo, hi = 0, 1  
while hi ** k <= n:  
hi *= 2  
while lo + 1 < hi:  
mid = (lo + hi) // 2  
if mid ** k <= n:  
lo = mid  
else:  
hi = mid  
return lo

def unshuffle(lst: list[str], seed_value: int) -> list[str]:  
"""Undo one deterministic random.shuffle call by reconstructing the permutation."""  
idx = list(range(len(lst)))  
random.seed(seed_value)  
random.shuffle(idx)  
original = [None] * len(lst)  
for new_pos, old_pos in enumerate(idx):  
original[old_pos] = lst[new_pos]  
return original

def main() -> None:  
# Recover m from enc_seed = m^49  
m = iroot(enc_seed, 49)  
msg = m.to_bytes((m.bit_length() + 7) // 8, "big")  
print(f"[+] Recovered message: {msg!r}")

if msg != b"I_LOVE_RNG":  
print("[!] Warning: recovered plaintext is unexpected")

# Original seed = m^7  
seed = m ** 7  
print(f"[+] Reconstructed seed: {seed}")

# Convert scrambled flag from hex to bit list  
enc_bytes = bytes.fromhex(hex_flag)  
bits: list[str] = []

for b in enc_bytes:  
bits.extend(bin(b)[2:].zfill(8))

# Undo the 10 shuffle rounds in reverse order  
for i in reversed(range(10)):  
bits = unshuffle(bits, seed * (i + 1))

# Rebuild bytes from recovered bits  
flag = bytes(int("".join(bits[i:i + 8]), 2) for i in range(0, len(bits), 8))

print(f"[+] Flag: {flag.decode()}")

if __name__ == "__main__":  
main()  
```

![](<https://github.com/user-attachments/assets/6c75ccae-14d4-46b5-bad6-a418bc5db6c9>)

## FLAG:

`UMASS{tH4Nk5_f0R_uN5CR4m8L1nG_mY_M3554g3}`
