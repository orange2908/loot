---
title: "Let’s Break Something at LoWE’s - JerseyCTF V"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lattice", "caesar", "lwe", "deserialization", "base64", "jerseyctf-v", "ctf-writeup"]
summary: "\\- Mary and Maya were in LoWE's to grow their crypto toolbox, when Maya saw some mysterious white seagulls..."
source:
  name: "CTFtime writeup #40133"
  url: "https://ctftime.org/writeup/40133"
ctf:
  name: "JerseyCTF V"
  challenge: "Let’s Break Something at LoWE’s"
---

## Metadata

- **CTF:** JerseyCTF V
- **Task:** Let’s Break Something at LoWE’s
- **Author team:** Highlander Hackers
- **CTFtime:** <https://ctftime.org/writeup/40133>

---
# Lets-Break-Something-at-LoWEs

## Description

\- Mary and Maya were in LoWE's to grow their crypto toolbox, when Maya saw some mysterious white seagulls... or drones, hovering around the building. Suddenly, a gust of wind made one of the drones drop a blue paper on Maya's head. Mary thinks it might have the structure and inner workings of "The Turing Lock". Can you open it to see what's inside? At the LoWE's Pro Desk, Maya spotted an oracle at `nc [lets-break-something-at-lowes.aws.jerseyctf.com](http://lets-break-something-at-lowes.aws.jerseyctf.com) 5555`, but she's not sure if it can help...

## Hint

\- LoWE's is slow, but its formulas might not have so many _random_ errors after all...  
\- Does the oracle really work? Why is the oracle code called "broken"?

## Credit:

\- Developed by: [Raunak Singh](<https://github.com/Raunak-Singh-Inventor>)

## Solution Steps

After reading about the [fundamentals of simple lattice-based encryption schemes](<https://www.di-mgt.com.au/lattice-lwe-simple-pke.html>), we see that the oracle's security is based on small errors introduced into what is basically a system of linear equations.

We notice that in the lattice-based encryption scheme described in the [fundamentals](<https://www.di-mgt.com.au/lattice-lwe-simple-pke.html>), the binary vector $\textbf{r}$ is sampled randomly each time an encryption is called. Conceptually, this is important as in a correctly-implemented oracle, $\textbf{r}$ is the only variable that changes over multiple different encryptions ($\textbf{b}$ is initialized at the start of the algorithm and remains the same), and thus plays a large role in the oracle's security. However, in the oracle given, $\textbf{r}$ stays the same across multiple decryptions (it is only initialized at the start).

We can exploit the scheme using this observation. If we fix the $\textbf{r}_0$ for one pair $(u_0, v_0)$, we know that same $r$ can be utilized to decrypt an arbitrary pair $(u, v)$.

Notice also that the oracle is called broken oracle... maybe it doesn't even have the right key pair for the blueprint? When we start the oracle, we notice that it generates a new key pair every time it is run. Well, finding r is independent of the plaintext value, all we need is the ciphertext. And, as strings of multiple bits are encrypted bit by bit, we can just take the first bit of the blueprint and use that to find r.

Based on these observations, we can write an attack script that finds the r value, and then uses that to decrypt anything. It assumes that the user has put following files in same location as `[attack.py](http://attack.py)`:

\- `public_key.pkl` - retrieved from challenge  
\- `blueprint.pkl` - retrieved from challenge

`[attack.py](http://attack.py)`:

```  
import pickle  
import numpy as np

DECRYPTION_FILE = "blueprint.pkl"

pub_key = open("public_key.pkl", "rb")  
A, b = pickle.load(pub_key)  
pub_key.close()

def recover_r():  
'''  
Recover the random vector r because its reused  
'''  
f = open(DECRYPTION_FILE, "rb")  
c0 = pickle.load(f)[0]  
f.close()

u0, v0 = c0

u0 = np.array(u0, dtype=int)  
v0 = int(v0)

# the same r is used for every encryption  
# so can solve for one r using A^T * r = u0  
A_T = A.T  
r = np.linalg.lstsq(A_T, u0, rcond=None)[0]  
r = np.round(r).astype(int) % 3329

return r

def decrypt_anything(ciphertext, r):  
u, v = ciphertext  
u = np.array(u, dtype=int)

# d = v - b_T * r = (q / 2) * m  
b_T_r = np.dot(np.array(b, dtype=int).T, r) % 3329  
d = (v - b_T_r) % 3329

# m = (2 / q) * d  
# in mod 2 as m is binary (0 or 1)  
m = (2 * d // 3329) % 2  
return int(m)

r = recover_r()  
# print("Recovered r:", r)

with open(DECRYPTION_FILE, "rb") as f:  
encrypted_data = pickle.load(f)

decrypted_string = "".join(str(decrypt_anything(c, r)) for c in encrypted_data)  
decrypted_string = " ".join(decrypted_string[i:i+8] for i in range(0, len(decrypted_string), 8))  
print(f"Decrypted string from {DECRYPTION_FILE}: {decrypted_string}")  
```

And the output of running this script on aforementioned files is a binary code like:

```  
01010111 01101100 01001110 01101011 01010110 01101101 01011010 01110010 01010000 01000100 01000010 01000101 01010000 00110001 01001101 01101010 01001101 01000100 01111000 01100110 01010010 01111010 01010101 01101010 01010100 01111010 00111001 01101010 01010100 00110001 00110100 01100111... so on  
```

Decoding this using a [binary to text translator](<https://www.rapidtables.com/convert/number/binary-to-ascii.html>) gives:

```  
WlNkVmZrPDBEP1MjMDxfRzUjTz9jT14gZE9jIE9CMF5UIF1PMFZkVWJPUVxcbSAoMTkyMSwgb3JpZ2luYWwgZ29vZ2xlIG1hcCBsb2NhdGlvbnMgaW4gLy8vbWVzc2VuZ2Vycy5pbnNlcnRpb24uYmFzZW1lbnRzIGFuZCBBU0NJSSwgTlkp  
```

This is very clearly a base64 encoded string, so we can [base64 decode](<https://www.base64decode.org/>) it, and we get:

```  
ZSdVfk<0D?S#0<_G5#O?cO^ dOc OB0^T ]O0VdUbOQ\\\m (1921, original google map locations in ///messengers.insertion.basements and ASCII, NY)  
```

We have some odd looking unreadable text at the start, but some readable text at the end. Given that this challenge is called Lowes and has "tools", looking at the Lowes home improvement store wikipedia page shows us that:

> The first Lowe's store, Mr. L.S. Lowe's North Wilkesboro Hardware, opened in North Wilkesboro, North Carolina, in 1921 by Lucius Smith Lowe

The years match, so the challenge is indeed themed after Lowe's Home Department store. Now, let's investigate the locations.

The first location is from [what3words.com](http://what3words.com) (this can be easily found through some quick searches). Its on Casar Rd.  
And the second location is ASCII, NY (nothing interesting to see on the google maps there, thats why it isn't provided in a format like what3words).

Given that this is in the crypto category, _Casar_ Rd. makes us think of _Caesar_ Cipher. Going to a [caesar cipher decoder](<https://www.dcode.fr/caesar-cipher>), initially decrypting it doesn't show anything useful. But then we see that there is an ASCII Table option for the alphabet, matching the ASCII, NY location name. Maybe 1921 is the shift key? Decrypting using these parameters gives us: `jctfv{L@TOc3@LoWE3_Os_n0t_s0_R@nd0m_@fter_all}`
