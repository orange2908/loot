---
title: "Going in circles - Nullcon Goa HackIM 2026 CTF"
category: "crypto"
subcategory: "number-theory"
type: "writeup"
tags: ["crypto", "sage", "chinese-remainder", "going", "circles", "number-theory", "nullcon-goa-hackim-2026-ctf", "2026", "ctf-writeup"]
summary: "We are given a python script chall.py and a remote service."
source:
  name: "CTFtime writeup #40593"
  url: "https://ctftime.org/writeup/40593"
ctf:
  name: "Nullcon Goa HackIM 2026 CTF"
  year: 2026
  challenge: "Going in circles"
---

## Metadata

- **CTF:** Nullcon Goa HackIM 2026 CTF
- **Task:** Going in circles
- **Author team:** mritunjya
- **CTFtime:** <https://ctftime.org/writeup/40593>

---
**Challenge Description**:  
We are given a python script `[chall.py](http://chall.py)` and a remote service. The service provides outputs from a specific encryption function.

**Analysis**:  
The `[chall.py](http://chall.py)` script implements a custom `reduce(a, f)` function:  
```python  
BITS = 32  
def reduce(a,f):  
while (l := a.bit_length()) > BITS:  
a ^= f << (l - BITS)  
return a  
```  
This function effectively performs polynomial reduction over $GF(2)$. If we treat the integer `a` as a polynomial $A(x)$ where the bits are coefficients, `reduce(a, f)` computes $A(x) \pmod{F(x)}$, where $F(x)$ corresponds to the integer `f`.

The challenge server generates a random 32-bit integer $f$ (a polynomial of degree approx 31) and outputs:  
1\. `reduce(flag, f)` -> Remainder $R(x)$  
2\. `f` -> Modulus $F(x)$

So for each connection, we get a congruence:  
$$ Flag(x) \equiv R_i(x) \pmod{F_i(x)} $$

**Solution**:  
Since we can connect to the server multiple times, we can collect many such congruences:  
$$  
\begin{align*}  
Flag(x) &\equiv R_1(x) \pmod{F_1(x)} \\\  
Flag(x) &\equiv R_2(x) \pmod{F_2(x)} \\\  
&\vdots \\\  
Flag(x) &\equiv R_n(x) \pmod{F_n(x)}  
\end{align*}  
$$

This is a classic application of the **Chinese Remainder Theorem (CRT)**. Since we are working over the field $GF(2)$, the ring of polynomials $GF(2)[x]$ is a Euclidean Domain, and CRT holds.

We need enough moduli such that their product has a degree larger than the degree of the Flag polynomial. The flag is likely a few hundred bits long. Each modulus provides about 32 bits of information. Collecting 60 pairs ($32 \times 60 = 1920$ bits) is more than enough.

**Implementation**:

1\. **Data Collection**:  
We wrote a script to connect to the server 60 times and save the `(remainder, modulus)` pairs.  
[[collect_data.py](http://collect_data.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/going_in_circles/[collect_data.py](http://collect_data.py))

2\. **Solver**:  
We used **SageMath** because it has built-in support for $GF(2)[x]$ and CRT.  
The solver reads the pairs, converts the integers to polynomials, applies `crt()`, and converts the result back to bytes.  
[[solve.py](http://solve.py)](file:///home/mritunjya/ctf/2026/nullcon/crypto/going_in_circles/[solve.py](http://solve.py))

**Snippet from Solver**:  
```python  
R = GF(2)['x']  
# ... logic to parsing pairs into (rem_poly, mod_poly) ...  
full_poly = crt(rems, mods)  
# ... convert full_poly back to bytes ...  
```

**Flag**:  
`ENO{CRC_is_just_some_modular_remainder}`
