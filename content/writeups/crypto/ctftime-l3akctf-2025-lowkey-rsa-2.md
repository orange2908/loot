---
title: "Lowkey RSA - L3akCTF 2025"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["cryptography-rsa", "crypto", "rsa", "wiener", "proof-of-work", "low-exponent", "l3akctf", "l3akctf-2025", "2025", "ctf-writeup"]
summary: "Alright, let's talk about \"Lowkey RSA\"."
source:
  name: "CTFtime writeup #40345"
  url: "https://ctftime.org/writeup/40345"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-07-14-LowkeyRSA-writeup"
ctf:
  name: "L3akCTF 2025"
  year: 2025
  challenge: "Lowkey RSA"
---

## Metadata

- **CTF:** L3akCTF 2025
- **Task:** Lowkey RSA
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** cryptography-rsa, crypto
- **CTFtime:** <https://ctftime.org/writeup/40345>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-07-14-LowkeyRSA-writeup>

---
## Lowkey RSA - L3AK-CTF 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/lowkeyrsa/image.png)

**Challenge:** Lowkey RSA  
**Category:** Crypto  
**Points:** 50

### Introduction

Alright, let's talk about "Lowkey RSA". When I first saw this challenge, I thought, "Cool, another RSA problem. Probably some common factoring attack, maybe a small public exponent, or something with common factors." The name itself, "Lowkey RSA," and the description, "This RSA might lowkey be insecure, no cap fr fr," definitely hinted that something was intentionally weak. But as I dove into the source code, I realized it wasn't going to be that straightforward. This challenge took me on a fun little mathematical rollercoaster, from head-scratching confusion to that amazing "aha!" moment when it all finally clicks.

### The Journey: From "Huh?" to "Gotcha!"

Let's walk through the thought process, because the final script hides all the fun trial-and-error.

**1. First Glance: "Okay, It's... Weird RSA"**

I opened [`[lowkey-rsa.py](http://lowkey-rsa.py)`](https://writeups.thebusfactoris1.online/assets/files/lowkeyrsa/image.png) and saw the usual suspects: `e`, `N`, and `c`. But then my eyes caught this line:

```python  
phi = (p**4-1)*(q**4-1)  
```

Wait, what? That's not the standard Euler's totient function, `phi = (p-1)*(q-1)`. My first thought was, "Is this a typo? Or some exotic variant of RSA?" This was the first major red flag that this wasn't a textbook problem.

**2. The Key Generation: The Plot Thickens**

Next, I looked at how `e` was generated.

```python  
e = inverse_mod(phi-d, phi)  
```

This looked intentionally cryptic. Time for some modulo arithmetic to simplify it.  
If `e` is the inverse of `(phi - d)` modulo `phi`, it means:

`e * (phi - d) ≡ 1 (mod phi)`

Let's expand that:

`e * phi - e * d ≡ 1 (mod phi)`

Since `e * phi` is a multiple of `phi`, it's equivalent to `0` in `mod phi`. So:

`-e * d ≡ 1 (mod phi)`

Which is the same as:

`e * d ≡ -1 (mod phi)`

This is a breakthrough! It means that `e * d` is one less than a multiple of `phi`. We can write this as an equation with an integer `k`:

`e * d = k * phi - 1`

**3. The "Lowkey" Clue and Wiener's Attack**

This equation, `e * d = k * phi - 1`, looked incredibly familiar. It's the core relationship exploited in **Wiener's Attack**, which works when the private exponent `d` is small.

But wait, in our case, `d` isn't the private exponent. It's just some parameter. However, the challenge name is "Lowkey," and the source code explicitly makes `d` small:

```python  
d = randint(1, round(sqrt(t)) - 1)  
```

The expression for `t` is a complicated mess, but the intent is clear: `d` is small. The puzzle pieces were starting to fit together. We have a small integer `d` in an equation that looks just like the one from Wiener's attack.

We can rearrange our equation:

`e * d + 1 = k * phi` => `(e * d + 1) / k = phi`

And if we divide by `phi`:

`e / phi ≈ k / d`

This is it! This is the classic setup for a **continued fraction attack**. If `d` is small enough, then `k/d` is a very good rational approximation of `e/phi`.

**4. The `phi` Problem and the Final Attack Plan**

There's one big problem: we don't know `phi`. But can we approximate it?

`phi = (p⁴-1)(q⁴-1) = p⁴q⁴ - p⁴ - q⁴ + 1`

Since `p` and `q` are large primes, `p⁴` and `q⁴` are massive. We can say that `p⁴-1` is *very* close to `p⁴`, and `q⁴-1` is *very* close to `q⁴`.

So, `phi ≈ p⁴q⁴ = (pq)⁴ = N⁴`.

This is a good start, but we can do better. Let's expand `phi` again:  
`phi = N⁴ - (p⁴ + q⁴) + 1`.  
A better approximation for `p⁴ + q⁴` is `2N²`. This leads to a much better `phi` approximation:  
`phi_approx = N⁴ - 2N² + 1 = (N²-1)²`.

This was the final key. With this approximation, I could build the attack:

1\. **Approximate:** Calculate `phi_approx = (N**2 - 1)**2`.  
2\. **Attack:** Run the continued fraction algorithm on `e / phi_approx` to get a list of convergents (approximations) `k/d`.  
3\. **Test:** For each `(k, d)` pair, calculate a `phi_candidate = (e * d + 1) // k`.  
4\. **Solve:** Use this `phi_candidate` to find `p` and `q`. We know `p⁴ + q⁴ = N⁴ - phi_candidate + 1`. This lets us form a quadratic equation `z² - (p⁴+q⁴)z + (p⁴q⁴) = 0`, where the roots are `p⁴` and `q⁴`.  
5\. **Verify:** Check if the roots are perfect fourth powers. If they are, we get `p` and `q`. The final check is to see if `p * q == N`. If it all works, we've factored `N`!  
6\. **Decrypt:** With `p` and `q`, we can calculate the *real* private key `d_priv` using the standard totient and decrypt the message.

This plan worked perfectly and revealed the flag.

### The Final Solution

This is the Python script that implements the attack described above.

```python  
import gmpy2  
from Crypto.Util.number import long_to_bytes

e = 370641246943654763647982436393968410523035056803076571952063446221981....  
N = 102220140627681259226019620046863611364476585.......  
c = 43231841965942801407608738887........

def solve():  
print("[*] Starting Wiener-like attack...")

phi_approx = (N**2 - 1)**2  
print("[*] Approximating phi...")

print("[*] Finding (k, d) wit continued fractions...")  
num = e  
den = phi_approx  
k_prev, d_prev = 0, 1  
k_curr, d_curr = 1, 0  
  
p_found, q_found = None, None

while den != 0:  
a, remainder = divmod(num, den)  
num, den = den, remainder  
  
k_next = a * k_curr + k_prev  
d_next = a * d_curr + d_prev  
k_prev, d_prev = k_curr, d_curr  
k_curr, d_curr = k_next, d_next

k, d = k_curr, d_curr

if k == 0 or d == 0:  
continue

if (e * d + 1) % k == 0:  
phi_candidate = (e * d + 1) // k  
  
P_plus_Q = N**4 - phi_candidate + 1  
  
discriminant = P_plus_Q**2 - 4 * (N**4)  
if discriminant >= 0:  
sqrt_discriminant = gmpy2.isqrt(discriminant)  
if sqrt_discriminant**2 == discriminant:  
P = (P_plus_Q + sqrt_discriminant) // 2  
Q = (P_plus_Q - sqrt_discriminant) // 2   
p_cand, p_is_perfect = gmpy2.iroot(P, 4)  
if p_is_perfect:  
q_cand, q_is_perfect = gmpy2.iroot(Q, 4)  
if q_is_perfect:  
if p_cand * q_cand == N:  
p_found = p_cand  
q_found = q_cand  
print("\n[+] P And Q Factor Found!")  
print(f" > p = {p_found}")  
print(f" > q = {q_found}")  
break   
if p_found and q_found:  
print("\n[*] Decrypting")   
phi_std = (p_found - 1) * (q_found - 1)  
  
d_priv = gmpy2.invert(e, phi_std)  
  
m = pow(c, d_priv, N)  
  
flag = long_to_bytes(m)   
print(f"Flag: {flag.decode('utf-8')}")  
else:  
print("\n[-] Failed")

if __name__ == '__main__':  
solve()  
```  
```bash  
python3 [lowkeyrsa.py](http://lowkeyrsa.py)  
[*] Starting Wiener-like attack...  
[*] Approximating phi...  
[*] Finding (k, d) wit continued fractions...

[+] P And Q Factor Found!  
> p = 38744845630229096973223564078774890632168139978141962677044971931180793166793401934  
57338651072052279492626914668259535884521069809739439009166898918784261 > q = 26382900477458125043920894322225379241125953196389554679901635270856200294942187137  
37790740237119243610722880728776987283256391634009123635310812720036889   
[*] Decrypting  
Flag: L3AK{L0wK3y_Th1S_RSA_i5_kiNda_ScuFf3D_LmA0}  
```  
### Flag  
```bash  
flag: L3AK{L0wK3y_Th1S_RSA_i5_kiNda_ScuFf3D_LmA0}  
```
