---
title: "Field trip - Nullcon Berlin HackIM 2025 CTF"
category: "crypto"
subcategory: "discrete-log"
type: "writeup"
tags: ["crypto", "pohlig-hellman", "aes", "pollard-rho", "ecb", "discrete-log", "chinese-remainder", "factordb", "proof-of-work", "nullcon-berlin-hackim-2025-ctf", "2025", "ctf-writeup"]
summary: "When I first opened the challenge description it only said:"
source:
  name: "CTFtime writeup #40408"
  url: "https://ctftime.org/writeup/40408"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-09-05-field-trip-writeup"
ctf:
  name: "Nullcon Berlin HackIM 2025 CTF"
  year: 2025
  challenge: "Field trip"
---

## Metadata

- **CTF:** Nullcon Berlin HackIM 2025 CTF
- **Task:** Field trip
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crypto, pohlig-hellman
- **CTFtime:** <https://ctftime.org/writeup/40408>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-09-05-field-trip-writeup>

---
## Field trip - nullcon HackIM CTF Berlin 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/trip/image.png)

**Challenge:** Field trip  
**Category:** Crypto  
**Points:** 329  
**Author:** LTFZP

## Intro  
When I first opened the challenge description it only said:   
> “I recently went on a field trip and all I brought home was a bunch of numbers.”

At first glance it looked innocent. But of course, “numbers” in a crypto challenge usually mean trouble. Let’s see what we actually brought home.

## Scanning   
First things first, let's break down the provided [**[chal.py](http://chal.py)**](https://writeups.thebusfactoris1.online/assets/files/trip/[trip.py](http://trip.py)) script.  
```py  
#!/bin/python3  
from hashlib import sha256  
from Crypto.Util import number  
from Crypto.Cipher import AES

BITS = 224

# This is our irreducible polynomial for GF(2^224)  
f = 26959946667150639794667015087019630673637144422540572481103610249993  
g = 7 # The generator

# Custom functions for field arithmetic  
def reduce(a):  
while (l := a.bit_length()) > 224:  
a ^= f << (l - 225)  
return a

def mul(a,b):  
# ... implementation ...  
return reduce(res)

def pow(a,n):  
# ... implementation ...  
return res

if __name__ == '__main__':  
a = number.getRandomNBitInteger(BITS) # Alice's secret  
A = pow(g,a) # Alice's public key  
print(A)  
b = number.getRandomNBitInteger(BITS) # Bob's secret  
B = pow(g,b) # Bob's public key  
print(B)  
K = pow(A,b) # Shared secret  
assert K == pow(B,a)  
key = sha256(K.to_bytes(28)).digest() # AES key from shared secret  
flag = open('../meta/flag.txt','r').read().encode()  
# Encrypt the flag  
print(AES.new(key, AES.MODE_ECB).encrypt(flag + b'\x00' * (16 - len(flag) % 16)).hex())  
```

Okay, what are we looking at?

* It's a **Diffie-Hellman key exchange**. Alice and Bob (or in this case, the script itself) agree on a generator `g` and a field. They each pick a secret number (`a` and `b`), compute public keys (`A = g^a` and `B = g^b`), and then derive a shared secret `K`.  
* The math isn't happening modulo a prime `p`. Instead, it's happening in a **binary finite field**, GF(2   
224  
). The number `f` is the irreducible polynomial that defines this field. The custom `mul` and `reduce` functions implement polynomial multiplication and reduction.  
* The shared secret `K` is hashed with SHA256 to create an AES key, which then encrypts the flag.  
* The output file gives us the public keys `A`, `B`, and the encrypted flag.

Our task, is to find the secret exponent `a`. Once we have `a`, we can calculate the shared secret $K = B^a$, derive the AES key, and decrypt the flag. This is the classic **Discrete Logarithm Problem (DLP)**.

The group order is $|G| = 2^{224} - 1$. This number is massive (around $2.69 \\\times 10^{67}$). A direct attack is completely out of the question. We need a smarter approach.

## Process   
### Pohlig-Hellman  
When you see a `DLP` in a group with a huge, non-prime order, your first thought should be the [**Pohlig-Hellman algorithm**](<https://math.stackexchange.com/questions/3260409/solving-dlp-using-the-method-of-pohlig-hellman>). This algorithm is a lifesaver. It breaks down one massive DLP into several smaller, manageable DLPs. It works if the order of the group, $N = |G|$, can be factored into small prime powers.

The strategy is:

1\. **Factor the group order** $N = 2^{224} - 1$.  
2\. For each prime factor $p\\_i$ of $N$, solve the DLP in the subgroup of order $p\\_i$. This will give us $a \\\pmod{p\\_i}$.  
3\. Use the **Chinese Remainder Theorem (CRT)** to combine all the results ($a \\\pmod{p\\_i}$) to recover the full secret `a`.

### Step 1: Factoring the Order

Time to fire up an online tool like [`[factordb.com](http://factordb.com)`](<http://factordb.com/>). Factoring $N = 2^{224} - 1$ gives us:

```py  
{  
3: 0,  
5: 4,  
17: 4,  
29: 24,  
43: 32,  
113: 37,  
127: 125,  
257: 59,  
449: 286,  
2689: 1882,  
5153: 4699,  
65537: 64291,  
15790321: 965000,  
183076097: 103765144,  
54410972897: 15098735073  
}  
```

Most of these factors are small enough to deal with easily. However, we have one big boy at the end: $p\\_{big} = 358429848460993$.

### The Small Fries

For each small prime factor $p\\_i$, we need to find $a \\\pmod{p\\_i}$. The Pohlig-Hellman algorithm tells us how. We transform the original equation $A = g^a$ into a new one within a subgroup of order $p\\_i$.

Let $N = p\\_i \\\cdot m$. We can raise both sides to the power of $m$:  
$A^m = (g^a)^m = (g^m)^a$

Now, let $A' = A^m$ and $g' = g^m$. Our new problem is to find $a' = a \\\pmod{p\\_i}$ by solving $A' = (g')^{a'}$. This is a DLP in a much smaller group of order $p\\_i$. For the smaller factors, we can just brute-force this.

### Pollard's Rho

The largest prime factor, $p\\_{big} \\\approx 3.58 \\\times 10^{14}$, is too big for brute force. This is where we need a more advanced algorithm: [**Pollard's Rho algorithm**](https://writeups.thebusfactoris1.online/assets/files/trip/ph.pdf).

Pollard's Rho is an ingenious method for finding discrete logs with a time complexity of roughly $O(\\\sqrt{p})$, where $p$ is the order of the group. In our case, that's $O(\\\sqrt{p\\_{big}}) \\\approx \\\sqrt{3.58 \\\times 10^{14}} \\\approx 1.9 \\\times 10^7$ iterations. That's totally doable\\!

The algorithm works by taking a "pseudo-random walk" through the group and looking for a collision. This is often visualized using Floyd's cycle-finding algorithm, also known as the "tortoise and the hare." We have two pointers traversing the walk, one moving twice as fast as the other. When they land on the same value, we've found a cycle, and this collision gives us an equation that we can solve to find the discrete log.

Here's a simplified look at the Pollard's Rho implementation from the solver script to tackle the DLP in the subgroup of order $p\\_{big}$.  
```python  
def pollard_rho_log(g1, A1, order, ...):  
# This function defines the "random walk"  
def f(state):  
v, a, b = state  
# ... rules to update v, a, b based on v ...  
# e.g., v = mul(v, g1), v = mul(v, A1), or v = mul(v, v)  
return (v, a, b)

# Initialize tortoise and hare at the start of the walk  
tort = (v0, a0, b0)  
hare = f(tort)

while True:  
tort = f(tort)  
hare = f(f(hare)) # Hare moves twice as fast  
if tort[0] == hare[0]: # A collision!  
# ... solve for the discrete log using the exponents ...  
return x  
```

Running this takes a while (about 50 minutes on my machine\\!), but it eventually spits out the value of $a \\\pmod{p\\_{big}}$.

### Final Assembly

Now we have a system of congruences:

* $a \\\equiv a\\_1 \\\pmod{p\\_1}$  
* $a \\\equiv a\\_2 \\\pmod{p\\_2}$  
* ...  
* $a \\\equiv a\\_{big} \\\pmod{p\\_{big}}$

The [**Chinese Remainder Theorem (CRT)**](<https://en.wikipedia.org/wiki/Chinese_remainder_theorem)is> the perfect tool to stitch these pieces back together into the one and only solution for `a` modulo $N$.

### Decryption

With the full secret exponent `a` recovered, the rest is straightforward:

1\. Calculate the shared secret: $K = B^a$.  
2\. Hash it to get the AES key: `key = sha256(K_bytes).digest()`.  
3\. Initialize the AES cipher and decrypt the ciphertext.

Here's a solver script:  
```py  
from hashlib import sha256  
from Crypto.Cipher import AES  
import random, time, math

BITS = 224  
f_poly = 26959946667150639794667015087019630673637144422540572481103610249993  
g = 7

def reduce_field(a):  
while a.bit_length() > BITS:  
l = a.bit_length()  
a ^= f_poly << (l - 225)  
return a

def mul(a,b):  
res = 0  
bb = b  
i = 0  
while bb:  
if bb & 1:  
res ^= (a << i)  
bb >>= 1  
i += 1  
return reduce_field(res)

def pow_field(a, n):  
res = 1  
exp = a  
while n > 0:  
if n & 1:  
res = mul(res, exp)  
exp = mul(exp, exp)  
n >>= 1  
return res

A = 22740222493854193828995311834548386053886320984395671900304436279839  
B = 13537441615011702013355237281886711701217244531581593794890884829133  
ct = bytes.fromhex("9946ca81ffb1a741cff186a38ecbb4ddcf0e912764413642641fab7db83278a31268b5dc13e66cd86990ab1b65b73465")

q = 2**224 - 1

factors = [3,5,17,29,43,113,127,257,449,2689,5153,65537,15790321,183076097,54410972897,358429848460993]

residues = {  
3: 0,  
5: 4,  
17: 4,  
29: 24,  
43: 32,  
113: 37,  
127: 125,  
257: 59,  
449: 286,  
2689: 1882,  
5153: 4699,  
65537: 64291,  
15790321: 965000,  
183076097: 103765144,  
54410972897: 15098735073  
}

p_big = 358429848460993

def pollard_rho_log(g1, A1, order, max_iters=100_000_000):  
def f(state):  
v,a,b = state  
r = v & 0x7   
if r < 2:  
v = mul(v, g1)  
a = (a + 1) % order  
elif r < 4:  
v = mul(v, A1)  
b = (b + 1) % order  
elif r < 6:  
v = mul(v, v)  
a = (2*a) % order  
b = (2*b) % order  
else:  
v = mul(v, mul(g1, A1))  
a = (a + 1) % order  
b = (b + 1) % order  
return (v,a,b)

a0 = random.randrange(order)  
b0 = random.randrange(order)  
v0 = mul(pow_field(g1, a0), pow_field(A1, b0))  
tort = (v0, a0, b0)  
hare = f(tort)  
steps = 0  
while True:  
tort = f(tort)  
hare = f(f(hare))  
steps += 1  
if tort[0] == hare[0]:  
a1,b1 = tort[1], tort[2]  
a2,b2 = hare[1], hare[2]  
r = (a1 - a2) % order  
s = (b2 - b1) % order  
if s % order == 0:  
return None  
inv_s = pow(s, -1, order)  
x = (r * inv_s) % order  
return x  
if steps % 1000000 == 0:  
print("Pollard steps:", steps)  
if steps > max_iters:  
return None

print("Preparing subgroup for p_big...")  
exp = q // p_big  
g1 = pow_field(g, exp)  
A1 = pow_field(A, exp)  
print("Starting Pollard-Rho for p_big (order ~ {})".format(p_big))  
start = time.time()  
x_large = pollard_rho_log(g1, A1, p_big, max_iters=40_000_000) # adjust max_iters if needed  
elapsed = time.time() - start  
print("Pollard result:", x_large, "time:", elapsed, "seconds")

if x_large is None:  
print("Pollard failed or reached iteration limit. You can re-run with larger max_iters.")  
exit(0)

residues[p_big] = x_large  
print("Recovered residue:", x_large)

primes = list(residues.keys())  
moduli = primes  
remainders = [residues[p] for p in primes]

def crt_pair(a1, n1, a2, n2):  
m = pow(n1, -1, n2)  
t = ((a2 - a1) * m) % n2  
x = a1 + n1 * t  
return x % (n1*n2), n1*n2

x_total = remainders[0]  
M = moduli[0]  
for i in range(1, len(moduli)):  
x_total, M = crt_pair(x_total, M, remainders[i], moduli[i])

print("a (0 <= a < q):", x_total)

A_check = pow_field(g, x_total)  
print("A_check == A ?", A_check == A)

K = pow_field(B, x_total)  
K_bytes = K.to_bytes(28, 'big')  
key = sha256(K_bytes).digest()  
cipher = AES.new(key, AES.MODE_ECB)  
pt = cipher.decrypt(ct)  
pt = pt.rstrip(b'\x00')  
print("Plaintext (raw bytes):", pt)  
print("Plaintext:", None if b'\x00' in pt else pt.decode('utf-8', errors='replace'))  
```

Let's run the full solver.

```bash  
$ python3 [solve.py](http://solve.py)  
Starting Pollard-Rho for p_big (order ~ 358429848460993)  
Pollard steps: 1000000  
Pollard steps: 2000000  
Pollard steps: 3000000  
Pollard steps: 4000000  
Pollard steps: 5000000  
Pollard steps: 6000000  
Pollard steps: 7000000  
Pollard steps: 8000000  
Pollard steps: 9000000  
Pollard steps: 10000000  
Pollard steps: 11000000  
Pollard result: 17647135938227 time: 3009.7346289157867 seconds  
Recovered residue for p_big: 17647135938227  
Recovered exponent a (0 <= a < q): 19304722128197700500806739139164244735096547731206137123982781068619  
A_check == A ? True  
Plaintext (raw bytes): b'ENO{1t_i5_no1_th3_fi3ld_5iz3_th4t_c0unts}\n'  
Plaintext (utf-8, if text): ENO{1t_i5_no1_th3_fi3ld_5iz3_th4t_c0unts}  
```

Success\\! We got the flag. Turns out, it's not the field size that counts, but how you factor it. ?

## FLAG

```bash  
FLAG : ENO{1t_i5_no1_th3_fi3ld_5iz3_th4t_c0unts}  
```
