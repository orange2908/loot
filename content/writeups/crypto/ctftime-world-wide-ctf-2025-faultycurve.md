---
title: "FaultyCurve - World Wide CTF 2025"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "crytography", "ecc", "sage", "discrete-log", "singular-curve", "quadratic-residue", "world-wide-ctf", "world-wide-ctf-2025", "2025", "ctf-writeup"]
summary: "Ah, another Elliptic Curve challenge!"
source:
  name: "CTFtime writeup #40367"
  url: "https://ctftime.org/writeup/40367"
original_source: "https://writeups.thebusfactoris1.online/posts/2025-07-28-FaultyCurve-writeup"
ctf:
  name: "World Wide CTF 2025"
  year: 2025
  challenge: "FaultyCurve"
---

## Metadata

- **CTF:** World Wide CTF 2025
- **Task:** FaultyCurve
- **Author team:** The Bus Factor is 1:
- **CTFtime tags:** crytography
- **CTFtime:** <https://ctftime.org/writeup/40367>
- **Original writeup:** <https://writeups.thebusfactoris1.online/posts/2025-07-28-FaultyCurve-writeup>

---
## FaultyCurve - World Wide CTF 2025 Write-up

![Banner](https://writeups.thebusfactoris1.online/assets/files/faculty/image.jpg)

**Challenge:** FaultyCurve  
**Category:** Cryptography  
**Points:** 436

### Introduction

Ah, another Elliptic Curve challenge! At first glance, this ([`[chall.py](http://chall.py)`](https://writeups.thebusfactoris1.online/assets/files/faculty/[chall.py](http://chall.py))) looked like a classic Elliptic Curve Discrete Logarithm Problem (ECDLP). We're given the curve parameters `p` and `a`, the x-coordinate of a generator point `G`, and the x-coordinate of a public key `Q`, where `Q = flag * G`. Our mission, should we choose to accept it, is to find the `flag`.

Normally, this would be computationally infeasible. But the challenge author, Warri, left us a delicious breadcrumb in the source code:

```python  
# EllipticCurve(GF(p), [a,b]) in sage gives an error for some reason :sob:  
# Some error in /src/sage/schemes/elliptic_curves but i'm too nub to figure out why :sob: :sob:  
```

This isn't just flavor text; it's the entire key to the challenge. If SageMath, the powerhouse of computational mathematics, can't even initialize the curve, it means the curve is broken. In the world of elliptic curves, "broken" usually means it's **singular**. This vulnerability turns an impossible problem into a solvable one. Let's dive in!

### The Journey to the Flag: A Tale of Trial and Error

#### Step 1: Unmasking the Curve

A standard elliptic curve `y² = x³ + ax + b` is non-singular, meaning its discriminant, `Δ = -16(4a³ + 27b²)`, is non-zero. If the curve is singular, `Δ = 0`, which implies `4a³ + 27b² ≡ 0 (mod p)`.

We have `p` and `a`, but not `b`. However, with the singularity condition, we can solve for `b`:

`b² ≡ -4a³ * (27⁻¹) (mod p)`

This gives us two potential candidates for `b` (let's call them `b` and `-b`). To find the correct one, we use the fact that the generator point `G` must lie on the curve. This means `Gx³ + a*Gx + b` must be a quadratic residue modulo `p` (i.e., it must have a square root, which would be `Gy`). A quick check with the given `Gx` revealed the correct value for `b`.

#### Step 2: The First Wrong Turn (Cuspidal Confusion)

Singular curves come in two main flavors: cuspidal and nodal. My first assumption was that we were dealing with a **cuspidal curve**.

**The Theory:** On a cuspidal curve, the group of non-singular points is isomorphic to the *additive group* `(GF(p), +)`. This means we can map points from the tricky elliptic curve group to the simple additive group of the finite field, where the DLP becomes trivial division. The mapping is given by `ψ(x, y) = (x - x₀) / y`, where `(x₀, 0)` is the singular point.

**The (Failed) Attack:**  
1\. Find the singular point `(x₀, 0)` by solving `3x₀² + a = 0`. This gives two possibilities for `x₀`.  
2\. Find the `y` coordinates for `G` and `Q`. Again, two possibilities for each (a positive and negative root).  
3\. Apply the transformation: `Q = flag * G` becomes `ψ(Q) = flag * ψ(G)`.  
4\. Solve for the flag: `flag = ψ(Q) / ψ(G)`.

I wrote a Sage script to iterate through all possible combinations of `x₀`, `Gy`, and `Qy`. I ran it, full of hope, and... nothing. It cycled through every combination and found no valid flag.

This was a classic moment. The logic was sound *if* the curve was cuspidal. The failure meant my initial assumption was wrong. It was time to pivot.

#### Step 3: The "Aha!" Moment (Nodal Power)

If it's not cuspidal, it must be **nodal**.

**The Theory:** On a nodal curve, the group of non-singular points is isomorphic to the *multiplicative group* `(GF(p)*, *)`. This is a different, but still very solvable, transformation. The mapping involves the slopes of the two tangent lines at the singular point. The isomorphism is `ψ(P) = (y - m(x-x₀)) / (y + m(x-x₀))`.

**The Correct Attack:**  
1\. The singular point `x₀` and the y-coordinates are found the same way.  
2\. Find the slopes `m` of the tangents at the singular point by solving `m² = 3x₀`.  
3\. Apply the new transformation: `Q = flag * G` becomes `ψ(Q) = ψ(G)^flag`.  
4\. This is a standard discrete logarithm problem in `GF(p)`. We can solve for the flag using Sage's built-in `log` function: `flag = log(ψ(Q), ψ(G))`.

I modified the script with the new logic and ran it again. This time, it hit! The script started spitting out valid flag candidates. The first one was garbage, but by iterating through the different sign choices for the coordinates and slopes, the correct flag finally appeared.

#### Step 4: One Last Bug

Just as I was about to celebrate, my first working script crashed with one final, cryptic error:  
`AttributeError: 'sage.rings.integer.Integer' object has no attribute 'to_bytes'`

It turns out that SageMath's `log` function returns a special Sage `Integer` type, not a standard Python `int`. This Sage type doesn't have the `.to_bytes()` method needed to convert the number back into the flag string.

The fix was laughably simple: just cast the result to a Python `int` before the conversion.  
`py_flag = int(flag_candidate)`

With that final tweak, the script ran perfectly and delivered the prize.

### The Final Solution

The key was correctly identifying the curve as a nodal singular curve and applying the corresponding isomorphism to the multiplicative group of the finite field. The ECDLP was transformed into a regular DLP, which was easily solved.

Here is the final, working Sage script:

```sage  
p = 3059506932006842768669313045979965122802573567548630439761719809964279577239571933  
a = 2448848303492708630919982332575904911263442803797664768836842024937962142592572096  
Gx = 3  
Qx = 1461547606525901279892022258912247705593987307619875233742411837094451720970084133

Fp = GF(p)  
a = Fp(a)  
Gx = Fp(Gx)  
Qx = Fp(Qx)

def point_add(P, Q, a, p_int):  
F = GF(p_int)  
a = F(a)  
if P is None:  
return Q  
if Q is None:  
return P  
x1, y1 = F(P[0]), F(P[1])  
x2, y2 = F(Q[0]), F(Q[1])

if x1 == x2 and (y1 != y2 or y1 == 0):  
return None  
if x1 == x2:  
m = (3 * x1 * x1 + a) * (2 * y1)^-1  
else:  
m = (y2 - y1) * (x2 - x1)^-1  
x3 = m * m - x1 - x2  
y3 = m * (x1 - x3) - y1  
return (Integer(x3), Integer(y3))

def point_mul(k, P, a, p_int):  
R0 = None  
R1 = P  
for bit in bin(k)[2:]:  
if bit == '0':  
R1 = point_add(R0, R1, a, p_int)  
R0 = point_add(R0, R0, a, p_int)  
else:  
R0 = point_add(R0, R1, a, p_int)  
R1 = point_add(R1, R1, a, p_int)  
return R0

print("[+] Step 1: Assuming singularity and finding b")  
inv27 = Fp(27)^-1  
b_squared = -4 * a^3 * inv27

if not b_squared.is_square():  
print("[-] Error: Exiting.")  
exit()

b1 = b_squared.sqrt()  
b2 = -b1  
print(" Found two possible values for b.")

# The point G must be on the curve, so Gx^3 + a*Gx + b must be a square (so Gy exists).  
print("\n[+] Finding the correct value of b")  
b = None  
rhs_G_b1 = Gx^3 + a*Gx + b1  
if rhs_G_b1.is_square():  
b = b1  
print(" Selected b1.")  
elif (Gx^3 + a*Gx + b2).is_square():  
b = b2  
print(" Selected b2.")  
else:  
print("[-] Error: Exiting.")  
exit()

# 3. Find the singular point (x0, 0)  
# It satisfies 3*x0^2 + a = 0  
print("\n[+] Finding the singular point (x0, 0)")  
inv3 = Fp(3)^-1  
x0_squared = -a * inv3  
if not x0_squared.is_square():  
print("[-] Error: Exiting.")  
exit()

x0_1 = x0_squared.sqrt()  
x0_2 = -x0_1  
print(" Found two possible values for x0.")

# 4. Find the y-coordinates for G and Q  
print("\n[+] Finding y-coordinates for G and Q")  
rhs_G = Gx^3 + a*Gx + b  
Gy1 = rhs_G.sqrt()  
Gy2 = -Gy1

rhs_Q = Qx^3 + a*Qx + b  
if not rhs_Q.is_square():  
print("[-] Qx is not on the curve with the determined b. Exiting.")  
exit()  
Qy1 = rhs_Q.sqrt()  
Qy2 = -Qy1  
print(" Found y-coordinates.")

# 5. The curve is a Nodal Curve. We find the isomorphism to (Fp*, *) and solve the DLP.  
print("\n[+] Step 5: Solving for the flag using Nodal Curve isomorphism")  
for x0 in [x0_1, x0_2]:  
# For a nodal curve, the slopes of the tangents at the singular point are m = +/-sqrt(3*x0)  
m_squared = 3 * x0  
if not m_squared.is_square():  
continue  
  
m = m_squared.sqrt()  
  
for slope in [m, -m]:  
for Gy in [Gy1, Gy2]:  
for Qy in [Qy1, Qy2]:  
print(f" Trying combination: x0={Integer(x0)}, slope sign={'+' if slope==m else '-'}, Gy sign={'+' if Gy==Gy1 else '-'}, Qy sign={'+' if Qy==Qy1 else '-'}")  
den_G = Gy + slope * (Gx - x0)  
den_Q = Qy + slope * (Qx - x0)

if den_G == 0 or den_Q == 0:  
continue

num_G = Gy - slope * (Gx - x0)  
num_Q = Qy - slope * (Qx - x0)  
  
psi_G = num_G / den_G  
psi_Q = num_Q / den_Q

# The relation is psi(Q) = psi(G)^flag. We can solve with discrete log.  
if psi_G == 0 or psi_G == 1 or psi_Q == 0:  
continue

try:  
flag_candidate = psi_Q.log(psi_G)  
except (ValueError, ZeroDivisionError):  
continue

G_point = (Integer(Gx), Integer(Gy))  
Q_cand_point = point_mul(flag_candidate, G_point, Integer(a), p)

if Q_cand_point is not None and Q_cand_point[0] == Integer(Qx):  
print("\n[+] Found a valid flag candidate that produces the correct Qx.")  
# Convert Sage Integer to Python int before calling .to_bytes()  
py_flag = int(flag_candidate)  
if py_flag > 0:  
flag_bytes = py_flag.to_bytes((py_flag.bit_length() + 7) // 8, 'big')  
print(f"\n[*] Flag (int): {py_flag}")  
print(f"[*] Flag (hex): {hex(py_flag)}")  
print(f"[*] Flag (bytes): {flag_bytes}")  
try:  
decoded_flag = flag_bytes.decode('ascii')  
if decoded_flag.startswith("wwf{"):  
print(f"\n\n>>> Found Flag: {decoded_flag} <<<\n")  
exit()  
except UnicodeDecodeError:  
print("Wrong flag")  
  
print("\n[-] fuck")  
```

```bash  
sage cr.sage  
[+] Step 1: Assuming singularity and finding b  
Found two possible values for b.  
[+] Finding the correct value of b  
Selected b1.  
[+] Finding the singular point (x0, 0)  
Found two possible values for x0.  
[+] Finding y-coordinates for G and Q  
Found y-coordinates.  
[+] Step 5: Solving for the flag using Nodal Curve isomorphism  
Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=+, Gy sign=+, Qy sign=+ Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=+, Gy sign=+, Qy sign=- Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=+, Gy sign=-, Qy sign=+ Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=+, Gy sign=-, Qy sign=- Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=-, Gy sign=+, Qy sign=+ Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=-, Gy sign=+, Qy sign=- Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=-, Gy sign=-, Qy sign=+ Trying combination: x0=226770143609168095988944120625835438848563372707012403  
356916078083579353641057787, slope sign=-, Gy sign=-, Qy sign=- Trying combination: x0=283273678839767467268036892535412968395401019484161803  
6404803731880700223598514146, slope sign=+, Gy sign=+, Qy sign=+   
[+] Found a valid flag candidate that produces the correct Qx.

[*] Flag (int): 30594528958157542913038141798069794644136547961046562706018762402  
14102822645935199 [*] Flag (hex): 0x6735f36dd4b66263b928440d040894acb75e87d066e94dd99284da66f214637  
82c5f [*] Flag (bytes): b'g5\xf3m\xd4\xb6bc\xb9(D\r\x04\x08\x94\xac\xb7^\x87\xd0f\xe9M\  
xd9\x92\x84\xdaf\xf2\x14cx,_' Wrong flag  
Trying combination: x0=283273678839767467268036892535412968395401019484161803  
6404803731880700223598514146, slope sign=+, Gy sign=+, Qy sign=-   
[+] Found a valid flag candidate that produces the correct Qx.

[*] Flag (int): 54036191088477365498866172985658388918771443974169159843569750176  
754593636733   
[*] Flag (hex): 0x7777667b737570337273316e67756c34725f3173306d3072706831356d73217  
d   
[*] Flag (bytes): b'wwf{sup3rs1ngul4r_1s0m0rph15ms!}'  
>>> Found Flag: wwf{sup3rs1ngul4r_1s0m0rph15ms!} <<<  
```  
### FLAG  
```  
FLAG : wwf{sup3rs1ngul4r_1s0m0rph15ms!}  
```
