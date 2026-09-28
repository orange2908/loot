---
title: "Copperbox - Cyber Apocalypse CTF 2025: Tales from Eldoria"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "coppersmith", "lll", "lattice", "sage", "lcg", "prng", "proof-of-work", "rsa", "cyber-apocalypse-ctf-2025-tale", "cyber-apocalypse-ctf-2025-tales-fr", "2025", "ctf-writeup"]
summary: "We are given the following Python source code that encrypts the flag:"
source:
  name: "CTFtime writeup #40217"
  url: "https://ctftime.org/writeup/40217"
original_source: "https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/copperbox/"
ctf:
  name: "Cyber Apocalypse CTF 2025: Tales from Eldoria"
  year: 2025
  challenge: "Copperbox"
---

## Metadata

- **CTF:** Cyber Apocalypse CTF 2025: Tales from Eldoria
- **Task:** Copperbox
- **Author team:** Watch4Hack
- **CTFtime:** <https://ctftime.org/writeup/40217>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/htb-cyber-apocalypse/copperbox/>

---
We are given the following Python source code that encrypts the flag:

`

```
    import secrets
    
    p = 0x31337313373133731337313373133731337313373133731337313373133732ad
    a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
    b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
    
    def lcg(x, a, b):
        while True:
            yield (x := a*x + b)
    
    flag = open('flag.txt', 'rb').read()
    x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')
    gen = lcg(x, a, b)
    
    h1 = next(gen) * pow(next(gen), -1, p) % p
    h2 = next(gen) * pow(next(gen), -1, p) % p
    
    with open('output.txt', 'w') as o:
        trunc = 48
        # oops, i forgot the last part
        o.write(f'hint1 = {h1 >> trunc}\n')
        o.write(f'hint2 = {h2 >> trunc}\n')
```

`

And we also have the `output.txt` file:

`

```
    hint1 = 77759147870011250959067600299812670660963056658309113392093130
    hint2 = 50608194198883881938583003429122755064581079722494357415324546
```

`

## Source code analysis

Luckily for us, the code is short. It starts by defining three integer numbers ,  and , which are used to define a generator `lcg`:

`

```
    p = 0x31337313373133731337313373133731337313373133731337313373133732ad
    a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
    b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
    
    def lcg(x, a, b):
        while True:
            yield (x := a*x + b)
```

`

The above generator implemente a Linear Congruential Generator (LCG), which is normaly used as a pseudo-random number generator (PRNG). For instance, Glibc and Java use LCG-based PRNGs.

The seed of the LCG is the flag as an integer value with some random bytes at the end:

`

```
    flag = open('flag.txt', 'rb').read()
    x = int.from_bytes(flag + secrets.token_bytes(30-len(flag)), 'big')
    gen = lcg(x, a, b)
```

`

Then, the program computes two values `h1` and `h2` that depend on the LCG steps (4 steps in total):

`

```
    h1 = next(gen) * pow(next(gen), -1, p) % p
    h2 = next(gen) * pow(next(gen), -1, p) % p
```

`

Finally, we are given truncated values of these `h1` and `h2`. Particularly, the program removes the 48 least significant bits:

`

```
    with open('output.txt', 'w') as o:
        trunc = 48
        # oops, i forgot the last part
        o.write(f'hint1 = {h1 >> trunc}\n')
        o.write(f'hint2 = {h2 >> trunc}\n')
```

`

### Linear Congruential Generator

Let’s define the LCG in math terms as follows:

Notice that we are missing the “Congruential” part of the LCG because there is no modulus.

The LCG steps are usually defined in a recursive way, but we can transform the expression:

With this, we have expressed the LCG steps in terms of the initial seed :

Notice that LCGs are not secure, because leaking a single  will allow to recover previous states and to predict future steps. For this reason, the steps of the LCGs are usually truncated, in order to prevent adversaries from cracking the PRNG (or at least, making it more difficult to crack).

### Analyzing the output

Let’s express  in math terms:

If we expand the values  and , we get

We can do the same with , which depends on  and :

But we are not given  nor … That would be too easy. Instead, we have:

## Solution

Whenever you see truncated outputs in a cryptography CTF challenge, it is very likely that the solution is related to [Coppersmith method](https://en.wikipedia.org/wiki/Coppersmith_method) or some lattice-reduction technique. Indeed, the challenge name is Copperbox, which suggests the use of Coppersmith method.

For this, we need to define one or more polynomials modulo an integer such that there is a small root modulo a divisor of the modulo. This time, the modulo  is a prime number, so we don’t have to worry about it.

This small root will be found by Coppersmith method. Technique employs lattice reduction to find another polynomial that shares the same root with the provided modular polynomial. However, the new polynomial is defined in the integers, so computing solutions is efficient.

So, let’s see what values we are missing. Basically,

  * Initial seed  (the flag)
  * Truncated value from  (48 bits). Let it be 
  * Truncated value from  (48 bits). Let it be 


Hence, we can express:

At this point, we can substitute the above values in the previous expressions. To improve readability, let , and also , , so

So far, so good. But let’s get rid of the modular inverse by multyplying in both sides:

Now, we can group variables:

We are left with three variables and two equations. If we didn’t have more information about this system, it would not be solvable. However, this time we know that , so they are short values compared to ,  or . These  are good candidates to look for small roots. Notice that  can be large, since it is a flag (usually around 30 characters, so around ).

One trick is to eliminate the  variable in the equations by combining the two of them. Since the expressions are a bit long, let

So, we start with

Then, we put the same coefficient on variable :

Now we subtract both equations:

Notice that we can simplify a bit the expression and remove the :

So we have found a single equation on variables  and . Now we can easily define the polynomial:

Notice that , so it is a root, and indeed small because they are bounded by . As a result, we can use a bivariate Coppersmith method to find both values. Once we have them, it is trivial to find :

  * First we find :


  * Next, we solve for :


And with this, we find the flag .

### Implementation

In SageMath, we can define the variables  and  in , define the auxiliary values and then define the polynomial :

`

```
    #!/usr/bin/env sage
    
    p = 0x31337313373133731337313373133731337313373133731337313373133732ad
    a = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
    b = 0xdeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de
    
    trunc = 48
    
    hint1 = 77759147870011250959067600299812670660963056658309113392093130
    hint2 = 50608194198883881938583003429122755064581079722494357415324546
    
    
    Y, Z = PolynomialRing(Zmod(p), 'Y, Z').gens()
    
    A = [sum(a ** m for m in range(i + 1)) for i in range(4)]
    
    H1 = hint1 << trunc
    H2 = hint2 << trunc
    
    HY = a * H1 + a * Y - 1
    HZ = a * H2 + a * Z - 1
    
    P = a ** 2 * HZ * ((H1 + Y) * A[1] - A[0]) - HY * ((H2 + Z) * A[3] - A[2])
```

`

Now, we use Coppersmith method to compute the small roots  and . I will be using [defund](https://github.com/defund/coppersmith/blob/master/coppersmith.sage)’s implementation:

`

```
    load('coppersmith.sage')
    y, z = small_roots(P, (2 ** trunc, 2 ** trunc))[0]
    print(f'{y = }; {z = }')
```

`

Finally, we compute the  value to get the flag:

`

```
    h1 = H1 + y
    h2 = H2 + z
    
    x = b * (A[0] - A[1] * h1) * pow(a ** 2 * h1 - a, -1, p) % p
    assert x == b * (A[2] - A[3] * h2) * pow(a ** 4 * h2 - a ** 3, -1, p) % p
    
    print(bytes.fromhex(hex(x)[2:]))
```

`

## Flag

If we run the script, we will get the flag (a nice easter egg is that the random padding `L\xc6` looks like LCG):

`

```
    $ sage solve.sage
    y = 53006259096585; z = 248699398699637
    b'HTB{sm1th1ng_mY_c0pp3r_fl4G}L\xc6'
```

`

The full script can be found in here: [`solve.sage`](https://github.com/7Rocky/CTF-scripts/blob/main/HTB%20Cyber%20Apocalypse/Crypto/Copperbox/solve.sage).
