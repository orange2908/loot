---
title: "マスタースパーク - SekaiCTF 2024"
category: "crypto"
subcategory: "ecc"
type: "writeup"
tags: ["crypto", "ecc", "sage", "pohlig-hellman", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "We are given a SageMath script called challenge.sage:"
source:
  name: "CTFtime writeup #39408"
  url: "https://ctftime.org/writeup/39408"
original_source: "https://7rocky.github.io/en/ctf/other/sekaictf/マスタースパーク/"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "マスタースパーク"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** マスタースパーク
- **Author team:** ICAI Cyber Team
- **CTFtime:** <https://ctftime.org/writeup/39408>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/sekaictf/マスタースパーク/>

---
We are given a SageMath script called `challenge.sage`:

`

```
    from Crypto.Util.number import *
    import os
    from timeout_decorator import timeout, TimeoutError
    
    load("GA.sage")
    
    FLAG = os.getenv("FLAG")
    secret = getPrime(256)
    choice = set()
    
    
    @timeout(60)
    def T_T(p, primes, secret):
    
        assert isPrime(p)
        assert len(primes) > 3
    
        Fp = GF(p)
        Fp2.<j> =  GF(p ^ 2, modulus=x ^ 2 + 1)
        ls = len(factor(p + 1)) - 2
    
        m = ceil((sqrt(p) ** (1 / ls) - 1) / 2)
        alice_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
        bob_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
        EC = montgomery(Fp2, 0)
        P = EC.gens()[0]
        k = 1
        alice_pub, Q = group_action(p, primes, Fp, Fp2, 0, alice_priv, k * P)
        share_bob, Q = group_action(p, primes, Fp, Fp2, alice_pub, bob_priv, secret * Q)
        bob_pub, P = group_action(p, primes, Fp, Fp2, 0, bob_priv, P)
        share_alice, P = group_action(p, primes, Fp, Fp2, bob_pub, alice_priv, P)
        return P, Q
    
    
    def check(p):
        assert isPrime(p)
        assert p.bit_length() <= 96
        assert ((p + 1) // 4) % 2 == 1
        prime_list = []
        cnt = 0
    
        for p, i in factor((p + 1) // 4):
            assert not p in choice
            if i > 1:
                cnt += 1
                choice.add(p)
                assert int(p).bit_length() <= 32
            else:
                prime_list.append(p)
                choice.add(p)
    
        assert all([int(p).bit_length() <= 16 for p in prime_list])
        assert cnt == 1
    
        return prime_list
    
    
    def main():
        while True:
            try:
                p = int(input("input your prime number or secret > "))
                if int(p).bit_length() == 256:
                    if p == secret:
                        print(FLAG)
                        exit()
                    print("not flag T_T")
                else:
                    prime_list = check(p)
                    P, Q = T_T(p, prime_list, secret)
                    print(P.xy())
                    print(Q.xy())
            except:
                print("T_T")
                exit()
    main()
```

`

Moreover, we have `GA.sage` with some functions used by the main script:

`

```
    from random import randint
    
    # I received advice from Mitsu to write this program. I appreciate it very much
    
    def montgomery(Fp2, A):
        return EllipticCurve(Fp2, [0, A, 0, 1, 0])
    
    def to_montgomery(Fp, Fp2, E, G):
        Ep = E.change_ring(Fp).short_weierstrass_model()
        a, b = Ep.a4(), Ep.a6()
        P.<x> = PolynomialRing(Fp)
        r = (x^3 + a*x + b).roots()[0][0]
        s = sqrt(3 * r^2 + a)
        if not is_square(s):
            s = -s
        A = 3 * r / s
        phi = E.isomorphism_to(EllipticCurve(Fp2, [0, A, 0, 1, 0]))
        return Fp(A), phi(G)
    
    def group_action(p, primes, Fp, Fp2, pub, priv, G):
        E = montgomery(Fp2, pub)
        es = priv[:]
        while any(es):
            x = Fp.random_element()
            P = E.lift_x(x)
            s = 1 if P[1] in Fp else -1
            S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
            k = prod([primes[i] for i in S])
            Q = ((p + 1) // k) * P
            
            for i in S:
                R = (k // primes[i]) * Q
                if R.is_zero():
                    continue
                phi = E.isogeny(R)
                E = phi.codomain()
                Q, G = phi(Q), phi(G)
                es[i] -= s
                k //= primes[i]
        return to_montgomery(Fp, Fp2, E, G)
```

`

## Source code analysis

In this challenge, we are allowed to enter prime numbers, with some properties, that will be used for a key exchange protocol:

`

```
    def main():
        while True:
            try:
                p = int(input("input your prime number or secret > "))
                if int(p).bit_length() == 256:
                    if p == secret:
                        print(FLAG)
                        exit()
                    print("not flag T_T")
                else:
                    prime_list = check(p)
                    P, Q = T_T(p, prime_list, secret)
                    print(P.xy())
                    print(Q.xy())
            except:
                print("T_T")
                exit()
```

`

The key exchange protocol is implemented in `T_T`:

`

```
    @timeout(60)
    def T_T(p, primes, secret):
    
        assert isPrime(p)
        assert len(primes) > 3
    
        Fp = GF(p)
        Fp2.<j> =  GF(p ^ 2, modulus=x ^ 2 + 1)
        ls = len(factor(p + 1)) - 2
    
        m = ceil((sqrt(p) ** (1 / ls) - 1) / 2)
        alice_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
        bob_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
        EC = montgomery(Fp2, 0)
        P = EC.gens()[0]
        k = 1
        alice_pub, Q = group_action(p, primes, Fp, Fp2, 0, alice_priv, k * P)
        share_bob, Q = group_action(p, primes, Fp, Fp2, alice_pub, bob_priv, secret * Q)
        bob_pub, P = group_action(p, primes, Fp, Fp2, 0, bob_priv, P)
        share_alice, P = group_action(p, primes, Fp, Fp2, bob_pub, alice_priv, P)
        return P, Q
```

`

### CSIDH

As can be seen, it defines an elliptic curve over . Specifically, this is a supersingular elliptic curve. Then, the key exchange protocol is based on group actions. Therefore, this is a [CSIDH](https://csidh.isogeny.org/csidh-20181118.pdf) protocol. In fact, the `group_action` function is the same CSIDH uses:

`

```
    def group_action(p, primes, Fp, Fp2, pub, priv, G):
        E = montgomery(Fp2, pub)
        es = priv[:]
        while any(es):
            x = Fp.random_element()
            P = E.lift_x(x)
            s = 1 if P[1] in Fp else -1
            S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
            k = prod([primes[i] for i in S])
            Q = ((p + 1) // k) * P
            
            for i in S:
                R = (k // primes[i]) * Q
                if R.is_zero():
                    continue
                phi = E.isogeny(R)
                E = phi.codomain()
                Q, G = phi(Q), phi(G)
                es[i] -= s
                k //= primes[i]
        return to_montgomery(Fp, Fp2, E, G)
```

`

To learn more about isogeny-based cryptography, I definitely recommend [CryptoHack](https://cryptohack.org/challenges/isogenies/).

In brief, Alice’s private key is a list of random integers between  and . The CSIDH protocol uses this list to walk from a base elliptic curve  to another elliptic curve  by computing several isogenies. Bob does the same with his private key to walk from  to . The public keys are the Montgomery coefficient of the elliptic curves  and . Then, Alice can use her private key to walk from  to , whereas Bob uses his private key to walk from  to . Both end elliptic curves are the same, so the shared secret is the Montgomery coefficient of the curves.

I have left a lot of concepts to explain about CSIDH and isogenies, but we don’t need to actually know them to solve this challenge. Just keep in mind that an isogeny is a homomorphism between two supersingular elliptic curves.

## Solution

If we take a closer look at `T_T`, we see that the actual CSIDH public values from Alice and Bob are not returned from the function:

`

```
        EC = montgomery(Fp2, 0)
        P = EC.gens()[0]
        k = 1
        alice_pub, Q = group_action(p, primes, Fp, Fp2, 0, alice_priv, k * P)
        share_bob, Q = group_action(p, primes, Fp, Fp2, alice_pub, bob_priv, secret * Q)
        bob_pub, P = group_action(p, primes, Fp, Fp2, 0, bob_priv, P)
        share_alice, P = group_action(p, primes, Fp, Fp2, bob_pub, alice_priv, P)
        return P, Q
```

`

Instead, we are given two points  and  that are transformed by the isogenies. Let’s define the isogenies:

### Isogenies

Following the key exchange protocol, the above lines of SageMath code can be expressed in math terms as:

  * In , we know that  and that  is a generator of ; therefore, 
  * In , since , then  as well. Then, after applying , we get 
  * In , we know , so when applying , we get 
  * In , we know , so when applying , we get 


So, in the end, the points  and  that are given to us belong to . As a result, we are able to compute the parameters of the curve equation. Specifically, we can use a single point to get the Montgomery coefficient :

Therefore, we can define . Now, we are interested in finding , which is a value we need to know in order to get the flag:

`

```
    FLAG = os.getenv("FLAG")
    secret = getPrime(256)
    
    # ...
    
    def main():
        while True:
            try:
                p = int(input("input your prime number or secret > "))
                if int(p).bit_length() == 256:
                    if p == secret:
                        print(FLAG)
                        exit()
```

`

Notice that the  we have from the `T_T` function is related to the initial  point (the generator of ), let’s actually label it as :

Since  and  are isogenies (group homomorphisms), point addition is preserved (and also multiplication by scalar), so

Further, since  we can simplify it to .

Then, notice that the  returned by `T_T` is just . It looks similar to the previous  expression, but the order of the isogenies is reversed. However, we are talking about CSIDH, where the “C” stands for commutative, so .

### Discrete logarithm

As a result, we have:

So, the challenge reduces to solving a discrete logarithm over ! This one is easy to solve because the curve is supersingular, so the order of the curve is smooth (it has many small factors). An algorithm like [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) will find the solution pretty quickly. In SageMath, we can simply use the `log` method

### Prime generation

We have skipped one part of the challenge, that has to do with the primes we can send to the server:

`

```
    def check(p):
        assert isPrime(p)
        assert p.bit_length() <= 96
        assert ((p + 1) // 4) % 2 == 1
        prime_list = []
        cnt = 0
    
        for p, i in factor((p + 1) // 4):
            assert not p in choice
            if i > 1:
                cnt += 1
                choice.add(p)
                assert int(p).bit_length() <= 32
            else:
                prime_list.append(p)
                choice.add(p)
    
        assert all([int(p).bit_length() <= 16 for p in prime_list])
        assert cnt == 1
    
        return prime_list
```

`

As can be seen, the primes must be  and also . This means that

Then, the server takes the prime factors of  and adds them to a set called `choice`. For prime factors that appear more than once (the exponent is greater than ), the counter `cnt` is increased and the prime factor must be less than . On the other hand, if the prime factor appears once, it is appended to `prime_list`. At the end, the function checks that all primes in `prime_list` are less than  and that `cnt` equals `1`.

So, we see that the prime  must have the following structure (a bit more restrictive than before):

Where all  and  are odd prime numbers and  is some exponent greater than , so that

Notice also that , because it is verified in `T_T`:

`

```
    @timeout(60)
    def T_T(p, primes, secret):
    
        assert isPrime(p)
        assert len(primes) > 3
    
        # ...
```

`

The way I generated these prime numbers is not so interesting, since I just used random prime numbers within the range we are allowed and checked if the prime factors were already in the `choice` set. I also used  and  for simplicity:

`

```
    def gen_prime():
        global choice
        prev_choice = set(choice)
    
        while True:
            p = 4 * prod(random_prime(2 ** 8) for _ in range(4)) * random_prime(2 ** 14) ** 2 - 1
            try:
                check(p)
                return p
            except AssertionError:
                choice = set(prev_choice)
```

`

### CRT

Finally, we are able to send a known prime and solve the discrete logarithm  on the curve , which we can recover using one point.

However,  is a 256-bit number, whereas the primes we are sending are at most 96-bit numbers. Therefore, we will need to solve several discrete logarithms using different primes. With all the intermediate results, we can use the CRT to join them all and find the  value (this is actually a kind of [Pohlig-Hellman](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm) algorithm).

### Implementation

First, we connect to the instance, define some constants, send a prime number and get the points  and :

`

```
    io = get_process()
    
    dlogs, mods = [], []
    
    for _ in range(8):
        p = gen_prime()
        Fp = GF(p)
        Fp2 = GF(p ** 2, modulus=[1, 0, 1], names='j')
        j = Fp2.gens()[0]
    
        io.sendlineafter(b'input your prime number or secret > ', str(p).encode())
        io.recvuntil(b'(')
        Px = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b', ', drop=True).decode())
        Py = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b')', drop=True).decode())
        io.recvuntil(b'(')
        Qx = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b', ', drop=True).decode())
        Qy = j * int(io.recvuntil(b'*j + ', drop=True).decode()) + int(io.recvuntil(b')', drop=True).decode())
```

`

Now, we find the curve :

`

```
        A = (Py ** 2 - Px ** 3 - Px) / (Px ** 2)
        Eab = EllipticCurve(Fp2, [0, A, 0, 1, 0])
    
        P = Eab(Px, Py)
        Q = Eab(Qx, Qy)
```

`

After that, we can solve the discrete logarithm and append the result and the order to `dlogs` and `mods` for later use with the CRT:

`

```
        dlogs.append(Q.log(P))
        mods.append(P.order())
```

`

This process repeats 8 times, which is enough information. At this point, we can compute the CRT. Notice that we need to consider positive and negative values of the intermediate results:

`

```
    for signs in product((-1, 1), repeat=len(dlogs)):
        try:
            secret = crt([s * d for s, d in zip(signs, dlogs)], mods)
    
            if secret.bit_length() != 256:
                continue
    
            io.info(f'Testing {secret = }')
            io.sendlineafter(b'input your prime number or secret > ', str(secret).encode())
    
            if 'not flag T_T' not in (msg := io.recvlineS()):
                io.success(msg)
                break
        except ValueError:
            pass
```

`

I’m not very sure why this is necessary, but I believe it is because  is not always the same as , just with a sign difference.

## Flag

If we run the script, we will get the flag:

`

```
    $ python3 solve.py master-spark.chals.sekai.team 1337
    [+] Opening connection to master-spark.chals.sekai.team on port 1337: Done
    [+] Starting local process '/usr/bin/bash': pid 109
    [*] Stopped process '/usr/bin/bash' (pid 109)
    [*] Testing secret = 92697392149653184017438929759734443022953789135986999376605724801638735010341
    [+] SEKAI{(h0w_4b0u7_70uh0u_pr0j3c7??_OH_WAIT_Help_me,ERINNNNNNNNNNNN!!_https://youtu.be/X8z23t428kU?si=4ufTbouKxwQ6Lbhm}
    [*] Closed connection to master-spark.chals.sekai.team port 1337
```

`

The full script can be found in here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/SekaiCTF/%E3%83%9E%E3%82%B9%E3%82%BF%E3%83%BC%E3%82%B9%E3%83%91%E3%83%BC%E3%82%AF/solve.py).
