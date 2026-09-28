---
title: "はやぶさ - SekaiCTF 2024"
category: "crypto"
subcategory: "lattice"
type: "writeup"
tags: ["crypto", "lll", "lattice", "sage", "lwe", "ntru", "eval", "sekaictf", "sekaictf-2024", "2024", "ctf-writeup"]
summary: "We are given a Python script called chall.py:"
source:
  name: "CTFtime writeup #39407"
  url: "https://ctftime.org/writeup/39407"
original_source: "https://7rocky.github.io/en/ctf/other/sekaictf/はやぶさ/"
ctf:
  name: "SekaiCTF 2024"
  year: 2024
  challenge: "はやぶさ"
---

## Metadata

- **CTF:** SekaiCTF 2024
- **Task:** はやぶさ
- **Author team:** ICAI Cyber Team
- **CTFtime:** <https://ctftime.org/writeup/39407>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/sekaictf/はやぶさ/>

---
We are given a Python script called `chall.py`:

`

```
    from falcon import falcon
    from flag import flag
    from timeout_decorator import timeout
    
    @timeout(30)
    def main():
        sk = falcon.SecretKey(64)
        pk = falcon.PublicKey(sk)
        print(pk)
    
        your_sig = bytes.fromhex(input("what is your sig? >"))
    
        if pk.verify(b"Can you break me", your_sig):
            print("well done!!")
            print(flag)
            exit()
    
        print("Broken your wing T_T")
    
    
    main()
```

`

And we also have a shell script called `up.sh`:

`

```
    git clone https://github.com/tprest/falcon.py.git
    
    mv falcon.py falcon
    
    echo "import os
    import sys
    
    sys.path.append(os.path.dirname(__file__))
    " > ./falcon/__init__.py
```

`

## Source code analysis

The Python script looks very short, but the thing is that `up.sh` is cloning a GitHub repository that will be used by the Python script.

In fact, this repository is named [falcon.py](https://github.com/tprest/falcon.py.git) (renamed to `falcon` so that Python `import` doesn’t complain).

So, let’s focus on `chall.py`. Basically, it generates a Falcon secret key with `n = 64`, prints out the public key and asks for the signature of a given message (`"Can you break me"`):

`

```
    @timeout(30)
    def main():
        sk = falcon.SecretKey(64)
        pk = falcon.PublicKey(sk)
        print(pk)
    
        your_sig = bytes.fromhex(input("what is your sig? >"))
    
        if pk.verify(b"Can you break me", your_sig):
            print("well done!!")
            print(flag)
            exit()
    
        print("Broken your wing T_T")
```

`

In public-key cryptography, a signature is generated using the private key, which is unknown to us. Plus, it should not be possible to derive the private key from the public key.

This time, we need to break [Falcon](https://falcon-sign.info) signatures, and it will be possible because `n = 64` is a weak value. Just as a reference, Falcon is one of the candidates for the NIST [Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography), and the proposed parameters are `n = 512` and `n = 1024`, which are notably higher values compared to this challenge.

## Solution

Falcon is an acronym that stands for **Fa** st-Fourier **L** attice-Based **Co** mpact signatures over **N** TRU. Basically, a set of NTRU secrets consists of polynomials  such that, for a known ,

Provided that polynomial  is invertible , we have the public key .

Actually, there are two ways to solve the challenge. The first one is to exploit the Falcon verification, which simply looks if a given signature represents a short vector:

`

```
        def verify(self, message, signature):
            # ...
    
            # Check that the (s0, s1) is short
            norm_sign = sum(coef ** 2 for coef in s0)
            norm_sign += sum(coef ** 2 for coef in s1)
            if norm_sign > self.signature_bound:
                print("Squared norm of signature is too large:", norm_sign)
                return False
    
            # If all checks are passed, accept
            return True
```

`

And the other attack is just to recover the private key, which is what I did during the CTF.

All these attacks are documented in Section 2.5.1 of the [Falcon paper](https://falcon-sign.info/falcon.pdf). Further reading and other resources I used while solving the challenge are:

  * [NTRU and Lattice-Based Crypto: Past, Present, and Future](http://archive.dimacs.rutgers.edu/Workshops/Post-Quantum/Slides/Silverman.pdf)
  * [Falcon](https://tprest.github.io/pdf/slides/falcon-polsys.pdf)
  * [Lattice Attacks on NTRU and LWE: A History of Refinements](https://eprint.iacr.org/2021/799.pdf)
  * [NTRU: A Ring-Based Public Key Cryptosystem](https://www.ntru.org/f/hps98.pdf)
  * [LatticeHacks: NTRU](https://latticehacks.cr.yp.to/ntru.html)


### Key recovery attack

We will try to find polynomials  and  from the public polynomial , given the fact that  and that both polynomials are short.

Using the NTRU lattice (shown in the previous resources), we can see how  belongs to the lattice:

As a result, if we reduce the lattice basis, we can probably find  and . Instead of using the LLL algorithm, this time it is better to use BKZ. Once we have  and , we can easily derive  and  from  and  by calling `ntru_solve`, as shown in the NTRU generation routine:

`

```
    def ntru_gen(n):
        """
        Implement the algorithm 5 (NTRUGen) of Falcon's documentation.
        At the end of the function, polynomials f, g, F, G in Z[x]/(x ** n + 1)
        are output, which verify f * G - g * F = q mod (x ** n + 1).
        """
        while True:
            f = gen_poly(n)
            g = gen_poly(n)
            if gs_norm(f, g, q) > (1.17 ** 2) * q:
                continue
            f_ntt = ntt(f)
            if any((elem == 0) for elem in f_ntt):
                continue
            try:
                F, G = ntru_solve(f, g)
                F = [int(coef) for coef in F]
                G = [int(coef) for coef in G]
                return f, g, F, G
            # If the NTRU equation cannot be solved, a ValueError is raised
            # In this case, we start again
            except ValueError:
                continue
```

`

One more thing to take into account is that the NTRU lattice matrix is made out of polynomials… But obviously, we need to transform it to a matrix with integer entries. This is easy because polynomials are reduced :

`

```
    $ sage -q
    sage: q = 12 * 1024 + 1
    sage: n = 64
    sage: 
    sage: P.<x> = PolynomialRing(Zmod(q))
    sage: R = P.quotient(x ** n + 1)
    sage: 
    sage: h_list = [7061, 5175, 9682, 7463, 11079, 3335, 2591, 5148, 4725, 1259, 7346, 3475, 2439, 8779, 2044, 11172, 7201, 8788, 12088, 9521, 11405, 2202, 4573,
    ....: 6362, 5585, 11674, 8189, 3777, 1870, 9742, 8067, 6636, 5089, 5700, 5686, 9359, 444, 11142, 1927, 382, 6753, 7527, 11940, 7481, 8169, 10312, 5940, 8709,
    ....: 6940, 7771, 810, 8596, 9070, 1920, 1970, 3412, 1744, 4082, 10049, 3390, 6266, 11869, 8941, 10025]
    sage: 
    sage: h = R(h_list)
    sage: h
    10025*xbar^63 + 8941*xbar^62 + 11869*xbar^61 + 6266*xbar^60 + 3390*xbar^59 + 10049*xbar^58 + 4082*xbar^57 + 1744*xbar^56 + 3412*xbar^55 + 1970*xbar^54 + 1920*xbar^53 + 9070*xbar^52 + 8596*xbar^51 + 810*xbar^50 + 7771*xbar^49 + 6940*xbar^48 + 8709*xbar^47 + 5940*xbar^46 + 10312*xbar^45 + 8169*xbar^44 + 7481*xbar^43 + 11940*xbar^42 + 7527*xbar^41 + 6753*xbar^40 + 382*xbar^39 + 1927*xbar^38 + 11142*xbar^37 + 444*xbar^36 + 9359*xbar^35 + 5686*xbar^34 + 5700*xbar^33 + 5089*xbar^32 + 6636*xbar^31 + 8067*xbar^30 + 9742*xbar^29 + 1870*xbar^28 + 3777*xbar^27 + 8189*xbar^26 + 11674*xbar^25 + 5585*xbar^24 + 6362*xbar^23 + 4573*xbar^22 + 2202*xbar^21 + 11405*xbar^20 + 9521*xbar^19 + 12088*xbar^18 + 8788*xbar^17 + 7201*xbar^16 + 11172*xbar^15 + 2044*xbar^14 + 8779*xbar^13 + 2439*xbar^12 + 3475*xbar^11 + 7346*xbar^10 + 1259*xbar^9 + 4725*xbar^8 + 5148*xbar^7 + 2591*xbar^6 + 3335*xbar^5 + 11079*xbar^4 + 7463*xbar^3 + 9682*xbar^2 + 5175*xbar + 7061
    sage: h * x
    8941*xbar^63 + 11869*xbar^62 + 6266*xbar^61 + 3390*xbar^60 + 10049*xbar^59 + 4082*xbar^58 + 1744*xbar^57 + 3412*xbar^56 + 1970*xbar^55 + 1920*xbar^54 + 9070*xbar^53 + 8596*xbar^52 + 810*xbar^51 + 7771*xbar^50 + 6940*xbar^49 + 8709*xbar^48 + 5940*xbar^47 + 10312*xbar^46 + 8169*xbar^45 + 7481*xbar^44 + 11940*xbar^43 + 7527*xbar^42 + 6753*xbar^41 + 382*xbar^40 + 1927*xbar^39 + 11142*xbar^38 + 444*xbar^37 + 9359*xbar^36 + 5686*xbar^35 + 5700*xbar^34 + 5089*xbar^33 + 6636*xbar^32 + 8067*xbar^31 + 9742*xbar^30 + 1870*xbar^29 + 3777*xbar^28 + 8189*xbar^27 + 11674*xbar^26 + 5585*xbar^25 + 6362*xbar^24 + 4573*xbar^23 + 2202*xbar^22 + 11405*xbar^21 + 9521*xbar^20 + 12088*xbar^19 + 8788*xbar^18 + 7201*xbar^17 + 11172*xbar^16 + 2044*xbar^15 + 8779*xbar^14 + 2439*xbar^13 + 3475*xbar^12 + 7346*xbar^11 + 1259*xbar^10 + 4725*xbar^9 + 5148*xbar^8 + 2591*xbar^7 + 3335*xbar^6 + 11079*xbar^5 + 7463*xbar^4 + 9682*xbar^3 + 5175*xbar^2 + 7061*xbar + 2264
    sage: h * x ** 2
    11869*xbar^63 + 6266*xbar^62 + 3390*xbar^61 + 10049*xbar^60 + 4082*xbar^59 + 1744*xbar^58 + 3412*xbar^57 + 1970*xbar^56 + 1920*xbar^55 + 9070*xbar^54 + 8596*xbar^53 + 810*xbar^52 + 7771*xbar^51 + 6940*xbar^50 + 8709*xbar^49 + 5940*xbar^48 + 10312*xbar^47 + 8169*xbar^46 + 7481*xbar^45 + 11940*xbar^44 + 7527*xbar^43 + 6753*xbar^42 + 382*xbar^41 + 1927*xbar^40 + 11142*xbar^39 + 444*xbar^38 + 9359*xbar^37 + 5686*xbar^36 + 5700*xbar^35 + 5089*xbar^34 + 6636*xbar^33 + 8067*xbar^32 + 9742*xbar^31 + 1870*xbar^30 + 3777*xbar^29 + 8189*xbar^28 + 11674*xbar^27 + 5585*xbar^26 + 6362*xbar^25 + 4573*xbar^24 + 2202*xbar^23 + 11405*xbar^22 + 9521*xbar^21 + 12088*xbar^20 + 8788*xbar^19 + 7201*xbar^18 + 11172*xbar^17 + 2044*xbar^16 + 8779*xbar^15 + 2439*xbar^14 + 3475*xbar^13 + 7346*xbar^12 + 1259*xbar^11 + 4725*xbar^10 + 5148*xbar^9 + 2591*xbar^8 + 3335*xbar^7 + 11079*xbar^6 + 7463*xbar^5 + 9682*xbar^4 + 5175*xbar^3 + 7061*xbar^2 + 2264*xbar + 3348
    sage: 
    sage: (h * x ** 3).list() == (-h).list()[-3:] + h.list()[:-3]
    True
```

`

The point is that adding polynomials  and  is just adding each coefficient of the corresponding degree term. And multiplying by  simply shifts the polynomial coefficients, putting the highest degree coefficient at the lowest position in negative form.

As a result, since lattice reduction only performs integer linear combinations of rows, we can transform the polynomial  to an  block matrix, so that the NTRU lattice is equivalent to:

Where

### Implementation

Once we have this, we only need to take the polynomial coefficients from :

`

```
    q = 12 * 1024 + 1
    n = 64
    
    P = PolynomialRing(Zmod(q), names='x')
    x = P.gens()[0]
    R = P.quotient(x ** n + 1)
    
    io = get_process()
    
    io.recvuntil(b'h = ').decode()
    h = R(literal_eval(io.recvlineS()))
```

`

Then, we construct the matrix:

`

```
    M = Matrix(ZZ, 2 * n, 2 * n)
    
    M[:n, :n] = identity_matrix(ZZ, n)
    M[n:, n:] = q * identity_matrix(ZZ, n)
    M[:n, n:] = Matrix(ZZ, [(h * R([0] * i + [1])).list() for i in range(n)])
```

`

Now, we are ready to reduce the lattice using BKZ (some `block_size` tweaking might be needed, `32` works well). The first row will contain the coefficients of  and :

`

```
    L = M.BKZ(block_size=n // 2)
    row = L[0]
```

`

Next, we need to find  and . For this, we will use `ntru_solve` from the given Falcon library. However, we need to transform the coefficients of  and  to be centered, that is:  instead of , which can be done with `lift_centered` in SageMath:

`

```
    center = lambda x: int(Mod(x, q).lift_centered())
    
    f, g = R(list(row[:n])), R(list(row[n:]))
    assert h == g * f.inverse()
    
    f_list = list(map(center, f.list()))
    g_list = list(map(center, g.list()))
    F_list, G_list = ntru_solve(f_list, g_list)
    F, G = R(F_list), R(G_list)
    assert f * G - g * F == 0
```

`

At this point, we are ready to get the secret key and sign the message in order to get the flag:

`

```
    sk = falcon.SecretKey(n, polys=(f_list, g_list, F_list, G_list))
    sig = sk.sign(b'Can you break me')
    
    io.sendlineafter(b'what is your sig? >', sig.hex().encode())
    io.recvuntil(b'well done!!\n')
    io.success(io.recvlineS())
```

`

## Flag

If we run the script, we will get the flag:

`

```
    $ python3 solve.py hayabusa.chals.sekai.team 1337
    [+] Opening connection to hayabusa.chals.sekai.team on port 1337: Done
    [+] b'SEKAI{1_l1k3_7h15_mu51c_h0w_4b0u7_y0u_:https://www.youtube.com/watch?v=uUvthLpSHrQ}'
    [*] Closed connection to hayabusa.chals.sekai.team port 1337
```

`

The full script can be found in here: [`solve.py`](https://github.com/7Rocky/CTF-scripts/tree/main/SekaiCTF/%E3%81%AF%E3%82%84%E3%81%B6%E3%81%95/solve.py).
