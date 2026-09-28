---
title: "grammar nazi - MaltaCTF 2025 Quals"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "rsa", "gcd", "sage", "chinese-remainder", "factordb", "proof-of-work", "maltactf-2025-quals", "2025", "ctf-writeup"]
summary: "We are given the following source code in Python, with the output as a multi-line string:"
source:
  name: "CTFtime writeup #40376"
  url: "https://ctftime.org/writeup/40376"
original_source: "https://7rocky.github.io/en/ctf/other/maltactf/grammar-nazi/"
ctf:
  name: "MaltaCTF 2025 Quals"
  year: 2025
  challenge: "grammar nazi"
---

## Metadata

- **CTF:** MaltaCTF 2025 Quals
- **Task:** grammar nazi
- **Author team:** thehackerscrew
- **CTFtime:** <https://ctftime.org/writeup/40376>
- **Original writeup:** <https://7rocky.github.io/en/ctf/other/maltactf/grammar-nazi/>

---
We are given the following source code in Python, with the output as a multi-line string:

`

```
    from Crypto.Util.number import *
    
    FLAG = 'maltactf{???????????????????????????????}'
    assert len(FLAG) == 41
    
    p = getPrime(128)
    q = getPrime(128)
    N = p * q
    e = 65537
    
    m = f'The flag is {FLAG}'
    c = pow(bytes_to_long(m.encode()), e, N)
    
    # ERROR: Sentences should end with a period.
    m += '.'
    c += pow(bytes_to_long(m.encode()), e, N)
    
    # All good now!
    print(f'{N = }')
    print(f'{c = }')
    
    '''
    N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
    c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
    '''
```

`

## Source code analysis

The source code is short and straight-forward:

  * We know the flag format and its length
  * The program generates two 128-bit prime numbers  and  (RSA private key)
  * and uses that to create an RSA public key  and 
  * After that, the program encrypts a message that contains the flag: 
  * Then, it updates  in a weird way to “add a period”


We are given  as `N` and the updated  as `c`. With this information, we need to find the flag.

## Solution

Let  be the original message and  the updated message with the period. Therefore, , where 46 is the ASCII decimal value of a period.

As a result, the given `c` value is :

In brief, we can define a polynomial , such that  is a root of  in . However, finding roots under a composite modulus with unknown factorization is difficult.

In a secure RSA implementation, such as RSA-2048 or RSA-4096, this would be impossible to solve in a reasonable time. However, this time the server uses RSA-256, since the primes  and  are 128-bit numbers. We could use tools like [cado-nfs](https://github.com/cado-nfs/cado-nfs) to factor , but this time, the number was already uploaded to [factordb](http://www.factordb.com/index.php?query=83839453754784827797201083929300181050320503279359875805303608931874182224243):

`

```
    $ sage -q
    sage: N = 83839453754784827797201083929300181050320503279359875805303608931874182224243
    sage: c = 32104483815246305654072935180480116143927362174667948848821645940823281560338
    sage: 
    sage: e = 65537
    sage: 
    sage: p = 276784813000398431755706235529589161781
    sage: q = 302904819256337380397575865141537456903
    sage: N == p * q
    True
```

`

So, given that we know  and  such that , we can find  within the roots of  in . For this, we can consider  separately in  and , find possible roots and then apply the Chinese Remainder Theorem (CRT).

In other words, we can easily find  such that  and  such that , which means

### Implementation

In SageMath, we could be tempted to use the following code:

`

```
    sage: Pp.<xp> = PolynomialRing(GF(p))
    sage: Pq.<xq> = PolynomialRing(GF(q))
    sage: 
    sage: fp = xp ** e + (256 * xp + 46) ** e - c
    sage: fq = xq ** e + (256 * xq + 46) ** e - c
    sage: 
    sage: fp.roots()
    sage: fq.roots()
```

`

However, this will take a long time to finish. A fast way to get a root is to use `any_root`:

`

```
    sage: fp.any_root()
    38745752538982310497402322032299730998
```

`

We can do the same with  defined in  and compute the CRT. Obviously, there can be many roots, so we need to run `any_root` several times until getting the desired one. Nevertheless, even if we find the desired roots, we won’t be able to get the expected message. Notice that the flag is 41 bytes long, so the message  is 53 bytes long because of `"The flag is "`. Remember that  is a 256-bit integer, so 32 bytes long. Therefore, instead of finding the expected message , we will be getting , and it won’t be trivial to find .

The way to address this is issue to consider the known bytes, so that , where  is the integer value of `"The flag is maltactf{\0\0...\0}"`, and  is the unknown integer value of the inner flag, replacing the null bytes. With this, the new unknown  is only 31 bytes long (41 minus the length of `"maltactf{}"`), which is less than ; and therefore we will find the exact value. So, this is the polynomial after the change of variable:

`

```
    sage: M = int.from_bytes(b'The flag is maltactf{???????????????????????????????}'.replace(b'?', b'\0'))
    sage: 
    sage: fp = (M + 256 * yp) ** e + (256 * (M + 256 * yp) + 46) ** e - c
    sage: fq = (M + 256 * yq) ** e + (256 * (M + 256 * yq) + 46) ** e - c
```

`

Now, using `any_root` several times on both `fp` and `fq` and trying the CRT, we will eventually find the flag.

### Trick for finding roots

However, there is another way to compute roots of a polynomial under a finite field, which is an implementation trick in SageMath.

Let’s consider  in , where  is a prime number. We know that  for any  because  ([Fermat’s little theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem)), and . In other words, all elements of  are a root of , which means that  can be rewritten as:

Let’s return to the challenge. Theoretically,  has at least one root (we know it exists since the flag satisfies the equation). Without loss of generality, let’s consider  to be  under  and . Remember that  for any element of . Hence, the roots of  also are roots of . As a result, we can use the polynomial greatest common divisor (GCD) to consider only common roots (precisely, the ones we want from ), so

However, we can’t simply define  in SageMath like `yp ** p - yp`, because it will complain that the exponent is huge. Instead, remember this GCD property: . We can use this property in a tricky way to define  as `pow(yp, p, fp) - yp`.

So, this way we can get all possible roots of  in  and in :

`

```
    sage: roots_p = fp.gcd(pow(yp, p, fp) - yp).roots(multiplicities=False)
    sage: roots_q = fq.gcd(pow(yq, q, fq) - yq).roots(multiplicities=False)
```

`

## Flag

At this point, we only need to consider each possible pair, compute the CRT and see if the result is the expected flag:

`

```
    sage: from itertools import product
    sage: from Crypto.Util.number import long_to_bytes
    sage: 
    sage: for rp, rq in product(roots_p, roots_q):
    ....:     if (data := long_to_bytes(crt([int(rp), int(rq)], [p, q]))).isascii():
    ....:         print((b'maltactf{' + data + b'}').decode())
    ....: 
    maltactf{Ferm4ts_littl3_polyn0mial_tr1ck}
```

`
