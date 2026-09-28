---
title: "Known Phi (crypto-attacks)"
category: "crypto"
subcategory: "rsa"
type: "script"
tags: ["crypto-attacks", "factorization", "rsa", "gcd", "known", "phi", "known-phi", "crypto"]
summary: "Element to factorize."
tools: ["crypto-attacks"]
source:
  name: "jvdsn/crypto-attacks"
  url: "https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/known_phi.py"
license: "MIT"
---

## What it does

Element to factorize.

## Where it lives

- Vendored locally at `vendor/crypto-attacks/attacks/factorization/known_phi.py`
- Upstream: <https://github.com/jvdsn/crypto-attacks/blob/d42a3df980bf/attacks/factorization/known_phi.py>

## Usage

```bash
# read or run it straight from the vendored copy
$EDITOR vendor/crypto-attacks/attacks/factorization/known_phi.py
python3 vendor/crypto-attacks/attacks/factorization/known_phi.py
```

## Code

```python
from math import gcd
from math import isqrt
from random import randrange

from sage.all import is_prime


def factorize(N, phi):
    """
    Recovers the prime factors from a modulus if Euler's totient is known.
    This method only works for a modulus consisting of 2 primes!
    :param N: the modulus
    :param phi: Euler's totient, the order of the multiplicative group modulo N
    :return: a tuple containing the prime factors, or None if the factors were not found
    """
    s = N + 1 - phi
    d = s ** 2 - 4 * N
    p = int(s - isqrt(d)) // 2
    q = int(s + isqrt(d)) // 2
    return p, q if p * q == N else None


def factorize_multi_prime(N, phi):
    """
    Recovers the prime factors from a modulus if Euler's totient is known.
    This method works for a modulus consisting of any number of primes, but is considerably be slower than factorize.
    More information: Hinek M. J., Low M. K., Teske E., "On Some Attacks on Multi-prime RSA" (Section 3)
    :param N: the modulus
    :param phi: Euler's totient, the order of the multiplicative group modulo N
    :return: a tuple containing the prime factors
    """
    prime_factors = set()
    factors = [N]
    while len(factors) > 0:
        # Element to factorize.
        N = factors[0]

        w = randrange(2, N - 1)
        i = 1
        while phi % (2 ** i) == 0:
            sqrt_1 = pow(w, phi // (2 ** i), N)
            if sqrt_1 > 1 and sqrt_1 != N - 1:
                # We can remove the element to factorize now, because we have a factorization.
                factors = factors[1:]

                p = gcd(N, sqrt_1 + 1)
                q = N // p

                if is_prime(p):
                    prime_factors.add(p)
                elif p > 1:
                    factors.append(p)

                if is_prime(q):
                    prime_factors.add(q)
                elif q > 1:
                    factors.append(q)

                # Continue in the outer loop
                break

            i += 1

    return tuple(prime_factors)

```

## Attribution

- **Author:** Joachim Vandersmissen (jvdsn)
- **Repository:** <https://github.com/jvdsn/crypto-attacks> (commit `d42a3df980bf`)
- **Licence:** MIT — see `vendor/crypto-attacks/LICENSE`

This file is a wrapper for search and reference. The code is the original authors' work, redistributed unmodified under its own licence.
