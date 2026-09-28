---
title: "Tool - FactorDB"
category: crypto
subcategory: factoring
type: tool
tags: [factordb, factoring, rsa, integer-factorisation, n, primes, api, yafu, cado-nfs, msieve, ecm, crypto, lookup, modulus]
summary: "A public database of known integer factorisations: paste n and you may get p and q instantly, before you try any real factoring."
related: [rsa-decision-tree, crypto-triage, rsactftool, sagemath]
---

## What it is

FactorDB is a community database of integer factorisations. Anyone can submit a number; the database stores its known factors and status. In CTF this matters because:
- Challenge authors often generate primes from small/common sources that are already in the database.
- A modulus reused from a previous CTF or a tutorial is almost certainly already factored.
- Even when `n` is not factored, the database tells you its status (`FF` fully factored, `CF` composite with known factors, `C` composite unknown, `P`/`PRP` prime).

It costs three seconds. Do it before anything else on an RSA challenge.

## Access

```sh
# there is no install; it is an HTTP API.
# the Python client is convenient:
pip install factordb-pycli
# or the library
pip install factordb-python
```

## The invocations that matter

```sh
N=143

# 1. the raw JSON API (works from any shell)
curl -s "http://factordb.com/api?query=$N" | python3 -m json.tool

# 2. a readable one-liner
curl -s "http://factordb.com/api?query=$N" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('status:', d['status'])
for f, e in d['factors']:
    print('factor:', f, '^', e)"

# 3. the CLI client
factordb "$N"

# 4. from Python, inside your solve script
python3 - <<'PY'
from factordb.factordb import FactorDB
n = 143
f = FactorDB(n)
f.connect()
print(f.get_status())        # FF, CF, C, P, PRP, U (unknown), Unit
print(f.get_factor_list())   # [11, 13]
PY

# 5. batch-check every modulus you have
for n in $(cat moduli.txt); do
  printf '%s -> %s\n' "${n:0:20}..." "$(curl -s "http://factordb.com/api?query=$n" | python3 -c 'import json,sys;print(json.load(sys.stdin)["status"])')"
done

# 6. check whether a number is prime (useful sanity check on a "modulus")
curl -s "http://factordb.com/api?query=$N" | grep -o '"status":"[^"]*"'
```

A drop-in helper for a solve script:
```python
#!/usr/bin/env python3
"""Look up n in FactorDB; fall back to local factoring hints."""
import json
import sys
import urllib.request


def factordb(n: int):
    """Return (status, [factors]) for n. Status FF/CF means factors are known."""
    url = f"http://factordb.com/api?query={n}"
    with urllib.request.urlopen(url, timeout=15) as r:
        d = json.load(r)
    factors = []
    for base, exp in d.get("factors", []):
        factors.extend([int(base)] * int(exp))
    return d.get("status"), factors


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 143
    status, factors = factordb(n)
    print("status:", status)
    print("factors:", factors)
    if status in ("FF", "CF") and len(factors) >= 2:
        prod = 1
        for f in factors:
            prod *= f
        assert prod == n, "factor product does not match n"
        print("verified")
    else:
        print("not factored - try: yafu, cado-nfs, ecm, or a structural attack")
        print("n has", n.bit_length(), "bits")
```

## Status codes

| Status | Meaning |
|---|---|
| `FF` | fully factored - you have everything |
| `CF` | composite, **some** factors known (partially factored) |
| `C` | composite, no factors known |
| `P` | definitely prime |
| `PRP` | probably prime |
| `U` | unknown |
| `Unit` | 1 |
| `Z` | zero |

## Gotchas

- **It requires network access.** During an offline or air-gapped CTF this simply will not work; know your local fallbacks.
- Submitting a challenge's modulus publishes it. For most CTFs that is harmless, but in a private/corporate event it may leak the challenge - and other teams can see recently submitted numbers. Think before pasting a 2048-bit modulus during a closed competition.
- The API returns factors as strings in a `[[base, exponent], ...]` structure; convert with `int()` and expand the exponents.
- `CF` is easy to misread as success. Check that the product of the returned factors equals `n`; if not, you only have a partial factorisation (still useful - divide it out and factor the cofactor).
- A very large `n` that is not in the database will return `C` almost instantly. That is not a failure of the lookup; it means you need a real attack.
- Rate limits exist; do not loop over thousands of queries without a delay.
- The site occasionally returns HTML instead of JSON under load - handle the parse failure.
- FactorDB will happily factor a 300-bit number for you if you submit it and wait, but you should not rely on that during a timed event.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| `n` under ~300 bits | `yafu "factor(@)"` - handles most of these in seconds to minutes |
| `n` 300-500 bits | `cado-nfs.py <n>` (needs hours and cores), `msieve` |
| A small factor exists | `ecm -c 1000 1e6 < n.txt` (Lenstra ECM), `sympy.factorint(n)` |
| `p` and `q` are close | Fermat factorisation - see `ctfbrain search rsa-decision-tree` |
| `p-1` is smooth | Pollard p-1 |
| Two moduli available | `gcd(n1, n2)` |
| Offline general-purpose | SageMath `factor(n)` (uses PARI/FLINT) |
| `n` is 1024+ bits | stop. Factoring is not the intended path; find the structural bug |
