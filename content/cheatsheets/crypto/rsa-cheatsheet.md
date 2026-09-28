---
title: "RSA - Cheatsheet (what do I have -> what attack)"
category: crypto
subcategory: rsa
type: cheatsheet
tags: [rsa, cheatsheet, decision-table, openssl, pem, der, modulus, phi, lcm, gcd, nth-root, modular-inverse, rsactftool, sympy, gmpy2, pycryptodome, factordb, one-liners, dp, qinv]
summary: "Dense RSA reference: attack decision table, every openssl key/cert command, python one-liners for n/e/c/d/phi, RsaCtfTool invocations, and the gotchas that waste hours."
tools: [openssl, python3, rsactftool, sympy, gmpy2, sage, factordb, yafu]
related: [factoring-cheatsheet, rsa-toolkit, factoring-toolkit]
---

## Decision table - what do I have

| You have | Condition | Attack | File |
|---|---|---|---|
| `n, e, c` | `e` small (3,5,17), short m | integer e-th root | `rsa-small-e` |
| `n, e, c` | `e` huge (~n bits) | Wiener | `rsa-wiener-small-d` |
| `n, e, c` | `e` huge, Wiener failed | Boneh-Durfee | `rsa-boneh-durfee` |
| `n, e, c` | `isqrt(n)^2` close to `n` | Fermat | `rsa-fermat-close-primes` |
| `n, e, c` | `p-1` smooth | Pollard p-1 | `rsa-pollard-p-minus-1` |
| `n, e, c` | `p+1` smooth | Williams p+1 | `rsa-pollard-p-minus-1` |
| `n, e, c` | `n` small (<330 bits) | yafu / cado-nfs | `factoring-cheatsheet` |
| `n, e, c` | smallest factor < 40 digits | ECM | `rsa-pollard-rho-ecm` |
| `n, e, c` | `n` in factordb | lookup | `factoring-cheatsheet` |
| `n, e, c` | `gcd(e, phi) != 1` | AMM e-th roots | `rsa-eth-root-amm` |
| `n, e, c` | ROCA-structured primes | Coppersmith/ROCA | `rsa-weak-keygen-roca-e-gcd-phi` |
| many `n_i` | any two share a prime | batch GCD | `rsa-common-factor-batch-gcd` |
| `n, e1, c1, e2, c2` | same `n`, `gcd(e1,e2)=1` | common modulus | `rsa-common-modulus` |
| `(n_i, c_i)` x e | same `m`, same small `e` | Hastad broadcast | `rsa-hastad-broadcast` |
| `n, e, c1, c2` | `m2 = a*m1 + b` known | Franklin-Reiter | `rsa-franklin-reiter` |
| `n, e, c` | most of `m` known | Coppersmith stereotyped | `rsa-coppersmith` |
| `n, e` + half of `p` | `unknown < n^0.25` | Coppersmith partial p | `rsa-partial-key-exposure` |
| `n, e` + low bits of `d` | `>= n_bits/4`, small e | BDF partial d | `rsa-partial-key-exposure` |
| parity oracle | 1 bit per query | LSB binary search | `rsa-lsb-parity-oracle` |
| padding oracle | PKCS#1 v1.5 valid/invalid | Bleichenbacher | `rsa-bleichenbacher-pkcs1` |
| decrypt oracle + blacklist | unpadded | blinding `c*r^e` | `rsa-blinding-decrypt-oracle` |
| verifier + `e=3` | lazy PKCS#1 parser | signature forgery | `rsa-signature-forgery-e3` |
| faulty signature | CRT-RSA | Bellcore `gcd(s^e-m, n)` | `rsa-crt-fault-attack` |
| `n, e, phi` | 2 primes | quadratic | `rsa-known-phi-known-d` |
| `n, e, d` | any prime count | `e*d-1` square roots | `rsa-known-phi-known-d` |
| `n, e, dp` | CRT exponent | `gcd(2^(e*dp)-2, n)` | `rsa-known-phi-known-d` |
| `n = p*q*r...` | multi-prime | same maths, `phi = prod(p_i-1)` | `rsa-known-phi-known-d` |

## 60-second triage on any (n, e, c)

```bash
# 1. sizes
python3 -c 'n=<N>;e=<E>;c=<C>;print("n",n.bit_length(),"e",e.bit_length(),"c",c.bit_length())'
# 2. e small? -> cube root.   e huge? -> wiener.   c << n? -> no reduction happened.
# 3. close primes?
python3 -c 'from math import isqrt;n=<N>;r=isqrt(n);print("gap bits",(n-r*r).bit_length())'
# 4. perfect power / square?
python3 -c 'from math import isqrt;n=<N>;r=isqrt(n);print(r*r==n)'
# 5. small factors?
python3 -c 'from sympy import factorint;print(factorint(<N>, limit=100000))'
# 6. factordb
curl -s "http://factordb.com/api?query=<N>" | python3 -m json.tool
# 7. gcd with every other modulus in the challenge set
python3 -c 'from math import gcd;print(gcd(<N1>,<N2>))'
```

## openssl - keys, certs, and getting the numbers out

```bash
# generate a test key pair
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -pubout -out pub.pem

# dump EVERY field of a private key (n, e, d, p, q, dp, dq, qinv)
openssl rsa -in priv.pem -text -noout

# dump a public key (modulus + exponent)
openssl rsa -pubin -in pub.pem -text -noout

# modulus only, as hex on one line
openssl rsa -pubin -in pub.pem -modulus -noout        # Modulus=ABCD...

# same for a certificate
openssl x509 -in cert.pem -text -noout
openssl x509 -in cert.pem -pubkey -noout > pub.pem
openssl x509 -in cert.pem -modulus -noout

# a CSR
openssl req -in req.csr -text -noout

# PEM <-> DER
openssl rsa -pubin -in pub.pem -outform DER -out pub.der
openssl rsa -pubin -inform DER -in pub.der -out pub.pem

# PKCS#8 / PKCS#1 conversion
openssl pkcs8 -topk8 -nocrypt -in priv.pem -out priv_pkcs8.pem
openssl rsa -in priv_pkcs8.pem -out priv_pkcs1.pem

# decrypt an encrypted private key
openssl rsa -in enc_priv.pem -passin pass:secret -out priv.pem

# raw RSA operations (no padding) - great for oracles
openssl rsautl -encrypt -raw -pubin -inkey pub.pem -in m.bin -out c.bin
openssl rsautl -decrypt -raw -inkey priv.pem -in c.bin -out m.bin
openssl rsautl -verify -raw -pubin -inkey pub.pem -in sig.bin -hexdump

# PKCS#1 v1.5 and OAEP
openssl pkeyutl -encrypt -pubin -inkey pub.pem -in m.bin -out c.bin
openssl pkeyutl -encrypt -pubin -inkey pub.pem -in m.bin -out c.bin \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
openssl pkeyutl -decrypt -inkey priv.pem -in c.bin

# sign / verify
openssl dgst -sha256 -sign priv.pem -out sig.bin msg.txt
openssl dgst -sha256 -verify pub.pem -signature sig.bin msg.txt
openssl dgst -sha256 -sign priv.pem -sigopt rsa_padding_mode:pss -out sig.bin msg.txt

# parse an unknown blob
openssl asn1parse -in mystery.pem
openssl asn1parse -inform DER -in mystery.der -i

# ssh keys
ssh-keygen -f id_rsa.pub -e -m PKCS8 > pub.pem
ssh-keygen -y -f id_rsa > id_rsa.pub
```

## python - read / build keys

```python
# read any key with pycryptodome
from Crypto.PublicKey import RSA
k = RSA.import_key(open("pub.pem").read()); print(k.n, k.e)
k = RSA.import_key(open("priv.pem").read()); print(k.d, k.p, k.q)

# build a private key from p, q, e and export it
from Crypto.PublicKey import RSA
p, q, e = P, Q, 65537
n = p * q; d = pow(e, -1, (p - 1) * (q - 1))
open("recovered.pem", "wb").write(RSA.construct((n, e, d, p, q)).export_key())

# build a public key from n, e
open("pub.pem", "wb").write(RSA.construct((n, e)).export_key())

# read a DER/PEM without pycryptodome (cryptography lib)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
pk = load_pem_public_key(open("pub.pem","rb").read()); print(pk.public_numbers().n)
```

## python one-liners - n, e, c, d, phi

```bash
# bytes <-> int
python3 -c 'from Crypto.Util.number import bytes_to_long as b2l;print(b2l(open("flag","rb").read()))'
python3 -c 'from Crypto.Util.number import long_to_bytes as l2b;print(l2b(<M>))'
python3 -c 'print(int.from_bytes(b"flag","big"))'
python3 -c 'x=<M>;print(x.to_bytes((x.bit_length()+7)//8,"big"))'

# hex / base64 ciphertext
python3 -c 'print(int(open("c.hex").read().strip(),16))'
python3 -c 'import base64;print(int.from_bytes(base64.b64decode(open("c.b64").read()),"big"))'

# phi and d
python3 -c 'p,q,e=<P>,<Q>,<E>;phi=(p-1)*(q-1);print(pow(e,-1,phi))'
python3 -c 'from math import gcd;p,q,e=<P>,<Q>,<E>;l=(p-1)*(q-1)//gcd(p-1,q-1);print(pow(e,-1,l))'

# decrypt
python3 -c 'from Crypto.Util.number import long_to_bytes as l2b;print(l2b(pow(<C>,<D>,<N>)))'

# CRT decryption (fast)
python3 -c '
c,p,q,e=<C>,<P>,<Q>,<E>
dp,dq=pow(e,-1,p-1),pow(e,-1,q-1)
m=(pow(c,dq,q)+q*((pow(q,-1,p)*(pow(c,dp,p)-pow(c,dq,q)))%p))%(p*q)
print(m.to_bytes((m.bit_length()+7)//8,"big"))'

# integer e-th root (exact test!)
python3 -c 'import gmpy2;r,ok=gmpy2.iroot(<C>,3);print(ok,r)'
python3 -c 'from sympy import integer_nthroot;print(integer_nthroot(<C>,3))'

# modular inverse / gcd / lcm
python3 -c 'print(pow(<A>,-1,<M>))'
python3 -c 'from math import gcd,lcm;print(gcd(<A>,<B>), lcm(<A>,<B>))'

# factor n from phi
python3 -c '
from math import isqrt
n,phi=<N>,<PHI>; s=n-phi+1; d=isqrt(s*s-4*n)
print((s+d)//2,(s-d)//2)'

# factor n from d (works for multi-prime)
python3 -c '
import random
from math import gcd
n,e,d=<N>,<E>,<D>; k=e*d-1; t=k; s=0
while t%2==0: t//=2; s+=1
while True:
    g=random.randrange(2,n-1); x=pow(g,t,n)
    for _ in range(s):
        y=pow(x,2,n)
        if y==1 and x!=1 and x!=n-1:
            print(gcd(x-1,n)); raise SystemExit
        x=y'

# factor n from dp
python3 -c 'from math import gcd;print(gcd(pow(2,<E>*<DP>,<N>)-2,<N>))'

# common modulus
python3 -c '
from math import gcd
n,e1,c1,e2,c2=<N>,<E1>,<C1>,<E2>,<C2>
a=pow(e1,-1,e2); b=(1-a*e1)//e2
m=pow(c1,a,n)*pow(c2,b,n)%n
print(m.to_bytes((m.bit_length()+7)//8,"big"))'

# hastad (e=3, three pairs)
python3 -c '
from sympy.ntheory.modular import crt
import gmpy2
M,_=crt([<N1>,<N2>,<N3>],[<C1>,<C2>,<C3>])
r,ok=gmpy2.iroot(int(M),3); print(ok,int(r))'

# wiener in one import
python3 -c 'import owiener;print(owiener.attack(<E>,<N>))'

# check whether e is invertible mod phi
python3 -c 'from math import gcd;print(gcd(<E>,(<P>-1)*(<Q>-1)))'

# is the modulus a perfect square / power?
python3 -c 'from sympy import integer_nthroot;n=<N>;print([(k,)+integer_nthroot(n,k) for k in range(2,8)])'

# quick primality
python3 -c 'from sympy import isprime;print(isprime(<P>))'
python3 -c 'import gmpy2;print(gmpy2.is_prime(<P>))'
```

## RsaCtfTool

```bash
git clone https://github.com/RsaCtfTool/RsaCtfTool && cd RsaCtfTool
pip3 install -r requirements.txt

# everything it knows, against a public key
python3 RsaCtfTool.py --publickey pub.pem --private
python3 RsaCtfTool.py --publickey pub.pem --uncipherfile c.bin

# from raw numbers
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C>
python3 RsaCtfTool.py -n <N> -e <E> --private

# pick specific attacks (much faster than --attack all)
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack wiener
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack fermat
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack boneh_durfee
python3 RsaCtfTool.py -n <N> -e 3   --uncipher <C> --attack cube_root
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack pollard_p_1
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack ecm
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack factordb
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack roca
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack smallq
python3 RsaCtfTool.py -n <N> -e <E> --uncipher <C> --attack common_modulus --e2 <E2> --c2 <C2>

# a whole directory of keys (finds shared factors)
python3 RsaCtfTool.py --publickey "keys/*.pem" --private --attack common_factors

# list every attack module it ships with
python3 RsaCtfTool.py --list-attacks

# dump n and e from a key without openssl
python3 RsaCtfTool.py --dumpkey --key pub.pem

# build a PEM from n, e (and d if you have it)
python3 RsaCtfTool.py --createpub -n <N> -e <E> > pub.pem
```

## sage one-liners

```bash
sage -c 'print(factor(<N>))'
sage -c 'R.<x> = Zmod(<N>)[]; f = x + <PHIGH>; print(f.small_roots(X=2^250, beta=0.5))'
sage -c 'R.<x> = Zmod(<N>)[]; print(gcd(x^3 - <C1>, (x+1)^3 - <C2>))'
sage -c 'print(GF(<P>)(<C>).nth_root(3, all=True))'
sage -c 'print(inverse_mod(<E>, <PHI>))'
sage -c 'print(crt([<C1>,<C2>,<C3>],[<N1>,<N2>,<N3>]))'
```

## Padding formats you will meet

```
textbook / raw        m                                   (no padding, everything breaks)
PKCS#1 v1.5 enc       00 02 <PS: >=8 nonzero> 00 <m>       Bleichenbacher
PKCS#1 v1.5 sign      00 01 FF FF ... FF 00 <DigestInfo>   e=3 forgery if parsed lazily
OAEP                  00 <maskedSeed> <maskedDB>           Manger's attack (~1000 queries)
PSS                   randomized, no forgery shortcut
```

DigestInfo ASN.1 prefixes (hex):

```
MD5     3020300c06082a864886f70d020505000410
SHA-1   3021300906052b0e03021a05000414
SHA-224 302d300d06096086480165030402040500041c
SHA-256 3031300d060960864801650304020105000420
SHA-384 3041300d060960864801650304020205000430
SHA-512 3051300d060960864801650304020305000440
```

## Formulas worth memorising

```
n           = p*q
phi(n)      = (p-1)*(q-1)                      lambda(n) = lcm(p-1, q-1)
phi(p^k)    = p^(k-1) * (p-1)                  <-- NOT p^k - 1
d           = e^-1 mod phi   (or mod lambda)
p + q       = n - phi + 1
p - q       = isqrt((p+q)^2 - 4n)
p, q        = ((p+q) +- (p-q)) / 2
dp          = d mod (p-1)      dq = d mod (q-1)      qinv = q^-1 mod p
CRT decrypt : m = (m_q + q * ((qinv * (m_p - m_q)) mod p))        m_p = c^dp mod p
e*d - 1     = k * phi   with 1 <= k < e
#roots of x^e = c mod n  =  gcd(e, p-1) * gcd(e, q-1)
```

## Gotchas that waste hours

```
- float roots: int(c ** (1/3)) is WRONG above 2^53. Use gmpy2.iroot / integer_nthroot.
- gmpy2.iroot returns (root, is_exact) - check the second element.
- n = p^2 -> phi = p*(p-1), not p^2-1. Silently decrypts to garbage otherwise.
- e even, or gcd(e, phi) != 1 -> no d exists. Use AMM (rsa-eth-root-amm).
- long_to_bytes drops leading zero bytes: a PKCS block starts with 0x00.
- Wiener uses the continued fraction of e/n (not n/e, not e/phi).
- Verify a factorisation by p*q == n, never by "the plaintext looks printable".
- If pow(x, -1, n) raises, gcd(x, n) is a factor - that is a win, not an error.
- Hastad needs at least e ciphertexts; fewer means the root will not be exact.
- Franklin-Reiter needs the EXACT affine relation; a wrong (a,b) gives a degree>1 gcd.
- Coppersmith shift polynomials f^i must be expanded over Z, never reduced mod N.
- A 'huge random e' means small d. A 'tiny e' means small-root attacks. Both are gifts.
- Multiple moduli in one challenge -> always run pairwise gcd first, it costs nothing.
- factordb rate-limits: cache responses, do not loop over thousands of moduli.
- python's pow(a, b, m) is fine with b negative since 3.8 (modular inverse).
- Decode the flag as bytes AND as hex - some challenges encode m as an ASCII hex string.
```

## Minimal RSA in 6 lines (for building test cases)

```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
p, q = getPrime(512), getPrime(512)
n, e = p * q, 65537
d = pow(e, -1, (p - 1) * (q - 1))
c = pow(bytes_to_long(b"CTF{test}"), e, n)
assert long_to_bytes(pow(c, d, n)) == b"CTF{test}"
```

## References

- RFC 8017 (PKCS #1 v2.2): https://www.rfc-editor.org/rfc/rfc8017
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
- CTF Wiki RSA: https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_module_attack/
- factordb: http://factordb.com/
