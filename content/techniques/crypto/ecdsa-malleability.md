---
title: "ECDSA - Malleability, Missing Range Checks and Forged Signatures"
category: crypto
subcategory: ecdsa
type: technique
tags: [ecdsa, malleability, low-s, bip62, der, asn1, non-canonical-encoding, range-check, psychic-signature, cve-2022-21449, zero-signature, replay, txid-mutation, ed25519, signature-forgery, python]
difficulty: medium
summary: "(r, s) and (r, n-s) both verify. Skip the 1 <= r,s <= n-1 check and (0,0) verifies too. Lenient DER parsing gives infinitely many encodings of one signature."
when_to_use:
  - "A protocol treats a signature as a unique identifier (nonce, txid, replay cache key)"
  - "The verifier does not check 0 < r < n and 0 < s < n"
  - "Signatures are DER-encoded and compared byte-for-byte somewhere"
  - "A 'signature already used' blacklist must be bypassed"
tools: [python, openssl, sage]
related: [ecdsa-nonce-reuse, ecdsa-weak-k-derivation, ecc-montgomery-x-only, ecc-cheatsheet]
---

## TL;DR

ECDSA signatures are not unique. For every valid `(r, s)` the pair `(r, n - s)` is equally
valid, so any system that uses the signature bytes as an identity is broken. Worse, the
standard mandates `0 < r < n` and `0 < s < n`; verifiers that skip it can be made to accept
the all-zero signature for *any* message and *any* public key (CVE-2022-21449, "psychic
signatures"). DER adds a third layer: a lenient parser accepts many byte strings for one
signature.

## Recognise it

- A replay cache, nonce store or "already spent" set keyed on the raw signature.
- `if sig in used_signatures: reject` with no canonicalisation.
- A verifier that goes straight to `w = inverse(s)` with no bounds check.
- A hand-rolled ASN.1/DER parser (`if data[0] != 0x30: fail` and little else).
- Java-based targets (JDK 15-18 before the April 2022 CPU): try `r = s = 0`.
- Bitcoin-flavoured challenges mentioning "txid", "malleability" or "BIP 62".

## Theory

**Negation malleability.** Verification computes `R = u_1 G + u_2 Q` with
`u_1 = h s^{-1}`, `u_2 = r s^{-1}`, and checks `x(R) mod n == r`. Replacing `s` by `n - s`
negates both `u_1` and `u_2`, hence `R -> -R`, and `x(-R) = x(R)`. The check still passes.
BIP 62 fixes this by demanding the *low-s* form `s <= (n-1)/2`.

**Zero signature.** With `r = s = 0`, a compliant verifier rejects immediately. A verifier
that omits the range check computes `s^{-1}` -- and several big-integer libraries return `0`
for the inverse of `0` instead of raising. Then `u_1 = u_2 = 0`, `R = O`, and an
implementation that encodes the point at infinity with `x = 0` compares `0 == r = 0` and
accepts. Any message, any key, no private key needed.

**Unreduced `s` and `r`.** `u_1` and `u_2` only depend on `s mod n`, so `s + n` verifies
wherever `s` does -- unless the verifier checks `s < n`. The same holds for `r` when the
final comparison is done mod `n`.

**DER malleability.** A signature is `SEQUENCE { INTEGER r, INTEGER s }`. Non-canonical but
widely accepted variants:

| variant | bytes | why it parses |
| --- | --- | --- |
| extra leading zero | `02 21 00 00 ..` | lenient parsers strip zeros |
| long-form length | `30 81 44 ..` | valid BER, not valid DER |
| trailing garbage | `30 44 .. DEADBEEF` | parser reads only the declared length |
| negative `r` | high bit set without `00` | parser sign-extends |
| indefinite length | `30 80 .. 00 00` | BER only |

Each yields a different byte string for the same `(r, s)`.

**Ed25519 analogue.** `s` must be reduced mod `L`; `s + L` is a different encoding of the
same signature, and non-canonical `R`/`A` encodings give more. RFC 8032 requires the check,
many libraries historically did not.

## Attack

1. Take any valid signature `(r, s)` you can observe.
2. Emit `(r, n - s)`: a second, distinct, valid signature for the same message.
3. If the target keys a cache on the signature, you have a replay.
4. Probe the verifier with `(0, 0)`, `(r, 0)`, `(0, s)`, `(r, s + n)`, `(r + n, s)`.
5. Re-encode in DER with an extra leading zero, long-form length and trailing bytes.
6. Anything accepted that should not be is the bug; anything rejected tells you which check
   exists.

## Code

```python
#!/usr/bin/env python3
"""ECDSA malleability: negation, zero signatures, unreduced values, DER variants."""
import hashlib
import random

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def ec_add(A, B):
    if A is None:
        return B
    if B is None:
        return A
    (x1, y1), (x2, y2) = A, B
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    lam = ((3 * x1 * x1) * pow(2 * y1 % P, -1, P) if A == B
           else (y2 - y1) * pow((x2 - x1) % P, -1, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)

def ec_mul(k, A):
    R, S, k = None, A, k % N
    while k:
        if k & 1:
            R = ec_add(R, S)
        S, k = ec_add(S, S), k >> 1
    return R

def h_of(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N

def sign(d, msg, k):
    r = ec_mul(k, G)[0] % N
    return r, pow(k, -1, N) * (h_of(msg) + r * d) % N

def inv_lenient(x, n):
    """Some big-integer libraries return 0 for the inverse of 0 instead of raising."""
    return pow(x, -1, n) if x % n else 0

def verify_strict(Q, msg, sig):
    """RFC 6979 / SEC1 compliant."""
    r, s = sig
    if not (0 < r < N and 0 < s < N):
        return False
    w = pow(s, -1, N)
    h = h_of(msg)
    R = ec_add(ec_mul(h * w % N, G), ec_mul(r * w % N, Q))
    return R is not None and R[0] % N == r

def verify_vulnerable(Q, msg, sig):
    """The same code with the range check removed -- the CVE-2022-21449 shape."""
    r, s = sig
    w = inv_lenient(s, N)
    h = h_of(msg)
    R = ec_add(ec_mul(h * w % N, G), ec_mul(r * w % N, Q))
    x = 0 if R is None else R[0]          # infinity encoded as x = 0
    return x % N == r % N

def verify_low_s(Q, msg, sig):
    """BIP 62: reject the high-s half to make signatures canonical."""
    r, s = sig
    return s <= (N - 1) // 2 and verify_strict(Q, msg, sig)

# ---- DER ---------------------------------------------------------------

def _der_int(v, pad=0, longform=False):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    b = b"\x00" * pad + b
    length = bytes([0x81, len(b)]) if longform else bytes([len(b)])
    return b"\x02" + length + b

def der_encode(r, s, pad=0, longform=False, trailing=b""):
    body = _der_int(r, pad, longform) + _der_int(s, pad, longform)
    hdr = bytes([0x81, len(body)]) if longform else bytes([len(body)])
    return b"\x30" + hdr + body + trailing

def der_parse_lenient(blob):
    """A forgiving parser: ignores trailing bytes and extra leading zeros."""
    assert blob[0] == 0x30
    i = 1
    if blob[i] & 0x80:
        i += 1 + (blob[i] & 0x7F)
    else:
        i += 1
    out = []
    for _ in range(2):
        assert blob[i] == 0x02
        i += 1
        if blob[i] & 0x80:
            nb = blob[i] & 0x7F
            ln = int.from_bytes(blob[i + 1:i + 1 + nb], "big")
            i += 1 + nb
        else:
            ln, i = blob[i], i + 1
        out.append(int.from_bytes(blob[i:i + ln], "big"))
        i += ln
    return tuple(out)

if __name__ == "__main__":
    rng = random.Random(9)
    d = rng.randrange(1, N)
    Q = ec_mul(d, G)
    msg = b"pay 10 coins to bob"
    sig = sign(d, msg, rng.randrange(1, N))
    r, s = sig
    assert verify_strict(Q, msg, sig)
    print("[ok] baseline signature verifies")

    # --- 1. negation malleability ---
    mal = (r, (N - s) % N)
    assert mal != sig and verify_strict(Q, msg, mal)
    print("[ok] (r, n-s) is a DIFFERENT signature that also verifies")

    # a replay cache keyed on the signature is therefore useless
    used = {sig}
    assert mal not in used and verify_strict(Q, msg, mal)
    print("[ok] replay cache keyed on raw (r, s) bypassed")

    # BIP 62 low-s canonicalisation kills it
    canon = lambda t: (t[0], min(t[1], N - t[1]))
    assert canon(sig) == canon(mal)
    assert verify_low_s(Q, msg, canon(sig))
    assert not verify_low_s(Q, msg, (r, max(s, N - s)))
    print("[ok] low-s canonicalisation makes the two forms identical")

    # --- 2. unreduced s and r ---
    assert verify_vulnerable(Q, msg, (r, s + N))
    assert not verify_strict(Q, msg, (r, s + N))
    print("[ok] s + n verifies under the unchecked verifier, rejected by the strict one")

    # --- 3. the zero signature: valid for ANY message under ANY key ---
    for m in (b"pay 10 coins to bob", b"pay all coins to mallory", b"anything at all"):
        assert verify_vulnerable(Q, m, (0, 0))
        assert not verify_strict(Q, m, (0, 0))
    other = ec_mul(rng.randrange(1, N), G)
    assert verify_vulnerable(other, b"not even my key", (0, 0))
    print("[ok] (0, 0) forges every message under every key when r,s are unchecked")

    # --- 4. DER encodings of one signature ---
    forms = [
        der_encode(r, s),
        der_encode(r, s, pad=1),
        der_encode(r, s, longform=True),
        der_encode(r, s, trailing=b"\xde\xad\xbe\xef"),
        der_encode(r, N - s),
    ]
    assert len(set(forms)) == len(forms), "each encoding is a distinct byte string"
    for blob in forms[:4]:
        assert der_parse_lenient(blob) == (r, s)
    assert der_parse_lenient(forms[4]) == (r, (N - s) % N)
    print(f"[ok] {len(forms)} distinct byte strings, all parsed as a valid signature")

    # --- 5. degenerate probes a verifier should reject ---
    probes = [(0, 0), (r, 0), (0, s), (r, N), (N, s), (r, s + N), (r + N, s)]
    strict = [verify_strict(Q, msg, t) for t in probes]
    assert not any(strict), "a compliant verifier rejects every degenerate probe"
    print(f"[ok] strict verifier rejected all {len(probes)} degenerate probes")
    print("all self-tests passed")
```

## Variants and pitfalls

- **Malleability is not key recovery.** You cannot sign a *new* message; you can only produce
  another encoding of a signature you already have. The impact is always in the surrounding
  protocol: replay caches, txids, idempotency keys, "one signature per user" logic.
- **Where it becomes forgery.** Missing range checks (`(0,0)`) or a verifier that compares
  `x(R)` without reducing mod `n` do let you forge. Probe before assuming.
- **`h` not reduced.** If the verifier uses the full hash while the signer truncated (or vice
  versa), signatures fail for a boring reason. Do not mistake that for a checked verifier.
- **Bitcoin.** Since BIP 62 / BIP 146 only low-s signatures are relayed, and SegWit moved the
  signature out of the txid entirely. Legacy challenges still model the old behaviour.
- **Ed25519.** Check for `s >= L` acceptance and for small-order `A`/`R`. Cofactored vs
  cofactorless verification disagree; two "correct" libraries can disagree on the same
  signature.
- **OpenSSL is strict**, so do not use it as your oracle for whether a target is strict.
- **ASN.1 parsers in other languages.** Go's `encoding/asn1` rejects non-minimal integers;
  Python's naive `struct`-style parsers usually do not. Fingerprint by sending one variant at
  a time.

## Tools

```sh
# inspect a DER signature's structure and integers
openssl asn1parse -inform DER -in sig.der
# verify with a strict implementation as a reference oracle
openssl dgst -sha256 -verify pub.pem -signature sig.der message.txt
```

```python
# SageMath / python: canonicalise to low-s before any byte comparison
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
low_s = lambda r, s: (r, s if s <= (n - 1) // 2 else n - s)
```

## References

- https://nvd.nist.gov/vuln/detail/CVE-2022-21449 ("psychic signatures" in Java)
- https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
- https://www.secg.org/sec1-v2.pdf (section 4.1.4, verification with its range checks)
- https://datatracker.ietf.org/doc/html/rfc8032#section-8.4 (Ed25519 malleability)
