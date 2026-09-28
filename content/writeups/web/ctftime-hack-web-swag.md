---
title: "Web - Swag - Hackअस्त्र"
category: "web"
subcategory: "jwt"
type: "writeup"
tags: ["web", "confusion", "algorithm", "jwt", "rsa", "gcd", "hack", "ctf-writeup"]
summary: "For the complete documentation index, see llms.txt."
source:
  name: "CTFtime writeup #40817"
  url: "https://ctftime.org/writeup/40817"
original_source: "https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/swag-hack-2026"
ctf:
  name: "Hackअस्त्र"
  challenge: "Web - Swag"
---

## Metadata

- **CTF:** Hackअस्त्र
- **Task:** Web - Swag
- **Author team:** Team0Skills
- **CTFtime tags:** confusion, algorithm, jwt
- **CTFtime:** <https://ctftime.org/writeup/40817>
- **Original writeup:** <https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/swag-hack-2026>

---
For the complete documentation index, see [llms.txt](https://l1nuxkid.gitbook.io/l1nuxkid-docs/llms.txt). This page is also available as [Markdown](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/swag-hack-2026.md).

### Overview

This challenge is a classic **JWT Algorithm Confusion** attack, specifically the RS256 → HS256 confusion variant. It's a real-world vulnerability class that has appeared in production APIs and is well-documented in the JWT security community.

The core idea: the server signs tokens with an RSA private key (RS256), but its verification code naively accepts whatever algorithm is declared in the JWT header. If we switch the algorithm to HS256 and sign with the RSA _public_ key as the HMAC secret, the server verifies it successfully — because it uses the same key for both modes.

The twist in this challenge: the public key isn't given to us. We have to _recover it_ from two JWT signatures using modular arithmetic and the GCD.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252Fvt567lEBsvyml7EWUndi%252Fimage.png%3Falt%3Dmedia%26token%3Dabc33803-8f65-48b6-96f7-bf448c9df904&width=768&dpr=3&quality=100&sign=7bfbd4516f87dbf27629abccb046535e&sv=3)

### Understanding JWT Structure

Before diving in, a quick primer. Every JWT is three base64url-encoded chunks joined by dots:

For our tokens, the header decoded to `{"typ":"JWT","alg":"RS256"}` and the payload to `{"username":"l1nuxkid","role":"user"}`. The `role` field is what we need to change to `admin` but we can't just edit the payload, because the signature would no longer be valid.

In RS256, the server signs with its private key and verifies with its public key. We don't have the private key, so we can't produce a valid RS256 signature. But if we can get the server to use HS256 verification and we know what it uses as the HMAC secret we can forge anything we want.

### Attack Chain

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FEm8B2UrtQy3Y7U0c2cCe%252FScreenshot%25202026-05-31%2520at%25209.23.07%25E2%2580%25AFAM.png%3Falt%3Dmedia%26token%3D608467cf-3dc3-4d40-b475-098453c9dac9&width=768&dpr=3&quality=100&sign=259c306a2cc4962eac2d3dd6420c9558&sv=3)

### Step 1 Swagger Recon

The challenge name and description ("Our team is very proud of their Swagger docs") is a direct hint. Navigate to `/swagger` or `/api-docs` on the target to find the full API documentation exposed. Swagger (OpenAPI) docs list every endpoint, their parameters, and expected responses a complete attack surface map handed to us for free.

From the docs we identified the key endpoints: `/api/register`, `/api/login`, `/api/profile`, and `/api/flag`.

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FJ3KxAGUM1OlP60u0LGOW%252Fimage.png%3Falt%3Dmedia%26token%3Dc5c2973c-b01f-4bd3-a3ff-bfc2fffaf9e7&width=768&dpr=3&quality=100&sign=0b80b42da903f35488210de3853cf5b8&sv=3)

### Step 2 Register, Login, Confirm the Wall

Register a user and grab a JWT:

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FXunV84vfCbE5Vg41tbeY%252Fimage.png%3Falt%3Dmedia%26token%3Dd09bacbe-afa0-4cd9-b856-6b25466ae47d&width=768&dpr=3&quality=100&sign=ec7a314a1b866f11e46adbfdc5fafe44&sv=3)

![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FqoFTyc62yHgH3ww8cg9C%252Fimage.png%3Falt%3Dmedia%26token%3Dce1f37a5-1bcc-41ba-bb97-2d8d2c691c30&width=768&dpr=3&quality=100&sign=0893ff1964b48db2a79250cc4154cfa3&sv=3)

This returns a JWT. Hitting `/api/profile` confirms:

And as expected, `/api/flag` returns:

We need `"role":"admin"` in the token payload. Time to forge one.

### Step 3 Collect Two RS256 Tokens

Register a second user and collect both their JWTs. We need exactly two distinct tokens to run the GCD-based key recovery in the next step.

Save both JWTs. You can decode the middle chunk (payload) in Python to confirm what's inside:

### Step 4 Recover the RSA Public Key

This is the math-heavy heart of the attack (THANKS TO AI). Here's the intuition:

In RSA, a signature is computed as:

Which means:

Or rearranged:

If we have two signatures from the same server (same `n`), both `(sig1^e - msg1)` and `(sig2^e - msg2)` are multiples of `n`. Their GCD will be `n` itself (or a small multiple we can factor out).

This prints the RSA public key PEM the same key the server uses to verify tokens.

#### Step 5 Forge the Admin Token (RS256 → HS256 Confusion)

Now the exploitation. We craft a new JWT with `"alg":"HS256"` in the header and `"role":"admin"` in the payload, then sign it using HMAC-SHA256 with the PEM-encoded public key as the secret.

The server's vulnerable verification logic looks roughly like this:

When we send an HS256 token, the server calls `verifyHMAC(token, publicKey)`. Since we signed it with that same public key, the HMAC matches perfectly.

#### Step 6 Capture the Flag

bash

* * *

#### Vulnerability Summary

Issue

Impact

Swagger docs publicly exposed

Full API surface mapped without any auth

Server accepts both RS256 and HS256

Algorithm confusion attack is possible

No algorithm restriction on verification

Public key usable as HMAC secret

Role claim trusted from JWT payload

Admin access via forged `"role":"admin"`

The fix is a single line restrict the allowed algorithms explicitly:

With this in place, an HS256 token is rejected outright, regardless of how it was signed.

* * *

#### The Math in Plain English

Think of it like a nightclub bouncer with two ID systems:

  * **RS256** (normal): The club has a master stamp (private key). Only they can create valid stamps. The bouncer checks stamps with a scanner (public key).

  * **HS256** (the bug): Both the creator and the bouncer use the same secret password for HMAC. If the bouncer's "password" is just the public scanner key sitting on the desk — and we grab it — we can stamp our own fake IDs.


The GCD trick for recovering `n` is like reverse-engineering the stamp machine from two legitimate stamped IDs. Both IDs share the same machine (same `n`), so the GCD of their mathematical differences is the machine's fingerprint.

#### References

  * [PortSwigger JWT algorithm confusion attacks](https://portswigger.net/web-security/jwt/algorithm-confusion)

  * [jwt.io debugger](https://jwt.io) for decoding tokens during recon

  * [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)


![](https://l1nuxkid.gitbook.io/l1nuxkid-docs/~gitbook/image?url=https%3A%2F%2F3649623708-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FYlNnAjgJP1t8Fm42Oonh%252Fuploads%252FSjBu6NqnoxB01gvwftCz%252Fimage.png%3Falt%3Dmedia%26token%3D386fbeff-246a-481d-9f3c-f5799a08b8ee&width=768&dpr=3&quality=100&sign=550e2ca93c31d6445f09335d75e78b46&sv=3)

[PreviousBeta app - Hackअस्त्र 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/beta-app-hack-2026)[NextMission Control - Hackअस्त्र 2026](https://l1nuxkid.gitbook.io/l1nuxkid-docs/ctftime.org-writeups/mission-control-hack-2026)

Last updated 3 months ago
