---
title: "phpnotes - hxp 38C3 CTF"
category: "web"
subcategory: "rsa"
type: "writeup"
tags: ["web", "rsa", "path-traversal", "jwt", "request-smuggling", "flask", "werkzeug", "base64", "nginx", "unicode-normalization", "hxp-38c3-ctf", "ctf-writeup"]
summary: "Sun, 29 December 2024 ~ hlt"
source:
  name: "CTFtime writeup #39731"
  url: "https://ctftime.org/writeup/39731"
original_source: "https://hxp.io/blog/113/hxp-38C3-CTF-phpnotes/"
ctf:
  name: "hxp 38C3 CTF"
  challenge: "phpnotes"
---

## Metadata

- **CTF:** hxp 38C3 CTF
- **Task:** phpnotes
- **Author team:** hxp
- **CTFtime:** <https://ctftime.org/writeup/39731>
- **Original writeup:** <https://hxp.io/blog/113/hxp-38C3-CTF-phpnotes/>

---
Sun, 29 December 2024 ~ hlt

## hxp 38C3 CTF: phpnotes

WEB (625 points, 7 solves)

Here we explain the intended solution for the web challenge [phpnotes](https://2024.ctf.link/internal/challenge/b98bbcec-faad-40a0-8efa-e2998039d5be/) from our recent CTF.

This challenge consisted of a PHP frontend and two Python backends for a simple note-taking application. Some PHP quirks lead to request smuggling, and unexpected (?) Unicode normalization gives us the flag.

This challenge deploys as three separate containers with a PHP frontend and two Python backends.

  * The PHP frontend (PHP-FPM behind nginx, as usual) is fairly lean. You can perform the usual registration/login/logout and create, view, and edit notes; the interesting parts of all of which occur the frontend-backend interactions in `src/lib/backend.php`.
  * The Python backends run Flask behind uwsgi behind nginx. There is an authentication backend that has a user database and handles login and registration requests (returning RSA-signed JWTs for successful authentications), and a storage backend that actually stores the notes as JSON files on disk.


The flag is in the storage backend in the same directory as the other notes (and the app sources).

Initially, one might want to query the flag directly, but the frontend will not allow such a request. Each note has an ID (corresponding to its filename) that consists of 16 random hex-encoded bytes, and the frontend (in `Backend::check`) validates that the note IDs that we request actually follow this format.

From the [challenge](https://github.com/ECSC2024/openECSC-2024/tree/main/round-2/web03) linked in the description, we learn that passing unsanitized user input as HTTP headers into PHP’s `stream_context_create` allows request smuggling.

However, in this challenge, our control over the headers is significantly lower: the only injection point we have is the JWT from the `auth` cookie, which is validated by the `firebase/php-jwt` package before it is actually forwarded. In general, a JWT consists of three URL-safe base64-encoded segments joined by `.`:

  * The _header_ is a JSON object containing metadata about the token (e.g., the signature algorithm that was used).

  * The _claims_ are a JSON object containing the token’s actual payload (e.g., the expiry time, logged-in username, etc.).

  * Finally, the token contains a cryptographic signature or MAC over the header and claims, to verify that it was not tampered with. Depending on the use case, this can be symmetric or asymmetric cryptography; here, the final entry is a 2048-bit RSA signature over the SHA256 hash of the data (`RS256`).


Since the signature is computed over the raw header and claims, modifying either of these is out of the question. Therefore, we need to modify the signature in a way that leaves it valid. But since the actual cryptography is performed using OpenSSL, and OpenSSL is generally sane[[verification needed]](https://en.wikipedia.org/wiki/Wikipedia:Verifiability), there should be no useful RSA tricks here.

Instead, let us take a look at the code that does the actual verification (in `Firebase\JWT\JWT::decode`):

```
    $sig = static::urlsafeB64Decode($cryptob64);
    /* ... */
    if (!self::verify("{$headb64}.{$bodyb64}", $sig, $key->getKeyMaterial(), $header->alg)) {
```

Here, `urlsafeB64Decode` just adds the missing base64 padding, replaces `-` and `_` with `+` and `/` respectively (switching from the “URL-safe” alphabet to the default alphabet), and calls PHP’s builtin `base64_decode`.

`base64_decode` has a (documented) quirk if `strict` is `false` (the default): it will silently drop any characters not in the base64 alphabet before decoding, and not error. This means that we can add any character that is not in `[A-Za-z0-9+/=_-]` to the encoded signature, and it will still decode to the original data and verify correctly.

This means we can smuggle through any character not in that set, including CR, LF, and any bytes above 0x7f. Since PHP will URL-decode the `auth` cookie for us, it is fairly straightforward to get these bytes there.

However, remember that the original goal was to perform request smuggling — and the largest part of an HTTP request is alphanumeric, exactly the characters that we _cannot_ inject! Thankfully, the request that we want to perform (`GET /flag`) is not particularly complicated:

  * There is no need to include the HTTP version. The backend runs nginx, which handles the old HTTP/0.9 GET requests just fine, and it will in fact _rewrite_ the request to “more correct” HTTP/1.0 before forwarding it to uwsgi.

  * nginx also supports request pipelining, so we only need to keep the connection open to send additional requests. The frontend already adds `Connection: keep-alive` to remove PHP’s default `Connection: close` header, so this is already taken care of.


This still leaves 8 characters in the base64 alphabet in the request, which is incredibly unlikely to appear randomly in a signature so that we might reuse them.

Instead, we (ab)use the fact that the storage backend uses `werkzeug.util.secure_filename` to derive a “secure” filename for the note (without slashes or path traversal, etc.) — but that performs NFKD unicode normalization of the input first, so lots of Unicode characters get converted to normal printable ASCII. You can find normalization tables [here](https://www.unicode.org/charts/normalization/). For example, `ᶠₗₐℊ` (`\u1da0\u2097\u2090\u210a`) will be normalized to `flag`.

Since in UTF-8, the high bits of multi-byte characters are set, `ᶠₗₐℊ` consists entirely of bytes that we can smuggle through the signature check (`E1 B6 A0 E2 82 97 E2 82 90 E2 84 8A`).

The only part of the request that needs to be plain ASCII and that we cannot replace is the method (`GET`) and the first slash in the URL (which is required by the nginx HTTP parser). Therefore, we obtain encoded signatures until one contains `GET_` (remember, `urlsafeB64Decode` will replace `_` with `/` for the verification, so we can perform this replacement by hand before).

The 256-byte signatures turn into 342 base64-encoded characters (without the padding), but the last character cannot be `_`. This leaves 338 possible positions for `GET_` in the encoded signature. Assuming that the signatures are randomly distributed over the 256-byte space (this is not quite true, but alas), we expect to see `GET_` in roughly one of every 50000 signatures ($p = 1 - \left(1 - \frac{1}{64^4}\right)^{338}$).

Of course, you should use multiple threads to obtain signatures more quickly. A caveat here is that the signature process itself is deterministic for a given message, and the message only changes based on the username and the second-granular UNIX timestamp of issue (`iat`) and expiry (`exp`). If you attempt to obtain signatures by logging in the same user over and over again, you will receive lots of duplicates, and spend a long time searching. Instead, rotate the username so that you log in every user at most once per second in order to avoid duplicates.

Then, we can finally construct our malicious authentication cookie:

  * First, add `\r\n\r\n` before the `GET_` to terminate the original “valid” request.

  * Then, replace `GET_` with `GET /ᶠₗₐℊ\r\n` to actually get the flag.

  * Finally, turn the remainder of the signature into a valid but nonsensical header by inserting a `:` at some point.


The final requests might look like this:

```
    GET /439f7dbe59ffd842e2b4e11b31cb41f1 HTTP/1.1
    Host: backend
    Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imh4cC02NzcxNDYzZjVlMjM4OGU3ZWQ5MmM5MTcxNjdkOWQ5MyIsImlhdCI6MTczNTQ3Njk0NiwiZXhwIjoxNzM1NDgwNTQ2fQ.PwRtWmjsfpXvrrDLiLEnQkg4jIlo9NJjU6ukG4GJ6xlV044V1eDn9ROKjz2T0T1AYIJFBUEZsGclS5vayz11-lxTvfz0dZfKBr9id123K0UuvurNMpedrP0gRflMaICToiB--0MRc1aCM5fh418yKKuIhd
    
    GET /ᶠₗₐℊ
    L:ZZfhbvvY6JlVQwy5Fk1NwRl73KHi4jZFI1CGKl2iHKbAytEVXbxebzN1Hb-Eue3cS1CxJ0k4OI6yluUB_N7s2ItcKBFaFznPKLWLj7dtadcFglCgCEzgao8tfPdxK-9QFnAS2l8OOiy3TUfre7vDIXGYjMbdznYTqzI-rBXRxyRKH38NBffWGVQ
    Connection: keep-alive
```

Of course, the flag file is not valid JSON, and therefore not a valid note. Luckily, the error message leaks the entire content (first from the backend into the frontend, and then because JSON decoding also fails there, from the frontend to the user):

```
    Failed to decode response from http://backend/439f7dbe59ffd842e2b4e11b31cb41f1: {"note":{"content":"90c4f5847fcc6471","title":"6ce41de3c20923d4"},"success":true}
    {"error":"malformed note json: hxp{nie_do_konca_jednolinijkowy_przepraszam}\n","success":false}
```

For added “fun”, try hosting the challenge with and without nginx, and try replacing uwsgi with aiohttp-wsgi, gunicorn, or the werkzeug/Flask development server, and see how it changes (or breaks)…
  *[JWTs]: JSON Web Tokens
  *[JWT]: JSON Web Token
