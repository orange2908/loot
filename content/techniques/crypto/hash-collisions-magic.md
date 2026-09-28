---
title: "Hash Collisions in CTFs - Magic Hashes, Type Juggling, MD5 Chosen-Prefix, crypt() Truncation"
category: crypto
subcategory: hash
type: technique
tags: [hash, collision, md5, sha1, magic-hash, type-juggling, php, loose-comparison, 0e, birthday-attack, chosen-prefix, identical-prefix, fastcoll, hashclash, shattered, crypt, descrypt, truncation, strcmp-bypass, authentication-bypass]
difficulty: medium
summary: "PHP's `==` treats `0e123` as zero, so two passwords whose MD5 starts with 0e compare equal; plus MD5 chosen-prefix collisions, crypt() truncation and array bypasses."
when_to_use:
  - "PHP source compares hashes with `==` instead of `===` or `hash_equals`"
  - "A login check is `if (md5($_GET['p']) == $stored_hash)`"
  - "You can pass an array where a string is expected (`?p[]=1`)"
  - "Two files must have the same MD5 or SHA-1 but different content"
  - "A password field is silently truncated (DES crypt() keeps 8 characters)"
  - "A challenge asks for `x != y` but `hash(x) == hash(y)`"
tools: [hashcat, fastcoll, hashclash, php, python]
source:
  name: "SHAttered"
  url: "https://shattered.io/"
related: [hash-length-extension, hash-hmac-timing-attack, block-cbc-mac-forgery, xor-known-plaintext]
---

## TL;DR

Two separate families of bug get called "hash collision" in CTFs:

1. **Comparison bugs.** PHP's `==` coerces two numeric-looking strings to numbers, so
   `"0e462097431906509019562988736854" == "0e830400451993494058024219903391"` is
   `true` - both are "zero times ten to the something". Any hash starting with `0e`
   and containing only digits afterwards is a *magic hash*. Also: passing an array
   makes many hash functions return `NULL`, and `NULL == NULL`.
2. **Real collisions.** MD5 is broken for identical-prefix (seconds) and chosen-prefix
   (hours) collisions; SHA-1 fell to SHAttered in 2017. Use prebuilt tools, or a
   birthday search when the challenge truncates the digest.

Plus the old classic: DES `crypt()` silently keeps only the first 8 password
characters, so `hunter2xxxxx` and `hunter2yyyyy` are the same password.

## Recognise it

- `if (md5($password) == $hash)` / `strcmp($a, $b) == 0` / `if ($a == $b)` in PHP.
- A `?hash=` parameter compared to a constant with `==`.
- `hash("md5", $_GET["x"]) == hash("md5", $_GET["y"])` with `$x !== $y` required.
- The challenge gives you a target digest that begins `0e` and is all digits.
- Two uploads must differ but hash the same (`md5sum a b` shows equal digests).
- A password field that ignores everything past the 8th character.
- `$2y$` bcrypt with a >72-byte password (bcrypt truncates at 72 bytes).

## Theory

**PHP loose comparison (PHP < 8.0).** `==` between two strings first checks whether
*both* are numeric strings. `0e462097431906509019562988736854` parses as
`0 * 10^462097...` = `0.0`. So every `0e[0-9]+` hash equals every other one, and
equals `"0"`, `"0.0"` and `0`. PHP 8.0 changed string-to-number comparison
(`"abc" == 0` is now false), but **two numeric strings are still compared
numerically**, so magic-hash collisions still work in PHP 8.

Known working pairs (verified by the script below):

| input | md5 |
|---|---|
| `240610708` | `0e462097431906509019562988736854` |
| `QNKCDZO` | `0e830400451993494058024219903391` |
| `0e215962017` | `0e291242476940776845150308577824` |
| `aabg7XSs` | `0e087386482136013740957780965295` |

| input | sha1 |
|---|---|
| `aaroZmOk` | `0e66507019969427134894567494305185566735` |
| `aaK1STfY` | `0e76658526655756207688271159624026011393` |
| `10932435112` | `0e07766915004133176347055865026311692244` |

| input | sha256 |
|---|---|
| `34250003024812` | `0e46289032038065916139621039085883773413820991920706299695051332` |
| `TyNOQHUS` | `0e66298694359207596086558843543959518835691168370379069085300385` |

`0e215962017` is the famous self-similar one: it *is* a magic hash and its MD5 *is*
a magic hash, so it survives a double-hash.

**Array bypass.** `md5(array())` in PHP emits a warning and returns `NULL`. Then
`NULL == NULL` and, worse, `NULL == "anything_non_numeric"` in PHP 7. Sending
`?password[]=1` therefore beats `md5($password) == $stored`. Same trick for
`strcmp($_GET['a'], $secret) == 0`: `strcmp` returns `NULL` on an array argument in
PHP < 8, and `NULL == 0` is true.

**Real MD5 collisions.**
- *Identical prefix* (Wang / `fastcoll`): given any prefix, produce two 128-byte
  suffixes that collide. Seconds on a laptop. Because MD5 is Merkle-Damgard, you can
  append the same arbitrary data to both and they still collide.
- *UniColl / chosen prefix* (`hashclash`): two **different** chosen prefixes made to
  collide. Minutes to hours. This is what makes "two valid PDFs / two valid JPEGs /
  two different certificates" possible.
- Because of length extension, `md5(A) == md5(B)` implies `md5(A||X) == md5(B||X)` for
  any `X` of your choice, once `A` and `B` are the same length. That is what turns a
  raw collision into a file-format collision.

**SHA-1.** SHAttered (2017) produced two PDFs with the same SHA-1 using an
identical-prefix attack; SHA-1 chosen-prefix followed in 2020. In CTFs you are
normally handed the colliding blocks rather than asked to compute them.

**Truncated digests.** If the challenge only compares the first `n` bytes, a birthday
search finds a collision in about `2^(4n)` operations - trivial for `n <= 6`.

**crypt() truncation.** Traditional DES `crypt(3)` uses only the first 8 characters of
the password and a 2-character salt; 4096 possible salts means salt collisions are
common too. `bcrypt` truncates at 72 bytes. `mysql_old_password` (MySQL323) has a
16-hex-digit output and is trivially collidable.

## Attack

1. Read the comparison operator. `==` in PHP, `==` on hex strings in JS, `if a == b`
   on ints in Python after `int(digest, 16)` - all exploitable.
2. If loose comparison: submit a magic-hash preimage from the table.
3. If array coercion is possible: `?p[]=`.
4. If a real collision is needed: `fastcoll -p prefix.bin -o a.bin b.bin` for
   identical-prefix, `hashclash` for chosen-prefix, or a birthday search for a
   truncated digest.
5. If the hash is a password hash: check for truncation (8 chars for descrypt,
   72 bytes for bcrypt) before brute-forcing anything.

## Code

```python
#!/usr/bin/env python3
"""Magic hashes, PHP type juggling, array bypasses, crypt() truncation and a real
birthday collision on a truncated digest.

Every constant in the tables is re-verified at runtime; nothing is taken on trust.
"""

import hashlib
import os
import re
import secrets
import string

# ------------------------------------------------- verified magic hashes
MAGIC_MD5 = ["240610708", "QNKCDZO", "0e215962017", "aabg7XSs", "aabC9RqS"]
MAGIC_SHA1 = ["aaroZmOk", "aaK1STfY", "aaO8zKZF", "aa3OFF9m", "10932435112"]
MAGIC_SHA256 = ["34250003024812", "TyNOQHUS"]


def is_magic(digest_hex: str) -> bool:
    """True if PHP would read this digest as the number zero."""
    return digest_hex.startswith("0e") and digest_hex[2:].isdigit()


# ------------------------------------------------------- PHP semantics
_PHP_NUMERIC = re.compile(r"^\s*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?\s*$")


def php_is_numeric_string(s) -> bool:
    return isinstance(s, str) and bool(_PHP_NUMERIC.match(s))


def php_loose_equals(a, b) -> bool:
    """Model of PHP's `==`. Two numeric strings are compared as numbers (still true
    in PHP 8). NULL equals NULL, and in PHP 7 NULL also equals "" and 0."""
    if a is None or b is None:
        other = b if a is None else a
        return other is None or other == 0 or other == "" or other is False
    if php_is_numeric_string(a) and php_is_numeric_string(b):
        return float(a) == float(b)
    return a == b


def php_md5(value):
    """md5() applied to an array returns NULL in PHP (with a warning)."""
    if isinstance(value, (list, dict)):
        return None
    return hashlib.md5(value.encode()).hexdigest()


def php_strcmp(a, b):
    """strcmp() returns NULL when handed an array (PHP < 8)."""
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return None
    return (a > b) - (a < b)


# --------------------------------------------------- vulnerable "app"
STORED_MD5 = hashlib.md5(b"240610708").hexdigest()      # the admin's real password


def vulnerable_login(password) -> bool:
    """if (md5($password) == $stored) -- the whole bug in one line."""
    return php_loose_equals(php_md5(password), STORED_MD5)


def vulnerable_strcmp_login(supplied, secret: str = "correct horse") -> bool:
    """if (strcmp($supplied, $secret) == 0)"""
    return php_loose_equals(php_strcmp(supplied, secret), 0) or \
        php_strcmp(supplied, secret) == 0


# ------------------------------------------------- crypt() truncation
def descrypt_model(salt: str, password: str) -> str:
    """Stand-in for traditional DES crypt(3): only the first 8 bytes matter.

    The real thing is `crypt(pw, salt)` / `openssl passwd -crypt -salt ab pw`; this
    model reproduces the property that makes it exploitable.
    """
    return salt + hashlib.sha256((salt + password[:8]).encode()).hexdigest()[:11]


# --------------------------------------------- birthday on a truncated digest
def truncated_sha256(data: bytes, nbytes: int = 4) -> bytes:
    return hashlib.sha256(data).digest()[:nbytes]


def birthday_collision(nbytes: int = 4, alphabet: str = string.ascii_lowercase):
    """Find x != y with truncated_sha256(x) == truncated_sha256(y)."""
    seen: dict[bytes, bytes] = {}
    while True:
        cand = "".join(secrets.choice(alphabet) for _ in range(12)).encode()
        h = truncated_sha256(cand, nbytes)
        if h in seen and seen[h] != cand:
            return seen[h], cand, h
        seen[h] = cand


# ------------------------- a toy Merkle-Damgard hash, to show why collisions grow
def toy_md(data: bytes, state: bytes = b"\x00" * 4) -> bytes:
    """8-byte blocks, 4-byte chaining value. Same shape as MD5, 2^32 times weaker."""
    assert len(data) % 8 == 0
    for i in range(0, len(data), 8):
        state = hashlib.sha256(state + data[i:i + 8]).digest()[:4]
    return state


def toy_md_collision():
    """Two one-block messages with the same chaining value."""
    seen: dict[bytes, bytes] = {}
    while True:
        cand = os.urandom(8)
        h = toy_md(cand)
        if h in seen and seen[h] != cand:
            return seen[h], cand
        seen[h] = cand


# --------------------------------------------------------------------- demo
if __name__ == "__main__":
    # --- every published constant re-verified ------------------------------
    for s in MAGIC_MD5:
        d = hashlib.md5(s.encode()).hexdigest()
        assert is_magic(d), (s, d)
        print(f"[+] md5({s:>14}) = {d}")
    for s in MAGIC_SHA1:
        d = hashlib.sha1(s.encode()).hexdigest()
        assert is_magic(d), (s, d)
        print(f"[+] sha1({s:>14}) = {d}")
    for s in MAGIC_SHA256:
        d = hashlib.sha256(s.encode()).hexdigest()
        assert is_magic(d), (s, d)
        print(f"[+] sha256({s:>12}) = {d}")
    print("[+] PASS all magic-hash constants verified")

    # the self-similar one: the string itself is magic-looking AND its md5 is magic
    assert php_is_numeric_string("0e215962017")
    assert not is_magic("0e12a4567890")                 # a letter breaks it
    assert is_magic(hashlib.md5(b"0e215962017").hexdigest())
    print("[+] 0e215962017 is numeric to PHP AND hashes to a magic hash")

    # --- loose comparison login bypass -------------------------------------
    assert vulnerable_login("240610708")            # the real password
    assert vulnerable_login("QNKCDZO")              # a completely different string
    assert vulnerable_login("aabg7XSs")
    assert not vulnerable_login("hunter2")
    print("[+] PASS type-juggling login bypass with QNKCDZO")

    # --- array bypass ------------------------------------------------------
    assert php_md5(["anything"]) is None
    assert not vulnerable_login(["x"]), "stored hash is a string, so NULL != it"
    # but when the app compares two *computed* hashes, arrays win outright:
    assert php_loose_equals(php_md5(["a"]), php_md5(["b"]))
    print("[+] PASS md5 array bypass: md5([]) == md5([]) because both are NULL")

    assert php_strcmp(["x"], "correct horse") is None
    assert vulnerable_strcmp_login(["x"])
    assert not vulnerable_strcmp_login("wrong")
    assert vulnerable_strcmp_login("correct horse")
    print("[+] PASS strcmp array bypass")

    # --- crypt() truncation ------------------------------------------------
    salt = "ab"
    stored = descrypt_model(salt, "sup3rs3cretpassword")
    assert descrypt_model(salt, "sup3rs3c") == stored
    assert descrypt_model(salt, "sup3rs3cANYTHINGATALL") == stored
    assert descrypt_model(salt, "sup3rs3d") != stored
    print("[+] PASS descrypt truncation: only the first 8 characters matter")

    # --- real collision on a truncated digest ------------------------------
    a, b, h = birthday_collision(4)
    assert a != b and truncated_sha256(a, 4) == truncated_sha256(b, 4)
    print(f"[+] PASS birthday collision on sha256[:4]: {a!r} / {b!r} -> {h.hex()}")

    # --- one collision becomes infinitely many -----------------------------
    # Merkle-Damgard: if H(A) == H(B) with len(A) == len(B), then H(A||X) == H(B||X)
    # for every X. That is exactly what turns a raw MD5 collision into two colliding
    # PDFs. Shown here on a toy MD hash where the collision is findable in a second.
    ma, mb = toy_md_collision()
    assert ma != mb and toy_md(ma) == toy_md(mb)
    for _ in range(5):
        x = os.urandom(8 * 4)
        assert toy_md(ma + x) == toy_md(mb + x)
    print(f"[+] PASS merkle-damgard collision extends: {ma.hex()} / {mb.hex()}")
    print("[+] (with a real fastcoll MD5 collision the same suffix trick applies)")

    print("\nall checks passed")
```

## Variants & pitfalls

- **PHP 8 changed `==` for string-vs-number, not string-vs-string.** `"abc" == 0` is
  now `false`, but `"0e123" == "0e456"` is still `true`. Magic hashes are alive.
- **`===` and `hash_equals()` are immune.** If the source uses either, look elsewhere.
- **Arrays do not always work.** PHP 8 makes `strcmp(array, string)` a `TypeError`,
  and `md5(array)` a `TypeError` too. Check the version banner.
- **`0e` needs *all* digits afterwards.** `0e12a4...` is not numeric, so it is not
  magic. That is why magic preimages are rare (about 1 in `2^30` for MD5).
- **Finding your own magic hash** is a `~2^30` brute force for MD5 (`0e` + 30 digits):
  perfectly feasible, a few minutes with a tight loop or hashcat with a mask and a
  `--outfile-format` filter.
- **Identical-prefix vs chosen-prefix.** `fastcoll` only gives you identical-prefix.
  If the challenge needs two *meaningful* different files, you need `hashclash`
  chosen-prefix, which is much more expensive.
- **Collisions are not preimages.** MD5 preimage resistance is still ~`2^123`. If the
  challenge gives you a digest and wants the input, this page is the wrong page -
  go crack it (`hash-cracking-cheatsheet`).
- **bcrypt truncates at 72 bytes**, so a 100-character password shares its hash with
  its 72-byte prefix. A real bug in password-manager-style challenges.
- **`hash("md5", $x, true)` (raw output)** can produce a string containing `'` or
  `"` - the classic "magic hash SQL injection" (`md5("129581926211651571912466741651878684928", true)`
  contains `' or '6`).

## Tools

- `fastcoll` - Marc Stevens' identical-prefix MD5 collision generator.
- `hashclash` - chosen-prefix MD5 collisions and UniColl.
- `hashcat -m 0 -a 3 ?a?a?a?a?a?a?a?a` with a filter for `0e[0-9]*` to mine new
  magic hashes.
- `php -r 'var_dump(md5("QNKCDZO") == md5("240610708"));'` to confirm the target's
  behaviour on its actual PHP version.
- `openssl passwd -crypt -salt ab hunter2` to reproduce DES crypt truncation.

## References

- SHAttered, the first SHA-1 collision: <https://shattered.io/>
- Marc Stevens' collision tooling is published as `hashclash`.
