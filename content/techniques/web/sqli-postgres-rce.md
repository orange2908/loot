---
title: "SQL Injection - PostgreSQL Server-Side Primitives"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, postgres, postgresql, copy-from-program, pg-read-file, pg-ls-dir, pg-read-binary-file, large-object, lo-import, lo-export, dblink, postgres-fdw, plpythonu, create-function, superuser, pg-execute-server-program, pg-read-server-files, privilege-enumeration, sqlmap]
difficulty: medium
summary: "On Postgres the interesting primitives (program execution, file read, dblink) are role-gated - enumerate the role first, because that decides which of them exist at all."
when_to_use:
  - "You have SQL execution against PostgreSQL and want to reason about leaving the database"
  - "`version()` returns a `PostgreSQL x.y` banner, or errors mention `unterminated quoted string at or near`"
  - "You need to understand why a documented Postgres primitive returns `permission denied` for your role"
  - "You are assessing how much a Postgres injection actually reaches on a given deployment"
tools: [psql, sqlmap, burp]
related: [sqli-union-based, sqli-error-based, sqli-mysql-file-rce, ssrf-fundamentals]
---

## TL;DR

Postgres exposes several server-side primitives that touch the host: program execution, file read/write,
and outbound connections. None of them are toggled by a config flag you can flip from SQL - every one is
gated by **role membership**. So the technique is not a payload, it is an enumeration: establish what your
role is allowed to do, and that tells you which primitives exist for you at all. Most of the time the answer
is "none of them", and knowing that quickly is worth more than a payload list.

## Recognise it

- `SELECT version()` -> `PostgreSQL 14.9 (Debian 14.9-1) on x86_64-pc-linux-gnu, compiled by gcc ...`
- Error text: `unterminated quoted string at or near "'"`, `syntax error at or near`,
  `operator does not exist: integer = text`, `column "x" does not exist`.
- `UNION` is type-strict. `UNION types integer and text cannot be matched` is a Postgres fingerprint by itself,
  and it is why `NULL` padding matters more here than on MySQL.
- String concatenation is `||`. `SELECT 'a'||'b'` -> `ab`. `+` on text is an error.
- Stacked queries are frequently available (psycopg2's `execute`, PDO_pgsql). This matters a lot, because
  `COPY`, `CREATE FUNCTION` and `DO` are *statements*, not expressions - without stacking you are limited to
  what fits in a `SELECT`.
- `SHOW data_directory` returns something like `/var/lib/postgresql/14/main`.

## Theory

### The privilege model is the whole story

Postgres 11 replaced "superuser or nothing" with **default roles**, renamed *predefined roles* in 14.
Each server-side capability hangs off one of them:

| Role | What membership grants |
|------|------------------------|
| `pg_read_server_files` | `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir` on absolute paths |
| `pg_write_server_files` | `COPY ... TO '<abs path>'`, `lo_export` |
| `pg_execute_server_program` | `COPY ... FROM/TO PROGRAM` |
| `superuser` | all of the above, plus `CREATE FUNCTION ... LANGUAGE C` and untrusted procedural languages |

Before 11, `pg_read_file` was superuser-only *and* confined to paths under the data directory, which is why
old writeups show relative escapes like `pg_read_file('../../../../etc/passwd')`. From 11 onward a member of
`pg_read_server_files` passes an absolute path directly, and the relative trick is unnecessary.

The practical consequence: an injection into an app whose database user is an ordinary owner of one schema
reaches **none** of this. A lot of CTF challenges hand you a superuser connection precisely because otherwise
the category would not exist. Checking is one query, so check before theorising.

### Enumeration queries

These are the questions worth asking, in order. Each is a single scalar, so each doubles as a blind-injection
oracle (`AND (SELECT usesuper FROM pg_user WHERE usename=current_user)`):

```sql
SELECT version();
SELECT current_user, session_user;
SELECT usesuper FROM pg_user WHERE usename = current_user;
SELECT pg_has_role(current_user, 'pg_read_server_files', 'member');
SELECT pg_has_role(current_user, 'pg_write_server_files', 'member');
SELECT pg_has_role(current_user, 'pg_execute_server_program', 'member');
SELECT has_function_privilege(current_user, 'pg_read_file(text)', 'execute');
SHOW data_directory;
SHOW is_superuser;
SELECT extname FROM pg_extension;      -- is dblink / postgres_fdw already installed?
```

`pg_has_role(...)` returning `t` is the single most informative bit on the whole target: it converts
"maybe there is an escalation here" into a yes/no in one round trip.

### COPY ... FROM PROGRAM - program execution

`COPY` moves rows between a table and a file. Since 9.3 it can also move rows to or from the standard
streams of a **shell command** run by the `postgres` OS user:

```sql
COPY t FROM PROGRAM 'id';
```

This is documented, intentional functionality (it exists so DBAs can pipe through `gzip`), restricted to
superusers and `pg_execute_server_program`. There is no server setting that disables it short of not granting
the role. Because the command goes through `/bin/sh -c`, ordinary shell syntax applies inside it.

The mechanism worth internalising: the privilege boundary is the role grant, not the syntax. Filtering the
word `PROGRAM` in an application WAF does nothing about a role that should not have had the grant.

### pg_read_file and friends - file read

```sql
SELECT pg_ls_dir('/');                                     -- one row per entry
SELECT pg_read_file('/etc/hostname');                      -- whole file as text
SELECT pg_read_file('/etc/hostname', 0, 200);              -- offset, length
SELECT encode(pg_read_binary_file('/etc/hostname'), 'base64');
```

`pg_read_file` returns `text` and therefore **fails on invalid UTF-8** with
`invalid byte sequence for encoding "UTF8"`. `pg_read_binary_file` returns `bytea` and never does. When a
read errors on something binary-looking, that is the reason; switch to the binary form and wrap it in
`encode(..., 'base64')`, which also makes the output survive a narrow reflection window.

The `offset, length` form is the one that matters for blind extraction: it turns a whole-file read into a
windowed read you can walk, which is what you need when the response only shows you a short string.

### Large objects - the other file path

The `lo_*` family stores blobs in `pg_largeobject` as 2048-byte pages:

- `lo_import('/path')` returns an OID; the bytes then live in
  `SELECT data FROM pg_largeobject WHERE loid = <oid> ORDER BY pageno`.
- `lo_from_bytea(0, decode('...','base64'))` builds an object from data you supply; `lo_export(oid, '/path')`
  writes it out.

Two reasons this is worth knowing even when `pg_read_file` works. First, the privilege check is a different
one, so a role can have one and not the other. Second, the page-per-row structure means you can fetch a large
file through a reflection that only shows one short value at a time, without needing the `offset, length`
arguments.

### dblink and postgres_fdw - outbound connections

`dblink('host=10.0.0.5 port=6379 ...', 'SELECT 1')` makes the **database server** open a TCP connection.
That is server-side request forgery with the database's network position, which is often deeper inside the
network than the web tier. Two practical limits that decide whether it is useful:

- The extension must be installed (`CREATE EXTENSION dblink` needs privilege; check `pg_extension` first).
- It speaks the Postgres wire protocol, so against a non-Postgres service you get a connection attempt and an
  error, not a controlled exchange. The error text is still an oracle for "is this port open", which makes it
  a port scanner even when it is nothing more.

Connection *errors* frequently differ between "connection refused", "timed out" and "received invalid
response", and that difference is the scan result. See `ssrf-fundamentals` for the general model.

### Procedural languages

`plpythonu` and `plperlu` are *untrusted* languages - the `u` suffix means exactly that - and creating a
function in one requires superuser. `CREATE FUNCTION ... LANGUAGE C` loads a shared object from disk and is
likewise superuser-only. All three are the same story as `COPY ... FROM PROGRAM`: documented capability,
gated on the role, not on syntax.

## Attack

1. **Fingerprint.** Confirm Postgres from the error grammar or `version()`.
2. **Establish stacking.** Can you terminate with `;` and run a second statement? If not, you are limited to
   expression context, which rules out `COPY`, `CREATE FUNCTION` and `DO` and leaves `pg_read_file`,
   `lo_import` and `dblink` (all callable inside a `SELECT`).
3. **Enumerate the role.** Run the block above. This is the branch point; everything after it is decided here.
4. **Pick by privilege, not by preference.** `pg_execute_server_program` -> program execution.
   `pg_read_server_files` -> file read. Neither -> you are staying in the database, so pivot to reading
   application tables, credentials and any secrets stored in them.
5. **Choose the output channel.** If the injection reflects, read directly. If it is blind, use the windowed
   read (`offset, length`) or large-object pages, and drive it with a boolean or timing oracle.

## Code

An offline reasoning helper. It takes the results of the enumeration block and reports which primitives are
reachable and why - the point being that this is a *decision procedure over privileges*, not a payload list.
It runs with no database and no network.

```python
#!/usr/bin/env python3
"""Decide which PostgreSQL server-side primitives a role can reach.

Feed it the answers to the enumeration queries in the Theory section; it reports
which primitives exist for that role, and which are ruled out and by what.
Pure local logic - no database connection, no network.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RoleFacts:
    """The answers to the enumeration block, as scalars."""
    version_major: int
    is_superuser: bool = False
    read_server_files: bool = False
    write_server_files: bool = False
    execute_server_program: bool = False
    stacked_queries: bool = True
    extensions: list[str] = field(default_factory=list)


@dataclass
class Finding:
    primitive: str
    available: bool
    reason: str

    def __str__(self) -> str:
        mark = "yes" if self.available else "no "
        return f"  [{mark}] {self.primitive:<28} {self.reason}"


def assess(f: RoleFacts) -> list[Finding]:
    out: list[Finding] = []
    sup = f.is_superuser

    # Program execution: role-gated AND statement-context-gated.
    if not (sup or f.execute_server_program):
        out.append(Finding("COPY ... FROM PROGRAM", False,
                           "needs superuser or pg_execute_server_program"))
    elif not f.stacked_queries:
        out.append(Finding("COPY ... FROM PROGRAM", False,
                           "role permits it, but COPY is a statement and stacking is unavailable"))
    else:
        out.append(Finding("COPY ... FROM PROGRAM", True,
                           "role grants it and statements can be stacked"))

    # File read: callable inside SELECT, so stacking is irrelevant.
    if sup or f.read_server_files:
        note = ("absolute paths allowed (v11+)" if f.version_major >= 11
                else "pre-11: confined to the data directory, needs a relative escape")
        out.append(Finding("pg_read_file / pg_ls_dir", True, note))
    else:
        out.append(Finding("pg_read_file / pg_ls_dir", False,
                           "needs superuser or pg_read_server_files"))

    # Large objects: lo_import reads, lo_export writes - different privilege each way.
    out.append(Finding("lo_import (read to pg_largeobject)", sup or f.read_server_files,
                       "same read privilege; pages are fetchable one row at a time"
                       if (sup or f.read_server_files) else "needs the server-file read privilege"))
    out.append(Finding("lo_export (write to disk)", sup or f.write_server_files,
                       "role grants server-file write" if (sup or f.write_server_files)
                       else "needs superuser or pg_write_server_files"))

    # Outbound connections: extension presence is the gate, not just the role.
    has_dblink = "dblink" in f.extensions
    has_fdw = "postgres_fdw" in f.extensions
    if has_dblink or has_fdw:
        out.append(Finding("dblink / postgres_fdw SSRF", True,
                           f"installed: {', '.join(x for x in ('dblink', 'postgres_fdw') if x in f.extensions)}"))
    elif sup:
        out.append(Finding("dblink / postgres_fdw SSRF", True,
                           "not installed, but superuser can CREATE EXTENSION dblink"))
    else:
        out.append(Finding("dblink / postgres_fdw SSRF", False,
                           "extension absent and role cannot CREATE EXTENSION"))

    # Untrusted PLs and C functions are superuser-only, full stop.
    out.append(Finding("CREATE FUNCTION (C / plpythonu)", sup and f.stacked_queries,
                       "superuser with stacking" if (sup and f.stacked_queries)
                       else "superuser-only, and needs statement context"))
    return out


def report(name: str, f: RoleFacts) -> list[Finding]:
    findings = assess(f)
    reachable = sum(1 for x in findings if x.available)
    print(f"\n{name}  (Postgres {f.version_major}, {reachable}/{len(findings)} primitives reachable)")
    for finding in findings:
        print(finding)
    return findings


if __name__ == "__main__":
    # The common CTF shape: superuser connection, stacking available.
    sup = RoleFacts(version_major=14, is_superuser=True, stacked_queries=True)
    got = report("superuser, stacked", sup)
    assert all(x.available for x in got), "superuser should reach everything"

    # The common real-world shape: ordinary app owner. Nothing host-side is reachable.
    app = RoleFacts(version_major=14, is_superuser=False, stacked_queries=True)
    got = report("ordinary app role", app)
    assert not any(x.available for x in got), "unprivileged role should reach nothing host-side"

    # Role has the read grant but the injection is expression-only (no stacking).
    # File read still works, because pg_read_file is callable inside a SELECT.
    reader = RoleFacts(version_major=13, is_superuser=False,
                       read_server_files=True, stacked_queries=False)
    got = report("pg_read_server_files, no stacking", reader)
    by_name = {x.primitive: x for x in got}
    assert by_name["pg_read_file / pg_ls_dir"].available
    assert not by_name["COPY ... FROM PROGRAM"].available

    # Pre-11 with the read grant: absolute paths are not allowed, note says so.
    old = RoleFacts(version_major=9, is_superuser=False, read_server_files=True)
    got = report("pre-11 reader", old)
    assert "data directory" in {x.primitive: x for x in got}["pg_read_file / pg_ls_dir"].reason

    # Program execution granted without superuser - the interesting middle case.
    prog = RoleFacts(version_major=15, execute_server_program=True, extensions=["dblink"])
    got = report("pg_execute_server_program only", prog)
    by_name = {x.primitive: x for x in got}
    assert by_name["COPY ... FROM PROGRAM"].available
    assert not by_name["pg_read_file / pg_ls_dir"].available, "separate grant, separate answer"
    assert by_name["dblink / postgres_fdw SSRF"].available, "extension already installed"

    print("\nself-test ok")
```

## Variants & pitfalls

- **`SHOW is_superuser` lies about roles.** It reflects the session's superuser status, not membership in
  the predefined roles. A role with `pg_execute_server_program` and no superuser bit shows `off` here and
  still has program execution. Use `pg_has_role` for the real answer.
- **Stacking is a property of the driver, not the database.** The same injection is statement-capable through
  one client library and expression-only through another. Test it rather than assuming.
- **`pg_read_file` on binary data errors out** with an encoding complaint. That error is not "permission
  denied" and does not mean the read failed for privilege reasons.
- **`current_user` versus `session_user`.** Inside a `SECURITY DEFINER` function they differ, and the
  privilege checks follow `current_user`. If your enumeration is running inside one, you may be measuring the
  wrong role.
- **`COPY TO '<path>'` writes as the `postgres` OS user**, so the destination must be writable by that user -
  which the data directory is and most web roots are not.
- **Type strictness costs you UNION columns.** Postgres rejects mismatched types across a UNION, so the
  `NULL`-padding probe is not optional here the way it is on MySQL.
- **dblink against a non-Postgres port** yields a protocol error, not a usable exchange. Useful as a port
  oracle, not as a general-purpose client.

### Defence / what closes this

Do not connect the application to the database as a superuser or as a member of any `pg_*_server_files` or
`pg_execute_server_program` role - that single change removes every primitive on this page, regardless of
what gets past input validation. Give the app role ownership of only its own schema, and use parameterised
queries so the injection does not exist in the first place. Do not install `dblink` or `postgres_fdw` unless
a feature needs them. Run the cluster as an unprivileged OS user with the data directory outside any
web-served path, and put egress filtering in front of the database host so that a connection made by the
database has somewhere it cannot go.

## Tools

- `psql` - the reference client; use it to confirm behaviour locally before reasoning about a remote target.
- `sqlmap` - `--dbms=postgresql`, `--privileges` and `--current-user` automate the enumeration block.
- Burp Repeater - for driving the one-scalar-at-a-time oracles by hand.
- A local Postgres in Docker - the only honest way to check which of these your target's version permits.

## References

- PostgreSQL manual, `COPY`: https://www.postgresql.org/docs/current/sql-copy.html
- PostgreSQL manual, predefined roles: https://www.postgresql.org/docs/current/predefined-roles.html
- PostgreSQL manual, server-side file functions: https://www.postgresql.org/docs/current/functions-admin.html
- PostgreSQL manual, large objects: https://www.postgresql.org/docs/current/lo-funcs.html
- PostgreSQL manual, `dblink`: https://www.postgresql.org/docs/current/dblink.html
- PayloadsAllTheThings, PostgreSQL injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
