---
title: "SQL Injection - MySQL File Read and Write"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, mysql, mariadb, load-file, into-outfile, into-dumpfile, secure-file-priv, file-privilege, plugin-dir, udf, lib-mysqludf-sys, local-infile, load-data-local, client-side-file-read, allowloadlocalinfile, information-schema, sqlmap]
difficulty: medium
summary: "MySQL's file primitives are gated by FILE privilege and secure_file_priv; LOCAL INFILE inverts the trust and lets a server read the client's disk."
when_to_use:
  - "You have SQL execution against MySQL/MariaDB and want to know whether file read or write is reachable"
  - "You need to explain why LOAD_FILE returns NULL rather than an error"
  - "The challenge involves a MySQL client connecting out to a server you influence"
  - "You are assessing how much a MySQL injection reaches on a hardened default install"
tools: [mysql, sqlmap, burp]
related: [sqli-union-based, sqli-postgres-rce, lfi-to-rce]
---

## TL;DR

MySQL can read and write files on the server host, but only for a user holding the `FILE` privilege and only
within whatever `secure_file_priv` allows - and on every modern default that variable is set to a directory
no web root lives in. The separate and more interesting primitive is `LOAD DATA LOCAL INFILE`, which reverses
the direction: the **server** asks the **client** for a file, so a client that has local-infile enabled will
hand over any path the server names.

## Recognise it

- `SELECT version()` -> `8.0.35` or `10.11.6-MariaDB`. `@@version_comment` names the distribution.
- Errors: `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version`.
- `#` and `-- ` both comment; `/*! */` executes as a versioned comment. That last one is a MySQL fingerprint.
- `SELECT LOAD_FILE('/etc/hostname')` returning `NULL` rather than raising - MySQL signals *every* file-read
  failure as NULL, which is why this looks so confusing the first time.
- `SHOW VARIABLES LIKE 'secure_file_priv'` returns an empty string, a path, or `NULL`.

## Theory

### Two gates, both server-side

A file read or write from MySQL passes two independent checks:

1. **The `FILE` privilege**, a global grant (`GRANT FILE ON *.*`). It cannot be scoped to one database, which
   is exactly why it is so rarely granted - handing it out gives read access to everything the mysqld user
   can read, everywhere.
2. **`secure_file_priv`**, a read-only server variable set at startup:

| Value | Meaning |
|-------|---------|
| `NULL` | file import/export **disabled entirely** - no path works, for anyone |
| `''` (empty) | no restriction; any path the mysqld OS user can reach |
| `/some/dir` | reads and writes confined to that directory |

MySQL 5.7.6+ ships with this defaulting to a platform-specific directory such as `/var/lib/mysql-files`.
That default is what makes "write a webshell to the web root" a historical technique rather than a current
one: the web root is not that directory, and you cannot change the variable from SQL because it is read-only.

The confusing part is the error reporting. `LOAD_FILE()` returns `NULL` when the file does not exist, when
the mysqld user cannot read it, when it exceeds `max_allowed_packet`, when `FILE` is missing, *and* when
`secure_file_priv` forbids the path. One symptom, five causes. Distinguish them by checking the variables
directly rather than by guessing from the NULL:

```sql
SELECT user(), current_user();
SELECT @@secure_file_priv, @@version, @@plugin_dir, @@max_allowed_packet;
SELECT * FROM information_schema.user_privileges WHERE grantee LIKE CONCAT("'", SUBSTRING_INDEX(user(), '@', 1), "'%");
```

### Reading: LOAD_FILE

```sql
SELECT LOAD_FILE('/etc/hostname');
SELECT HEX(LOAD_FILE('/etc/hostname'));   -- survives binary content and narrow reflections
```

`LOAD_FILE` reads the file whole, into memory, subject to `max_allowed_packet`. There is no offset/length
form, which is a real difference from Postgres: to window a large file you wrap it in `SUBSTRING()`, and the
whole read still happens server-side first.

`HEX()` matters for the same reason `encode(...,'base64')` does on Postgres - it makes binary content
survive a text channel, and it makes the value safe to carry through a reflection that would otherwise
mangle it.

### Writing: INTO OUTFILE versus INTO DUMPFILE

```sql
SELECT 'content' INTO OUTFILE '/var/lib/mysql-files/a.txt';
SELECT 'content' INTO DUMPFILE '/var/lib/mysql-files/a.bin';
```

The difference is not cosmetic:

- `INTO OUTFILE` writes a *result set* using the table-export format. It escapes backslashes, and it appends
  row and column terminators (newline and tab by default). Fine for text, corrupting for anything else.
- `INTO DUMPFILE` writes **one row, one column, raw** - no escaping, no terminators. This is the only one
  that can reproduce a binary file byte for byte, which is why every shared-object write uses it.

Both refuse to overwrite an existing file. That is a genuine constraint, not a quirk to work around: a failed
write leaves no partial file, and a second attempt at the same path fails regardless of content.

### UDF via the plugin directory

MySQL can load a user-defined function from a shared object in `@@plugin_dir`
(`CREATE FUNCTION sys_exec RETURNS INT SONAME 'x.so'`). Chaining that to a file write requires
`@@plugin_dir` to be *writable by the mysqld OS user* and reachable under `secure_file_priv` - two
conditions that are both false on a packaged install, where the plugin directory is root-owned and the
file-priv directory is somewhere else entirely. The historical `lib_mysqludf_sys` library is the usual
subject of these writeups. Treat the whole path as a statement about misconfiguration rather than a
technique: if the plugin directory is writable by the database, the deployment has a bigger problem than
the injection.

### LOAD DATA LOCAL INFILE - the direction reverses

This is the one worth understanding properly, because it is not a server-side file read at all.

`LOAD DATA LOCAL INFILE '/path' INTO TABLE t` is a *client* feature. The protocol exchange:

1. The client sends the statement as a normal `COM_QUERY` packet.
2. The server, instead of replying with a result set or an OK packet, replies with a packet whose first byte
   is `0xFB` followed by a **filename**.
3. The client opens that path on its own disk and streams the contents back to the server.
4. The server replies with an OK packet.

The security property that falls out of this: the filename in step 2 comes from the server. A well-behaved
server echoes the path the client asked for, but nothing in the protocol requires that. A server that
answers *any* query with a `0xFB` packet naming a path of its choosing will receive that file from the
client - the client is not in a position to know the request was unsolicited, because the protocol has no
field that ties the response to the original filename.

That makes it a client-side file disclosure triggered by connecting to an untrusted server. It is the
mechanism behind the "malicious MySQL server" class of challenge, and behind real incidents where a tool
that connects to user-supplied database hosts leaked local files.

The controls are all client-side, which is the point:

- `local_infile` server variable gates whether the server will *ask* (`SET GLOBAL local_infile=0`).
- The client must also have it enabled: `--enable-local-infile` for the CLI, `allowLoadLocalInfile: false`
  (the default in modern mysqljs/mysql2), `local_infile=False` in Python connectors, `allowLoadLocalInfile`
  in Connector/J. Modern clients default this **off** precisely because of this exchange.
- `LOAD DATA` without `LOCAL` is server-side and follows `secure_file_priv` instead.

So when a challenge hands you "point this app at a database host you control", the question to ask is which
client library it uses and what that library's default is.

## Attack

1. **Fingerprint** MySQL versus MariaDB and get the version - the `secure_file_priv` default changed at 5.7.6.
2. **Read the variables before trying anything**: `@@secure_file_priv`, `@@plugin_dir`, `@@max_allowed_packet`,
   and the user's privileges from `information_schema.user_privileges`. Five NULL causes collapse to one
   answer once you have these.
3. **Decide read or write.** `NULL` secure_file_priv ends it. A directory value means reads and writes are
   possible but confined there, which is usually useless for execution and still fine for reading a flag that
   happens to live there.
4. **For reads**, wrap in `HEX()` and window with `SUBSTRING()` if the channel is narrow.
5. **For the client-side variant**, identify the client library and its local-infile default; that single
   fact decides whether the exchange is reachable.

## Code

An offline decision helper for the two server-side gates plus the client-side one. It encodes the
`secure_file_priv` semantics and the NULL-ambiguity that makes this primitive confusing, and runs with no
database.

```python
#!/usr/bin/env python3
"""Reason about MySQL file-access reachability from server variables.

Encodes the secure_file_priv semantics, the FILE privilege gate, and the
client-side local-infile question. Pure local logic; no database, no network.
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass


@dataclass
class ServerFacts:
    version: str
    has_file_priv: bool
    secure_file_priv: str | None   # None models SQL NULL; "" models unrestricted
    plugin_dir: str = "/usr/lib/mysql/plugin"
    plugin_dir_writable_by_mysqld: bool = False


def _within(path: str, root: str) -> bool:
    """True if path sits inside root, comparing normalised absolute paths."""
    root = posixpath.normpath(root)
    target = posixpath.normpath(path)
    return target == root or target.startswith(root.rstrip("/") + "/")


def can_access(facts: ServerFacts, path: str) -> tuple[bool, str]:
    """Can the server read/write `path`? Returns (verdict, the deciding reason)."""
    if not facts.has_file_priv:
        return False, "no FILE privilege (global grant, cannot be scoped to one schema)"
    if facts.secure_file_priv is None:
        return False, "secure_file_priv is NULL - import/export disabled server-wide"
    if facts.secure_file_priv == "":
        return True, "secure_file_priv empty - unrestricted, subject to OS permissions"
    if _within(path, facts.secure_file_priv):
        return True, f"inside secure_file_priv ({facts.secure_file_priv})"
    return False, f"outside secure_file_priv ({facts.secure_file_priv})"


def null_causes(facts: ServerFacts, path: str) -> list[str]:
    """Every reason LOAD_FILE() might return NULL for this path.

    The point of this function: MySQL reports all of these identically, so a NULL
    tells you nothing on its own. Enumerate rather than guess.
    """
    causes: list[str] = []
    if not facts.has_file_priv:
        causes.append("FILE privilege missing")
    if facts.secure_file_priv is None:
        causes.append("secure_file_priv is NULL")
    elif facts.secure_file_priv and not _within(path, facts.secure_file_priv):
        causes.append("path outside secure_file_priv")
    causes.append("file may not exist")
    causes.append("mysqld OS user may lack read permission")
    causes.append("file may exceed max_allowed_packet")
    return causes


def udf_reachable(facts: ServerFacts) -> tuple[bool, str]:
    """A shared object must be writable to a directory the server will load from."""
    ok, why = can_access(facts, posixpath.join(facts.plugin_dir, "x.so"))
    if not ok:
        return False, f"cannot write into plugin_dir: {why}"
    if not facts.plugin_dir_writable_by_mysqld:
        return False, "plugin_dir not writable by the mysqld OS user (root-owned on packaged installs)"
    return True, "plugin_dir is both within secure_file_priv and writable - misconfigured host"


CLIENT_LOCAL_INFILE_DEFAULTS = {
    "mysql-cli": False,          # needs --enable-local-infile
    "mysql2 (node)":  False,     # allowLoadLocalInfile defaults false
    "mysqlclient (python)": False,
    "connector-j (java)": False, # allowLoadLocalInfile defaults false
    "legacy-client": True,       # the shape that makes the exchange reachable
}


def client_file_read_reachable(client: str) -> tuple[bool, str]:
    """Would this client honour an unsolicited 0xFB filename request?"""
    if client not in CLIENT_LOCAL_INFILE_DEFAULTS:
        return False, f"unknown client {client!r} - check its local-infile default explicitly"
    enabled = CLIENT_LOCAL_INFILE_DEFAULTS[client]
    if enabled:
        return True, "local-infile enabled by default: server names a path, client streams it back"
    return False, "local-infile disabled by default; needs explicit opt-in"


if __name__ == "__main__":
    modern = ServerFacts("8.0.35", has_file_priv=True,
                         secure_file_priv="/var/lib/mysql-files")
    legacy = ServerFacts("5.5.62", has_file_priv=True, secure_file_priv="")
    locked = ServerFacts("8.0.35", has_file_priv=True, secure_file_priv=None)
    noprivs = ServerFacts("8.0.35", has_file_priv=False, secure_file_priv="")

    print("== can_access('/var/www/html/s.php') ==")
    for name, f in [("modern default", modern), ("legacy unrestricted", legacy),
                    ("locked (NULL)", locked), ("no FILE priv", noprivs)]:
        ok, why = can_access(f, "/var/www/html/s.php")
        print(f"  {name:<22} {'yes' if ok else 'no ':<4} {why}")

    # The modern default blocks the web root but permits its own directory.
    assert not can_access(modern, "/var/www/html/s.php")[0]
    assert can_access(modern, "/var/lib/mysql-files/out.txt")[0]
    # NULL and a missing FILE privilege block everything, everywhere.
    assert not can_access(locked, "/var/lib/mysql-files/out.txt")[0]
    assert not can_access(noprivs, "/tmp/x")[0]
    # An old unrestricted server reaches anything the OS permits.
    assert can_access(legacy, "/var/www/html/s.php")[0]
    # Traversal does not escape the confinement: normpath collapses it first.
    assert not can_access(modern, "/var/lib/mysql-files/../../../etc/passwd")[0]

    print("\n== why LOAD_FILE returned NULL (modern default, web root) ==")
    for cause in null_causes(modern, "/var/www/html/s.php"):
        print(f"  - {cause}")
    assert len(null_causes(modern, "/var/www/html/s.php")) >= 4, "NULL is ambiguous by design"

    print("\n== UDF path ==")
    for name, f in [("packaged install", modern),
                    ("misconfigured", ServerFacts("5.5.62", True, "", "/tmp/plugin", True))]:
        ok, why = udf_reachable(f)
        print(f"  {name:<22} {'yes' if ok else 'no ':<4} {why}")
    assert not udf_reachable(modern)[0]

    print("\n== client-side LOAD DATA LOCAL INFILE ==")
    for client in CLIENT_LOCAL_INFILE_DEFAULTS:
        ok, why = client_file_read_reachable(client)
        print(f"  {client:<22} {'yes' if ok else 'no ':<4} {why}")
    assert client_file_read_reachable("legacy-client")[0]
    assert not client_file_read_reachable("mysql2 (node)")[0]

    print("\nself-test ok")
```

## Variants & pitfalls

- **NULL is not an error.** `LOAD_FILE` collapses five distinct failures into one return value. Read the
  variables instead of inferring from it.
- **`secure_file_priv` is read-only.** `SET GLOBAL secure_file_priv=''` fails. It is a startup option, so
  there is no in-band way to widen it.
- **OUTFILE corrupts binaries.** The row/column terminators and backslash escaping are applied silently.
  Use `DUMPFILE` for anything that is not plain text.
- **Neither write overwrites.** Existing destination means failure, so a half-finished attempt blocks the
  retry at that path.
- **MariaDB diverges.** Variable defaults and plugin handling differ from MySQL at the same nominal version;
  check `@@version_comment` rather than assuming.
- **`max_allowed_packet` caps reads** - a large file returns NULL for size reasons alone, which looks exactly
  like a permission failure.
- **`LOAD DATA LOCAL INFILE` is not server-side file read.** Confusing the two leads to hunting for `FILE`
  privilege on a target where the relevant setting lives in the client.
- **The client-side exchange needs the client to connect to you.** It is not reachable through an injection
  into an app that talks to its own database.

### Defence / what closes this

Do not grant `FILE` to an application database user; it is global by construction and cannot be scoped. Leave
`secure_file_priv` at a dedicated directory or set it to `NULL` outright if no feature imports or exports
files. Keep `@@plugin_dir` root-owned and not writable by the mysqld user, which removes the UDF path
entirely. Set `local_infile=0` on the server, and leave the client-side local-infile option disabled - the
modern connector defaults are already off, so the risk is a deployment that explicitly turned it back on.
Never point a database client at a host supplied by a user. And use parameterised queries, which removes the
injection that reaches any of this.

## Tools

- `mysql` CLI - check `@@secure_file_priv` behaviour against a local container before theorising remotely.
- `sqlmap` - `--file-read`, `--file-write` and `--privileges` implement these checks.
- Burp Repeater - for one-value-at-a-time extraction through a reflection.

## References

- MySQL manual, `LOAD_FILE()`: https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file
- MySQL manual, `SELECT ... INTO`: https://dev.mysql.com/doc/refman/8.0/en/select-into.html
- MySQL manual, `secure_file_priv`: https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_secure_file_priv
- MySQL manual, security considerations for LOAD DATA LOCAL: https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html
- MySQL manual, privileges provided by MySQL (`FILE`): https://dev.mysql.com/doc/refman/8.0/en/privileges-provided.html
- PayloadsAllTheThings, MySQL injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
