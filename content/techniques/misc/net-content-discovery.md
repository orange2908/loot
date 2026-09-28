---
title: "Web Content Discovery - Directory, File and Parameter Fuzzing"
category: misc
subcategory: recon
type: technique
tags: [ffuf, feroxbuster, gobuster, dirsearch, wfuzz, content-discovery, directory-brute-force, seclists, wordlists, soft-404, recursion, vhost-fuzzing, parameter-fuzzing, backup-files, recon]
difficulty: easy
summary: "Find unlinked paths, files, parameters and vhosts with ffuf/feroxbuster; the hard part is wordlist choice and killing soft-404 false positives."
when_to_use:
  - "A web app shows a default page or a tiny amount of linked content"
  - "You need an admin panel, an upload dir, a backup file or an API route that is not linked"
  - "Your fuzzer returns 10000 hits with HTTP 200 and you need to filter them"
  - "The IP serves a placeholder page and you suspect name-based virtual hosts"
tools: [ffuf, feroxbuster, gobuster, dirsearch, wfuzz, seclists, httpx]
related: [net-subdomain-enum, net-fuzzing-cheatsheet, svc-source-leakage]
---

## TL;DR

Content discovery is brute forcing the URL space. Pick the right wordlist for the stack, add the
right extensions, recurse into directories you find, and calibrate the filter so soft-404s do not
drown the signal. `ffuf` for speed and precision, `feroxbuster` for automatic recursion.

## Recognise it

- The site has almost no links, or is a single static page.
- You found a framework fingerprint (PHP/Java/ASP.NET/Node) but no entry points.
- A path like `/admin` 302-redirects instead of 404-ing -- the app knows about it.
- Response sizes vary by one or two bytes across "not found" pages: a soft-404 that echoes the path.

## Attack

### Step 1 -- baseline the 404 first

Before fuzzing, learn what "not found" looks like. Request a path that certainly does not exist.

```bash
# Baseline: status code, size, word count and line count of a guaranteed-miss path
curl -s -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' http://target.ctf/definitely-not-here-12345

# Same for a fake file with the extension you plan to fuzz
curl -s -o /dev/null -w 'status=%{http_code} size=%{size_download}\n' http://target.ctf/nope12345.php
```

If the miss returns **200** with a fixed size, you filter on size (`-fs`). If it returns 200 with a
size that varies with the path length, filter on words or lines (`-fw` / `-fl`) or use ffuf's
auto-calibration (`-ac`).

### Step 2 -- first pass, directories

```bash
# Fast directory pass: 40 threads, follow no redirects, hide 404s
ffuf -u http://target.ctf/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 40 -mc all -fc 404

# Auto-calibrate against random baselines instead of hand-picking a filter
ffuf -u http://target.ctf/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -ac

# gobuster equivalent, with status codes and a 10s timeout
gobuster dir -u http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -s 200,204,301,302,307,401,403 -b '' --timeout 10s

# feroxbuster: recursive by default, depth 3, smart filtering
feroxbuster -u http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -d 3 -t 50 --filter-status 404
```

Note `-mc all -fc 404`: match everything, then hide 404. This surfaces 401/403/500, which are
*more* interesting than 200 -- a 403 on `/admin` proves the directory exists.

### Step 3 -- files with the right extensions

Extensions depend on the server stack. Guessing `.php` on a Java app wastes the whole run.

| Fingerprint | Extensions to fuzz |
|---|---|
| Apache + PHP | `php,phtml,php3,php5,phps,html,txt,bak,old,zip,inc` |
| nginx + PHP-FPM | `php,html,txt,json,bak` |
| IIS / ASP.NET | `asp,aspx,ashx,asmx,config,txt,bak` |
| Java (Tomcat/Jetty) | `jsp,jspx,do,action,war,xml,properties` |
| Node/Express | `js,json,map,txt,env` |
| Python (Flask/Django) | `py,txt,json,cfg,env,pyc` |
| Static / unknown | `txt,html,json,xml,bak,old,zip,tar.gz,7z,sql,log` |

```bash
# ffuf with an extension list -- each word is tried with each suffix
ffuf -u http://target.ctf/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -e .php,.txt,.bak,.old,.zip -ac

# gobuster with extensions and a no-extension pass in the same run
gobuster dir -u http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak,old,zip

# dirsearch has a sensible built-in list plus automatic extension tagging
dirsearch -u http://target.ctf -e php,html,js,txt,bak -x 404,403 --random-agent
```

### Step 4 -- recursion

```bash
# ffuf recursion: follow discovered directories to depth 2, only recurse into 30x/200
ffuf -u http://target.ctf/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -recursion -recursion-depth 2 -ac

# feroxbuster with an extraction of links from responses (finds paths the wordlist misses)
feroxbuster -u http://target.ctf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --extract-links -d 4
```

Recursion multiplies the request count; use a **small** wordlist when recursing and a large one
only at depth 1.

### Step 5 -- wordlist selection

```
/usr/share/seclists/Discovery/Web-Content/
  common.txt                         # 4.7k, fast first pass
  raft-small-directories.txt         # good recursion list
  raft-medium-directories.txt        # the workhorse
  raft-large-words.txt               # last resort
  directory-list-2.3-small.txt       # dirbuster, ordered by hit frequency
  directory-list-2.3-medium.txt      # the classic 220k list
  big.txt                            # 20k, decent coverage
  api/api-endpoints.txt              # API routes
  Web-Content/CMS/                   # wordpress/joomla/drupal specific
  burp-parameter-names.txt           # parameter fuzzing
```

Strategy: `common.txt` -> `raft-medium-directories.txt` -> stack-specific list
(`CMS/wordpress.fuzz.txt`, `tomcat.txt`, etc.) -> `directory-list-2.3-medium.txt` if desperate.
Also build a target-specific list from the site itself:

```bash
# Harvest words from the live site to make a custom wordlist
cewl -d 2 -m 4 -w custom.txt http://target.ctf

# Pull every path already referenced in the HTML/JS
curl -s http://target.ctf | grep -oE '(href|src)="[^"]+"' | cut -d'"' -f2 | sort -u
```

### Step 6 -- filtering false positives

```bash
# Hide by size, word count and line count (comma lists are allowed)
ffuf -u http://target.ctf/FUZZ -w list.txt -fs 1234 -fw 210 -fl 45

# Hide a regex in the body -- best filter when size is dynamic
ffuf -u http://target.ctf/FUZZ -w list.txt -fr 'Page Not Found'

# Match only responses whose body contains a marker
ffuf -u http://target.ctf/FUZZ -w list.txt -mr 'admin'

# Filter a size RANGE (ffuf accepts ranges with >, < and comma lists)
ffuf -u http://target.ctf/FUZZ -w list.txt -fs '<100'
```

Order of preference: `-ac` (auto-calibrate) -> `-fr` regex on the 404 text -> `-fw` -> `-fs`.
Size filters break the moment the app echoes the requested path.

### Step 7 -- authenticated and header-based fuzzing

```bash
# Fuzz with a session cookie
ffuf -u http://target.ctf/FUZZ -w list.txt -b 'PHPSESSID=abc123; role=user' -ac

# Fuzz with a bearer token and a custom user agent
ffuf -u http://target.ctf/api/FUZZ -w api-endpoints.txt -H 'Authorization: Bearer eyJ...' -H 'User-Agent: Mozilla/5.0' -ac

# POST body fuzzing -- find valid usernames on a login endpoint
ffuf -u http://target.ctf/login -X POST -d 'user=FUZZ&pass=x' -H 'Content-Type: application/x-www-form-urlencoded' -w users.txt -fr 'Unknown user'
```

### Step 8 -- parameter discovery

```bash
# GET parameter names: look for a response that differs from the baseline
ffuf -u 'http://target.ctf/index.php?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac

# Same for POST bodies
ffuf -u http://target.ctf/index.php -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' -w burp-parameter-names.txt -ac

# Dedicated tool: arjun brute forces parameters with built-in chunking
arjun -u http://target.ctf/index.php

# Two-position fuzzing: parameter name AND value at once
ffuf -u 'http://target.ctf/?W1=W2' -w names.txt:W1 -w values.txt:W2 -mode clusterbomb -ac
```

### Step 9 -- vhost fuzzing (different from DNS brute force)

```bash
# Fuzz the Host header against a fixed IP; filter the default-site response size
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 1234

# gobuster vhost mode, appending the base domain automatically
gobuster vhost -u http://target.ctf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

See `net-subdomain-enum` for the full treatment.

### Step 10 -- backup and leftover files

```bash
# Try the classic backup suffixes against every file you already found
for f in index.php config.php db.php; do
  for s in .bak .old .orig .save '~' .swp .txt .1 .zip; do
    curl -s -o /dev/null -w "%{http_code} $f$s\n" "http://target.ctf/$f$s"
  done
done

# Vim swap file recovery once you have downloaded .index.php.swp
vim -r .index.php.swp

# Source leak checks worth one request each
curl -s http://target.ctf/.git/HEAD
curl -s http://target.ctf/.env
curl -s http://target.ctf/.DS_Store -o DS_Store
curl -s http://target.ctf/robots.txt
curl -s http://target.ctf/sitemap.xml
curl -s http://target.ctf/.well-known/security.txt
```

## Code

Triage helper: re-requests every hit a fuzzer found, clusters responses by body hash, and tells
you which ones are actually distinct. Kills soft-404 noise after the fact.

```python
#!/usr/bin/env python3
"""Cluster fuzzing hits by response fingerprint to expose soft-404s.

Usage:
    ffuf -u http://t/FUZZ -w list.txt -mc all -o hits.json -of json
    python3 triage.py hits.json
    # or feed it a plain list of URLs on stdin
    cat urls.txt | python3 triage.py -
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import defaultdict
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

TIMEOUT = 8


def load_urls(source: str) -> list[str]:
    """Read URLs from a ffuf JSON report or from stdin."""
    if source == "-":
        return [line.strip() for line in sys.stdin if line.strip()]
    with open(source, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [r["url"] for r in data.get("results", []) if "url" in r]


def fetch(url: str) -> tuple[int, int, str]:
    """Return (status, length, sha1-of-body) for a URL, tolerating errors."""
    req = Request(url, headers={"User-Agent": "triage/1.0"})
    try:
        with urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            return resp.status, len(body), hashlib.sha1(body).hexdigest()[:12]
    except HTTPError as exc:
        body = exc.read()
        return exc.code, len(body), hashlib.sha1(body).hexdigest()[:12]
    except (URLError, OSError) as exc:
        return 0, 0, f"err:{type(exc).__name__}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    urls = load_urls(argv[1])
    clusters: dict[tuple[int, str], list[str]] = defaultdict(list)
    for url in urls:
        status, length, digest = fetch(url)
        clusters[(status, digest)].append(url)
        print(f"{status:>3} {length:>8} {digest} {url}", file=sys.stderr)

    print("\n=== clusters (largest = almost certainly the soft-404 template) ===")
    for (status, digest), members in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
        tag = "NOISE" if len(members) > 3 else "LOOK"
        print(f"[{tag}] status={status} body={digest} count={len(members)}")
        for url in members[:5]:
            print(f"        {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

## Variants & pitfalls

- **Soft-404s.** The single biggest time sink. Always baseline first; prefer `-ac` or `-fr`.
- **Rate limiting / WAF.** If hits stop abruptly, lower `-t` (ffuf threads) or add `-p 0.1` (delay).
  A sudden wall of 429 or 403 means you are being throttled, not that the paths do not exist.
- **Case sensitivity.** Linux paths are case sensitive, IIS is not. On IIS also try the 8.3
  short-name trick (`~1`) when you see a legacy server.
- **Trailing slash.** Some servers 301 `/admin` -> `/admin/`. Follow redirects (`-r` in ffuf)
  or you will miss content behind them, but then filter on the final size.
- **Extensions on the wrong stack** double the run time for zero value. Fingerprint first.
- **`-mc all` matters.** Default ffuf matching is `200,204,301,302,307,401,403,405,500`; if the
  app answers 418 or 302-to-login you may miss it.
- **Huge wordlists are not a strategy.** `directory-list-2.3-medium.txt` with 5 extensions is
  1.1M requests. Start small, recurse, and build a custom list from the site.
- **Fuzzing the wrong vhost.** If the IP hosts several names, fuzz each name separately; results differ.
- **API routes** rarely live in web wordlists. Use `api-endpoints.txt`, look for `/api/v1/`,
  swagger at `/swagger.json`, `/openapi.json`, `/api-docs`, and GraphQL at `/graphql`.

## Tools

- `ffuf` -- fastest, most flexible, best filters; the default choice.
- `feroxbuster` -- recursion and link extraction with sane defaults.
- `gobuster` -- simple, has `dir`, `dns`, `vhost`, `fuzz` and `s3` modes.
- `dirsearch` -- good built-in wordlist and reporting.
- `wfuzz` -- older, still useful for complex multi-payload cases.
- `arjun` -- dedicated HTTP parameter discovery.
- `cewl` -- build a target-specific wordlist from the site's own text.
- SecLists -- the wordlist collection everything above assumes.

## References

- SecLists (Discovery/Web-Content, Discovery/DNS) -- the standard wordlist repository.
- `ffuf -h` and the ffuf wiki shipped with the tool for the full filter/matcher matrix.
- OWASP Web Security Testing Guide, "Review Webserver Metafiles" and "Enumerate Applications" sections.
