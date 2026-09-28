---
title: "Web Fuzzing Cheatsheet - ffuf, feroxbuster, wfuzz, gobuster"
category: misc
subcategory: recon
type: cheatsheet
tags: [ffuf, feroxbuster, gobuster, wfuzz, dirsearch, content-discovery, vhost-fuzzing, parameter-fuzzing, filtering, seclists, recon, directory-brute-force]
summary: "Every useful flag and filter for the four main web fuzzers: directories, files, vhosts, parameters, recursion and false-positive filtering."
related: [net-content-discovery, net-subdomain-enum, net-nmap-and-recon-cheatsheet]
---

## Wordlists (SecLists paths)

```bash
# Fast first pass
/usr/share/seclists/Discovery/Web-Content/common.txt
# The workhorse directory list
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
# Files
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
# Classic dirbuster list (ordered by frequency)
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
# API endpoints
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
# Parameter names
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
# DNS / vhost names
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
```

## ffuf - directories

```bash
# Basic dir pass, match all, hide 404
ffuf -u http://t/FUZZ -w raft-medium-directories.txt -mc all -fc 404
# Auto-calibrate against random baselines (best soft-404 defence)
ffuf -u http://t/FUZZ -w raft-medium-directories.txt -ac
# Threads and request delay (rate limit friendly)
ffuf -u http://t/FUZZ -w list.txt -t 40 -p 0.1
# Follow redirects
ffuf -u http://t/FUZZ -w list.txt -r
# Verbose (show full URLs) and silent (results only)
ffuf -u http://t/FUZZ -w list.txt -v
ffuf -u http://t/FUZZ -w list.txt -s
```

## ffuf - files and extensions

```bash
# Append extensions to each word
ffuf -u http://t/FUZZ -w raft-medium-files.txt -e .php,.txt,.bak,.old,.zip -ac
# Only specific status codes
ffuf -u http://t/FUZZ -w list.txt -mc 200,301,302,401,403
```

## ffuf - filters and matchers

```bash
# Hide by size / words / lines (comma lists allowed)
ffuf -u http://t/FUZZ -w list.txt -fs 1234 -fw 210 -fl 45
# Hide a regex found on the 404 page (best when size is dynamic)
ffuf -u http://t/FUZZ -w list.txt -fr 'Page Not Found'
# Match only responses containing a marker
ffuf -u http://t/FUZZ -w list.txt -mr 'admin'
# Filter a size range
ffuf -u http://t/FUZZ -w list.txt -fs '<100'
# Match a size range
ffuf -u http://t/FUZZ -w list.txt -ms '200-5000'
```

## ffuf - recursion

```bash
# Recurse discovered dirs to depth 2 (use a SMALL wordlist)
ffuf -u http://t/FUZZ -w raft-small-directories.txt -recursion -recursion-depth 2 -ac
# Recurse only into specific statuses
ffuf -u http://t/FUZZ -w list.txt -recursion -rc 200,301
```

## ffuf - auth, headers, methods

```bash
# Cookie
ffuf -u http://t/FUZZ -w list.txt -b 'PHPSESSID=abc; role=user' -ac
# Bearer token + custom UA
ffuf -u http://t/api/FUZZ -w api.txt -H 'Authorization: Bearer eyJ...' -H 'User-Agent: Mozilla/5.0' -ac
# POST body fuzzing (login user enum)
ffuf -u http://t/login -X POST -d 'user=FUZZ&pass=x' -H 'Content-Type: application/x-www-form-urlencoded' -w users.txt -fr 'Unknown user'
```

## ffuf - parameters

```bash
# GET parameter name discovery
ffuf -u 'http://t/index.php?FUZZ=test' -w burp-parameter-names.txt -ac
# POST parameter name discovery
ffuf -u http://t/index.php -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' -w burp-parameter-names.txt -ac
# Two-position clusterbomb (name AND value)
ffuf -u 'http://t/?W1=W2' -w names.txt:W1 -w values.txt:W2 -mode clusterbomb -ac
# Pitchfork (paired lists)
ffuf -u 'http://t/?u=W1&p=W2' -w users.txt:W1 -w pass.txt:W2 -mode pitchfork -ac
```

## ffuf - vhost fuzzing

```bash
# Fuzz Host header against a fixed IP, hide default-site size
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w subdomains-top1million-20000.txt -fs 1234
# Auto-calibrate vhosts
ffuf -u http://10.10.10.5/ -H 'Host: FUZZ.target.ctf' -w subdomains-top1million-5000.txt -ac
```

## ffuf - output

```bash
# JSON output for later triage
ffuf -u http://t/FUZZ -w list.txt -o hits.json -of json
# All formats
ffuf -u http://t/FUZZ -w list.txt -o hits -of all
```

## feroxbuster

```bash
# Recursive by default, depth 3
feroxbuster -u http://t -w raft-medium-directories.txt -d 3 -t 50
# Filter status / size / words / lines
feroxbuster -u http://t -w list.txt --filter-status 404 --filter-size 1234
# Extract links from responses (finds paths not in the wordlist)
feroxbuster -u http://t -w raft-small-words.txt --extract-links
# Add extensions
feroxbuster -u http://t -w list.txt -x php,txt,bak
# With cookies / headers
feroxbuster -u http://t -w list.txt -b 'session=abc' -H 'Authorization: Bearer x'
# Resume a scan / save state
feroxbuster -u http://t -w list.txt --resume-from ferox-state.json
```

## gobuster

```bash
# Directory mode with status codes and extensions
gobuster dir -u http://t -w common.txt -x php,txt,bak -s 200,204,301,302,307,401,403 -b ''
# DNS subdomain brute force
gobuster dns -d target.com -w subdomains-top1million-20000.txt -t 50 -i
# Vhost mode (append base domain to each word)
gobuster vhost -u http://10.10.10.5 -w subdomains-top1million-5000.txt --append-domain
# Generic fuzz mode (FUZZ keyword)
gobuster fuzz -u http://t/FUZZ -w list.txt --exclude-length 1234
# S3 bucket mode
gobuster s3 -w bucket-names.txt
```

## wfuzz

```bash
# Directory brute, hide 404 (hc)
wfuzz -c -z file,list.txt --hc 404 http://t/FUZZ
# Hide by chars/words/lines
wfuzz -c -z file,list.txt --hh 1234 http://t/FUZZ
# POST login brute with response-word filter
wfuzz -c -z file,pass.txt -d 'user=admin&pass=FUZZ' --hw 25 http://t/login
# Two payloads
wfuzz -c -z file,users.txt -z file,pass.txt -d 'user=FUZZ&pass=FUZ2Z' --hc 401 http://t/login
```

## dirsearch

```bash
# Sensible defaults with extension tagging, exclude statuses
dirsearch -u http://t -e php,html,js,txt,bak -x 404,403 --random-agent
# Recursive
dirsearch -u http://t -e php -r -R 2
# With a cookie
dirsearch -u http://t -e php --cookie 'session=abc'
```

## Custom wordlists

```bash
# Build a target-specific wordlist from the site's text
cewl -d 2 -m 4 -w custom.txt http://t
# Mangle with hashcat rules into candidates
hashcat --stdout custom.txt -r /usr/share/hashcat/rules/best64.rule > candidates.txt
# Pull paths already referenced in HTML/JS
curl -s http://t | grep -oE '(href|src)="[^"]+"' | cut -d'"' -f2 | sort -u
```

## Backup / leak checks

```bash
# Backup suffixes on known files
for f in index.php config.php; do for s in .bak .old .orig .save '~' .swp .txt .zip; do curl -s -o /dev/null -w "%{http_code} $f$s\n" "http://t/$f$s"; done; done
# Common leak paths
for p in /.git/HEAD /.env /.DS_Store /robots.txt /sitemap.xml /.well-known/security.txt /swagger.json /openapi.json; do echo "== $p"; curl -s "http://t$p" | head -2; done
```
