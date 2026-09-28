---
title: "Tool - ffuf"
category: web
subcategory: fuzzing
type: tool
tags: [ffuf, fuzzing, directory-brute-force, content-discovery, vhost, parameter-discovery, wordlist, filtering, gobuster, feroxbuster, web-recon, clusterbomb, pitchfork]
summary: "Fast Go web fuzzer: directories, files, parameters, vhosts, and any other position in an HTTP request, with precise response filtering."
related: [web-triage, wordlists-and-resources, burpsuite, sqlmap]
---

## What it is

`ffuf` replaces one word (`FUZZ`) anywhere in an HTTP request with each line of a wordlist and reports the responses. Because `FUZZ` can appear in the URL, a header, the body, or a cookie, it covers directory brute forcing, parameter discovery, vhost enumeration, credential spraying and value fuzzing with one tool.

## Install

```sh
# Go (always current)
go install github.com/ffuf/ffuf/v2@latest    # binary lands in ~/go/bin
# Debian/Kali
sudo apt install ffuf
# macOS
brew install ffuf
# verify
ffuf -V
```

## The invocations that matter

```sh
U=https://target.ctf
W=/usr/share/seclists/Discovery/Web-Content

# 1. directories
ffuf -u "$U/FUZZ" -w "$W/raft-medium-directories.txt" -mc all -fc 404 -t 60

# 2. files with extensions
ffuf -u "$U/FUZZ" -w "$W/raft-medium-files.txt" -e .php,.txt,.bak,.old,.zip,.json,.js -mc all -fc 404

# 3. recursive discovery (follow every directory it finds)
ffuf -u "$U/FUZZ" -w "$W/raft-small-directories.txt" -recursion -recursion-depth 2 -mc all -fc 404

# 4. parameter names (GET)
ffuf -u "$U/page.php?FUZZ=test" -w "$W/burp-parameter-names.txt" -fs $(curl -s "$U/page.php" | wc -c)

# 5. parameter names (POST body)
ffuf -u "$U/api" -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' \
     -w "$W/burp-parameter-names.txt" -fs 0

# 6. vhost / subdomain enumeration via the Host header
ffuf -u "$U/" -H 'Host: FUZZ.target.ctf' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0

# 7. two wordlists at once (clusterbomb: every combination)
ffuf -u "$U/login" -X POST -d 'user=U1&pass=P1' \
     -w users.txt:U1 -w passwords.txt:P1 -mode clusterbomb -fr 'Invalid'

# 8. pitchfork mode (pair line N with line N)
ffuf -u "$U/FUZZHOST/FUZZPATH" -w hosts.txt:FUZZHOST -w paths.txt:FUZZPATH -mode pitchfork

# 9. authenticated fuzzing with a cookie and a proxy through Burp
ffuf -u "$U/FUZZ" -w "$W/common.txt" -b 'session=abc123' -x http://127.0.0.1:8080

# 10. save results for later processing
ffuf -u "$U/FUZZ" -w "$W/common.txt" -mc all -fc 404 -of json -o results.json
jq -r '.results[] | "\(.status) \(.length) \(.url)"' results.json | sort -n
```

Filtering and matching - this is where ffuf is won or lost:

| Flag | Meaning |
|---|---|
| `-mc` | match status codes (`-mc all` then filter, rather than guessing) |
| `-fc` | filter out status codes (`-fc 404`) |
| `-fs` | filter by response size (`-fs 1234`, or `-fs 100-200`) |
| `-fw` | filter by word count |
| `-fl` | filter by line count |
| `-fr` | filter by regex in the response |
| `-mr` | match by regex in the response |
| `-ms`, `-mw`, `-ml` | the match equivalents |
| `-ac` | auto-calibrate: send known-bad requests first and filter automatically |
| `-acc` | auto-calibrate with an extra custom string |

Other flags worth knowing: `-t 40` (threads), `-p 0.1` (delay between requests), `-rate 50` (requests/sec cap), `-timeout 10`, `-r` (follow redirects), `-ic` (ignore wordlist comment lines), `-s` (silent, machine-readable), `-D` (DirSearch-style wordlist expansion), `-request file.txt -request-proto https` (use a saved raw request as the template).

The workflow that actually works:
```sh
# 1. baseline: what does a definitely-missing path return?
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "$U/definitely-not-here-12345"
# 2. run with -mc all so nothing is hidden
ffuf -u "$U/FUZZ" -w "$W/common.txt" -mc all -t 60 | tee raw.txt
# 3. filter on the size you saw in step 1
ffuf -u "$U/FUZZ" -w "$W/raft-medium-directories.txt" -mc all -fs <baseline-size> -t 60
```

## Gotchas

- **Do not filter on `-fc 404` blindly.** Many CTF apps return `200` with a "not found" body for everything. Establish a baseline first and filter on size or a regex.
- Dynamic pages (timestamps, CSRF tokens, ads) change size every request, breaking `-fs`. Use `-fw` (word count) or `-fr` on a stable string instead, or `-ac`.
- `-ac` auto-calibration sends several junk requests per target and derives filters. It is the fastest way to a clean run, but it can over-filter - verify with a known-good path.
- `FUZZ` must appear exactly once per keyword. If you need two positions, name the keywords (`-w list.txt:KEY`).
- High `-t` will knock over a small CTF container and can get you rate-limited or banned. 40-60 is plenty; drop to 10 with `-p 0.1` if you see 429s.
- Wordlists with comments (`#`) produce junk requests: use `-ic`.
- ffuf does not render JavaScript. A single-page app's routes will not appear; read the JS bundle instead.
- Redirects are not followed by default. A `301` to the real content is still a hit - do not filter `3xx` away.
- URL-encoding: ffuf sends the wordlist entry literally. For payload fuzzing with special characters, pre-encode or use `-enc FUZZ:urlencode`.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| You want recursion with better UX | `feroxbuster` (recursive by default, excellent output) |
| Simple directory brute force | `gobuster dir -u URL -w list` |
| You need a browser-aware crawl | `katana`, `hakrawler`, or Burp's crawler |
| Parameter discovery specifically | `arjun -u URL`, `paramspider` |
| Fuzzing inside a complex authenticated flow | Burp Intruder / Turbo Intruder |
| Fuzzing a non-HTTP protocol | a Python script with `socket`, or `wfuzz` |
| Very large wordlists on a slow target | filter the wordlist first; brute force is rarely the intended path in CTF |
