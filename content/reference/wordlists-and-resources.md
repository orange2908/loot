---
title: "Reference - Wordlists: Which One, For What, and Where"
category: misc
subcategory: wordlists
type: reference
tags: [wordlists, rockyou, seclists, fuzzing, ffuf, gobuster, hashcat, john, rules, masks, directory-brute-force, subdomain, usernames, passwords, kali, parrot, macos, paths]
summary: "Which wordlist to use for each task, where it lives on Kali/Parrot/macOS, and how to build one when none fits."
related: [ffuf, hashcat, john, web-triage, common-ports-services]
---

## 1. Where they live

| System | Location |
|---|---|
| Kali Linux | `/usr/share/wordlists/` (symlinks into `/usr/share/`), SecLists at `/usr/share/seclists/` |
| Parrot OS | `/usr/share/wordlists/`, SecLists at `/usr/share/seclists/` |
| Debian/Ubuntu (manual) | wherever you cloned it; convention is `/usr/share/seclists` |
| macOS (Homebrew) | `brew install seclists` puts it under `$(brew --prefix)/share/seclists`; check with `brew --prefix seclists` |
| Anywhere | `git clone --depth 1 https://github.com/danielmiessler/SecLists` |

```sh
# find them on any system
ls -la /usr/share/wordlists/ 2>/dev/null
locate rockyou.txt 2>/dev/null || find / -name 'rockyou.txt*' 2>/dev/null
# Kali ships rockyou gzipped
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
wc -l /usr/share/wordlists/rockyou.txt      # ~14,344,391 lines
```

Set these once in your shell profile so every command is short:
```sh
export WL=/usr/share/wordlists
export SL=/usr/share/seclists
export ROCKYOU="$WL/rockyou.txt"
```

---

## 2. Passwords

| Wordlist | Size | Use it for |
|---|---|---|
| `rockyou.txt` | ~14.3M | the default for any password cracking or stego password. Real leaked passwords |
| `$SL/Passwords/Leaked-Databases/rockyou-75.txt` | ~59k | a fast first pass |
| `$SL/Passwords/Common-Credentials/10k-most-common.txt` | 10k | very fast triage |
| `$SL/Passwords/Common-Credentials/best1050.txt` | 1050 | a 5-second pass |
| `$SL/Passwords/Common-Credentials/xato-net-10-million-passwords.txt` | 10M | a modern alternative to rockyou |
| `$SL/Passwords/Default-Credentials/` | many | device/service defaults by vendor |
| `$SL/Passwords/darkweb2017-top10000.txt` | 10k | good hit rate for its size |
| `$WL/fasttrack.txt` | ~250 | tiny, surprisingly effective on CTF boxes |

Order of attack for an unknown hash:
```sh
# 1. tiny list, seconds
hashcat -m <mode> hash.txt "$SL/Passwords/Common-Credentials/10k-most-common.txt"
# 2. rockyou straight
hashcat -m <mode> hash.txt "$ROCKYOU"
# 3. rockyou with rules (the highest-yield step)
hashcat -m <mode> hash.txt "$ROCKYOU" -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hash.txt "$ROCKYOU" -r /usr/share/hashcat/rules/rockyou-30000.rule
# 4. masks for structured passwords
hashcat -m <mode> hash.txt -a 3 '?u?l?l?l?l?l?d?d'
# 5. a custom list built from the challenge itself (section 7)
```

Hashcat rule files ship in `/usr/share/hashcat/rules/`: `best64.rule`, `d3ad0ne.rule`, `dive.rule`, `rockyou-30000.rule`, `OneRuleToRuleThemAll.rule` (third-party, very effective). John's are in `/etc/john/john.conf` under `[List.Rules:...]` - use `--rules=Jumbo` or `--rules=KoreLogic`.

---

## 3. Web content discovery

| Wordlist | Size | Use it for |
|---|---|---|
| `$SL/Discovery/Web-Content/common.txt` | ~4.7k | the fast first sweep |
| `$SL/Discovery/Web-Content/raft-small-directories.txt` | ~20k | good directory coverage, fast |
| `$SL/Discovery/Web-Content/raft-medium-directories.txt` | ~30k | the default choice |
| `$SL/Discovery/Web-Content/raft-large-directories.txt` | ~62k | when medium finds nothing |
| `$SL/Discovery/Web-Content/raft-medium-files.txt` | ~17k | file names, pair with `-e` extensions |
| `$SL/Discovery/Web-Content/directory-list-2.3-medium.txt` | ~220k | the classic dirbuster list |
| `$SL/Discovery/Web-Content/directory-list-2.3-small.txt` | ~87k | faster version |
| `$SL/Discovery/Web-Content/big.txt` | ~20k | dirb's big list |
| `$SL/Discovery/Web-Content/burp-parameter-names.txt` | ~2.5k | **parameter discovery** |
| `$SL/Discovery/Web-Content/api/api-endpoints.txt` | - | REST API paths |
| `$SL/Discovery/Web-Content/graphql.txt` | - | GraphQL endpoint names |
| `$SL/Discovery/Web-Content/quickhits.txt` | ~2.4k | high-value files (`.git/HEAD`, `.env`, backups) |
| `$SL/Discovery/Web-Content/web-extensions.txt` | - | extension list for `-e` |
| `$SL/Discovery/Web-Content/CMS/` | - | WordPress/Joomla/Drupal specific |
| `$SL/Fuzzing/LFI/LFI-Jhaddix.txt` | - | LFI payloads |
| `$SL/Fuzzing/XSS/` | - | XSS payloads |
| `$SL/Fuzzing/SQLi/` | - | SQLi payloads |
| `$SL/Fuzzing/big-list-of-naughty-strings.txt` | ~500 | input-validation edge cases |

```sh
# the standard CTF web sweep
ffuf -u "$URL/FUZZ" -w "$SL/Discovery/Web-Content/raft-medium-directories.txt" -mc all -fc 404 -t 60
ffuf -u "$URL/FUZZ" -w "$SL/Discovery/Web-Content/raft-medium-files.txt" -e .php,.txt,.bak,.old,.zip,.json,.js -mc all -fc 404
ffuf -u "$URL/FUZZ" -w "$SL/Discovery/Web-Content/quickhits.txt" -mc all -fc 404
ffuf -u "$URL/index.php?FUZZ=1" -w "$SL/Discovery/Web-Content/burp-parameter-names.txt" -fs <baseline-size>
```
`ctfbrain search ffuf`

---

## 4. Subdomains and vhosts

| Wordlist | Size | Use |
|---|---|---|
| `$SL/Discovery/DNS/subdomains-top1million-5000.txt` | 5k | fast |
| `$SL/Discovery/DNS/subdomains-top1million-20000.txt` | 20k | the usual choice |
| `$SL/Discovery/DNS/subdomains-top1million-110000.txt` | 110k | thorough |
| `$SL/Discovery/DNS/bitquark-subdomains-top100000.txt` | 100k | alternative corpus |
| `$SL/Discovery/DNS/dns-Jhaddix.txt` | ~2M | exhaustive, slow |
| `$SL/Discovery/DNS/namelist.txt` | - | classic |

```sh
# vhost fuzzing (same IP, different Host header) - the CTF-relevant one
ffuf -u "http://$IP/" -H "Host: FUZZ.target.ctf" -w "$SL/Discovery/DNS/subdomains-top1million-5000.txt" -fs 0
# real DNS resolution
ffuf -u "http://FUZZ.target.ctf/" -w "$SL/Discovery/DNS/subdomains-top1million-20000.txt" -mc all
```

---

## 5. Usernames

| Wordlist | Use |
|---|---|
| `$SL/Usernames/top-usernames-shortlist.txt` | 17 entries, always try first |
| `$SL/Usernames/xato-net-10-million-usernames.txt` | 8.3M, for enumeration |
| `$SL/Usernames/Names/names.txt` | first names |
| `$SL/Usernames/cirt-default-usernames.txt` | vendor defaults |
| `/etc/passwd` from the target | the real answer, if you have file read |

---

## 6. Other useful corpora

| Wordlist | Use |
|---|---|
| `$WL/dirb/`, `$WL/dirbuster/` | legacy lists, still fine |
| `$SL/Miscellaneous/wordlist-common-snmp-community-strings.txt` | SNMP |
| `$SL/Discovery/Infrastructure/` | ports, services |
| `$SL/Pattern-Matching/` | regexes for secret scanning |
| `$SL/Payloads/` | malicious file samples (zip bombs, polyglots) |
| `/usr/share/dict/words` (or `/usr/share/dict/american-english`) | English dictionary - for classical ciphers, crib dragging, anagram solving |
| `$SL/Discovery/Variables/secret-keys.txt` | environment variable names |
| `$SL/Web-Shells/` | webshells for upload challenges |

On macOS, `/usr/share/dict/words` exists by default (~235k words) - useful for Vigenere key guessing and crib dragging.

---

## 7. Build a wordlist from the challenge itself

This beats rockyou for CTF-specific passwords more often than not.

```sh
# 1. scrape every word from the target site
cewl -d 3 -m 5 -w custom.txt https://target.ctf
cewl -d 3 -m 5 --with-numbers -w custom.txt https://target.ctf

# 2. every word from the handout files
cat handout/* 2>/dev/null | tr -cs 'A-Za-z0-9_' '\n' | sort -u | awk 'length($0)>3' > from_files.txt
strings -a binary | tr -cs 'A-Za-z0-9_' '\n' | sort -u | awk 'length($0)>3' >> from_files.txt

# 3. add the obvious CTF-specific words
printf '%s\n' "$CTFNAME" "$CHALLENGE" flag secret password admin ctf > seed.txt

# 4. mutate them (leetspeak, years, suffixes)
john --wordlist=seed.txt --rules=Jumbo --stdout > mutated.txt
hashcat --stdout seed.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# 5. targeted generation from known personal details
cupp -i          # interactive: name, partner, pet, birthdate

# 6. combine and dedupe
cat custom.txt from_files.txt mutated.txt | sort -u > final.txt; wc -l final.txt
```

Generate a keyspace directly when you know the format:
```sh
# all 6-char lowercase+digit strings
crunch 6 6 abcdefghijklmnopqrstuvwxyz0123456789 -o out.txt
# a known pattern: FLAG- then 4 digits
crunch 9 9 -t FLAG-%%%% -o out.txt
# hashcat masks (no file needed)
hashcat -a 3 -m 0 hash.txt '?u?l?l?l?l?d?d?d'
```

Hashcat mask charsets: `?l` = a-z, `?u` = A-Z, `?d` = 0-9, `?s` = specials, `?a` = all of the above, `?b` = 0x00-0xff, `?h` = 0-9a-f, `?H` = 0-9A-F. Custom: `-1 ?l?d -2 abcxyz` then use `?1`, `?2`.

---

## 8. Picking the right list, by task

| Task | List |
|---|---|
| Crack a hash you just found | `rockyou.txt` + `best64.rule` |
| Crack a ZIP/RAR/PDF password | `rockyou.txt`, then a custom list from the challenge |
| Crack a steghide password | `rockyou.txt` via `stegseek` (it is fast enough to use the full list) |
| Find hidden web directories | `raft-medium-directories.txt` |
| Find backup/config files | `quickhits.txt`, then `raft-medium-files.txt -e .bak,.old,.zip,.txt,.swp` |
| Find a hidden parameter | `burp-parameter-names.txt` |
| Find a vhost | `subdomains-top1million-5000.txt` |
| Brute force a login | `top-usernames-shortlist.txt` x `10k-most-common.txt` |
| Find an SNMP community string | `wordlist-common-snmp-community-strings.txt`, or just `public`/`private` |
| Guess a Vigenere key | `/usr/share/dict/words` filtered by length |
| Guess a crypto challenge's passphrase | a custom list from the challenge text |
| Fuzz for input-handling bugs | `big-list-of-naughty-strings.txt` |

---

## 9. Performance notes

- Sort and dedupe before use: `sort -u big.txt -o big.txt`. Duplicate entries waste real time on slow hashes.
- Filter by length when you know it: `awk 'length($0)==8' rockyou.txt > eight.txt`.
- Filter by charset: `grep -P '^[a-z0-9]+$' rockyou.txt > alnum.txt`.
- For very slow hashes (bcrypt, argon2, scrypt) a 14M-entry list is not viable. Use a 10k list plus rules, or a mask.
- `ffuf -t 60` is a sensible default; going much higher will get you rate-limited or will crash the challenge container. Be considerate - other teams share it.
- Always set `-fc 404` **and** check what a known-bad path returns; many CTF apps return 200 for everything.
- Keep a `~/ctf/wordlists/` of lists you built during past events; CTF authors reuse themes.
