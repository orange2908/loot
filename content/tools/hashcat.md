---
title: "Tool - hashcat"
category: misc
subcategory: password-cracking
type: tool
tags: [hashcat, gpu-cracking, password-cracking, hash-mode, mask-attack, rules, best64, wordlist, potfile, benchmark, ntlm, bcrypt, wpa, kerberos, cracking]
summary: "GPU-accelerated password cracker: pick the mode number, pick the attack mode, apply rules or a mask."
related: [john, wordlists-and-resources, crypto-triage]
---

## What it is

hashcat cracks password hashes on the GPU (and CPU). It is the fastest option for any hash with a large keyspace. The two things you must get right are the **mode number** (`-m`, which hash algorithm) and the **attack mode** (`-a`, how candidates are generated).

## Install

```sh
# Debian/Kali
sudo apt install hashcat
# macOS
brew install hashcat
# verify the GPU is actually usable
hashcat -I            # list OpenCL/CUDA devices
hashcat -b -m 0       # benchmark MD5
# if no GPU: force CPU
hashcat -D 1 -m 0 hash.txt wordlist.txt
```

## The invocations that matter

```sh
# 1. straight wordlist attack
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

# 2. wordlist + rules (the single highest-yield configuration)
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule

# 3. mask attack (brute force a known pattern)
hashcat -m 0 -a 3 hash.txt '?u?l?l?l?l?d?d?d'
hashcat -m 0 -a 3 hash.txt 'flag{?l?l?l?l?l?l}'
hashcat -m 0 -a 3 hash.txt --increment --increment-min=4 --increment-max=8 '?a?a?a?a?a?a?a?a'

# 4. combinator (word1+word2)
hashcat -m 0 -a 1 hash.txt left.txt right.txt

# 5. hybrid wordlist + mask
hashcat -m 0 -a 6 hash.txt rockyou.txt '?d?d?d?d'     # word then 4 digits
hashcat -m 0 -a 7 hash.txt '?d?d?d?d' rockyou.txt     # 4 digits then word

# 6. show cracked results (they live in ~/.local/share/hashcat/hashcat.potfile)
hashcat -m 0 hash.txt --show
hashcat -m 0 hash.txt --show --outfile-format=2       # plaintext only

# 7. identify the mode number for an unknown hash
hashcat --identify hash.txt
hashcat --help | grep -i 'sha-256'

# 8. custom charsets in a mask
hashcat -m 0 -a 3 hash.txt -1 '?l?d' -2 'abcxyz' '?1?1?1?2?2'

# 9. write results to a file and keep going
hashcat -m 0 -a 0 hash.txt rockyou.txt -o cracked.txt --outfile-format=2 --potfile-disable

# 10. resume / session management for long runs
hashcat -m 3200 -a 0 hash.txt rockyou.txt --session=ctf
hashcat --session=ctf --restore
```

Mode numbers you will actually use:

| `-m` | Hash |
|---|---|
| 0 | MD5 |
| 10 | md5($pass.$salt) |
| 20 | md5($salt.$pass) |
| 100 | SHA1 |
| 1000 | NTLM |
| 1400 | SHA2-256 |
| 1700 | SHA2-512 |
| 1800 | sha512crypt `$6$` |
| 500 | md5crypt `$1$` |
| 7400 | sha256crypt `$5$` |
| 3200 | bcrypt `$2*$` |
| 1600 | Apache apr1 |
| 400 | phpass / WordPress `$P$` |
| 10000 | Django PBKDF2-SHA256 |
| 22921 | RSA/DSA/EC/OpenSSH private keys (from `ssh2john`) |
| 13600 | WinZip AES |
| 17200-17230 | PKZIP variants |
| 13000 | RAR5 |
| 11600 | 7-Zip |
| 10400-10700 | PDF by version |
| 9400-9800 | MS Office by version |
| 13400 | KeePass |
| 22000 | WPA-PBKDF2-PMKID+EAPOL (the modern WPA mode) |
| 5600 | NetNTLMv2 |
| 13100 | Kerberos 5 TGS-REP (kerberoasting) |
| 18200 | Kerberos 5 AS-REP |
| 1500 | descrypt |
| 16500 | JWT (HMAC signature cracking) |
| 99999 | plaintext (for testing rules) |

Mask charsets: `?l` a-z, `?u` A-Z, `?d` 0-9, `?s` special, `?a` all of those, `?b` 0x00-0xff, `?h` 0-9a-f, `?H` 0-9A-F. Define your own with `-1`, `-2`, `-3`, `-4`.

Useful extra flags: `-w 3` (workload profile, 1-4; 3 is a good default, 4 makes the machine unusable), `--status --status-timer=10`, `--force` (ignore warnings on unsupported setups), `-O` (optimised kernels - faster but caps password length), `--runtime=3600`, `--left` (show uncracked hashes), `--username` (hash files in `user:hash` form), `--remove` (strip cracked hashes from the file).

## Gotchas

- **The mode number is everything.** `--identify` narrows it down but often lists several candidates; pick by the hash's visible structure (`$2b$` = bcrypt = 3200, `$6$` = 1800).
- **The potfile remembers.** "All hashes found as potfile entries" means it was already cracked - use `--show`, or `--potfile-disable` to force a fresh run.
- Hash file format matters: one hash per line, no whitespace, no quotes, no trailing spaces. Salted formats need the exact `hash:salt` separator hashcat expects for that mode (`--help` documents it per mode).
- `-O` (optimised) silently limits the maximum password length (usually 31 or less). If a long password is not found, retry without `-O`.
- In a VM without GPU passthrough, hashcat runs on the CPU and is slower than John. Check with `hashcat -I`.
- For slow hashes (bcrypt cost 12, argon2, PDF, Office) even a GPU does only thousands of guesses per second. A 14M wordlist may take hours; use a small list plus rules or a targeted mask.
- `--force` hides real driver problems; if results seem wrong, fix the driver rather than forcing.
- Rules are applied per wordlist entry, so `rockyou.txt` with a 30,000-rule file is 430 billion candidates - check the estimated time before starting.
- hashcat does not do `*2john`-style extraction. Use John's converters to produce the hash, then crack it with hashcat if the mode exists.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| No GPU | `john` on CPU; it is competitive for slow hashes |
| The format has no hashcat mode | `john --list=formats` - jumbo covers far more formats |
| Extracting a hash from a file | John's `*2john` converters |
| ZipCrypto with known plaintext | `bkcrack` - do not crack the password |
| steghide | `stegseek` |
| Unknown hash type | `hashid`, `name-that-hash`, or `hashcat --identify` |
| Cracking is taking forever | stop. In CTF, a hash that needs more than a wordlist+rules pass is usually not the intended path |
