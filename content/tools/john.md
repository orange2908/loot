---
title: "Tool - John the Ripper"
category: misc
subcategory: password-cracking
type: tool
tags: [john, john-the-ripper, jumbo, password-cracking, hash, zip2john, ssh2john, rules, wordlist, incremental, unshadow, formats, pot-file, cracking]
summary: "CPU password cracker with the best format coverage and the best *2john converters for turning files into crackable hashes."
related: [hashcat, wordlists-and-resources, stego-triage, forensics-triage]
---

## What it is

John the Ripper (the "jumbo" community build) cracks password hashes on the CPU. Its distinguishing feature for CTF is the enormous collection of `*2john` converters that turn an encrypted file - a ZIP, an SSH key, a PDF, a KeePass database, a Bitcoin wallet - into a hash string John can attack.

## Install

```sh
# Debian/Kali ship the jumbo build
sudo apt install john
# macOS
brew install john-jumbo
# from source for the newest formats and converters
git clone --depth 1 https://github.com/openwall/john -b bleeding-jumbo
cd john/src && ./configure && make -sj4      # binaries land in ../run/
# verify and see what formats you have
john --list=formats | tr ',' '\n' | head -40
ls /usr/share/john/*2john* /usr/sbin/*2john 2>/dev/null
```

## The invocations that matter

```sh
# 1. the default run: wordlist + the default rule set
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# 2. with mangling rules (the highest-yield option)
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo hash.txt
john --wordlist=rockyou.txt --rules=KoreLogic hash.txt

# 3. tell it the format when autodetection is wrong or ambiguous
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
john --list=formats | tr ',' '\n' | grep -i sha256

# 4. show what has already been cracked (results live in ~/.john/john.pot)
john --show hash.txt
john --show --format=raw-md5 hash.txt

# 5. incremental (pure brute force) with a length limit
john --incremental=ASCII --min-length=1 --max-length=6 hash.txt

# 6. a mask attack for a known pattern
john --mask='?u?l?l?l?l?d?d' hash.txt
john --mask='CTF-?d?d?d?d' hash.txt

# 7. Linux shadow file
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=rockyou.txt combined.txt

# 8. the *2john converters (this is why you keep John installed)
zip2john secret.zip > h.txt
rar2john secret.rar > h.txt
7z2john.pl secret.7z > h.txt
ssh2john id_rsa > h.txt
pdf2john.pl doc.pdf > h.txt
office2john.py doc.docx > h.txt
keepass2john db.kdbx > h.txt
gpg2john secret.gpg > h.txt
bitlocker2john -i disk.img > h.txt
truecrypt2john volume.tc > h.txt
luks2john disk.img > h.txt
# then:
john --wordlist=rockyou.txt h.txt && john --show h.txt

# 9. resume an interrupted session
john --session=ctf --wordlist=rockyou.txt hash.txt
john --restore=ctf

# 10. pipe a custom candidate generator into John
crunch 6 6 abc123 | john --stdin hash.txt
python3 gen_candidates.py | john --pipe --rules=Jumbo hash.txt
```

## Gotchas

- **`~/.john/john.pot` is sticky.** If John says "No password hashes left to crack (see FAQ)", it already cracked this hash in a previous run - use `--show`, or delete the pot file to re-crack.
- Autodetection picks one format when a hash string is ambiguous (a 32-hex string could be raw-MD5, NTLM, LM, MD4...). If it finds nothing, try each candidate format explicitly.
- The distro `john` on some systems is the **core** build, not jumbo, and lacks most formats and all the `*2john` converters. Check with `john --list=formats | wc -l` - jumbo has hundreds.
- The `*2john` scripts live in different places per install: `/usr/share/john/`, `/usr/sbin/`, or `run/` in a source build. `locate 2john` or `ls $(dirname $(which john))`.
- Some converters are Perl or Python scripts with the `.pl`/`.py` extension; some are compiled binaries. `zip2john` is compiled; `pdf2john.pl` is not.
- John is CPU-only in practice. For fast hashes (MD5, SHA1, NTLM) with a large keyspace, `hashcat` on a GPU is 100x faster. For slow hashes (bcrypt, PDF, Office) the gap is much smaller and John's format coverage wins.
- Rules matter more than wordlist size. `rockyou + Jumbo rules` beats a 100M-entry raw list most of the time.
- `--fork=4` uses multiple processes; John does not multithread all formats by default.
- For ZIP files using ZipCrypto with a known plaintext, **do not crack the password at all** - use `bkcrack`. It is minutes instead of never.

## If it fails, use instead

| Situation | Alternative |
|---|---|
| Fast hash, big keyspace, GPU available | `hashcat` (`ctfbrain search hashcat`) |
| ZipCrypto with known plaintext | `bkcrack` (`ctfbrain search bkcrack`) |
| steghide password | `stegseek` (purpose-built, far faster) |
| Unknown hash type | `hashid '<hash>'`, `hash-identifier`, or `name-that-hash` |
| Online lookup of a common hash | a rainbow-table lookup service, for unsalted MD5/SHA1 |
| The password is challenge-specific | build a custom wordlist from the challenge text (`cewl`, `strings`) |
| Not a password at all | re-read the challenge; cracking is rarely the intended path for a strong hash |
