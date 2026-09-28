---
title: "Hash Cracking Cheatsheet - hashcat, John, Masks, Rules, Identification"
category: crypto
subcategory: hash-cracking
type: cheatsheet
tags: [hashcat, john-the-ripper, jtr, hash-cracking, password-cracking, rockyou, seclists, mask-attack, rule-based-attack, best64, hashid, name-that-hash, ntlm, netntlmv2, kerberoast, bcrypt, sha512crypt, descrypt, jwt, zip2john]
summary: "Mode numbers that actually show up in CTF, the *2john family, mask and rule syntax, wordlist advice, and a length/prefix table for identifying an unknown hash."
tools: [hashcat, john, hashid, hash-identifier, name-that-hash, cewl, crunch, maskprocessor]
related: [hash-collisions-magic, hash-length-extension, hash-hmac-timing-attack]
---

## Identify it first

```text
# hex length -> candidates (all lowercase hex, no prefix)
16   MySQL323 (old MySQL), CRC-based junk
32   MD5, MD4, NTLM, LM (half), RIPEMD-128, MD2, Snefru-128
40   SHA-1, RIPEMD-160, HAVAL-160, Tiger-160, MySQL4.1+ (usually shown with a leading *)
48   Tiger-192, HAVAL-192
56   SHA-224, SHA3-224, HAVAL-224
64   SHA-256, SHA3-256, BLAKE2s-256, RIPEMD-256, GOST, Keccak-256, SM3
96   SHA-384, SHA3-384
128  SHA-512, SHA3-512, BLAKE2b-512, Whirlpool
# base64 instead of hex? decode first: 44 b64 chars -> 32 bytes -> SHA-256.

# prefix -> scheme (modular crypt format, $id$rounds$salt$hash)
$1$      md5crypt                      hashcat 500     john md5crypt
$apr1$   Apache md5crypt               hashcat 1600    john md5crypt-long
$2a$ $2b$ $2y$   bcrypt                hashcat 3200    john bcrypt
$5$      sha256crypt                   hashcat 7400    john sha256crypt
$6$      sha512crypt                   hashcat 1800    john sha512crypt
$y$      yescrypt (modern Linux)       -- john "crypt" / unshadow + libxcrypt
$7$      scrypt                        hashcat 8900    john scrypt
$argon2i$ $argon2id$ $argon2d$         hashcat 34000-ish -- VERIFY with --example-hashes
{SSHA}   LDAP salted SHA-1 (base64)    hashcat 111     john ssha
{SHA}    LDAP SHA-1 (base64)           hashcat 101     john Raw-SHA1
$P$ $H$  phpass (WordPress, Joomla)    hashcat 400     john phpass
$pbkdf2-sha256$  passlib pbkdf2        hashcat 10900   john PBKDF2-HMAC-SHA256
$krb5tgs$23$...  Kerberoast TGS-REP    hashcat 13100   john krb5tgs
$krb5asrep$23$.. AS-REP roast          hashcat 18200   john krb5asrep
$DCC2$ / $MSCASH2$  domain cached cred hashcat 2100    john mscash2
$ml$     macOS 10.8+ PBKDF2-SHA512     hashcat 7100    john PBKDF2-HMAC-SHA512
$sha1$   Atlassian / passlib sha1_crypt -- VERIFY
$NT$     NTLM in a john-style file     hashcat 1000    john NT
$office$ / $oldoffice$                 hashcat 9400+   john office
$zip2$ / $pkzip2$                      hashcat 13600 / 17200+  john ZIP / PKZIP
$RAR3$ / $rar5$                        hashcat 12500 / 13000   john rar / RAR5
$7z$                                   hashcat 11600   john 7z
$keepass$                              hashcat 13400   john KeePass
$bitcoin$                              hashcat 11300   john Bitcoin
eyJ...  (three base64 parts, dots)     JWT: hashcat 16500 for HS256/384/512
aad3b435b51404ee...:<32 hex>           LM:NTLM pair from a SAM/NTDS dump
```

```sh
# Tooling: none of these are authoritative, always sanity-check the result.
hashid -m '5f4dcc3b5aa765d61d8327deb882cf99'        # -m prints hashcat modes
hash-identifier                                      # interactive, older, noisier
nth --text '5f4dcc3b5aa765d61d8327deb882cf99'        # name-that-hash, ranked guesses
haiti '5f4dcc3b5aa765d61d8327deb882cf99'             # another identifier, if installed

# The ground truth is hashcat's own example list:
hashcat --example-hashes | less
hashcat --example-hashes | grep -i -B2 -A2 'bcrypt'
hashcat -h | grep -i 'kerberos'
john --list=formats | tr ',' '\n' | grep -i krb
john --list=format-details --format=bcrypt
```

## hashcat mode numbers worth memorising

```text
# raw and salted
    0  MD5                         100  SHA-1                1400  SHA2-256
 1700  SHA2-512                    900  MD4                  1000  NTLM
   10  md5($pass.$salt)             20  md5($salt.$pass)
  110  sha1($pass.$salt)           120  sha1($salt.$pass)
 1410  sha256($pass.$salt)        1420  sha256($salt.$pass)
 1710  sha512($pass.$salt)        1720  sha512($salt.$pass)
  160  HMAC-SHA1 (key = $salt)    1450  HMAC-SHA256 (key = $salt)
  150  HMAC-SHA1 (key = $pass)    1460  HMAC-SHA256 (key = $pass)
 1700  SHA2-512                   17400 SHA3-256 (VERIFY)     600  BLAKE2b-512

# unix / os
  500  md5crypt $1$              1500  descrypt (DES crypt, 8 chars max!)
 3000  LM                        1800  sha512crypt $6$
 7400  sha256crypt $5$           3200  bcrypt $2*$
 1600  Apache $apr1$             7100  macOS 10.8+ PBKDF2-SHA512
 2100  DCC2 / MS Cache 2

# windows / active directory
 1000  NTLM                      5500  NetNTLMv1
 5600  NetNTLMv2                13100  Kerberos 5 TGS-REP etype 23 (kerberoast)
18200  Kerberos 5 AS-REP etype 23 (asreproast)
19600  Kerberos 5 TGS-REP etype 17 (AES128)   19700  etype 18 (AES256)

# web / app
  400  phpass (WordPress, Joomla, phpBB3)
16500  JWT (HS256/HS384/HS512)
  124  Django SHA-1             10000  Django PBKDF2-SHA256
12000  PBKDF2-HMAC-SHA1         10900  PBKDF2-HMAC-SHA256    12100  PBKDF2-HMAC-SHA512
  200  MySQL323                   300  MySQL4.1/MySQL5
   12  PostgreSQL               11100  PostgreSQL CRAM (MD5)
  131  MSSQL 2000                 132  MSSQL 2005            1731  MSSQL 2012/2014
  112  Oracle S (11+)            3100  Oracle H (7-10g)

# archives and containers
13600  WinZip                   17200 / 17210 / 17220 / 17225  PKZIP variants
12500  RAR3-hp                  13000  RAR5
11600  7-Zip                    13400  KeePass 1/2
 9400  MS Office 2007            9500  MS Office 2010         9600  MS Office 2013+
 9700-9820  MS Office <= 2003
10400 / 10410 / 10420 / 10500 / 10600 / 10700  PDF, by version
22921  RSA/DSA/EC/OpenSSH private keys
 6211 / 6212 / 6213  TrueCrypt          13711 / 13712 / 13713  VeraCrypt (RIPEMD160)
11300  Bitcoin / Litecoin wallet.dat     6800  LastPass
22000  WPA-PBKDF2-PMKID+EAPOL  (replaces the old 2500 / 16800)
```

Anything not on this list: `hashcat --example-hashes | grep -i <name>` and match the
example format against your hash. Never guess a mode number from memory for an
unusual format - a wrong mode silently cracks nothing.

## hashcat: attack modes and flags

```sh
# -a 0  straight (wordlist), optionally with rules
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 -a 0 hashes.txt rockyou.txt -r rules/best64.rule -r rules/toggles1.rule

# -a 1  combinator: every word of A joined to every word of B
hashcat -m 0 -a 1 hashes.txt words1.txt words2.txt
hashcat -m 0 -a 1 hashes.txt w1.txt w2.txt -j '$-' -k '$!'   # separators

# -a 3  mask (pure brute force over a charset pattern)
hashcat -m 0 -a 3 hashes.txt '?u?l?l?l?l?d?d?d'
hashcat -m 0 -a 3 hashes.txt 'CTF{?l?l?l?l?l?l}'            # known flag format
hashcat -m 0 -a 3 hashes.txt --increment --increment-min 4 --increment-max 8 '?a?a?a?a?a?a?a?a'

# -a 6  hybrid wordlist + mask   |   -a 7  hybrid mask + wordlist
hashcat -m 0 -a 6 hashes.txt rockyou.txt '?d?d?d?d'
hashcat -m 0 -a 7 hashes.txt '?d?d?d?d' rockyou.txt

# -a 9  association (one candidate per hash, e.g. the username as the password)
hashcat -m 0 -a 9 hashes.txt users.txt --username

# housekeeping
hashcat -m 0 hashes.txt rockyou.txt --show            # already-cracked, from the potfile
hashcat -m 0 hashes.txt --left                        # still uncracked
hashcat -m 0 ... --username                           # input is user:hash
hashcat -m 0 ... --outfile cracked.txt --outfile-format 2      # 2 = plain only
hashcat -m 0 ... --potfile-path ./this-ctf.pot        # keep CTFs separate
hashcat -m 0 ... --session ctf1                       # then: hashcat --restore --session ctf1
hashcat -m 0 ... -O -w 3                              # optimised kernel, high workload
hashcat -b -m 3200                                    # benchmark one mode
hashcat -m 0 -a 3 --stdout '?l?l?l'                   # print candidates, do not crack
hashcat -a 0 --stdout rockyou.txt -r best64.rule | head   # preview what a rule does
hashcat --keyspace -a 3 -m 0 '?a?a?a?a?a?a?a'         # how big is this really
```

`-O` caps the password length (usually 31) but is much faster. Drop it if long
candidates matter. `-w 4` maxes out the GPU and makes the desktop unusable.

## Mask syntax

```text
?l  abcdefghijklmnopqrstuvwxyz          ?u  ABCDEFGHIJKLMNOPQRSTUVWXYZ
?d  0123456789                          ?s  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ and space
?h  0123456789abcdef                    ?H  0123456789ABCDEF
?a  ?l?u?d?s  (95 printable)            ?b  0x00-0xff (256, for binary)

# custom charsets: -1 -2 -3 -4, then ?1 ?2 ?3 ?4 in the mask
hashcat -a 3 -1 '?l?d' -m 0 hashes.txt '?1?1?1?1?1?1?1?1'
hashcat -a 3 -1 'abc123' -2 '!@#' -m 0 hashes.txt '?1?1?1?1?2'

# a mask file (one mask per line, with its own -1.. definitions inline)
echo '?l?d,?1?1?1?1?1?1' > masks.hcmask
hashcat -a 3 -m 0 hashes.txt masks.hcmask

# keyspace maths: 95^8 = 6.6e15 (do not). 26^8 = 2.1e11 (minutes on a GPU).
# Every extra ?a multiplies by 95. Always constrain with what you know about the
# password policy or the flag format.
```

## Rules

```sh
# ships with hashcat, in /usr/share/hashcat/rules or $(hashcat --help | grep rules)
best64.rule            # 64 rules, the default first try, ~77x wordlist expansion
rockyou-30000.rule     # generated from rockyou, big and effective
d3ad0ne.rule           # ~34k rules, slow but thorough
dive.rule              # ~99k rules, the heaviest stock ruleset
generated2.rule        # ~65k, machine-generated
toggles1..5.rule       # case toggling only
leetspeak.rule         # a->4, e->3, ...
# community: OneRuleToRuleThemAll.rule (NotSoSecure), clem9669 rules, pantagrule

# stacking multiplies rulesets together
hashcat -m 0 hashes.txt rockyou.txt -r best64.rule -r toggles1.rule

# john's equivalents
john --wordlist=rockyou.txt --rules=Jumbo hashes.txt
john --wordlist=rockyou.txt --rules=Best64 hashes.txt
john --wordlist=rockyou.txt --rules=KoreLogic hashes.txt
```

```text
# rule syntax (one rule per line, operations applied left to right)
:           do nothing (keep the word as is)         l  lowercase       u  uppercase
c           capitalise                               C  invert capitalise
t           toggle every character's case            TN toggle char N
r           reverse                                  d  duplicate (word -> wordword)
pN          repeat the word N times                  f  reflect (word -> worddrow)
{ }         rotate left / right                      [ ]  delete first / last char
$X          append character X                       ^X prepend character X
DN          delete char at N                         xNM extract M chars from N
iNX         insert X at position N                   oNX overwrite position N with X
sXY         replace every X with Y                   @X purge all X
'N          truncate to N characters                 zN/ZN duplicate first/last char N times

# the ones you will actually write
$2 $0 $2 $4        -> append 2024
$! $!              -> append !!
c $1 $2 $3         -> Capitalise then append 123
so0 se3 sa@        -> leetspeak o->0, e->3, a->@
c $2 $0 $2 $5 $!   -> Capitalise + 2025 + !
u                  -> ALLCAPS
```

## John the Ripper

```sh
# the *2john family turns a file into a crackable hash
zip2john secret.zip > h        rar2john secret.rar > h       7z2john.pl a.7z > h
ssh2john id_rsa > h            keepass2john db.kdbx > h      office2john.py x.docx > h
pdf2john.pl doc.pdf > h        gpg2john secring.gpg > h      bitlocker2john -i disk > h
truecrypt2john volume > h      bitcoin2john.py wallet.dat > h
unshadow /etc/passwd /etc/shadow > h        # linux local accounts
samdump2 SYSTEM SAM > h                      # windows local accounts

# cracking
john h                                       # autodetect, single + wordlist + incremental
john --format=raw-md5 --wordlist=rockyou.txt h
john --format=NT --wordlist=rockyou.txt --rules=Jumbo h
john --incremental=Digits --format=raw-sha1 h
john --mask='CTF{?l?l?l?l?l?l}' --format=raw-md5 h
john --show h                                # print what has been cracked
john --show --format=NT h
john --status                                # progress of a running session
john --restore                               # resume the last session

# common --format= values
raw-md5 raw-sha1 raw-sha256 raw-sha512 md5crypt sha256crypt sha512crypt descrypt
bcrypt NT netntlmv2 netntlm krb5tgs krb5asrep mscash2 ZIP PKZIP RAR5 rar 7z PDF
office ssh keepass gpg Bitcoin axcrypt dmg racf phpass HMAC-SHA256
```

## Wordlists

```sh
# rockyou: 14.3M passwords, the default answer
gunzip -k /usr/share/wordlists/rockyou.txt.gz          # kali/parrot
ls /usr/share/seclists/Passwords/                       # SecLists, apt install seclists
#   Leaked-Databases/rockyou.txt, Common-Credentials/10-million-password-list-top-*.txt
#   Default-Credentials/, Software/, Honeypot-Captures/
# github.com/danielmiessler/SecLists is the upstream

# build a target-specific list from the challenge website
cewl -d 3 -m 5 -w site.txt http://target/
cewl -d 2 -m 4 --with-numbers -w site.txt http://target/
# then mangle it
hashcat -a 0 --stdout site.txt -r /usr/share/hashcat/rules/best64.rule > site-mangled.txt

# generated lists
crunch 6 8 abcdef0123456789 -o out.txt                  # length 6-8 over a charset
crunch 8 8 -t CTF{@@@@}                                  # pattern, @ = lowercase
mp64 '?u?l?l?l?d?d?d?d'                                  # maskprocessor, hashcat's own
# prefer hashcat -a 3 masks over writing a file: no disk, no I/O bottleneck

# dedupe and sort a merged list
cat a.txt b.txt | awk '!seen[$0]++' > merged.txt
```

Order of attack in a CTF: the flag format as a mask, then rockyou straight, then
rockyou + best64, then a CeWL list from the challenge text, then rockyou +
OneRuleToRuleThemAll, then masks. Stop as soon as the format tells you the keyspace is
small - `CTF{?l?l?l?l?l?l}` is `3.1e8`, seconds on a GPU.

## Identify by length, in code

```python
#!/usr/bin/env python3
"""Narrow an unknown hash down from its encoding, length and prefix."""

import re

BY_HEX_LEN = {
    16: ["MySQL323"],
    32: ["MD5", "MD4", "NTLM", "LM (half)", "RIPEMD-128", "MD2"],
    40: ["SHA-1", "RIPEMD-160", "MySQL4.1+", "Tiger-160"],
    48: ["Tiger-192", "HAVAL-192"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "GOST", "Keccak-256", "SM3"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

BY_PREFIX = [
    ("$1$", "md5crypt", 500), ("$apr1$", "Apache md5crypt", 1600),
    ("$2a$", "bcrypt", 3200), ("$2b$", "bcrypt", 3200), ("$2y$", "bcrypt", 3200),
    ("$5$", "sha256crypt", 7400), ("$6$", "sha512crypt", 1800),
    ("$y$", "yescrypt", None), ("$7$", "scrypt", 8900),
    ("$argon2", "argon2", None), ("{SSHA}", "LDAP SSHA-1", 111),
    ("{SHA}", "LDAP SHA-1", 101), ("$P$", "phpass", 400), ("$H$", "phpass", 400),
    ("$krb5tgs$", "Kerberoast TGS-REP", 13100),
    ("$krb5asrep$", "AS-REP roast", 18200),
    ("$pbkdf2-sha256$", "passlib PBKDF2-SHA256", 10900),
    ("$zip2$", "WinZip", 13600), ("$rar5$", "RAR5", 13000),
    ("$7z$", "7-Zip", 11600), ("$keepass$", "KeePass", 13400),
    ("$office$", "MS Office", 9400), ("$bitcoin$", "Bitcoin wallet", 11300),
]

HEX = re.compile(r"^[0-9a-fA-F]+$")
JWT = re.compile(r"^eyJ[\w-]*\.[\w-]+\.[\w-]+$")


def identify(h: str) -> list[str]:
    h = h.strip()
    out = []
    for prefix, name, mode in BY_PREFIX:
        if h.startswith(prefix):
            out.append(f"{name} (hashcat {mode if mode else '-- check --example-hashes'})")
    if JWT.match(h):
        out.append("JWT HS256/384/512 (hashcat 16500)")
    if h.startswith("*") and len(h) == 41 and HEX.match(h[1:]):
        out.append("MySQL4.1+ (hashcat 300)")
    if ":" in h and len(h.split(":")) >= 2:
        out.append("looks like user:hash or LM:NTLM -- split it, use --username")
    if HEX.match(h) and len(h) in BY_HEX_LEN:
        out.append(f"raw hex {len(h)}: " + ", ".join(BY_HEX_LEN[len(h)]))
    return out or ["unknown -- try: hashid -m, nth, hashcat --example-hashes"]


if __name__ == "__main__":
    tests = [
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "$2y$10$abcdefghijklmnopqrstuv",
        "$6$rounds=5000$salt$hash",
        "$krb5tgs$23$*user$DOM$svc*$aabb$ccdd",
        "*A4B6157319038724E3560894F7F932C8886EBFCF",
        "{SSHA}abcdefghijklmnopqrstuvwxyz0123",
        "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9"
        "80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
    ]
    for t in tests:
        print(f"{t[:40]:42s} -> {identify(t)}")
    assert "MD5" in identify(tests[0])[0]
    assert identify(tests[1])[0].startswith("bcrypt")
    assert identify(tests[2])[0].startswith("sha512crypt")
    assert "Kerberoast" in identify(tests[3])[0]
    assert "MySQL4.1+" in identify(tests[4])[0]
    assert "LDAP SSHA-1" in identify(tests[5])[0]
    assert "SHA-512" in identify(tests[6])[0]
    print("\n[+] identification checks passed")
```

## Practical recipes

```sh
# /etc/shadow line
unshadow passwd shadow > unsh
grep root unsh
hashcat -m 1800 -a 0 '$6$salt$hash...' rockyou.txt -r best64.rule
john --wordlist=rockyou.txt --format=sha512crypt unsh

# encrypted zip
zip2john secret.zip > z.hash && head -c 120 z.hash
john --wordlist=rockyou.txt z.hash && john --show z.hash
hashcat -m 17225 z.hash rockyou.txt        # pick the mode matching the $pkzip2$ variant

# ssh private key
ssh2john id_rsa > k.hash
hashcat -m 22921 k.hash rockyou.txt        # newer OpenSSH format
john --wordlist=rockyou.txt k.hash         # john autodetects both old and new

# JWT HS256 secret
echo 'eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.SIGNATURE' > jwt.txt
hashcat -m 16500 jwt.txt rockyou.txt -r best64.rule
# then re-sign with the recovered secret and change the claims

# NTLM dump from secretsdump / NTDS
cut -d: -f4 ntds.dump | sort -u > nt.hashes
hashcat -m 1000 nt.hashes rockyou.txt -r rules/OneRuleToRuleThemAll.rule
hashcat -m 1000 nt.hashes --show --username

# kerberoast ticket
hashcat -m 13100 tgs.hash rockyou.txt -r best64.rule

# keepass database
keepass2john db.kdbx > kp.hash
hashcat -m 13400 kp.hash rockyou.txt

# a flag with a known format, no wordlist needed
hashcat -m 0 -a 3 flag.hash 'flag{?l?l?l?l?l?l?l?l}'
```

## Gotchas

```text
- The potfile hides results: hashcat says "Exhausted" for hashes it already cracked.
  Use --show, or --potfile-disable, or a per-CTF --potfile-path.
- Salt included? md5($pass.$salt) hashes must be given as `hash:salt`, not just hash.
- --username strips `user:` from the input. Without it hashcat treats the username as
  part of the hash and cracks nothing.
- Windows line endings in a hash file break the parser. `dos2unix hashes.txt`.
- LM hashes are uppercase, 7-char halves, no salt. Crack with mode 3000 and a mask,
  then fix the case with NTLM (mode 1000) using the LM result as a wordlist rule set.
- descrypt ignores everything past the 8th character. Never brute past 8.
- bcrypt truncates at 72 bytes and is deliberately slow: wordlist + a small ruleset
  only, never masks over 8 characters.
- A "hash" that starts with 0e and is all digits is a magic hash, not something to
  crack -- see hash-collisions-magic.
- Rate: MD5 on a modern GPU is ~10^10 h/s, bcrypt cost 10 is ~10^4 h/s. That factor of
  a million decides your whole strategy.
```
