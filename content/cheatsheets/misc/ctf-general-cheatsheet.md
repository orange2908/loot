---
title: "CTF General Cheatsheet - Flags, Encodings, strings, nc, PoW"
category: misc
subcategory: general
type: cheatsheet
tags: [flag-format, encoding, base64, base32, base58, hex, rot13, xor, strings, netcat, socat, pwntools, proof-of-work, one-liners, cyberchef, cheatsheet]
summary: "Flag formats, the encoding ladder, strings variants, nc/socat interaction, PoW solvers and the one-liners you retype every event."
tools: [strings, xxd, base64, nc, socat, python3, pwntools, file, curl, jq]
related: [remote-interaction-and-pow, pow-solver, jail-escape-payloads, gtfobins-quickref, stego-cheatsheet, misc-classics]
---

## Flag formats seen in the wild

```text
flag{...}            CTF{...}            FLAG{...}
picoCTF{...}         HTB{...}            THM{...}
ctf{...}             <event>{...}        <event>_{...}
uiuctf{...}          actf{...}           DUCTF{...}
crypto{...}          (cryptohack)        0xL4ugh{...}
# md5-looking 32-hex, or a UUID, when the platform takes a raw hash
# some events use the flag as the answer to a question, with no wrapper at all
```

```bash
# grep for any of them, recursively, in binaries too
grep -raoiE '[a-z0-9_]{2,15}\{[^}]{4,120}\}' . | sort -u | head -50
grep -raoiE 'flag|ctf\{|key|secret|password' . | head -50
# in a binary, with offsets
strings -a -t x ./chal | grep -iE 'flag|ctf\{'
# after every transform you try
... | grep -aoE '[a-zA-Z0-9_]{2,15}\{[^}]+\}'
```

## strings variants

```bash
strings file                      # 7-bit ASCII, min length 4
strings -n 8 file                 # min length 8, cuts the noise
strings -a file                   # scan the WHOLE file, not just loadable sections
strings -t x file                 # print hex offsets (then dd/xxd there)
strings -t d file                 # decimal offsets
strings -e s file                 # single-7-bit (default)
strings -e S file                 # single-8-bit (latin1)
strings -e l file                 # 16-bit little endian (UTF-16LE: Windows, .NET)
strings -e b file                 # 16-bit big endian
strings -e L file                 # 32-bit little endian
strings -f *.bin                  # prefix each line with the filename
# the combination that finds Windows/UTF-16 flags people miss:
strings -e l -n 6 file | grep -i flag
# ripgrep over binaries
rg -a --text 'flag\{' .
```

## The encoding ladder (try in this order)

```bash
S='ZmxhZ3t0ZXN0fQ=='
echo "$S" | base64 -d                       # base64
echo "$S" | base64 -d 2>/dev/null | xxd | head
echo "$S" | base32 -d                       # base32 (A-Z2-7, '=' padding)
echo "$S" | basenc --base16 -d              # hex via coreutils
echo "$S" | xxd -r -p                       # hex
echo "$S" | tr 'A-Za-z' 'N-ZA-Mn-za-m'      # rot13
echo "$S" | rev                             # reversed
echo "$S" | tr '!-~' 'P-~!-O'               # rot47
python3 -c "import base64,sys;print(base64.b85decode(sys.argv[1]))" "$S"
python3 -c "import base64,sys;print(base64.b16decode(sys.argv[1]))" "$S"
python3 -c "import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))" "$S"
python3 -c "import html,sys;print(html.unescape(sys.argv[1]))" "$S"
python3 -c "import codecs,sys;print(codecs.decode(sys.argv[1],'rot13'))" "$S"
python3 -c "import binascii,sys;print(binascii.a2b_uu(sys.argv[1]))" "$S"
```

| Looks like | Try |
| --- | --- |
| `A-Za-z0-9+/` with `=` padding, length % 4 == 0 | base64 |
| `A-Z2-7` with `=` padding | base32 |
| `[0-9a-f]` only, even length | hex |
| `A-Za-z0-9` no `0OIl` | base58 (bitcoin) |
| `0-9` groups of 2-3 separated by spaces | decimal ASCII |
| `01` in groups of 8 | binary ASCII |
| `. -` and `/` or spaces | Morse |
| `Ook.`/`+-<>[].,` | esolang (see esolangs) |
| `%xx` | URL encoding |
| `&#NN;` / `&amp;` | HTML entities |
| `\uXXXX` / `\xXX` | unicode/hex escapes |
| `=XX` at line ends, lines <= 76 chars | quoted-printable |
| `begin 644 name` | uuencode |
| High-entropy, no structure | encrypted or compressed, not encoded |

```bash
# quick entropy check: is it encoded or encrypted?
python3 -c "
import sys,math,collections
d=open(sys.argv[1],'rb').read(); c=collections.Counter(d)
print('entropy', round(-sum(v/len(d)*math.log2(v/len(d)) for v in c.values()),3),
      'distinct', len(c))" file
# > 7.9 with 256 distinct bytes: compressed/encrypted. ~4-5: text. ~6: base64 of random.
```

## XOR

```bash
# single-byte xor brute force
python3 -c "
import sys
d=open(sys.argv[1],'rb').read()
for k in range(256):
    x=bytes(b^k for b in d)
    if sum(32<=c<127 or c in (9,10,13) for c in x) > len(x)*0.9:
        print(k, x[:200])" file

# xor with a known key
python3 -c "
import sys
d=open(sys.argv[1],'rb').read(); k=sys.argv[2].encode()
sys.stdout.buffer.write(bytes(b^k[i%len(k)] for i,b in enumerate(d)))" file KEY

# recover the key when you know a crib (e.g. the flag prefix)
python3 -c "
import sys
d=open(sys.argv[1],'rb').read(); crib=b'flag{'
print([bytes(a^b for a,b in zip(d[i:i+len(crib)],crib)) for i in range(4)])" file

# xortool finds the key length and the key
xortool -c 20 file
xortool -l 8 -c 00 file
```

## Hashes and identification

```bash
file chal                          # magic-byte type
file -i chal                       # mime type
xxd chal | head -4                 # the actual first bytes
binwalk chal                       # embedded files
hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hash-identifier
john --list=formats | tr ',' '\n' | grep -i <thing>
hashcat --example-hashes | grep -B2 -A2 '<format>'
# crack
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt && john --show hash.txt
hashcat -m 0 -a 0 hash.txt rockyou.txt          # 0 = MD5, 100 = SHA1, 1400 = SHA256
hashcat -m 1800 hash.txt rockyou.txt            # sha512crypt ($6$)
hashcat -m 500 hash.txt rockyou.txt             # md5crypt ($1$)
hashcat -m 3200 hash.txt rockyou.txt            # bcrypt ($2a$/$2y$)
```

## nc / socat interaction

```bash
nc host 1337
nc -v host 1337
nc -lvnp 4444                          # listener for a reverse shell
nc -u host 1337                        # udp
rlwrap nc host 1337                    # readline: arrow keys and history
ncat --ssl host 1337                   # TLS
openssl s_client -connect host:1337 -quiet
socat - TCP:host:1337
socat -v - TCP:host:1337 2>log         # log both directions
socat FILE:`tty`,raw,echo=0 TCP:host:1337   # full pty
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash,pty,stderr
# pipe a scripted answer
printf 'answer\n' | nc host 1337
{ echo first; sleep 1; echo second; cat; } | nc host 1337
# hexdump everything the service says
nc host 1337 | xxd
# timeout so a hung service does not block your script
timeout 10 nc host 1337 < input.txt
```

## pwntools skeleton

```python
from pwn import *

context.log_level = "debug"          # "info" once it works
context.arch = "amd64"
io = remote(args.HOST or "host", int(args.PORT or 1337))
# io = process("./chal")
# io = remote("host", 1337, ssl=True)
# io = gdb.debug("./chal", "b *main\nc")

io.recvuntil(b"> ")
io.sendline(b"payload")
data = io.recvline()
log.info(f"got {data!r}")
io.interactive()
```

```bash
# useful pwntools CLI tools that ship with it
pwn checksec ./chal
pwn cyclic 200
pwn cyclic -l 0x6161616c
pwn asm 'mov rax, 1' -c amd64
pwn disasm '4831c0' -c amd64
pwn shellcraft amd64.linux.sh -f raw | xxd
pwn hex 'abc'; pwn unhex 616263
pwn phd ./file                        # a nicer hexdump
```

## Proof of work

```bash
# the two common hosted solvers
curl -sSfL https://pwn.red/pow | sh -s <challenge-string>
python3 <(curl -sSL https://goo.gle/kctf-pow) solve <challenge-string>
hashcash -mb28 -r <resource>
```

```python
# leading-hex-zeros PoW, single file, no dependencies
import hashlib, itertools, string
prefix, n = b"abc123", 6
for i in itertools.count():
    s = str(i).encode()
    if hashlib.sha256(prefix + s).hexdigest().startswith("0" * n):
        print(s.decode()); break
```

```python
# leading-zero-BITS variant (20 bits is instant, 26 takes a few seconds)
import hashlib, itertools
prefix, bits = b"abc123", 24
target = 1 << (256 - bits)
for i in itertools.count():
    s = b"%d" % i
    if int(hashlib.sha256(prefix + s).hexdigest(), 16) < target:
        print(s.decode()); break
```

```python
# fixed-length / charset-constrained answer
import hashlib, itertools, string
prefix, n = b"abc", 4
for tup in itertools.product(string.ascii_lowercase, repeat=4):
    s = "".join(tup).encode()
    if hashlib.sha256(prefix + s).hexdigest().startswith("0" * n):
        print(s.decode()); break
```

## Archives and compression

```bash
file x; 7z l x; unzip -l x; tar tvf x
7z x x -oout/                        # handles zip/7z/rar/tar/gz/xz/iso/...
unzip -P password x.zip
zip2john x.zip > h && john h
tar xvf x.tar; tar xzvf x.tgz; tar xjvf x.tbz2; tar xJvf x.txz
gzip -d x.gz; bzip2 -d x.bz2; xz -d x.xz; zstd -d x.zst
# peel a deep chain automatically
while file flag | grep -qiE 'gzip|bzip2|xz|zip|tar|zstd'; do
  mv flag f.bin && 7z x -y f.bin -oout >/dev/null && mv out/* flag && rmdir out
done
```

## Files and quick transforms

```bash
xxd file | head -20
xxd -r -p <<< '666c6167'             # hex to bytes
xxd -i file                          # C array
od -A x -t x1z file | head
dd if=file bs=1 skip=100 count=50 2>/dev/null | xxd
truncate -s 100 file
split -b 1M file part_
cat part_* > rebuilt
cmp -l a b | head                    # byte-level differences
diff <(xxd a) <(xxd b) | head
sha256sum *; md5sum *
```

## HTTP and APIs

```bash
curl -s -D- https://target/path -o /dev/null           # headers only
curl -sk https://target -H 'User-Agent: x' -b 'k=v'
curl -s https://target/api | jq .
curl -s -X POST https://target/api -H 'Content-Type: application/json' -d '{"a":1}'
curl -s --path-as-is 'https://target/../../etc/passwd'
curl -s https://target --resolve target:443:1.2.3.4
wget -r -np -nH --cut-dirs=1 https://target/dir/
# decode a JWT without any tool
cut -d. -f2 <<< "$JWT" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

## Text wrangling one-liners

```bash
tr -d '\n' < f                        # strip newlines
tr -cd '[:print:]' < f                # keep printable only
tr 'A-Za-z' 'N-ZA-Mn-za-m' < f        # rot13
fold -w1 f | sort | uniq -c | sort -rn | head    # character frequency
awk '{print $2}' f | sort -u
sed -n '10,20p' f
grep -oP '(?<=prefix).*?(?=suffix)' f
paste -sd, f                          # join lines with commas
comm -12 <(sort a) <(sort b)          # common lines
column -t f
jq -r '.[] | .field' f.json
python3 -c "import sys;print(''.join(chr(int(x)) for x in sys.stdin.read().split()))" < decimals.txt
python3 -c "import sys;print(''.join(chr(int(x,2)) for x in sys.stdin.read().split()))" < binary.txt
```

## Python REPL snippets worth memorising

```python
# bytes <-> int <-> hex
int.from_bytes(b'flag', 'big'); (1718378855).to_bytes(4,'big'); b'flag'.hex()
bytes.fromhex('666c6167'); int('666c6167', 16)

# long_to_bytes without pycryptodome
n=1718378855; n.to_bytes((n.bit_length()+7)//8, 'big')

# base64 of bytes, url-safe variant
import base64; base64.b64encode(b'x'); base64.urlsafe_b64decode('eA==')

# xor two byte strings
bytes(a^b for a,b in zip(x,y))

# chunk a sequence
[d[i:i+16] for i in range(0,len(d),16)]

# printable ratio, to score a candidate decoding
sum(32<=c<127 for c in d)/len(d)

# every rotation of a string
[s[i:]+s[:i] for i in range(len(s))]

# CRC32 and common checksums
import zlib, binascii; zlib.crc32(b'x'); binascii.crc_hqx(b'x',0)
```

## When you are stuck

```text
1. Re-read the challenge text. The hint is almost always in the title or description.
2. `file`, `strings -n 8`, `xxd | head`, `xxd | tail`, `binwalk` - on EVERY artifact.
3. Check the flag format: are you even looking for the right shape?
4. Diff against a clean/original version of the same file if one exists.
5. Try the transform you have not tried: reverse, invert, transpose, rotate, decompress.
6. Search the exact error string or protocol banner - it is often an off-the-shelf component.
7. Look at file sizes and timestamps; an outlier is a signal.
8. Ask: what would the author have had to do to build this? Work backwards from that.
9. If a tool says "nothing found", check what that tool does NOT cover, and cover it.
10. Take the artifact to CyberChef and use "Magic" with a depth of 3 as a last resort.
```
