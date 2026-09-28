---
title: "Encodings - Base16/32/58/62/64/85/91, uuencode, URL, HTML, Punycode and Friends"
category: crypto
subcategory: encoding
type: cheatsheet
tags: [encoding, base64, base32, base16, base58, base62, base85, ascii85, base91, base45, uuencode, quoted-printable, url-encoding, html-entities, punycode, brainfuck, endianness, magic-bytes, nested-encoding, cyberchef]
summary: "Recognise and convert every encoding a CTF throws at you, with python3 one-liners, shell equivalents and the matching CyberChef operations."
tools: [cyberchef, python, base64, xxd, dcode]
related: [cipher-identification, classical-ciphers-cheatsheet]
---

## Identification table

| Charset / shape | Encoding | Padding / tell |
|---|---|---|
| `0-9A-Fa-f`, even length | hex (base16) | `xxd -r -p` |
| `A-Za-z0-9+/` and `=` | base64 | length % 4 == 0 |
| `A-Za-z0-9-_` | base64url | `-` and `_` replace `+` and `/` |
| `A-Z2-7` and `=` | base32 | length % 8 == 0 |
| `0-9A-Va-v` | base32hex | RFC 4648 extended hex alphabet |
| `1-9A-HJ-NP-Za-km-z` (no `0OIl`) | base58 | Bitcoin/IPFS; no padding |
| `0-9A-Za-z` only, no padding | base62 | ambiguous - try base64 first |
| `!"#$%&'()*+,-./0-9:;<=>?@A-Z[\]^_` a-u` | ascii85 / base85 | often wrapped in `<~ ~>` |
| printable ASCII incl. `"` and `\` | base91 | densest of the printables |
| `0-9A-Z $%*+-./:` | base45 | EU COVID certificates, `HC1:` prefix |
| starts `begin 644 ` | uuencode | `uudecode` |
| `=XX` escapes, `=` at line ends | quoted-printable | email bodies |
| `%XX` escapes | URL / percent | `+` may mean space |
| `&amp;` `&#65;` `&#x41;` | HTML entities | |
| `xn--` prefix | punycode / IDNA | domain names |
| `+ADw-` style | UTF-7 | old XSS filter bypass |
| `><+-.,[]` only | Brainfuck | |
| `Ook. Ook? Ook!` | Ook! | Brainfuck dialect |
| `ubiquitous` word-soup with `'&%` | Malbolge | use an interpreter |
| `Hello World` / `Zzzz` whitespace only | Whitespace lang | tabs/spaces/newlines |
| Morse `. - /` | Morse | see the classical cheatsheet |

Magic prefixes visible **after** base64-decoding (check these every time):

| Bytes | Format | base64 prefix |
|---|---|---|
| `1f 8b` | gzip | `H4sI` |
| `78 9c` / `78 01` / `78 da` | zlib | `eJ` / `eA` / `ew` |
| `50 4b 03 04` | zip / docx / jar | `UEsDB` |
| `42 5a 68` | bzip2 | `Qlpo` |
| `fd 37 7a 58 5a` | xz | `/Td6WFo` |
| `28 b5 2f fd` | zstd | `KLUv` |
| `89 50 4e 47` | PNG | `iVBORw0KG` |
| `ff d8 ff` | JPEG | `/9j/` |
| `25 50 44 46` | PDF | `JVBERi0` |
| `7f 45 4c 46` | ELF | `f0VMR` |
| `4d 5a` | PE/EXE | `TVo` |
| `30 82` | DER (ASN.1 SEQUENCE) | `MI` |
| `{"` | JSON | `eyJ` |
| `<?xml` | XML | `PD94bWw` |
| `-----BEGIN` | PEM | `LS0tLS1CRUdJTiB` |

## Base64 / base64url

```sh
# Decode / encode, shell
echo -n 'SGVsbG8sIHdvcmxkIQ==' | base64 -d
echo -n 'Hello, world!' | base64
echo -n 'Hello, world!' | base64 -w0          # GNU: no line wrapping

# Python
python3 -c "import base64;print(base64.b64decode('SGVsbG8sIHdvcmxkIQ=='))"
python3 -c "import base64;print(base64.b64encode(b'Hello, world!').decode())"

# base64url (- and _ instead of + and /), tolerant of missing padding
python3 -c "import base64;s='SGVsbG8_d29ybGQ';print(base64.urlsafe_b64decode(s+'='*(-len(s)%4)))"

# Fix missing padding on ordinary base64
python3 -c "import base64;s='SGVsbG8sIHdvcmxkIQ';print(base64.b64decode(s+'='*(-len(s)%4)))"

# Decode ignoring whitespace and newlines
python3 -c "import base64,sys;print(base64.b64decode(''.join(sys.stdin.read().split())))" < blob.txt

# Custom / shuffled base64 alphabet (very common CTF twist)
python3 -c "
import base64
STD='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUS='ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/'
s='...'
print(base64.b64decode(s.translate(str.maketrans(CUS,STD))))"

# Is it base64 at all? (charset + length check)
python3 -c "import re,sys;s=sys.argv[1];print(bool(re.fullmatch(r'[A-Za-z0-9+/]*={0,2}',s)) and len(s)%4==0)" 'SGVsbG8='
```

CyberChef: `From Base64` (alphabet dropdown covers URL-safe, XML, Radix-64, Rot13'd
and more), `To Base64`, `Show Base64 offsets`.

## Base32 / base32hex / base16

```sh
# base32
python3 -c "import base64;print(base64.b32decode('JBSWY3DPFQQHO33SNRSCC==='))"   # -> b'Hello, world!'
python3 -c "import base64;print(base64.b32encode(b'Hello, world!').decode())"
echo -n 'JBSWY3DPFQQHO33SNRSCC===' | base32 -d

# base32 with missing padding
python3 -c "import base64;s='JBSWY3DPFQQHO33SNRSCC';print(base64.b32decode(s+'='*(-len(s)%8)))"

# base32hex (RFC 4648 extended hex alphabet)
python3 -c "import base64;print(base64.b32hexdecode('91IMOR3F5GG7ERRIDHI22==='))"   # -> b'Hello, world!'

# base16 (hex) both ways
python3 -c "import base64;print(base64.b16decode('48656C6C6F'))"
echo -n '48656c6c6f' | xxd -r -p
xxd -p <<< 'Hello'
```

CyberChef: `From Base32`, `From Hex`, `To Hex`.

## Base58 / base62 / base45

```sh
# base58 (Bitcoin alphabet) - pure stdlib
python3 -c "
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
s='StV1DL6CwTryKyV'
n=0
for c in s: n=n*58+A.index(c)
b=n.to_bytes((n.bit_length()+7)//8,'big')
print(b'\x00'*(len(s)-len(s.lstrip('1')))+b)"

# base58 encode
python3 -c "
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
d=b'hello world'; n=int.from_bytes(d,'big'); out=''
while n: n,r=divmod(n,58); out=A[r]+out
print('1'*(len(d)-len(d.lstrip(b'\x00')))+out)"

# with the base58 package
pip install base58 && python3 -c "import base58;print(base58.b58decode('StV1DL6CwTryKyV'))"

# base62 (0-9A-Za-z)
python3 -c "
A='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
s='AAYOU'; n=0
for c in s: n=n*62+A.index(c)
print(n, n.to_bytes((n.bit_length()+7)//8,'big'))"

# base45 (EU digital COVID certificates; payload is usually zlib+CBOR after 'HC1:')
pip install base45 && python3 -c "import base45;print(base45.b45decode('QED8WEX0'))"
```

CyberChef: `From Base58`, `From Base62`, `From Base45`.

## Base85 / ascii85 / base91

```sh
# Adobe ascii85 (the <~ ~> wrapper is optional)
python3 -c "import base64;print(base64.a85decode('87cURD_*#TDfTZ)+T'))"   # -> b'Hello, world!'
python3 -c "import base64;print(base64.a85encode(b'Hello, world!').decode())"

# RFC 1924 / ZeroMQ base85
python3 -c "import base64;print(base64.b85decode('NM&qnZ!92pZ*pv8Ap'))"   # -> b'Hello, world!'
python3 -c "import base64;print(base64.b85encode(b'Hello, world!').decode())"

# base91
pip install base91 && python3 -c "import base91;print(base91.decode('fPNKd'))"
```

CyberChef: `From Base85` (alphabet dropdown: Standard, Z85, IPv6), `From Base92`.

## uuencode / xxencode / yEnc

```sh
# uudecode a classic block
uudecode file.uu                    # honours the "begin 644 name" header

# Python
python3 -c "import binascii;print(binascii.a2b_uu(r',2&5L;&\@=V]R;&0A'))"   # -> b'Hello world!'
python3 -c "import binascii;print(binascii.b2a_uu(b'Hello world!').decode())"

# Whole-file uuencode/uudecode through the codecs module
python3 -c "import codecs;open('out.bin','wb').write(codecs.decode(open('in.uu','rb').read(),'uu'))"
```

CyberChef: `From UUEncoding` / `To UUEncoding`; `From Base64` with the UUEncoding
alphabet also works if the header line is stripped.

## Quoted-printable, URL, HTML, punycode, UTF-7

```sh
# Quoted-printable
python3 -c "import quopri;print(quopri.decodestring(b'Hello=2C=20world=21'))"
python3 -c "import quopri;print(quopri.encodestring(b'Hello, world!').decode())"

# URL / percent encoding ('+' means space in form data)
python3 -c "import urllib.parse as u;print(u.unquote_plus('Hello%2C+world%21'))"
python3 -c "import urllib.parse as u;print(u.quote('Hello, world!', safe=''))"

# Double-encoded URL (decode until it stops changing)
python3 -c "
import urllib.parse as u
s='%2568%2565%256c%256c%256f'
while True:
    d=u.unquote(s)
    if d==s: break
    s=d
print(s)"

# HTML entities both ways
python3 -c "import html;print(html.unescape('&lt;b&gt;caf&eacute;&#33;&#x21;&lt;/b&gt;'))"
python3 -c "import html;print(html.escape('<b>café!</b>'))"

# Punycode / IDNA
python3 -c "print('80ak6aa92e'.encode().decode('punycode'))"          # strip the xn-- prefix first
python3 -c "print('xn--80ak6aa92e.com'.encode('ascii').decode('idna'))"
python3 -c "print('münchen'.encode('idna'))"

# UTF-7 (classic filter bypass)
python3 -c "print(b'+ADw-script+AD4-'.decode('utf-7'))"
python3 -c "print('<script>'.encode('utf-7'))"
```

CyberChef: `From Quoted Printable`, `URL Decode`, `From HTML Entity`,
`From Punycode`, `Decode text` (charset dropdown includes UTF-7).

## Numbers: hex, decimal, octal, binary, endianness

```sh
# hex <-> bytes
python3 -c "print(bytes.fromhex('48656c6c6f'))"
python3 -c "print(b'Hello'.hex())"
python3 -c "print(bytes.fromhex('48 65 6c 6c 6f'.replace(' ','')))"

# binary string -> bytes (8 bits per char)
python3 -c "s='0100100001101001';print(int(s,2).to_bytes(len(s)//8,'big'))"
python3 -c "print(' '.join(format(b,'08b') for b in b'Hi'))"

# decimal byte list -> bytes
python3 -c "print(bytes([72,101,108,108,111]))"
python3 -c "print(' '.join(str(b) for b in b'Hello'))"

# octal escapes
python3 -c "print(bytes(int(x,8) for x in '110 145 154 154 157'.split()))"

# big int -> bytes and back (the classic RSA 'long_to_bytes')
python3 -c "n=0x48656c6c6f;print(n.to_bytes((n.bit_length()+7)//8,'big'))"
python3 -c "print(int.from_bytes(b'Hello','big'))"
python3 -c "from Crypto.Util.number import long_to_bytes,bytes_to_long;print(long_to_bytes(310939249775))"

# endianness flip (32-bit words)
python3 -c "import struct;d=bytes.fromhex('deadbeef');print(struct.pack('<I',*struct.unpack('>I',d)).hex())"
python3 -c "d=bytes.fromhex('0123456789abcdef');print(b''.join(d[i:i+4][::-1] for i in range(0,len(d),4)).hex())"

# hexdump views
xxd file.bin | head
xxd -p file.bin | tr -d '\n'                 # flat hex
od -A x -t x1z file.bin | head
```

CyberChef: `From Hex`, `From Binary`, `From Decimal`, `From Octal`,
`Swap endianness`, `To Hexdump`.

## Unicode escapes and mojibake

```sh
# \uXXXX and \xXX escapes
python3 -c "print('\\u0048\\u0065llo'.encode().decode('unicode_escape'))"
python3 -c "print('Héllo'.encode('unicode_escape').decode())"

# \N{NAME} and codepoint listing
python3 -c "import unicodedata;s='café';print([(c,hex(ord(c)),unicodedata.name(c,'?')) for c in s])"

# Percent-encoded UTF-8 -> text
python3 -c "import urllib.parse as u;print(u.unquote('caf%C3%A9'))"

# Fix classic mojibake (UTF-8 read as latin-1)
python3 -c "print('cafÃ©'.encode('latin-1').decode('utf-8'))"

# Strip zero-width / bidi steganography characters and show what was there
python3 -c "
s=open('in.txt',encoding='utf-8').read()
hidden=[hex(ord(c)) for c in s if ord(c) in (0x200b,0x200c,0x200d,0x2060,0xfeff) or 0x202a<=ord(c)<=0x202e]
print(len(hidden),hidden[:40])"

# Homoglyph check: any non-ASCII letters pretending to be ASCII?
python3 -c "
import unicodedata
s=open('in.txt',encoding='utf-8').read()
print([(c,unicodedata.name(c,'?')) for c in set(s) if ord(c)>127])"
```

CyberChef: `Unescape Unicode Characters`, `Escape Unicode Characters`,
`Remove Diacritics`, `Show Base64 offsets`.

## Compression hiding inside an encoding

```sh
# gzip / zlib / bz2 / lzma after a base64 layer
python3 -c "import base64,gzip;print(gzip.decompress(base64.b64decode(open('b64.txt').read())))"
python3 -c "import base64,zlib;print(zlib.decompress(base64.b64decode(open('b64.txt').read())))"
python3 -c "import base64,zlib;print(zlib.decompress(base64.b64decode(open('b64.txt').read()),-15))"   # raw deflate
python3 -c "import base64,bz2;print(bz2.decompress(base64.b64decode(open('b64.txt').read())))"
python3 -c "import base64,lzma;print(lzma.decompress(base64.b64decode(open('b64.txt').read())))"

# Identify the decoded bytes before guessing
python3 -c "import base64;d=base64.b64decode(open('b64.txt').read());print(d[:8].hex(),d[:16])"
file <(python3 -c "import base64,sys;sys.stdout.buffer.write(base64.b64decode(open('b64.txt').read()))")
```

CyberChef: `Gunzip`, `Zlib Inflate`, `Raw Inflate`, `Bzip2 Decompress`,
`LZMA Decompress`, `Detect File Type`, `Magic`.

## Esoteric languages

```sh
# Brainfuck: charset is exactly ><+-.,[]
python3 -c "import re;s=open('in.txt').read();print(set(s) <= set('><+-.,[] \n'))"
pip install brainfuck-interpreter   # or use an online interpreter

# Minimal Brainfuck interpreter (output only)
python3 -c "
import sys
code=''.join(c for c in open('in.bf').read() if c in '><+-.,[]')
tape=[0]*30000; p=i=0; out=[]
jumps={}; stack=[]
for k,c in enumerate(code):
    if c=='[': stack.append(k)
    elif c==']': j=stack.pop(); jumps[j]=k; jumps[k]=j
while i<len(code):
    c=code[i]
    if c=='>': p+=1
    elif c=='<': p-=1
    elif c=='+': tape[p]=(tape[p]+1)%256
    elif c=='-': tape[p]=(tape[p]-1)%256
    elif c=='.': out.append(chr(tape[p]))
    elif c=='[' and not tape[p]: i=jumps[i]
    elif c==']' and tape[p]: i=jumps[i]
    i+=1
print(''.join(out))"

# Ook! -> Brainfuck
python3 -c "
m={'Ook. Ook?':'>','Ook? Ook.':'<','Ook. Ook.':'+','Ook! Ook!':'-','Ook! Ook.':'.','Ook. Ook!':',','Ook! Ook?':'[','Ook? Ook!':']'}
t=open('in.ook').read().split()
print(''.join(m[t[i]+' '+t[i+1]] for i in range(0,len(t)-1,2)))"
```

CyberChef: no Brainfuck; use <https://www.dcode.fr/brainfuck-language> or
<https://copy.sh/brainfuck/>. Malbolge: <https://www.dcode.fr/malbolge-language>.

## Nested-encoding detection

```sh
# Auto-peel: keep decoding while the result still looks like an encoding
python3 -c "
import base64,re,zlib,gzip
s=open('in.txt').read().strip()
for step in range(12):
    b=None
    try:
        if re.fullmatch(r'[0-9a-fA-F\s]+',s) and len(s.split())<=1 and len(s)%2==0:
            b=bytes.fromhex(s)
        elif re.fullmatch(r'[A-Za-z0-9+/=\s]+',s):
            t=''.join(s.split()); b=base64.b64decode(t+'='*(-len(t)%4))
        elif re.fullmatch(r'[A-Z2-7=\s]+',s):
            t=''.join(s.split()); b=base64.b32decode(t+'='*(-len(t)%8))
    except Exception:
        b=None
    if b is None: break
    if b[:2]==b'\x1f\x8b': b=gzip.decompress(b)
    elif b[:1]==b'\x78': b=zlib.decompress(b)
    print(step, b[:60])
    try: s=b.decode()
    except UnicodeDecodeError: break"

# Entropy: 7.9+ bits/byte means compressed or encrypted, not encoded text
python3 -c "
import math,collections,sys
d=open(sys.argv[1],'rb').read(); c=collections.Counter(d); n=len(d)
print(round(-sum(v/n*math.log2(v/n) for v in c.values()),3))" file.bin

# Printable ratio: >0.95 means it is still text, keep decoding
python3 -c "
import sys
d=open(sys.argv[1],'rb').read()
print(sum(32<=b<127 or b in (9,10,13) for b in d)/len(d))" file.bin
```

CyberChef: the **`Magic`** operation does exactly this - it brute-forces decoding
chains and ranks them. Set "Depth" to 3-4 and tick "Intensive mode".

## CyberChef equivalents at a glance

```
hex            -> From Hex / To Hex
base64         -> From Base64 / To Base64        (alphabet dropdown for variants)
base32         -> From Base32
base58         -> From Base58
base62         -> From Base62
base85         -> From Base85
base45         -> From Base45
uuencode       -> From UUEncoding
quoted-printable -> From Quoted Printable
url            -> URL Decode / URL Encode
html entities  -> From HTML Entity / To HTML Entity
punycode       -> From Punycode / To Punycode
charset change -> Encode text / Decode text
gzip/zlib      -> Gunzip / Zlib Inflate / Raw Inflate
unknown        -> Magic (with Intensive mode), Detect File Type, Entropy
binary/decimal -> From Binary / From Decimal / From Octal
endianness     -> Swap endianness
```

## Gotchas

```
- base64 of ASCII text almost always starts with a letter in [A-Za-z]; base64 of a
  binary header usually starts with the magic prefixes in the table above.
- '=' inside (not just at the end of) a base64 string means it is several
  concatenated base64 blobs, or it is quoted-printable.
- base32 and base64 overlap on A-Z2-7 - if base64 gives noise, try base32.
- A leading 'eyJ' is JSON; 'eyJhbGciOi' is a JWT header - split on '.' and decode
  each part as base64url.
- Missing padding is normal in JWTs, URLs and many APIs. Always re-pad.
- '+' in a URL query string is a space; '+' in a raw base64 blob is data. Decoding a
  base64 value taken from a URL usually needs unquote() FIRST.
- Uppercase-only hex with no spaces can also be base32 - check the length modulus.
- If the decode is 'almost' right but every byte is off, suspect a custom alphabet
  or a rot-n applied to the alphabet.
- Text that decodes to more text is normal; CTFs nest 3-5 layers routinely.
```

## References

- CyberChef - <https://gchq.github.io/CyberChef/>
- RFC 4648 (base16/32/64) - <https://www.rfc-editor.org/rfc/rfc4648>
- RFC 1924 (base85) - <https://www.rfc-editor.org/rfc/rfc1924>
- dcode.fr tools list - <https://www.dcode.fr/tools-list>
- Python `base64` module - <https://docs.python.org/3/library/base64.html>
- Python `codecs` module - <https://docs.python.org/3/library/codecs.html>
