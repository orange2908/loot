---
title: "Cipher and Encoding Identification - A Decision Tree"
category: misc
subcategory: identification
type: reference
tags: [cipher-identification, cipher-identifier, encoding-identification, decision-tree, charset, index-of-coincidence, ioc, entropy, magic-bytes, length-divisibility, triage, dcode, cyberchef, classical-cipher, prng, hash-identification]
summary: "Start from the charset, then the length, then the IoC and entropy: a step-by-step decision tree from 'what does this blob look like' to 'it is probably X'."
tools: [cyberchef, dcode, python, file, hashid]
related: [classical-ciphers-cheatsheet, encoding-cheatsheet, prng-cheatsheet, classical-caesar-affine, classical-vigenere, classical-transposition]
---

## The three measurements you take first

```sh
# 1. charset - what characters actually appear
python3 -c "import sys;d=open(sys.argv[1]).read();print(len(d),''.join(sorted(set(d))))" blob.txt

# 2. length and its divisors - grids, block sizes, key lengths hide here
python3 -c "import sys;n=len(''.join(open(sys.argv[1]).read().split()));print(n,[d for d in range(2,n) if n%d==0])" blob.txt

# 3. index of coincidence (letters only) and entropy (bytes)
python3 -c "
import sys,collections,math
raw=open(sys.argv[1],'rb').read()
s=''.join(chr(b) for b in raw if 65<=b<=90 or 97<=b<=122).upper()
if len(s)>1:
    c=collections.Counter(s); n=len(s)
    print('IoC', round(sum(v*(v-1) for v in c.values())/(n*(n-1)),4))
c=collections.Counter(raw); n=len(raw)
print('entropy', round(-sum(v/n*math.log2(v/n) for v in c.values()),3), 'bits/byte')
print('printable', round(sum(32<=b<127 or b in (9,10,13) for b in raw)/n,3))" blob.txt
```

Interpretation:

| Measurement | Value | Meaning |
|---|---|---|
| entropy | < 4.5 | plain text or a simple substitution |
| entropy | 4.5 - 6.0 | encoded text (base64/hex) or a structured format |
| entropy | 6.0 - 7.5 | mixed / partly compressed |
| entropy | > 7.9 | compressed or encrypted - stop looking for a classical cipher |
| printable ratio | > 0.95 | still text: keep decoding |
| printable ratio | ~0.5 | binary; check magic bytes |
| IoC | ~0.066 | monoalphabetic **or** transposition (English) |
| IoC | 0.045 - 0.060 | digraphic (Playfair, Hill) or fractionating (Bifid) |
| IoC | 0.038 - 0.050 | polyalphabetic (Vigenere) or a rotor machine |
| IoC | ~0.0385 | effectively random: long key, OTP, or a modern cipher |

## Decision tree

```
START
|
+-- Is it binary (printable ratio < 0.9)?
|     |
|     +-- Do the first bytes match a magic number?
|     |     1f 8b -> gzip          78 9c/01/da -> zlib      50 4b 03 04 -> zip
|     |     42 5a 68 -> bzip2      fd 37 7a 58 5a -> xz     28 b5 2f fd -> zstd
|     |     89 50 4e 47 -> PNG     ff d8 ff -> JPEG         25 50 44 46 -> PDF
|     |     7f 45 4c 46 -> ELF     4d 5a -> PE              30 82 -> DER/ASN.1
|     |     -> decompress/parse and restart from the output
|     |
|     +-- entropy > 7.9 and no magic -> encrypted or compressed-without-header.
|     |     Look for block structure: is the length a multiple of 8 or 16?
|     |       16 -> AES/Camellia block cipher. Repeated 16-byte blocks -> ECB.
|     |        8 -> DES/3DES/Blowfish.
|     |     Not a multiple of a block size -> a stream cipher or raw XOR.
|     |
|     +-- entropy 4-7, length a multiple of 16 with repeating blocks -> ECB
|
+-- Is it text?
      |
      +-- Only 2 distinct symbols?
      |     length % 5 == 0  -> BACONIAN (try 24- and 26-letter, both polarities)
      |     length % 8 == 0  -> BINARY (8 bits per byte)
      |     length % 7 == 0  -> 7-bit ASCII
      |     otherwise        -> a bit stream; look for a framing pattern
      |
      +-- Only 3 distinct symbols?
      |     '.', '-', '/' or ' ' -> MORSE
      |     '.', '-', 'x'        -> FRACTIONATED MORSE intermediate
      |     0, 1, 2              -> ternary / Trifid coordinates
      |
      +-- Only '><+-.,[]'              -> BRAINFUCK
      +-- 'Ook.' 'Ook?' 'Ook!'         -> OOK!
      +-- Only spaces/tabs/newlines    -> WHITESPACE language
      +-- Word soup with '&%* and D'   -> MALBOLGE
      |
      +-- Only digits?
      |     pairs in 11..55                 -> POLYBIUS 5x5
      |     pairs in 11..66                 -> POLYBIUS 6x6
      |     space-separated 22..110         -> NIHILIST
      |     runs of 2-9                     -> MULTI-TAP / T9
      |     values 32..126                  -> DECIMAL ASCII
      |     values 0..255, length % 1       -> byte list
      |     long single number              -> a big integer: try long_to_bytes
      |
      +-- Only 0-9 a-f (even length)        -> HEX -> decode and restart
      +-- Only A-Z 2-7 (+ '=')              -> BASE32 -> decode and restart
      +-- A-Za-z0-9+/ (+ '='), len % 4 == 0 -> BASE64 -> decode and restart
      +-- A-Za-z0-9-_                       -> BASE64URL (re-pad first)
      +-- No 0 O I l, alnum                 -> BASE58
      +-- Printable incl. ! " # $ % ...     -> BASE85 / ASCII85 / BASE91
      +-- '%XX' escapes                     -> URL ENCODING
      +-- '=XX' escapes                     -> QUOTED-PRINTABLE
      +-- '&#65;' '&amp;'                   -> HTML ENTITIES
      +-- starts 'xn--'                     -> PUNYCODE
      +-- starts 'begin 644'                -> UUENCODE
      +-- 'eyJ' and two dots                -> JWT (base64url x3)
      |
      +-- Letters only (A-Z, maybe spaces/punctuation)?
            |
            +-- Compute the IoC.
            |
            +-- IoC ~0.066 (monoalphabetic or transposition)
            |     |
            |     +-- Are the letter COUNTS an anagram of plausible English
            |     |   (lots of E T A, almost no Z Q X)?
            |     |     yes and unreadable -> TRANSPOSITION
            |     |          length has small factors       -> COLUMNAR / SCYTALE
            |     |          no nice factors                -> RAIL FENCE / ROUTE
            |     |     no  -> SUBSTITUTION family
            |     |
            |     +-- Is the frequency histogram a ROTATION of English's?
            |     |     yes -> CAESAR / ROT-n
            |     +-- Is it an arithmetic progression (constant step between
            |     |   consecutive plaintext letters' images)?
            |     |     yes -> AFFINE (Atbash is a = 25, b = 25)
            |     +-- otherwise -> SIMPLE SUBSTITUTION
            |           word boundaries present -> aristocrat: quipqiup
            |           grouped in 5s           -> patristocrat: hill climb
            |           > 26 distinct symbols   -> HOMOPHONIC
            |
            +-- IoC 0.045 - 0.060
            |     |
            |     +-- Even length, no J, no doubled letter inside a pair
            |     |     -> PLAYFAIR
            |     +-- Even length, doubled letters inside pairs allowed
            |     |     -> FOUR-SQUARE / TWO-SQUARE
            |     +-- Length divisible by 2/3/4, J present
            |     |     -> HILL CIPHER
            |     +-- "period" mentioned, 25-letter alphabet
            |     |     -> BIFID
            |     +-- 27 symbols (26 + a filler)
            |           -> TRIFID
            |
            +-- IoC 0.038 - 0.050
                  |
                  +-- Only A D F G V X  -> ADFGVX    (A D F G X -> ADFGX)
                  +-- Per-period IoC spikes at some m <= 40
                  |     -> VIGENERE family, key length m
                  |        readable with c - k       -> VIGENERE
                  |        readable with k - c       -> BEAUFORT
                  |        readable with c + k       -> VARIANT BEAUFORT
                  |        key is digits only        -> GRONSFELD
                  +-- No spike at any m
                        |
                        +-- Does any letter ever encrypt to itself against a
                        |   plausible crib?
                        |     never -> ENIGMA / rotor machine
                        |     yes   -> continue
                        +-- IoC ~0.045, text length arbitrary
                        |     -> RUNNING KEY / BOOK CIPHER  (crib drag)
                        +-- IoC ~0.0385 and the key is as long as the message
                              -> ONE-TIME PAD (look for key reuse instead)
```

## Length-divisibility signals

| Length property | Suggests |
|---|---|
| multiple of 5 with 2 symbols | Baconian |
| multiple of 8 with 2 symbols | binary ASCII |
| even, 26-letter alphabet | Playfair, Four-square, Hill(2), Bifid |
| multiple of 3 or 4 | Hill with n = 3 or 4 |
| multiple of 16 (bytes) | AES block cipher |
| multiple of 8 (bytes) | DES/3DES/Blowfish |
| product of two smallish factors | transposition grid (rows x columns) |
| multiple of 4 (base64 chars) | base64 |
| multiple of 8 (base32 chars) | base32 |
| length 32 / 40 / 64 / 128 hex chars | MD5 / SHA-1 / SHA-256 / SHA-512 digest |
| length 16 / 24 / 32 bytes | an AES key |

## Charset fingerprints at a glance

```
ADFGVX                     -> ADFGVX cipher
ADFGX                      -> ADFGX cipher
AB / 01 / case / bold      -> Baconian
.-/                        -> Morse
.-x                        -> fractionated Morse intermediate
><+-.,[]                   -> Brainfuck
0-9 pairs 11-55            -> Polybius
0-9A-F                     -> hex
A-Z2-7=                    -> base32
A-Za-z0-9+/=               -> base64
A-Za-z0-9-_                -> base64url
1-9A-HJ-NP-Za-km-z         -> base58 (no 0, O, I, l)
0-9A-Za-z                  -> base62
!-u printable              -> ascii85
0-9A-Z $%*+-./:            -> base45
U+2800..U+28FF             -> Braille
U+E000.. private use       -> a custom glyph font; dump the font's cmap
```

## Entropy-based triage for binary blobs

```sh
# Per-256-byte-block entropy - spots an encrypted region inside a normal file
python3 -c "
import sys,collections,math
d=open(sys.argv[1],'rb').read()
for off in range(0,len(d),256):
    b=d[off:off+256]
    if len(b)<32: break
    c=collections.Counter(b); n=len(b)
    e=-sum(v/n*math.log2(v/n) for v in c.values())
    print(f'{off:08x} {e:.2f} ' + ('#'*int(e*4)))" blob.bin

# Repeated 16-byte blocks -> AES-ECB
python3 -c "
import sys,collections
d=open(sys.argv[1],'rb').read()
c=collections.Counter(d[i:i+16] for i in range(0,len(d)-15,16))
dup=[(v,k.hex()) for k,v in c.items() if v>1]
print('duplicate 16-byte blocks:',len(dup)); print(sorted(dup,reverse=True)[:5])" blob.bin

# Repeated 8-byte blocks -> DES-ECB
python3 -c "
import sys,collections
d=open(sys.argv[1],'rb').read()
c=collections.Counter(d[i:i+8] for i in range(0,len(d)-7,8))
print('duplicate 8-byte blocks:',sum(1 for v in c.values() if v>1))" blob.bin

# Hamming-distance key-length search for repeating-key XOR
python3 -c "
import sys
d=open(sys.argv[1],'rb').read()
def ham(a,b): return sum(bin(x^y).count('1') for x,y in zip(a,b))
res=[]
for k in range(2,41):
    blocks=[d[i*k:(i+1)*k] for i in range(4) if len(d)>=(i+1)*k]
    if len(blocks)<4: continue
    pairs=[(0,1),(1,2),(2,3),(0,2),(0,3),(1,3)]
    res.append((sum(ham(blocks[i],blocks[j]) for i,j in pairs)/(6*k),k))
print(sorted(res)[:5])" blob.bin
```

## When the plaintext is not English

IoC is language-dependent. If a text scores as "monoalphabetic" but no key produces
English, try another language's statistics before concluding the cipher is something
else.

| Language | IoC | Most common letters |
|---|---|---|
| English | 0.0667 | E T A O I N S |
| French | 0.0778 | E A S I T N R |
| German | 0.0762 | E N I S R A T |
| Spanish | 0.0770 | E A O S R N I |
| Italian | 0.0738 | E A I O N L R |
| Portuguese | 0.0745 | A E O S R I N |
| Russian (Cyrillic) | 0.0529 | O E A I N T S (transliterated) |
| random 26 letters | 0.0385 | - |

## Things that are NOT ciphers

```
- A 32/40/64/128-char hex string  -> a HASH. Identify with hashid / hash-identifier,
  then crack with hashcat or look it up. Do not try to "decrypt" it.
- 'eyJ...' with two dots          -> a JWT. Decode each base64url part.
- '$2y$', '$argon2id$', '$6$'     -> a password hash with its parameters inline.
- '-----BEGIN ... KEY-----'       -> PEM. Parse with openssl / cryptography.
- Random-looking base64 that decodes to high-entropy bytes -> ciphertext or a key.
- A UUID                          -> see prng-uuid-php-mt-rand for v1/v7 timestamps.
- A very long decimal integer     -> probably an RSA ciphertext or modulus.
```

## Fast automated identifiers

```
https://www.dcode.fr/cipher-identifier     # paste text, ranked guesses + direct links
https://gchq.github.io/CyberChef/          # the Magic operation brute-forces chains
https://www.boxentriq.com/code-breaking/cipher-identifier
hashid '<hexstring>'                       # pip install hashid
file blob.bin                              # magic-number identification
binwalk blob.bin                           # embedded files inside a blob
```

## A 60-second triage script

```sh
python3 - <<'EOF' blob.txt
import sys, collections, math, re
raw = open(sys.argv[1], 'rb').read()
txt = raw.decode('utf-8', 'replace')
body = ''.join(txt.split())
letters = ''.join(c for c in txt.upper() if 'A' <= c <= 'Z')

print("bytes        :", len(raw))
print("charset      :", ''.join(sorted(set(body)))[:120])
print("distinct     :", len(set(body)))
c = collections.Counter(raw); n = len(raw)
print("entropy      :", round(-sum(v/n*math.log2(v/n) for v in c.values()), 3))
print("printable    :", round(sum(32 <= b < 127 or b in (9,10,13) for b in raw)/n, 3))
if len(letters) > 1:
    cc = collections.Counter(letters); m = len(letters)
    print("IoC          :", round(sum(v*(v-1) for v in cc.values())/(m*(m-1)), 4))
    print("top letters  :", ''.join(k for k, _ in cc.most_common(8)))
print("len factors  :", [d for d in range(2, min(len(body), 64)) if len(body) % d == 0])

checks = [
    ("hex",       r'^[0-9a-fA-F\s]+$'),
    ("base64",    r'^[A-Za-z0-9+/=\s]+$'),
    ("base64url", r'^[A-Za-z0-9\-_=\s]+$'),
    ("base32",    r'^[A-Z2-7=\s]+$'),
    ("base58",    r'^[1-9A-HJ-NP-Za-km-z\s]+$'),
    ("binary",    r'^[01\s]+$'),
    ("decimal",   r'^[0-9\s]+$'),
    ("morse",     r'^[.\-/\s]+$'),
    ("adfgvx",    r'^[ADFGVX\s]+$'),
    ("bacon",     r'^[ABab\s]+$'),
    ("brainfuck", r'^[><+\-.,\[\]\s]+$'),
    ("letters",   r'^[A-Za-z\s.,!?\'"-]+$'),
]
print("matches      :", [name for name, pat in checks if re.fullmatch(pat, txt)])
EOF
```

## References

- dcode.fr cipher identifier - <https://www.dcode.fr/cipher-identifier>
- CyberChef (the `Magic` operation) - <https://gchq.github.io/CyberChef/>
- Boxentriq cipher identifier - <https://www.boxentriq.com/code-breaking/cipher-identifier>
- Practical Cryptography, "Cryptanalysis" index - <http://practicalcryptography.com/cryptanalysis/>
- Wikipedia, "Index of coincidence" - <https://en.wikipedia.org/wiki/Index_of_coincidence>
