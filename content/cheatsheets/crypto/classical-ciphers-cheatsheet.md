---
title: "Classical Ciphers - Identification and One-Liner Cheatsheet"
category: crypto
subcategory: classical
type: cheatsheet
tags: [classical-cipher, caesar, rot13, rot47, atbash, affine, vigenere, beaufort, playfair, bifid, trifid, hill-cipher, adfgvx, polybius, nihilist, bacon, morse, rail-fence, columnar-transposition, index-of-coincidence]
summary: "Identification table (charset, length pattern, IoC), plus dcode/CyberChef/quipqiup pointers and copy-pasteable one-liners for every classical cipher."
tools: [cyberchef, dcode, quipqiup, cryptool, python]
related: [cipher-identification, classical-caesar-affine, classical-vigenere, classical-substitution-hillclimb, classical-transposition, encoding-cheatsheet]
---

## Identification table

| Signal | Likely cipher | Next step |
|---|---|---|
| `A-Z` only, IoC ~0.066, histogram is a *rotation* of English | Caesar / ROT-n | brute 26 |
| `A-Z` only, IoC ~0.066, histogram is a *permutation* | Substitution / Affine / Atbash | quipqiup, hill-climb |
| `A-Z` only, IoC ~0.066, letters are an anagram of English | Transposition | rail fence, columnar |
| `A-Z`, IoC 0.038-0.050, no dominant letter | Vigenere / Beaufort / Gronsfeld | IoC per period, Kasiski |
| `A-Z`, IoC ~0.045, no period spikes at all | Running key / autokey / OTP | crib drag |
| `A-Z`, IoC ~0.040, groups of 5, no letter maps to itself | Enigma | IoC brute force on rotors |
| Even length, no `J`, no doubled letter inside a pair | Playfair | wordlist keys |
| Even length, no `J`, IoC ~0.045, "period" mentioned | Bifid | period scan |
| 27 symbols (26 + `.`/`+`) | Trifid | period scan |
| Length divisible by 2/3/4, `J` present, IoC low | Hill | known-plaintext matrix |
| Only `A D F G V X` | ADFGVX | transposition then square |
| Only `A D F G X` | ADFGX | same, 5x5 square |
| Digit pairs 11-55 | Polybius | direct decode |
| Numbers 22-110 | Nihilist | period + additive |
| Exactly 2 distinct symbols, length % 5 == 0 | Baconian | both variants, both polarities |
| `.` `-` `/` and spaces | Morse | direct or word-DP |
| `A-Z` but flat IoC and "morse" hinted | Fractionated Morse | trigram table |
| Runs of 1-5 identical marks in pairs | Tap code | 5x5, no K |
| Braille dots / `U+28xx` | Braille | direct |
| Unknown glyphs, ~26 distinct | Pigpen / dancing men / SGA | dcode symbol gallery |
| Digits 2-9 in runs | Multi-tap / T9 | direct |

Reference IoC values: English 0.0667, French 0.0778, German 0.0762, Spanish 0.0770,
Italian 0.0738, random over 26 letters 0.0385.

## Quick triage one-liners

```sh
# Character set of a ciphertext file - the single most informative measurement
python3 -c "import sys,collections;d=open(sys.argv[1]).read();print(sorted(set(d)));print(len(d))" ct.txt

# Index of coincidence
python3 -c "import sys,collections;s=''.join(c for c in open(sys.argv[1]).read().upper() if c.isalpha());n=len(s);c=collections.Counter(s);print(sum(v*(v-1) for v in c.values())/(n*(n-1)))" ct.txt

# Letter frequency histogram, most common first
python3 -c "import sys,collections;s=''.join(c for c in open(sys.argv[1]).read().upper() if c.isalpha());print(collections.Counter(s).most_common())" ct.txt

# Length factors - candidate grid widths / key lengths for transposition
python3 -c "import sys;n=len(''.join(c for c in open(sys.argv[1]).read() if c.isalpha()));print(n,[d for d in range(2,n) if n%d==0])" ct.txt

# Repeated 3-grams and their distances (Kasiski)
python3 -c "import sys,collections;s=''.join(c for c in open(sys.argv[1]).read().upper() if c.isalpha());p=collections.defaultdict(list);[p[s[i:i+3]].append(i) for i in range(len(s)-2)];print([(g,[b-a for a,b in zip(v,v[1:])]) for g,v in p.items() if len(v)>1][:20])" ct.txt

# Per-period average IoC for key lengths 1..30 (spike = Vigenere key length)
python3 -c "import sys,collections;s=''.join(c for c in open(sys.argv[1]).read().upper() if c.isalpha());f=lambda t:(lambda c,n:sum(v*(v-1) for v in c.values())/(n*(n-1)) if n>1 else 0)(collections.Counter(t),len(t));print([(m,round(sum(f(s[i::m]) for i in range(m))/m,4)) for m in range(1,31)])" ct.txt
```

## Caesar / ROT-n / ROT47 / Atbash

```sh
# All 26 Caesar shifts of a string
python3 -c "s='WKH IODJ LV KHUH';[print(k,''.join(chr((ord(c)-65-k)%26+65) if c.isalpha() else c for c in s)) for k in range(26)]"

# ROT13 in pure shell (self-inverse)
echo 'synt{ebg13_vf_abg_pelcgb}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ROT13 with Python's stdlib codec
python3 -c "import codecs;print(codecs.encode('synt{uryyb}','rot13'))"

# ROT47 (self-inverse, covers printable ASCII 33..126)
python3 -c "s='w6==@[ H@C=5P';print(''.join(chr(33+(ord(c)-33+47)%94) if 33<=ord(c)<=126 else c for c in s))"   # -> Hello, world!

# ROT5 on digits only, and ROT18 = ROT13 + ROT5
python3 -c "s='abc123';print(''.join(chr((ord(c)-48+5)%10+48) if c.isdigit() else c for c in s))"

# Atbash (A<->Z), self-inverse
python3 -c "s='ZGYZHS';print(''.join(chr(155-ord(c)) if c.isupper() else c for c in s))"

# ROT-n over a custom alphabet (e.g. rotate a base64 string's alphabet)
python3 -c "A='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';s='SGVsbG8=';n=13;print(''.join(A[(A.index(c)+n)%len(A)] if c in A else c for c in s))"

# Grep every shift for a flag marker
python3 -c "s=open('ct.txt').read();[print(k,t) for k in range(26) for t in [''.join(chr((ord(c)-65-k)%26+65) if c.isupper() else chr((ord(c)-97-k)%26+97) if c.islower() else c for c in s)] if 'flag{' in t.lower()]"
```

- CyberChef: `ROT13` (Amount slider = n), `ROT13 Brute Force`, `ROT47`,
  `Atbash Cipher`, `Affine Cipher Decode`.
- dcode: <https://www.dcode.fr/caesar-cipher>, <https://www.dcode.fr/rot-47-cipher>,
  <https://www.dcode.fr/atbash-cipher>

## Affine

```sh
# Encrypt c = a*p + b mod 26  (a must be coprime with 26)
python3 -c "a,b,s=5,8,'ATTACKATDAWN';print(''.join(chr((a*(ord(c)-65)+b)%26+65) for c in s))"

# Brute force all 312 affine keys and print those containing a marker
python3 -c "from math import gcd;s=open('ct.txt').read().strip().upper();[print(a,b,t) for a in range(1,26) if gcd(a,26)==1 for b in range(26) for t in [''.join(chr((pow(a,-1,26)*(ord(c)-65-b))%26+65) if c.isalpha() else c for c in s)] if 'FLAG' in t]"

# Affine over bytes (mod 256): 128 valid multipliers, 32768 keys
python3 -c "d=open('ct.bin','rb').read();[print(a,b,t[:40]) for a in range(1,256,2) for b in range(256) for t in [bytes((pow(a,-1,256)*(x-b))%256 for x in d)] if b'flag{' in t]"
```

- dcode: <https://www.dcode.fr/affine-cipher>

## Monoalphabetic substitution

```sh
# Apply a known key (ciphertext letter -> plaintext letter)
python3 -c "K='QWERTYUIOPASDFGHJKLZXCVBNM';s='HELLO';import string;print(s.translate(str.maketrans(string.ascii_uppercase,K)))"

# Word-pattern signature - match ciphertext words against a dictionary
python3 -c "p=lambda w:(lambda d:tuple(d.setdefault(c,len(d)) for c in w))({});print(p('HELLO'),p('XYZZO'))"

# Candidate dictionary words for a ciphertext word by pattern
python3 -c "p=lambda w:(lambda d:tuple(d.setdefault(c,len(d)) for c in w.upper()))({});w='XYZZO';print([x.strip() for x in open('/usr/share/dict/words') if len(x.strip())==len(w) and p(x.strip())==p(w)][:20])"

# Frequency-order seed key (most common ct letter -> E, ...)
python3 -c "import collections,string;s=''.join(c for c in open('ct.txt').read().upper() if c.isalpha());o=[c for c,_ in collections.Counter(s).most_common()];o+=[c for c in string.ascii_uppercase if c not in o];print(dict(zip(o,'ETAOINSRHDLUCMFYWGPBVKXQJZ')))"
```

- **quipqiup** <https://quipqiup.com/> - paste the ciphertext, it solves aristocrats
  instantly; supports clues like `XY=TH` and a "solve as pattern" mode.
- dcode: <https://www.dcode.fr/monoalphabetic-substitution>
- CyberChef: `Substitute` (apply a key you already have).

## Vigenere family

```sh
# Encrypt / decrypt with a known key
python3 -c "k='CRYPTO';s='ATTACKATDAWN';print(''.join(chr((ord(c)-65+ord(k[i%len(k)])-65)%26+65) for i,c in enumerate(s)))"
python3 -c "k='CRYPTO';s='CKRPVYCKBPLB';print(''.join(chr((ord(c)-65-(ord(k[i%len(k)])-65))%26+65) for i,c in enumerate(s)))"

# Recover the key for a known length m by chi-squared on each column
python3 -c "
import sys,collections
F=[8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074]
s=''.join(c for c in open('ct.txt').read().upper() if c.isalpha()); m=int(sys.argv[1])
key=''
for i in range(m):
    col=s[i::m]; best=(1e18,0)
    for k in range(26):
        cnt=[0]*26
        for ch in col: cnt[(ord(ch)-65-k)%26]+=1
        chi=sum((cnt[j]-len(col)*F[j]/100)**2/(len(col)*F[j]/100) for j in range(26))
        best=min(best,(chi,k))
    key+=chr(65+best[1])
print(key)" 6

# Beaufort (self-inverse): p = k - c
python3 -c "k='KEY';s='ATTACK';print(''.join(chr(((ord(k[i%len(k)])-65)-(ord(c)-65))%26+65) for i,c in enumerate(s)))"

# Gronsfeld: numeric key
python3 -c "k='31415';s='ATTACKATDAWN';print(''.join(chr((ord(c)-65+int(k[i%len(k)]))%26+65) for i,c in enumerate(s)))"

# Autokey with a short primer: brute force primers of length 1-3
python3 -c "
import itertools,string
s=''.join(c for c in open('ct.txt').read().upper() if c.isalpha())
for L in (1,2,3):
  for pr in itertools.product(string.ascii_uppercase,repeat=L):
    k=list(pr); out=[]
    for i,c in enumerate(s):
      p=(ord(c)-65-(ord(k[i])-65))%26; out.append(chr(65+p)); k.append(chr(65+p))
    t=''.join(out)
    if 'THE' in t and 'AND' in t: print(''.join(pr), t[:60])"
```

- dcode: <https://www.dcode.fr/vigenere-cipher>, <https://www.dcode.fr/beaufort-cipher>,
  <https://www.dcode.fr/autoclave-cipher>
- CyberChef: `Vigenere Decode`, `Index of Coincidence`, `Frequency Distribution`.
- CrypTool 2 has a Vigenere analyser with Kasiski + Friedman built in.

## Transposition

```sh
# Rail fence decode for every rail count 2..15
python3 -c "
s=''.join(c for c in open('ct.txt').read() if not c.isspace())
for r in range(2,16):
    cyc=2*r-2
    pat=[min(i%cyc,cyc-i%cyc) for i in range(len(s))]
    pos={}; run=0
    for row in range(r):
        pos[row]=run; run+=pat.count(row)
    out=[]
    for row in pat:
        out.append(s[pos[row]]); pos[row]+=1
    print(r,''.join(out))"

# Scytale / simple columnar: read every k-th letter for each divisor of the length
python3 -c "s=open('ct.txt').read().strip();n=len(s);[print(k,''.join(s[i::n//k] for i in range(n//k))) for k in range(2,n) if n%k==0]"

# Columnar transposition with a known keyword
python3 -c "
kw='ZEBRAS'; s=open('ct.txt').read().strip()
order=[i for i,_ in sorted(enumerate(kw),key=lambda t:(t[1],t[0]))]
k=len(order); L=len(s)//k
cols={}; pos=0
for c in order: cols[c]=s[pos:pos+L]; pos+=L
print(''.join(cols[c][r] for r in range(L) for c in range(k)))"

# Brute force every k! column order for k = 2..7 and print anything with THE + AND
python3 -c "
from itertools import permutations
s=''.join(c for c in open('ct.txt').read().upper() if c.isalpha())
for k in range(2,8):
  if len(s)%k: continue
  L=len(s)//k
  for o in permutations(range(k)):
    cols={}; pos=0
    for c in o: cols[c]=s[pos:pos+L]; pos+=L
    t=''.join(cols[c][r] for r in range(L) for c in range(k))
    if 'THE' in t and 'AND' in t: print(k,o,t[:70])"

# Reverse the whole string (the laziest transposition)
python3 -c "print(open('ct.txt').read().strip()[::-1])"
```

- CyberChef: `Rail Fence Cipher Decode`, `Columnar Transposition Cipher Decode`,
  `Reverse`, `Rotate`.
- dcode: <https://www.dcode.fr/transposition-cipher>,
  <https://www.dcode.fr/rail-fence-cipher>, <https://www.dcode.fr/scytale-cipher>

## Playfair / Bifid / Trifid / Four-square

```sh
# Build a 5x5 keyed square (I=J) from a keyword
python3 -c "kw='PLAYFAIREXAMPLE';A='ABCDEFGHIKLMNOPQRSTUVWXYZ';seen=[];[seen.append(c) for c in kw.upper().replace('J','I')+A if c in A and c not in seen];print(''.join(seen))"

# Playfair decrypt with a known key
python3 -c "
kw='PLAYFAIREXAMPLE'; ct='BMODZBXDNABEKUDMUIXMMOUVIF'
A='ABCDEFGHIKLMNOPQRSTUVWXYZ'; sq=[]
[sq.append(c) for c in kw.upper().replace('J','I')+A if c in A and c not in sq]
sq=''.join(sq); out=[]
for i in range(0,len(ct)-1,2):
    a,b=ct[i],ct[i+1]; r1,c1=divmod(sq.index(a),5); r2,c2=divmod(sq.index(b),5)
    if r1==r2: out.append(sq[r1*5+(c1-1)%5]+sq[r2*5+(c2-1)%5])
    elif c1==c2: out.append(sq[((r1-1)%5)*5+c1]+sq[((r2-1)%5)*5+c2])
    else: out.append(sq[r1*5+c2]+sq[r2*5+c1])
print(''.join(out))"

# Playfair validity check: even length, no J, no doubled letter inside a pair
python3 -c "s=open('ct.txt').read().strip().upper();print(len(s)%2==0, 'J' not in s, all(s[i]!=s[i+1] for i in range(0,len(s)-1,2)))"
```

- dcode: <https://www.dcode.fr/playfair-cipher>, <https://www.dcode.fr/bifid-cipher>,
  <https://www.dcode.fr/trifid-cipher>, <https://www.dcode.fr/four-square-cipher>
- CyberChef: `Bifid Cipher Decode`.
- CrypTool 2 has proper simulated-annealing analysers for Playfair and Bifid.

## Hill cipher

```sh
# Inverse of a key matrix mod 26 with sympy (exact - never use numpy.linalg.inv)
python3 -c "from sympy import Matrix;K=Matrix([[6,24,1],[13,16,10],[20,17,15]]);print(K.inv_mod(26))"

# Decrypt with a known key
python3 -c "
from sympy import Matrix
K=Matrix([[6,24,1],[13,16,10],[20,17,15]]).inv_mod(26); ct='POHZYY'
n=K.shape[0]; out=''
for i in range(0,len(ct),n):
    v=Matrix([ord(c)-65 for c in ct[i:i+n]])
    out+=''.join(chr(x%26+65) for x in (K*v))
print(out)"

# Recover the key from known plaintext: K = C * P^-1 mod 26
python3 -c "
from sympy import Matrix
pt='THEFLAGIS'; ct='POHXXXYYY'; n=3
P=Matrix(n,n,lambda r,c: ord(pt[c*n+r])-65)
C=Matrix(n,n,lambda r,c: ord(ct[c*n+r])-65)
print((C*P.inv_mod(26))%26)"
```

- dcode: <https://www.dcode.fr/hill-cipher>

## ADFGVX / Polybius / Nihilist

```sh
# Polybius decode from digit pairs with a keyed 5x5 square
python3 -c "
A='ABCDEFGHIKLMNOPQRSTUVWXYZ'; kw='POLYBIUS'; sq=[]
[sq.append(c) for c in kw+A if c in A and c not in sq]
sq=''.join(sq); d='245151242541'
print(''.join(sq[(int(d[i])-1)*5+int(d[i+1])-1] for i in range(0,len(d),2)))"

# ADFGVX: confirm the alphabet and find candidate transposition key lengths
python3 -c "s=''.join(c for c in open('ct.txt').read().upper() if c in 'ADFGVX');print(sorted(set(s)),len(s),[k for k in range(2,13) if len(s)%k==0])"

# Nihilist: value range check (22..110 means a 5x5 additive)
python3 -c "v=[int(x) for x in open('ct.txt').read().split()];print(min(v),max(v),len(v))"
```

- dcode: <https://www.dcode.fr/adfgvx-cipher>, <https://www.dcode.fr/polybius-cipher>,
  <https://www.dcode.fr/nihilist-cipher>
- CyberChef: `ADFGVX Cipher Decode`.

## Bacon / Morse / tap code / Braille / T9

```sh
# Baconian decode (26-letter variant) from A/B text
python3 -c "
import string
T={format(i,'05b').replace('0','A').replace('1','B'):c for i,c in enumerate(string.ascii_uppercase)}
s=''.join(c for c in open('ct.txt').read().upper() if c in 'AB')
print(''.join(T.get(s[i:i+5],'?') for i in range(0,len(s)-4,5)))"

# Baconian hidden in letter case
python3 -c "
import string
T={format(i,'05b').replace('0','A').replace('1','B'):c for i,c in enumerate(string.ascii_uppercase)}
b=''.join('B' if c.isupper() else 'A' for c in open('ct.txt').read() if c.isalpha())
print(''.join(T.get(b[i:i+5],'?') for i in range(0,len(b)-4,5)))"

# Morse decode with '/' between words
python3 -c "
M={'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9'}
print(''.join(' ' if w=='/' else M.get(w,'?') for w in open('ct.txt').read().split()))"

# Tap code (5x5, K written as C)
python3 -c "
A='ABCDEFGHIJLMNOPQRSTUVWXYZ'
g=[x.split() for x in open('ct.txt').read().split('/')]
print(''.join(A[(len(p[0])-1)*5+len(p[1])-1] for p in g if len(p)==2))"

# Braille (Unicode U+2800 block) -> dot numbers
python3 -c "s=open('ct.txt').read();print([[i+1 for i in range(6) if (ord(c)-0x2800)>>i&1] for c in s if 0x2800<=ord(c)<=0x28FF])"

# Multi-tap / T9 decode
python3 -c "
K={'2':'ABC','3':'DEF','4':'GHI','5':'JKL','6':'MNO','7':'PQRS','8':'TUV','9':'WXYZ'}
print(''.join(' ' if g=='0' else K[g[0]][(len(g)-1)%len(K[g[0]])] for g in open('ct.txt').read().split()))"
```

- dcode symbol gallery (pigpen, dancing men, Standard Galactic, runes, semaphore,
  Hexahue, Daedric and ~200 more): <https://www.dcode.fr/symbols-ciphers>
- CyberChef: `From Morse Code`, `Bacon Cipher Decode`, `From Braille`.
- Audio Morse / DTMF: `multimon-ng -a MORSE_CW -t wav file.wav`,
  `multimon-ng -a DTMF -t wav file.wav`.

## Enigma

```sh
# Rotor wirings and notches (Wehrmacht I-V), reflectors B and C
# I    EKMFLGDQVZNTOWYHXUSPAIBRCJ  notch Q
# II   AJDKSIRUXBLHWTMCQGZNPYFVOE  notch E
# III  BDFHJLCPRTXVZNYEIWGAKMUSQO  notch V
# IV   ESOVPZJAYQUIRHXLNFTGKDCMWB  notch J
# V    VZBRGITYUPSDNHLXAWMJQOFECK  notch Z
# UKW-B YRUHQSLDPXNGOKMIEBFZCWVJAT
# UKW-C FVPJIAOYEDRZXWGCTKUQSBNMHL

# Canonical test vector: rotors I II III, reflector B, rings AAA, positions AAA
#   'A'*25 -> BDZGOWCXLTKSBTMCDLPBMUQOF

# Crib filter: Enigma never maps a letter to itself
python3 -c "
ct=open('ct.txt').read().strip().upper(); crib='WETTERBERICHT'
print([o for o in range(len(ct)-len(crib)+1) if all(crib[i]!=ct[o+i] for i in range(len(crib)))])"
```

- CyberChef: `Enigma` (rotors, rings, plugboard, reflector).
- dcode: <https://www.dcode.fr/enigma-machine-cipher>
- `pip install py-enigma` then `enigma.py --key-file ...`, or use CrypTool 2's
  Enigma analyser for the full IoC + plugboard hill climb.

## Online solvers worth bookmarking

```
https://www.dcode.fr/cipher-identifier     # paste ciphertext, get ranked guesses
https://www.dcode.fr/tools-list            # every classical cipher dcode implements
https://quipqiup.com/                      # substitution/cryptogram solver
https://gchq.github.io/CyberChef/          # encoding + many classical operations
https://www.cryptool.org/en/ct2/           # offline: Vigenere, Playfair, Enigma analysers
https://www.boxentriq.com/code-breaking    # identification guides + solvers
```

## Wordlists that crack classical keys

```sh
# CTF classical keys are almost always dictionary words - try these first
/usr/share/dict/words
/usr/share/wordlists/rockyou.txt
# plus: the challenge name, the CTF name, the author's handle, the file name
```

## Last-resort checklist

```
1. Measure the charset and the IoC before guessing anything.
2. Try ROT-n, Atbash, Base64 and reversal - 30 seconds, catches a third of challenges.
3. Factor the length: transposition grids and Hill block sizes hide there.
4. Look for a keyword: the recovered key is often the flag.
5. Chain the tools: base64 -> rot13 -> vigenere is a normal CTF depth.
6. If the plaintext is not English, swap the frequency table before concluding failure.
7. Read the challenge description again - it usually names the cipher.
```
