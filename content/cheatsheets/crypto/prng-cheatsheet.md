---
title: "PRNG Cheatsheet - Which Language Uses What, and How to Break It"
category: crypto
subcategory: prng
type: cheatsheet
tags: [prng, mt19937, mersenne-twister, lcg, xorshift, xoshiro, pcg, splitmix64, glibc-rand, java-random, php-mt-rand, math-random, randcrack, mt19937predictor, php-mt-seed, untwister, z3, csprng, state-recovery, seed-bruteforce]
summary: "Per-language table of default generators, state size, outputs needed for recovery, and the tool that breaks each one - plus install and usage one-liners."
tools: [randcrack, mt19937predictor, php_mt_seed, untwister, z3, python]
related: [prng-mt19937-state-recovery, prng-lcg-recovery, prng-java-random, prng-glibc-rand, prng-xorshift-v8-math-random, prng-toolkit]
---

## Who uses what

| Language / runtime | Default RNG | State | Output per step | Outputs needed | Tool |
|---|---|---|---|---|---|
| Python `random` | MT19937 | 624 x 32 bits | 32 | 624 `getrandbits(32)` | randcrack, mt19937predictor |
| Python `numpy.random.seed`/`RandomState` | MT19937 | 624 x 32 | 32 | 624 | randcrack |
| Python `numpy.default_rng()` | PCG64 | 128 bits | 64 | ~4 + z3 | z3 |
| Python `secrets`, `SystemRandom`, `os.urandom` | OS CSPRNG | - | - | **not breakable** | - |
| PHP `mt_rand`, `rand` (7.1+) | MT19937 (`>> 1`) | 624 x 32 | 31 | ~700, or seed brute | php_mt_seed |
| PHP `mt_rand` (< 7.1) | MT19937 with a buggy twist | 624 x 32 | 31 | same | php_mt_seed `-p` |
| PHP `rand` (< 7.1) | libc `rand()` | see glibc | 31 | 31 | custom |
| PHP `uniqid()` | microtime, not random | - | - | 0 | read the clock |
| PHP `random_int`, `random_bytes` | CSPRNG | - | - | **not breakable** | - |
| C/C++ glibc `rand`, `random` | TYPE_3 additive feedback | 34 x 32 bits | 31 | 31 (+1 carry bit) | custom, untwister |
| C `rand_r` | weak LCG | 32 bits | 31 | 2 | LCG recovery |
| MSVC `rand()` | LCG `214013x+2531011 mod 2**31` | 32 bits | 15 | 2-3 | truncated-LCG lattice |
| C++ `std::mt19937` | MT19937 | 624 x 32 | 32 | 624 | randcrack |
| C++ `std::minstd_rand` | Park-Miller LCG | 31 bits | 31 | 2-3 | LCG recovery |
| Java `java.util.Random` | 48-bit LCG | 48 bits | 32 | 2 `nextInt()` or 1 `nextLong()` | 2^16 brute force |
| Java `ThreadLocalRandom` | SplitMix-style 64-bit | 64 bits | 64 | 1-2 | invert the mixer |
| Java `SecureRandom` (no seed) | OS / SHA1PRNG | - | - | **not breakable** | - |
| JavaScript V8 (Chrome/Node) `Math.random` | xorshift128+ | 128 bits | 52 (of 64) | **4** | GF(2) solve / z3 |
| JavaScript SpiderMonkey `Math.random` | xorshift128+ | 128 bits | 52 | 4 | same, different ToDouble |
| Node `crypto.randomBytes`, `randomUUID` | OS CSPRNG | - | - | **not breakable** | - |
| Go `math/rand` (pre-1.20 seeded) | ALFG, 607-element table | 607 x 64 | 63 | 607, or seed brute | custom |
| Go `math/rand/v2` | ChaCha8 / PCG | 256 / 128 bits | 64 | - / z3 | - |
| Go `crypto/rand` | OS CSPRNG | - | - | **not breakable** | - |
| Rust `rand::thread_rng` | ChaCha12 | 256 bits | - | **not breakable** | - |
| Rust `SmallRng` | xoshiro256++ / xoshiro128++ | 256 / 128 | 64 / 32 | ~5 | GF(2) solve |
| Ruby `Random`, `rand` | MT19937 | 624 x 32 | 32 | 624 | randcrack |
| .NET `System.Random` (< .NET 6) | subtractive lagged Fibonacci | 56 x 32 | 31 | 55 | custom |
| .NET `System.Random` (.NET 6+) | xoshiro256** | 256 bits | 64 | ~5 | invert scrambler + GF(2) |
| .NET `RandomNumberGenerator` | OS CSPRNG | - | - | **not breakable** | - |
| Lua 5.4 `math.random` | xoshiro256** | 256 bits | 64 | ~5 | invert + GF(2) |
| SQL `RAND()` (MySQL) | two 31-bit LCGs | 64 bits | double | 2-3 | LCG recovery |

## Magic constants -> generator

```
0x9908B0DF  0x9D2C5680  0xEFC60000  1812433253  624  397   -> MT19937
0x5DEECE66D  0xB  (1<<48)                                   -> java.util.Random / drand48
1103515245  12345  (1<<31)                                  -> ANSI C / glibc TYPE_0 LCG
214013  2531011                                             -> MSVC rand()
22695477                                                    -> Borland rand()
16807  127773  2836  2147483647                             -> Park-Miller (glibc srandom init)
6364136223846793005                                         -> PCG32 / MMIX LCG
1442695040888963407                                         -> MMIX increment / PCG default inc
0x9E3779B97F4A7C15                                          -> SplitMix64 / golden gamma
0xBF58476D1CE4E5B9  0x94D049BB133111EB                      -> SplitMix64 finaliser
<< 23  >> 17  >> 26                                         -> xorshift128+ (V8 Math.random)
rotl(s[1]*5,7)*9                                            -> xoshiro256**
0x2545F4914F6CDD1D                                          -> xorshift64*
31  3  310                                                  -> glibc random() TYPE_3
```

## Tools: install and use

```sh
# randcrack - Python MT19937, needs exactly 624 getrandbits(32) values
pip install randcrack
python3 -c "
from randcrack import RandCrack
import random
rc = RandCrack()
for _ in range(624):
    rc.submit(random.getrandbits(32))
print(rc.predict_getrandbits(32))"

# mt19937predictor - accepts partial-width feeds
pip install mt19937predictor
python3 -c "
from mt19937predictor import MT19937Predictor
import random
p = MT19937Predictor()
for _ in range(624):
    p.setrandbits(random.getrandbits(32), 32)
print(p.getrandbits(32))"

# php_mt_seed - GPU-capable PHP mt_rand seed cracker
git clone https://github.com/openwall/php_mt_seed && cd php_mt_seed && make
./php_mt_seed 1234567890                    # exact mt_rand() output
./php_mt_seed 5 5 1 10                      # mt_rand(1,10) returned 5
./php_mt_seed 5 5 1 10  7 7 1 10            # several constraints in sequence

# untwister - multi-PRNG seed brute forcer (MT19937, glibc, Java, Ruby, PHP)
git clone https://github.com/altf4/untwister && cd untwister && make
./untwister -i observed.txt -r mt19937 -t 8
./untwister -i observed.txt -r glibc-rand -d 86400     # search a 1-day time window

# z3 - for truncated outputs and non-linear scramblers
pip install z3-solver
```

## Python `random` accounting (get this wrong and nothing works)

```
getrandbits(32)        1 output, untouched              <- ask for this
getrandbits(k<=32)     1 output, >> (32-k)
getrandbits(64)        2 outputs, value = w0 | (w1<<32)  (LOW word first)
random()               2 outputs, (a>>5)*2**26 + (b>>6), /2**53
randrange(n)/randint   _randbelow(n): getrandbits(n.bit_length()) with REJECTION
                       n = 2**m  -> averages 2 outputs (worst case)
                       n = 2**m-1 -> averages ~1 output (best case)
choice(seq)            _randbelow(len(seq))
choices(k=..)          random() per pick -> 2 outputs each
shuffle(x)             reversed Fisher-Yates, _randbelow(i+1) for i = n-1 .. 1
sample(pop,k)          data-dependent - do not count on it
seed()                 os.urandom(32)  -> NOT brute-forceable
seed(int)              init_by_array over the abs value's 32-bit limbs
seed(str/bytes)        int.from_bytes(n + sha512(n).digest(), "big")
```

## One-liners

```sh
# Clone Python's random from 624 outputs (no external packages)
python3 -c "
import random
def ut(y):
    def ur(y,n):
        x=y
        for _ in range((32+n-1)//n): x=y^(x>>n)
        return x&0xffffffff
    def ul(y,n,m):
        x=y
        for _ in range((32+n-1)//n): x=y^((x<<n)&m)
        return x&0xffffffff
    y=ur(y,18); y=ul(y,15,0xefc60000); y=ul(y,7,0x9d2c5680); return ur(y,11)
v=random.Random(1337)
obs=[v.getrandbits(32) for _ in range(624)]
c=random.Random(); c.setstate((3,tuple([ut(o) for o in obs]+[624]),None))
print(v.getrandbits(32)==c.getrandbits(32))"

# Brute force random.seed(int(time.time())) over a day
python3 -c "
import random,time
target=<observed 32-bit value>
now=int(time.time())
for s in range(now-86400, now+1):
    if random.Random(s).getrandbits(32)==target: print(s); break"

# Java: crack the 48-bit state from two nextInt() values
python3 -c "
a,b = <int1>&0xffffffff, <int2>&0xffffffff
M,A,C = (1<<48)-1, 0x5DEECE66D, 0xB
for low in range(1<<16):
    s=(a<<16)|low
    if ((s*A+C)&M)>>16 == b: print(s, 'literal seed =', hex(s^A)); break"

# glibc random(): predict from 31 outputs (one-bit carry ambiguity)
python3 -c "
o=[<31 consecutive random() outputs>]
for _ in range(10):
    s=(o[-3]+o[-31])%(1<<31); print(s, s+1); o.append(s)"

# LCG: recover m, a, c from 8 outputs
python3 -c "
from math import gcd
from functools import reduce
s=[<8 consecutive outputs>]
t=[b-a for a,b in zip(s,s[1:])]
m=abs(reduce(gcd,[t[i+2]*t[i]-t[i+1]**2 for i in range(len(t)-2)]))
a=((s[2]-s[1])*pow(s[1]-s[0],-1,m))%m
c=(s[1]-a*s[0])%m
print(a,c,m)"

# V8 Math.random: pull the known 52 bits out of each double
python3 -c "
import struct
for d in [<Math.random() values>]:
    print(hex(struct.unpack('<Q',struct.pack('<d',d+1.0))[0] & ((1<<52)-1)))"

# PHP: reproduce mt_rand offline
php -r 'mt_srand(12345); for($i=0;$i<5;$i++) echo mt_rand(),\"\n\";'

# Java: reproduce a sequence offline
cat > T.java <<'EOF'
import java.util.Random;
public class T { public static void main(String[] a){
  Random r = new Random(Long.parseLong(a[0]));
  for (int i=0;i<10;i++) System.out.println(r.nextInt());
}}
EOF
javac T.java && java T 42

# C: reproduce glibc rand()
printf '#include <stdio.h>\n#include <stdlib.h>\nint main(int c,char**v){srand(atoi(v[1]));for(int i=0;i<10;i++)printf("%%d\\n",rand());}\n' > r.c
cc -o r r.c && ./r 12345
```

## Decision flow

```
Do you have 624+ consecutive full 32-bit outputs?
  yes -> MT19937 state recovery (randcrack). Done.
  no  -> Is the seed a timestamp / PID / small int / dictionary word?
           yes -> seed brute force (a day is 86,400 candidates)
           no  -> How many outputs can you get?
                    4 doubles from JS      -> xorshift128+ GF(2) solve
                    2 Java nextInt()       -> 2^16 brute force
                    8 full-width ints      -> LCG parameter recovery
                    8-20 truncated ints    -> LLL + Babai (truncated LCG)
                    31 glibc random()      -> additive feedback, 1-bit carry
                    1 splitmix64 output    -> invert the finaliser
                    fewer than that        -> look for another oracle:
                                              a shuffle, a UUID, a timestamp
Is it secrets / os.urandom / SecureRandom() / crypto.randomBytes / crypto/rand?
  -> stop, attack something else in the challenge.
```

## Oracles that leak RNG state without looking like it

```
- A shuffled deck / list of known items: Fisher-Yates is invertible -> every
  _randbelow output.
- A "random" password from a known alphabet: each character is one _randbelow.
- A UUIDv4 from a weak RNG: 122 bits in one object.
- A CAPTCHA, a lottery draw, a dice roll, a card deal, a colour.
- A filename made with tempfile.mktemp / uniqid.
- A session token, a CSRF token, a password-reset token, an invite code.
- A nonce or IV reused across requests.
- Anything numbered "randomly" that you can request repeatedly.
```

## Sanity checks before you start

```sh
# Are the values actually uniform over the claimed range?
python3 -c "
import sys,collections
v=[int(x) for x in open(sys.argv[1])]
print(min(v),max(v),len(v),len(set(v)))" samples.txt

# Bit-width: 31 vs 32 bits distinguishes glibc rand() from MT19937 immediately
python3 -c "
v=[int(x) for x in open('samples.txt')]
print(max(v).bit_length(), 'values >= 2**31:', sum(x>=2**31 for x in v))"

# Are they consecutive? Predict one and check before building the whole exploit.
```

## References

- randcrack - <https://github.com/tna0y/Python-random-module-cracker>
- mt19937predictor - <https://github.com/kmyk/mersenne-twister-predictor>
- php_mt_seed - <https://www.openwall.com/php_mt_seed/>
- untwister - <https://github.com/altf4/untwister>
- z3 - <https://github.com/Z3Prover/z3>
- Vigna, xoshiro/xoroshiro - <https://prng.di.unimi.it/>
- PCG - <https://www.pcg-random.org/>
