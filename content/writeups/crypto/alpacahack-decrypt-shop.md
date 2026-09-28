---
title: "Decrypt Shop - AlpacaHack Daily"
category: "crypto"
subcategory: "rsa"
type: "writeup"
tags: ["crypto", "alpacahack", "rsa", "gcd", "decrypt", "shop"]
summary: "crypto writeup for \"Decrypt Shop\" from AlpacaHack Daily - techniques: alpacahack, rsa, gcd, decrypt, shop."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d29_Decrypt_Shop/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Decrypt Shop"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Decrypt Shop
- **Date:** 2026-05-29
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d29_Decrypt_Shop>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202605/d29_Decrypt_Shop/README.md>

---
# Decrypt Shop

## 問題

flag の暗号文以外なら、どんな暗号文でも魔法で復号してあげます。本当ですよ

```py
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = inverse(e, phi)

c = pow(bytes_to_long(flag), e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")
print("Give me a ciphertext. I will decrypt it, unless it is the flag ciphertext.")

while True:
    try:
        x = int(input("> "))
    except:
        print("invalid")
        exit(0)

    if not 0 <= x < n:
        print("out of range")
        exit(0)

    if x == c:
        print("no")
        exit(0)

    m = pow(x, d, n)
    print(m)
```

## 概要

最初にRSA暗号の鍵 $`n`$, $`e`$ とこの鍵でフラグを暗号化した $`c`$ が与えられます。

その後、$`0 \le x \lt n`$ かつ $`x \ne c`$ を満たす整数 $`x`$ を入力するたびにこれを同じ鍵で復号した $`m \equiv x^{d} \pmod{n}`$ を教えてくれます。

$`c`$ そのものや同じ復号結果になる $`c \pm kn (k=1,2,...)`$ は復号してもらえないようですが、どうすればフラグを得ることができるのでしょうか？

## 解法

すみません、今回の問題は一瞬でわかってしまいました。なぜなら・・・

なんと、偶然にも私が出題しようと思って作っている途中だった問題とほぼ丸被りしてしまったからです！

まあ問題作成をしていたらそういうこともありますよね。

というわけで、以降はその時のために用意していたWriteupの解法を今回の問題向けに微調整したものになります。

---

RSAには乗法準同型性という性質があり、 $`m`$ を暗号化したものを $`Enc(m)`$ とすると、

$`Enc(m_{1}m_{2}) \equiv Enc(m_{1}) \cdot Enc(m_{2}) \pmod{n}`$

が成立します。

よって、フラグを数値化したものを $`f`$ とすると、

$`Enc(2f) \equiv Enc(2) \cdot Enc(f) \pmod{n}`$

が成立しますが、

$`Enc(2) \equiv 2^{e} \pmod{n}`$

$`Enc(f) = c`$

から、既知の $`n`$, $`e`$, $`c`$ を用いて $`c' = Enc(2f)`$ を求めることができます。

この $`c'`$ を送ると、復号結果 $`f' \equiv 2f \pmod{n}`$ を得ることができるので、

$`f ≡ f' \cdot 2^{-1} \pmod{n}`$

によって $`f`$ を求めることができます。

※$`n`$ は奇数であり、$`gcd(2, n) = 1`$ であることから、$`n`$ を法とする $`2`$ の逆元は必ず求めることができます。

```py
from Crypto.Util.number import long_to_bytes
import pwn

#HOST, PORT = "localhost", 1337
HOST, PORT = "34.170.146.252", 41193
p = pwn.remote(HOST, PORT)

data = p.recvuntil(b'> ').decode().split()
n = int(data[2])
e = int(data[5])
c = int(data[8])

c2 = c * pow(2, e, n) % n
p.sendline(str(c2).encode())

data = p.recvuntil(b'> ').decode().split()
f2 = int(data[0])

f = f2 * pow(2, -1, n) % n
flag = long_to_bytes(f)
print(f"{flag = }")
```

※今回の問題のように $`f`$ がパディングされておらず $`2f < n`$ に収まるときは、逆元をとらずにただ2で割るだけでも求めることができます。
