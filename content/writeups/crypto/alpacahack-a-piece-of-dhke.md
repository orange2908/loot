---
title: "A Piece of DHKE - AlpacaHack Daily"
category: "crypto"
subcategory: "aes"
type: "writeup"
tags: ["crypto", "alpacahack", "aes", "piece", "dhke", "cryptography"]
summary: "crypto writeup for \"A Piece of DHKE\" from AlpacaHack Daily - techniques: alpacahack, aes, piece, dhke, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d09_%20A_Piece_of_DHKE/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "A Piece of DHKE"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** A Piece of DHKE
- **Date:** 2026-06-09
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d09_%20A_Piece_of_DHKE>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202606/d09_%20A_Piece_of_DHKE/README.md>

---
# A Piece of DHKE

## 問題

Diffie-Hellman で鍵交換をしたつもりが、何かが足りないようです…

```py
flag = os.getenv("FLAG", "Alpaca{REDACTED}").encode()

# experimental 512-bit MODP DH Group like RFC 3526
g = 2
p_hex = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74
020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3CB093 FFFFFFFF FFFFFFFF
"""
p = int.from_bytes(bytes.fromhex(p_hex), "big")
assert p.bit_length() == 512 and isPrime(p)

# order of g is (p - 1) // 2
assert p % 6 == 1 and isPrime((p - 1) // 6)  # p - 1 = 2 * 3 * q
assert pow(g, (p - 1) // 6, p) != 1
assert pow(g, (p - 1) // 3, p) != 1
assert pow(g, (p - 1) // 2, p) == 1


def main():
    a = getRandomNBitInteger(256)

    print("ga = {pow(g, a, p)}")

    gb = int(input("gb = "))

    if not 1 < gb < p - 1:
        raise ValueError("Invalid gb value")

    flag_enc = encrypt(pow(gb, a, p), flag)
    print(f"flag_enc = {flag_enc.hex()}")
```

## 概要

DHKE (Diffie-Hellman Key Exchange) は、盗聴されるおそれのある安全でない通信経路上でも安全に共通鍵を共有できる仕組みです。

概ね次のような手順で行われます。

- 巨大な素数`p`と整数`g`を選んで共有する。
- Aliceは整数`a`を無作為に選び、$`A \equiv g^{a} \pmod{p}`$をBobに送る。
- Bobは整数`b`を無作為に選び、$`B \equiv g^{b} \pmod{p}`$をAliceに送る。
- Aliceは$`K \equiv B^{a} \pmod{p}`$によって`K`を得る。
- Bobは$`K \equiv A^{b} \pmod{p}`$によって`K`を得る。

この手順において、 $`A^{b} = B^{a} = g^{ab}`$ より、AliceとBobは同じ`K`を得ることができます。

また、第三者が`p`,`g`,`A`,`B`を全て盗聴しても`K`を得ることは事実上不可能です。

このことから、共通鍵`K`を安全に共有することができるというわけですね。

今回の問題はこのBobの視点になっていて、`B`を入力すると、`K`でフラグを暗号化した暗号文が返されるようになっています。

※`server.py`の中では、`A`は変数`ga`、`B`は変数`gb`で表されています。

`A`がわかれば`b`を使って`K`を求めることができますが、今回のプログラムにはバグがあり、
```py
    print("ga = {pow(g, a, p)}") # f"..."のfが無い!?
```
となっているので、`A`の値を表示してくれません。

この状況でどうすれば共通鍵`K`を得て暗号文を復号しフラグを得ることができるのでしょうか？

## 方針

位数が小さい`gb`を送り、暗号文を全ての鍵候補で復号してみる。

## 解法

$`\pmod{p}`$における`g`の「位数」とは、$`g^{x} \equiv 1 \pmod{p}`$を満たす最小の正整数 $`x`$ のことです。

$`g^{i} \pmod{p} (i = 1,2,...)`$ を計算していくと長さ $`x`$ の周期で回る、と考えるとわかりやすいでしょうか。

フェルマーの小定理により、 $`p`$ が素数であれば $`g^{p-1} \equiv 1 \pmod{p}`$ が成り立つので、位数は必ず $`p - 1`$ の約数になります。

さて、`B`すなわち`gb`の値として、位数が小さくなる値を送ったらどうなるでしょうか？

`a`の値は全くわかりませんが、 $`K \equiv B^{a} \pmod{p}`$ はその短い周期で回ることになるので、共通鍵`K`の候補数はその位数の数に絞り込まれることになります。

具体的にはどんな値を送ればいいのでしょうか？

ソースコードのassert文のところをみてみると、そのヒントが書いてありました。
```py
assert pow(g, (p - 1) // 3, p) != 1
```
この問題において`p`と`g`は固定かつ明示された値なので、本来このようなassert文を入れる必要はないはずです。

結論から言うと、実はこの`g' = pow(g, (p - 1) // 3, p)`こそ、3という小さい位数である値のひとつなのです。

なぜなら、

$`g^{p-1} = g^{\frac{p-1}{3} \cdot 3} \equiv 1 \pmod{p}`$

より

$`g'^{3} \equiv 1 \pmod{p}`$

が成り立つからです。（3は素数なので途中で1を経由することもありません。）

この`g'`を`gb`の値として送ると、 $`B^{i} \pmod{p}`$ は $`1`$, $`B`$, $`B^{2} \pmod{p}`$ の3つを順に回ることになるので、共通鍵`K`はこれらのうちどれかになります。

共通鍵の候補が3つしかないので、全て使って復号を試してしまえばいいでしょう。

```py
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import pwn

#HOST, PORT = "localhost", 1337
HOST, PORT = "34.170.146.252", 50224

# ここにhash_int関数,decrypt関数の定義とg,pの初期化の部分を全てコピペする

gb = pow(g, (p-1)//3, p)
keys = [1, gb, pow(gb, 2, p)]

r = pwn.remote(HOST, PORT)
r.sendlineafter(b'gb = ', str(gb).encode())
d = r.recvall().decode()
c = bytes.fromhex(d.split()[-1])

for k in keys:
    try:
        plain = decrypt(k, c)
        if b'Alpaca{' in plain:
            print(f"Flag found: {plain}")
            break
    except:
        pass
else:
    print("Flag not found.")
```
