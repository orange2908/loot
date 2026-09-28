---
title: "Lets Poly1305 2 - AlpacaHack Daily"
category: "crypto"
subcategory: "mac"
type: "writeup"
tags: ["crypto", "alpacahack", "poly1305", "lets", "mac", "cryptography"]
summary: "crypto writeup for \"Lets Poly1305 2\" from AlpacaHack Daily - techniques: alpacahack, poly1305, lets, mac, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d15_Lets_Poly1305_2/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lets Poly1305 2"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lets Poly1305 2
- **Date:** 2026-07-15
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d15_Lets_Poly1305_2>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d15_Lets_Poly1305_2/README.md>

---
# Let's Poly1305! 2

## 問題

Poly1305 の鍵の半分は分かっています。

```py
FLAG = os.getenv("FLAG", "Alpaca{dummy}")
TARGET = b"admin=true"

# Poly1305_MAC clamps r internally
r, s = token_bytes(16), token_bytes(16)
print(f"HINT! s: {s.hex()}")

message = input("message: ").encode()
if not message or message == TARGET:
    raise SystemExit("invalid message")
print(Poly1305_MAC(r, s, message).hexdigest())

if input("tag: ") == Poly1305_MAC(r, s, TARGET).hexdigest():
    print(FLAG)
else:
    print("invalid")
```

## 概要

7月8日の過去問「Let's Poly1305!」の関連問題のようです。

今回は`r`ではなく`s`が与えられています。どうすれば`r`を求めて正しいタグを推測できるのでしょうか？

## 解法

Poly1305_MAC関数の計算方法については[Let's Poly1305!の解法](https://github.com/baumroll0928-spec/myRepository/tree/main/Daily_AlpacaHack/m202607/d08_Lets_Poly1305#%E8%A7%A3%E6%B3%95)に記載したとおりです。

ザックリとしたイメージとしては、

- てきとーなメッセージ（1ブロック(=16バイト)以下）を送ってタグを得る
- 取得したタグから最初にヒントとして与えられた`s`を引く
- さらに送ったメッセージの逆元を掛けて`r`を求める

といった方法で解くことができます。

ただちょっと厄介なのが、最後に`s`を足すときのmodの法が`r`を掛けるときのそれよりも小さいということです。

具体的には、前者が $`2^{128}`$ 、後者が $`2^{130}-5`$ なので、`s`を足す計算のところで2ビット欠けてしまいます。

とはいえ、たったの2ビットなので、`00`,`01`,`10`,`11`の4通り全て試してみればいいでしょう。

ただ、推測の提出は1回しかできません。

4つのうちどれか1つを選んで提出する必要がありますが、どれが正解なのでしょうか？

※求める値はフラグそのものではないので、プレフィックス`Alpaca{`を用いた判断などはできません。

候補は4つしかないので、そのうちの1つをあてずっぽうで当たるまで繰り返し試し続けてもよさそうです。

しかし、そんなことをしなくても正解をみつける方法はあります。

それは、求めた`r`が正しくクランプされたものであるかどうかを確認することです。

Poly1305_MACの計算において、最初に
```py
r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
```
によって、16バイト=128ビットのうち特定の22か所のビットが強制的に落とされます。

メッセージの逆元を掛けた時点で正しい`r`が求まっていたら、これらの22か所のビットは全て落ちている（0である）はずです。

しかし、間違った`r`が求まった場合、ほぼ100%の確率で本来落ちているべきビットが立っている（1になっている）と思われます。

※そもそも求めた`r`が $`2^{128}`$ 以上になった場合は論外なわけですが、これも同じチェックで一緒に弾くことができます。

正しい`r`が求まったらあとは「Let's Poly1305!」と同じように正しいタグを送りフラグを取得します。

```py
import pwn
from Crypto.Hash.Poly1305 import Poly1305_MAC

io = pwn.process(['python', 'server.py'])
#io = pwn.remote('34.170.146.252', 37134)

# sを取得
d = io.recvuntil(b"message: ")
s_hex = d.decode().split()[2]
s = bytes.fromhex(s_hex)

# メッセージを送ってtagを取得する
test_message = b"alpaca"
io.sendline(test_message)
d = io.recvuntil(b"tag: ")
tag1_hex = d.decode().split()[0]
tag1 = bytes.fromhex(tag1_hex)

# 取得したtagからsを引く
x = int.from_bytes(tag1,"little")
y = int.from_bytes(s, "little")
nr0 = (x - y) % (1 << 128)

# 送ったメッセージの逆元を求めておく
p = (1 << 130) - 5
n = int.from_bytes(test_message + b"\x01", "little")
inv_n = pow(n, -1, p)

# 4通り全て試す
for i in range(4):
    # 仮のrを求める
    nr = (i << 128) + nr0
    r_int = nr * pow(n, -1, p) % p
    # 仮のrが正しくクランプされたものであるか調べる
    if r_int & 0x0ffffffc0ffffffc0ffffffc0fffffff == r_int:
        break
else:
    print("not found")
    exit(0)

# ターゲットと求めたr、与えられたsからtagを生成する
r = r_int.to_bytes(16, "little")
target = b"admin=true"
tag_hex = Poly1305_MAC(r, s, target).hexdigest()

# 生成したtagを送信しフラグを得る
io.sendline(tag_hex.encode())
print(io.recvline())
```
