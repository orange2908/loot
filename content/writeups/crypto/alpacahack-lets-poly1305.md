---
title: "Lets Poly1305 - AlpacaHack Daily"
category: "crypto"
subcategory: "mac"
type: "writeup"
tags: ["crypto", "alpacahack", "poly1305", "lets", "mac", "cryptography"]
summary: "crypto writeup for \"Lets Poly1305\" from AlpacaHack Daily - techniques: alpacahack, poly1305, lets, mac, cryptography."
source:
  name: "baumroll0928-spec/myRepository"
  url: "https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d08_Lets_Poly1305/README.md"
ctf:
  name: "AlpacaHack Daily"
  year: 2026
  challenge: "Lets Poly1305"
---

## Source

- **CTF:** AlpacaHack Daily
- **Challenge:** Lets Poly1305
- **Date:** 2026-07-08
- **Repository:** [baumroll0928-spec/myRepository](https://github.com/baumroll0928-spec/myRepository)
- **Directory:** <https://github.com/baumroll0928-spec/myRepository/tree/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d08_Lets_Poly1305>
- **File:** <https://github.com/baumroll0928-spec/myRepository/blob/a7f1cdb83e529deb9dad77ce670a12fc7209ab07/Daily_AlpacaHack/m202607/d08_Lets_Poly1305/README.md>

---
# Let's Poly1305!

前日に予定トピック「MAC」を見て、「Mac PC？ MACアドレス？ マク○ナルド？」とかいろいろ考えましたが全てハズレだったようです。

## 問題

Poly1305 の鍵の半分は分かっています。

```py
import os
from secrets import token_bytes
from Crypto.Hash.Poly1305 import Poly1305_MAC

FLAG = os.getenv("FLAG", "Alpaca{dummy}")
TARGET = b"admin=true"

# Poly1305_MAC clamps r internally
r, s = token_bytes(16), token_bytes(16)
print(f"HINT! r: {r.hex()}")

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

起動すると、Poly1305のランダムな鍵`(r, s)`のうち`r`だけ教えてくれます。

その後、任意のメッセージ（空または`TARGET`("admin=true")はダメ）を送ると、同じ`(r, s)`で生成したタグを返してくれます。

最後に`TARGET`から生成したタグを推測して送り、当たっていたらフラグをゲットできます。

`s`は教えてもらえませんが、どうすれば`TARGET`から生成したタグを求めることができるのでしょうか？

## 方針

受け取ったタグと全て0の`s`で生成したタグの差分から正しい`s`を求める。

## 解法

まず、Poly1305について調べてみました。

Poly1305は、Daniel J. Bernstein が設計したメッセージ認証コード(Message Authentication Code)のアルゴリズムです。

データが改ざんされていないことを確認するために使われます。暗号化の機能は提供しません。

Poly1305_MACでは、概ね下記のような計算が行われます。
```py
def poly1305(r_bytes:bytes, s_bytes:bytes, msg_bytes:bytes):
    # rを整数化しクランプする（一部のビットを落とす）
    r = int.from_bytes(r_bytes, "little")
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    # sを整数化する
    s = int.from_bytes(s_bytes, "little")

    acc = 0
    # ブロックごとに処理する
    for i in range(0, len(msg_bytes), 16):
        # ブロックにb"\x01"をつけ足して整数化する
        n = int.from_bytes(msg_bytes[i : i+16] + b"\x01", "little")
        # mod(2^130 - 5)でnを足しr倍する
        acc = (acc + n) * r % ((1 << 130) - 5)
    # mod(2^128)でsを加算する
    tag = (acc + s) % (1 << 128)
    # bytesに変換して返す
    return tag.to_bytes(16, "little")
```
※数値がリトルエンディアン扱いになっている点に注意が必要です。

ここで、`s`は最後に$`\pmod{2^{128}}`$で加算されているだけです。

よって、てきとーなmsgについて、
```
tag1 = Poly1305_MAC(r, s, msg)
tag0 = Poly1305_MAC(r, b"\x00"*16, msg)
```
がわかれば、
```
tag1 == (tag0 + s) % (1 << 128)
```
が成立するので、
```
s = (tag1 - tag0) % (1 << 128)
```
で`s`を求めることができます。（※概念的な書き方なので正確な文法ではありません。）

ここで、`tag1`はサーバーが送ってくれるのでわかります。

また、`r`がわかっているので、`tag0`は手元で計算することができます。

こうして`s`が求まったら、あとは
```
tag = Poly1305_MAC(r, s, TARGET)
```
を計算すれば送るべき値がわかります。

```py
import pwn
from Crypto.Hash.Poly1305 import Poly1305_MAC

io = pwn.process(['python', 'server.py'])
#io = pwn.remote('34.170.146.252', 12581)

# rを取得
d = io.recvuntil(b"message: ")
r_hex = d.decode().split()[2]
r = bytes.fromhex(r_hex)

# メッセージを送ってtagを取得する
test_message = b"alpaca"
io.sendline(test_message)
d = io.recvuntil(b"tag: ")
tag1_hex = d.decode().split()[0]
tag1 = bytes.fromhex(tag1_hex)

# 同じメッセージと全て0のs0からtagを生成する
s0 = b"\x00" * 16
tag0_hex = Poly1305_MAC(r, s0, test_message).hexdigest()
tag0 = bytes.fromhex(tag0_hex)

# 差分を計算してsを求める
x = int.from_bytes(tag1, 'little')
y = int.from_bytes(tag0, 'little')
diff = (x - y) % (1 << 128)
s = diff.to_bytes(16, 'little')

# ターゲットとsからtagを生成する
target = b"admin=true"
tag_hex = Poly1305_MAC(r, s, target).hexdigest()

# 生成したtagを送信しフラグを得る
io.sendline(tag_hex.encode())
print(io.recvline())
```

## その他

今回はわりと簡単に解くことができましたが、ちょっと気になったのが、同じ予定トピック「MAC」の問題が、7月17日にもう1問、さらに7月25日にhard問題が既に予定されているということです。

今回の問題はただのチュートリアルにすぎなかったのでしょうか？それとも全然違う問題が出るのでしょうか？予習しつつ楽しみに待っていることにします。
